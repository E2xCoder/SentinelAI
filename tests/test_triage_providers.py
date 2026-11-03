"""Tests for the triage providers, LLM config validation and the triage cache."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import requests

from sentinelai.ai.triage_cache import TriageCache, prompt_sha
from sentinelai.ai.triage_models import TriageProviderError, TriageResult
from sentinelai.ai.triage_providers import (
    MAX_RESPONSE_BYTES,
    OllamaProvider,
    OpenAICompatProvider,
    create_provider,
)
from sentinelai.config.models import LLMConfig
from sentinelai.core.exceptions import ConfigError

SCHEMA: dict[str, Any] = {"type": "object", "properties": {"verdict": {"type": "string"}}}
SYSTEM = "SYSTEM-PROMPT-MARKER-aa11"
USER = "USER-PROMPT-MARKER-bb22 sshd failed password for root"
FAKE_KEY = "sk-test-FAKEKEY-0000"


# --------------------------------------------------------------------------- fakes


class FakeResponse:
    """Minimal stand-in for a streamed ``requests.Response``."""

    def __init__(
        self,
        body: bytes = b"",
        status_code: int = 200,
        read_error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self._body = body
        self._read_error = read_error
        self.closed = False

    def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
        if self._read_error is not None:
            raise self._read_error
        for start in range(0, len(self._body), chunk_size):
            yield self._body[start : start + chunk_size]

    def close(self) -> None:
        self.closed = True


class FakeSession:
    """Records ``post`` calls and returns / raises a canned outcome."""

    def __init__(self, outcome: FakeResponse | Exception) -> None:
        self.outcome = outcome
        self.calls: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def _ollama_body(content: Any = '{"verdict": "benign"}') -> bytes:
    return json.dumps({"message": {"role": "assistant", "content": content}}).encode()


def _openai_body(content: Any = '{"verdict": "benign"}') -> bytes:
    message = {"role": "assistant", "content": content}
    return json.dumps({"choices": [{"message": message}]}).encode()


def _ollama(session: FakeSession, endpoint: str = "http://llm.test:11434") -> OllamaProvider:
    return OllamaProvider(endpoint, "model-x", 12.5, 321, session=session)  # type: ignore[arg-type]


def _openai(
    session: FakeSession, endpoint: str = "https://llm.test", api_key: str = ""
) -> OpenAICompatProvider:
    return OpenAICompatProvider(
        endpoint, "model-y", 7.0, 222, api_key=api_key, session=session  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- Ollama


class TestOllamaProvider:
    def test_complete_posts_to_api_chat_and_returns_message_content(self) -> None:
        session = FakeSession(FakeResponse(_ollama_body('{"verdict": "malicious"}')))
        answer = _ollama(session).complete(SYSTEM, USER, SCHEMA)
        assert answer == '{"verdict": "malicious"}'
        assert session.calls[0]["url"] == "http://llm.test:11434/api/chat"

    def test_trailing_slash_in_endpoint_is_stripped(self) -> None:
        session = FakeSession(FakeResponse(_ollama_body()))
        _ollama(session, "http://llm.test:11434///").complete(SYSTEM, USER, SCHEMA)
        assert session.calls[0]["url"] == "http://llm.test:11434/api/chat"

    def test_payload_has_model_messages_and_non_streaming(self) -> None:
        session = FakeSession(FakeResponse(_ollama_body()))
        _ollama(session).complete(SYSTEM, USER, SCHEMA)
        payload = session.calls[0]["json"]
        assert payload["model"] == "model-x"
        assert payload["stream"] is False
        assert payload["messages"] == [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": USER},
        ]

    def test_payload_format_equals_schema(self) -> None:
        session = FakeSession(FakeResponse(_ollama_body()))
        _ollama(session).complete(SYSTEM, USER, SCHEMA)
        assert session.calls[0]["json"]["format"] == SCHEMA

    def test_payload_options_are_deterministic_and_bounded(self) -> None:
        session = FakeSession(FakeResponse(_ollama_body()))
        _ollama(session).complete(SYSTEM, USER, SCHEMA)
        assert session.calls[0]["json"]["options"] == {"temperature": 0, "num_predict": 321}

    def test_redirects_disabled_timeout_and_streaming_passed(self) -> None:
        session = FakeSession(FakeResponse(_ollama_body()))
        _ollama(session).complete(SYSTEM, USER, SCHEMA)
        call = session.calls[0]
        assert call["allow_redirects"] is False
        assert call["timeout"] == 12.5
        assert call["stream"] is True

    def test_no_authorization_header_is_sent(self) -> None:
        session = FakeSession(FakeResponse(_ollama_body()))
        _ollama(session).complete(SYSTEM, USER, SCHEMA)
        assert "Authorization" not in session.calls[0]["headers"]

    def test_response_is_closed_after_success(self) -> None:
        response = FakeResponse(_ollama_body())
        _ollama(FakeSession(response)).complete(SYSTEM, USER, SCHEMA)
        assert response.closed is True

    def test_response_is_closed_after_http_error(self) -> None:
        response = FakeResponse(b"boom", status_code=500)
        with pytest.raises(TriageProviderError):
            _ollama(FakeSession(response)).complete(SYSTEM, USER, SCHEMA)
        assert response.closed is True

    @pytest.mark.parametrize(
        "exc",
        [
            requests.ConnectionError("refused http://llm.test " + USER),
            requests.Timeout("timed out " + USER),
        ],
    )
    def test_network_errors_become_provider_error(self, exc: Exception) -> None:
        with pytest.raises(TriageProviderError) as info:
            _ollama(FakeSession(exc)).complete(SYSTEM, USER, SCHEMA)
        assert type(exc).__name__ in str(info.value)

    def test_http_500_raises_provider_error_with_status(self) -> None:
        with pytest.raises(TriageProviderError, match="500"):
            _ollama(FakeSession(FakeResponse(b"{}", status_code=500))).complete(
                SYSTEM, USER, SCHEMA
            )

    def test_redirect_status_is_rejected(self) -> None:
        with pytest.raises(TriageProviderError, match="302"):
            _ollama(FakeSession(FakeResponse(b"", status_code=302))).complete(
                SYSTEM, USER, SCHEMA
            )

    def test_non_json_body_raises_provider_error(self) -> None:
        with pytest.raises(TriageProviderError, match="non-JSON"):
            _ollama(FakeSession(FakeResponse(b"<html>nope</html>"))).complete(
                SYSTEM, USER, SCHEMA
            )

    def test_invalid_utf8_body_raises_provider_error(self) -> None:
        with pytest.raises(TriageProviderError):
            _ollama(FakeSession(FakeResponse(b"\xff\xfe\x00garbage"))).complete(
                SYSTEM, USER, SCHEMA
            )

    @pytest.mark.parametrize(
        "body",
        [
            b"{}",
            b'{"message": "text"}',
            b'{"message": null}',
            b"[]",
            b'"just a string"',
            b"null",
        ],
    )
    def test_unexpected_envelope_raises_provider_error(self, body: bytes) -> None:
        with pytest.raises(TriageProviderError):
            _ollama(FakeSession(FakeResponse(body))).complete(SYSTEM, USER, SCHEMA)

    @pytest.mark.parametrize("content", ["", "   \n\t", None, 42, ["x"]])
    def test_empty_or_non_string_content_raises_provider_error(self, content: Any) -> None:
        body = _ollama_body(content)
        with pytest.raises(TriageProviderError):
            _ollama(FakeSession(FakeResponse(body))).complete(SYSTEM, USER, SCHEMA)

    def test_missing_content_key_raises_provider_error(self) -> None:
        body = json.dumps({"message": {"role": "assistant"}}).encode()
        with pytest.raises(TriageProviderError):
            _ollama(FakeSession(FakeResponse(body))).complete(SYSTEM, USER, SCHEMA)

    def test_body_over_limit_raises_provider_error(self) -> None:
        body = b" " * (MAX_RESPONSE_BYTES + 1)
        with pytest.raises(TriageProviderError, match="size limit"):
            _ollama(FakeSession(FakeResponse(body))).complete(SYSTEM, USER, SCHEMA)

    def test_body_exactly_at_limit_is_not_rejected_for_size(self) -> None:
        # Valid JSON padded with whitespace to exactly the limit.
        raw = _ollama_body()
        body = raw + b" " * (MAX_RESPONSE_BYTES - len(raw))
        assert len(body) == MAX_RESPONSE_BYTES
        answer = _ollama(FakeSession(FakeResponse(body))).complete(SYSTEM, USER, SCHEMA)
        assert answer == '{"verdict": "benign"}'

    def test_read_error_during_body_raises_provider_error(self) -> None:
        response = FakeResponse(read_error=requests.ConnectionError("reset " + USER))
        with pytest.raises(TriageProviderError) as info:
            _ollama(FakeSession(response)).complete(SYSTEM, USER, SCHEMA)
        assert "ConnectionError" in str(info.value)
        assert response.closed is True

    @pytest.mark.parametrize("endpoint", ["ftp://llm.test", "llm.test:11434", "", "file:///etc"])
    def test_non_http_endpoint_rejected_by_constructor(self, endpoint: str) -> None:
        with pytest.raises(TriageProviderError, match="http"):
            OllamaProvider(endpoint, "m", 5.0, 100)

    def test_non_string_endpoint_rejected_by_constructor(self) -> None:
        with pytest.raises(TriageProviderError):
            OllamaProvider(None, "m", 5.0, 100)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "outcome",
        [
            requests.ConnectionError(USER),
            requests.Timeout(USER),
            FakeResponse(b"{}", status_code=500),
            FakeResponse(b"not json"),
            FakeResponse(b"{}"),
            FakeResponse(_ollama_body("")),
            FakeResponse(b" " * (MAX_RESPONSE_BYTES + 1)),
        ],
    )
    def test_error_messages_never_contain_prompt_text(
        self, outcome: FakeResponse | Exception
    ) -> None:
        with pytest.raises(TriageProviderError) as info:
            _ollama(FakeSession(outcome)).complete(SYSTEM, USER, SCHEMA)
        message = str(info.value)
        assert SYSTEM not in message
        assert "USER-PROMPT-MARKER" not in message
        assert "failed password" not in message


# --------------------------------------------------------------------------- OpenAI


class TestOpenAICompatProvider:
    def test_complete_posts_to_chat_completions_and_returns_content(self) -> None:
        session = FakeSession(FakeResponse(_openai_body('{"verdict": "suspicious"}')))
        answer = _openai(session).complete(SYSTEM, USER, SCHEMA)
        assert answer == '{"verdict": "suspicious"}'
        assert session.calls[0]["url"] == "https://llm.test/v1/chat/completions"

    def test_trailing_slash_in_endpoint_is_stripped(self) -> None:
        session = FakeSession(FakeResponse(_openai_body()))
        _openai(session, "https://llm.test/").complete(SYSTEM, USER, SCHEMA)
        assert session.calls[0]["url"] == "https://llm.test/v1/chat/completions"

    def test_payload_has_messages_model_and_limits(self) -> None:
        session = FakeSession(FakeResponse(_openai_body()))
        _openai(session).complete(SYSTEM, USER, SCHEMA)
        payload = session.calls[0]["json"]
        assert payload["model"] == "model-y"
        assert payload["temperature"] == 0
        assert payload["max_tokens"] == 222
        assert payload["messages"] == [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": USER},
        ]

    def test_payload_response_format_is_strict_json_schema(self) -> None:
        session = FakeSession(FakeResponse(_openai_body()))
        _openai(session).complete(SYSTEM, USER, SCHEMA)
        response_format = session.calls[0]["json"]["response_format"]
        assert response_format["type"] == "json_schema"
        assert response_format["json_schema"]["strict"] is True
        assert response_format["json_schema"]["schema"] == SCHEMA

    def test_redirects_disabled_timeout_and_streaming_passed(self) -> None:
        session = FakeSession(FakeResponse(_openai_body()))
        _openai(session).complete(SYSTEM, USER, SCHEMA)
        call = session.calls[0]
        assert call["allow_redirects"] is False
        assert call["timeout"] == 7.0
        assert call["stream"] is True

    def test_bearer_header_sent_when_key_is_set(self) -> None:
        session = FakeSession(FakeResponse(_openai_body()))
        _openai(session, api_key=FAKE_KEY).complete(SYSTEM, USER, SCHEMA)
        assert session.calls[0]["headers"]["Authorization"] == f"Bearer {FAKE_KEY}"

    def test_no_authorization_header_when_key_is_empty(self) -> None:
        session = FakeSession(FakeResponse(_openai_body()))
        _openai(session, api_key="").complete(SYSTEM, USER, SCHEMA)
        assert "Authorization" not in session.calls[0]["headers"]

    def test_repr_does_not_contain_api_key(self) -> None:
        provider = _openai(FakeSession(FakeResponse(_openai_body())), api_key=FAKE_KEY)
        assert FAKE_KEY not in repr(provider)

    def test_only_first_choice_is_used(self) -> None:
        body = json.dumps(
            {
                "choices": [
                    {"message": {"content": "first"}},
                    {"message": {"content": "second"}},
                ]
            }
        ).encode()
        assert _openai(FakeSession(FakeResponse(body))).complete(SYSTEM, USER, SCHEMA) == "first"

    @pytest.mark.parametrize(
        "body",
        [
            b"{}",
            b'{"choices": []}',
            b'{"choices": "x"}',
            b'{"choices": [null]}',
            b'{"choices": ["text"]}',
            b'{"choices": [{}]}',
            b'{"choices": [{"message": "text"}]}',
            b'{"choices": [{"message": null}]}',
            b'{"choices": [{"message": {}}]}',
            b'{"choices": [{"message": {"content": ""}}]}',
            b'{"choices": [{"message": {"content": "  "}}]}',
            b'{"choices": [{"message": {"content": null}}]}',
            b'{"choices": [{"message": {"content": 5}}]}',
            b"[]",
            b"null",
        ],
    )
    def test_odd_envelope_raises_provider_error(self, body: bytes) -> None:
        with pytest.raises(TriageProviderError):
            _openai(FakeSession(FakeResponse(body))).complete(SYSTEM, USER, SCHEMA)

    @pytest.mark.parametrize(
        "outcome",
        [
            requests.ConnectionError(f"failed for Bearer {FAKE_KEY} {USER}"),
            requests.Timeout(f"{FAKE_KEY} {USER}"),
            FakeResponse(b"{}", status_code=401),
            FakeResponse(b"{}", status_code=500),
            FakeResponse(b"not json"),
            FakeResponse(b"{}"),
            FakeResponse(b" " * (MAX_RESPONSE_BYTES + 1)),
        ],
    )
    def test_errors_never_leak_key_or_prompt(self, outcome: FakeResponse | Exception) -> None:
        provider = _openai(FakeSession(outcome), api_key=FAKE_KEY)
        with pytest.raises(TriageProviderError) as info:
            provider.complete(SYSTEM, USER, SCHEMA)
        message = str(info.value)
        assert FAKE_KEY not in message
        assert "Bearer" not in message
        assert "USER-PROMPT-MARKER" not in message
        assert SYSTEM not in message

    def test_provider_error_does_not_chain_original_exception(self) -> None:
        session = FakeSession(requests.ConnectionError(f"Bearer {FAKE_KEY}"))
        with pytest.raises(TriageProviderError) as info:
            _openai(session, api_key=FAKE_KEY).complete(SYSTEM, USER, SCHEMA)
        assert info.value.__cause__ is None
        assert info.value.__suppress_context__ is True

    def test_non_http_endpoint_rejected_by_constructor(self) -> None:
        with pytest.raises(TriageProviderError, match="http"):
            OpenAICompatProvider("ftp://llm.test", "m", 5.0, 100, api_key=FAKE_KEY)

    def test_endpoint_error_does_not_contain_api_key(self) -> None:
        with pytest.raises(TriageProviderError) as info:
            OpenAICompatProvider("gopher://x", "m", 5.0, 100, api_key=FAKE_KEY)
        assert FAKE_KEY not in str(info.value)


# --------------------------------------------------------------------------- factory


class TestCreateProvider:
    def test_ollama_provider_selected(self) -> None:
        provider = create_provider(LLMConfig(provider="ollama"))
        assert isinstance(provider, OllamaProvider)
        assert provider.name == "ollama"

    def test_openai_provider_selected_with_key(self) -> None:
        session = FakeSession(FakeResponse(_openai_body()))
        config = LLMConfig(provider="openai", endpoint="https://api.test", api_key=FAKE_KEY)
        provider = create_provider(config, session=session)  # type: ignore[arg-type]
        assert isinstance(provider, OpenAICompatProvider)
        provider.complete(SYSTEM, USER, SCHEMA)
        assert session.calls[0]["headers"]["Authorization"] == f"Bearer {FAKE_KEY}"

    def test_config_values_are_forwarded(self) -> None:
        session = FakeSession(FakeResponse(_ollama_body()))
        config = LLMConfig(
            endpoint="http://cfg.test:1/", model="cfg-model", timeout_seconds=3.0, max_tokens=55
        )
        provider = create_provider(config, session=session)  # type: ignore[arg-type]
        provider.complete(SYSTEM, USER, SCHEMA)
        call = session.calls[0]
        assert provider.model == "cfg-model"
        assert call["url"] == "http://cfg.test:1/api/chat"
        assert call["timeout"] == 3.0
        assert call["json"]["options"]["num_predict"] == 55

    def test_unknown_provider_raises_provider_error(self) -> None:
        config = LLMConfig()
        config.provider = "anthropic"
        with pytest.raises(TriageProviderError, match="Unknown LLM provider"):
            create_provider(config)

    def test_bad_endpoint_in_config_raises_provider_error(self) -> None:
        with pytest.raises(TriageProviderError):
            create_provider(LLMConfig(endpoint="ftp://x"))


# --------------------------------------------------------------------------- config


class TestLLMConfigValidation:
    def test_defaults_are_valid(self) -> None:
        LLMConfig().validate()

    def test_enabled_defaults_are_valid(self) -> None:
        LLMConfig(enabled=True).validate()

    @pytest.mark.parametrize("provider", ["ollama", "openai"])
    def test_known_providers_accepted(self, provider: str) -> None:
        LLMConfig(provider=provider).validate()

    @pytest.mark.parametrize("provider", ["", "OpenAI", "anthropic", "ollama "])
    def test_unknown_provider_rejected(self, provider: str) -> None:
        with pytest.raises(ConfigError, match="provider"):
            LLMConfig(provider=provider).validate()

    @pytest.mark.parametrize("language", ["en", "tr", "de"])
    def test_supported_languages_accepted(self, language: str) -> None:
        LLMConfig(language=language).validate()

    @pytest.mark.parametrize("language", ["", "fr", "EN", "english"])
    def test_unsupported_language_rejected(self, language: str) -> None:
        with pytest.raises(ConfigError, match="language"):
            LLMConfig(language=language).validate()

    @pytest.mark.parametrize("retries", [0, 1, 2, 3])
    def test_max_retries_in_range_accepted(self, retries: int) -> None:
        LLMConfig(max_retries=retries).validate()

    @pytest.mark.parametrize("retries", [-1, 4, 100, True, 1.5, "1", None])
    def test_max_retries_out_of_range_or_wrong_type_rejected(self, retries: Any) -> None:
        with pytest.raises(ConfigError, match="max_retries"):
            LLMConfig(max_retries=retries).validate()

    @pytest.mark.parametrize("backoff", [0, 0.0, 0.5, 1, 30])
    def test_retry_backoff_valid_values_accepted(self, backoff: float) -> None:
        LLMConfig(retry_backoff_seconds=backoff).validate()

    @pytest.mark.parametrize(
        "backoff", [-0.1, -1, float("nan"), float("inf"), float("-inf"), True, "1", None]
    )
    def test_retry_backoff_invalid_values_rejected(self, backoff: Any) -> None:
        with pytest.raises(ConfigError, match="retry_backoff_seconds"):
            LLMConfig(retry_backoff_seconds=backoff).validate()

    @pytest.mark.parametrize("ttl", [0, 1, 3600])
    def test_cache_ttl_valid_values_accepted(self, ttl: int) -> None:
        LLMConfig(cache_ttl_seconds=ttl).validate()

    @pytest.mark.parametrize("ttl", [-1, 1.5, True, "60", None])
    def test_cache_ttl_invalid_values_rejected(self, ttl: Any) -> None:
        with pytest.raises(ConfigError, match="cache_ttl_seconds"):
            LLMConfig(cache_ttl_seconds=ttl).validate()

    @pytest.mark.parametrize("api_key", [123, None, b"key", ["k"]])
    def test_non_string_api_key_rejected(self, api_key: Any) -> None:
        with pytest.raises(ConfigError, match="api_key"):
            LLMConfig(api_key=api_key).validate()

    def test_string_api_key_accepted(self) -> None:
        LLMConfig(api_key=FAKE_KEY).validate()

    def test_empty_api_key_accepted(self) -> None:
        LLMConfig(api_key="").validate()

    def test_enabled_with_non_http_endpoint_rejected(self) -> None:
        with pytest.raises(ConfigError, match="endpoint"):
            LLMConfig(enabled=True, endpoint="ftp://x").validate()

    @pytest.mark.parametrize("timeout", [0, -1.0])
    def test_non_positive_timeout_rejected(self, timeout: float) -> None:
        with pytest.raises(ConfigError, match="timeout_seconds"):
            LLMConfig(timeout_seconds=timeout).validate()

    @pytest.mark.parametrize("tokens", [0, -5])
    def test_non_positive_max_tokens_rejected(self, tokens: int) -> None:
        with pytest.raises(ConfigError, match="max_tokens"):
            LLMConfig(max_tokens=tokens).validate()


# --------------------------------------------------------------------------- cache

T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


class Clock:
    """Mutable injectable clock."""

    def __init__(self, start: datetime = T0) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


def _result(**overrides: Any) -> TriageResult:
    values: dict[str, Any] = {
        "verdict": "suspicious",
        "confidence": 0.8,
        "summary": "Repeated failed logins from one address.",
        "reasoning": "Many failures in a short window; ozet: sifre denemesi.",
        "recommended_actions": ("block ip", "reset password"),
        "referenced_event_ids": (1, 3),
    }
    values.update(overrides)
    return TriageResult(**values)


KEY = ("fp-1", "model-a", "en", "sha-1")


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "cache" / "triage.db"


@pytest.fixture()
def cache(db_path: Path, clock: Clock) -> Iterator[TriageCache]:
    instance = TriageCache(db_path, ttl_seconds=100, now=clock)
    yield instance
    instance.close()


def _raw_exec(db_path: Path, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(sql, params).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


class TestTriageCache:
    def test_put_then_get_returns_equal_result(self, cache: TriageCache) -> None:
        result = _result()
        cache.put(*KEY, result)
        assert cache.get(*KEY) == result

    def test_roundtrip_preserves_tuples(self, cache: TriageCache) -> None:
        cache.put(*KEY, _result())
        loaded = cache.get(*KEY)
        assert loaded is not None
        assert isinstance(loaded.recommended_actions, tuple)
        assert isinstance(loaded.referenced_event_ids, tuple)

    def test_roundtrip_with_empty_tuples(self, cache: TriageCache) -> None:
        result = _result(recommended_actions=(), referenced_event_ids=())
        cache.put(*KEY, result)
        assert cache.get(*KEY) == result

    def test_roundtrip_preserves_unicode(self, cache: TriageCache) -> None:
        result = _result(summary="Şüpheli giriş denemesi", reasoning="Grüße, İstanbul")
        cache.put(*KEY, result)
        assert cache.get(*KEY) == result

    def test_get_on_empty_cache_is_miss(self, cache: TriageCache) -> None:
        assert cache.get(*KEY) is None

    @pytest.mark.parametrize(
        "other",
        [
            ("fp-2", "model-a", "en", "sha-1"),
            ("fp-1", "model-b", "en", "sha-1"),
            ("fp-1", "model-a", "tr", "sha-1"),
            ("fp-1", "model-a", "en", "sha-2"),
        ],
    )
    def test_different_key_part_is_miss(
        self, cache: TriageCache, other: tuple[str, str, str, str]
    ) -> None:
        cache.put(*KEY, _result())
        assert cache.get(*other) is None

    def test_entry_within_ttl_is_hit(self, cache: TriageCache, clock: Clock) -> None:
        cache.put(*KEY, _result())
        clock.advance(100)
        assert cache.get(*KEY) is not None

    def test_entry_past_ttl_is_miss(self, cache: TriageCache, clock: Clock) -> None:
        cache.put(*KEY, _result())
        clock.advance(101)
        assert cache.get(*KEY) is None

    def test_expired_entry_is_deleted_on_get(
        self, cache: TriageCache, clock: Clock, db_path: Path
    ) -> None:
        cache.put(*KEY, _result())
        clock.advance(500)
        cache.get(*KEY)
        assert _raw_exec(db_path, "SELECT COUNT(*) FROM triage_cache") == [(0,)]

    def test_ttl_zero_get_returns_none(self, db_path: Path, clock: Clock) -> None:
        zero = TriageCache(db_path, ttl_seconds=0, now=clock)
        try:
            zero.put(*KEY, _result())
            assert zero.get(*KEY) is None
        finally:
            zero.close()

    def test_ttl_zero_put_stores_nothing(self, db_path: Path, clock: Clock) -> None:
        zero = TriageCache(db_path, ttl_seconds=0, now=clock)
        try:
            zero.put(*KEY, _result())
        finally:
            zero.close()
        assert _raw_exec(db_path, "SELECT COUNT(*) FROM triage_cache") == [(0,)]

    def test_ttl_zero_purge_returns_zero(self, db_path: Path, clock: Clock) -> None:
        zero = TriageCache(db_path, ttl_seconds=0, now=clock)
        try:
            assert zero.purge_expired() == 0
        finally:
            zero.close()

    def test_negative_ttl_behaves_as_disabled(self, db_path: Path, clock: Clock) -> None:
        negative = TriageCache(db_path, ttl_seconds=-5, now=clock)
        try:
            negative.put(*KEY, _result())
            assert negative.get(*KEY) is None
        finally:
            negative.close()

    def test_purge_expired_counts_only_expired_rows(
        self, cache: TriageCache, clock: Clock
    ) -> None:
        cache.put("old-1", "m", "en", "s", _result())
        cache.put("old-2", "m", "en", "s", _result())
        clock.advance(80)
        cache.put("fresh", "m", "en", "s", _result())
        clock.advance(30)  # old rows are 110s old, fresh is 30s old
        assert cache.purge_expired() == 2
        assert cache.get("fresh", "m", "en", "s") is not None
        assert cache.get("old-1", "m", "en", "s") is None

    def test_purge_expired_with_nothing_expired_returns_zero(
        self, cache: TriageCache, clock: Clock
    ) -> None:
        cache.put(*KEY, _result())
        clock.advance(10)
        assert cache.purge_expired() == 0

    def test_purge_expired_on_empty_cache_returns_zero(self, cache: TriageCache) -> None:
        assert cache.purge_expired() == 0

    @pytest.mark.parametrize(
        "bad_json",
        [
            "not json at all",
            "[]",
            "null",
            json.dumps({"verdict": "unknown", "confidence": 0.5, "summary": "s",
                        "reasoning": "r", "recommended_actions": [],
                        "referenced_event_ids": []}),
            json.dumps({"verdict": "benign", "confidence": 7, "summary": "s",
                        "reasoning": "r", "recommended_actions": [],
                        "referenced_event_ids": []}),
            json.dumps({"verdict": "benign", "confidence": True, "summary": "s",
                        "reasoning": "r", "recommended_actions": [],
                        "referenced_event_ids": []}),
            json.dumps({"verdict": "benign", "confidence": 0.5, "summary": "s",
                        "reasoning": "r", "recommended_actions": [1],
                        "referenced_event_ids": []}),
            json.dumps({"verdict": "benign", "confidence": 0.5, "summary": "s",
                        "reasoning": "r", "recommended_actions": [],
                        "referenced_event_ids": ["1"]}),
            json.dumps({"verdict": "benign"}),
        ],
    )
    def test_corrupt_row_is_miss_and_deleted(
        self, cache: TriageCache, db_path: Path, clock: Clock, bad_json: str
    ) -> None:
        cache.put(*KEY, _result())
        _raw_exec(db_path, "UPDATE triage_cache SET result = ?", (bad_json,))
        assert cache.get(*KEY) is None
        assert _raw_exec(db_path, "SELECT COUNT(*) FROM triage_cache") == [(0,)]

    def test_corrupt_timestamp_is_miss_and_deleted(
        self, cache: TriageCache, db_path: Path
    ) -> None:
        cache.put(*KEY, _result())
        _raw_exec(db_path, "UPDATE triage_cache SET created_at = 'garbage'")
        assert cache.get(*KEY) is None
        assert _raw_exec(db_path, "SELECT COUNT(*) FROM triage_cache") == [(0,)]

    def test_put_same_key_replaces_previous_entry(
        self, cache: TriageCache, db_path: Path
    ) -> None:
        cache.put(*KEY, _result(verdict="benign"))
        cache.put(*KEY, _result(verdict="malicious"))
        loaded = cache.get(*KEY)
        assert loaded is not None
        assert loaded.verdict == "malicious"
        assert _raw_exec(db_path, "SELECT COUNT(*) FROM triage_cache") == [(1,)]

    def test_replace_refreshes_the_ttl(self, cache: TriageCache, clock: Clock) -> None:
        cache.put(*KEY, _result())
        clock.advance(90)
        cache.put(*KEY, _result())
        clock.advance(90)  # 180s after the first put, 90s after the second
        assert cache.get(*KEY) is not None

    def test_sql_injection_in_fingerprint_is_stored_literally(
        self, cache: TriageCache, db_path: Path
    ) -> None:
        evil = "'; DROP TABLE triage_cache;--"
        result = _result()
        cache.put(evil, "model-a", "en", "sha-1", result)
        assert cache.get(evil, "model-a", "en", "sha-1") == result
        tables = _raw_exec(
            db_path, "SELECT name FROM sqlite_master WHERE type='table' AND name='triage_cache'"
        )
        assert tables == [("triage_cache",)]
        assert _raw_exec(db_path, "SELECT fingerprint FROM triage_cache") == [(evil,)]

    def test_sql_injection_in_model_and_language_does_not_match_others(
        self, cache: TriageCache
    ) -> None:
        cache.put(*KEY, _result())
        assert cache.get("fp-1", "' OR '1'='1", "en", "sha-1") is None
        assert cache.get("fp-1", "model-a", "en' OR '1'='1", "sha-1") is None

    def test_data_persists_across_instances(self, db_path: Path, clock: Clock) -> None:
        first = TriageCache(db_path, ttl_seconds=100, now=clock)
        first.put(*KEY, _result())
        first.close()
        second = TriageCache(db_path, ttl_seconds=100, now=clock)
        try:
            assert second.get(*KEY) == _result()
        finally:
            second.close()

    def test_parent_directory_is_created(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b" / "c.db"
        TriageCache(nested, ttl_seconds=10).close()
        assert nested.exists()

    def test_default_clock_roundtrip_hits(self, tmp_path: Path) -> None:
        real = TriageCache(tmp_path / "real.db", ttl_seconds=60)
        try:
            real.put(*KEY, _result())
            assert real.get(*KEY) == _result()
        finally:
            real.close()


class TestPromptSha:
    def test_prompt_sha_is_stable(self) -> None:
        assert prompt_sha("sys", "usr") == prompt_sha("sys", "usr")

    def test_prompt_sha_is_64_hex_chars(self) -> None:
        digest = prompt_sha("sys", "usr")
        assert len(digest) == 64
        int(digest, 16)

    def test_prompt_sha_changes_when_system_changes(self) -> None:
        assert prompt_sha("sys-1", "usr") != prompt_sha("sys-2", "usr")

    def test_prompt_sha_changes_when_user_changes(self) -> None:
        assert prompt_sha("sys", "usr-1") != prompt_sha("sys", "usr-2")

    def test_prompt_sha_boundary_is_unambiguous(self) -> None:
        assert prompt_sha("ab", "c") != prompt_sha("a", "bc")

    def test_prompt_sha_swapped_parts_differ(self) -> None:
        assert prompt_sha("a", "b") != prompt_sha("b", "a")

    def test_prompt_sha_handles_empty_and_lone_surrogates(self) -> None:
        assert prompt_sha("", "") != prompt_sha("x", "")
        assert len(prompt_sha("\ud800", "\udfff")) == 64
