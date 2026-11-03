"""Security-hardening regression tests for the triage pipeline.

Covers ReDoS resistance, provider failure classification and transport
hardening, LLMConfig validation, cache row validation, AIEngine lifecycle and
terminal-injection-safe console rendering.
"""

from __future__ import annotations

import io
import json
import re
import sqlite3
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import requests
from rich.console import Console

from sentinelai.ai.engine import AIEngine
from sentinelai.ai.triage import parse_triage, sanitize_text
from sentinelai.ai.triage_cache import TriageCache
from sentinelai.ai.triage_engine import TriageEngine
from sentinelai.ai.triage_models import (
    TriageProviderError,
    TriageResult,
    TriageValidationError,
    api_key_endpoint_allowed,
)
from sentinelai.ai.triage_providers import (
    MAX_RESPONSE_BYTES,
    OllamaProvider,
    OpenAICompatProvider,
)
from sentinelai.cli import console as console_module
from sentinelai.config.models import AIConfig, LLMConfig
from sentinelai.core.exceptions import ConfigError
from sentinelai.core.models import AIInsight, Alert, IPReputation, RiskFactor
from sentinelai.detection.base import available_rules
from sentinelai.risk.engine import RiskEngine
from tests.conftest import make_event

SCHEMA: dict[str, Any] = {"type": "object"}
MAX_SECONDS = 2.0
T0 = datetime(2025, 1, 1, tzinfo=timezone.utc)


def _valid_answer(**overrides: Any) -> str:
    data: dict[str, Any] = {
        "verdict": "suspicious",
        "confidence": 0.7,
        "summary": "Repeated failed logins.",
        "reasoning": "Many failures from one address.",
        "recommended_actions": ["Block the source IP."],
        "referenced_event_ids": [1],
    }
    data.update(overrides)
    return json.dumps(data)


def _alert() -> Alert:
    import sentinelai.detection.rules  # noqa: F401  (registers built-in rules)

    rule = available_rules()["R001"]()
    events = [
        make_event(offset=i, ip="203.0.113.9", user="alice", message=f"fail {i}")
        for i in range(3)
    ]
    alert = rule.make_alert(events[-1], "Brute force", "Many failed logins", events=events)
    RiskEngine().score(alert)
    return alert


# -- fakes -----------------------------------------------------------------


class FakeResponse:
    def __init__(
        self, body: bytes = b"", status_code: int = 200, chunks: list[bytes] | None = None
    ) -> None:
        self.status_code = status_code
        self._body = body
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
        if self._chunks is not None:
            yield from self._chunks
            return
        for start in range(0, len(self._body), chunk_size):
            yield self._body[start : start + chunk_size]

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, outcome: FakeResponse | Exception) -> None:
        self.outcome = outcome
        self.close_calls = 0

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome

    def close(self) -> None:
        self.close_calls += 1


def _ollama_body(content: Any = '{"verdict": "benign"}') -> bytes:
    return json.dumps({"message": {"role": "assistant", "content": content}}).encode()


def _openai_body(content: Any = '{"verdict": "benign"}') -> bytes:
    return json.dumps({"choices": [{"message": {"content": content}}]}).encode()


def _ollama(session: Any, endpoint: str = "http://localhost:11434") -> OllamaProvider:
    return OllamaProvider(endpoint, "m", 10.0, 100, session=session)


def _openai(session: Any, endpoint: str = "https://llm.test") -> OpenAICompatProvider:
    return OpenAICompatProvider(endpoint, "m", 10.0, 100, session=session)


def _complete_error(provider: Any) -> TriageProviderError:
    with pytest.raises(TriageProviderError) as info:
        provider.complete("sys", "usr", SCHEMA)
    return info.value


# -- (a) ReDoS regression ----------------------------------------------------


class TestRedosRegression:
    def test_parse_triage_long_whitespace_after_fence_is_fast_and_rejected(self) -> None:
        start = time.perf_counter()
        with pytest.raises(TriageValidationError):
            parse_triage("```" + " " * 20000 + "x", 1)
        assert time.perf_counter() - start < MAX_SECONDS

    def test_sanitize_text_repeated_marker_fragments_is_fast(self) -> None:
        payload = "<<<" * 1800 + "LOG_DATA" * 1800
        start = time.perf_counter()
        result = sanitize_text(payload)
        assert time.perf_counter() - start < MAX_SECONDS
        assert re.search(r"<<<\s*LOG_DATA|LOG_DATA\s*>>>", result, re.IGNORECASE) is None
        assert len(result) <= 300

    def test_parse_triage_deeply_nested_brackets_is_rejected_quickly(self) -> None:
        start = time.perf_counter()
        with pytest.raises(TriageValidationError):
            parse_triage("[" * 20000, 1)
        assert time.perf_counter() - start < MAX_SECONDS

    def test_json_fenced_answer_still_parses(self) -> None:
        result = parse_triage(f"```json\n{_valid_answer()}\n```", 1)
        assert result.verdict == "suspicious"

    def test_plain_fenced_answer_still_parses(self) -> None:
        result = parse_triage(f"```\n{_valid_answer()}\n```", 1)
        assert result.referenced_event_ids == (1,)

    def test_unterminated_fence_is_rejected(self) -> None:
        with pytest.raises(TriageValidationError):
            parse_triage("```json\n" + _valid_answer(), 1)


# -- (b) providers -----------------------------------------------------------


class TestTransientClassification:
    @pytest.mark.parametrize("status", [429, 500, 502, 503])
    def test_retryable_http_status_is_transient(self, status: int) -> None:
        error = _complete_error(_ollama(FakeSession(FakeResponse(b"{}", status))))
        assert error.transient is True

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 302])
    def test_permanent_http_status_is_not_transient(self, status: int) -> None:
        error = _complete_error(_openai(FakeSession(FakeResponse(b"{}", status))))
        assert error.transient is False

    def test_non_json_body_is_not_transient(self) -> None:
        error = _complete_error(_ollama(FakeSession(FakeResponse(b"<html>nope"))))
        assert error.transient is False

    def test_bad_ollama_envelope_is_not_transient(self) -> None:
        body = json.dumps({"unexpected": 1}).encode()
        assert _complete_error(_ollama(FakeSession(FakeResponse(body)))).transient is False

    def test_bad_openai_envelope_is_not_transient(self) -> None:
        body = json.dumps({"choices": []}).encode()
        assert _complete_error(_openai(FakeSession(FakeResponse(body)))).transient is False

    def test_oversize_response_is_not_transient(self) -> None:
        body = b"x" * (MAX_RESPONSE_BYTES + 1)
        error = _complete_error(_ollama(FakeSession(FakeResponse(body))))
        assert error.transient is False
        assert "size limit" in str(error)

    @pytest.mark.parametrize(
        "exc",
        [requests.exceptions.ConnectionError("x"), requests.exceptions.Timeout("x")],
        ids=["connection", "timeout"],
    )
    def test_network_error_is_transient(self, exc: Exception) -> None:
        assert _complete_error(_ollama(FakeSession(exc))).transient is True

    def test_invalid_url_error_is_not_transient(self) -> None:
        error = _complete_error(_ollama(FakeSession(requests.exceptions.InvalidURL("x"))))
        assert error.transient is False

    def test_good_response_returns_content(self) -> None:
        provider = _openai(FakeSession(FakeResponse(_openai_body("hello"))))
        assert provider.complete("sys", "usr", SCHEMA) == "hello"


class TestSlowDrip:
    def test_deadline_exceeded_while_streaming_raises_transient_too_slow(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        readings = iter([0.0])

        def fake_monotonic() -> float:
            return next(readings, 10_000.0)  # first call sets the deadline, then jump

        monkeypatch.setattr(
            "sentinelai.ai.triage_providers.time", SimpleNamespace(monotonic=fake_monotonic)
        )
        response = FakeResponse(chunks=[b"{", b'"a"', b":1"])
        error = _complete_error(_ollama(FakeSession(response)))
        assert str(error) == "response too slow"
        assert error.transient is True
        assert response.closed is True

    def test_response_within_deadline_is_read_normally(self) -> None:
        provider = _ollama(FakeSession(FakeResponse(_ollama_body("fine"))))
        assert provider.complete("sys", "usr", SCHEMA) == "fine"

    def test_read_error_while_streaming_is_transient(self) -> None:
        class Broken(FakeResponse):
            def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
                raise requests.exceptions.ChunkedEncodingError("cut")
                yield b""  # pragma: no cover

        error = _complete_error(_ollama(FakeSession(Broken())))
        assert error.transient is True


class TestSessionHandling:
    def test_self_created_session_ignores_environment(self) -> None:
        provider = OllamaProvider("http://localhost:11434", "m", 10.0, 100)
        try:
            assert provider._session.trust_env is False  # noqa: SLF001
        finally:
            provider.close()

    def test_self_created_openai_session_ignores_environment(self) -> None:
        provider = OpenAICompatProvider("https://llm.test", "m", 10.0, 100)
        try:
            assert provider._session.trust_env is False  # noqa: SLF001
        finally:
            provider.close()

    def test_injected_session_is_left_untouched(self) -> None:
        session = requests.Session()
        try:
            default = session.trust_env
            provider = _ollama(session)
            assert provider._session is session  # noqa: SLF001
            assert session.trust_env is default
        finally:
            session.close()

    def test_close_closes_self_created_session(self, monkeypatch: pytest.MonkeyPatch) -> None:
        provider = OllamaProvider("http://localhost:11434", "m", 10.0, 100)
        closed: list[bool] = []
        monkeypatch.setattr(provider._session, "close", lambda: closed.append(True))  # noqa: SLF001
        provider.close()
        assert closed == [True]

    def test_close_leaves_injected_session_open(self) -> None:
        session = FakeSession(FakeResponse())
        _ollama(session).close()
        _openai(session).close()
        assert session.close_calls == 0


class TestApiKeyTransportRules:
    def test_key_over_plain_http_to_remote_host_is_refused(self) -> None:
        with pytest.raises(TriageProviderError):
            OpenAICompatProvider("http://remote.example", "m", 10.0, 100, api_key="k")

    @pytest.mark.parametrize(
        "endpoint",
        [
            "https://remote.example",
            "http://localhost:11434",
            "http://127.0.0.1:1234",
            "http://[::1]:8080",
        ],
    )
    def test_key_is_accepted_for_https_and_loopback(self, endpoint: str) -> None:
        provider = OpenAICompatProvider(endpoint, "m", 10.0, 100, api_key="k")
        provider.close()

    def test_no_key_over_plain_http_is_fine(self) -> None:
        OpenAICompatProvider("http://remote.example", "m", 10.0, 100).close()

    def test_refusal_message_does_not_contain_key(self) -> None:
        with pytest.raises(TriageProviderError) as info:
            OpenAICompatProvider("http://remote.example", "m", 10.0, 100, api_key="TOPSECRET")
        assert "TOPSECRET" not in str(info.value)

    def test_provider_repr_does_not_contain_key(self) -> None:
        provider = OpenAICompatProvider("https://llm.test", "m", 10.0, 100, api_key="TOPSECRET")
        provider.close()
        assert "TOPSECRET" not in repr(provider)


class TestJsonRecursion:
    def test_recursion_error_from_json_loads_becomes_provider_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(_body: bytes) -> Any:
            raise RecursionError("too deep")

        monkeypatch.setattr("sentinelai.ai.triage_providers.json", SimpleNamespace(loads=boom))
        error = _complete_error(_ollama(FakeSession(FakeResponse(b"{}"))))
        assert error.transient is False

    def test_real_deeply_nested_body_becomes_provider_error(self) -> None:
        body = b"[" * 200_000
        error = _complete_error(_ollama(FakeSession(FakeResponse(body))))
        assert isinstance(error, TriageProviderError)


# -- (c) LLMConfig -----------------------------------------------------------


class TestLLMConfigHardening:
    def test_repr_hides_api_key(self) -> None:
        assert "secret" not in repr(LLMConfig(api_key="secret"))

    @pytest.mark.parametrize(
        "timeout", [float("inf"), float("nan"), 0, -1, 601], ids=["inf", "nan", "0", "neg", "601"]
    )
    def test_invalid_timeout_is_rejected(self, timeout: float) -> None:
        with pytest.raises(ConfigError, match=r"ai\.llm\.timeout_seconds"):
            LLMConfig(timeout_seconds=timeout).validate()

    @pytest.mark.parametrize("timeout", [0.5, 60, 600])
    def test_valid_timeout_is_accepted(self, timeout: float) -> None:
        LLMConfig(timeout_seconds=timeout).validate()

    def test_backoff_above_cap_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match=r"ai\.llm\.retry_backoff_seconds"):
            LLMConfig(retry_backoff_seconds=61).validate()

    @pytest.mark.parametrize("backoff", [float("nan"), float("inf"), -1])
    def test_non_finite_or_negative_backoff_is_rejected(self, backoff: float) -> None:
        with pytest.raises(ConfigError, match=r"ai\.llm\.retry_backoff_seconds"):
            LLMConfig(retry_backoff_seconds=backoff).validate()

    def test_backoff_at_cap_is_accepted(self) -> None:
        LLMConfig(retry_backoff_seconds=60).validate()

    @pytest.mark.parametrize("endpoint", ["http://remote.example", "http://10.0.0.5:8000"])
    def test_api_key_with_plain_http_remote_endpoint_is_rejected(self, endpoint: str) -> None:
        with pytest.raises(ConfigError, match=r"ai\.llm\."):
            LLMConfig(endpoint=endpoint, api_key="k").validate()

    @pytest.mark.parametrize(
        "endpoint", ["https://remote.example", "http://localhost:11434", "http://127.0.0.1:1"]
    )
    def test_api_key_with_https_or_loopback_is_accepted(self, endpoint: str) -> None:
        LLMConfig(endpoint=endpoint, api_key="k").validate()

    def test_plain_http_remote_without_key_is_accepted(self) -> None:
        LLMConfig(endpoint="http://remote.example").validate()

    @pytest.mark.parametrize(
        ("endpoint", "expected"),
        [
            ("https://api.example.com", True),
            ("HTTPS://api.example.com/v1", True),
            ("http://localhost", True),
            ("http://localhost:11434", True),
            ("http://127.0.0.1:8080", True),
            ("http://127.5.5.5", True),
            ("http://[::1]:8080", True),
            ("https://localhost", True),
            ("http://example.com", False),
            ("http://10.0.0.1", False),
            ("http://192.168.1.1:80", False),
            ("http://localhost.evil.com", False),
            ("http://127.0.0.1.evil.com", False),
            ("ftp://localhost", False),
            ("localhost:11434", False),
            ("https://", False),
            ("http://", False),
            ("", False),
            (None, False),
            (123, False),
        ],
    )
    def test_api_key_endpoint_allowed_truth_table(self, endpoint: Any, expected: bool) -> None:
        assert api_key_endpoint_allowed(endpoint) is expected


# -- (d) cache ---------------------------------------------------------------

KEY = ("fp-1", "model-a", "en", "sha-1")


class Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current


def _result(**overrides: Any) -> TriageResult:
    values: dict[str, Any] = {
        "verdict": "suspicious",
        "confidence": 0.8,
        "summary": "Repeated failed logins.",
        "reasoning": "Many failures in a short window.",
        "recommended_actions": ("block ip",),
        "referenced_event_ids": (1, 3),
    }
    values.update(overrides)
    return TriageResult(**values)


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "triage.db"


@pytest.fixture()
def cache(db_path: Path, clock: Clock) -> Iterator[TriageCache]:
    instance = TriageCache(db_path, ttl_seconds=100, now=clock)
    yield instance
    instance.close()


def _rows(db_path: Path) -> int:
    conn = sqlite3.connect(str(db_path))
    try:
        return int(conn.execute("SELECT COUNT(*) FROM triage_cache").fetchone()[0])
    finally:
        conn.close()


def _tamper(db_path: Path, **changes: Any) -> None:
    """Rewrite the stored result JSON with *changes* applied."""
    conn = sqlite3.connect(str(db_path))
    try:
        (text,) = conn.execute("SELECT result FROM triage_cache").fetchone()
        data = json.loads(text)
        data.update(changes)
        conn.execute("UPDATE triage_cache SET result = ?", (json.dumps(data),))
        conn.commit()
    finally:
        conn.close()


class TestCacheRowValidation:
    def test_untampered_row_is_a_hit(self, cache: TriageCache) -> None:
        cache.put(*KEY, _result())
        assert cache.get(*KEY) == _result()

    @pytest.mark.parametrize(
        "changes",
        [
            {"summary": ""},
            {"summary": "s" * 401},
            {"reasoning": ""},
            {"reasoning": "r" * 1501},
            {"recommended_actions": ["a"] * 6},
            {"recommended_actions": ["x" * 201]},
            {"recommended_actions": [""]},
            {"referenced_event_ids": [1, 1]},
            {"referenced_event_ids": [0]},
            {"referenced_event_ids": [True]},
            {"verdict": "catastrophic"},
            {"confidence": 1.5},
            {"summary": 5},
        ],
        ids=[
            "empty-summary",
            "long-summary",
            "empty-reasoning",
            "long-reasoning",
            "six-actions",
            "long-action",
            "empty-action",
            "duplicate-ids",
            "zero-id",
            "bool-id",
            "bad-verdict",
            "bad-confidence",
            "summary-not-str",
        ],
    )
    def test_row_violating_limits_is_corrupt_deleted_and_a_miss(
        self, cache: TriageCache, db_path: Path, changes: dict[str, Any]
    ) -> None:
        cache.put(*KEY, _result())
        _tamper(db_path, **changes)
        assert cache.get(*KEY) is None
        assert _rows(db_path) == 0

    def test_row_at_exact_limits_is_still_a_hit(self, cache: TriageCache) -> None:
        result = _result(
            summary="s" * 400,
            reasoning="r" * 1500,
            recommended_actions=tuple("a" * 200 for _ in range(5)),
        )
        cache.put(*KEY, result)
        assert cache.get(*KEY) == result

    def test_future_created_at_is_expired_and_deleted(
        self, db_path: Path, clock: Clock
    ) -> None:
        clock.current = T0 + timedelta(hours=1)
        instance = TriageCache(db_path, ttl_seconds=100, now=clock)
        try:
            instance.put(*KEY, _result())
            clock.current = T0  # the stored row now claims to be from the future
            assert instance.get(*KEY) is None
            assert _rows(db_path) == 0
        finally:
            instance.close()


class RecordingCache:
    def __init__(self) -> None:
        self.models: list[str] = []

    def get(self, fingerprint: str, model: str, language: str, digest: str) -> None:
        self.models.append(model)

    def put(self, fingerprint: str, model: str, *args: Any) -> None:
        self.models.append(model)


class _Answering:
    name = "fake"
    model = "irrelevant"

    def complete(self, system: str, user: str, schema: Any) -> str:
        return _valid_answer()


class TestCacheKeyModelComponent:
    @pytest.mark.parametrize(
        ("provider", "endpoint", "model"),
        [
            ("ollama", "http://localhost:11434", "llama3.1"),
            ("openai", "https://api.example.com", "gpt-x"),
        ],
    )
    def test_cache_model_is_provider_endpoint_model(
        self, provider: str, endpoint: str, model: str
    ) -> None:
        recorder = RecordingCache()
        config = LLMConfig(
            enabled=True, provider=provider, endpoint=endpoint, model=model, max_retries=0
        )
        engine = TriageEngine(config, provider=_Answering(), cache=recorder)  # type: ignore[arg-type]
        engine.triage(_alert())
        assert recorder.models == [f"{provider}|{endpoint}|{model}"] * 2

    def test_changing_endpoint_misses_cache(self, tmp_path: Path) -> None:
        shared = TriageCache(tmp_path / "c.db", 3600)
        try:
            alert = _alert()
            first = LLMConfig(enabled=True, endpoint="http://localhost:1", max_retries=0)
            second = LLMConfig(enabled=True, endpoint="http://localhost:2", max_retries=0)
            TriageEngine(first, provider=_Answering(), cache=shared).triage(alert)
            outcome = TriageEngine(second, provider=_Answering(), cache=shared).triage(alert)
            assert outcome.cached is False
        finally:
            shared.close()


# -- (e) AIEngine lifecycle ---------------------------------------------------


def _ai_config() -> AIConfig:
    return AIConfig(enabled=False, llm=LLMConfig(enabled=True, max_retries=0))


class TestAIEngineLifecycle:
    def test_close_is_idempotent(self, tmp_path: Path) -> None:
        engine = AIEngine(_ai_config(), state_dir=tmp_path)
        engine.close()
        engine.close()

    def test_close_closes_triage_engine_and_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        closed: list[str] = []
        original_triage_close = TriageEngine.close
        original_cache_close = TriageCache.close

        def triage_close(self: TriageEngine) -> None:
            closed.append("triage")
            original_triage_close(self)

        def cache_close(self: TriageCache) -> None:
            closed.append("cache")
            original_cache_close(self)

        monkeypatch.setattr(TriageEngine, "close", triage_close)
        monkeypatch.setattr(TriageCache, "close", cache_close)
        engine = AIEngine(_ai_config(), state_dir=tmp_path)
        engine.close()
        engine.close()
        assert closed == ["triage", "cache"]

    def test_cache_connection_is_unusable_after_close(self, tmp_path: Path) -> None:
        engine = AIEngine(_ai_config(), state_dir=tmp_path)
        cache = engine._triage_cache  # noqa: SLF001
        assert cache is not None
        engine.close()
        with pytest.raises(sqlite3.ProgrammingError):
            cache._conn.execute("SELECT 1")  # noqa: SLF001

    def test_purge_expired_is_called_when_cache_opens(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[int] = []
        original: Callable[[TriageCache], int] = TriageCache.purge_expired

        def spy(self: TriageCache) -> int:
            calls.append(1)
            return original(self)

        monkeypatch.setattr(TriageCache, "purge_expired", spy)
        engine = AIEngine(_ai_config(), state_dir=tmp_path)
        try:
            assert calls == [1]
        finally:
            engine.close()

    def test_expired_rows_are_purged_on_open(self, tmp_path: Path) -> None:
        db = tmp_path / "triage_cache.db"
        ancient = datetime.now(timezone.utc) - timedelta(days=365)
        old = TriageCache(db, 604800, now=lambda: ancient)
        old.put(*KEY, _result())
        old.close()
        assert _rows(db) == 1
        engine = AIEngine(_ai_config(), state_dir=tmp_path)
        try:
            assert _rows(db) == 0
        finally:
            engine.close()

    def test_failing_purge_does_not_disable_triage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sentinelai.core.exceptions import StorageError

        def boom(self: TriageCache) -> int:
            raise StorageError("purge failed")

        monkeypatch.setattr(TriageCache, "purge_expired", boom)
        engine = AIEngine(_ai_config(), state_dir=tmp_path)
        try:
            assert engine._triage is not None  # noqa: SLF001
        finally:
            engine.close()


# -- (f) console rendering ----------------------------------------------------

HOSTILE = "[/] [link=https://evil]x[/link] [bold]B[/bold] \x1b[2J end"


def _hostile_alert() -> Alert:
    alert = _alert()
    alert.title = f"T {HOSTILE}"
    alert.description = f"D {HOSTILE}"
    alert.user = f"U{HOSTILE}"
    alert.recommendation = f"R {HOSTILE}"
    alert.risk.factors = [RiskFactor("hostile", 5.0, f"F {HOSTILE}")]
    alert.intel = IPReputation(ip="203.0.113.9", sources={f"S {HOSTILE}": {"score": 1}})
    alert.ai = AIInsight(
        explanation=f"E {HOSTILE}",
        explanation_source=f"X {HOSTILE}",
        triage={"verdict": f"V {HOSTILE}", "confidence": 0.5, "valid_llm": True},
    )
    return alert


class TestConsoleInjection:
    @staticmethod
    def _render(monkeypatch: pytest.MonkeyPatch, alert: Alert) -> str:
        recorder = Console(record=True, file=io.StringIO(), width=300, force_terminal=False)
        monkeypatch.setattr(console_module, "console", recorder)
        console_module.print_alert_detail(alert)
        return recorder.export_text()

    def test_print_alert_detail_does_not_raise_on_hostile_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._render(monkeypatch, _hostile_alert())

    def test_literal_markup_text_is_visible(self, monkeypatch: pytest.MonkeyPatch) -> None:
        text = self._render(monkeypatch, _hostile_alert())
        assert "[/]" in text
        assert "[link=https://evil]x[/link]" in text
        assert "[bold]B[/bold]" in text

    def test_escape_characters_are_removed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        text = self._render(monkeypatch, _hostile_alert())
        assert "\x1b" not in text
        assert "\x1b" not in io.StringIO().getvalue()

    @pytest.mark.parametrize(
        "marker", ["T [/]", "D [/]", "U[/]", "F [/]", "S [/]", "E [/]", "V [/]", "R [/]"]
    )
    def test_each_hostile_field_is_rendered(
        self, monkeypatch: pytest.MonkeyPatch, marker: str
    ) -> None:
        text = self._render(monkeypatch, _hostile_alert())
        assert marker in text

    def test_raw_output_stream_has_no_escape_from_alert_content(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stream = io.StringIO()
        recorder = Console(record=True, file=stream, width=300, force_terminal=False)
        monkeypatch.setattr(console_module, "console", recorder)
        console_module.print_alert_detail(_hostile_alert())
        assert "\x1b" not in stream.getvalue()
        assert "[/]" in stream.getvalue()
