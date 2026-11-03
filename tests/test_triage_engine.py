"""Tests for TriageEngine: cache, retries, fallback, advisory invariant, AIEngine wiring."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from sentinelai.ai.engine import AIEngine
from sentinelai.ai.explain import AlertExplainer
from sentinelai.ai.triage import build_prompt, render_text, template_triage
from sentinelai.ai.triage_cache import TriageCache
from sentinelai.ai.triage_engine import TriageEngine
from sentinelai.ai.triage_models import TriageOutcome, TriageProviderError
from sentinelai.config.models import AIConfig, LLMConfig
from sentinelai.core.models import Alert
from sentinelai.core.store import AlertStore
from sentinelai.detection.base import available_rules
from sentinelai.risk.engine import RiskEngine
from tests.conftest import make_event

MODEL = "fake-model"
BACKOFF = 0.5
TRIAGE_KEYS = {
    "verdict",
    "confidence",
    "summary",
    "reasoning",
    "recommended_actions",
    "referenced_event_ids",
    "source",
    "language",
    "valid_llm",
    "cached",
    "rejection",
}

# -- helpers ---------------------------------------------------------------


def _alert(messages: list[str] | None = None, title: str = "Brute force from 203.0.113.9") -> Alert:
    """Build a real, risk-scored alert via Rule.make_alert + RiskEngine."""
    import sentinelai.detection.rules  # noqa: F401  (registers built-in rules)

    rule = available_rules()["R001"]()
    texts = messages if messages is not None else ["fail one", "fail two", "fail three"]
    events = [
        make_event(offset=i, ip="203.0.113.9", user="alice", message=text)
        for i, text in enumerate(texts)
    ]
    alert = rule.make_alert(events[-1], title, "Many failed logins", events=events)
    RiskEngine().score(alert)
    return alert


def _answer(**overrides: Any) -> str:
    data: dict[str, Any] = {
        "verdict": "malicious",
        "confidence": 0.9,
        "summary": "Brute force against alice.",
        "reasoning": "Repeated failed logins from one address.",
        "recommended_actions": ["Block the source IP."],
        "referenced_event_ids": [1, 2],
    }
    data.update(overrides)
    return json.dumps(data)


def _config(**overrides: Any) -> LLMConfig:
    values: dict[str, Any] = {
        "enabled": True,
        "model": MODEL,
        "max_retries": 0,
        "retry_backoff_seconds": BACKOFF,
    }
    values.update(overrides)
    return LLMConfig(**values)


class FakeProvider:
    """Scripted provider: each script item is a str to return or an Exception/value."""

    name = "fake"
    model = MODEL

    def __init__(self, *script: Any) -> None:
        self._script: Iterator[Any] = iter(script)
        self.calls: list[tuple[str, str, Mapping[str, Any]]] = []

    def complete(self, system: str, user: str, schema: Mapping[str, Any]) -> str:
        self.calls.append((system, user, schema))
        item = next(self._script)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[no-any-return]


class FakeClock:
    """Returns successive values of a fixed sequence."""

    def __init__(self, *values: float) -> None:
        self._values = iter(values)

    def __call__(self) -> float:
        return next(self._values)


def _engine(
    provider: FakeProvider | None,
    config: LLMConfig | None = None,
    *,
    cache: TriageCache | None = None,
    sleeps: list[float] | None = None,
    clock: Callable[[], float] | None = None,
) -> TriageEngine:
    record = sleeps if sleeps is not None else []
    kwargs: dict[str, Any] = {"provider": provider, "cache": cache, "sleep": record.append}
    if clock is not None:
        kwargs["clock"] = clock
    return TriageEngine(config or _config(), **kwargs)


@pytest.fixture()
def cache(tmp_path: Path) -> Iterator[TriageCache]:
    instance = TriageCache(tmp_path / "cache.db", 3600)
    yield instance
    instance.close()


def _transient() -> TriageProviderError:
    return TriageProviderError("down", transient=True)


def _assert_template(outcome: TriageOutcome, alert: Alert, language: str = "en") -> None:
    assert outcome.source == "template"
    assert outcome.valid_llm is False
    assert outcome.cached is False
    assert outcome.result == template_triage(alert, language)


# -- disabled / happy path -------------------------------------------------


class TestDisabledAndSuccess:
    def test_disabled_config_returns_template_without_calling_provider(self) -> None:
        alert = _alert()
        provider = FakeProvider(_answer())
        outcome = _engine(provider, _config(enabled=False)).triage(alert)
        assert provider.calls == []
        _assert_template(outcome, alert)
        assert outcome.rejection == "llm disabled"

    def test_good_answer_is_used_with_llm_source_and_clock_latency(self) -> None:
        provider = FakeProvider(_answer())
        outcome = _engine(provider, clock=FakeClock(10.0, 10.75)).triage(_alert())
        assert outcome.source == f"llm:{MODEL}"
        assert outcome.valid_llm is True
        assert outcome.cached is False
        assert outcome.attempts == 1
        assert outcome.latency_seconds == pytest.approx(0.75)
        assert outcome.rejection is None
        assert outcome.result.verdict == "malicious"
        assert outcome.result.referenced_event_ids == (1, 2)

    def test_provider_receives_exactly_the_built_prompt(self) -> None:
        alert = _alert()
        provider = FakeProvider(_answer())
        _engine(provider, _config(language="tr")).triage(alert)
        prompt = build_prompt(alert, "tr")
        assert len(provider.calls) == 1
        system, user, schema = provider.calls[0]
        assert (system, user) == (prompt.system, prompt.user)
        assert schema["required"]

    def test_fenced_json_answer_is_accepted(self) -> None:
        provider = FakeProvider(f"```json\n{_answer()}\n```")
        outcome = _engine(provider).triage(_alert())
        assert outcome.valid_llm is True


# -- cache -----------------------------------------------------------------


class TestCache:
    def test_second_identical_triage_is_a_cache_hit(self, cache: TriageCache) -> None:
        alert = _alert()
        provider = FakeProvider(_answer())
        engine = _engine(provider, cache=cache)
        first = engine.triage(alert)
        second = engine.triage(alert)
        assert len(provider.calls) == 1
        assert first.source == f"llm:{MODEL}"
        assert second.source == f"cache:{MODEL}"
        assert second.cached is True
        assert second.valid_llm is True
        assert second.result == first.result

    def test_different_language_misses_cache(self, cache: TriageCache) -> None:
        alert = _alert()
        provider = FakeProvider(_answer(), _answer())
        _engine(provider, _config(language="en"), cache=cache).triage(alert)
        outcome = _engine(provider, _config(language="de"), cache=cache).triage(alert)
        assert len(provider.calls) == 2
        assert outcome.cached is False
        assert outcome.source == f"llm:{MODEL}"

    def test_different_alert_evidence_misses_cache(self, cache: TriageCache) -> None:
        provider = FakeProvider(_answer(), _answer())
        engine = _engine(provider, cache=cache)
        engine.triage(_alert(["fail one", "fail two", "fail three"]))
        outcome = engine.triage(_alert(["other one", "other two", "other three"]))
        assert len(provider.calls) == 2
        assert outcome.cached is False

    def test_invalid_answer_is_never_cached(self, cache: TriageCache) -> None:
        alert = _alert()
        provider = FakeProvider("not json", _answer())
        engine = _engine(provider, cache=cache)
        first = engine.triage(alert)
        second = engine.triage(alert)
        assert first.valid_llm is False
        assert second.source == f"llm:{MODEL}"
        assert len(provider.calls) == 2

    def test_broken_cache_is_treated_as_miss(self) -> None:
        class BrokenCache:
            def get(self, *args: Any) -> None:
                raise RuntimeError("boom")

            def put(self, *args: Any) -> None:
                raise RuntimeError("boom")

        provider = FakeProvider(_answer())
        engine = TriageEngine(
            _config(), provider=provider, cache=BrokenCache(), sleep=lambda _s: None  # type: ignore[arg-type]
        )
        outcome = engine.triage(_alert())
        assert outcome.valid_llm is True


# -- retries ---------------------------------------------------------------


class TestRetries:
    def test_two_provider_errors_then_success_uses_exponential_backoff(self) -> None:
        sleeps: list[float] = []
        provider = FakeProvider(_transient(), _transient(), _answer())
        engine = _engine(provider, _config(max_retries=2), sleeps=sleeps)
        outcome = engine.triage(_alert())
        assert outcome.valid_llm is True
        assert outcome.attempts == 3
        assert sleeps == [BACKOFF, 2 * BACKOFF]

    def test_no_sleep_after_last_failed_attempt(self) -> None:
        sleeps: list[float] = []
        provider = FakeProvider(*[_transient() for _ in range(3)])
        engine = _engine(provider, _config(max_retries=2), sleeps=sleeps)
        outcome = engine.triage(_alert())
        assert len(provider.calls) == 3
        assert sleeps == [BACKOFF, 2 * BACKOFF]
        assert outcome.attempts == 3

    def test_exhausted_retries_fall_back_to_template(self) -> None:
        alert = _alert()
        provider = FakeProvider(_transient(), _transient())
        outcome = _engine(provider, _config(max_retries=1), clock=FakeClock(1.0, 1.5, 3.0)).triage(
            alert
        )
        _assert_template(outcome, alert)
        assert outcome.attempts == 2
        assert outcome.latency_seconds == pytest.approx(2.0)
        assert outcome.rejection == "TriageProviderError: down"

    def test_invalid_answer_is_not_retried(self) -> None:
        sleeps: list[float] = []
        alert = _alert()
        provider = FakeProvider("garbage", _answer())
        outcome = _engine(provider, _config(max_retries=2), sleeps=sleeps).triage(alert)
        _assert_template(outcome, alert)
        assert outcome.attempts == 1
        assert len(provider.calls) == 1
        assert sleeps == []

    def test_non_transient_provider_error_is_not_retried(self) -> None:
        sleeps: list[float] = []
        alert = _alert()
        provider = FakeProvider(TriageProviderError("bad key"), _answer())
        outcome = _engine(provider, _config(max_retries=2), sleeps=sleeps).triage(alert)
        _assert_template(outcome, alert)
        assert outcome.attempts == 1
        assert len(provider.calls) == 1
        assert sleeps == []

    def test_transient_error_then_invalid_answer_stops_without_further_retry(self) -> None:
        sleeps: list[float] = []
        provider = FakeProvider(_transient(), "garbage", _answer())
        outcome = _engine(provider, _config(max_retries=2), sleeps=sleeps).triage(_alert())
        assert outcome.valid_llm is False
        assert outcome.attempts == 2
        assert len(provider.calls) == 2
        assert sleeps == [BACKOFF]

    def test_elapsed_time_over_budget_stops_retrying(self) -> None:
        sleeps: list[float] = []
        alert = _alert()
        # budget = timeout_seconds * (1 + max_retries) = 1.0 * 3 = 3.0
        config = _config(max_retries=2, timeout_seconds=1.0)
        provider = FakeProvider(_transient(), _transient(), _answer())
        clock = FakeClock(0.0, 3.5, 4.0)  # start, check after attempt 1, end
        outcome = _engine(provider, config, sleeps=sleeps, clock=clock).triage(alert)
        _assert_template(outcome, alert)
        assert outcome.attempts == 1
        assert len(provider.calls) == 1
        assert sleeps == []

    def test_elapsed_time_within_budget_keeps_retrying(self) -> None:
        sleeps: list[float] = []
        config = _config(max_retries=1, timeout_seconds=1.0)
        provider = FakeProvider(_transient(), _answer())
        clock = FakeClock(0.0, 1.5, 2.0)  # start, check (1.5 <= 2.0), end
        outcome = _engine(provider, config, sleeps=sleeps, clock=clock).triage(_alert())
        assert outcome.valid_llm is True
        assert outcome.attempts == 2
        assert sleeps == [BACKOFF]

    def test_rejection_is_bounded_and_leaks_no_prompt(self) -> None:
        alert = _alert()
        prompt = build_prompt(alert, "en")
        leak = f"{prompt.user} {'Z' * 500}"
        provider = FakeProvider(TriageProviderError(leak))
        outcome = _engine(provider).triage(alert)
        assert outcome.rejection is not None
        assert len(outcome.rejection) <= len("TriageProviderError: ") + 160
        assert prompt.user not in outcome.rejection
        assert "\n" not in outcome.rejection

    def test_raw_model_output_is_not_echoed_in_rejection(self) -> None:
        secret = "SECRET-RAW-OUTPUT " + "Q" * 400
        outcome = _engine(FakeProvider(secret)).triage(_alert())
        assert outcome.valid_llm is False
        assert outcome.rejection is not None
        assert "SECRET-RAW-OUTPUT" not in outcome.rejection
        assert len(outcome.rejection) <= len("TriageValidationError: ") + 160


# -- rejected answers -> template -------------------------------------------


class TestRejectedAnswers:
    @pytest.mark.parametrize(
        "raw",
        [
            "this is not json",
            "",
            "[]",
            json.dumps({"verdict": "malicious"}),
            _answer(verdict="catastrophic"),
            _answer(confidence=1.5),
            _answer(summary=""),
            json.dumps({**json.loads(_answer()), "extra": 1}),
            _answer(referenced_event_ids=[9]),
            _answer(referenced_event_ids=[1, 1]),
            _answer(verdict="benign", referenced_event_ids=[9, 10]),
        ],
        ids=[
            "invalid-json",
            "empty",
            "root-not-object",
            "missing-keys",
            "bad-verdict",
            "confidence-range",
            "empty-summary",
            "extra-key",
            "ungrounded-id",
            "duplicate-id",
            "benign-hallucinated-ids",
        ],
    )
    def test_bad_answer_is_rejected_and_template_used(self, raw: str) -> None:
        alert = _alert()  # three events, so only E1..E3 are valid
        outcome = _engine(FakeProvider(raw)).triage(alert)
        _assert_template(outcome, alert)
        assert outcome.rejection

    def test_ungrounded_event_id_has_explicit_rejection(self) -> None:
        outcome = _engine(FakeProvider(_answer(referenced_event_ids=[9]))).triage(_alert())
        assert outcome.rejection is not None
        assert "not provided" in outcome.rejection

    def test_unexpected_runtime_error_gives_template_with_unexpected_error(self) -> None:
        alert = _alert()
        outcome = _engine(FakeProvider(RuntimeError("secret internals"))).triage(alert)
        _assert_template(outcome, alert)
        assert outcome.rejection == "unexpected error: RuntimeError"

    def test_non_str_answer_is_rejected_and_template_used(self) -> None:
        alert = _alert()
        outcome = _engine(FakeProvider(12345)).triage(alert)
        _assert_template(outcome, alert)
        assert outcome.rejection is not None
        assert "not text" in outcome.rejection

    def test_unknown_provider_in_config_falls_back_to_template(self) -> None:
        alert = _alert()
        engine = TriageEngine(_config(provider="bogus"), sleep=lambda _s: None)
        outcome = engine.triage(alert)
        _assert_template(outcome, alert)
        assert outcome.rejection is not None
        assert "Unknown LLM provider" in outcome.rejection

    def test_create_provider_unexpected_exception_never_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(_config: LLMConfig) -> FakeProvider:
            raise ValueError("kaput")

        monkeypatch.setattr("sentinelai.ai.triage_engine.create_provider", boom)
        alert = _alert()
        outcome = TriageEngine(_config()).triage(alert)
        _assert_template(outcome, alert)
        assert outcome.rejection == "unexpected error: ValueError"

    def test_language_is_carried_into_template_outcome(self) -> None:
        alert = _alert()
        outcome = _engine(FakeProvider("nope"), _config(language="tr")).triage(alert)
        _assert_template(outcome, alert, "tr")
        assert outcome.language == "tr"

    def test_close_without_owned_provider_is_safe(self) -> None:
        engine = _engine(FakeProvider(_answer()))
        engine.triage(_alert())
        engine.close()
        engine.close()


# -- advisory invariant ----------------------------------------------------


class TestAdvisoryInvariant:
    @pytest.mark.parametrize(
        "script",
        [
            (_answer(verdict="benign", confidence=0.99),),
            (_answer(verdict="malicious", confidence=0.99),),
            ("garbage",),
            (RuntimeError("x"),),
        ],
        ids=["benign", "malicious", "invalid", "crash"],
    )
    def test_triage_does_not_change_alert(self, script: tuple[Any, ...]) -> None:
        alert = _alert()
        before = alert.to_dict()
        _engine(FakeProvider(*script)).triage(alert)
        assert alert.to_dict() == before

    def test_disabled_triage_does_not_change_alert(self) -> None:
        alert = _alert()
        before = alert.to_dict()
        _engine(FakeProvider(), _config(enabled=False)).triage(alert)
        assert alert.to_dict() == before

    def test_benign_verdict_does_not_lower_risk_or_severity(self) -> None:
        alert = _alert()
        score, severity = alert.risk.score, alert.severity
        _engine(FakeProvider(_answer(verdict="benign", confidence=1.0))).triage(alert)
        assert (alert.risk.score, alert.severity) == (score, severity)


# -- AlertExplainer / AIEngine wiring ---------------------------------------


class TestExplainerAndAIEngine:
    def test_disabled_explainer_returns_template_tuple(self) -> None:
        alert = _alert()
        explainer = AlertExplainer(_config(enabled=False))
        text, source, confidence = explainer.explain(alert)
        assert (source, confidence) == ("template", 0.7)
        assert text == AlertExplainer._explain_template(alert)
        assert text.startswith("WHY SUSPICIOUS:")

    def test_disabled_explain_full_has_no_outcome(self) -> None:
        _text, _source, _confidence, outcome = AlertExplainer(_config(enabled=False)).explain_full(
            _alert()
        )
        assert outcome is None

    def test_enabled_explainer_renders_triage_text(self) -> None:
        alert = _alert()
        provider = FakeProvider(_answer())
        explainer = AlertExplainer(_config(), _engine(provider))
        text, source, confidence = explainer.explain(alert)
        assert source == f"llm:{MODEL}"
        assert confidence == pytest.approx(0.9)
        assert text == render_text(_engine(FakeProvider(_answer())).triage(alert).result)

    def test_aiengine_explain_stores_triage_and_builds_cache_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = FakeProvider(_answer())
        monkeypatch.setattr(
            "sentinelai.ai.triage_engine.create_provider", lambda _config: provider
        )
        config = AIConfig(enabled=False, llm=_config())
        engine = AIEngine(config, state_dir=tmp_path)
        try:
            assert (tmp_path / "triage_cache.db").is_file()
            alert = _alert()
            insight = engine.explain(alert)
            assert alert.ai is insight
            assert insight.triage is not None
            assert set(insight.triage) == TRIAGE_KEYS
            assert insight.triage["source"] == f"llm:{MODEL}"
            assert insight.triage["valid_llm"] is True
            assert insight.triage["cached"] is False
            assert insight.triage["rejection"] is None
            assert insight.explanation_source == f"llm:{MODEL}"

            again = _alert()
            engine.explain(again)
            assert again.ai is not None and again.ai.triage is not None
            assert again.ai.triage["source"] == f"cache:{MODEL}"
            assert again.ai.triage["cached"] is True
            assert len(provider.calls) == 1
        finally:
            engine.close()

    def test_aiengine_explain_changes_only_alert_ai(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = FakeProvider(_answer(verdict="benign", confidence=1.0))
        monkeypatch.setattr(
            "sentinelai.ai.triage_engine.create_provider", lambda _config: provider
        )
        engine = AIEngine(AIConfig(enabled=False, llm=_config()), state_dir=tmp_path)
        try:
            alert = _alert()
            before = {k: v for k, v in alert.to_dict().items() if k != "ai"}
            engine.explain(alert)
            after = {k: v for k, v in alert.to_dict().items() if k != "ai"}
            assert after == before
            assert alert.ai is not None and alert.ai.triage is not None
        finally:
            engine.close()

    def test_aiengine_with_failing_provider_stores_template_triage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = FakeProvider(TriageProviderError("down"))  # permanent: no retry
        monkeypatch.setattr(
            "sentinelai.ai.triage_engine.create_provider", lambda _config: provider
        )
        engine = AIEngine(AIConfig(enabled=False, llm=_config()), state_dir=tmp_path)
        try:
            alert = _alert()
            insight = engine.explain(alert)
            assert insight.triage is not None
            assert insight.triage["source"] == "template"
            assert insight.triage["valid_llm"] is False
            assert insight.triage["rejection"] == "TriageProviderError: down"
            assert insight.explanation_source == "template"
        finally:
            engine.close()

    def test_aiengine_llm_disabled_has_no_triage_and_no_cache(self, tmp_path: Path) -> None:
        engine = AIEngine(AIConfig(enabled=False, llm=_config(enabled=False)), state_dir=tmp_path)
        try:
            alert = _alert()
            insight = engine.explain(alert)
            assert insight.triage is None
            assert insight.explanation_source == "template"
            assert insight.confidence == 0.7
            assert not (tmp_path / "triage_cache.db").exists()
        finally:
            engine.close()

    def test_triage_dict_survives_alert_store_round_trip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = FakeProvider(_answer())
        monkeypatch.setattr(
            "sentinelai.ai.triage_engine.create_provider", lambda _config: provider
        )
        engine = AIEngine(AIConfig(enabled=False, llm=_config()), state_dir=tmp_path)
        store = AlertStore(tmp_path / "alerts.db")
        try:
            alert = _alert()
            engine.explain(alert)
            assert alert.ai is not None
            expected = dict(alert.ai.triage or {})
            alert_id = store.save(alert)
            loaded = store.get(alert_id)
            assert loaded is not None and loaded.ai is not None
            assert loaded.ai.triage == expected
            assert set(loaded.ai.triage or {}) == TRIAGE_KEYS
        finally:
            store.close()
            engine.close()
