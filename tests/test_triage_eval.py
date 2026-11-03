"""Tests for the advisory LLM triage evaluation and ``sentinel eval --triage``.

No network: every model call goes through a fake provider.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from sentinelai.ai.triage_engine import TriageEngine
from sentinelai.ai.triage_models import TriageProviderError
from sentinelai.cli.app import cli
from sentinelai.config.models import LLMConfig
from sentinelai.evaluation.models import KIND_ATTACK
from sentinelai.evaluation.runner import load_scenarios
from sentinelai.evaluation.triage_eval import percentile, run_triage_eval, summarize

ROOT = Path(__file__).resolve().parent.parent / "benchmarks"
SCENARIOS = ROOT / "scenarios"
BASELINE = ROOT / "baseline.json"

LATENCY = 0.25
SMALL = 6


# --------------------------------------------------------------------------- fakes


def _answer(verdict: str = "malicious") -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": 0.9,
            "summary": "Repeated failed logins from one source.",
            "reasoning": "The events show a brute force pattern.",
            "recommended_actions": ["Block the source address."],
            "referenced_event_ids": [],
        }
    )


class FakeProvider:
    """Answers from a script; the script is cycled. ``None`` means invalid JSON."""

    name = "fake"
    model = "fake-model"

    def __init__(self, script: Sequence[str | None] = ("malicious",)) -> None:
        self._script = list(script)
        self.calls = 0

    def complete(self, system: str, user: str, schema: Mapping[str, Any]) -> str:
        item = self._script[self.calls % len(self._script)]
        self.calls += 1
        if item is None:
            return "this is not json at all"
        return _answer(item)


class RaisingProvider:
    name = "fake"
    model = "fake-model"

    def complete(self, system: str, user: str, schema: Mapping[str, Any]) -> str:
        raise TriageProviderError("connection refused")


class TransientProvider:
    """Always fails with a retryable (transient) provider error."""

    name = "fake"
    model = "fake-model"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, system: str, user: str, schema: Mapping[str, Any]) -> str:
        self.calls += 1
        raise TriageProviderError("temporarily down", transient=True)


class FakeClock:
    """Each triage reads the clock twice (start, end); the end adds one latency."""

    def __init__(self, latencies: Sequence[float] = (LATENCY,)) -> None:
        self._latencies = list(latencies)
        self._now = 100.0
        self._reads = 0

    def __call__(self) -> float:
        if self._reads % 2 == 1:
            self._now += self._latencies[(self._reads // 2) % len(self._latencies)]
        self._reads += 1
        return self._now


def _llm(**overrides: Any) -> LLMConfig:
    values: dict[str, Any] = {
        "enabled": True,
        "model": "fake-model",
        "provider": "ollama",
        "max_retries": 0,
    }
    values.update(overrides)
    return LLMConfig(**values)


def _engine(
    provider: Any,
    llm: LLMConfig | None = None,
    clock: Callable[[], float] | None = None,
) -> TriageEngine:
    return TriageEngine(
        llm or _llm(),
        provider=provider,
        sleep=lambda _seconds: None,
        clock=clock or FakeClock(),
    )


def _run(
    script: Sequence[str | None] = ("malicious",),
    *,
    limit: int | None = SMALL,
    llm: LLMConfig | None = None,
    clock: Callable[[], float] | None = None,
) -> dict[str, Any]:
    config = llm or _llm()
    engine = _engine(FakeProvider(script), config, clock)
    return run_triage_eval(SCENARIOS, config, limit=limit, engine=engine)


def _strip_latency(data: dict[str, Any]) -> dict[str, Any]:
    clean = {k: v for k, v in data.items() if k != "latency"}
    clean["per_alert"] = [
        {k: v for k, v in row.items() if k != "latency_seconds"} for row in data["per_alert"]
    ]
    return clean


@pytest.fixture(scope="module")
def attack_names() -> set[str]:
    return {s.label.name for s in load_scenarios(SCENARIOS) if s.label.kind == KIND_ATTACK}


@pytest.fixture(scope="module")
def full_run() -> dict[str, Any]:
    return _run(limit=None)


# --------------------------------------------------------------------------- percentile


class TestPercentile:
    def test_empty_values_return_zero(self) -> None:
        assert percentile([], 50) == 0.0
        assert percentile([], 95) == 0.0

    def test_single_value_is_every_percentile(self) -> None:
        assert percentile([0.7], 0) == 0.7
        assert percentile([0.7], 50) == 0.7
        assert percentile([0.7], 100) == 0.7

    def test_nearest_rank_on_even_count(self) -> None:
        values = [1.0, 2.0, 3.0, 4.0]
        assert percentile(values, 50) == 2.0
        assert percentile(values, 95) == 4.0

    def test_nearest_rank_on_odd_count(self) -> None:
        assert percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50) == 3.0

    def test_unsorted_input_is_sorted_first(self) -> None:
        assert percentile([9.0, 1.0, 5.0, 3.0], 50) == 3.0

    def test_zero_percent_returns_minimum(self) -> None:
        assert percentile([4.0, 2.0, 8.0], 0) == 2.0

    def test_hundred_percent_returns_maximum(self) -> None:
        assert percentile([4.0, 2.0, 8.0], 100) == 8.0

    def test_input_is_not_mutated(self) -> None:
        values = [3.0, 1.0, 2.0]
        percentile(values, 50)
        assert values == [3.0, 1.0, 2.0]


# --------------------------------------------------------------------------- happy path


class TestAllMalicious:
    def test_limit_caps_the_total_number_of_alerts(self) -> None:
        data = _run(limit=SMALL)
        assert data["alerts"] == SMALL
        assert len(data["per_alert"]) == SMALL

    def test_small_limit_stays_within_first_alerts(self) -> None:
        data = _run(limit=1)
        assert data["alerts"] == 1

    def test_all_answers_valid_and_agree(self) -> None:
        data = _run()
        assert data["llm_valid"] == data["alerts"] == SMALL
        assert data["schema_valid_rate"] == 1.0
        assert data["agreement_rate"] == 1.0
        assert data["malicious_rate"] == 1.0
        assert data["fallback_rate"] == 0.0

    def test_verdict_counts(self) -> None:
        data = _run()
        assert data["verdicts"] == {"benign": 0, "suspicious": 0, "malicious": SMALL}

    def test_no_rejections_when_everything_is_valid(self) -> None:
        assert _run()["rejections"] == {}

    def test_latency_stats_come_from_the_fake_clock(self) -> None:
        latency = _run()["latency"]
        assert latency == {"count": SMALL, "mean": LATENCY, "p50": LATENCY, "p95": LATENCY}

    def test_latency_percentiles_follow_varied_clock(self) -> None:
        clock = FakeClock([0.1, 0.2, 0.3, 0.4])
        latency = _run(limit=4, clock=clock)["latency"]
        assert latency["count"] == 4
        assert latency["mean"] == 0.25
        assert latency["p50"] == 0.2
        assert latency["p95"] == 0.4

    def test_metadata_reflects_config(self) -> None:
        llm = _llm(model="m-x", provider="openai", language="de")
        data = _run(llm=llm)
        assert (data["model"], data["provider"], data["language"]) == ("m-x", "openai", "de")

    def test_per_alert_rows_have_expected_fields(self) -> None:
        row = _run(limit=1)["per_alert"][0]
        assert set(row) == {
            "scenario",
            "rule_id",
            "verdict",
            "confidence",
            "source",
            "valid_llm",
            "attempts",
            "latency_seconds",
            "rejection",
        }
        assert row["verdict"] == "malicious"
        assert row["source"] == "llm:fake-model"
        assert row["valid_llm"] is True
        assert row["attempts"] == 1
        assert row["rejection"] is None

    def test_provider_is_called_once_per_alert(self) -> None:
        provider = FakeProvider()
        config = _llm()
        engine = _engine(provider, config)
        data = run_triage_eval(SCENARIOS, config, limit=SMALL, engine=engine)
        assert provider.calls == data["alerts"] == SMALL


class TestAttackOnly:
    def test_only_attack_scenarios_are_triaged(self, attack_names: set[str]) -> None:
        data = _run(limit=40)
        scenarios = {row["scenario"] for row in data["per_alert"]}
        assert scenarios
        assert scenarios <= attack_names

    def test_unlimited_run_covers_only_attack_scenarios(
        self, full_run: dict[str, Any], attack_names: set[str]
    ) -> None:
        scenarios = {row["scenario"] for row in full_run["per_alert"]}
        assert scenarios <= attack_names
        assert full_run["alerts"] > SMALL

    def test_unlimited_run_has_rule_ids_on_every_row(self, full_run: dict[str, Any]) -> None:
        assert all(row["rule_id"] for row in full_run["per_alert"])

    def test_limit_above_total_returns_everything(self, full_run: dict[str, Any]) -> None:
        data = _run(limit=full_run["alerts"] + 1000)
        assert data["alerts"] == full_run["alerts"]

    def test_limit_equal_to_total_returns_everything(self, full_run: dict[str, Any]) -> None:
        data = _run(limit=full_run["alerts"])
        assert data["alerts"] == full_run["alerts"]

    def test_limited_run_is_a_prefix_of_unlimited_run(self, full_run: dict[str, Any]) -> None:
        data = _run(limit=SMALL)
        head = [(r["scenario"], r["rule_id"]) for r in data["per_alert"]]
        full = [(r["scenario"], r["rule_id"]) for r in full_run["per_alert"]]
        assert head == full[:SMALL]


# --------------------------------------------------------------------------- invalid output


class TestInvalidJson:
    def test_every_answer_rejected_gives_zero_validity(self) -> None:
        data = _run([None])
        assert data["alerts"] == SMALL
        assert data["llm_valid"] == 0
        assert data["schema_valid_rate"] == 0
        assert data["fallback_rate"] == 1.0

    def test_rejections_histogram_is_not_empty(self) -> None:
        rejections = _run([None])["rejections"]
        assert rejections
        assert sum(rejections.values()) == SMALL
        assert all("TriageValidationError" in reason for reason in rejections)

    def test_template_verdicts_are_still_counted(self) -> None:
        data = _run([None])
        assert sum(data["verdicts"].values()) == SMALL
        assert all(row["source"] == "template" for row in data["per_alert"])
        assert all(row["valid_llm"] is False for row in data["per_alert"])

    def test_fallback_latency_is_excluded_from_stats(self) -> None:
        latency = _run([None])["latency"]
        assert latency == {"count": 0, "mean": 0.0, "p50": 0.0, "p95": 0.0}

    def test_transient_retries_are_reflected_in_attempts(self) -> None:
        config = _llm(max_retries=2)
        provider = TransientProvider()
        engine = _engine(provider, config)
        data = run_triage_eval(SCENARIOS, config, limit=2, engine=engine)
        assert [row["attempts"] for row in data["per_alert"]] == [3, 3]
        assert provider.calls == 6

    def test_invalid_answers_are_not_retried(self) -> None:
        data = _run([None], limit=2, llm=_llm(max_retries=2))
        assert [row["attempts"] for row in data["per_alert"]] == [1, 1]

    def test_provider_errors_fall_back_to_template(self) -> None:
        config = _llm()
        engine = _engine(RaisingProvider(), config)
        data = run_triage_eval(SCENARIOS, config, limit=3, engine=engine)
        assert data["alerts"] == 3
        assert data["schema_valid_rate"] == 0
        assert data["fallback_rate"] == 1.0
        assert any("TriageProviderError" in reason for reason in data["rejections"])

    def test_wrong_verdict_value_is_rejected(self) -> None:
        provider = FakeProvider(["definitely-evil"])
        config = _llm()
        engine = _engine(provider, config)
        data = run_triage_eval(SCENARIOS, config, limit=2, engine=engine)
        assert data["llm_valid"] == 0
        assert data["fallback_rate"] == 1.0


class TestMixedAnswers:
    def test_alternating_good_and_bad_gives_half_rates(self) -> None:
        data = _run(["malicious", None])
        assert data["alerts"] == SMALL
        assert data["llm_valid"] == SMALL // 2
        assert data["schema_valid_rate"] == 0.5
        assert data["fallback_rate"] == 0.5

    def test_mixed_latency_counts_only_valid_answers(self) -> None:
        data = _run(["malicious", None])
        assert data["latency"]["count"] == SMALL // 2

    def test_mixed_rejections_count_only_the_bad_ones(self) -> None:
        data = _run(["malicious", None])
        assert sum(data["rejections"].values()) == SMALL // 2

    def test_one_in_three_valid_rounds_to_four_places(self) -> None:
        data = _run([None, None, "malicious"])
        assert data["schema_valid_rate"] == 0.3333
        assert data["fallback_rate"] == 0.6667


class TestBenignVerdicts:
    def test_benign_verdicts_lower_agreement(self) -> None:
        data = _run(["malicious", "benign", "suspicious", "benign"], limit=8)
        assert data["verdicts"]["benign"] == 4
        assert data["agreement_rate"] == 0.5
        assert data["malicious_rate"] == 0.25
        assert data["schema_valid_rate"] == 1.0

    def test_all_benign_gives_zero_agreement(self) -> None:
        data = _run(["benign"])
        assert data["agreement_rate"] == 0.0
        assert data["malicious_rate"] == 0.0
        assert data["schema_valid_rate"] == 1.0

    def test_suspicious_counts_as_agreement_but_not_malicious(self) -> None:
        data = _run(["suspicious"])
        assert data["agreement_rate"] == 1.0
        assert data["malicious_rate"] == 0.0
        assert data["verdicts"]["suspicious"] == SMALL


# --------------------------------------------------------------------------- empty / edge


class TestZeroAlerts:
    def test_limit_zero_does_not_divide_by_zero(self) -> None:
        provider = FakeProvider()
        config = _llm()
        engine = _engine(provider, config)
        data = run_triage_eval(SCENARIOS, config, limit=0, engine=engine)
        assert data["alerts"] == 0
        assert data["per_alert"] == []
        assert provider.calls == 0
        for key in ("schema_valid_rate", "fallback_rate", "agreement_rate", "malicious_rate"):
            assert data[key] == 0.0

    def test_negative_limit_is_treated_as_zero(self) -> None:
        assert _run(limit=-5)["alerts"] == 0

    def test_empty_entry_list_summarizes_to_zeroes(self) -> None:
        data = summarize(_llm(), [])
        assert data["alerts"] == 0
        assert data["llm_valid"] == 0
        assert data["verdicts"] == {"benign": 0, "suspicious": 0, "malicious": 0}
        assert data["latency"] == {"count": 0, "mean": 0.0, "p50": 0.0, "p95": 0.0}
        assert data["rejections"] == {}
        assert data["per_alert"] == []


class TestStructure:
    def test_result_is_json_serializable(self) -> None:
        data = _run(["malicious", None, "benign"])
        assert json.loads(json.dumps(data)) == data

    def test_result_has_expected_top_level_keys(self) -> None:
        assert set(_run(limit=1)) == {
            "model",
            "provider",
            "language",
            "alerts",
            "llm_valid",
            "schema_valid_rate",
            "fallback_rate",
            "agreement_rate",
            "malicious_rate",
            "verdicts",
            "latency",
            "rejections",
            "per_alert",
        }

    def test_two_runs_are_equal_except_latency(self) -> None:
        first = _run(["malicious", None, "benign"], limit=9, clock=FakeClock([0.1, 0.5]))
        second = _run(["malicious", None, "benign"], limit=9, clock=FakeClock([0.9, 0.3]))
        assert _strip_latency(first) == _strip_latency(second)

    def test_identical_inputs_give_identical_reports(self) -> None:
        first = _run(["malicious", None], limit=8)
        second = _run(["malicious", None], limit=8)
        assert first == second

    def test_injected_engine_is_not_closed(self) -> None:
        closed: list[bool] = []

        class Closable(FakeProvider):
            def close(self) -> None:
                closed.append(True)

        config = _llm()
        engine = _engine(Closable(), config)
        run_triage_eval(SCENARIOS, config, limit=1, engine=engine)
        assert closed == []

    def test_long_rejection_reasons_are_shortened(self) -> None:
        data = _run([None], limit=2)
        for row in data["per_alert"]:
            assert row["rejection"] is not None
            assert len(row["rejection"]) <= 80
        assert all(len(reason) <= 80 for reason in data["rejections"])


# --------------------------------------------------------------------------- CLI


def _write_config(tmp_path: Path, *, llm_enabled: bool) -> str:
    data: dict[str, Any] = {"state_dir": str(tmp_path / "state")}
    if llm_enabled:
        data["ai"] = {
            "llm": {
                "enabled": True,
                "model": "fake-model",
                "endpoint": "http://localhost:9",
                "max_retries": 0,
            }
        }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


def _invoke(config: str, *args: str) -> Any:
    return CliRunner().invoke(cli, ["--no-plugins", "--config", config, "eval", *args])


def _norm(text: str) -> str:
    return " ".join(text.split())


def _lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


@pytest.fixture
def fake_provider(monkeypatch: pytest.MonkeyPatch) -> FakeProvider:
    provider = FakeProvider(["malicious"])
    monkeypatch.setattr(
        "sentinelai.ai.triage_engine.create_provider", lambda _config: provider
    )
    return provider


class TestCliTriageDisabled:
    def test_triage_without_llm_enabled_fails(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, llm_enabled=False)
        result = _invoke(cfg, "--benchmarks", str(ROOT), "--triage")
        assert result.exit_code != 0
        assert "ai.llm.enabled" in _norm(result.output)

    def test_triage_without_llm_enabled_does_not_run_anything(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        monkeypatch.setattr(
            "sentinelai.cli.commands.evaluation.run_benchmark",
            lambda *a, **k: calls.append("benchmark"),
        )
        monkeypatch.setattr(
            "sentinelai.cli.commands.evaluation.run_triage_eval",
            lambda *a, **k: calls.append("triage"),
        )
        cfg = _write_config(tmp_path, llm_enabled=False)
        result = _invoke(cfg, "--benchmarks", str(ROOT), "--triage")
        assert result.exit_code != 0
        assert calls == []

    def test_triage_without_llm_enabled_writes_no_output(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, llm_enabled=False)
        target = tmp_path / "triage.json"
        result = _invoke(cfg, "--benchmarks", str(ROOT), "--triage", "--triage-output", str(target))
        assert result.exit_code != 0
        assert not target.exists()


class TestCliWithoutTriage:
    def test_eval_without_triage_is_unchanged(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, llm_enabled=False)
        result = _invoke(cfg, "--benchmarks", str(ROOT), "--baseline", str(BASELINE))
        assert result.exit_code == 0
        assert "LLM triage" not in result.output

    def test_eval_without_triage_ignores_enabled_llm(
        self, tmp_path: Path, fake_provider: FakeProvider
    ) -> None:
        cfg = _write_config(tmp_path, llm_enabled=True)
        result = _invoke(cfg, "--benchmarks", str(ROOT), "--baseline", str(BASELINE))
        assert result.exit_code == 0
        assert fake_provider.calls == 0
        assert "LLM triage" not in result.output

    def test_triage_output_without_triage_flag_writes_nothing(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, llm_enabled=True)
        target = tmp_path / "triage.json"
        result = _invoke(cfg, "--benchmarks", str(ROOT), "--triage-output", str(target))
        assert result.exit_code == 0
        assert not target.exists()


class TestCliTriageEnabled:
    def test_triage_writes_output_json(self, tmp_path: Path, fake_provider: FakeProvider) -> None:
        cfg = _write_config(tmp_path, llm_enabled=True)
        target = tmp_path / "out" / "triage.json"
        result = _invoke(
            cfg,
            "--benchmarks",
            str(ROOT),
            "--baseline",
            str(BASELINE),
            "--triage",
            "--triage-limit",
            "3",
            "--triage-output",
            str(target),
        )
        assert result.exit_code == 0, result.output
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["alerts"] == 3
        assert data["model"] == "fake-model"
        assert data["schema_valid_rate"] == 1.0
        assert data["agreement_rate"] == 1.0
        assert data["fallback_rate"] == 0.0
        assert len(data["per_alert"]) == 3
        assert fake_provider.calls == 3

    def test_triage_prints_advisory_note(self, tmp_path: Path, fake_provider: FakeProvider) -> None:
        cfg = _write_config(tmp_path, llm_enabled=True)
        result = _invoke(cfg, "--benchmarks", str(ROOT), "--triage", "--triage-limit", "2")
        assert result.exit_code == 0, result.output
        text = _norm(result.output)
        assert "LLM triage (advisory)" in text
        assert "advisory and do not affect the exit code" in text

    def test_triage_json_mode_keeps_stdout_parseable(
        self, tmp_path: Path, fake_provider: FakeProvider
    ) -> None:
        cfg = _write_config(tmp_path, llm_enabled=True)
        result = _invoke(
            cfg, "--benchmarks", str(ROOT), "--json", "--triage", "--triage-limit", "2"
        )
        assert result.exit_code == 0, result.output
        assert "summary" in json.loads(result.stdout)

    def test_triage_never_leaks_into_written_baseline(
        self, tmp_path: Path, fake_provider: FakeProvider
    ) -> None:
        cfg = _write_config(tmp_path, llm_enabled=True)
        target = tmp_path / "new_baseline.json"
        result = _invoke(
            cfg,
            "--benchmarks",
            str(ROOT),
            "--triage",
            "--triage-limit",
            "3",
            "--write-baseline",
            str(target),
        )
        assert result.exit_code == 0, result.output
        written = target.read_bytes()
        assert _lf(written) == _lf(BASELINE.read_bytes())
        assert b"triage" not in written.lower()
        assert b"verdict" not in written.lower()

    def test_triage_failure_answers_do_not_change_exit_code(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "sentinelai.ai.triage_engine.create_provider",
            lambda _config: FakeProvider([None]),
        )
        cfg = _write_config(tmp_path, llm_enabled=True)
        target = tmp_path / "triage.json"
        result = _invoke(
            cfg,
            "--benchmarks",
            str(ROOT),
            "--baseline",
            str(BASELINE),
            "--triage",
            "--triage-limit",
            "2",
            "--triage-output",
            str(target),
        )
        assert result.exit_code == 0, result.output
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["schema_valid_rate"] == 0
        assert data["fallback_rate"] == 1.0

    def test_triage_limit_below_one_is_rejected(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, llm_enabled=True)
        result = _invoke(cfg, "--benchmarks", str(ROOT), "--triage", "--triage-limit", "0")
        assert result.exit_code == 2
