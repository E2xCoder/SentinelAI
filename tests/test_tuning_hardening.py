"""Regression tests for the tuning-loop review fixes.

Covers expiry at match time, the benchmark trust root of the gate, protection
of analyst-confirmed true positives, and the hardened tuning CLI commands.
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

import sentinelai.detection.rules  # noqa: F401  (registers the built-in rules)
from sentinelai.cli.app import cli
from sentinelai.cli.commands.tuning import _clean
from sentinelai.config.loader import load_config
from sentinelai.config.models import DetectionConfig, Suppression
from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent
from sentinelai.core.store import AlertStore
from sentinelai.detection.base import available_rules
from sentinelai.detection.engine import RuleEngine
from sentinelai.detection.suppression import SuppressionMatcher
from sentinelai.evaluation.manifest import write_manifest
from sentinelai.risk.engine import RiskEngine
from sentinelai.tuning import gate
from sentinelai.tuning.models import KIND_THRESHOLD, Proposal
from sentinelai.tuning.replay import ReplayContext
from tests.conftest import BASE_TS, make_event

BENCH = Path(__file__).resolve().parent.parent / "benchmarks"

ATTACKER_IP = "203.0.113.5"
FP_IP = "198.51.100.7"
GATE_NOW = datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)


# -- helpers ---------------------------------------------------------------


@dataclass
class Env:
    root: Path
    state: Path
    cfg: Path

    @property
    def overlay(self) -> Path:
        return self.state / "tuning.yaml"

    @property
    def audit(self) -> Path:
        return self.state / "tuning" / "audit.jsonl"

    def store(self) -> AlertStore:
        return AlertStore(self.state / "alerts.db")


def make_env(root: Path) -> Env:
    state = root / "state"
    state.mkdir(parents=True, exist_ok=True)
    cfg = root / "config.yaml"
    cfg.write_text(f'state_dir: "{state.as_posix()}"\n', encoding="utf-8")
    return Env(root=root, state=state, cfg=cfg)


def run_cli(env: Env, *args: str) -> Any:
    return CliRunner().invoke(cli, ["--config", str(env.cfg), "--no-plugins", *args])


def full_output(result: Any) -> str:
    return result.output + getattr(result, "stderr", "")


def save_alert(
    store: AlertStore,
    rule_id: str,
    *,
    label: str | None = None,
    score: float | None = None,
    ip: str | None = FP_IP,
    user: str | None = "scanner",
    **context: Any,
) -> int:
    """Save a risk-scored R-rule alert, optionally overriding its score and labelling it."""
    rule = available_rules()[rule_id]()
    alert: Alert = rule.make_alert(make_event(ip=ip, user=user), f"{rule_id} test", "synthetic")
    alert.context = dict(context)
    RiskEngine().score(alert)
    if score is not None:
        alert.risk.score = score
    alert_id = store.save(alert)
    if label is not None:
        store.add_feedback(alert_id, label, note="synthetic")
    return alert_id


def failed_logins(count: int, start: float = 0.0) -> list[LogEvent]:
    return [
        make_event(
            offset=start + i,
            event_type=EventType.AUTH_FAILURE,
            category=EventCategory.AUTHENTICATION,
            ip=ATTACKER_IP,
            user="alice",
        )
        for i in range(count)
    ]


def run_events(engine: RuleEngine, events: list[LogEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        alerts.extend(engine.process(event))
    return alerts


def threshold_proposal(value: int = 7) -> Proposal:
    return Proposal(
        id="p-r001-threshold",
        kind=KIND_THRESHOLD,
        rule_id="R001",
        patch={"detection": {"brute_force_attempts": value}},
        rationale="x",
    )


@pytest.fixture()
def bench_copy(tmp_path: Path) -> Path:
    target = tmp_path / "benchmarks"
    shutil.copytree(BENCH, target)
    return target


def evaluate_threshold(bench: Path, config: Any, feedback: list[Any] | None = None) -> Any:
    return gate.evaluate([threshold_proposal()], config, feedback or [], bench, now=GATE_NOW)


# -- 1. expiry at match time -----------------------------------------------------


class TestExpiryAtMatchTime:
    def _engine(self, clock: list[datetime], expires: datetime) -> RuleEngine:
        detection = DetectionConfig(
            suppressions=[{"rule": "R001", "ip": f"{ATTACKER_IP}/32", "expires": expires}]
        )
        return RuleEngine(detection, now=lambda: clock[0])

    def test_suppression_active_at_clock_time_drops_the_alert(self) -> None:
        clock = [BASE_TS]
        engine = self._engine(clock, BASE_TS + timedelta(hours=1))
        alerts = run_events(engine, failed_logins(6))
        assert [a for a in alerts if a.rule_id == "R001"] == []
        assert engine.suppressed_by_rule.get("R001", 0) >= 1

    def test_same_engine_raises_alert_after_clock_passes_expiry(self) -> None:
        clock = [BASE_TS]
        engine = self._engine(clock, BASE_TS + timedelta(hours=1))
        assert [a for a in run_events(engine, failed_logins(6)) if a.rule_id == "R001"] == []

        clock[0] = BASE_TS + timedelta(hours=2)
        later = run_events(engine, failed_logins(6, start=7200))
        assert [a.rule_id for a in later if a.rule_id == "R001"] == ["R001"]

    def test_matcher_len_follows_the_clock(self) -> None:
        clock = [BASE_TS]
        entry = Suppression(
            rule="R001", user=None, ip=ATTACKER_IP, expires=BASE_TS + timedelta(hours=1)
        )
        matcher = SuppressionMatcher([entry], lambda: clock[0])
        assert len(matcher) == 1
        clock[0] = BASE_TS + timedelta(hours=1)
        assert len(matcher) == 0

    def test_matcher_match_stops_matching_when_clock_passes_expiry(self) -> None:
        clock = [BASE_TS]
        entry = Suppression(
            rule="R001", user=None, ip=ATTACKER_IP, expires=BASE_TS + timedelta(hours=1)
        )
        matcher = SuppressionMatcher([entry], lambda: clock[0])
        assert matcher.match_fields("R001", ATTACKER_IP, None, "error") is entry
        clock[0] = BASE_TS + timedelta(hours=1, seconds=1)
        assert matcher.match_fields("R001", ATTACKER_IP, None, "error") is None

    def test_matcher_accepts_a_fixed_datetime(self) -> None:
        entry = Suppression(
            rule="R001", user=None, ip=ATTACKER_IP, expires=BASE_TS + timedelta(hours=1)
        )
        assert len(SuppressionMatcher([entry], BASE_TS)) == 1
        assert len(SuppressionMatcher([entry], BASE_TS + timedelta(days=1))) == 0


# -- 2. gate trust root ------------------------------------------------------------


class TestGateTrustRoot:
    def test_tampered_scenario_file_is_rejected(self, bench_copy: Path) -> None:
        log = bench_copy / "scenarios" / "r001_ssh_bruteforce" / "auth.log"
        with log.open("a", encoding="utf-8", newline="") as handle:
            handle.write("2026-01-07T12:05:00+00:00 web01 sshd[1]: Accepted password for x\n")

        result = evaluate_threshold(bench_copy, load_config(None))

        assert not result.accepted
        assert any("frozen benchmark failed verification" in r for r in result.reasons)

    def test_empty_scenarios_dir_with_updated_manifest_is_rejected(
        self, bench_copy: Path
    ) -> None:
        scenarios = bench_copy / "scenarios"
        shutil.rmtree(scenarios)
        scenarios.mkdir()
        write_manifest(bench_copy)

        result = evaluate_threshold(bench_copy, load_config(None))

        assert not result.accepted
        # The runner refuses an empty tree itself; the gate's own "no attack scenarios"
        # check is the second line of defence. Either way it must be rejected.
        assert any(
            "no attack scenarios" in r.lower() or "no scenarios" in r.lower()
            for r in result.reasons
        )

    def test_benchmark_already_failing_under_current_config_is_rejected(
        self, bench_copy: Path
    ) -> None:
        config = load_config(None)
        config.detection.brute_force_attempts = 50

        result = evaluate_threshold(bench_copy, config)

        assert not result.accepted
        assert any("already failing" in r for r in result.reasons)

    def test_missing_benchmark_directory_is_rejected(self, tmp_path: Path) -> None:
        result = evaluate_threshold(tmp_path / "nope", load_config(None))
        assert not result.accepted
        assert any("frozen benchmark not found" in r for r in result.reasons)


# -- 3. true-positive protection ------------------------------------------------------


class TestTruePositiveProtection:
    def _feedback(self, tmp_path: Path, tp_context: dict[str, Any]) -> list[Any]:
        env = make_env(tmp_path)
        store = env.store()
        try:
            save_alert(store, "R001", label="tp", score=20.0, ip="203.0.113.9", **tp_context)
            for _ in range(3):
                save_alert(store, "R001", label="fp", attempts=6)
            return store.list_feedback()
        finally:
            store.close()

    def test_low_score_true_positive_at_threshold_edge_counts_as_lost(
        self, tmp_path: Path
    ) -> None:
        feedback = self._feedback(tmp_path, {"attempts": 6})
        result = evaluate_threshold(BENCH, load_config(None), feedback)

        assert result.tp_lost >= 1
        assert result.fp_after < result.fp_before
        assert not result.accepted
        assert any("true positive" in r for r in result.reasons)

    def test_true_positive_without_attempts_evidence_counts_as_lost_when_raising(
        self, tmp_path: Path
    ) -> None:
        feedback = self._feedback(tmp_path, {})
        result = evaluate_threshold(BENCH, load_config(None), feedback)

        assert result.tp_lost >= 1
        assert not result.accepted

    def test_replay_context_flags_evidence_less_alert_as_unverifiable(
        self, tmp_path: Path
    ) -> None:
        feedback = self._feedback(tmp_path, {})
        context = ReplayContext(load_config(None), GATE_NOW)
        tp = next(e for e in feedback if e.label == "tp")
        assert context.threshold_unverifiable(tp)

    def test_replay_context_with_attempts_is_verifiable(self, tmp_path: Path) -> None:
        feedback = self._feedback(tmp_path, {"attempts": 6})
        context = ReplayContext(load_config(None), GATE_NOW)
        tp = next(e for e in feedback if e.label == "tp")
        assert not context.threshold_unverifiable(tp)


# -- 4. CLI hardening ----------------------------------------------------------------------


@pytest.fixture()
def argv_for(monkeypatch: pytest.MonkeyPatch) -> Any:
    """CliRunner does not touch sys.argv; the CLI inspects it for --rollback/--history."""

    def _set(*args: str) -> None:
        monkeypatch.setattr(sys, "argv", ["sentinel", *args])

    return _set


class TestCorruptedOverlay:
    @pytest.fixture(params=["firewall:\n  backend: iptables\n", "detection: [unclosed\n  - : :"])
    def broken(self, request: pytest.FixtureRequest, tmp_path: Path) -> Env:
        env = make_env(tmp_path)
        env.overlay.write_text(request.param, encoding="utf-8")
        return env

    def test_history_works_with_corrupted_overlay(self, broken: Env, argv_for: Any) -> None:
        argv_for("tune", "--history")
        result = run_cli(broken, "tune", "--history")
        assert result.exit_code == 0, full_output(result)
        assert "No tuning changes recorded" in full_output(result)

    def test_rollback_with_corrupted_overlay_is_not_a_config_error(
        self, broken: Env, argv_for: Any
    ) -> None:
        argv_for("tune", "--rollback")
        result = run_cli(broken, "tune", "--rollback")
        # Nothing to roll back is a clean failure, but never the configuration error.
        assert "Configuration error" not in full_output(result)
        assert "nothing to roll back" in full_output(result).lower()

    def test_scan_with_corrupted_overlay_exits_nonzero(self, broken: Env, argv_for: Any) -> None:
        log = broken.root / "auth.log"
        log.write_text(
            "2026-01-07T12:00:00+00:00 web01 sshd[1]: Failed password for a from 203.0.113.9\n",
            encoding="utf-8",
        )
        argv_for("scan", str(log))
        result = run_cli(broken, "scan", str(log), "--no-ai")
        assert result.exit_code != 0
        assert "Configuration error" in full_output(result)


class TestFeedbackAudit:
    def _audit_lines(self, env: Env) -> list[dict[str, Any]]:
        lines = env.audit.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def test_first_feedback_writes_audit_line_with_null_previous_label(
        self, tmp_path: Path
    ) -> None:
        env = make_env(tmp_path)
        store = env.store()
        try:
            alert_id = save_alert(store, "R001")
        finally:
            store.close()

        result = run_cli(env, "feedback", str(alert_id), "--fp")
        assert result.exit_code == 0, full_output(result)

        (record,) = [r for r in self._audit_lines(env) if r["event"] == "feedback"]
        assert record["alert_id"] == alert_id
        assert record["label"] == "fp"
        assert record["previous_label"] is None
        assert record["rule_id"] == "R001"

    def test_relabelling_records_the_previous_label(self, tmp_path: Path) -> None:
        env = make_env(tmp_path)
        store = env.store()
        try:
            alert_id = save_alert(store, "R001")
        finally:
            store.close()

        for flag in ("--fp", "--tp", "--fp"):
            assert run_cli(env, "feedback", str(alert_id), flag).exit_code == 0

        records = [r for r in self._audit_lines(env) if r["event"] == "feedback"]
        assert [r["previous_label"] for r in records] == [None, "fp", "tp"]
        assert [r["label"] for r in records] == ["fp", "tp", "fp"]


class TestReviewSanitising:
    def test_clean_strips_escape_sequences(self) -> None:
        cleaned = _clean("evil\x1b[2J title\x07\x00\x7f\x9b")
        assert "\x1b" not in cleaned
        assert all(ch in "\t\n" or ord(ch) >= 32 and not 0x7F <= ord(ch) <= 0x9F for ch in cleaned)

    def test_clean_keeps_tab_and_newline(self) -> None:
        assert _clean("a\tb\nc") == "a\tb\nc"

    def test_clean_leaves_plain_text_untouched(self) -> None:
        assert _clean("Brute force from 203.0.113.5") == "Brute force from 203.0.113.5"

    def test_review_panel_strips_escape_from_title(self) -> None:
        from rich.console import Console

        from sentinelai.cli.commands.tuning import _review_panel

        rule = available_rules()["R001"]()
        alert = rule.make_alert(make_event(ip=ATTACKER_IP, user="a\x1b[31mb"), "x\x1b[2Jy", "d")
        RiskEngine().score(alert)
        alert.id = 1

        console = Console(record=True, width=100, force_terminal=False)
        console.print(_review_panel(alert, 1, 1))
        text = console.export_text()

        assert "\x1b" not in text
        assert "x[2Jy" in text
