"""Phase 4 acceptance: safe active response, end to end.

Drives a real :class:`AnalysisPipeline` and the real ``sentinel respond``
CLI against an in-memory fake firewall (no real firewall is ever touched).
Covers self-lockout protection, temporary blocks and their TTL, approval
mode, the hourly circuit breaker and the operator CLI.
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
from click.testing import CliRunner, Result

import sentinelai.detection.rules  # noqa: F401  (registers the built-in rules)
from sentinelai.cli.app import cli
from sentinelai.config.loader import load_config
from sentinelai.core.pipeline import AnalysisPipeline, ScanResult
from sentinelai.core.store import AlertStore
from sentinelai.firewall.operator import ResponseOperator
from sentinelai.parsers.reader import read_events

ADMIN_IP = "198.51.100.5"
ADMIN_RANGE = "198.51.100.0/24"
EXTERNAL_IP = "203.0.113.9"
OTHER_IP = "203.0.113.20"
THIRD_IP = "203.0.113.30"


# -- fakes and helpers -----------------------------------------------------


class FakeFirewall:
    """In-memory FirewallController shared across pipeline instances."""

    def __init__(self) -> None:
        self.blocked: set[str] = set()
        self.calls: list[tuple[str, str]] = []

    def block_ip(self, ip: str) -> bool:
        self.calls.append(("block_ip", ip))
        self.blocked.add(ip)
        return True

    def unblock_ip(self, ip: str) -> bool:
        self.calls.append(("unblock_ip", ip))
        self.blocked.discard(ip)
        return True

    def temporary_block(self, ip: str, duration_seconds: int) -> bool:
        self.calls.append(("temporary_block", ip))
        self.blocked.add(ip)
        return True

    def list_blocked(self) -> list[str]:
        return sorted(self.blocked)

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked


@dataclass
class Env:
    """A throwaway state directory plus the config file pointing at it."""

    root: Path
    state: Path
    cfg: Path

    @property
    def audit_path(self) -> Path:
        return self.state / "response" / "audit.jsonl"

    def store(self) -> AlertStore:
        return AlertStore(self.state / "alerts.db")

    def audit(self, decision: str | None = None) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        records = [
            json.loads(line)
            for line in self.audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if decision is None:
            return records
        return [r for r in records if r.get("decision") == decision]

    def actions(self, **filters: Any) -> list[Any]:
        store = self.store()
        try:
            return store.list_response_actions(**filters)
        finally:
            store.close()

    def pending(self, status: str | None = "pending") -> list[Any]:
        store = self.store()
        try:
            return store.list_pending(status)
        finally:
            store.close()

    def write_config(self, **response: Any) -> None:
        settings: dict[str, Any] = {
            "enabled": True,
            "min_risk_level": "medium",
            "temporary_block": True,
            "block_duration_seconds": 3600,
            "admin_ranges": [ADMIN_RANGE],
            # Keep the guard hermetic: no gateway / host-address probing.
            "protect_gateway": False,
            "protect_own_addresses": False,
        }
        settings.update(response)
        data = {"state_dir": self.state.as_posix(), "response": settings}
        self.cfg.write_text(yaml.safe_dump(data), encoding="utf-8")


def make_env(root: Path, **response: Any) -> Env:
    state = root / "state"
    state.mkdir(parents=True, exist_ok=True)
    env = Env(root=root, state=state, cfg=root / "config.yaml")
    env.write_config(**response)
    return env


def write_bruteforce_log(path: Path, ip: str) -> Path:
    lines = [
        f"2026-01-07T12:00:0{n}+00:00 web01 sshd[10]: "
        f"Failed password for root from {ip} port 4000{n} ssh2"
        for n in range(1, 9)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def scan(env: Env, ip: str, name: str | None = None) -> ScanResult:
    """Scan a fresh brute-force log from *ip* with a brand-new pipeline."""
    log = write_bruteforce_log(env.root / (name or f"auth_{ip}.log"), ip)
    pipeline = AnalysisPipeline(load_config(env.cfg))
    try:
        return pipeline.run_scan(read_events(log), use_ai=False)
    finally:
        pipeline.close()


def run_cli(env: Env, *args: str) -> Result:
    return CliRunner().invoke(cli, ["--config", str(env.cfg), "--no-plugins", "respond", *args])


@pytest.fixture(autouse=True)
def _no_ssh_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_CLIENT", raising=False)


@pytest.fixture()
def fw(monkeypatch: pytest.MonkeyPatch) -> FakeFirewall:
    fake = FakeFirewall()
    monkeypatch.setattr("sentinelai.core.pipeline.create_firewall", lambda _cfg: fake)
    return fake


@pytest.fixture()
def env(tmp_path: Path, fw: FakeFirewall) -> Iterator[Env]:
    yield make_env(tmp_path)


def _r001_ips(result: ScanResult) -> set[str | None]:
    return {a.ip for a in result.alerts if a.rule_id == "R001"}


# -- (1) admin IP is never blocked -----------------------------------------


class TestAdminIpProtected:
    def test_admin_ip_alert_raised_but_not_blocked(self, env: Env, fw: FakeFirewall) -> None:
        result = scan(env, ADMIN_IP)

        assert ADMIN_IP in _r001_ips(result)
        assert fw.blocked == set()
        assert fw.calls == []

    def test_admin_ip_leaves_no_response_action_row(self, env: Env) -> None:
        scan(env, ADMIN_IP)

        assert env.actions() == []

    def test_admin_ip_audit_records_skip_with_lockout_reason(self, env: Env) -> None:
        scan(env, ADMIN_IP)

        skipped = [r for r in env.audit("skipped") if r.get("ip") == ADMIN_IP]
        assert skipped
        assert any("self-lockout protection" in r["reason"] for r in skipped)
        assert any(ADMIN_RANGE in r["reason"] for r in skipped)
        assert env.audit("blocked") == []


# -- (2) external IP is blocked temporarily --------------------------------


class TestExternalIpBlocked:
    def test_external_ip_is_blocked_via_temporary_block(
        self, env: Env, fw: FakeFirewall
    ) -> None:
        result = scan(env, EXTERNAL_IP)

        assert EXTERNAL_IP in _r001_ips(result)
        assert EXTERNAL_IP in fw.blocked
        assert ("temporary_block", EXTERNAL_IP) in fw.calls
        assert not any(name == "block_ip" for name, _ in fw.calls)

    def test_external_ip_row_is_applied_and_expires_in_one_hour(self, env: Env) -> None:
        scan(env, EXTERNAL_IP)

        rows = [r for r in env.actions() if r.ip == EXTERNAL_IP]
        assert len(rows) == 1
        row = rows[0]
        assert row.status == "applied"
        assert row.rule_id == "R001"
        assert row.duration_seconds == 3600
        assert row.expires_at is not None
        expected = datetime.now(timezone.utc) + timedelta(hours=1)
        assert abs((row.expires_at - expected).total_seconds()) < 120

    def test_external_ip_audit_records_blocked_for_r001(self, env: Env) -> None:
        scan(env, EXTERNAL_IP)

        blocked = [r for r in env.audit("blocked") if r.get("ip") == EXTERNAL_IP]
        assert blocked
        assert blocked[0]["rule_id"] == "R001"

    def test_rescan_of_blocked_ip_does_not_block_twice(self, env: Env, fw: FakeFirewall) -> None:
        scan(env, EXTERNAL_IP, "first.log")
        scan(env, EXTERNAL_IP, "second.log")

        assert [c for c in fw.calls if c[0] == "temporary_block"] == [
            ("temporary_block", EXTERNAL_IP)
        ]
        assert len([r for r in env.actions() if r.ip == EXTERNAL_IP]) == 1


# -- (3) TTL: the reaper unblocks expired blocks ---------------------------


class TestTemporaryBlockExpiry:
    def _operator(self, env: Env, fw: FakeFirewall, now: datetime) -> ResponseOperator:
        pipeline = AnalysisPipeline(load_config(env.cfg))
        self._pipeline = pipeline
        return ResponseOperator(
            pipeline.response_config,
            fw,
            pipeline.store,
            pipeline.response_audit,
            pipeline.guard,
            clock=lambda: now,
        )

    def teardown_method(self) -> None:
        pipeline = getattr(self, "_pipeline", None)
        if pipeline is not None:
            pipeline.close()

    def test_reap_before_expiry_keeps_the_block(self, env: Env, fw: FakeFirewall) -> None:
        scan(env, EXTERNAL_IP)
        operator = self._operator(env, fw, datetime.now(timezone.utc) + timedelta(minutes=10))

        assert operator.reap() == []
        assert EXTERNAL_IP in fw.blocked

    def test_reap_after_expiry_unblocks_ip_and_marks_row_reaped(
        self, env: Env, fw: FakeFirewall
    ) -> None:
        scan(env, EXTERNAL_IP)
        operator = self._operator(env, fw, datetime.now(timezone.utc) + timedelta(hours=2))

        actions = operator.reap()

        assert [(a.action, a.ip, a.success) for a in actions] == [("unblock", EXTERNAL_IP, True)]
        assert EXTERNAL_IP not in fw.blocked
        assert [r.status for r in env.actions(ip=EXTERNAL_IP)] == ["reaped"]

    def test_reap_after_expiry_writes_reaped_audit_record(
        self, env: Env, fw: FakeFirewall
    ) -> None:
        scan(env, EXTERNAL_IP)
        self._operator(env, fw, datetime.now(timezone.utc) + timedelta(hours=2)).reap()

        reaped = env.audit("reaped")
        assert [r["ip"] for r in reaped] == [EXTERNAL_IP]
        assert reaped[0]["rule_id"] == "R001"

    def test_reap_twice_does_not_unblock_again(self, env: Env, fw: FakeFirewall) -> None:
        scan(env, EXTERNAL_IP)
        operator = self._operator(env, fw, datetime.now(timezone.utc) + timedelta(hours=2))
        operator.reap()

        assert operator.reap() == []
        assert fw.calls.count(("unblock_ip", EXTERNAL_IP)) == 1


# -- (4) SSH peer protection ------------------------------------------------


class TestSshPeerProtected:
    def test_current_ssh_peer_is_not_blocked(
        self, env: Env, fw: FakeFirewall, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_CONNECTION", f"{EXTERNAL_IP} 5555 192.0.2.10 22")

        result = scan(env, EXTERNAL_IP)

        assert EXTERNAL_IP in _r001_ips(result)
        assert fw.blocked == set()
        assert env.actions() == []
        skipped = [r for r in env.audit("skipped") if r.get("ip") == EXTERNAL_IP]
        assert any("SSH session" in r["reason"] for r in skipped)

    def test_other_ip_is_still_blocked_while_ssh_peer_is_protected(
        self, env: Env, fw: FakeFirewall, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_CONNECTION", f"{EXTERNAL_IP} 5555 192.0.2.10 22")

        scan(env, OTHER_IP)

        assert fw.blocked == {OTHER_IP}


# -- (5) approval mode -------------------------------------------------------


class TestApprovalMode:
    @pytest.fixture()
    def env(self, tmp_path: Path, fw: FakeFirewall) -> Env:
        return make_env(tmp_path, mode="approval")

    def test_scan_queues_pending_row_and_blocks_nothing(self, env: Env, fw: FakeFirewall) -> None:
        scan(env, EXTERNAL_IP)

        pending = env.pending()
        assert [(p.ip, p.rule_id, p.status) for p in pending] == [(EXTERNAL_IP, "R001", "pending")]
        assert fw.blocked == set()
        assert fw.calls == []
        assert env.actions() == []
        assert [r["ip"] for r in env.audit("queued")] == [EXTERNAL_IP]

    def test_pending_listing_shows_queued_request(self, env: Env) -> None:
        scan(env, EXTERNAL_IP)

        result = run_cli(env, "--pending")

        assert result.exit_code == 0, result.output
        assert EXTERNAL_IP in result.output
        assert "R001" in result.output

    def test_pending_listing_when_empty_says_so(self, env: Env) -> None:
        result = run_cli(env, "--pending")

        assert result.exit_code == 0, result.output
        assert "No pending responses" in result.output

    def test_approve_blocks_the_ip_and_records_applied_action(
        self, env: Env, fw: FakeFirewall
    ) -> None:
        scan(env, EXTERNAL_IP)
        pending_id = env.pending()[0].id

        result = run_cli(env, "--approve", str(pending_id), "--yes")

        assert result.exit_code == 0, result.output
        assert EXTERNAL_IP in fw.blocked
        assert [r.status for r in env.actions(ip=EXTERNAL_IP)] == ["applied"]
        assert env.pending() == []
        assert [r["ip"] for r in env.audit("blocked")] == [EXTERNAL_IP]

    def test_approve_after_ip_joined_admin_ranges_is_refused(
        self, env: Env, fw: FakeFirewall
    ) -> None:
        scan(env, OTHER_IP)
        pending_id = env.pending()[0].id
        env.write_config(mode="approval", admin_ranges=[ADMIN_RANGE, "203.0.113.0/24"])

        result = run_cli(env, "--approve", str(pending_id), "--yes")

        assert result.exit_code == 1
        assert fw.blocked == set()
        assert fw.calls == []
        assert env.actions() == []
        assert [p.status for p in env.pending(None)] == ["denied"]
        assert any("self-lockout" in r["reason"] for r in env.audit("denied"))

    def test_approve_unknown_id_fails_with_exit_code_one(self, env: Env, fw: FakeFirewall) -> None:
        result = run_cli(env, "--approve", "999", "--yes")

        assert result.exit_code == 1
        assert fw.blocked == set()

    def test_deny_blocks_nothing_and_marks_request_denied(
        self, env: Env, fw: FakeFirewall
    ) -> None:
        scan(env, EXTERNAL_IP)
        pending_id = env.pending()[0].id

        result = run_cli(env, "--deny", str(pending_id), "--yes")

        assert result.exit_code == 0, result.output
        assert fw.blocked == set()
        assert fw.calls == []
        assert env.actions() == []
        assert [p.status for p in env.pending(None)] == ["denied"]
        assert [r["ip"] for r in env.audit("denied")] == [EXTERNAL_IP]

    def test_denied_request_cannot_be_approved_afterwards(
        self, env: Env, fw: FakeFirewall
    ) -> None:
        scan(env, EXTERNAL_IP)
        pending_id = env.pending()[0].id
        run_cli(env, "--deny", str(pending_id), "--yes")

        result = run_cli(env, "--approve", str(pending_id), "--yes")

        assert result.exit_code == 1
        assert fw.blocked == set()


# -- (6) hourly circuit breaker across runs ---------------------------------


class TestHourlyCircuitBreaker:
    @pytest.fixture()
    def env(self, tmp_path: Path, fw: FakeFirewall) -> Env:
        return make_env(tmp_path, max_blocks_per_hour=1)

    def test_second_run_in_same_hour_is_not_blocked(self, env: Env, fw: FakeFirewall) -> None:
        scan(env, EXTERNAL_IP)
        scan(env, OTHER_IP)

        assert fw.blocked == {EXTERNAL_IP}
        assert [r.ip for r in env.actions()] == [EXTERNAL_IP]

    def test_second_run_audits_circuit_breaker(self, env: Env) -> None:
        scan(env, EXTERNAL_IP)
        scan(env, OTHER_IP)

        tripped = env.audit("circuit_breaker")
        assert tripped
        assert {r["ip"] for r in tripped} == {OTHER_IP}
        assert all("circuit breaker" in r["reason"] for r in tripped)

    def test_approval_of_a_further_block_is_refused_when_breaker_is_open(
        self, tmp_path: Path, fw: FakeFirewall
    ) -> None:
        env = make_env(tmp_path, mode="approval", max_blocks_per_hour=1)
        scan(env, EXTERNAL_IP)
        scan(env, OTHER_IP)
        first, second = (p.id for p in env.pending())
        assert run_cli(env, "--approve", str(first), "--yes").exit_code == 0

        result = run_cli(env, "--approve", str(second), "--yes")

        assert result.exit_code == 1
        assert fw.blocked == {EXTERNAL_IP}


# -- (7) the respond CLI ------------------------------------------------------


class TestRespondCliUsage:
    def test_no_action_is_a_usage_error(self, env: Env) -> None:
        assert run_cli(env).exit_code == 2

    def test_two_actions_is_a_usage_error(self, env: Env) -> None:
        assert run_cli(env, "--pending", "--history").exit_code == 2

    def test_rollback_without_since_or_run_is_a_usage_error(self, env: Env) -> None:
        assert run_cli(env, "--rollback", "--yes").exit_code == 2

    def test_since_without_rollback_is_a_usage_error(self, env: Env) -> None:
        assert run_cli(env, "--pending", "--since", "1h").exit_code == 2

    def test_invalid_since_value_is_a_usage_error(self, env: Env) -> None:
        assert run_cli(env, "--rollback", "--since", "yesterday-ish", "--yes").exit_code == 2

    def test_note_without_approve_or_deny_is_a_usage_error(self, env: Env) -> None:
        assert run_cli(env, "--pending", "--note", "hi").exit_code == 2


class TestRespondCliActions:
    def test_rollback_unblocks_applied_blocks_and_marks_rolled_back(
        self, env: Env, fw: FakeFirewall
    ) -> None:
        scan(env, EXTERNAL_IP)
        scan(env, OTHER_IP)
        assert fw.blocked == {EXTERNAL_IP, OTHER_IP}

        result = run_cli(env, "--rollback", "--since", "1h", "--yes")

        assert result.exit_code == 0, result.output
        assert fw.blocked == set()
        assert {r.status for r in env.actions()} == {"rolled_back"}
        assert {r["ip"] for r in env.audit("rolled_back")} == {EXTERNAL_IP, OTHER_IP}

    def test_rollback_by_run_id_only_touches_that_run(self, env: Env, fw: FakeFirewall) -> None:
        scan(env, EXTERNAL_IP)
        scan(env, OTHER_IP)
        first_run = env.actions()[0].run_id

        result = run_cli(env, "--rollback", "--run", first_run, "--yes")

        assert result.exit_code == 0, result.output
        assert fw.blocked == {OTHER_IP}

    def test_rollback_with_nothing_to_undo_succeeds(self, env: Env, fw: FakeFirewall) -> None:
        result = run_cli(env, "--rollback", "--since", "1h", "--yes")

        assert result.exit_code == 0, result.output
        assert "Nothing to roll back" in result.output

    def test_reap_unblocks_due_blocks(self, env: Env, fw: FakeFirewall) -> None:
        now = datetime.now(timezone.utc)
        fw.blocked.update({EXTERNAL_IP, OTHER_IP})
        store = env.store()
        try:
            for ip, expires in ((EXTERNAL_IP, now - timedelta(minutes=5)),
                                (OTHER_IP, now + timedelta(hours=1))):
                store.add_response_action(
                    action="temporary_block",
                    ip=ip,
                    duration_seconds=3600,
                    expires_at=expires,
                    status="applied",
                    alert_id=None,
                    rule_id="R001",
                    run_id="seed",
                    ts=now - timedelta(minutes=30),
                )
        finally:
            store.close()

        result = run_cli(env, "--reap", "--yes")

        assert result.exit_code == 0, result.output
        assert fw.blocked == {OTHER_IP}
        statuses = {r.ip: r.status for r in env.actions()}
        assert statuses == {EXTERNAL_IP: "reaped", OTHER_IP: "applied"}
        assert [r["ip"] for r in env.audit("reaped")] == [EXTERNAL_IP]

    def test_reap_with_nothing_due_succeeds(self, env: Env) -> None:
        result = run_cli(env, "--reap", "--yes")

        assert result.exit_code == 0, result.output
        assert "No expired blocks" in result.output

    def test_history_prints_recorded_decisions(self, env: Env) -> None:
        scan(env, EXTERNAL_IP)
        scan(env, ADMIN_IP)

        result = run_cli(env, "--history")

        assert result.exit_code == 0, result.output
        assert "blocked" in result.output
        assert "skipped" in result.output
        assert EXTERNAL_IP in result.output

    def test_history_without_records_says_so(self, env: Env) -> None:
        result = run_cli(env, "--history")

        assert result.exit_code == 0, result.output
        assert "No response decisions" in result.output


class TestRespondCliConfirmation:
    """Mutating actions refuse to run non-interactively without --yes."""

    def test_rollback_without_yes_aborts_and_changes_nothing(
        self, env: Env, fw: FakeFirewall
    ) -> None:
        scan(env, EXTERNAL_IP)

        result = run_cli(env, "--rollback", "--since", "1h")

        assert result.exit_code == 1
        assert fw.blocked == {EXTERNAL_IP}
        assert [r.status for r in env.actions()] == ["applied"]

    def test_reap_without_yes_aborts_and_changes_nothing(
        self, env: Env, fw: FakeFirewall
    ) -> None:
        scan(env, EXTERNAL_IP)

        result = run_cli(env, "--reap")

        assert result.exit_code == 1
        assert fw.blocked == {EXTERNAL_IP}
        assert [r.status for r in env.actions()] == ["applied"]

    def test_approve_without_yes_aborts_and_blocks_nothing(
        self, tmp_path: Path, fw: FakeFirewall
    ) -> None:
        env = make_env(tmp_path, mode="approval")
        scan(env, EXTERNAL_IP)
        pending_id = env.pending()[0].id

        result = run_cli(env, "--approve", str(pending_id))

        assert result.exit_code == 1
        assert fw.blocked == set()
        assert [p.status for p in env.pending(None)] == ["pending"]

    def test_deny_without_yes_aborts_and_keeps_request_pending(
        self, tmp_path: Path, fw: FakeFirewall
    ) -> None:
        env = make_env(tmp_path, mode="approval")
        scan(env, EXTERNAL_IP)
        pending_id = env.pending()[0].id

        result = run_cli(env, "--deny", str(pending_id))

        assert result.exit_code == 1
        assert [p.status for p in env.pending(None)] == ["pending"]

    def test_read_only_actions_need_no_confirmation(self, env: Env) -> None:
        assert run_cli(env, "--pending").exit_code == 0
        assert run_cli(env, "--history").exit_code == 0
