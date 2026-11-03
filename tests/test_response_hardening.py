"""Hardening tests for the response subsystem (security fixes).

Covers canonical IP handling, fail-closed block tracking, flood limits,
approval race semantics, reaper/rollback edge cases, store primitives,
audit rotation, lockout fail-closed behaviour and the ``respond`` CLI.

Self-contained on purpose: only an in-memory fake firewall is used, so no
real firewall is ever touched. All addresses are documentation ranges.
"""

from __future__ import annotations

import json
import re
import sqlite3
import subprocess
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner, Result

import sentinelai.detection.rules  # noqa: F401  (registers built-in rules)
from sentinelai.cli.app import cli
from sentinelai.config.models import ResponseConfig
from sentinelai.core.exceptions import FirewallError, StorageError
from sentinelai.core.models import Alert
from sentinelai.core.store import AlertStore
from sentinelai.detection.base import available_rules
from sentinelai.firewall.audit import ResponseAudit
from sentinelai.firewall.lockout import LockoutGuard
from sentinelai.firewall.operator import ResponseOperator
from sentinelai.firewall.responder import AutoResponder, execute_block
from sentinelai.risk.engine import RiskEngine
from sentinelai.utils.net import (
    blockable_reason,
    canonical_ip,
    ip_in_networks,
    is_valid_ip,
)
from tests.conftest import make_event

NOW = datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)

IP_A = "203.0.113.10"
IP_B = "198.51.100.20"
IP_C = "192.0.2.30"
V6 = "2001:db8::1"
V6_LONG = "2001:0db8::1"
FAIL_CLOSED = "could not evaluate lockout protection"


# -- helpers ---------------------------------------------------------------


class Clock:
    """Injectable, mutable UTC clock."""

    def __init__(self, start: datetime = NOW) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


class FakeFirewall:
    """In-memory FirewallController that records calls and can be told to fail."""

    def __init__(self) -> None:
        self.blocked: set[str] = set()
        self.calls: list[tuple[str, str, int | None]] = []
        self.block_result = True
        self.block_error: Exception | None = None
        self.unblock_result = True

    def _block(self, name: str, ip: str, duration: int | None) -> bool:
        self.calls.append((name, ip, duration))
        if self.block_error is not None:
            raise self.block_error
        if not self.block_result:
            return False
        self.blocked.add(ip)
        return True

    def block_ip(self, ip: str) -> bool:
        return self._block("block_ip", ip, None)

    def temporary_block(self, ip: str, duration_seconds: int) -> bool:
        return self._block("temporary_block", ip, duration_seconds)

    def unblock_ip(self, ip: str) -> bool:
        self.calls.append(("unblock_ip", ip, None))
        if not self.unblock_result:
            return False
        self.blocked.discard(ip)
        return True

    def list_blocked(self) -> list[str]:
        return sorted(self.blocked)

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked

    def calls_named(self, name: str) -> list[tuple[str, str, int | None]]:
        return [c for c in self.calls if c[0] == name]


def make_config(**overrides: Any) -> ResponseConfig:
    """Enabled config with lockout flags off (tests opt in explicitly)."""
    values: dict[str, Any] = {
        "enabled": True,
        "protect_ssh_peer": False,
        "protect_gateway": False,
        "protect_own_addresses": False,
    }
    values.update(overrides)
    return ResponseConfig(**values)


def make_alert(ip: str | None, *, alert_id: int | None = 1) -> Alert:
    """Build a real, risk-scored HIGH alert (R031 with 20 events)."""
    rule = available_rules()["R031"]()
    alert = rule.make_alert(make_event(ip=ip), "R031 test", "synthetic alert")
    alert.event_count = 20
    RiskEngine().score(alert)
    alert.ip = ip
    alert.id = alert_id
    return alert


def make_guard(config: ResponseConfig, **kwargs: Any) -> LockoutGuard:
    kwargs.setdefault("env", {})
    kwargs.setdefault("own_addresses", set)
    kwargs.setdefault("gateways", set)
    return LockoutGuard(config, **kwargs)


def add_action(
    store: AlertStore,
    ip: str,
    *,
    expires_at: datetime | None,
    status: str = "applied",
    run_id: str = "run-x",
    ts: datetime = NOW,
) -> int:
    return store.add_response_action(
        action="temporary_block" if expires_at is not None else "block_ip",
        ip=ip,
        duration_seconds=3600 if expires_at is not None else None,
        expires_at=expires_at,
        status=status,
        alert_id=None,
        rule_id="R031",
        run_id=run_id,
        ts=ts,
    )


def add_pending(store: AlertStore, ip: str, ts: datetime = NOW) -> int:
    return store.add_pending(
        ip=ip,
        alert_id=None,
        rule_id="R031",
        risk_level="high",
        risk_score=80.0,
        action="temporary_block",
        duration_seconds=3600,
        ts=ts,
    )


def fill_pending(store: AlertStore, count: int) -> None:
    for i in range(count):
        add_pending(store, f"198.18.{i // 200}.{i % 200 + 1}")


class Rig:
    """Real store + audit log with a fake firewall and shared clock."""

    def __init__(self, tmp_path: Path) -> None:
        self.db_path = tmp_path / "alerts.db"
        self.store = AlertStore(self.db_path)
        self.audit = ResponseAudit(tmp_path / "audit.jsonl")
        self.clock = Clock()
        self.fw = FakeFirewall()

    def responder(
        self, config: ResponseConfig | None = None, *, guard: LockoutGuard | None = None
    ) -> AutoResponder:
        return AutoResponder(
            config or make_config(),
            self.fw,
            store=self.store,
            audit=self.audit,
            guard=guard,
            run_id="run-1",
            clock=self.clock,
        )

    def operator(
        self, config: ResponseConfig | None = None, *, guard: LockoutGuard | None = None
    ) -> ResponseOperator:
        return ResponseOperator(
            config or make_config(), self.fw, self.store, self.audit, guard, self.clock
        )

    def queue(self, ip: str = IP_A, *, alert_id: int = 1) -> int:
        alert = make_alert(ip, alert_id=alert_id)
        self.responder(make_config(mode="approval")).consider(alert)
        return int(alert.context["response"]["pending_id"])

    def decisions(self) -> list[str]:
        return [r["decision"] for r in self.audit.read(500)]

    def records(self, decision: str) -> list[dict[str, Any]]:
        return [r for r in self.audit.read(500) if r["decision"] == decision]

    def pending_status(self, pending_id: int) -> str:
        row = self.store.get_pending(pending_id)
        assert row is not None
        return row.status


@pytest.fixture()
def rig(tmp_path: Path) -> Iterator[Rig]:
    r = Rig(tmp_path)
    try:
        yield r
    finally:
        r.store.close()


@pytest.fixture()
def store(tmp_path: Path) -> Iterator[AlertStore]:
    s = AlertStore(tmp_path / "store.db")
    try:
        yield s
    finally:
        s.close()


# -- (1) canonical IPs -------------------------------------------------------

REJECTED = [
    "fe80::1%eth0",
    "2606:4700::1%x",
    " 203.0.113.7",
    "203.0.113.7 ",
    "203.0.113.7\n",
    "203.0.113. 7",
    "203.0.113.7/32",
    "2001:db8::/32",
    "10.0.0.0/8",
    "",
    "not-an-ip",
    "203.0.113.7\x00",
    "1" * 80,
    None,
    123,
    b"203.0.113.7",
    ["203.0.113.7"],
]


class TestCanonicalIp:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("203.0.113.7", "203.0.113.7"),
            ("2001:db8::1", "2001:db8::1"),
            ("2001:0DB8::1", "2001:db8::1"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            ("::ffff:203.0.113.7", "203.0.113.7"),
            ("::FFFF:203.0.113.7", "203.0.113.7"),
            ("::ffff:cb00:710a", "203.0.113.10"),
        ],
    )
    def test_plain_addresses_are_canonicalised(self, raw: str, expected: str) -> None:
        assert canonical_ip(raw) == expected

    @pytest.mark.parametrize("raw", REJECTED)
    def test_unsafe_or_malformed_input_is_rejected(self, raw: Any) -> None:
        assert canonical_ip(raw) is None

    @pytest.mark.parametrize("raw", REJECTED + ["203.0.113.7", "2001:0DB8::1", "::ffff:1.2.3.4"])
    def test_is_valid_ip_agrees_with_canonical_ip(self, raw: Any) -> None:
        assert is_valid_ip(raw) is (canonical_ip(raw) is not None)

    def test_ipv4_mapped_address_matches_ipv4_allowlist(self) -> None:
        assert ip_in_networks("::ffff:203.0.113.7", ["203.0.113.7/32"]) is True

    def test_zone_id_address_never_matches_a_network(self) -> None:
        assert ip_in_networks("fe80::1%eth0", ["fe80::/10"]) is False

    def test_invalid_cidr_entries_are_skipped_not_fatal(self) -> None:
        assert ip_in_networks(IP_A, ["garbage", "203.0.113.0/24"]) is True
        assert ip_in_networks(IP_A, ["garbage"]) is False

    @pytest.mark.parametrize(
        "ip",
        [
            "0.0.0.0",
            "255.255.255.255",
            "::",
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "224.0.0.1",
            "ff02::1",
            "169.254.1.1",
            "fe80::1",
            "240.0.0.1",
        ],
    )
    def test_never_blockable_addresses_have_a_reason(self, ip: str) -> None:
        reason = blockable_reason(ip)
        assert reason is not None
        assert "never blocked" in reason

    @pytest.mark.parametrize("ip", [IP_A, "8.8.8.8", V6, "2001:4860:4860::8888"])
    def test_public_addresses_are_blockable(self, ip: str) -> None:
        assert blockable_reason(ip) is None

    @pytest.mark.parametrize("ip", ["garbage", "fe80::1%eth0", ""])
    def test_invalid_addresses_report_not_valid(self, ip: str) -> None:
        assert blockable_reason(ip) == "not a valid IP address"


class TestCanonicalIpInResponder:
    def test_mapped_allowlisted_ip_is_not_blocked_in_auto_mode(self, rig: Rig) -> None:
        cfg = make_config(allowlist=["203.0.113.0/24"])
        assert rig.responder(cfg).consider(make_alert("::ffff:" + IP_A)) is None
        assert rig.fw.calls == []
        assert rig.store.list_response_actions() == []
        (record,) = rig.audit.read()
        assert "allowlisted" in record["reason"]
        assert record["ip"] == IP_A

    def test_mapped_allowlisted_ip_is_not_queued_in_approval_mode(self, rig: Rig) -> None:
        cfg = make_config(mode="approval", allowlist=["203.0.113.0/24"])
        assert rig.responder(cfg).consider(make_alert("::ffff:" + IP_A)) is None
        assert rig.store.list_pending(None) == []

    def test_mapped_admin_ip_is_protected_by_the_guard(self, rig: Rig) -> None:
        cfg = make_config(admin_ranges=["203.0.113.0/24"])
        guard = make_guard(cfg)
        assert rig.responder(cfg, guard=guard).consider(make_alert("::ffff:" + IP_A)) is None
        assert rig.fw.calls == []
        assert "self-lockout protection" in rig.audit.read()[0]["reason"]

    @pytest.mark.parametrize("raw", ["fe80::1%eth0", "2606:4700::1%x", " " + IP_A, IP_A + "/32"])
    def test_unsafe_ip_text_is_skipped_as_invalid(self, rig: Rig, raw: str) -> None:
        assert rig.responder().consider(make_alert(raw)) is None
        assert rig.fw.calls == []
        assert rig.store.list_response_actions() == []
        (record,) = rig.audit.read()
        assert "no valid source IP" in record["reason"]

    @pytest.mark.parametrize(("first", "second"), [(V6, V6_LONG), (V6_LONG, V6)])
    def test_spellings_share_already_blocked_state(
        self, rig: Rig, first: str, second: str
    ) -> None:
        rig.fw.blocked.add(V6)
        assert rig.responder().consider(make_alert(first)) is None
        assert rig.responder().consider(make_alert(second, alert_id=2)) is None
        assert rig.fw.calls == []
        assert all("already blocked" in r["reason"] for r in rig.records("skipped"))

    @pytest.mark.parametrize(("first", "second"), [(V6, V6_LONG), (V6_LONG, V6)])
    def test_spellings_share_the_cooldown(self, rig: Rig, first: str, second: str) -> None:
        responder = rig.responder()
        assert responder.consider(make_alert(first)) is not None
        rig.fw.blocked.clear()  # externally unblocked; only the cooldown remains
        assert responder.consider(make_alert(second, alert_id=2)) is None
        assert rig.fw.calls == [("temporary_block", V6, 3600)]
        assert "in cooldown" in rig.records("skipped")[0]["reason"]

    def test_mapped_and_plain_ipv4_share_the_cooldown(self, rig: Rig) -> None:
        responder = rig.responder()
        assert responder.consider(make_alert("::ffff:" + IP_A)) is not None
        rig.fw.blocked.clear()
        assert responder.consider(make_alert(IP_A, alert_id=2)) is None
        assert len(rig.fw.calls) == 1

    @pytest.mark.parametrize(("first", "second"), [(V6, V6_LONG), (V6_LONG, V6)])
    def test_spellings_share_pending_dedup(self, rig: Rig, first: str, second: str) -> None:
        responder = rig.responder(make_config(mode="approval"))
        responder.consider(make_alert(first))
        responder.consider(make_alert(second, alert_id=2))
        (row,) = rig.store.list_pending(None)
        assert row.ip == V6
        assert "already pending approval" in rig.records("skipped")[0]["reason"]

    @pytest.mark.parametrize("raw", [V6_LONG, "2001:0DB8::1", "::ffff:" + IP_A])
    def test_db_firewall_and_audit_only_see_the_canonical_string(
        self, rig: Rig, raw: str
    ) -> None:
        action = rig.responder().consider(make_alert(raw))
        expected = canonical_ip(raw)
        assert action is not None and action.ip == expected
        assert [c[1] for c in rig.fw.calls] == [expected]
        assert [r.ip for r in rig.store.list_response_actions()] == [expected]
        assert [r["ip"] for r in rig.audit.read()] == [expected]

    def test_skip_audit_throttle_treats_spellings_as_one_key(self, rig: Rig) -> None:
        responder = rig.responder(make_config(allowlist=["203.0.113.0/24"]))
        responder.consider(make_alert(IP_A))
        responder.consider(make_alert("::ffff:" + IP_A, alert_id=2))
        assert len(rig.records("skipped")) == 1


# -- (2) fail-closed tracking ------------------------------------------------


def _storage_boom(*args: Any, **kwargs: Any) -> int:
    raise StorageError("disk full")


class TestFailClosedTracking:
    def test_untrackable_block_never_reaches_the_firewall(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(rig.store, "add_response_action", _storage_boom)
        action = rig.responder().consider(make_alert(IP_A))
        assert action is not None and action.success is False
        assert rig.fw.calls == []
        assert rig.decisions() == ["failed"]
        assert "untracked" in rig.records("failed")[0]["reason"]

    @pytest.mark.parametrize(
        "setup",
        ["false", "firewall_error", "runtime_error"],
    )
    def test_failed_block_is_recorded_failed_never_applied(self, rig: Rig, setup: str) -> None:
        if setup == "false":
            rig.fw.block_result = False
        elif setup == "firewall_error":
            rig.fw.block_error = FirewallError("ufw missing")
        else:
            rig.fw.block_error = RuntimeError("boom")
        action = rig.responder().consider(make_alert(IP_A))
        assert action is not None and action.success is False
        assert [r.status for r in rig.store.list_response_actions()] == ["failed"]
        assert rig.store.list_response_actions(status="applied") == []
        assert rig.decisions() == ["failed"]

    @pytest.mark.parametrize(
        "error",
        [
            RuntimeError("secret-token-123"),
            subprocess.TimeoutExpired(cmd="fw secret-token-123", timeout=5),
            KeyError("secret-token-123"),
            ValueError("secret-token-123"),
        ],
    )
    @pytest.mark.parametrize("duration", [None, 600])
    def test_execute_block_reduces_arbitrary_errors_to_the_class_name(
        self, error: Exception, duration: int | None
    ) -> None:
        fw = FakeFirewall()
        fw.block_error = error
        action = execute_block(fw, IP_A, duration, "ok")
        assert action.success is False
        assert action.detail == type(error).__name__
        assert "secret" not in action.detail
        assert action.duration_seconds == duration

    def test_execute_block_keeps_our_own_firewall_error_message_truncated(self) -> None:
        fw = FakeFirewall()
        fw.block_error = FirewallError("x" * 500)
        action = execute_block(fw, IP_A, None, "ok")
        assert action.success is False
        assert action.detail == "x" * 200

    def test_adapter_exception_text_does_not_reach_record_or_audit(self, rig: Rig) -> None:
        rig.fw.block_error = RuntimeError("secret-token-123")
        rig.responder().consider(make_alert(IP_A))
        (row,) = rig.store.list_response_actions()
        assert row.detail == "RuntimeError"
        assert "secret-token-123" not in rig.audit.path.read_text(encoding="utf-8")

    @staticmethod
    def _fail(responder: AutoResponder, count: int, start: int = 0) -> None:
        for i in range(count):
            responder.consider(make_alert(f"203.0.113.{100 + start + i}", alert_id=start + i + 1))

    def test_five_consecutive_failures_stop_further_attempts(self, rig: Rig) -> None:
        rig.fw.block_result = False
        responder = rig.responder()
        self._fail(responder, 5)
        assert len(rig.fw.calls) == 5

        rig.fw.block_result = True  # even a recovered firewall is not retried this window
        assert responder.consider(make_alert("203.0.113.200", alert_id=9)) is None
        assert len(rig.fw.calls) == 5
        (record,) = rig.records("skipped")
        assert "firewall failing repeatedly" in record["reason"]

    def test_next_hourly_window_resets_the_failure_streak(self, rig: Rig) -> None:
        rig.fw.block_result = False
        responder = rig.responder()
        self._fail(responder, 5)
        rig.fw.block_result = True
        rig.clock.advance(3600)
        action = responder.consider(make_alert("203.0.113.200", alert_id=9))
        assert action is not None and action.success is True

    def test_failures_stay_blocked_just_before_the_window_ends(self, rig: Rig) -> None:
        rig.fw.block_result = False
        responder = rig.responder()
        self._fail(responder, 5)
        rig.clock.advance(3599)
        assert responder.consider(make_alert("203.0.113.200", alert_id=9)) is None

    def test_a_success_resets_the_failure_streak(self, rig: Rig) -> None:
        responder = rig.responder()
        rig.fw.block_result = False
        self._fail(responder, 4)
        rig.fw.block_result = True
        assert responder.consider(make_alert("203.0.113.150", alert_id=50)) is not None
        rig.fw.block_result = False
        self._fail(responder, 4, start=100)  # 8 failures overall, never 5 in a row
        assert responder.consider(make_alert("203.0.113.250", alert_id=99)) is not None
        assert len(rig.fw.calls) == 10

    def test_failed_ip_enters_cooldown(self, rig: Rig) -> None:
        responder = rig.responder()
        rig.fw.block_result = False
        assert responder.consider(make_alert(IP_A)) is not None
        rig.fw.block_result = True
        assert responder.consider(make_alert(IP_A, alert_id=2)) is None
        assert len(rig.fw.calls) == 1
        assert "in cooldown" in rig.records("skipped")[0]["reason"]


# -- (3) flood limits --------------------------------------------------------


class TestFloodLimits:
    def test_approval_queue_stops_at_the_floor_cap(self, rig: Rig) -> None:
        fill_pending(rig.store, 100)
        responder = rig.responder(make_config(mode="approval", max_blocks_per_hour=1))
        assert responder.consider(make_alert(IP_A)) is None
        assert rig.store.pending_count() == 100
        assert rig.store.has_open_pending(IP_A) is None
        (record,) = rig.records("skipped")
        assert "approval queue is full" in record["reason"]

    def test_queue_just_below_the_cap_still_accepts(self, rig: Rig) -> None:
        fill_pending(rig.store, 99)
        responder = rig.responder(make_config(mode="approval", max_blocks_per_hour=1))
        responder.consider(make_alert(IP_A))
        assert rig.store.pending_count() == 100

    def test_cap_scales_with_the_hourly_limit(self, rig: Rig) -> None:
        fill_pending(rig.store, 100)
        responder = rig.responder(make_config(mode="approval", max_blocks_per_hour=20))
        responder.consider(make_alert(IP_A))  # cap is 20 * 10 = 200
        assert rig.store.has_open_pending(IP_A) is not None

    def test_identical_skip_records_are_throttled_to_one_per_minute(self, rig: Rig) -> None:
        responder = rig.responder()
        for _ in range(5):
            responder.consider(make_alert("not-an-ip"))
        assert len(rig.records("skipped")) == 1

        rig.clock.advance(59)
        responder.consider(make_alert("not-an-ip"))
        assert len(rig.records("skipped")) == 1

        rig.clock.advance(1)  # a full 60 s since the first record
        responder.consider(make_alert("not-an-ip"))
        assert len(rig.records("skipped")) == 2

    def test_different_ip_or_reason_is_not_throttled(self, rig: Rig) -> None:
        responder = rig.responder()
        responder.consider(make_alert("not-an-ip"))
        responder.consider(make_alert("also-bad"))
        rig.fw.blocked.add(IP_A)
        responder.consider(make_alert(IP_A))
        assert len(rig.records("skipped")) == 3

    def test_per_run_budget_resets_after_an_hour_of_clock_time(self, rig: Rig) -> None:
        responder = rig.responder(make_config(max_blocks_per_run=1))
        assert responder.consider(make_alert(IP_A, alert_id=1)) is not None
        rig.clock.advance(3599)
        assert responder.consider(make_alert(IP_B, alert_id=2)) is None
        assert "per-run block budget" in rig.records("skipped")[0]["reason"]

        rig.clock.advance(1)
        action = responder.consider(make_alert(IP_B, alert_id=3))
        assert action is not None and action.success is True


# -- (4) approval semantics --------------------------------------------------


class TestApprovalSemantics:
    def test_loser_of_a_claim_race_blocks_nothing(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pid = rig.queue(IP_A)
        stale = rig.store.get_pending(pid)
        assert rig.store.claim_pending(pid) is True  # the concurrent winner
        monkeypatch.setattr(rig.store, "get_pending", lambda _pid: stale)
        with pytest.raises(FirewallError, match="no longer pending"):
            rig.operator().approve(pid)
        assert rig.fw.calls == []
        assert rig.store.list_response_actions() == []

    def test_second_approval_of_a_finished_request_blocks_only_once(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pid = rig.queue(IP_A)
        stale = rig.store.get_pending(pid)
        assert rig.operator().approve(pid).success is True
        monkeypatch.setattr(rig.store, "get_pending", lambda _pid: stale)
        with pytest.raises(FirewallError, match="no longer pending"):
            rig.operator().approve(pid)
        assert len(rig.fw.calls_named("temporary_block")) == 1
        assert len(rig.store.list_response_actions(status="applied")) == 1

    def test_two_sequential_approvals_apply_exactly_one_block(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        op = rig.operator()
        op.approve(pid)
        with pytest.raises(FirewallError, match="already approved"):
            op.approve(pid)
        assert len(rig.fw.calls_named("temporary_block")) == 1
        assert len(rig.store.list_response_actions(status="applied")) == 1

    def test_stale_request_cannot_be_approved(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        cfg = make_config(pending_expire_seconds=120)
        rig.clock.advance(121)
        with pytest.raises(FirewallError, match="expired"):
            rig.operator(cfg).approve(pid)  # no pending() call first
        assert rig.pending_status(pid) == "expired"
        assert rig.fw.calls == []

    def test_transient_breaker_keeps_request_pending_and_retryable(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        for i in range(2):
            seeded_ts = NOW - timedelta(minutes=10)
            add_action(rig.store, f"198.18.0.{i + 1}", expires_at=None, ts=seeded_ts)
        op = rig.operator(make_config(max_blocks_per_hour=2))
        with pytest.raises(FirewallError, match="circuit breaker") as info:
            op.approve(pid)
        assert "try again later" in str(info.value)
        assert rig.pending_status(pid) == "pending"
        assert rig.fw.calls == []
        assert rig.records("denied") == []

        rig.clock.advance(51 * 60)  # the seeded blocks leave the one-hour window
        assert op.approve(pid).success is True
        assert rig.pending_status(pid) == "approved"

    def test_transient_already_blocked_keeps_request_pending(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.fw.blocked.add(IP_A)
        op = rig.operator()
        with pytest.raises(FirewallError, match="already blocked"):
            op.approve(pid)
        assert rig.pending_status(pid) == "pending"

        rig.fw.blocked.clear()
        assert op.approve(pid).success is True

    def test_permanent_reason_denies_the_request(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        op = rig.operator(make_config(allowlist=["203.0.113.0/24"]))
        with pytest.raises(FirewallError, match="allowlisted"):
            op.approve(pid)
        row = rig.store.get_pending(pid)
        assert row is not None and row.status == "denied"
        assert "allowlisted" in row.note
        with pytest.raises(FirewallError, match="already denied"):
            op.approve(pid)
        assert rig.fw.calls == []

    @pytest.mark.parametrize(
        ("stored_ip", "part"),
        [
            ("127.0.0.1", "loopback"),
            ("not-an-ip", "no valid source IP"),
            ("fe80::1%eth0", "no valid"),
        ],
    )
    def test_unblockable_stored_ip_is_denied_outright(
        self, rig: Rig, stored_ip: str, part: str
    ) -> None:
        pid = add_pending(rig.store, stored_ip)
        with pytest.raises(FirewallError, match=part):
            rig.operator().approve(pid)
        assert rig.pending_status(pid) == "denied"
        assert rig.fw.calls == []

    def test_non_canonical_stored_ip_is_blocked_in_canonical_form(self, rig: Rig) -> None:
        pid = add_pending(rig.store, "2001:0DB8::1")
        action = rig.operator().approve(pid)
        assert action.ip == V6
        assert rig.fw.calls == [("temporary_block", V6, 3600)]
        assert [r.ip for r in rig.store.list_response_actions()] == [V6]

    def test_firewall_refusal_releases_the_claim(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.fw.block_result = False
        op = rig.operator()
        with pytest.raises(FirewallError, match="could not block"):
            op.approve(pid)
        assert rig.pending_status(pid) == "pending"
        assert [r.status for r in rig.store.list_response_actions()] == ["failed"]
        assert rig.store.claim_pending(pid) is True  # claimable again

    def test_adapter_exception_text_is_not_leaked_to_the_operator(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.fw.block_error = RuntimeError("secret-token-123")
        with pytest.raises(FirewallError) as info:
            rig.operator().approve(pid)
        assert "secret-token-123" not in str(info.value)
        assert "RuntimeError" in str(info.value)
        assert "secret-token-123" not in rig.audit.path.read_text(encoding="utf-8")
        assert rig.pending_status(pid) == "pending"

    def test_untrackable_approval_never_reaches_the_firewall(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pid = rig.queue(IP_A)
        monkeypatch.setattr(rig.store, "add_response_action", _storage_boom)
        with pytest.raises(FirewallError, match="untracked"):
            rig.operator().approve(pid)
        assert rig.fw.calls == []
        assert rig.pending_status(pid) == "pending"


# -- (5) reaper and rollback -------------------------------------------------


class TestReaperAndRollback:
    def test_reaping_a_block_covered_by_a_permanent_row_keeps_the_ip_blocked(
        self, rig: Rig
    ) -> None:
        r1 = add_action(rig.store, "2001:0db8::1", expires_at=NOW + HOUR)
        r2 = add_action(rig.store, V6, expires_at=None)
        rig.fw.blocked.add(V6)
        rig.clock.advance(3601)

        (action,) = rig.operator().reap()

        assert action.success is True
        assert rig.fw.calls_named("unblock_ip") == []
        assert rig.fw.blocked == {V6}
        rows = {r.id: r for r in rig.store.list_response_actions()}
        assert rows[r1].status == "reaped"
        assert "longer-lived block" in rows[r1].detail
        assert rows[r2].status == "applied"

    def test_block_covered_by_a_longer_timed_row_is_not_unblocked_until_the_last_expires(
        self, rig: Rig
    ) -> None:
        r1 = add_action(rig.store, IP_A, expires_at=NOW + HOUR)
        r2 = add_action(rig.store, IP_A, expires_at=NOW + 2 * HOUR)
        rig.fw.blocked.add(IP_A)
        op = rig.operator()

        rig.clock.advance(3601)
        op.reap()
        assert rig.fw.calls_named("unblock_ip") == []

        rig.clock.advance(3600)
        op.reap()
        assert rig.fw.calls_named("unblock_ip") == [("unblock_ip", IP_A, None)]
        statuses = {r.id: r.status for r in rig.store.list_response_actions()}
        assert statuses == {r1: "reaped", r2: "reaped"}

    @pytest.mark.parametrize(
        ("column", "garbage"), [("ts", "not-a-time"), ("expires_at", "0000-garbage")]
    )
    def test_corrupt_stored_timestamp_does_not_abort_reap(
        self, rig: Rig, column: str, garbage: str
    ) -> None:
        bad = add_action(rig.store, IP_B, expires_at=NOW + HOUR)
        add_action(rig.store, IP_A, expires_at=NOW + HOUR)
        rig.fw.blocked.update({IP_A, IP_B})
        conn = sqlite3.connect(rig.db_path)
        try:
            conn.execute(f"UPDATE response_actions SET {column} = ? WHERE id = ?", (garbage, bad))
            conn.commit()
        finally:
            conn.close()
        rig.clock.advance(3601)

        actions = rig.operator().reap()

        assert [(a.ip, a.success) for a in actions] == [(IP_A, True)]
        assert rig.fw.calls_named("unblock_ip") == [("unblock_ip", IP_A, None)]

    def test_row_with_invalid_stored_ip_fails_alone(self, rig: Rig) -> None:
        add_action(rig.store, "not-an-ip", expires_at=NOW + HOUR)
        add_action(rig.store, IP_A, expires_at=NOW + HOUR)
        rig.fw.blocked.add(IP_A)
        rig.clock.advance(3601)

        first, second = rig.operator().reap()

        assert first.success is False and first.detail == "stored IP is invalid"
        assert second.success is True
        assert rig.fw.calls_named("unblock_ip") == [("unblock_ip", IP_A, None)]

    @pytest.mark.parametrize("since", [None, NOW])
    def test_rollback_with_empty_run_id_raises_value_error(
        self, rig: Rig, since: datetime | None
    ) -> None:
        add_action(rig.store, IP_A, expires_at=None, run_id="run-1")
        rig.fw.blocked.add(IP_A)
        with pytest.raises(ValueError, match="empty"):
            rig.operator().rollback(since=since, run_id="")
        assert rig.fw.calls == []
        assert rig.fw.blocked == {IP_A}


# -- (6) store primitives ----------------------------------------------------


class TestStorePending:
    def test_second_pending_row_for_the_same_ip_is_rejected(self, store: AlertStore) -> None:
        add_pending(store, IP_A)
        with pytest.raises(StorageError, match="already pending"):
            add_pending(store, IP_A)
        assert store.pending_count() == 1

    def test_new_pending_row_is_allowed_once_the_old_one_is_decided(
        self, store: AlertStore
    ) -> None:
        first = add_pending(store, IP_A)
        store.decide_pending(first, "denied", note="no")
        assert add_pending(store, IP_A) != first

    def test_claim_returns_true_once_then_false(self, store: AlertStore) -> None:
        pid = add_pending(store, IP_A)
        assert store.claim_pending(pid, "me") is True
        assert store.claim_pending(pid, "you") is False
        row = store.get_pending(pid)
        assert row is not None and row.status == "approved" and row.note == "me"

    def test_claim_of_unknown_id_is_false(self, store: AlertStore) -> None:
        assert store.claim_pending(4242) is False

    def test_release_restores_pending(self, store: AlertStore) -> None:
        pid = add_pending(store, IP_A)
        store.claim_pending(pid)
        store.release_pending(pid)
        row = store.get_pending(pid)
        assert row is not None and row.status == "pending" and row.decided_at is None
        assert store.claim_pending(pid) is True

    def test_release_with_a_newer_pending_for_the_ip_marks_the_old_one_superseded(
        self, store: AlertStore
    ) -> None:
        old = add_pending(store, IP_A)
        store.claim_pending(old)
        newer = add_pending(store, IP_A)  # allowed: the old row is no longer 'pending'

        store.release_pending(old)

        old_row = store.get_pending(old)
        assert old_row is not None
        assert old_row.status == "denied" and old_row.note == "superseded"
        assert store.get_pending(newer) is not None
        assert store.has_open_pending(IP_A) == newer
        assert store.pending_count() == 1

    @pytest.mark.parametrize("final", ["pending", "denied"])
    def test_release_is_a_noop_unless_the_row_is_claimed(
        self, store: AlertStore, final: str
    ) -> None:
        pid = add_pending(store, IP_A)
        if final == "denied":
            store.decide_pending(pid, "denied", note="no")
        store.release_pending(pid)
        row = store.get_pending(pid)
        assert row is not None and row.status == final

    def test_pending_count_counts_only_open_rows(self, store: AlertStore) -> None:
        assert store.pending_count() == 0
        a = add_pending(store, IP_A)
        b = add_pending(store, IP_B)
        add_pending(store, IP_C)
        store.claim_pending(a)
        store.decide_pending(b, "denied")
        assert store.pending_count() == 1


class TestStoreCovering:
    def test_covering_returns_only_longer_lived_applied_rows_for_the_ip(
        self, store: AlertStore
    ) -> None:
        target = NOW + HOUR
        me = add_action(store, IP_A, expires_at=target)
        permanent = add_action(store, IP_A, expires_at=None)
        longer = add_action(store, IP_A, expires_at=target + HOUR)
        add_action(store, IP_A, expires_at=target - timedelta(minutes=1))  # shorter
        add_action(store, IP_A, expires_at=target)  # same expiry: not strictly later
        add_action(store, IP_A, expires_at=None, status="reaped")  # not applied
        add_action(store, IP_A, expires_at=None, status="failed")
        add_action(store, IP_B, expires_at=None)  # other IP

        rows = store.covering_response_actions(IP_A, exclude_id=me, expires_after=target)

        assert [r.id for r in rows] == [permanent, longer]

    def test_without_an_expiry_only_permanent_rows_cover(self, store: AlertStore) -> None:
        me = add_action(store, IP_A, expires_at=None)
        add_action(store, IP_A, expires_at=NOW + 5 * HOUR)
        permanent = add_action(store, IP_A, expires_at=None)
        rows = store.covering_response_actions(IP_A, exclude_id=me, expires_after=None)
        assert [r.id for r in rows] == [permanent]

    def test_the_excluded_row_never_covers_itself(self, store: AlertStore) -> None:
        only = add_action(store, IP_A, expires_at=None)
        assert store.covering_response_actions(IP_A, exclude_id=only, expires_after=None) == []


# -- (7) audit rotation ------------------------------------------------------


def _write(audit: ResponseAudit, count: int) -> list[str]:
    reasons = [f"record-{i:03d}" for i in range(count)]
    for reason in reasons:
        audit.record("blocked", ip=IP_A, reason=reason)
    return reasons


def _reasons(records: list[dict[str, Any]]) -> list[str]:
    return [r["reason"] for r in records]


class TestAuditRotation:
    def test_rotation_keeps_at_most_keep_files(self, tmp_path: Path) -> None:
        audit = ResponseAudit(tmp_path / "audit.jsonl", max_bytes=300, keep=2)
        _write(audit, 40)
        names = sorted(p.name for p in tmp_path.glob("audit.jsonl*"))
        assert names == ["audit.jsonl", "audit.jsonl.1", "audit.jsonl.2"]

    def test_no_record_is_lost_inside_the_kept_window(self, tmp_path: Path) -> None:
        audit = ResponseAudit(tmp_path / "audit.jsonl", max_bytes=300, keep=2)
        expected = _write(audit, 40)
        got = _reasons(audit.read(1000))
        assert len(got) > 3
        assert got == expected[-len(got) :]  # contiguous, oldest first, newest last
        total = sum(
            len(p.read_text(encoding="utf-8").splitlines())
            for p in tmp_path.glob("audit.jsonl*")
        )
        assert total == len(got)

    def test_read_limit_spans_files_oldest_to_newest(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        audit = ResponseAudit(path, max_bytes=300, keep=2)
        expected = _write(audit, 40)
        active = len(path.read_text(encoding="utf-8").splitlines())

        within = _reasons(audit.read(active))
        spanning = _reasons(audit.read(active + 2))

        assert within == expected[-active:]
        assert spanning == expected[-(active + 2) :]

    def test_read_with_non_positive_limit_is_empty(self, tmp_path: Path) -> None:
        audit = ResponseAudit(tmp_path / "audit.jsonl")
        _write(audit, 2)
        assert audit.read(0) == []
        assert audit.read(-5) == []

    def test_keep_below_one_is_clamped_to_one(self, tmp_path: Path) -> None:
        audit = ResponseAudit(tmp_path / "audit.jsonl", max_bytes=200, keep=0)
        _write(audit, 20)
        names = sorted(p.name for p in tmp_path.glob("audit.jsonl*"))
        assert names == ["audit.jsonl", "audit.jsonl.1"]

    def test_non_positive_max_bytes_disables_rotation(self, tmp_path: Path) -> None:
        audit = ResponseAudit(tmp_path / "audit.jsonl", max_bytes=0, keep=2)
        _write(audit, 30)
        assert [p.name for p in tmp_path.glob("audit.jsonl*")] == ["audit.jsonl"]
        assert len(audit.read(1000)) == 30

    def test_rotation_failure_does_not_raise_and_keeps_writing(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        blocker = tmp_path / "audit.jsonl.1"
        blocker.mkdir()
        (blocker / "keep.txt").write_text("x", encoding="utf-8")
        audit = ResponseAudit(path, max_bytes=100, keep=1)

        expected = _write(audit, 6)  # every write tries (and fails) to rotate

        assert blocker.is_dir()
        assert _reasons(audit.read(100)) == expected


# -- (8) lockout fail-closed -------------------------------------------------


def _raising() -> set[str]:
    raise RuntimeError("provider exploded")


class TestLockoutFailClosed:
    @pytest.mark.parametrize(
        ("flag", "kwarg"),
        [("protect_own_addresses", "own_addresses"), ("protect_gateway", "gateways")],
    )
    def test_raising_provider_fails_closed(self, flag: str, kwarg: str) -> None:
        cfg = make_config(**{flag: True})
        guard = make_guard(cfg, **{kwarg: _raising})
        assert guard.protected_reason(IP_A) == FAIL_CLOSED

    def test_provider_error_is_not_cached(self) -> None:
        state = {"fail": True}

        def flaky() -> set[str]:
            if state["fail"]:
                raise RuntimeError("provider exploded")
            return {IP_B}

        guard = make_guard(make_config(protect_own_addresses=True), own_addresses=flaky)
        assert guard.protected_reason(IP_B) == FAIL_CLOSED
        state["fail"] = False
        assert guard.protected_reason(IP_B) == "is an address of this host"
        assert guard.protected_reason(IP_A) is None

    @pytest.mark.parametrize(
        ("flag", "kwarg", "reason"),
        [
            ("protect_own_addresses", "own_addresses", "is an address of this host"),
            ("protect_gateway", "gateways", "is the default gateway"),
        ],
    )
    def test_cache_expires_after_300_seconds_of_injected_clock(
        self, flag: str, kwarg: str, reason: str
    ) -> None:
        ticks = [1000.0]
        calls: list[int] = []

        def provider() -> set[str]:
            calls.append(1)
            return {IP_A} if len(calls) == 1 else {IP_B}

        guard = make_guard(
            make_config(**{flag: True}), clock=lambda: ticks[0], **{kwarg: provider}
        )
        assert guard.protected_reason(IP_A) == reason
        ticks[0] = 1299.9
        assert guard.protected_reason(IP_A) == reason
        assert len(calls) == 1

        ticks[0] = 1300.0
        assert guard.protected_reason(IP_A) is None
        assert guard.protected_reason(IP_B) == reason
        assert len(calls) == 2

    def test_refresh_drops_the_cache(self) -> None:
        calls: list[int] = []

        def provider() -> set[str]:
            calls.append(1)
            return {IP_A}

        guard = make_guard(
            make_config(protect_own_addresses=True), own_addresses=provider, clock=lambda: 0.0
        )
        guard.protected_reason(IP_A)
        guard.protected_reason(IP_A)
        assert len(calls) == 1
        guard.refresh()
        guard.protected_reason(IP_A)
        assert len(calls) == 2

    def test_mapped_ipv4_is_protected_by_an_ipv4_admin_range(self) -> None:
        guard = make_guard(make_config(admin_ranges=["203.0.113.0/24"]))
        assert "admin range" in (guard.protected_reason("::ffff:" + IP_A) or "")

    def test_describe_mentions_admin_ranges(self) -> None:
        guard = make_guard(make_config(admin_ranges=["203.0.113.0/24"]))
        assert "admin_ranges=203.0.113.0/24" in guard.describe_session_protection()

    def test_describe_with_nothing_enabled(self) -> None:
        assert make_guard(make_config()).describe_session_protection() == (
            "no lockout protection enabled"
        )

    def test_describe_never_raises_when_a_provider_fails(self) -> None:
        guard = make_guard(
            make_config(protect_own_addresses=True, admin_ranges=["203.0.113.0/24"]),
            own_addresses=_raising,
        )
        text = guard.describe_session_protection()
        assert text == "lockout protection state unavailable (RuntimeError)"

    def test_describe_includes_ssh_peer_from_env(self) -> None:
        guard = make_guard(
            make_config(protect_ssh_peer=True),
            env={"SSH_CONNECTION": f"{IP_A} 51234 192.0.2.99 22"},
        )
        assert f"ssh_peer={IP_A}" in guard.describe_session_protection()


# -- (9) respond CLI ---------------------------------------------------------


class CliEnv:
    """Throwaway state dir plus a config file pointing at it."""

    def __init__(self, root: Path) -> None:
        self.state = root / "state"
        self.state.mkdir(parents=True, exist_ok=True)
        self.cfg = root / "config.yaml"
        response = {
            "enabled": True,
            "mode": "approval",
            "protect_gateway": False,
            "protect_own_addresses": False,
        }
        data = {"state_dir": self.state.as_posix(), "response": response}
        self.cfg.write_text(yaml.safe_dump(data), encoding="utf-8")

    @property
    def audit_path(self) -> Path:
        return self.state / "response" / "audit.jsonl"

    def add_pending(self, ip: str) -> int:
        store = AlertStore(self.state / "alerts.db")
        try:
            return add_pending(store, ip, ts=datetime.now(timezone.utc))
        finally:
            store.close()

    def pending_statuses(self) -> list[str]:
        store = AlertStore(self.state / "alerts.db")
        try:
            return [p.status for p in store.list_pending(None)]
        finally:
            store.close()

    def action_count(self) -> int:
        store = AlertStore(self.state / "alerts.db")
        try:
            return len(store.list_response_actions())
        finally:
            store.close()

    def write_audit(self, *records: dict[str, Any]) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps({"event": "response", **rec}) for rec in records]
        self.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def run(self, *args: str) -> Result:
        return CliRunner().invoke(
            cli, ["--config", str(self.cfg), "--no-plugins", "respond", *args]
        )


class TestRespondCli:
    @pytest.fixture(autouse=True)
    def _hermetic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SSH_CONNECTION", raising=False)
        monkeypatch.delenv("SSH_CLIENT", raising=False)

    @pytest.fixture()
    def fw(self, monkeypatch: pytest.MonkeyPatch) -> FakeFirewall:
        fake = FakeFirewall()
        monkeypatch.setattr("sentinelai.core.pipeline.create_firewall", lambda _cfg: fake)
        return fake

    @pytest.fixture()
    def env(self, tmp_path: Path, fw: FakeFirewall) -> CliEnv:
        return CliEnv(tmp_path)

    def test_approve_without_yes_shows_the_target_and_changes_nothing(
        self, env: CliEnv, fw: FakeFirewall
    ) -> None:
        pid = env.add_pending(IP_A)

        result = env.run("--approve", str(pid))

        assert result.exit_code == 1
        assert f"#{pid} {IP_A}" in result.output
        assert fw.calls == []
        assert env.pending_statuses() == ["pending"]
        assert env.action_count() == 0

    def test_deny_without_yes_shows_the_target_and_changes_nothing(
        self, env: CliEnv, fw: FakeFirewall
    ) -> None:
        pid = env.add_pending(IP_A)
        result = env.run("--deny", str(pid))
        assert result.exit_code == 1
        assert f"#{pid} {IP_A}" in result.output
        assert env.pending_statuses() == ["pending"]

    @pytest.mark.parametrize("run_id", ["", "   "])
    def test_empty_run_id_is_a_usage_error(
        self, env: CliEnv, fw: FakeFirewall, run_id: str
    ) -> None:
        result = env.run("--rollback", "--run", run_id)
        assert result.exit_code == 2
        assert "RUN_ID" in result.output
        assert fw.calls == []

    @pytest.mark.parametrize(
        "separator", ["\n", "\r\n", "\t", "\x0b", "\x0c", " ", " ", "\x85"]
    )
    def test_history_cells_with_line_breaks_print_on_one_line(
        self, env: CliEnv, separator: str
    ) -> None:
        env.write_audit(
            {
                "decision": "skipped",
                "ip": IP_A,
                "reason": f"aa{separator}bb",
                "rule_id": "R001",
                "ts": "2026-01-07T12:00:00+00:00",
            }
        )

        result = env.run("--history")

        assert result.exit_code == 0
        assert re.search(r"aa +bb", result.output), result.output
        assert len([ln for ln in result.output.splitlines() if "skipped" in ln]) == 1
        assert "\t" not in result.output

    def test_history_without_any_records_says_so(self, env: CliEnv) -> None:
        result = env.run("--history")
        assert result.exit_code == 0
        assert "No response decisions recorded yet" in result.output
