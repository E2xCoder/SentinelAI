"""Tests for the response policy: AutoResponder, ResponseOperator, adapters, UFW example."""

from __future__ import annotations

import importlib.util
import subprocess
import types
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import sentinelai.detection.rules  # noqa: F401  (registers built-in rules)
from sentinelai.config.models import FirewallConfig, ResponseConfig
from sentinelai.core.exceptions import FirewallError
from sentinelai.core.models import Alert, RiskLevel
from sentinelai.core.store import AlertStore
from sentinelai.detection.base import available_rules
from sentinelai.firewall import responder as responder_module
from sentinelai.firewall.adapters import CommandAdapter, DryRunAdapter, create_firewall
from sentinelai.firewall.audit import ResponseAudit
from sentinelai.firewall.interface import FirewallController
from sentinelai.firewall.lockout import LockoutGuard
from sentinelai.firewall.operator import ResponseOperator
from sentinelai.firewall.responder import AutoResponder
from sentinelai.risk.engine import RiskEngine
from tests.conftest import make_event

NOW = datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)

# Documentation-range addresses: public enough for the policy, never real hosts.
IP_A = "203.0.113.10"
IP_B = "198.51.100.20"
IP_C = "192.0.2.30"


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
        self.unblock_error: Exception | None = None

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
        if self.unblock_error is not None:
            raise self.unblock_error
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


def make_alert(
    ip: str | None,
    *,
    event_count: int = 20,
    alert_id: int | None = 1,
    rule_id: str = "R031",
) -> Alert:
    """Build a real, risk-scored alert (R031 with 20 events scores HIGH)."""
    rule = available_rules()[rule_id]()
    alert = rule.make_alert(make_event(ip=ip), f"{rule_id} test", "synthetic alert")
    alert.event_count = event_count
    RiskEngine().score(alert)
    alert.ip = ip
    alert.id = alert_id
    return alert


def make_guard(
    config: ResponseConfig,
    *,
    env: dict[str, str] | None = None,
    own: tuple[str, ...] = (),
    gateways: tuple[str, ...] = (),
) -> LockoutGuard:
    return LockoutGuard(
        config,
        env=env if env is not None else {},
        own_addresses=lambda: set(own),
        gateways=lambda: set(gateways),
    )


def seed_actions(
    store: AlertStore,
    count: int,
    *,
    status: str = "applied",
    age: timedelta = timedelta(minutes=10),
    at: datetime = NOW,
) -> None:
    for i in range(count):
        store.add_response_action(
            action="temporary_block",
            ip=f"198.18.0.{i + 1}",
            duration_seconds=3600,
            expires_at=None,
            status=status,
            alert_id=None,
            rule_id="R031",
            run_id="seed",
            ts=at - age,
        )


class Rig:
    """Real store + audit log with a fake firewall and shared clock."""

    def __init__(self, tmp_path: Path) -> None:
        self.store = AlertStore(tmp_path / "alerts.db")
        self.audit = ResponseAudit(tmp_path / "audit.jsonl")
        self.clock = Clock()
        self.fw = FakeFirewall()

    def responder(
        self,
        config: ResponseConfig | None = None,
        *,
        guard: LockoutGuard | None = None,
        run_id: str = "run-1",
    ) -> AutoResponder:
        return AutoResponder(
            config or make_config(),
            self.fw,
            store=self.store,
            audit=self.audit,
            guard=guard,
            run_id=run_id,
            clock=self.clock,
        )

    def operator(
        self, config: ResponseConfig | None = None, *, guard: LockoutGuard | None = None
    ) -> ResponseOperator:
        return ResponseOperator(
            config or make_config(), self.fw, self.store, self.audit, guard, self.clock
        )

    def queue(self, ip: str = IP_A, *, alert_id: int = 1, **config: Any) -> int:
        """Queue one approval request through a real approval-mode responder."""
        alert = make_alert(ip, alert_id=alert_id)
        self.responder(make_config(mode="approval", **config)).consider(alert)
        return int(alert.context["response"]["pending_id"])

    def decisions(self) -> list[str]:
        return [r["decision"] for r in self.audit.read(500)]

    def records(self, decision: str) -> list[dict[str, Any]]:
        return [r for r in self.audit.read(500) if r["decision"] == decision]


@pytest.fixture()
def rig(tmp_path: Path) -> Iterator[Rig]:
    r = Rig(tmp_path)
    try:
        yield r
    finally:
        r.store.close()


class CrashingStore:
    """Every store method raises, simulating a broken database."""

    def __getattr__(self, name: str) -> Any:
        def boom(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError(f"store.{name} exploded")

        return boom


class CrashingAudit:
    def record(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("audit exploded")


def test_helper_alerts_have_expected_risk_levels() -> None:
    assert make_alert(IP_A).risk.level is RiskLevel.HIGH
    assert make_alert(IP_A, event_count=1).risk.level is RiskLevel.MEDIUM
    assert make_alert(IP_A, event_count=1, rule_id="R004").risk.level is RiskLevel.LOW


# -- AutoResponder: construction and skips ---------------------------------


class TestAutoResponderSkips:
    def test_legacy_two_argument_construction_still_blocks(self) -> None:
        fw = FakeFirewall()
        action = AutoResponder(make_config(), fw).consider(make_alert(IP_A))
        assert action is not None
        assert action.success is True
        assert fw.calls == [("temporary_block", IP_A, 3600)]

    def test_disabled_returns_none_and_writes_no_audit(self, rig: Rig) -> None:
        responder = rig.responder(make_config(enabled=False))
        assert responder.consider(make_alert(IP_A)) is None
        assert rig.fw.calls == []
        assert rig.audit.read() == []
        assert not rig.audit.path.exists()

    def test_below_risk_threshold_is_skipped_without_audit(self, rig: Rig) -> None:
        alert = make_alert(IP_A, event_count=1)  # medium < high
        assert rig.responder().consider(alert) is None
        assert rig.fw.calls == []
        assert rig.store.list_response_actions() == []
        assert rig.audit.read() == []

    def test_identical_skip_is_audited_once_per_minute(self, rig: Rig) -> None:
        responder = rig.responder(make_config(allowlist=["203.0.113.0/24"]))
        for _ in range(3):
            assert responder.consider(make_alert(IP_A)) is None
        assert len(rig.records("skipped")) == 1

        rig.clock.advance(59)
        responder.consider(make_alert(IP_A))
        assert len(rig.records("skipped")) == 1

        rig.clock.advance(2)  # 61 s after the first record
        responder.consider(make_alert(IP_A))
        assert len(rig.records("skipped")) == 2
        assert rig.fw.calls == []

    def test_skip_throttle_is_per_ip_and_per_reason(self, rig: Rig) -> None:
        responder = rig.responder(make_config(allowlist=["203.0.113.0/24"]))
        responder.consider(make_alert(IP_A))
        responder.consider(make_alert("203.0.113.11"))  # other ip, same reason
        responder.consider(make_alert(None))  # other reason
        assert len(rig.records("skipped")) == 3

    @pytest.mark.parametrize("ip", [None, "", "not-an-ip", "1.2.3.4; rm -rf /", "999.1.1.1"])
    def test_missing_or_invalid_ip_is_skipped_with_audit(self, rig: Rig, ip: str | None) -> None:
        assert rig.responder().consider(make_alert(ip)) is None
        assert rig.fw.calls == []
        (record,) = rig.audit.read()
        assert record["decision"] == "skipped"
        assert "no valid source IP" in record["reason"]

    def test_allowlisted_ip_is_skipped_with_audit(self, rig: Rig) -> None:
        cfg = make_config(allowlist=["203.0.113.0/24"])
        assert rig.responder(cfg).consider(make_alert(IP_A)) is None
        assert rig.fw.calls == []
        (record,) = rig.audit.read()
        assert record["decision"] == "skipped"
        assert "allowlisted" in record["reason"]

    def test_default_allowlist_protects_private_space(self, rig: Rig) -> None:
        assert rig.responder().consider(make_alert("192.168.1.50")) is None
        assert rig.fw.calls == []
        assert "allowlisted" in rig.audit.read()[0]["reason"]

    def _assert_lockout(
        self, rig: Rig, cfg: ResponseConfig, guard: LockoutGuard, part: str
    ) -> None:
        assert rig.responder(cfg, guard=guard).consider(make_alert(IP_A)) is None
        assert rig.fw.calls == []
        (record,) = rig.audit.read()
        assert record["decision"] == "skipped"
        assert record["reason"].startswith("self-lockout protection")
        assert part in record["reason"]

    def test_admin_range_is_protected(self, rig: Rig) -> None:
        cfg = make_config(admin_ranges=["203.0.113.0/24"])
        self._assert_lockout(rig, cfg, make_guard(cfg), "admin range")

    def test_ssh_peer_is_protected(self, rig: Rig) -> None:
        cfg = make_config(protect_ssh_peer=True)
        guard = make_guard(cfg, env={"SSH_CONNECTION": f"{IP_A} 51234 192.0.2.99 22"})
        self._assert_lockout(rig, cfg, guard, "SSH session")

    def test_default_gateway_is_protected(self, rig: Rig) -> None:
        cfg = make_config(protect_gateway=True)
        self._assert_lockout(rig, cfg, make_guard(cfg, gateways=(IP_A,)), "gateway")

    def test_own_address_is_protected(self, rig: Rig) -> None:
        cfg = make_config(protect_own_addresses=True)
        self._assert_lockout(rig, cfg, make_guard(cfg, own=(IP_A,)), "this host")

    def test_disabled_lockout_flag_does_not_protect(self, rig: Rig) -> None:
        cfg = make_config(protect_own_addresses=False)
        guard = make_guard(cfg, own=(IP_A,))
        assert rig.responder(cfg, guard=guard).consider(make_alert(IP_A)) is not None

    def test_unrelated_ip_passes_the_guard(self, rig: Rig) -> None:
        cfg = make_config(admin_ranges=["203.0.113.0/24"], protect_own_addresses=True)
        guard = make_guard(cfg, own=(IP_B,))
        assert rig.responder(cfg, guard=guard).consider(make_alert(IP_C)) is not None

    def test_per_run_budget_exhausted_is_skipped_with_audit(self, rig: Rig) -> None:
        responder = rig.responder(make_config(max_blocks_per_run=1))
        assert responder.consider(make_alert(IP_A, alert_id=1)) is not None
        assert responder.consider(make_alert(IP_B, alert_id=2)) is None
        assert rig.fw.blocked == {IP_A}
        skipped = rig.records("skipped")
        assert len(skipped) == 1
        assert "per-run block budget" in skipped[0]["reason"]
        assert skipped[0]["ip"] == IP_B

    def test_cooldown_skips_repeat_then_allows_after_it_elapses(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ticks = [100.0]
        monkeypatch.setattr(
            responder_module, "time", types.SimpleNamespace(monotonic=lambda: ticks[0])
        )
        responder = rig.responder(make_config(cooldown_seconds=600))
        assert responder.consider(make_alert(IP_A, alert_id=1)) is not None
        rig.fw.blocked.discard(IP_A)  # externally unblocked; only the cooldown remains

        ticks[0] = 150.0
        assert responder.consider(make_alert(IP_A, alert_id=2)) is None
        (record,) = rig.records("skipped")
        assert "cooldown" in record["reason"]
        assert len(rig.fw.calls_named("temporary_block")) == 1

        ticks[0] = 800.0
        assert responder.consider(make_alert(IP_A, alert_id=3)) is not None
        assert len(rig.fw.calls_named("temporary_block")) == 2

    def test_already_blocked_ip_is_skipped_with_audit(self, rig: Rig) -> None:
        rig.fw.blocked.add(IP_A)
        assert rig.responder().consider(make_alert(IP_A)) is None
        assert rig.fw.calls == []
        (record,) = rig.audit.read()
        assert record["decision"] == "skipped"
        assert "already blocked" in record["reason"]

    def test_is_blocked_error_does_not_stop_the_block(self, rig: Rig) -> None:
        def broken(ip: str) -> bool:
            raise FirewallError("status unavailable")

        rig.fw.is_blocked = broken  # type: ignore[method-assign]
        assert rig.responder().consider(make_alert(IP_A)) is not None


class TestHourlyCircuitBreaker:
    def test_breaker_open_skips_with_circuit_breaker_decision(self, rig: Rig) -> None:
        seed_actions(rig.store, 3)
        assert rig.responder(make_config(max_blocks_per_hour=3)).consider(make_alert(IP_A)) is None
        assert rig.fw.calls == []
        (record,) = rig.audit.read()
        assert record["decision"] == "circuit_breaker"
        assert "circuit breaker" in record["reason"]

    def test_just_below_the_cap_still_blocks(self, rig: Rig) -> None:
        seed_actions(rig.store, 2)
        action = rig.responder(make_config(max_blocks_per_hour=3)).consider(make_alert(IP_A))
        assert action is not None and action.success

    def test_rows_older_than_an_hour_do_not_count(self, rig: Rig) -> None:
        seed_actions(rig.store, 3, age=HOUR + timedelta(minutes=1))
        action = rig.responder(make_config(max_blocks_per_hour=3)).consider(make_alert(IP_A))
        assert action is not None and action.success

    def test_failed_rows_do_not_count(self, rig: Rig) -> None:
        seed_actions(rig.store, 3, status="failed")
        action = rig.responder(make_config(max_blocks_per_hour=3)).consider(make_alert(IP_A))
        assert action is not None and action.success

    def test_breaker_opens_across_responders_via_the_store(self, rig: Rig) -> None:
        cfg = make_config(max_blocks_per_hour=2)
        first = rig.responder(cfg, run_id="run-1")
        assert first.consider(make_alert(IP_A, alert_id=1)) is not None
        assert first.consider(make_alert(IP_B, alert_id=2)) is not None
        second = rig.responder(cfg, run_id="run-2")
        assert second.consider(make_alert(IP_C, alert_id=3)) is None
        assert rig.records("circuit_breaker")


# -- AutoResponder: auto mode ----------------------------------------------


class TestAutoMode:
    def test_temporary_block_uses_configured_duration(self, rig: Rig) -> None:
        action = rig.responder(make_config(block_duration_seconds=900)).consider(
            make_alert(IP_A)
        )
        assert action is not None
        assert action.action == "temporary_block"
        assert action.duration_seconds == 900
        assert rig.fw.calls == [("temporary_block", IP_A, 900)]

    def test_permanent_block_uses_block_ip(self, rig: Rig) -> None:
        action = rig.responder(make_config(temporary_block=False)).consider(make_alert(IP_A))
        assert action is not None
        assert action.action == "block_ip"
        assert action.duration_seconds is None
        assert rig.fw.calls == [("block_ip", IP_A, None)]

    def test_records_applied_row_with_expiry_run_and_alert(self, rig: Rig) -> None:
        rig.responder(make_config(block_duration_seconds=900), run_id="run-7").consider(
            make_alert(IP_A, alert_id=42)
        )
        (row,) = rig.store.list_response_actions()
        assert row.status == "applied"
        assert row.action == "temporary_block"
        assert row.ip == IP_A
        assert row.expires_at == NOW + timedelta(seconds=900)
        assert row.duration_seconds == 900
        assert row.run_id == "run-7"
        assert row.alert_id == 42
        assert row.rule_id == "R031"

    def test_permanent_block_row_has_no_expiry(self, rig: Rig) -> None:
        rig.responder(make_config(temporary_block=False)).consider(make_alert(IP_A))
        (row,) = rig.store.list_response_actions()
        assert row.action == "block_ip"
        assert row.expires_at is None
        assert row.duration_seconds is None

    def test_success_writes_blocked_audit_and_alert_context(self, rig: Rig) -> None:
        alert = make_alert(IP_A, alert_id=5)
        rig.responder(run_id="run-9").consider(alert)
        (record,) = rig.audit.read()
        assert record["decision"] == "blocked"
        assert record["ip"] == IP_A
        assert record["alert_id"] == 5
        assert record["run_id"] == "run-9"
        assert record["mode"] == "auto"
        assert alert.context["response"]["success"] is True

    def test_firewall_returning_false_records_failed_row_and_audit(self, rig: Rig) -> None:
        rig.fw.block_result = False
        action = rig.responder().consider(make_alert(IP_A))
        assert action is not None
        assert action.success is False
        assert action.detail == "firewall reported failure"
        (row,) = rig.store.list_response_actions()
        assert row.status == "failed"
        assert row.detail == "firewall reported failure"
        assert row.expires_at == NOW + timedelta(seconds=3600)
        assert rig.decisions() == ["failed"]
        assert rig.fw.blocked == set()

    def test_row_is_inserted_before_the_firewall_is_called(self, rig: Rig) -> None:
        seen: list[list[str]] = []
        original = rig.fw.temporary_block

        def spy(ip: str, duration_seconds: int) -> bool:
            seen.append([r.status for r in rig.store.list_response_actions()])
            return original(ip, duration_seconds)

        rig.fw.temporary_block = spy  # type: ignore[method-assign]
        rig.responder().consider(make_alert(IP_A))
        assert seen == [["applied"]]

    def test_row_insert_failure_applies_no_block_and_audits_failed(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*args: Any, **kwargs: Any) -> int:
            raise RuntimeError("disk full")

        monkeypatch.setattr(rig.store, "add_response_action", boom)
        alert = make_alert(IP_A)
        action = rig.responder().consider(alert)
        assert action is not None
        assert action.success is False
        assert rig.fw.calls == []
        assert rig.fw.blocked == set()
        (record,) = rig.audit.read()
        assert record["decision"] == "failed"
        assert "could not record the block" in record["reason"]
        assert alert.context["response"]["success"] is False

    def test_firewall_error_records_failed_row_and_audit(self, rig: Rig) -> None:
        rig.fw.block_error = FirewallError("ufw missing")
        action = rig.responder().consider(make_alert(IP_A))
        assert action is not None
        assert action.success is False
        assert "ufw missing" in action.detail
        (row,) = rig.store.list_response_actions()
        assert row.status == "failed"
        (record,) = rig.audit.read()
        assert record["decision"] == "failed"
        assert "ufw missing" in record["reason"]

    def test_failed_block_does_not_consume_run_budget(self, rig: Rig) -> None:
        responder = rig.responder(make_config(max_blocks_per_run=1))
        rig.fw.block_result = False
        responder.consider(make_alert(IP_A, alert_id=1))
        rig.fw.block_result = True
        assert responder.consider(make_alert(IP_B, alert_id=2)) is not None

    def test_actions_list_collects_every_attempt(self, rig: Rig) -> None:
        responder = rig.responder()
        responder.consider(make_alert(IP_A, alert_id=1))
        responder.consider(make_alert(IP_B, alert_id=2))
        assert [a.ip for a in responder.actions] == [IP_A, IP_B]


# -- AutoResponder: approval mode ------------------------------------------


class TestApprovalMode:
    def test_queues_one_pending_row_and_blocks_nothing(self, rig: Rig) -> None:
        alert = make_alert(IP_A, alert_id=11)
        assert rig.responder(make_config(mode="approval")).consider(alert) is None
        assert rig.fw.calls == []
        (row,) = rig.store.list_pending(None)
        assert row.status == "pending"
        assert row.ip == IP_A
        assert row.alert_id == 11
        assert row.action == "temporary_block"
        assert row.duration_seconds == 3600
        assert rig.store.list_response_actions() == []
        assert rig.decisions() == ["queued"]

    def test_alert_context_marks_response_pending(self, rig: Rig) -> None:
        alert = make_alert(IP_A)
        rig.responder(make_config(mode="approval")).consider(alert)
        response = alert.context["response"]
        assert response["status"] == "pending"
        assert response["pending_id"] == rig.store.list_pending()[0].id

    def test_second_alert_for_same_ip_is_skipped_as_already_pending(self, rig: Rig) -> None:
        responder = rig.responder(make_config(mode="approval"))
        responder.consider(make_alert(IP_A, alert_id=1))
        second = make_alert(IP_A, alert_id=2)
        assert responder.consider(second) is None
        assert len(rig.store.list_pending(None)) == 1
        (skip,) = rig.records("skipped")
        assert "already pending approval" in skip["reason"]
        assert "response" not in second.context

    def test_different_ips_are_queued_separately(self, rig: Rig) -> None:
        responder = rig.responder(make_config(mode="approval"))
        responder.consider(make_alert(IP_A, alert_id=1))
        responder.consider(make_alert(IP_B, alert_id=2))
        assert sorted(p.ip for p in rig.store.list_pending()) == sorted([IP_A, IP_B])

    def test_permanent_mode_queues_block_ip(self, rig: Rig) -> None:
        responder = rig.responder(make_config(mode="approval", temporary_block=False))
        responder.consider(make_alert(IP_A))
        (row,) = rig.store.list_pending()
        assert row.action == "block_ip"
        assert row.duration_seconds is None

    def test_policy_skips_still_apply_before_queueing(self, rig: Rig) -> None:
        responder = rig.responder(make_config(mode="approval"))
        responder.consider(make_alert(IP_A, event_count=1))
        responder.consider(make_alert("192.168.0.9"))
        assert rig.store.list_pending(None) == []

    def test_approval_mode_without_store_is_skipped_with_audit(self, tmp_path: Path) -> None:
        audit = ResponseAudit(tmp_path / "audit.jsonl")
        fw = FakeFirewall()
        responder = AutoResponder(make_config(mode="approval"), fw, audit=audit)
        assert responder.consider(make_alert(IP_A)) is None
        assert fw.calls == []
        (record,) = audit.read()
        assert record["decision"] == "skipped"
        assert "needs the alert store" in record["reason"]


# -- AutoResponder: resilience ---------------------------------------------


class TestResilience:
    def test_crashing_store_does_not_raise_in_auto_mode(self, tmp_path: Path) -> None:
        fw = FakeFirewall()
        audit = ResponseAudit(tmp_path / "audit.jsonl")
        responder = AutoResponder(
            make_config(), fw, store=CrashingStore(), audit=audit, run_id="r"  # type: ignore[arg-type]
        )
        assert responder.consider(make_alert(IP_A)) is None  # fail closed
        assert fw.calls == []
        (record,) = audit.read()
        assert record["decision"] == "circuit_breaker"
        assert "could not read the block history; refusing to block" in record["reason"]

    def test_crashing_store_does_not_raise_in_approval_mode(self, tmp_path: Path) -> None:
        fw = FakeFirewall()
        audit = ResponseAudit(tmp_path / "audit.jsonl")
        responder = AutoResponder(
            make_config(mode="approval"),
            fw,
            store=CrashingStore(),  # type: ignore[arg-type]
            audit=audit,
        )
        alert = make_alert(IP_A)
        assert responder.consider(alert) is None
        assert fw.calls == []
        (record,) = audit.read()
        assert record["decision"] == "circuit_breaker"
        assert "refusing to block" in record["reason"]
        assert "response" not in alert.context

    def test_unreadable_block_history_fails_closed_for_the_breaker(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(since: datetime) -> int:
            raise RuntimeError("db locked")

        monkeypatch.setattr(rig.store, "count_response_actions_since", boom)
        assert rig.responder().consider(make_alert(IP_A)) is None
        assert rig.fw.calls == []
        (record,) = rig.audit.read()
        assert record["decision"] == "circuit_breaker"
        assert record["reason"] == "could not read the block history; refusing to block"

    def test_crashing_audit_does_not_raise_for_block_skip_and_queue(self, rig: Rig) -> None:
        audit = CrashingAudit()
        auto = AutoResponder(
            make_config(), rig.fw, store=rig.store, audit=audit, clock=rig.clock  # type: ignore[arg-type]
        )
        assert auto.consider(make_alert(IP_A, alert_id=1)) is not None  # blocked
        assert auto.consider(make_alert(IP_B, event_count=1, alert_id=2)) is None  # skipped
        queue = AutoResponder(
            make_config(mode="approval"),
            rig.fw,
            store=rig.store,
            audit=audit,  # type: ignore[arg-type]
            clock=rig.clock,
        )
        assert queue.consider(make_alert(IP_C, alert_id=3)) is None  # queued
        assert len(rig.store.list_pending()) == 1

    def test_unwritable_audit_path_does_not_raise(self, tmp_path: Path) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        audit = ResponseAudit(blocker / "audit.jsonl")  # parent is a file
        fw = FakeFirewall()
        responder = AutoResponder(make_config(), fw, audit=audit)
        assert responder.consider(make_alert(IP_A)) is not None


# -- ResponseOperator: pending queue ---------------------------------------


class TestOperatorPending:
    def test_pending_lists_open_requests(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        assert [p.id for p in rig.operator().pending()] == [pid]

    def test_pending_expires_stale_rows_with_audit(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.clock.advance(86400 + 1)
        assert rig.operator(make_config(pending_expire_seconds=86400)).pending() == []
        row = rig.store.get_pending(pid)
        assert row is not None and row.status == "expired"
        (record,) = rig.records("expired")
        assert "1 pending request(s) expired" in record["reason"]

    def test_pending_keeps_fresh_rows(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.clock.advance(86400 - 10)
        pending = rig.operator(make_config(pending_expire_seconds=86400)).pending()
        assert [p.id for p in pending] == [pid]
        assert rig.records("expired") == []

    def test_approve_blocks_and_marks_row_approved(self, rig: Rig) -> None:
        pid = rig.queue(IP_A, alert_id=7)
        rig.clock.advance(60)
        action = rig.operator().approve(pid, note="looks real")
        assert action.success is True
        assert rig.fw.calls == [("temporary_block", IP_A, 3600)]
        row = rig.store.get_pending(pid)
        assert row is not None
        assert row.status == "approved"
        assert row.note == "looks real"
        (applied,) = rig.store.list_response_actions(status="applied")
        assert applied.ip == IP_A
        assert applied.alert_id == 7
        assert applied.run_id == "operator"
        assert applied.expires_at == rig.clock.current + timedelta(seconds=3600)
        assert rig.decisions() == ["queued", "approved", "blocked"]

    def test_approve_permanent_request_uses_block_ip_without_expiry(self, rig: Rig) -> None:
        pid = rig.queue(IP_A, temporary_block=False)
        rig.operator().approve(pid)
        assert rig.fw.calls == [("block_ip", IP_A, None)]
        (applied,) = rig.store.list_response_actions(status="applied")
        assert applied.expires_at is None

    def test_approve_denied_when_ip_became_protected_by_guard(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        cfg = make_config(mode="approval", admin_ranges=["203.0.113.0/24"])
        with pytest.raises(FirewallError, match="self-lockout protection"):
            rig.operator(cfg, guard=make_guard(cfg)).approve(pid)
        self._assert_denied(rig, pid, "self-lockout protection")

    def test_approve_denied_when_ip_became_allowlisted(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        cfg = make_config(mode="approval", allowlist=["203.0.113.0/24"])
        with pytest.raises(FirewallError, match="allowlisted"):
            rig.operator(cfg).approve(pid)
        self._assert_denied(rig, pid, "allowlisted")

    def test_approve_stays_pending_when_breaker_is_open(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        seed_actions(rig.store, 2)
        cfg = make_config(mode="approval", max_blocks_per_hour=2)
        with pytest.raises(FirewallError, match="circuit breaker.*try again later"):
            rig.operator(cfg).approve(pid)
        self._assert_still_pending(rig, pid, "circuit breaker")

    def test_approve_succeeds_after_the_breaker_window_passes(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        seed_actions(rig.store, 2)
        op = rig.operator(make_config(mode="approval", max_blocks_per_hour=2))
        with pytest.raises(FirewallError, match="try again later"):
            op.approve(pid)
        rig.clock.advance(3600)
        assert op.approve(pid).success is True
        row = rig.store.get_pending(pid)
        assert row is not None and row.status == "approved"

    def test_approve_stays_pending_when_ip_already_blocked(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.fw.blocked.add(IP_A)
        with pytest.raises(FirewallError, match="already blocked.*try again later"):
            rig.operator().approve(pid)
        self._assert_still_pending(rig, pid, "already blocked")

    def test_approve_fails_closed_when_block_history_is_unreadable(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pid = rig.queue(IP_A)

        def boom(since: datetime) -> int:
            raise RuntimeError("db locked")

        monkeypatch.setattr(rig.store, "count_response_actions_since", boom)
        with pytest.raises(FirewallError, match="refusing to block.*try again later"):
            rig.operator().approve(pid)
        self._assert_still_pending(rig, pid, "could not read the block history")

    def test_approve_applies_no_block_when_the_row_cannot_be_recorded(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pid = rig.queue(IP_A)

        def boom(*args: Any, **kwargs: Any) -> int:
            raise RuntimeError("disk full")

        monkeypatch.setattr(rig.store, "add_response_action", boom)
        with pytest.raises(FirewallError, match="could not record the block"):
            rig.operator().approve(pid)
        row = rig.store.get_pending(pid)
        assert row is not None and row.status == "pending"
        assert rig.fw.calls == []
        assert rig.records("failed")

    @staticmethod
    def _assert_still_pending(rig: Rig, pid: int, reason_part: str) -> None:
        row = rig.store.get_pending(pid)
        assert row is not None
        assert row.status == "pending"
        assert rig.fw.calls == []  # the firewall was never touched
        assert [r for r in rig.store.list_response_actions() if r.run_id != "seed"] == []
        assert rig.records("denied") == []
        (record,) = rig.records("skipped")
        assert reason_part in record["reason"]
        assert record["ip"] == IP_A

    @staticmethod
    def _assert_denied(rig: Rig, pid: int, reason_part: str) -> None:
        row = rig.store.get_pending(pid)
        assert row is not None
        assert row.status == "denied"
        assert reason_part in row.note
        assert rig.fw.calls == []  # no block (or unblock) was attempted
        assert [r for r in rig.store.list_response_actions() if r.run_id != "seed"] == []
        (record,) = rig.records("denied")
        assert reason_part in record["reason"]
        assert record["ip"] == IP_A

    def test_approve_when_firewall_refuses_keeps_pending_open(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.fw.block_result = False
        with pytest.raises(FirewallError, match="could not block"):
            rig.operator().approve(pid)
        row = rig.store.get_pending(pid)
        assert row is not None and row.status == "pending"
        assert rig.store.list_response_actions(status="applied") == []
        assert [r.status for r in rig.store.list_response_actions()] == ["failed"]
        assert rig.records("failed")

    def test_approve_when_firewall_raises_keeps_pending_open(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.fw.block_error = FirewallError("ufw missing")
        with pytest.raises(FirewallError, match="ufw missing"):
            rig.operator().approve(pid)
        row = rig.store.get_pending(pid)
        assert row is not None and row.status == "pending"

    def test_approve_can_be_retried_after_a_firewall_failure(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.fw.block_result = False
        op = rig.operator()
        with pytest.raises(FirewallError):
            op.approve(pid)
        rig.fw.block_result = True
        assert op.approve(pid).success is True

    def test_approve_unknown_id_raises(self, rig: Rig) -> None:
        with pytest.raises(FirewallError, match="not found"):
            rig.operator().approve(999)
        assert rig.fw.calls == []

    def test_approve_already_decided_raises_without_second_block(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        op = rig.operator()
        op.approve(pid)
        with pytest.raises(FirewallError, match="already approved"):
            op.approve(pid)
        assert len(rig.fw.calls_named("temporary_block")) == 1

    def test_approve_after_deny_raises(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        op = rig.operator()
        op.deny(pid)
        with pytest.raises(FirewallError, match="already denied"):
            op.approve(pid)
        assert rig.fw.calls == []

    def test_approve_expired_request_raises(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.clock.advance(86400 + 1)
        op = rig.operator()
        op.pending()  # expires it
        with pytest.raises(FirewallError, match="already expired"):
            op.approve(pid)

    def test_deny_marks_row_and_audits_without_touching_firewall(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.operator().deny(pid, note="false positive")
        row = rig.store.get_pending(pid)
        assert row is not None
        assert row.status == "denied"
        assert row.note == "false positive"
        assert rig.fw.calls == []
        (record,) = rig.records("denied")
        assert record["reason"] == "false positive"
        assert record["ip"] == IP_A
        assert record["pending_id"] == pid

    def test_deny_without_note_has_default_reason(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.operator().deny(pid)
        assert rig.records("denied")[0]["reason"] == "denied by operator"

    def test_deny_unknown_or_decided_id_raises(self, rig: Rig) -> None:
        op = rig.operator()
        with pytest.raises(FirewallError, match="not found"):
            op.deny(123)
        pid = rig.queue(IP_A)
        op.deny(pid)
        with pytest.raises(FirewallError, match="already denied"):
            op.deny(pid)


# -- ResponseOperator: reap, rollback, history ------------------------------


class TestOperatorReapRollbackHistory:
    def test_reap_does_nothing_before_expiry(self, rig: Rig) -> None:
        rig.responder().consider(make_alert(IP_A))
        rig.clock.advance(3599)
        assert rig.operator().reap() == []
        assert rig.fw.blocked == {IP_A}

    def test_reap_unblocks_due_temporary_block_and_marks_reaped(self, rig: Rig) -> None:
        rig.responder().consider(make_alert(IP_A))
        rig.clock.advance(3601)
        actions = rig.operator().reap()
        assert [(a.action, a.ip, a.success) for a in actions] == [("unblock", IP_A, True)]
        assert rig.fw.blocked == set()
        (row,) = rig.store.list_response_actions()
        assert row.status == "reaped"
        (record,) = rig.records("reaped")
        assert record["ip"] == IP_A

    def test_reap_leaves_permanent_blocks(self, rig: Rig) -> None:
        rig.responder(make_config(temporary_block=False)).consider(make_alert(IP_A, alert_id=1))
        rig.responder().consider(make_alert(IP_B, alert_id=2))
        rig.clock.advance(10 * 3600)
        actions = rig.operator().reap()
        assert [a.ip for a in actions] == [IP_B]
        assert rig.fw.blocked == {IP_A}
        statuses = {r.ip: r.status for r in rig.store.list_response_actions()}
        assert statuses == {IP_A: "applied", IP_B: "reaped"}

    def test_reap_retries_when_unblock_fails(self, rig: Rig) -> None:
        rig.responder().consider(make_alert(IP_A))
        rig.clock.advance(3601)
        op = rig.operator()
        rig.fw.unblock_result = False
        (failed,) = op.reap()
        assert failed.success is False
        assert rig.store.list_response_actions()[0].status == "applied"
        assert rig.fw.blocked == {IP_A}
        assert rig.records("failed")

        rig.fw.unblock_result = True
        (retry,) = op.reap()
        assert retry.success is True
        assert rig.store.list_response_actions()[0].status == "reaped"
        assert rig.fw.blocked == set()

    def test_reap_retries_when_unblock_raises(self, rig: Rig) -> None:
        rig.responder().consider(make_alert(IP_A))
        rig.clock.advance(3601)
        rig.fw.unblock_error = FirewallError("ufw gone")
        (failed,) = rig.operator().reap()
        assert failed.success is False
        assert "ufw gone" in failed.detail
        assert rig.store.list_response_actions()[0].status == "applied"

    def test_reaped_block_is_not_reaped_twice(self, rig: Rig) -> None:
        rig.responder().consider(make_alert(IP_A))
        rig.clock.advance(3601)
        op = rig.operator()
        assert len(op.reap()) == 1
        assert op.reap() == []
        assert len(rig.fw.calls_named("unblock_ip")) == 1

    def test_reap_also_expires_stale_pending_requests(self, rig: Rig) -> None:
        pid = rig.queue(IP_A)
        rig.clock.advance(86400 + 1)
        rig.operator().reap()
        row = rig.store.get_pending(pid)
        assert row is not None and row.status == "expired"

    def test_rollback_since_unblocks_only_later_rows(self, rig: Rig) -> None:
        rig.responder(run_id="run-1").consider(make_alert(IP_A, alert_id=1))
        rig.clock.advance(2 * 3600)
        rig.responder(run_id="run-2").consider(make_alert(IP_B, alert_id=2))
        actions = rig.operator().rollback(since=NOW + HOUR)
        assert [(a.ip, a.success) for a in actions] == [(IP_B, True)]
        assert rig.fw.blocked == {IP_A}
        statuses = {r.ip: r.status for r in rig.store.list_response_actions()}
        assert statuses == {IP_A: "applied", IP_B: "rolled_back"}
        (record,) = rig.records("rolled_back")
        assert record["ip"] == IP_B

    def test_rollback_run_id_unblocks_only_that_run(self, rig: Rig) -> None:
        rig.responder(run_id="run-1").consider(make_alert(IP_A, alert_id=1))
        rig.responder(run_id="run-2").consider(make_alert(IP_B, alert_id=2))
        actions = rig.operator().rollback(run_id="run-1")
        assert [a.ip for a in actions] == [IP_A]
        assert rig.fw.blocked == {IP_B}
        statuses = {r.ip: r.status for r in rig.store.list_response_actions()}
        assert statuses == {IP_A: "rolled_back", IP_B: "applied"}

    def test_rollback_without_filters_raises_value_error(self, rig: Rig) -> None:
        rig.responder().consider(make_alert(IP_A))
        with pytest.raises(ValueError, match="since"):
            rig.operator().rollback()
        assert rig.fw.blocked == {IP_A}

    def test_rollback_leaves_reaped_rows_untouched(self, rig: Rig) -> None:
        rig.responder(run_id="run-1").consider(make_alert(IP_A))
        rig.clock.advance(3601)
        op = rig.operator()
        op.reap()
        assert op.rollback(run_id="run-1") == []
        assert len(rig.fw.calls_named("unblock_ip")) == 1
        assert rig.store.list_response_actions()[0].status == "reaped"

    def test_rollback_ignores_failed_rows(self, rig: Rig) -> None:
        rig.fw.block_result = False
        rig.responder(run_id="run-1").consider(make_alert(IP_A))
        assert rig.operator().rollback(run_id="run-1") == []
        assert rig.fw.calls_named("unblock_ip") == []
        assert rig.store.list_response_actions()[0].status == "failed"

    def test_rollback_keeps_row_applied_when_unblock_fails(self, rig: Rig) -> None:
        rig.responder(run_id="run-1").consider(make_alert(IP_A))
        rig.fw.unblock_result = False
        (action,) = rig.operator().rollback(run_id="run-1")
        assert action.success is False
        assert rig.store.list_response_actions()[0].status == "applied"
        assert rig.records("failed")

    def test_history_returns_audit_records(self, rig: Rig) -> None:
        rig.responder().consider(make_alert(IP_A))
        history = rig.operator().history()
        assert [r["decision"] for r in history] == ["blocked"]
        assert history[0]["ip"] == IP_A

    def test_history_respects_limit_and_order(self, rig: Rig) -> None:
        rig.responder().consider(make_alert(IP_A, alert_id=1))
        rig.responder().consider(make_alert(IP_B, alert_id=2))
        history = rig.operator().history(limit=1)
        assert len(history) == 1
        assert history[0]["ip"] == IP_B

    def test_history_without_audit_is_empty(self, rig: Rig) -> None:
        op = ResponseOperator(make_config(), rig.fw, rig.store, None, None, rig.clock)
        assert op.history() == []


# -- CommandAdapter --------------------------------------------------------


class FakeRun:
    """Stand-in for ``subprocess.run`` that records every invocation."""

    def __init__(
        self,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
        error: Exception | None = None,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.error = error
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(args), kwargs))
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, self.stderr)


def patch_run(monkeypatch: pytest.MonkeyPatch, **kwargs: Any) -> FakeRun:
    fake = FakeRun(**kwargs)
    monkeypatch.setattr("sentinelai.firewall.adapters.subprocess.run", fake)
    return fake


def command_adapter(**overrides: Any) -> CommandAdapter:
    values: dict[str, Any] = {"adapter": "command", "command": "fwctl", "timeout_seconds": 7.0}
    values.update(overrides)
    return CommandAdapter(FirewallConfig(**values))


BAD_IPS = ["1.2.3.4; rm -rf /", "$(id)", "", "1.2.3.4 && reboot", "`id`", "../../etc/passwd"]


class TestCommandAdapter:
    def test_block_ip_passes_argument_list_without_shell(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        run = patch_run(monkeypatch)
        assert command_adapter().block_ip(IP_A) is True
        ((args, kwargs),) = run.calls
        assert args == ["fwctl", "block", IP_A]
        assert isinstance(args, list)
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 7.0

    def test_unblock_ip_substitutes_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run = patch_run(monkeypatch)
        assert command_adapter().unblock_ip(IP_A) is True
        assert run.calls[0][0] == ["fwctl", "unblock", IP_A]

    def test_temporary_block_substitutes_ip_and_duration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        run = patch_run(monkeypatch)
        assert command_adapter().temporary_block(IP_A, 600) is True
        assert run.calls[0][0] == ["fwctl", "block", IP_A, "--duration", "600"]

    def test_substitution_works_inside_a_larger_argument(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        run = patch_run(monkeypatch)
        adapter = command_adapter(block_args=["--src={ip}", "--ttl={duration}"])
        adapter.block_ip(IP_A)
        assert run.calls[0][0] == ["fwctl", f"--src={IP_A}", "--ttl={duration}"]

    @pytest.mark.parametrize("bad_ip", BAD_IPS)
    @pytest.mark.parametrize("method", ["block_ip", "unblock_ip", "temporary_block"])
    def test_invalid_ip_is_refused_without_running_anything(
        self, monkeypatch: pytest.MonkeyPatch, method: str, bad_ip: str
    ) -> None:
        run = patch_run(monkeypatch)
        adapter = command_adapter()
        args = (bad_ip, 60) if method == "temporary_block" else (bad_ip,)
        with pytest.raises(FirewallError, match="invalid IP"):
            getattr(adapter, method)(*args)
        assert run.calls == []

    @pytest.mark.parametrize("method", ["block_ip", "unblock_ip", "temporary_block"])
    def test_non_zero_exit_is_failure(self, monkeypatch: pytest.MonkeyPatch, method: str) -> None:
        patch_run(monkeypatch, returncode=2, stderr="denied")
        adapter = command_adapter()
        args = (IP_A, 60) if method == "temporary_block" else (IP_A,)
        assert getattr(adapter, method)(*args) is False

    @pytest.mark.parametrize(
        "error",
        [
            FileNotFoundError("fwctl not found"),
            PermissionError("not executable"),
            subprocess.TimeoutExpired(cmd="fwctl", timeout=7.0),
        ],
    )
    def test_oserror_and_timeout_become_firewall_error(
        self, monkeypatch: pytest.MonkeyPatch, error: Exception
    ) -> None:
        patch_run(monkeypatch, error=error)
        with pytest.raises(FirewallError, match="failed to run"):
            command_adapter().block_ip(IP_A)

    def test_list_blocked_parses_valid_ips_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        run = patch_run(monkeypatch, stdout=f"{IP_A} extra\nnot-an-ip\n{IP_B}\n")
        adapter = command_adapter()
        assert adapter.list_blocked() == [IP_A, IP_B]
        assert run.calls[0][0] == ["fwctl", "list"]
        assert adapter.is_blocked(IP_B) is True
        assert adapter.is_blocked(IP_C) is False

    def test_list_blocked_non_zero_exit_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_run(monkeypatch, returncode=1, stderr="boom")
        with pytest.raises(FirewallError, match="exited 1"):
            command_adapter().list_blocked()


class TestCreateFirewall:
    def test_dry_run_returns_dry_run_adapter(self) -> None:
        fw = create_firewall(FirewallConfig(adapter="dry_run"))
        assert isinstance(fw, DryRunAdapter)

    def test_command_returns_command_adapter(self) -> None:
        fw = create_firewall(FirewallConfig(adapter="command", command="fwctl"))
        assert isinstance(fw, CommandAdapter)

    def test_dry_run_satisfies_protocol_and_touches_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        run = patch_run(monkeypatch)
        fw = create_firewall(FirewallConfig(adapter="dry_run"))
        assert isinstance(fw, FirewallController)
        assert fw.temporary_block(IP_A, 60) is True
        assert fw.is_blocked(IP_A) is True
        assert fw.unblock_ip(IP_A) is True
        assert fw.is_blocked(IP_A) is False
        assert run.calls == []

    def test_fake_firewall_satisfies_protocol(self) -> None:
        assert isinstance(FakeFirewall(), FirewallController)


# -- Example UFW adapter ---------------------------------------------------

UFW_PATH = Path(__file__).resolve().parents[1] / "examples" / "firewall_adapter_ufw.py"

PUBLIC_V4 = "8.8.8.8"
PUBLIC_V6 = "2001:4860:4860::8888"

UFW_STATUS = """\
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
Anywhere                   DENY        8.8.8.8
Anywhere (v6)              DENY        2001:4860:4860::8888
Anywhere                   DENY IN     9.9.9.9
[ 1] Anywhere              DENY IN     1.1.1.1
[ 2] Anywhere (v6)         DENY IN     2606:4700:4700::1111
Anywhere                   ALLOW       4.4.4.4
Anywhere                   DENY        203.0.113.0/24
Anywhere                   DENY        8.8.8.8
Anywhere                   DENY        not-an-ip
22/tcp                     DENY        5.5.5.5
Anywhere
totally unrelated junk line
"""


@pytest.fixture(scope="module")
def ufw_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("firewall_adapter_ufw_under_test", UFW_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeRunner:
    """Injected ``runner`` for the UFW example."""

    def __init__(
        self,
        returncode: int = 0,
        stdout: str = "Status: active\n",
        error: Exception | None = None,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.error = error
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def commands(self) -> list[list[str]]:
        return [args for args, _ in self.calls]

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(args), kwargs))
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, "")


REFUSED_IPS = [
    "10.0.0.1",
    "192.168.1.1",
    "127.0.0.1",
    "::1",
    "224.0.0.1",
    "ff02::1",
    "169.254.1.1",
    "fe80::1",
    "0.0.0.0",
    "::",
    "garbage",
    "8.8.8.8; rm -rf /",
    "$(id)",
    "",
    "8.8.8.0/24",
    "8.8.8.8/32",
    "fe80::1%eth0",
    "2001:4860:4860::8888%eth0",
    "8.8.8.8 ",
    " 8.8.8.8",
    "8.8.8.8\n",
    "8.8.8.8 -s 1.1.1.1",
    "::ffff:10.0.0.1",
    "::ffff:127.0.0.1",
]


class TestUfwExampleAdapter:
    def test_block_ip_runs_ufw_deny_list_command(self, ufw_module: types.ModuleType) -> None:
        runner = FakeRunner()
        assert ufw_module.UfwFirewall(runner=runner).block_ip(PUBLIC_V4) is True
        assert runner.commands() == [
            ["sudo", "-n", "ufw", "status"],
            ["sudo", "-n", "ufw", "insert", "1", "deny", "from", PUBLIC_V4],
        ]
        assert all(kwargs["shell"] is False for _, kwargs in runner.calls)
        assert all(kwargs["timeout"] == 15 for _, kwargs in runner.calls)

    def test_unblock_ip_runs_ufw_delete_deny_command(self, ufw_module: types.ModuleType) -> None:
        runner = FakeRunner()
        assert ufw_module.UfwFirewall(runner=runner).unblock_ip(PUBLIC_V4) is True
        assert runner.commands() == [["sudo", "-n", "ufw", "delete", "deny", "from", PUBLIC_V4]]

    def test_default_prefix_is_sudo_non_interactive(self, ufw_module: types.ModuleType) -> None:
        runner = FakeRunner()
        ufw_module.UfwFirewall(runner=runner).list_blocked()
        assert runner.calls[0][0][:2] == ["sudo", "-n"]

    def test_ipv6_is_passed_in_canonical_form(self, ufw_module: types.ModuleType) -> None:
        runner = FakeRunner()
        ufw_module.UfwFirewall(runner=runner).block_ip("2001:4860:4860:0:0:0:0:8888")
        assert runner.calls[-1][0][-1] == PUBLIC_V6

    def test_ipv4_mapped_ipv6_is_canonicalised_to_ipv4(
        self, ufw_module: types.ModuleType
    ) -> None:
        runner = FakeRunner()
        assert ufw_module.UfwFirewall(runner=runner).block_ip("::ffff:8.8.8.8") is True
        assert runner.calls[-1][0][-1] == PUBLIC_V4

    def test_every_call_closes_stdin_and_forces_the_c_locale(
        self, ufw_module: types.ModuleType
    ) -> None:
        runner = FakeRunner(stdout=UFW_STATUS)
        fw = ufw_module.UfwFirewall(runner=runner)
        fw.block_ip(PUBLIC_V4)
        fw.unblock_ip(PUBLIC_V4)
        fw.list_blocked()
        assert runner.calls
        for _, kwargs in runner.calls:
            assert kwargs["stdin"] is subprocess.DEVNULL
            assert kwargs["env"]["LC_ALL"] == "C"

    def test_block_is_refused_while_ufw_is_inactive(self, ufw_module: types.ModuleType) -> None:
        runner = FakeRunner(stdout="Status: inactive\n")
        fw = ufw_module.UfwFirewall(runner=runner)
        assert fw.block_ip(PUBLIC_V4) is False
        assert fw.temporary_block(PUBLIC_V4, 60) is False
        assert runner.commands() == [["sudo", "-n", "ufw", "status"]] * 2

    def test_unblock_is_still_attempted_while_ufw_is_inactive(
        self, ufw_module: types.ModuleType
    ) -> None:
        runner = FakeRunner(stdout="Status: inactive\n")
        assert ufw_module.UfwFirewall(runner=runner).unblock_ip(PUBLIC_V4) is True
        assert runner.commands() == [["sudo", "-n", "ufw", "delete", "deny", "from", PUBLIC_V4]]

    def test_shell_is_never_true(self, ufw_module: types.ModuleType) -> None:
        runner = FakeRunner(stdout=UFW_STATUS)
        fw = ufw_module.UfwFirewall(runner=runner)
        fw.block_ip(PUBLIC_V4)
        fw.unblock_ip(PUBLIC_V4)
        fw.temporary_block(PUBLIC_V4, 60)
        fw.list_blocked()
        fw.is_blocked(PUBLIC_V4)
        assert len(runner.calls) == 7  # block/temp: status + insert; the rest: one call each
        assert all(kwargs.get("shell") is False for _, kwargs in runner.calls)
        assert all(isinstance(args, list) for args, _ in runner.calls)

    @pytest.mark.parametrize("bad_ip", REFUSED_IPS)
    def test_refused_ips_run_no_command_and_return_false(
        self, ufw_module: types.ModuleType, bad_ip: str
    ) -> None:
        runner = FakeRunner()
        fw = ufw_module.UfwFirewall(runner=runner)
        assert fw.block_ip(bad_ip) is False
        assert fw.unblock_ip(bad_ip) is False
        assert fw.temporary_block(bad_ip, 60) is False
        assert fw.is_blocked(bad_ip) is False
        assert runner.calls == []

    def test_non_string_ip_is_refused(self, ufw_module: types.ModuleType) -> None:
        runner = FakeRunner()
        fw = ufw_module.UfwFirewall(runner=runner)
        assert fw.block_ip(None) is False
        assert fw.block_ip(808) is False
        assert runner.calls == []

    def test_temporary_block_installs_plain_deny_rule(self, ufw_module: types.ModuleType) -> None:
        runner = FakeRunner()
        assert ufw_module.UfwFirewall(runner=runner).temporary_block(PUBLIC_V4, 300) is True
        assert runner.commands() == [
            ["sudo", "-n", "ufw", "status"],
            ["sudo", "-n", "ufw", "insert", "1", "deny", "from", PUBLIC_V4],
        ]

    @pytest.mark.parametrize("duration", [0, -1, -3600, True, False, 1.5, "60", None])
    def test_temporary_block_rejects_invalid_durations(
        self, ufw_module: types.ModuleType, duration: Any
    ) -> None:
        runner = FakeRunner()
        assert ufw_module.UfwFirewall(runner=runner).temporary_block(PUBLIC_V4, duration) is False
        assert runner.calls == []

    def test_list_blocked_parses_ufw_status_output(self, ufw_module: types.ModuleType) -> None:
        runner = FakeRunner(stdout=UFW_STATUS)
        blocked = ufw_module.UfwFirewall(runner=runner).list_blocked()
        assert blocked == [
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "8.8.8.8",
            "9.9.9.9",
        ]
        assert runner.calls[0][0] == ["sudo", "-n", "ufw", "status"]

    def test_list_blocked_ignores_allow_cidr_and_junk(self, ufw_module: types.ModuleType) -> None:
        status = (
            "Anywhere ALLOW 4.4.4.4\n"
            "Anywhere DENY 203.0.113.0/24\n"
            "Anywhere DENY\n"
            "Anywhere DENY IN\n"
            "22/tcp DENY 5.5.5.5\n"
            "\x00\x01 garbage\n"
        )
        assert ufw_module.UfwFirewall(runner=FakeRunner(stdout=status)).list_blocked() == []

    def test_list_blocked_collapses_duplicates(self, ufw_module: types.ModuleType) -> None:
        status = "Anywhere DENY 8.8.8.8\nAnywhere DENY IN 8.8.8.8\n[ 3] Anywhere DENY 8.8.8.8\n"
        fw = ufw_module.UfwFirewall(runner=FakeRunner(stdout=status))
        assert fw.list_blocked() == ["8.8.8.8"]

    def test_is_blocked_reflects_status_output(self, ufw_module: types.ModuleType) -> None:
        fw = ufw_module.UfwFirewall(runner=FakeRunner(stdout=UFW_STATUS))
        assert fw.is_blocked("9.9.9.9") is True
        assert fw.is_blocked("4.4.4.4") is False

    def test_runner_non_zero_exit_returns_failure(self, ufw_module: types.ModuleType) -> None:
        fw = ufw_module.UfwFirewall(runner=FakeRunner(returncode=1, stdout=UFW_STATUS))
        assert fw.block_ip(PUBLIC_V4) is False
        assert fw.unblock_ip(PUBLIC_V4) is False
        assert fw.temporary_block(PUBLIC_V4, 60) is False
        assert fw.list_blocked() == []
        assert fw.is_blocked("9.9.9.9") is False

    @pytest.mark.parametrize(
        "error",
        [
            FileNotFoundError("ufw"),
            PermissionError("sudo"),
            subprocess.TimeoutExpired(cmd="ufw", timeout=15),
            subprocess.CalledProcessError(1, "ufw"),
        ],
    )
    def test_runner_exceptions_are_swallowed_into_failure(
        self, ufw_module: types.ModuleType, error: Exception
    ) -> None:
        fw = ufw_module.UfwFirewall(runner=FakeRunner(error=error))
        assert fw.block_ip(PUBLIC_V4) is False
        assert fw.unblock_ip(PUBLIC_V4) is False
        assert fw.list_blocked() == []

    def test_empty_sudo_prefix_omits_sudo(self, ufw_module: types.ModuleType) -> None:
        runner = FakeRunner()
        fw = ufw_module.UfwFirewall(sudo_prefix=(), runner=runner)
        fw.block_ip(PUBLIC_V4)
        fw.list_blocked()
        assert runner.commands() == [
            ["ufw", "status"],
            ["ufw", "insert", "1", "deny", "from", PUBLIC_V4],
            ["ufw", "status"],
        ]

    def test_list_sudo_prefix_from_config_and_custom_binary(
        self, ufw_module: types.ModuleType
    ) -> None:
        runner = FakeRunner()
        fw = ufw_module.UfwFirewall(
            sudo_prefix=["doas"], ufw_binary="/usr/sbin/ufw", timeout_seconds=3, runner=runner
        )
        fw.unblock_ip(PUBLIC_V4)
        args, kwargs = runner.calls[0]
        assert args == ["doas", "/usr/sbin/ufw", "delete", "deny", "from", PUBLIC_V4]
        assert kwargs["timeout"] == 3

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"ufw_binary": ""},
            {"timeout_seconds": 0},
            {"timeout_seconds": -5},
            {"timeout_seconds": True},
            {"timeout_seconds": 1.5},
            {"sudo_prefix": ("sudo", "")},
            {"sudo_prefix": ("sudo", 1)},
        ],
    )
    def test_constructor_rejects_bad_arguments(
        self, ufw_module: types.ModuleType, kwargs: dict[str, Any]
    ) -> None:
        with pytest.raises(ValueError):
            ufw_module.UfwFirewall(runner=FakeRunner(), **kwargs)

    def test_satisfies_firewall_controller_protocol(self, ufw_module: types.ModuleType) -> None:
        assert isinstance(ufw_module.UfwFirewall(runner=FakeRunner()), FirewallController)
