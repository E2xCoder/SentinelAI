"""Tests for the response persistence layer: schema v3, actions and pending approvals."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinelai.core.exceptions import StorageError
from sentinelai.core.models import Alert, EventCategory, Severity
from sentinelai.core.store import SCHEMA_VERSION, AlertStore
from sentinelai.risk.engine import RiskEngine
from tests.conftest import BASE_TS

T0 = datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)


def make_alert(rule_id: str = "R001", ip: str = "203.0.113.5") -> Alert:
    alert = Alert(
        rule_id=rule_id,
        rule_name="Test Rule",
        title=f"{rule_id} fired",
        description="synthetic alert",
        category=EventCategory.AUTHENTICATION,
        severity=Severity.WARNING,
        first_seen=BASE_TS,
        last_seen=BASE_TS + timedelta(seconds=30),
        ip=ip,
        user="alice",
        hostname="web01",
        event_count=6,
    )
    alert.risk = RiskEngine().score(alert)
    return alert


def _table_names(path: Path) -> set[str]:
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    finally:
        conn.close()
    return {row[0] for row in rows}


@pytest.fixture()
def store(tmp_path: Path) -> Iterator[AlertStore]:
    db = AlertStore(tmp_path / "alerts.db")
    yield db
    db.close()


def _action(
    store: AlertStore,
    *,
    ip: str = "203.0.113.5",
    status: str = "applied",
    action: str = "temporary_block",
    expires_at: datetime | None = None,
    duration_seconds: int | None = 3600,
    run_id: str = "run-1",
    alert_id: int | None = None,
    rule_id: str = "R001",
    detail: str = "",
    ts: datetime | None = T0,
) -> int:
    return store.add_response_action(
        action=action,
        ip=ip,
        duration_seconds=duration_seconds,
        expires_at=expires_at,
        status=status,
        alert_id=alert_id,
        rule_id=rule_id,
        run_id=run_id,
        detail=detail,
        ts=ts,
    )


def _pending(
    store: AlertStore,
    *,
    ip: str = "203.0.113.5",
    action: str = "temporary_block",
    ts: datetime | None = T0,
) -> int:
    return store.add_pending(
        ip=ip,
        alert_id=None,
        rule_id="R001",
        risk_level="high",
        risk_score=82.5,
        action=action,
        duration_seconds=3600,
        ts=ts,
    )


# -- migration 3 ---------------------------------------------------------------------------


class TestMigration3:
    def test_fresh_database_is_at_current_schema_with_response_tables(
        self, tmp_path: Path
    ) -> None:
        db = AlertStore(tmp_path / "fresh.db")
        try:
            assert db.schema_version == SCHEMA_VERSION
        finally:
            db.close()
        assert SCHEMA_VERSION >= 3
        assert {"response_actions", "response_pending"} <= _table_names(tmp_path / "fresh.db")

    def test_v2_database_upgrades_with_alerts_and_feedback_intact(self, tmp_path: Path) -> None:
        path = tmp_path / "v2.db"
        first = AlertStore(path)
        alert_id = first.save(make_alert())
        first.add_feedback(alert_id, "fp", note="known scanner")
        first.close()

        # Rewind to a genuine v2 state: no response tables, user_version 2.
        conn = sqlite3.connect(str(path))
        conn.execute("DROP TABLE response_actions")
        conn.execute("DROP TABLE response_pending")
        conn.execute("PRAGMA user_version = 2")
        conn.commit()
        conn.close()
        assert "response_actions" not in _table_names(path)

        db = AlertStore(path)
        try:
            assert db.schema_version == SCHEMA_VERSION
            loaded = db.get(alert_id)
            assert loaded is not None
            assert loaded.rule_id == "R001"
            (entry,) = db.list_feedback()
            assert entry.label == "fp"
            assert entry.note == "known scanner"
            # The new tables are usable immediately.
            assert _action(db) > 0
            assert _pending(db) > 0
        finally:
            db.close()
        assert {"response_actions", "response_pending"} <= _table_names(path)

    def test_reopening_upgraded_database_keeps_response_rows(self, tmp_path: Path) -> None:
        path = tmp_path / "again.db"
        first = AlertStore(path)
        _action(first)
        _pending(first)
        first.close()
        second = AlertStore(path)
        try:
            assert second.schema_version == SCHEMA_VERSION
            assert len(second.list_response_actions()) == 1
            assert len(second.list_pending()) == 1
        finally:
            second.close()


# -- response actions ----------------------------------------------------------------------


class TestResponseActions:
    def test_add_and_list_roundtrip(self, store: AlertStore) -> None:
        alert_id = store.save(make_alert())
        expires = T0 + timedelta(hours=1)
        action_id = _action(
            store,
            alert_id=alert_id,
            expires_at=expires,
            run_id="run-7",
            rule_id="R010",
            detail="ufw deny",
        )
        (row,) = store.list_response_actions()
        assert row.id == action_id
        assert row.ts == T0
        assert row.action == "temporary_block"
        assert row.ip == "203.0.113.5"
        assert row.duration_seconds == 3600
        assert row.expires_at == expires
        assert row.status == "applied"
        assert row.alert_id == alert_id
        assert row.rule_id == "R010"
        assert row.run_id == "run-7"
        assert row.detail == "ufw deny"

    def test_permanent_block_has_no_duration_or_expiry(self, store: AlertStore) -> None:
        _action(store, action="block_ip", duration_seconds=None, expires_at=None)
        (row,) = store.list_response_actions()
        assert row.action == "block_ip"
        assert row.duration_seconds is None
        assert row.expires_at is None

    def test_naive_timestamp_is_treated_as_utc(self, store: AlertStore) -> None:
        _action(store, ts=datetime(2026, 1, 7, 12, 0, 0))
        (row,) = store.list_response_actions()
        assert row.ts == T0

    def test_non_utc_timestamp_is_normalised(self, store: AlertStore) -> None:
        tz = timezone(timedelta(hours=3))
        _action(store, ts=datetime(2026, 1, 7, 15, 0, 0, tzinfo=tz))
        (row,) = store.list_response_actions()
        assert row.ts == T0

    def test_default_timestamp_is_recent_and_aware(self, store: AlertStore) -> None:
        _action(store, ts=None)
        (row,) = store.list_response_actions()
        assert row.ts.tzinfo is not None
        assert abs(datetime.now(timezone.utc) - row.ts) < timedelta(minutes=1)

    def test_listing_is_ordered_by_id_ascending(self, store: AlertStore) -> None:
        ids = [_action(store, ip=f"203.0.113.{i}", ts=T0 - timedelta(minutes=i)) for i in range(4)]
        assert [r.id for r in store.list_response_actions()] == ids

    def test_filter_by_status(self, store: AlertStore) -> None:
        a = _action(store, status="applied")
        f = _action(store, status="failed")
        assert [r.id for r in store.list_response_actions(status="failed")] == [f]
        assert [r.id for r in store.list_response_actions(status="applied")] == [a]
        assert store.list_response_actions(status="reaped") == []

    def test_filter_by_since_is_inclusive(self, store: AlertStore) -> None:
        old = _action(store, ts=T0 - timedelta(hours=2))
        edge = _action(store, ts=T0)
        new = _action(store, ts=T0 + timedelta(hours=1))
        result = [r.id for r in store.list_response_actions(since=T0)]
        assert old not in result
        assert result == [edge, new]

    def test_filter_by_run_id(self, store: AlertStore) -> None:
        _action(store, run_id="run-a")
        b = _action(store, run_id="run-b")
        assert [r.id for r in store.list_response_actions(run_id="run-b")] == [b]

    def test_filter_by_ip(self, store: AlertStore) -> None:
        _action(store, ip="203.0.113.1")
        b = _action(store, ip="203.0.113.2")
        assert [r.id for r in store.list_response_actions(ip="203.0.113.2")] == [b]

    def test_filters_combine_with_and(self, store: AlertStore) -> None:
        _action(store, ip="203.0.113.1", run_id="r1", status="applied")
        _action(store, ip="203.0.113.1", run_id="r2", status="applied")
        target = _action(store, ip="203.0.113.1", run_id="r2", status="failed")
        result = store.list_response_actions(ip="203.0.113.1", run_id="r2", status="failed")
        assert [r.id for r in result] == [target]

    def test_limit_returns_first_n_by_id(self, store: AlertStore) -> None:
        ids = [_action(store, ip=f"203.0.113.{i}") for i in range(5)]
        assert [r.id for r in store.list_response_actions(limit=2)] == ids[:2]

    def test_empty_store_lists_nothing(self, store: AlertStore) -> None:
        assert store.list_response_actions() == []

    @pytest.mark.parametrize("bad", ["delete", "", "BLOCK_IP", "unblock"])
    def test_invalid_action_is_rejected(self, store: AlertStore, bad: str) -> None:
        with pytest.raises(StorageError, match="action"):
            _action(store, action=bad)
        assert store.list_response_actions() == []

    @pytest.mark.parametrize("bad", ["pending", "", "APPLIED", "done"])
    def test_invalid_status_is_rejected(self, store: AlertStore, bad: str) -> None:
        with pytest.raises(StorageError, match="status"):
            _action(store, status=bad)
        assert store.list_response_actions() == []

    def test_sql_injection_string_in_ip_is_stored_literally(self, store: AlertStore) -> None:
        evil = "1.1.1.1'); DROP TABLE response_actions; --"
        _action(store, ip=evil)
        _action(store, ip="203.0.113.5")
        (row,) = store.list_response_actions(ip=evil)
        assert row.ip == evil
        assert len(store.list_response_actions()) == 2
        assert store.list_response_actions(ip="1.1.1.1' OR '1'='1") == []

    def test_detail_is_truncated_to_500_characters(self, store: AlertStore) -> None:
        _action(store, detail="d" * 900)
        (row,) = store.list_response_actions()
        assert len(row.detail) == 500


class TestCountResponseActionsSince:
    def test_counts_only_applied_reaped_and_rolled_back(self, store: AlertStore) -> None:
        _action(store, status="applied")
        _action(store, status="reaped")
        _action(store, status="rolled_back")
        _action(store, status="failed")
        _action(store, status="failed")
        assert store.count_response_actions_since(T0 - timedelta(minutes=1)) == 3

    def test_respects_since_boundary(self, store: AlertStore) -> None:
        _action(store, ts=T0 - timedelta(hours=2))
        _action(store, ts=T0)
        _action(store, ts=T0 + timedelta(hours=1))
        assert store.count_response_actions_since(T0) == 2
        assert store.count_response_actions_since(T0 + timedelta(hours=2)) == 0

    def test_empty_store_counts_zero(self, store: AlertStore) -> None:
        assert store.count_response_actions_since(T0) == 0

    def test_since_in_other_timezone_is_normalised(self, store: AlertStore) -> None:
        _action(store, ts=T0)
        tz = timezone(timedelta(hours=-5))
        assert store.count_response_actions_since(datetime(2026, 1, 7, 7, 0, 0, tzinfo=tz)) == 1
        assert store.count_response_actions_since(datetime(2026, 1, 7, 7, 0, 1, tzinfo=tz)) == 0


class TestSetResponseActionStatus:
    def test_status_changes_and_detail_is_kept_when_omitted(self, store: AlertStore) -> None:
        action_id = _action(store, detail="original")
        store.set_response_action_status(action_id, "reaped")
        (row,) = store.list_response_actions()
        assert row.status == "reaped"
        assert row.detail == "original"

    def test_non_empty_detail_replaces_stored_detail(self, store: AlertStore) -> None:
        action_id = _action(store, detail="original")
        store.set_response_action_status(action_id, "failed", detail="adapter error")
        (row,) = store.list_response_actions()
        assert row.status == "failed"
        assert row.detail == "adapter error"

    def test_detail_is_truncated_to_500_characters(self, store: AlertStore) -> None:
        action_id = _action(store)
        store.set_response_action_status(action_id, "rolled_back", detail="x" * 800)
        (row,) = store.list_response_actions()
        assert len(row.detail) == 500

    def test_unknown_id_raises_storage_error(self, store: AlertStore) -> None:
        with pytest.raises(StorageError, match="does not exist"):
            store.set_response_action_status(4242, "reaped")

    @pytest.mark.parametrize("bad", ["pending", "", "approved", "Applied"])
    def test_invalid_status_raises_storage_error_and_changes_nothing(
        self, store: AlertStore, bad: str
    ) -> None:
        action_id = _action(store)
        with pytest.raises(StorageError, match="status"):
            store.set_response_action_status(action_id, bad)
        (row,) = store.list_response_actions()
        assert row.status == "applied"


class TestDueResponseActions:
    NOW = T0 + timedelta(hours=1)

    def test_only_applied_and_expired_rows_are_due(self, store: AlertStore) -> None:
        due = _action(store, expires_at=self.NOW - timedelta(seconds=1))
        _action(store, expires_at=self.NOW + timedelta(seconds=1))  # not expired yet
        _action(store, status="reaped", expires_at=self.NOW - timedelta(hours=1))
        _action(store, status="rolled_back", expires_at=self.NOW - timedelta(hours=1))
        _action(store, status="failed", expires_at=self.NOW - timedelta(hours=1))
        assert [r.id for r in store.due_response_actions(self.NOW)] == [due]

    def test_expiry_equal_to_now_is_due(self, store: AlertStore) -> None:
        due = _action(store, expires_at=self.NOW)
        assert [r.id for r in store.due_response_actions(self.NOW)] == [due]

    def test_permanent_blocks_are_never_due(self, store: AlertStore) -> None:
        _action(store, action="block_ip", duration_seconds=None, expires_at=None)
        assert store.due_response_actions(T0 + timedelta(days=36500)) == []

    def test_due_rows_are_ordered_by_id(self, store: AlertStore) -> None:
        first = _action(store, expires_at=self.NOW - timedelta(hours=3))
        second = _action(store, expires_at=self.NOW - timedelta(hours=5))
        assert [r.id for r in store.due_response_actions(self.NOW)] == [first, second]

    def test_reaped_row_is_no_longer_due(self, store: AlertStore) -> None:
        action_id = _action(store, expires_at=self.NOW - timedelta(minutes=1))
        assert len(store.due_response_actions(self.NOW)) == 1
        store.set_response_action_status(action_id, "reaped")
        assert store.due_response_actions(self.NOW) == []

    def test_now_in_other_timezone_is_normalised(self, store: AlertStore) -> None:
        due = _action(store, expires_at=self.NOW)
        tz = timezone(timedelta(hours=2))
        assert [r.id for r in store.due_response_actions(self.NOW.astimezone(tz))] == [due]


# -- pending approvals ---------------------------------------------------------------------


class TestPendingLifecycle:
    def test_add_and_get_roundtrip(self, store: AlertStore) -> None:
        alert_id = store.save(make_alert())
        pending_id = store.add_pending(
            ip="203.0.113.5",
            alert_id=alert_id,
            rule_id="R010",
            risk_level="critical",
            risk_score=91,
            action="block_ip",
            duration_seconds=None,
            ts=T0,
        )
        row = store.get_pending(pending_id)
        assert row is not None
        assert row.id == pending_id
        assert row.ts == T0
        assert row.ip == "203.0.113.5"
        assert row.alert_id == alert_id
        assert row.rule_id == "R010"
        assert row.risk_level == "critical"
        assert row.risk_score == 91.0
        assert row.action == "block_ip"
        assert row.duration_seconds is None
        assert row.status == "pending"
        assert row.decided_at is None
        assert row.note == ""

    def test_get_unknown_pending_returns_none(self, store: AlertStore) -> None:
        assert store.get_pending(4242) is None

    @pytest.mark.parametrize("bad", ["delete", "", "BLOCK_IP"])
    def test_add_pending_invalid_action_is_rejected(self, store: AlertStore, bad: str) -> None:
        with pytest.raises(StorageError, match="action"):
            _pending(store, action=bad)
        assert store.list_pending(None) == []

    def test_sql_injection_string_in_ip_is_stored_literally(self, store: AlertStore) -> None:
        evil = "1.1.1.1'; DROP TABLE response_pending; --"
        pending_id = _pending(store, ip=evil)
        row = store.get_pending(pending_id)
        assert row is not None
        assert row.ip == evil
        assert store.has_open_pending(evil) == pending_id
        assert store.has_open_pending("1.1.1.1") is None

    def test_list_pending_defaults_to_pending_only(self, store: AlertStore) -> None:
        open_id = _pending(store, ip="203.0.113.1")
        done_id = _pending(store, ip="203.0.113.2")
        store.decide_pending(done_id, "approved")
        assert [p.id for p in store.list_pending()] == [open_id]

    def test_list_pending_none_returns_every_row_in_id_order(self, store: AlertStore) -> None:
        a = _pending(store, ip="203.0.113.1")
        b = _pending(store, ip="203.0.113.2")
        c = _pending(store, ip="203.0.113.3")
        store.decide_pending(b, "denied")
        assert [p.id for p in store.list_pending(None)] == [a, b, c]

    def test_list_pending_status_filter(self, store: AlertStore) -> None:
        a = _pending(store, ip="203.0.113.1")
        b = _pending(store, ip="203.0.113.2")
        store.decide_pending(a, "approved")
        store.decide_pending(b, "denied")
        assert [p.id for p in store.list_pending("approved")] == [a]
        assert [p.id for p in store.list_pending("denied")] == [b]
        assert store.list_pending("expired") == []

    def test_has_open_pending_returns_the_open_id_for_that_ip_only(self, store: AlertStore) -> None:
        _pending(store, ip="203.0.113.6")
        open_id = _pending(store)
        assert store.has_open_pending("203.0.113.5") == open_id

    def test_second_open_pending_for_same_ip_is_rejected(self, store: AlertStore) -> None:
        first = _pending(store)
        with pytest.raises(StorageError, match="already pending"):
            _pending(store)
        assert [p.id for p in store.list_pending(None)] == [first]
        assert store.has_open_pending("203.0.113.5") == first

    def test_has_open_pending_none_when_unknown_ip(self, store: AlertStore) -> None:
        _pending(store)
        assert store.has_open_pending("198.51.100.1") is None

    def test_has_open_pending_none_once_decided(self, store: AlertStore) -> None:
        pending_id = _pending(store)
        store.decide_pending(pending_id, "denied")
        assert store.has_open_pending("203.0.113.5") is None

    def test_new_pending_is_allowed_once_the_previous_one_is_decided(
        self, store: AlertStore
    ) -> None:
        older = _pending(store)
        store.decide_pending(older, "denied")
        newer = _pending(store)
        assert newer != older
        assert store.has_open_pending("203.0.113.5") == newer


class TestDecidePending:
    @pytest.mark.parametrize("decision", ["approved", "denied", "expired"])
    def test_pending_can_move_to_each_decision(self, store: AlertStore, decision: str) -> None:
        pending_id = _pending(store)
        decided = T0 + timedelta(minutes=5)
        store.decide_pending(pending_id, decision, note="operator ok", decided_at=decided)
        row = store.get_pending(pending_id)
        assert row is not None
        assert row.status == decision
        assert row.note == "operator ok"
        assert row.decided_at == decided

    def test_decided_at_defaults_to_now(self, store: AlertStore) -> None:
        pending_id = _pending(store)
        store.decide_pending(pending_id, "approved")
        row = store.get_pending(pending_id)
        assert row is not None
        assert row.decided_at is not None
        assert abs(datetime.now(timezone.utc) - row.decided_at) < timedelta(minutes=1)

    def test_note_is_truncated_to_500_characters(self, store: AlertStore) -> None:
        pending_id = _pending(store)
        store.decide_pending(pending_id, "denied", note="n" * 900)
        row = store.get_pending(pending_id)
        assert row is not None
        assert len(row.note) == 500

    @pytest.mark.parametrize("bad", ["pending", "", "reaped", "Approved"])
    def test_invalid_status_raises_storage_error_and_leaves_row_pending(
        self, store: AlertStore, bad: str
    ) -> None:
        pending_id = _pending(store)
        with pytest.raises(StorageError, match="decision"):
            store.decide_pending(pending_id, bad)
        row = store.get_pending(pending_id)
        assert row is not None
        assert row.status == "pending"
        assert row.decided_at is None

    @pytest.mark.parametrize(
        ("first", "second"),
        [
            (first, second)
            for first in ("approved", "denied", "expired")
            for second in ("approved", "denied", "expired")
            if (first, second) != ("approved", "denied")  # allowed: see next test
        ],
    )
    def test_already_decided_row_cannot_be_decided_again(
        self, store: AlertStore, first: str, second: str
    ) -> None:
        pending_id = _pending(store)
        store.decide_pending(pending_id, first, note="first")
        with pytest.raises(StorageError, match="not pending"):
            store.decide_pending(pending_id, second, note="second")
        row = store.get_pending(pending_id)
        assert row is not None
        assert row.status == first
        assert row.note == "first"

    def test_approved_row_can_still_be_denied_once(self, store: AlertStore) -> None:
        pending_id = _pending(store)
        store.decide_pending(pending_id, "approved", note="claimed")
        store.decide_pending(pending_id, "denied", note="no longer safe")
        row = store.get_pending(pending_id)
        assert row is not None
        assert row.status == "denied"
        assert row.note == "no longer safe"
        with pytest.raises(StorageError, match="not pending"):
            store.decide_pending(pending_id, "approved", note="again")

    def test_unknown_id_raises_storage_error(self, store: AlertStore) -> None:
        with pytest.raises(StorageError, match="does not exist"):
            store.decide_pending(4242, "approved")


class TestExpirePending:
    def test_expires_only_older_pending_rows_and_returns_count(self, store: AlertStore) -> None:
        old1 = _pending(store, ip="203.0.113.1", ts=T0 - timedelta(days=2))
        old2 = _pending(store, ip="203.0.113.2", ts=T0 - timedelta(days=3))
        fresh = _pending(store, ip="203.0.113.3", ts=T0)
        assert store.expire_pending(T0 - timedelta(days=1)) == 2
        assert [p.id for p in store.list_pending()] == [fresh]
        for pending_id in (old1, old2):
            row = store.get_pending(pending_id)
            assert row is not None
            assert row.status == "expired"

    def test_decided_at_is_set_on_expired_rows(self, store: AlertStore) -> None:
        pending_id = _pending(store, ts=T0 - timedelta(days=2))
        before = datetime.now(timezone.utc)
        store.expire_pending(T0)
        row = store.get_pending(pending_id)
        assert row is not None
        assert row.decided_at is not None
        assert row.decided_at >= before - timedelta(seconds=1)

    def test_cutoff_is_exclusive(self, store: AlertStore) -> None:
        _pending(store, ts=T0)
        assert store.expire_pending(T0) == 0

    def test_already_decided_rows_are_untouched(self, store: AlertStore) -> None:
        approved = _pending(store, ip="203.0.113.1", ts=T0 - timedelta(days=2))
        store.decide_pending(approved, "approved", note="ok", decided_at=T0)
        assert store.expire_pending(T0 + timedelta(days=1)) == 0
        row = store.get_pending(approved)
        assert row is not None
        assert row.status == "approved"
        assert row.note == "ok"
        assert row.decided_at == T0

    def test_empty_table_returns_zero(self, store: AlertStore) -> None:
        assert store.expire_pending(T0) == 0

    def test_expired_ip_no_longer_has_open_pending(self, store: AlertStore) -> None:
        _pending(store, ts=T0 - timedelta(days=2))
        store.expire_pending(T0)
        assert store.has_open_pending("203.0.113.5") is None
