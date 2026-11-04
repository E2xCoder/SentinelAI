"""SQLite persistence for alerts.

Alerts are stored with indexed columns for querying plus the full JSON
document, so ``sentinel explain <id>`` and reporting can rehydrate
everything after the process exits.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelai.core.exceptions import StorageError
from sentinelai.core.models import (
    AIInsight,
    Alert,
    EventCategory,
    EventType,
    IPReputation,
    LogEvent,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    Severity,
)
from sentinelai.utils.logging import get_logger
from sentinelai.utils.timeparse import parse_iso_timestamp

_LOGGER = get_logger("core.store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    risk_level  TEXT NOT NULL,
    risk_score  REAL NOT NULL,
    ip          TEXT,
    user        TEXT,
    hostname    TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts (ip);
CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts (user);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_risk ON alerts (risk_level);
"""

SCHEMA_VERSION = 3

_MIGRATION_2: tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS feedback ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "alert_id INTEGER NOT NULL UNIQUE REFERENCES alerts(id), "
    "label TEXT NOT NULL CHECK(label IN ('tp','fp')), "
    "note TEXT NOT NULL DEFAULT '', "
    "ts TEXT NOT NULL, "
    "rule_id TEXT NOT NULL, "
    "snapshot TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_feedback_rule ON feedback (rule_id)",
    "CREATE TABLE IF NOT EXISTS config_history ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "ts TEXT NOT NULL, "
    "action TEXT NOT NULL CHECK(action IN ('apply','rollback')), "
    "proposal_ids TEXT NOT NULL, "
    "previous_text TEXT NOT NULL, "
    "new_text TEXT NOT NULL, "
    "note TEXT NOT NULL DEFAULT '', "
    "rolled_back INTEGER NOT NULL DEFAULT 0)",
)

_MIGRATION_3: tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS response_actions ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "ts TEXT NOT NULL, "
    "action TEXT NOT NULL CHECK(action IN ('block_ip','temporary_block')), "
    "ip TEXT NOT NULL, "
    "duration_seconds INTEGER, "
    "expires_at TEXT, "
    "status TEXT NOT NULL CHECK(status IN ('applied','reaped','rolled_back','failed')), "
    "alert_id INTEGER, "
    "rule_id TEXT NOT NULL DEFAULT '', "
    "run_id TEXT NOT NULL DEFAULT '', "
    "detail TEXT NOT NULL DEFAULT '')",
    "CREATE INDEX IF NOT EXISTS idx_response_actions_status_exp "
    "ON response_actions (status, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_response_actions_ip ON response_actions (ip)",
    "CREATE INDEX IF NOT EXISTS idx_response_actions_run ON response_actions (run_id)",
    "CREATE INDEX IF NOT EXISTS idx_response_actions_ts ON response_actions (ts)",
    "CREATE TABLE IF NOT EXISTS response_pending ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "ts TEXT NOT NULL, "
    "ip TEXT NOT NULL, "
    "alert_id INTEGER, "
    "rule_id TEXT NOT NULL DEFAULT '', "
    "risk_level TEXT NOT NULL, "
    "risk_score REAL NOT NULL, "
    "action TEXT NOT NULL CHECK(action IN ('block_ip','temporary_block')), "
    "duration_seconds INTEGER, "
    "status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired')), "
    "decided_at TEXT, "
    "note TEXT NOT NULL DEFAULT '')",
    "CREATE INDEX IF NOT EXISTS idx_response_pending_status ON response_pending (status)",
    "CREATE INDEX IF NOT EXISTS idx_response_pending_ip ON response_pending (ip)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_response_pending_ip "
    "ON response_pending (ip) WHERE status = 'pending'",
)

# Statements executed (inside one transaction) to reach each schema version.
_MIGRATIONS: dict[int, tuple[str, ...]] = {2: _MIGRATION_2, 3: _MIGRATION_3}

_FEEDBACK_LABELS = frozenset({"tp", "fp"})
_CONFIG_ACTIONS = frozenset({"apply", "rollback"})
_RESPONSE_ACTIONS = frozenset({"block_ip", "temporary_block"})
_RESPONSE_STATUSES = frozenset({"applied", "reaped", "rolled_back", "failed"})
_PENDING_STATUSES = frozenset({"pending", "approved", "denied", "expired"})
_PENDING_DECISIONS = frozenset({"approved", "denied", "expired"})
_MAX_NOTE_LEN = 500

_ACTION_COLUMNS = (
    "id, ts, action, ip, duration_seconds, expires_at, status, alert_id, rule_id, run_id, detail"
)
_PENDING_COLUMNS = (
    "id, ts, ip, alert_id, rule_id, risk_level, risk_score, action, duration_seconds, "
    "status, decided_at, note"
)


@dataclass(slots=True)
class FeedbackEntry:
    """Analyst verdict (true/false positive) attached to one alert."""

    id: int
    alert_id: int
    label: str
    note: str
    ts: datetime
    rule_id: str
    snapshot: dict[str, Any]


@dataclass(slots=True)
class ConfigHistoryEntry:
    """One applied or rolled-back configuration change."""

    id: int
    ts: datetime
    action: str
    proposal_ids: list[str]
    previous_text: str
    new_text: str
    note: str
    rolled_back: bool


@dataclass(slots=True)
class ResponseActionRow:
    """One firewall response action (block / temporary block) and its lifecycle state."""

    id: int
    ts: datetime
    action: str
    ip: str
    duration_seconds: int | None
    expires_at: datetime | None
    status: str
    alert_id: int | None
    rule_id: str
    run_id: str
    detail: str


@dataclass(slots=True)
class PendingResponse:
    """A response awaiting human approval."""

    id: int
    ts: datetime
    ip: str
    alert_id: int | None
    rule_id: str
    risk_level: str
    risk_score: float
    action: str
    duration_seconds: int | None
    status: str
    decided_at: datetime | None
    note: str


class AlertStore:
    """Durable alert storage with id assignment."""

    def __init__(self, db_path: str | Path) -> None:
        try:
            self._conn = sqlite3.connect(str(db_path))
            self._migrate()
        except sqlite3.Error as exc:
            raise StorageError(f"Cannot open alert database {db_path}: {exc}") from exc
        except StorageError:
            self._conn.close()
            raise

    @property
    def schema_version(self) -> int:
        """Current ``PRAGMA user_version`` of the database."""
        try:
            row = self._conn.execute("PRAGMA user_version").fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to read schema version: {exc}") from exc
        return int(row[0])

    def _migrate(self) -> None:
        """Bring the database up to :data:`SCHEMA_VERSION`."""
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise StorageError("database is newer than this SentinelAI")
        if version == 0:
            # Fresh DB, or legacy v1 DB (alerts table already present): the v1
            # schema is idempotent, so both are normalised to version 1.
            self._conn.executescript(_SCHEMA)
            self._set_version_atomically(1, ())
            version = 1
        for target in range(version + 1, SCHEMA_VERSION + 1):
            self._set_version_atomically(target, _MIGRATIONS[target])

    def _set_version_atomically(self, target: int, statements: tuple[str, ...]) -> None:
        """Run *statements* and bump ``user_version`` in a single transaction."""
        self._conn.commit()
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            for statement in statements:
                self._conn.execute(statement)
            self._conn.execute(f"PRAGMA user_version = {int(target)}")
            self._conn.commit()
        except sqlite3.Error:
            self._conn.rollback()
            raise

    def save(self, alert: Alert) -> int:
        """Persist *alert*, assigning and returning its integer id."""
        try:
            cursor = self._conn.execute(
                "INSERT INTO alerts (rule_id, title, category, severity, "
                "risk_level, risk_score, ip, user, hostname, first_seen, "
                "last_seen, created_at, fingerprint, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    alert.rule_id,
                    alert.title,
                    alert.category.value,
                    alert.severity.value,
                    alert.risk.level.value,
                    alert.risk.score,
                    alert.ip,
                    alert.user,
                    alert.hostname,
                    alert.first_seen.isoformat(),
                    alert.last_seen.isoformat(),
                    alert.created_at.isoformat(),
                    alert.fingerprint,
                    json.dumps(alert.to_dict(include_events=True)),
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to persist alert: {exc}") from exc
        alert.id = int(cursor.lastrowid or 0)
        return alert.id

    def update(self, alert: Alert) -> None:
        """Refresh a stored alert (risk, intel, AI fields may have changed)."""
        if alert.id is None:
            raise StorageError("Cannot update an alert that was never saved")
        try:
            self._conn.execute(
                "UPDATE alerts SET risk_level = ?, risk_score = ?, "
                "last_seen = ?, payload = ? WHERE id = ?",
                (
                    alert.risk.level.value,
                    alert.risk.score,
                    alert.last_seen.isoformat(),
                    json.dumps(alert.to_dict(include_events=True)),
                    alert.id,
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to update alert #{alert.id}: {exc}") from exc

    def get(self, alert_id: int) -> Alert | None:
        """Load one alert by id, rehydrated into a full object."""
        try:
            row = self._conn.execute(
                "SELECT payload FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to read alert #{alert_id}: {exc}") from exc
        if row is None:
            return None
        return _alert_from_payload(json.loads(row[0]), alert_id)

    def recent(self, limit: int = 50) -> list[Alert]:
        """Most recently created alerts, newest first."""
        try:
            rows = self._conn.execute(
                "SELECT id, payload FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to list alerts: {exc}") from exc
        return [_alert_from_payload(json.loads(payload), alert_id) for alert_id, payload in rows]

    def alerts_since(self, since: datetime, limit: int = 500) -> list[Alert]:
        """Alerts created at or after *since*, highest risk first (ties: newest first)."""
        try:
            rows = self._conn.execute(
                "SELECT id, payload FROM alerts WHERE created_at >= ? "
                "ORDER BY risk_score DESC, id DESC LIMIT ?",
                (_utc_iso(since), max(0, int(limit))),
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to list alerts: {exc}") from exc
        return [_alert_from_payload(json.loads(payload), alert_id) for alert_id, payload in rows]

    def count_alerts_by_level_since(self, since: datetime) -> dict[str, int]:
        """Exact number of alerts per risk level created at or after *since*."""
        try:
            rows = self._conn.execute(
                "SELECT risk_level, COUNT(*) FROM alerts WHERE created_at >= ? "
                "GROUP BY risk_level",
                (_utc_iso(since),),
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to count alerts: {exc}") from exc
        return {str(level): int(count) for level, count in rows}

    def count_alerts_since(self, since: datetime) -> int:
        """Exact number of alerts created at or after *since*."""
        try:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE created_at >= ?", (_utc_iso(since),)
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to count alerts: {exc}") from exc
        return int(row[0])

    def latest_alert_time(self) -> datetime | None:
        """Creation time of the most recently stored alert, or ``None`` if there is none."""
        try:
            row = self._conn.execute(
                "SELECT created_at FROM alerts ORDER BY id DESC LIMIT 1"
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to read latest alert time: {exc}") from exc
        if row is None:
            return None
        return _parse_stored_ts(row[0])

    # -- feedback ---------------------------------------------------------

    def add_feedback(
        self,
        alert_id: int,
        label: str,
        note: str = "",
        ts: datetime | None = None,
    ) -> int:
        """Label an alert ``tp``/``fp``; re-labelling replaces the previous verdict."""
        if label not in _FEEDBACK_LABELS:
            raise StorageError(f"Invalid feedback label {label!r}; expected 'tp' or 'fp'")
        stamp = _utc_iso(ts)
        note = note[:_MAX_NOTE_LEN]
        try:
            alert_row = self._conn.execute(
                "SELECT rule_id, payload FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            if alert_row is None:
                raise StorageError(f"Cannot add feedback: alert #{alert_id} does not exist")
            rule_id, payload = alert_row
            existing = self._conn.execute(
                "SELECT id FROM feedback WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            if existing is not None:
                feedback_id = int(existing[0])
                self._conn.execute(
                    "UPDATE feedback SET label = ?, note = ?, ts = ?, rule_id = ?, "
                    "snapshot = ? WHERE id = ?",
                    (label, note, stamp, rule_id, payload, feedback_id),
                )
            else:
                cursor = self._conn.execute(
                    "INSERT INTO feedback (alert_id, label, note, ts, rule_id, snapshot) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (alert_id, label, note, stamp, rule_id, payload),
                )
                feedback_id = int(cursor.lastrowid or 0)
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StorageError(f"Failed to store feedback for alert #{alert_id}: {exc}") from exc
        return feedback_id

    def list_feedback(
        self, label: str | None = None, rule_id: str | None = None
    ) -> list[FeedbackEntry]:
        """Feedback entries ordered by id, optionally filtered by label and/or rule."""
        clauses: list[str] = []
        params: list[Any] = []
        if label is not None:
            clauses.append("label = ?")
            params.append(label)
        if rule_id is not None:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        try:
            rows = self._conn.execute(
                "SELECT id, alert_id, label, note, ts, rule_id, snapshot "
                f"FROM feedback{where} ORDER BY id",
                params,
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to list feedback: {exc}") from exc
        return [
            FeedbackEntry(
                id=int(r[0]),
                alert_id=int(r[1]),
                label=str(r[2]),
                note=str(r[3]),
                ts=_parse_stored_ts(r[4]),
                rule_id=str(r[5]),
                snapshot=_load_json_object(r[6]),
            )
            for r in rows
        ]

    def delete_feedback(self, alert_id: int) -> bool:
        """Remove the feedback for *alert_id*; ``True`` if a row was deleted."""
        try:
            cursor = self._conn.execute("DELETE FROM feedback WHERE alert_id = ?", (alert_id,))
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StorageError(f"Failed to delete feedback for alert #{alert_id}: {exc}") from exc
        return cursor.rowcount > 0

    # -- config history ---------------------------------------------------

    def add_config_history(
        self,
        action: str,
        proposal_ids: Sequence[str],
        previous_text: str,
        new_text: str,
        note: str = "",
        ts: datetime | None = None,
    ) -> int:
        """Record a configuration change and return its history id."""
        if action not in _CONFIG_ACTIONS:
            raise StorageError(f"Invalid config action {action!r}; expected 'apply' or 'rollback'")
        stamp = _utc_iso(ts)
        try:
            cursor = self._conn.execute(
                "INSERT INTO config_history (ts, action, proposal_ids, previous_text, "
                "new_text, note, rolled_back) VALUES (?, ?, ?, ?, ?, ?, 0)",
                (
                    stamp,
                    action,
                    json.dumps([str(p) for p in proposal_ids]),
                    previous_text,
                    new_text,
                    note,
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StorageError(f"Failed to record config history: {exc}") from exc
        return int(cursor.lastrowid or 0)

    def list_config_history(self) -> list[ConfigHistoryEntry]:
        """All config history entries ordered by id (oldest first)."""
        try:
            rows = self._conn.execute(
                "SELECT id, ts, action, proposal_ids, previous_text, new_text, note, "
                "rolled_back FROM config_history ORDER BY id"
            ).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to list config history: {exc}") from exc
        return [
            ConfigHistoryEntry(
                id=int(r[0]),
                ts=_parse_stored_ts(r[1]),
                action=str(r[2]),
                proposal_ids=_load_str_list(r[3]),
                previous_text=str(r[4]),
                new_text=str(r[5]),
                note=str(r[6]),
                rolled_back=bool(r[7]),
            )
            for r in rows
        ]

    def mark_rolled_back(self, history_id: int) -> None:
        """Flag a history entry as rolled back; error if the id is unknown."""
        try:
            cursor = self._conn.execute(
                "UPDATE config_history SET rolled_back = 1 WHERE id = ?", (history_id,)
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StorageError(f"Failed to mark history #{history_id} rolled back: {exc}") from exc
        if cursor.rowcount == 0:
            raise StorageError(f"Config history entry #{history_id} does not exist")

    # -- response actions -------------------------------------------------

    def add_response_action(
        self,
        *,
        action: str,
        ip: str,
        duration_seconds: int | None,
        expires_at: datetime | None,
        status: str,
        alert_id: int | None,
        rule_id: str,
        run_id: str,
        detail: str = "",
        ts: datetime | None = None,
    ) -> int:
        """Record a response action and return its id."""
        if action not in _RESPONSE_ACTIONS:
            raise StorageError(f"Invalid response action {action!r}")
        if status not in _RESPONSE_STATUSES:
            raise StorageError(f"Invalid response action status {status!r}")
        stamp = _utc_iso(ts)
        expires = _utc_iso(expires_at) if expires_at is not None else None
        try:
            cursor = self._conn.execute(
                "INSERT INTO response_actions (ts, action, ip, duration_seconds, expires_at, "
                "status, alert_id, rule_id, run_id, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    stamp,
                    action,
                    ip,
                    duration_seconds,
                    expires,
                    status,
                    alert_id,
                    rule_id,
                    run_id,
                    detail[:_MAX_NOTE_LEN],
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StorageError(f"Failed to record response action: {exc}") from exc
        return int(cursor.lastrowid or 0)

    def list_response_actions(
        self,
        *,
        status: str | None = None,
        since: datetime | None = None,
        run_id: str | None = None,
        ip: str | None = None,
        limit: int | None = None,
    ) -> list[ResponseActionRow]:
        """Response actions ordered by id ascending, with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(_utc_iso(since))
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if ip is not None:
            clauses.append("ip = ?")
            params.append(ip)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        limit_sql = ""
        if limit is not None:
            limit_sql = " LIMIT ?"
            params.append(int(limit))
        return self._query_actions(
            f"SELECT {_ACTION_COLUMNS} FROM response_actions{where} ORDER BY id{limit_sql}",
            params,
        )

    def count_response_actions_since(self, since: datetime) -> int:
        """Number of successful blocks (applied/reaped/rolled_back) at or after *since*."""
        try:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM response_actions "
                "WHERE status IN ('applied', 'reaped', 'rolled_back') AND ts >= ?",
                (_utc_iso(since),),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to count response actions: {exc}") from exc
        return int(row[0])

    def set_response_action_status(self, action_id: int, status: str, detail: str = "") -> None:
        """Change an action's status; a non-empty *detail* replaces the stored detail."""
        if status not in _RESPONSE_STATUSES:
            raise StorageError(f"Invalid response action status {status!r}")
        try:
            if detail:
                cursor = self._conn.execute(
                    "UPDATE response_actions SET status = ?, detail = ? WHERE id = ?",
                    (status, detail[:_MAX_NOTE_LEN], action_id),
                )
            else:
                cursor = self._conn.execute(
                    "UPDATE response_actions SET status = ? WHERE id = ?",
                    (status, action_id),
                )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StorageError(f"Failed to update response action #{action_id}: {exc}") from exc
        if cursor.rowcount == 0:
            raise StorageError(f"Response action #{action_id} does not exist")

    def due_response_actions(self, now: datetime) -> list[ResponseActionRow]:
        """Applied actions whose expiry has passed (ready to be reaped)."""
        return self._query_actions(
            f"SELECT {_ACTION_COLUMNS} FROM response_actions "
            "WHERE status = 'applied' AND expires_at IS NOT NULL AND expires_at <= ? "
            "ORDER BY id",
            [_utc_iso(now)],
        )

    def covering_response_actions(
        self, ip: str, *, exclude_id: int, expires_after: datetime | None
    ) -> list[ResponseActionRow]:
        """Applied actions for *ip* (other than *exclude_id*) that outlive *expires_after*.

        Permanent rows always qualify; timed rows qualify only when
        *expires_after* is given and their expiry is strictly later.
        """
        sql = (
            f"SELECT {_ACTION_COLUMNS} FROM response_actions "
            "WHERE status = 'applied' AND ip = ? AND id != ? AND (expires_at IS NULL"
        )
        params: list[Any] = [ip, int(exclude_id)]
        if expires_after is not None:
            sql += " OR expires_at > ?"
            params.append(_utc_iso(expires_after))
        sql += ") ORDER BY id"
        return self._query_actions(sql, params)

    def _query_actions(self, sql: str, params: Sequence[Any]) -> list[ResponseActionRow]:
        try:
            rows = self._conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to list response actions: {exc}") from exc
        result: list[ResponseActionRow] = []
        for r in rows:
            try:
                result.append(_action_from_row(r))
            except (StorageError, ValueError, TypeError) as exc:
                _LOGGER.warning("Skipping corrupt response action row %r: %s", r[0], exc)
        return result

    # -- pending approvals ------------------------------------------------

    def add_pending(
        self,
        *,
        ip: str,
        alert_id: int | None,
        rule_id: str,
        risk_level: str,
        risk_score: float,
        action: str,
        duration_seconds: int | None,
        ts: datetime | None = None,
    ) -> int:
        """Queue a response for human approval and return the pending id."""
        if action not in _RESPONSE_ACTIONS:
            raise StorageError(f"Invalid response action {action!r}")
        stamp = _utc_iso(ts)
        try:
            cursor = self._conn.execute(
                "INSERT INTO response_pending (ts, ip, alert_id, rule_id, risk_level, "
                "risk_score, action, duration_seconds, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
                (
                    stamp,
                    ip,
                    alert_id,
                    rule_id,
                    risk_level,
                    float(risk_score),
                    action,
                    duration_seconds,
                ),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            if "UNIQUE" in str(exc).upper():
                raise StorageError("a request for this IP is already pending") from exc
            raise StorageError(f"Failed to queue pending response: {exc}") from exc
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StorageError(f"Failed to queue pending response: {exc}") from exc
        return int(cursor.lastrowid or 0)

    def list_pending(self, status: str | None = "pending") -> list[PendingResponse]:
        """Pending-response rows ordered by id; ``status=None`` returns every row."""
        sql = f"SELECT {_PENDING_COLUMNS} FROM response_pending"
        params: list[Any] = []
        if status is not None:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY id"
        try:
            rows = self._conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to list pending responses: {exc}") from exc
        return [p for p in (_safe_pending_from_row(r) for r in rows) if p is not None]

    def get_pending(self, pending_id: int) -> PendingResponse | None:
        """Load one pending response by id (``None`` if missing or corrupt)."""
        try:
            row = self._conn.execute(
                f"SELECT {_PENDING_COLUMNS} FROM response_pending WHERE id = ?",
                (pending_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to read pending response #{pending_id}: {exc}") from exc
        return _safe_pending_from_row(row) if row is not None else None

    def pending_count(self) -> int:
        """Number of rows still awaiting a decision."""
        try:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM response_pending WHERE status = 'pending'"
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to count pending responses: {exc}") from exc
        return int(row[0])

    def claim_pending(self, pending_id: int, note: str = "") -> bool:
        """Atomically move ``pending`` -> ``approved``; ``True`` only for the single winner."""
        try:
            cursor = self._conn.execute(
                "UPDATE response_pending SET status = 'approved', decided_at = ?, note = ? "
                "WHERE id = ? AND status = 'pending'",
                (_utc_iso(None), note[:_MAX_NOTE_LEN], pending_id),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StorageError(f"Failed to claim pending response #{pending_id}: {exc}") from exc
        return cursor.rowcount == 1

    def release_pending(self, pending_id: int) -> None:
        """Undo a claim (``approved`` -> ``pending``); no-op if it no longer applies.

        If another open request for the same IP exists meanwhile, the row is
        marked ``denied`` ("superseded") instead.
        """
        try:
            try:
                self._conn.execute(
                    "UPDATE response_pending SET status = 'pending', decided_at = NULL "
                    "WHERE id = ? AND status = 'approved'",
                    (pending_id,),
                )
            except sqlite3.IntegrityError:
                self._conn.rollback()
                self._conn.execute(
                    "UPDATE response_pending SET status = 'denied', note = ?, decided_at = ? "
                    "WHERE id = ? AND status = 'approved'",
                    ("superseded", _utc_iso(None), pending_id),
                )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StorageError(f"Failed to release pending response #{pending_id}: {exc}") from exc

    def has_open_pending(self, ip: str) -> int | None:
        """Id of a still-pending row for *ip*, else ``None``."""
        try:
            row = self._conn.execute(
                "SELECT id FROM response_pending WHERE ip = ? AND status = 'pending' "
                "ORDER BY id DESC LIMIT 1",
                (ip,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to look up pending response for {ip}: {exc}") from exc
        return int(row[0]) if row is not None else None

    def decide_pending(
        self,
        pending_id: int,
        status: str,
        note: str = "",
        decided_at: datetime | None = None,
    ) -> None:
        """Move a row to approved/denied/expired; valid from ``pending`` (or approved->denied)."""
        if status not in _PENDING_DECISIONS:
            raise StorageError(
                f"Invalid pending decision {status!r}; expected 'approved', 'denied' or 'expired'"
            )
        stamp = _utc_iso(decided_at)
        allowed_from = ("pending", "approved") if status == "denied" else ("pending",)
        placeholders = ", ".join("?" for _ in allowed_from)
        try:
            cursor = self._conn.execute(
                "UPDATE response_pending SET status = ?, note = ?, decided_at = ? "
                f"WHERE id = ? AND status IN ({placeholders})",
                (status, note[:_MAX_NOTE_LEN], stamp, pending_id, *allowed_from),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StorageError(f"Failed to decide pending response #{pending_id}: {exc}") from exc
        if cursor.rowcount == 0:
            raise StorageError(f"Pending response #{pending_id} does not exist or is not pending")

    def expire_pending(self, older_than: datetime) -> int:
        """Mark pending rows created before *older_than* as expired; return the count."""
        try:
            cursor = self._conn.execute(
                "UPDATE response_pending SET status = 'expired', decided_at = ? "
                "WHERE status = 'pending' AND ts < ?",
                (_utc_iso(None), _utc_iso(older_than)),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise StorageError(f"Failed to expire pending responses: {exc}") from exc
        return int(cursor.rowcount)

    def close(self) -> None:
        """Close the database handle."""
        self._conn.close()


def _action_from_row(r: Sequence[Any]) -> ResponseActionRow:
    return ResponseActionRow(
        id=int(r[0]),
        ts=_parse_stored_ts(r[1]),
        action=str(r[2]),
        ip=str(r[3]),
        duration_seconds=int(r[4]) if r[4] is not None else None,
        expires_at=_parse_stored_ts(r[5]) if r[5] is not None else None,
        status=str(r[6]),
        alert_id=int(r[7]) if r[7] is not None else None,
        rule_id=str(r[8]),
        run_id=str(r[9]),
        detail=str(r[10]),
    )


def _safe_pending_from_row(r: Sequence[Any]) -> PendingResponse | None:
    """Convert a row, logging and returning ``None`` if it is corrupt."""
    try:
        return _pending_from_row(r)
    except (StorageError, ValueError, TypeError) as exc:
        _LOGGER.warning("Skipping corrupt pending response row %r: %s", r[0], exc)
        return None


def _pending_from_row(r: Sequence[Any]) -> PendingResponse:
    return PendingResponse(
        id=int(r[0]),
        ts=_parse_stored_ts(r[1]),
        ip=str(r[2]),
        alert_id=int(r[3]) if r[3] is not None else None,
        rule_id=str(r[4]),
        risk_level=str(r[5]),
        risk_score=float(r[6]),
        action=str(r[7]),
        duration_seconds=int(r[8]) if r[8] is not None else None,
        status=str(r[9]),
        decided_at=_parse_stored_ts(r[10]) if r[10] is not None else None,
        note=str(r[11]),
    )


def _utc_iso(ts: datetime | None) -> str:
    """UTC ISO-8601 string; naive datetimes are assumed to already be UTC."""
    moment = ts if ts is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat()


def _parse_stored_ts(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise StorageError(f"Stored record has invalid timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _load_json_object(value: Any) -> dict[str, Any]:
    try:
        data = json.loads(str(value))
    except json.JSONDecodeError as exc:
        raise StorageError(f"Stored feedback snapshot is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise StorageError("Stored feedback snapshot is not a JSON object")
    return data


def _load_str_list(value: Any) -> list[str]:
    try:
        data = json.loads(str(value))
    except json.JSONDecodeError as exc:
        raise StorageError(f"Stored proposal ids are not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise StorageError("Stored proposal ids are not a JSON list")
    return [str(item) for item in data]


def _parse_ts(value: Any, fallback: datetime | None = None) -> datetime:
    parsed = parse_iso_timestamp(str(value)) if value else None
    if parsed is None:
        if fallback is None:
            raise StorageError(f"Stored alert has invalid timestamp: {value!r}")
        return fallback
    return parsed


def _alert_from_payload(data: dict[str, Any], alert_id: int) -> Alert:
    """Rebuild an Alert object from its stored JSON document."""
    risk_data = data.get("risk") or {}
    risk = RiskAssessment(
        score=float(risk_data.get("score", 0.0)),
        level=RiskLevel(risk_data.get("level", "informational")),
        factors=[
            RiskFactor(f["name"], float(f["points"]), f["reason"])
            for f in risk_data.get("factors", [])
        ],
    )
    intel = None
    if data.get("intel"):
        idata = data["intel"]
        intel = IPReputation(
            ip=idata["ip"],
            malicious=bool(idata.get("malicious")),
            score=float(idata.get("score", 0.0)),
            sources=idata.get("sources", {}),
            country=idata.get("country"),
            isp=idata.get("isp"),
            tags=idata.get("tags", []),
            checked_at=parse_iso_timestamp(idata["checked_at"])
            if idata.get("checked_at")
            else None,
            errors=idata.get("errors", []),
        )
    ai = None
    if data.get("ai"):
        adata = data["ai"]
        triage_data = adata.get("triage")
        ai = AIInsight(
            anomaly_score=adata.get("anomaly_score"),
            is_anomaly=bool(adata.get("is_anomaly")),
            model=adata.get("model"),
            patterns=adata.get("patterns", []),
            explanation=adata.get("explanation"),
            explanation_source=adata.get("explanation_source"),
            confidence=adata.get("confidence"),
            triage=triage_data if isinstance(triage_data, dict) else None,
        )
    events = []
    for edata in data.get("sample_events", []):
        try:
            events.append(
                LogEvent(
                    timestamp=_parse_ts(edata.get("timestamp")),
                    message=edata.get("message", ""),
                    raw=edata.get("message", ""),
                    source=edata.get("source", ""),
                    hostname=edata.get("hostname"),
                    service=edata.get("service"),
                    pid=edata.get("pid"),
                    event_type=EventType(edata.get("event_type", "generic")),
                    category=EventCategory(edata.get("category", "unknown")),
                    user=edata.get("user"),
                    ip=edata.get("ip"),
                    port=edata.get("port"),
                    severity=Severity(edata.get("severity", "info")),
                    extra=edata.get("extra", {}),
                )
            )
        except (StorageError, ValueError):
            _LOGGER.debug("Skipping malformed stored event on alert #%s", alert_id)
    first_seen = _parse_ts(data.get("first_seen"))
    return Alert(
        id=alert_id,
        rule_id=data["rule_id"],
        rule_name=data.get("rule_name", data["rule_id"]),
        title=data.get("title", ""),
        description=data.get("description", ""),
        category=EventCategory(data.get("category", "unknown")),
        severity=Severity(data.get("severity", "warning")),
        first_seen=first_seen,
        last_seen=_parse_ts(data.get("last_seen"), fallback=first_seen),
        ip=data.get("ip"),
        user=data.get("user"),
        hostname=data.get("hostname"),
        port=data.get("port"),
        event_count=int(data.get("event_count", 1)),
        mitre_tactics=data.get("mitre_tactics", []),
        mitre_techniques=data.get("mitre_techniques", []),
        sample_events=events,
        risk=risk,
        intel=intel,
        ai=ai,
        recommendation=data.get("recommendation", ""),
        context=data.get("context", {}),
        created_at=_parse_ts(data.get("created_at"), fallback=first_seen),
    )
