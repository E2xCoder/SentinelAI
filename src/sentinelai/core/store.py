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

SCHEMA_VERSION = 2

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

# Statements executed (inside one transaction) to reach each schema version.
_MIGRATIONS: dict[int, tuple[str, ...]] = {2: _MIGRATION_2}

_FEEDBACK_LABELS = frozenset({"tp", "fp"})
_CONFIG_ACTIONS = frozenset({"apply", "rollback"})
_MAX_NOTE_LEN = 500


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

    def close(self) -> None:
        """Close the database handle."""
        self._conn.close()


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
