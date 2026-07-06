"""SQLite persistence for alerts.

Alerts are stored with indexed columns for querying plus the full JSON
document, so ``sentinel explain <id>`` and reporting can rehydrate
everything after the process exits.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
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


class AlertStore:
    """Durable alert storage with id assignment."""

    def __init__(self, db_path: str | Path) -> None:
        try:
            self._conn = sqlite3.connect(str(db_path))
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError(f"Cannot open alert database {db_path}: {exc}") from exc

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

    def close(self) -> None:
        """Close the database handle."""
        self._conn.close()


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
        ai = AIInsight(
            anomaly_score=adata.get("anomaly_score"),
            is_anomaly=bool(adata.get("is_anomaly")),
            model=adata.get("model"),
            patterns=adata.get("patterns", []),
            explanation=adata.get("explanation"),
            explanation_source=adata.get("explanation_source"),
            confidence=adata.get("confidence"),
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
