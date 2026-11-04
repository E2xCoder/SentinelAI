"""Core domain models shared by every SentinelAI subsystem.

These models are deliberately dependency-free (standard library only) so
that parsers, rules, AI models and reporters can all exchange data
without coupling to any framework.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Normalized severity of a single log event."""

    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        """Numeric weight used for sorting and scoring."""
        order = {
            Severity.DEBUG: 0,
            Severity.INFO: 1,
            Severity.NOTICE: 2,
            Severity.WARNING: 3,
            Severity.ERROR: 4,
            Severity.CRITICAL: 5,
        }
        return order[self]


class EventCategory(str, Enum):
    """High-level classification of a log event."""

    AUTHENTICATION = "authentication"
    NETWORK = "network"
    WEB = "web"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SYSTEM = "system"
    FIREWALL = "firewall"
    DOCKER = "docker"
    SSH = "ssh"
    USER_MANAGEMENT = "user_management"
    PACKAGE_MANAGEMENT = "package_management"
    SERVICE_MANAGEMENT = "service_management"
    CRON = "cron"
    UNKNOWN = "unknown"


class EventType(str, Enum):
    """Fine-grained event type extracted by parsers."""

    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    INVALID_USER = "invalid_user"
    ROOT_LOGIN = "root_login"
    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    SUDO_COMMAND = "sudo_command"
    SUDO_FAILURE = "sudo_failure"
    USER_ADDED = "user_added"
    USER_DELETED = "user_deleted"
    USER_MODIFIED = "user_modified"
    GROUP_ADDED = "group_added"
    PASSWORD_CHANGED = "password_changed"
    ACCOUNT_LOCKED = "account_locked"
    SSH_KEY_EVENT = "ssh_key_event"
    CONNECTION = "connection"
    DISCONNECTION = "disconnection"
    CONNECTION_BLOCKED = "connection_blocked"
    PORT_PROBE = "port_probe"
    WEB_REQUEST = "web_request"
    WEB_ERROR = "web_error"
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    SERVICE_FAILED = "service_failed"
    FIREWALL_MODIFIED = "firewall_modified"
    FIREWALL_BLOCK = "firewall_block"
    BAN = "ban"
    UNBAN = "unban"
    CONTAINER_EVENT = "container_event"
    CRON_JOB = "cron_job"
    CRON_EDIT = "cron_edit"
    PACKAGE_EVENT = "package_event"
    GENERIC = "generic"


@dataclass(slots=True)
class LogEvent:
    """A single structured event extracted from one log line."""

    timestamp: datetime
    message: str
    raw: str
    source: str = ""
    hostname: str | None = None
    service: str | None = None
    pid: int | None = None
    event_type: EventType = EventType.GENERIC
    category: EventCategory = EventCategory.UNKNOWN
    user: str | None = None
    ip: str | None = None
    port: int | None = None
    severity: Severity = Severity.INFO
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "hostname": self.hostname,
            "service": self.service,
            "pid": self.pid,
            "event_type": self.event_type.value,
            "category": self.category.value,
            "user": self.user,
            "ip": self.ip,
            "port": self.port,
            "severity": self.severity.value,
            "message": self.message,
            "source": self.source,
            "extra": self.extra,
        }


class RiskLevel(str, Enum):
    """Discrete risk level derived from a numeric risk score (0-100)."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> RiskLevel:
        """Map a 0-100 score onto a discrete level."""
        if score >= 85:
            return cls.CRITICAL
        if score >= 65:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 15:
            return cls.LOW
        return cls.INFORMATIONAL

    @property
    def weight(self) -> int:
        """Numeric weight used for sorting and threshold comparisons."""
        order = {
            RiskLevel.INFORMATIONAL: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        return order[self]


@dataclass(slots=True)
class RiskFactor:
    """One contribution to a risk score, with its justification."""

    name: str
    points: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "points": round(self.points, 1), "reason": self.reason}


@dataclass(slots=True)
class RiskAssessment:
    """Full risk assessment of an alert: score, level and the *why*."""

    score: float = 0.0
    level: RiskLevel = RiskLevel.INFORMATIONAL
    factors: list[RiskFactor] = field(default_factory=list)

    def explain(self) -> str:
        """Human-readable multi-line explanation of the score."""
        lines = [f"Risk score {self.score:.0f}/100 ({self.level.value})"]
        lines.extend(f"  {f.points:+.0f}  {f.name}: {f.reason}" for f in self.factors)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "level": self.level.value,
            "factors": [f.to_dict() for f in self.factors],
        }


@dataclass(slots=True)
class IPReputation:
    """Aggregated threat-intelligence verdict for one IP address."""

    ip: str
    malicious: bool = False
    score: float = 0.0
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    country: str | None = None
    isp: str | None = None
    tags: list[str] = field(default_factory=list)
    checked_at: datetime | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "malicious": self.malicious,
            "score": round(self.score, 1),
            "sources": self.sources,
            "country": self.country,
            "isp": self.isp,
            "tags": self.tags,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
            "errors": self.errors,
        }


@dataclass(slots=True)
class AIInsight:
    """Output of the AI engine attached to an alert or report."""

    anomaly_score: float | None = None
    is_anomaly: bool = False
    model: str | None = None
    patterns: list[str] = field(default_factory=list)
    explanation: str | None = None
    explanation_source: str | None = None
    confidence: float | None = None
    #: Advisory structured triage (``TriageResult.to_dict()`` + ``source``/``language``).
    triage: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "anomaly_score": self.anomaly_score,
            "is_anomaly": self.is_anomaly,
            "model": self.model,
            "patterns": self.patterns,
            "explanation": self.explanation,
            "explanation_source": self.explanation_source,
            "confidence": self.confidence,
        }
        if self.triage is not None:
            data["triage"] = self.triage
        return data


@dataclass(slots=True)
class Alert:
    """A structured detection produced by the rule engine or AI engine."""

    rule_id: str
    rule_name: str
    title: str
    description: str
    category: EventCategory
    severity: Severity
    first_seen: datetime
    last_seen: datetime
    id: int | None = None
    ip: str | None = None
    user: str | None = None
    hostname: str | None = None
    port: int | None = None
    event_count: int = 1
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    sample_events: list[LogEvent] = field(default_factory=list)
    risk: RiskAssessment = field(default_factory=RiskAssessment)
    intel: IPReputation | None = None
    ai: AIInsight | None = None
    recommendation: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def fingerprint(self) -> str:
        """Stable identity used for de-duplication of repeated alerts."""
        key = f"{self.rule_id}|{self.ip or '-'}|{self.user or '-'}|{self.hostname or '-'}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self, include_events: bool = True) -> dict[str, Any]:
        """Serialize to a JSON-friendly dictionary."""
        data: dict[str, Any] = {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity.value,
            "ip": self.ip,
            "user": self.user,
            "hostname": self.hostname,
            "port": self.port,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "risk": self.risk.to_dict(),
            "intel": self.intel.to_dict() if self.intel else None,
            "ai": self.ai.to_dict() if self.ai else None,
            "recommendation": self.recommendation,
            "context": self.context,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at.isoformat(),
        }
        if include_events:
            data["sample_events"] = [e.to_dict() for e in self.sample_events]
        return data


def _parse_dt(value: Any) -> datetime:
    """Parse an ISO-8601 string (or datetime) into an aware UTC datetime."""
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if text[-1:] in ("Z", "z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item) for item in value]


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


@dataclass(slots=True)
class TimelineEntry:
    """One step of an incident timeline (an alert or a collapsed run of alerts)."""

    timestamp: datetime
    alert_id: int | None
    rule_id: str
    title: str
    tactic: str
    risk_level: str
    risk_score: float
    count: int = 1
    ip: str | None = None
    user: str | None = None
    host: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "tactic": self.tactic,
            "risk_level": self.risk_level,
            "risk_score": round(self.risk_score, 1),
            "count": self.count,
            "ip": self.ip,
            "user": self.user,
            "host": self.host,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimelineEntry:
        raw_id = data.get("alert_id")
        return cls(
            timestamp=_parse_dt(data["timestamp"]),
            alert_id=int(raw_id) if raw_id is not None else None,
            rule_id=str(data.get("rule_id", "")),
            title=str(data.get("title", "")),
            tactic=str(data.get("tactic", "")),
            risk_level=str(data.get("risk_level", RiskLevel.INFORMATIONAL.value)),
            risk_score=float(data.get("risk_score", 0.0)),
            count=int(data.get("count", 1)),
            ip=_opt_str(data.get("ip")),
            user=_opt_str(data.get("user")),
            host=_opt_str(data.get("host")),
        )


@dataclass(slots=True)
class Incident:
    """A correlated group of alerts forming one attack storyline (advisory only)."""

    title: str
    summary: str
    first_seen: datetime
    last_seen: datetime
    score: float
    level: RiskLevel
    stages: list[str]
    timeline: list[TimelineEntry]
    ips: list[str]
    users: list[str]
    hosts: list[str]
    alert_ids: list[int]
    rule_ids: list[str]
    mitre_techniques: list[str]
    alert_count: int
    id: int | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    triage: dict[str, Any] | None = None

    @property
    def fingerprint(self) -> str:
        """Stable identity: rules + IPs + users + first-seen day."""
        key = "|".join(
            (
                ",".join(sorted(self.rule_ids)),
                ",".join(sorted(self.ips)),
                ",".join(sorted(self.users)),
                self.first_seen.date().isoformat(),
            )
        )
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dictionary."""
        data: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "score": round(self.score, 1),
            "level": self.level.value,
            "stages": list(self.stages),
            "timeline": [entry.to_dict() for entry in self.timeline],
            "ips": list(self.ips),
            "users": list(self.users),
            "hosts": list(self.hosts),
            "alert_ids": list(self.alert_ids),
            "rule_ids": list(self.rule_ids),
            "mitre_techniques": list(self.mitre_techniques),
            "alert_count": self.alert_count,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at.isoformat(),
        }
        if self.triage is not None:
            data["triage"] = self.triage
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Incident:
        """Rebuild an incident from :meth:`to_dict` output (missing optional keys tolerated)."""
        first_seen = _parse_dt(data["first_seen"])
        last_raw = data.get("last_seen")
        created_raw = data.get("created_at")
        raw_id = data.get("id")
        timeline_raw = data.get("timeline")
        timeline = (
            [TimelineEntry.from_dict(t) for t in timeline_raw if isinstance(t, dict)]
            if isinstance(timeline_raw, list)
            else []
        )
        alert_ids_raw = data.get("alert_ids")
        alert_ids = (
            [int(a) for a in alert_ids_raw] if isinstance(alert_ids_raw, (list, tuple)) else []
        )
        triage = data.get("triage")
        return cls(
            title=str(data.get("title", "")),
            summary=str(data.get("summary", "")),
            first_seen=first_seen,
            last_seen=_parse_dt(last_raw) if last_raw else first_seen,
            score=float(data.get("score", 0.0)),
            level=RiskLevel(data.get("level", RiskLevel.INFORMATIONAL.value)),
            stages=_str_list(data.get("stages")),
            timeline=timeline,
            ips=_str_list(data.get("ips")),
            users=_str_list(data.get("users")),
            hosts=_str_list(data.get("hosts")),
            alert_ids=alert_ids,
            rule_ids=_str_list(data.get("rule_ids")),
            mitre_techniques=_str_list(data.get("mitre_techniques")),
            alert_count=int(data.get("alert_count", len(alert_ids))),
            id=int(raw_id) if raw_id is not None else None,
            created_at=_parse_dt(created_raw) if created_raw else first_seen,
            triage=triage if isinstance(triage, dict) else None,
        )
