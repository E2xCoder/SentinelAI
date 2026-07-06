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

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomaly_score": self.anomaly_score,
            "is_anomaly": self.is_anomaly,
            "model": self.model,
            "patterns": self.patterns,
            "explanation": self.explanation,
            "explanation_source": self.explanation_source,
            "confidence": self.confidence,
        }


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
