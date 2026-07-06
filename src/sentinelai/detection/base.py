"""Detection rule framework.

A rule is a small, focused class that inspects one event at a time
(optionally consulting shared sliding-window state) and emits structured
:class:`~sentinelai.core.models.Alert` objects. Rules are registered
with :func:`register_rule` so plugins can contribute detections without
touching the engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TypeVar

from sentinelai.config.models import DetectionConfig
from sentinelai.core.exceptions import SentinelError
from sentinelai.core.models import Alert, EventCategory, LogEvent, Severity
from sentinelai.detection.state import SlidingWindowStore

_RULE_REGISTRY: dict[str, type["Rule"]] = {}

R = TypeVar("R", bound=type["Rule"])

#: Number of raw events kept on an alert as supporting evidence.
MAX_SAMPLE_EVENTS = 5


class RuleContext:
    """Shared services available to rules during evaluation."""

    def __init__(self, config: DetectionConfig, state: SlidingWindowStore | None = None) -> None:
        self.config = config
        self.state = state or SlidingWindowStore()


class Rule(ABC):
    """Base class for all detection rules."""

    #: Stable identifier, e.g. ``R001``. Used in config enable/disable lists.
    rule_id: str = ""
    #: Human-readable rule name.
    name: str = ""
    #: What the rule detects and why it matters.
    description: str = ""
    #: Alert category assigned to detections.
    category: EventCategory = EventCategory.UNKNOWN
    #: Base severity of the produced alerts.
    severity: Severity = Severity.WARNING
    #: MITRE ATT&CK tactic names.
    mitre_tactics: tuple[str, ...] = ()
    #: MITRE ATT&CK technique IDs.
    mitre_techniques: tuple[str, ...] = ()
    #: Default remediation guidance included in alerts and reports.
    recommendation: str = ""

    @abstractmethod
    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        """Inspect one event; return an alert when the rule fires."""

    def make_alert(
        self,
        event: LogEvent,
        title: str,
        description: str,
        *,
        severity: Severity | None = None,
        events: list[LogEvent] | None = None,
        **context: object,
    ) -> Alert:
        """Build a structured alert from this rule for *event*."""
        evidence = events if events is not None else [event]
        timestamps = [e.timestamp for e in evidence] or [event.timestamp]
        return Alert(
            rule_id=self.rule_id,
            rule_name=self.name,
            title=title,
            description=description,
            category=self.category,
            severity=severity or self.severity,
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            ip=event.ip,
            user=event.user,
            hostname=event.hostname,
            port=event.port,
            event_count=len(evidence),
            mitre_tactics=list(self.mitre_tactics),
            mitre_techniques=list(self.mitre_techniques),
            sample_events=evidence[-MAX_SAMPLE_EVENTS:],
            recommendation=self.recommendation,
            context={k: v for k, v in context.items() if v is not None},
        )


def register_rule(cls: R) -> R:
    """Class decorator adding a rule to the global registry."""
    if not cls.rule_id or not cls.name:
        raise SentinelError(f"Rule {cls.__name__} must define rule_id and name")
    if cls.rule_id in _RULE_REGISTRY:
        raise SentinelError(f"Duplicate rule_id: {cls.rule_id}")
    _RULE_REGISTRY[cls.rule_id] = cls
    return cls


def available_rules() -> dict[str, type[Rule]]:
    """Return a copy of the rule registry."""
    return dict(_RULE_REGISTRY)
