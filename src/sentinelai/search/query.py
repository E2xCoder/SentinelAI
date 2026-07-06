"""Event search and filtering.

A :class:`EventQuery` is a composable set of predicates applied lazily
to an event stream, so searching a multi-gigabyte log stays streaming.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sentinelai.core.exceptions import SentinelError
from sentinelai.core.models import EventCategory, EventType, LogEvent, Severity
from sentinelai.utils.timeparse import parse_iso_timestamp

_FAILED_LOGIN_TYPES = frozenset(
    {EventType.AUTH_FAILURE, EventType.INVALID_USER, EventType.SUDO_FAILURE}
)


@dataclass(slots=True)
class EventQuery:
    """Declarative event filter; unset fields match everything."""

    ip: str | None = None
    user: str | None = None
    event_type: EventType | None = None
    category: EventCategory | None = None
    min_severity: Severity | None = None
    since: datetime | None = None
    until: datetime | None = None
    text: str | None = None
    failed_logins_only: bool = False
    today_only: bool = False

    def matches(self, event: LogEvent) -> bool:
        """Return True when *event* satisfies every set predicate."""
        if self.ip is not None and event.ip != self.ip:
            return False
        if self.user is not None and event.user != self.user:
            return False
        if self.event_type is not None and event.event_type is not self.event_type:
            return False
        if self.category is not None and event.category is not self.category:
            return False
        if (
            self.min_severity is not None
            and event.severity.weight < self.min_severity.weight
        ):
            return False
        if self.since is not None and event.timestamp < self.since:
            return False
        if self.until is not None and event.timestamp > self.until:
            return False
        if self.text is not None and self.text.lower() not in event.message.lower():
            return False
        if self.failed_logins_only and event.event_type not in _FAILED_LOGIN_TYPES:
            return False
        if self.today_only:
            today = datetime.now(timezone.utc).date()
            if event.timestamp.astimezone(timezone.utc).date() != today:
                return False
        return True

    def filter(self, events: Iterable[LogEvent]) -> Iterator[LogEvent]:
        """Lazily yield matching events."""
        return (event for event in events if self.matches(event))


def parse_date_bound(value: str, end_of_day: bool = False) -> datetime:
    """Parse a CLI date/datetime bound like ``2024-01-07`` or ISO-8601.

    Bare dates expand to the start (or end) of that UTC day.
    """
    parsed = parse_iso_timestamp(value)
    if parsed is None:
        raise SentinelError(
            f"Invalid date {value!r}; use YYYY-MM-DD or an ISO-8601 timestamp"
        )
    if len(value.strip()) == 10 and end_of_day:
        parsed = parsed + timedelta(days=1) - timedelta(microseconds=1)
    return parsed


def build_query(
    ip: str | None = None,
    user: str | None = None,
    event_type: str | None = None,
    category: str | None = None,
    min_severity: str | None = None,
    since: str | None = None,
    until: str | None = None,
    text: str | None = None,
    failed_only: bool = False,
    today: bool = False,
) -> EventQuery:
    """Build a query from raw CLI strings, validating enum values."""
    def _enum(cls: type, value: str, label: str) -> object:
        try:
            return cls(value.lower())
        except ValueError:
            valid = ", ".join(item.value for item in cls)  # type: ignore[attr-defined]
            raise SentinelError(f"Invalid {label} {value!r}; valid: {valid}") from None

    return EventQuery(
        ip=ip,
        user=user,
        event_type=_enum(EventType, event_type, "event type") if event_type else None,  # type: ignore[arg-type]
        category=_enum(EventCategory, category, "category") if category else None,  # type: ignore[arg-type]
        min_severity=_enum(Severity, min_severity, "severity") if min_severity else None,  # type: ignore[arg-type]
        since=parse_date_bound(since) if since else None,
        until=parse_date_bound(until, end_of_day=True) if until else None,
        text=text,
        failed_logins_only=failed_only,
        today_only=today,
    )
