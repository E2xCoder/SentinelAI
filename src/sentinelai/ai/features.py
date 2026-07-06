"""Feature extraction: turns log events into numeric vectors.

The feature set is deliberately behavioral rather than content-based:
time-of-day, severity, event class, source frequency. That lets the
anomaly model flag *unusual behavior* (a burst of failures at 03:00
from one IP) instead of memorizing message strings.
"""

from __future__ import annotations

import math
from collections import Counter

from sentinelai.core.models import EventCategory, EventType, LogEvent

#: Failure-ish event types (used for the failure-flag feature).
_FAILURE_TYPES = frozenset(
    {
        EventType.AUTH_FAILURE,
        EventType.INVALID_USER,
        EventType.SUDO_FAILURE,
        EventType.SERVICE_FAILED,
        EventType.FIREWALL_BLOCK,
        EventType.BAN,
    }
)

_CATEGORY_INDEX = {category: i for i, category in enumerate(EventCategory)}
_TYPE_INDEX = {etype: i for i, etype in enumerate(EventType)}

FEATURE_NAMES: tuple[str, ...] = (
    "hour_sin",
    "hour_cos",
    "weekday",
    "severity",
    "category_idx",
    "event_type_idx",
    "is_failure",
    "has_ip",
    "port_norm",
    "ip_burst",
    "user_burst",
    "message_len",
)


class FeatureExtractor:
    """Builds a feature matrix for a batch of events.

    Frequency features (``ip_burst``, ``user_burst``) are computed over
    the batch itself, so the extractor is fitted per analysis run.
    """

    def extract(self, events: list[LogEvent]) -> list[list[float]]:
        """Return one feature vector per event."""
        ip_counts: Counter[str] = Counter(e.ip for e in events if e.ip)
        user_counts: Counter[str] = Counter(e.user for e in events if e.user)
        total = max(len(events), 1)
        matrix: list[list[float]] = []
        for event in events:
            hour_angle = 2.0 * math.pi * event.timestamp.hour / 24.0
            matrix.append(
                [
                    math.sin(hour_angle),
                    math.cos(hour_angle),
                    float(event.timestamp.weekday()),
                    float(event.severity.weight),
                    float(_CATEGORY_INDEX.get(event.category, 0)),
                    float(_TYPE_INDEX.get(event.event_type, 0)),
                    1.0 if event.event_type in _FAILURE_TYPES else 0.0,
                    1.0 if event.ip else 0.0,
                    (event.port or 0) / 65535.0,
                    ip_counts.get(event.ip or "", 0) / total,
                    user_counts.get(event.user or "", 0) / total,
                    min(len(event.message), 500) / 500.0,
                ]
            )
        return matrix
