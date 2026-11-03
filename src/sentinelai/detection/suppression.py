"""Analyst-approved alert suppression.

A :class:`SuppressionMatcher` decides whether a freshly raised alert is
covered by an active, time-boxed suppression from the configuration.

Safety invariant: alerts of severity ``NEVER_SUPPRESS_SEVERITY`` are never
matched, whatever the configuration says.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import datetime, timezone

from sentinelai.config.models import Suppression
from sentinelai.core.models import Alert
from sentinelai.tuning.models import NEVER_SUPPRESS_SEVERITY
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("detection.suppression")

_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _aware(value: datetime) -> datetime:
    """Treat naive datetimes as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class SuppressionMatcher:
    """Matches alerts against the suppressions that are active at ``now``.

    ``now`` may be a fixed datetime or a clock callable; expiry is evaluated
    on every match so long-running processes never use a stale suppression.
    """

    def __init__(
        self, suppressions: list[Suppression], now: datetime | Callable[[], datetime]
    ) -> None:
        self._now = now
        self._active: list[tuple[Suppression, _IPNetwork | None]] = []
        for entry in suppressions:
            network: _IPNetwork | None = None
            if entry.ip is not None:
                try:
                    network = ipaddress.ip_network(entry.ip, strict=False)
                except ValueError:
                    _LOGGER.debug("Dropping suppression for %s: bad ip %r", entry.rule, entry.ip)
                    continue
            self._active.append((entry, network))

    def _current_time(self) -> datetime:
        value = self._now() if callable(self._now) else self._now
        return _aware(value)

    def __len__(self) -> int:
        current = self._current_time()
        return sum(1 for entry, _ in self._active if _aware(entry.expires) > current)

    def match(self, alert: Alert) -> Suppression | None:
        """Return the first active suppression covering ``alert``, if any."""
        return self.match_fields(alert.rule_id, alert.ip, alert.user, alert.severity.value)

    def match_fields(
        self, rule_id: str, ip: str | None, user: str | None, severity: str
    ) -> Suppression | None:
        """Field-level variant of :meth:`match` (used when replaying stored alerts)."""
        try:
            if severity == NEVER_SUPPRESS_SEVERITY:
                return None
            current = self._current_time()
            address = self._parse_ip(ip)
            for entry, network in self._active:
                if entry.rule != rule_id:
                    continue
                if _aware(entry.expires) <= current:
                    continue
                if entry.user is not None and user != entry.user:
                    continue
                if network is not None and (address is None or address not in network):
                    continue
                return entry
        except Exception:  # noqa: BLE001 - suppression must never break detection
            _LOGGER.debug("Suppression match failed for rule %s", rule_id, exc_info=True)
        return None

    @staticmethod
    def _parse_ip(
        value: str | None,
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        if not value:
            return None
        try:
            return ipaddress.ip_address(value.strip())
        except ValueError:
            return None
