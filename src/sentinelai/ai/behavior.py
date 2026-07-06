"""Behavior analysis: activity profiles per user and per source IP."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from sentinelai.core.models import EventType, LogEvent

_FAILURES = frozenset(
    {EventType.AUTH_FAILURE, EventType.INVALID_USER, EventType.SUDO_FAILURE}
)
_SUCCESSES = frozenset({EventType.AUTH_SUCCESS, EventType.ROOT_LOGIN})


@dataclass(slots=True)
class BehaviorProfile:
    """Aggregated behavior of one subject (a user or a source IP)."""

    subject: str
    kind: str  # "user" | "ip"
    event_count: int = 0
    failure_count: int = 0
    success_count: int = 0
    categories: Counter = field(default_factory=Counter)
    active_hours: Counter = field(default_factory=Counter)
    peers: Counter = field(default_factory=Counter)  # IPs for users, users for IPs

    @property
    def failure_ratio(self) -> float:
        attempts = self.failure_count + self.success_count
        return self.failure_count / attempts if attempts else 0.0

    def summarize(self) -> dict[str, Any]:
        """JSON-friendly summary used in reports and LLM prompts."""
        return {
            "subject": self.subject,
            "kind": self.kind,
            "events": self.event_count,
            "failures": self.failure_count,
            "successes": self.success_count,
            "failure_ratio": round(self.failure_ratio, 3),
            "top_categories": dict(self.categories.most_common(3)),
            "top_hours_utc": [hour for hour, _ in self.active_hours.most_common(3)],
            "top_peers": [peer for peer, _ in self.peers.most_common(5)],
        }


class BehaviorAnalyzer:
    """Builds behavior profiles from an event stream."""

    def __init__(self) -> None:
        self._users: dict[str, BehaviorProfile] = {}
        self._ips: dict[str, BehaviorProfile] = {}

    def observe(self, event: LogEvent) -> None:
        """Fold one event into the profiles."""
        if event.user:
            profile = self._users.setdefault(
                event.user, BehaviorProfile(event.user, "user")
            )
            self._update(profile, event, peer=event.ip)
        if event.ip:
            profile = self._ips.setdefault(event.ip, BehaviorProfile(event.ip, "ip"))
            self._update(profile, event, peer=event.user)

    @staticmethod
    def _update(profile: BehaviorProfile, event: LogEvent, peer: str | None) -> None:
        profile.event_count += 1
        profile.categories[event.category.value] += 1
        profile.active_hours[event.timestamp.hour] += 1
        if event.event_type in _FAILURES:
            profile.failure_count += 1
        elif event.event_type in _SUCCESSES:
            profile.success_count += 1
        if peer:
            profile.peers[peer] += 1

    def user_profile(self, user: str) -> BehaviorProfile | None:
        return self._users.get(user)

    def ip_profile(self, ip: str) -> BehaviorProfile | None:
        return self._ips.get(ip)

    def noisiest_ips(self, limit: int = 10) -> list[BehaviorProfile]:
        """Source IPs sorted by activity volume."""
        return sorted(
            self._ips.values(), key=lambda p: p.event_count, reverse=True
        )[:limit]

    def most_targeted_users(self, limit: int = 10) -> list[BehaviorProfile]:
        """Accounts sorted by failed-authentication pressure."""
        return sorted(
            self._users.values(), key=lambda p: p.failure_count, reverse=True
        )[:limit]
