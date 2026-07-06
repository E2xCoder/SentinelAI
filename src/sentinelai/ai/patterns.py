"""Attack-pattern recognition across correlated alerts.

Single alerts describe isolated behaviors; this module looks at the
whole alert set of a run and names the multi-stage attack narratives it
finds (e.g. brute force followed by a successful login from the same
source). Patterns are declarative: a new narrative is one more entry in
``_PATTERNS``, no engine changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from sentinelai.core.models import Alert


@dataclass(slots=True)
class AttackPattern:
    """A recognized multi-alert attack narrative."""

    name: str
    description: str
    alerts: list[Alert]
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "confidence": self.confidence,
            "alert_ids": [a.id for a in self.alerts],
            "rules": sorted({a.rule_id for a in self.alerts}),
        }


def _by_ip(alerts: list[Alert]) -> dict[str, list[Alert]]:
    grouped: dict[str, list[Alert]] = {}
    for alert in alerts:
        if alert.ip:
            grouped.setdefault(alert.ip, []).append(alert)
    return grouped


def _sequence_pattern(
    first_rules: frozenset[str],
    then_rules: frozenset[str],
    name: str,
    description: str,
    confidence: float,
) -> Callable[[list[Alert]], list[AttackPattern]]:
    """Build a matcher for '<rule set A> then <rule set B> from same IP'."""

    def match(alerts: list[Alert]) -> list[AttackPattern]:
        found: list[AttackPattern] = []
        for ip, group in _by_ip(alerts).items():
            ordered = sorted(group, key=lambda a: a.first_seen)
            stage_one = [a for a in ordered if a.rule_id in first_rules]
            stage_two = [a for a in ordered if a.rule_id in then_rules]
            if not stage_one or not stage_two:
                continue
            chains = [
                (a, b)
                for a in stage_one
                for b in stage_two
                if b.last_seen >= a.first_seen
            ]
            if not chains:
                continue
            unique: dict[int, Alert] = {}
            for first, second in chains:
                unique[id(first)] = first
                unique[id(second)] = second
            involved = sorted(unique.values(), key=lambda a: a.first_seen)
            found.append(
                AttackPattern(
                    name=name,
                    description=description.format(ip=ip),
                    alerts=involved,
                    confidence=confidence,
                )
            )
        return found

    return match


_BRUTE = frozenset({"R001", "R002", "R003", "R004", "R006"})
_ACCESS = frozenset({"R005", "R007", "R032"})
_PERSIST = frozenset({"R020", "R040", "R041", "R042"})
_RECON = frozenset({"R030"})
_EVASION = frozenset({"R050", "R051"})
_C2 = frozenset({"R031"})

_PATTERNS: list[Callable[[list[Alert]], list[AttackPattern]]] = [
    _sequence_pattern(
        _BRUTE,
        _ACCESS,
        "Successful intrusion after brute force",
        "Source {ip} brute-forced credentials and subsequently achieved a "
        "successful or suspicious login — the attack likely succeeded.",
        0.9,
    ),
    _sequence_pattern(
        _RECON,
        _BRUTE,
        "Reconnaissance followed by credential attack",
        "Source {ip} scanned for open ports and then launched credential "
        "attacks against discovered services.",
        0.8,
    ),
    _sequence_pattern(
        _BRUTE | _ACCESS,
        _PERSIST,
        "Persistence after account compromise",
        "After credential activity from {ip}, persistence mechanisms "
        "(accounts, cron jobs, SSH keys or autostarts) were established.",
        0.85,
    ),
    _sequence_pattern(
        _ACCESS | _BRUTE,
        _EVASION,
        "Defense evasion after access",
        "Following access-related activity from {ip}, security services or "
        "firewall rules were tampered with to weaken defenses.",
        0.8,
    ),
    _sequence_pattern(
        _ACCESS | _PERSIST,
        _C2,
        "Command-and-control establishment",
        "Activity from {ip} culminated in reverse-shell indicators — an "
        "interactive attacker channel is likely open.",
        0.95,
    ),
]


class AttackPatternRecognizer:
    """Runs every registered narrative matcher over a set of alerts."""

    def __init__(
        self,
        patterns: list[Callable[[list[Alert]], list[AttackPattern]]] | None = None,
    ) -> None:
        self._patterns = patterns or list(_PATTERNS)

    def recognize(self, alerts: list[Alert]) -> list[AttackPattern]:
        """Return all recognized attack narratives, strongest first."""
        found: list[AttackPattern] = []
        for matcher in self._patterns:
            found.extend(matcher(alerts))
        found.sort(key=lambda p: p.confidence, reverse=True)
        for pattern in found:
            for alert in pattern.alerts:
                if alert.ai is not None and pattern.name not in alert.ai.patterns:
                    alert.ai.patterns.append(pattern.name)
        return found
