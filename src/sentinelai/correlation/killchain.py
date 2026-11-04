"""MITRE ATT&CK kill-chain ordering helpers used by incident correlation."""

from __future__ import annotations

from collections.abc import Sequence

from sentinelai.core.models import Alert

#: Canonical tactic order, earliest stage first.
KILL_CHAIN: tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)

#: Label for alerts without any recognised tactic.
UNCLASSIFIED = "Unclassified"


def _normalize(tactic: str) -> str:
    text = tactic.replace("_", " ").replace("-", " ").replace("&", " and ")
    return " ".join(text.lower().split())


_INDEX: dict[str, int] = {_normalize(name): i for i, name in enumerate(KILL_CHAIN)}


def stage_index(tactic: str) -> int:
    """Kill-chain position of ``tactic`` (case-insensitive); -1 when unknown."""
    if not isinstance(tactic, str):
        return -1
    return _INDEX.get(_normalize(tactic), -1)


def primary_tactic(alert: Alert) -> str:
    """Tactic of ``alert`` that is furthest along the kill chain."""
    best = -1
    for tactic in alert.mitre_tactics or []:
        best = max(best, stage_index(tactic))
    return KILL_CHAIN[best] if best >= 0 else UNCLASSIFIED


def chain_bonus(stages: Sequence[str], stage_bonus: float, max_bonus: float) -> float:
    """Score bonus for progression through several distinct kill-chain stages."""
    known = {stage_index(s) for s in stages}
    known.discard(-1)
    if len(known) <= 1:
        return 0.0
    return float(min(max_bonus, stage_bonus * (len(known) - 1)))
