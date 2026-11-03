"""Shared contracts and hard limits of the human-approved tuning loop.

The loop never changes code or model weights. It can only propose small,
bounded edits to a machine-managed *overlay* (``<state_dir>/tuning.yaml``)
and every edit must pass a gate (frozen benchmark + the analyst's own
feedback) before ``sentinel tune --apply`` writes it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinelai.core.store import FeedbackEntry

# --- proposal kinds -------------------------------------------------------
KIND_THRESHOLD = "threshold"
KIND_SUPPRESSION = "suppression"
KIND_RISK_WEIGHT = "risk_weight"
ALLOWED_KINDS = (KIND_THRESHOLD, KIND_SUPPRESSION, KIND_RISK_WEIGHT)

# --- hard limits (anti-poisoning). Enforced in code, not in config. -------
#: A threshold may move within [default * MIN, default * MAX] without --force.
MIN_THRESHOLD_FACTOR = 0.5
MAX_THRESHOLD_FACTOR = 2.0
#: Suppressions per rule (existing + new). Never overridable.
MAX_SUPPRESSIONS_PER_RULE = 5
DEFAULT_SUPPRESSION_DAYS = 30
#: Never overridable, even with --force.
MAX_SUPPRESSION_DAYS = 90
#: Narrowest allowed source network (a /24 or smaller IPv4, /64 or smaller IPv6).
MIN_IPV4_PREFIX = 24
MIN_IPV6_PREFIX = 64
#: Per-rule risk multiplier bounds. Never overridable.
MIN_RISK_WEIGHT = 0.5
MAX_RISK_WEIGHT = 1.5
#: Rules of this severity need --force to be suppressed. A suppression is
#: always scoped to a user and/or a small network, so it can never disable a
#: rule outright; only critical rules are treated as too important to touch
#: without an explicit override.
FORCE_SEVERITIES = ("critical",)
#: An ALERT with this severity is never suppressed by the detection engine,
#: whatever the configuration says.
NEVER_SUPPRESS_SEVERITY = "critical"

# --- proposal generation heuristics ---------------------------------------
#: Minimum labelled alerts for a rule before anything is proposed.
MIN_LABELLED_PER_RULE = 3
MIN_FALSE_POSITIVES = 3
#: Share of labelled alerts that must be false positives.
MIN_FP_RATIO = 0.6
DEFAULT_RISK_WEIGHT_STEP = 0.8


@dataclass(frozen=True, slots=True)
class ThresholdSpec:
    """How a count-style rule threshold maps onto alert evidence.

    ``evidence`` names a key of ``alert.context``; when ``evidence_is_len``
    is true the value is a list and its length is the observed count.
    """

    rule_id: str
    field: str
    evidence: str
    evidence_is_len: bool = False


#: Rules whose firing threshold can be tuned from feedback evidence.
THRESHOLD_SPECS: dict[str, ThresholdSpec] = {
    "R001": ThresholdSpec("R001", "brute_force_attempts", "attempts"),
    "R002": ThresholdSpec("R002", "password_spray_users", "distinct_users", True),
    "R003": ThresholdSpec("R003", "credential_stuffing_attempts", "attempts"),
    "R004": ThresholdSpec("R004", "repeated_failure_attempts", "attempts"),
    "R006": ThresholdSpec("R006", "impossible_frequency_attempts", "attempts"),
    "R030": ThresholdSpec("R030", "port_scan_ports", "distinct_ports"),
}


@dataclass(frozen=True, slots=True)
class Proposal:
    """One proposed, reviewable change.

    ``patch`` is an overlay fragment:
    ``{"detection": {"brute_force_attempts": 8}}``,
    ``{"detection": {"suppressions": [{...}]}}`` (appended to existing ones) or
    ``{"risk": {"rule_weights": {"R001": 0.8}}}``.
    """

    id: str
    kind: str
    rule_id: str
    patch: dict[str, Any]
    rationale: str
    evidence_alert_ids: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "rule_id": self.rule_id,
            "patch": self.patch,
            "rationale": self.rationale,
            "evidence_alert_ids": list(self.evidence_alert_ids),
        }


@dataclass(slots=True)
class RuleFeedback:
    """Analyst labels collected for one rule."""

    rule_id: str
    tp: list[FeedbackEntry] = field(default_factory=list)
    fp: list[FeedbackEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.tp) + len(self.fp)

    @property
    def fp_ratio(self) -> float:
        return len(self.fp) / self.total if self.total else 0.0


@dataclass(slots=True)
class GateResult:
    """Outcome of gating one proposal (or a set applied together)."""

    proposal_ids: tuple[str, ...]
    accepted: bool
    #: Human-readable reasons: why it was rejected, or what was verified.
    reasons: list[str] = field(default_factory=list)
    benchmark_recall_before: float | None = None
    benchmark_recall_after: float | None = None
    #: Benchmark scenarios that passed before and fail with the candidate.
    benchmark_regressions: list[str] = field(default_factory=list)
    #: Analyst-labelled false positives that still alert (before -> after).
    fp_before: int = 0
    fp_after: int = 0
    #: Analyst-labelled true positives that would stop alerting.
    tp_lost: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_ids": list(self.proposal_ids),
            "accepted": self.accepted,
            "reasons": list(self.reasons),
            "benchmark_recall_before": self.benchmark_recall_before,
            "benchmark_recall_after": self.benchmark_recall_after,
            "benchmark_regressions": list(self.benchmark_regressions),
            "fp_before": self.fp_before,
            "fp_after": self.fp_after,
            "tp_lost": self.tp_lost,
        }
