"""Replay of stored, analyst-labelled alerts against a configuration.

Decides, from the alert snapshot saved at labelling time, whether an alert
would still be raised (threshold + suppressions) and how loud it would be
(stored risk score times the per-rule weight).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sentinelai.config.models import SentinelConfig
from sentinelai.core.store import FeedbackEntry
from sentinelai.detection.suppression import SuppressionMatcher
from sentinelai.tuning.feedback import evidence_value
from sentinelai.tuning.models import NEVER_SUPPRESS_SEVERITY, THRESHOLD_SPECS
from sentinelai.tuning.policy import rule_severity

#: Risk score at or above which an alert counts as "loud" (analyst-visible).
LOUD_SCORE = 40.0


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _stored_score(snapshot: Any) -> float:
    if not isinstance(snapshot, dict):
        return 0.0
    risk = snapshot.get("risk")
    if not isinstance(risk, dict):
        return 0.0
    value = risk.get("score")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value)


class ReplayContext:
    """Evaluates stored alerts under one configuration."""

    def __init__(self, config: SentinelConfig, now: datetime) -> None:
        self._config = config
        self._matcher = SuppressionMatcher(config.detection.parsed_suppressions(), now)

    def would_alert(self, entry: FeedbackEntry) -> bool:
        """True if the alert would still be raised under this configuration."""
        snapshot = entry.snapshot if isinstance(entry.snapshot, dict) else {}
        spec = THRESHOLD_SPECS.get(entry.rule_id)
        if spec is not None:
            observed = evidence_value(snapshot, spec)
            threshold = getattr(self._config.detection, spec.field)
            if observed is not None and observed < threshold:
                return False
        # A snapshot without a severity is treated as critical: when in doubt it
        # must count as "still alerts", never as suppressible.
        severity = _text(snapshot.get("severity")) or NEVER_SUPPRESS_SEVERITY
        # The registered rule severity is authoritative too: a tampered or stale
        # snapshot must not make a critical rule suppressible.
        if rule_severity(entry.rule_id) == NEVER_SUPPRESS_SEVERITY:
            severity = NEVER_SUPPRESS_SEVERITY
        suppression = self._matcher.match_fields(
            entry.rule_id, _text(snapshot.get("ip")), _text(snapshot.get("user")), severity
        )
        return suppression is None

    def threshold_unverifiable(self, entry: FeedbackEntry) -> bool:
        """True if the rule is threshold-tunable but the alert carries no replayable evidence."""
        spec = THRESHOLD_SPECS.get(entry.rule_id)
        if spec is None:
            return False
        snapshot = entry.snapshot if isinstance(entry.snapshot, dict) else {}
        return evidence_value(snapshot, spec) is None

    def score(self, entry: FeedbackEntry) -> float:
        """Stored risk score scaled by the configured rule weight, clamped to 0..100."""
        weight = self._config.risk.rule_weights.get(entry.rule_id, 1.0)
        return max(0.0, min(100.0, _stored_score(entry.snapshot) * weight))

    def alerts_loudly(self, entry: FeedbackEntry) -> bool:
        """True if the alert would be raised and reach :data:`LOUD_SCORE`."""
        return self.would_alert(entry) and self.score(entry) >= LOUD_SCORE
