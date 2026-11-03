"""Risk engine: combines factor contributions into an explained score."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from sentinelai.core.models import Alert, RiskAssessment, RiskFactor, RiskLevel
from sentinelai.risk.factors import DEFAULT_FACTORS, RiskFactorEvaluator, ScoringContext
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("risk.engine")


class RiskEngine:
    """Scores alerts on a 0-100 scale with a full audit trail.

    The engine is stateful across one analysis run: earlier alerts feed
    the :class:`ScoringContext`, so repeat offenders escalate naturally.
    """

    def __init__(
        self,
        factors: Sequence[RiskFactorEvaluator] | None = None,
        rule_weights: Mapping[str, float] | None = None,
    ) -> None:
        self._factors: list[RiskFactorEvaluator] = list(factors or DEFAULT_FACTORS)
        self._rule_weights: dict[str, float] = dict(rule_weights or {})
        self._ctx = ScoringContext()

    @property
    def rule_weights(self) -> dict[str, float]:
        """Copy of the per-rule analyst weights (rule_id -> multiplier)."""
        return dict(self._rule_weights)

    def add_factor(self, factor: RiskFactorEvaluator) -> None:
        """Plug an additional factor into the engine (used by plugins)."""
        self._factors.append(factor)

    def score(self, alert: Alert) -> RiskAssessment:
        """Assess *alert*, attach the result to it and return it."""
        contributions = []
        for factor in self._factors:
            try:
                result = factor.evaluate(alert, self._ctx)
            except Exception:  # noqa: BLE001 - a factor bug must not block alerting
                _LOGGER.exception(
                    "Risk factor %s crashed", type(factor).__name__
                )
                continue
            if result is not None:
                contributions.append(result)
        raw = sum(c.points for c in contributions)
        total = max(0.0, min(100.0, raw))
        weight = self._rule_weights.get(alert.rule_id)
        if weight is not None and weight != 1.0:
            adjusted = max(0.0, min(100.0, total * weight))
            # Delta is taken against the unclamped sum so that
            # score == clamp(sum(points)) keeps holding for the audit trail.
            contributions.append(
                RiskFactor(
                    "analyst_tuning",
                    adjusted - raw,
                    f"Analyst feedback weight {weight:g} applied to rule {alert.rule_id}",
                )
            )
            total = adjusted
        assessment = RiskAssessment(
            score=total,
            level=RiskLevel.from_score(total),
            factors=contributions,
        )
        alert.risk = assessment
        self._ctx.record(alert)
        return assessment

    def reset(self) -> None:
        """Clear cross-alert state (used between analysis runs)."""
        self._ctx = ScoringContext()
