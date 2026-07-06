"""Risk engine: combines factor contributions into an explained score."""

from __future__ import annotations

from collections.abc import Sequence

from sentinelai.core.models import Alert, RiskAssessment, RiskLevel
from sentinelai.risk.factors import DEFAULT_FACTORS, RiskFactorEvaluator, ScoringContext
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("risk.engine")


class RiskEngine:
    """Scores alerts on a 0-100 scale with a full audit trail.

    The engine is stateful across one analysis run: earlier alerts feed
    the :class:`ScoringContext`, so repeat offenders escalate naturally.
    """

    def __init__(self, factors: Sequence[RiskFactorEvaluator] | None = None) -> None:
        self._factors: list[RiskFactorEvaluator] = list(factors or DEFAULT_FACTORS)
        self._ctx = ScoringContext()

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
        total = max(0.0, min(100.0, sum(c.points for c in contributions)))
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
