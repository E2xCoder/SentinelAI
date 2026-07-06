"""Isolation Forest anomaly model (scikit-learn backed)."""

from __future__ import annotations

from sentinelai.ai.base import register_model
from sentinelai.core.exceptions import AIError

try:  # scikit-learn is an optional extra: sentinelai[ai]
    import numpy as _np
    from sklearn.ensemble import IsolationForest as _SkIsolationForest

    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    SKLEARN_AVAILABLE = False


class IsolationForestModel:
    """Unsupervised outlier detection with normalized 0..1 scores."""

    name = "isolation_forest"

    def __init__(self, contamination: float) -> None:
        if not SKLEARN_AVAILABLE:
            raise AIError(
                "scikit-learn is not installed. Install the AI extra with: "
                "pip install 'sentinelai[ai]'"
            )
        self._contamination = contamination

    def fit_score(self, matrix: list[list[float]]) -> list[float]:
        """Fit on the batch and return one anomaly score per event.

        Scores are min-max normalized from scikit-learn's decision
        function, where lower decision values mean more anomalous, onto
        0..1 with 1.0 = most anomalous in the batch.
        """
        if not matrix:
            return []
        data = _np.asarray(matrix, dtype=float)
        forest = _SkIsolationForest(
            n_estimators=200,
            contamination=self._contamination,
            random_state=42,
        )
        forest.fit(data)
        decision = forest.decision_function(data)
        low, high = float(decision.min()), float(decision.max())
        if high - low < 1e-12:
            return [0.0] * len(matrix)
        normalized = (high - decision) / (high - low)
        return [float(v) for v in normalized]


register_model("isolation_forest", IsolationForestModel)
