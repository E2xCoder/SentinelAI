"""AI model framework: protocol and registry for anomaly models.

New models plug in by implementing :class:`AnomalyModel` and calling
:func:`register_model` — the engine and CLI find them by name, so no
existing code changes when a model is added.
"""

from __future__ import annotations

from typing import Callable, Protocol

from sentinelai.core.exceptions import AIError


class AnomalyModel(Protocol):
    """Interface for unsupervised anomaly scorers.

    ``fit_score`` trains on the batch and returns one score per row in
    the range 0..1 where higher means more anomalous.
    """

    name: str

    def fit_score(self, matrix: list[list[float]]) -> list[float]:
        """Fit on *matrix* and return normalized anomaly scores."""
        ...


_MODEL_FACTORIES: dict[str, Callable[[float], AnomalyModel]] = {}


def register_model(name: str, factory: Callable[[float], AnomalyModel]) -> None:
    """Register an anomaly-model factory under *name*.

    The factory receives the configured contamination rate.
    """
    if name in _MODEL_FACTORIES:
        raise AIError(f"Duplicate AI model name: {name!r}")
    _MODEL_FACTORIES[name] = factory


def create_model(name: str, contamination: float) -> AnomalyModel:
    """Instantiate a registered model by name."""
    try:
        factory = _MODEL_FACTORIES[name]
    except KeyError:
        known = ", ".join(sorted(_MODEL_FACTORIES)) or "none"
        raise AIError(f"Unknown AI model {name!r}. Registered models: {known}") from None
    return factory(contamination)


def available_models() -> list[str]:
    """Names of all registered anomaly models."""
    return sorted(_MODEL_FACTORIES)
