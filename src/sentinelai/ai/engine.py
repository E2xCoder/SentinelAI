"""AI engine facade: anomaly detection, behavior, patterns, explanation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sentinelai.ai import isolation_forest  # noqa: F401 - registers the default model
from sentinelai.ai.base import create_model
from sentinelai.ai.behavior import BehaviorAnalyzer
from sentinelai.ai.explain import AlertExplainer
from sentinelai.ai.features import FeatureExtractor
from sentinelai.ai.patterns import AttackPattern, AttackPatternRecognizer
from sentinelai.ai.triage_cache import TriageCache
from sentinelai.ai.triage_engine import TriageEngine
from sentinelai.config.models import AIConfig
from sentinelai.core.exceptions import AIError, StorageError
from sentinelai.core.models import (
    AIInsight,
    Alert,
    EventCategory,
    LogEvent,
    Severity,
)
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("ai.engine")

#: Rule id used for alerts raised by the anomaly model itself.
ANOMALY_RULE_ID = "AI001"


class AIEngine:
    """Coordinates all AI capabilities behind one small interface."""

    def __init__(self, config: AIConfig, *, state_dir: Path | None = None) -> None:
        self._config = config
        self._extractor = FeatureExtractor()
        self._behavior = BehaviorAnalyzer()
        self._patterns = AttackPatternRecognizer()
        self._triage_cache: TriageCache | None = None
        triage: TriageEngine | None = None
        llm = config.llm
        if state_dir is not None and llm.enabled and llm.cache_ttl_seconds > 0:
            try:
                self._triage_cache = TriageCache(
                    state_dir / "triage_cache.db", llm.cache_ttl_seconds
                )
            except StorageError as exc:
                _LOGGER.warning("Triage cache disabled: %s", exc)
            else:
                try:
                    self._triage_cache.purge_expired()
                except StorageError as exc:
                    _LOGGER.warning("Triage cache purge failed: %s", exc)
                triage = TriageEngine(llm, cache=self._triage_cache)
        self._triage = triage
        self._explainer = AlertExplainer(llm, triage)
        self._available = config.enabled
        if self._available:
            try:
                # Fail fast if the configured model cannot be built.
                create_model(config.model, config.contamination)
            except AIError as exc:
                _LOGGER.warning("AI anomaly detection disabled: %s", exc)
                self._available = False

    @property
    def anomaly_detection_available(self) -> bool:
        """True when the anomaly model can actually run."""
        return self._available

    @property
    def behavior(self) -> BehaviorAnalyzer:
        """The behavior analyzer (fed by :meth:`observe`)."""
        return self._behavior

    def observe(self, event: LogEvent) -> None:
        """Feed one event into behavior profiling."""
        self._behavior.observe(event)

    def detect_anomalies(self, events: list[LogEvent]) -> list[tuple[LogEvent, float]]:
        """Score a batch of events; return those above the alert threshold.

        Requires at least ``ai.min_events`` events — anomaly detection on
        a handful of samples produces noise, not signal.
        """
        if not self._available or len(events) < self._config.min_events:
            return []
        try:
            model = create_model(self._config.model, self._config.contamination)
            scores = model.fit_score(self._extractor.extract(events))
        except AIError:
            raise
        except Exception as exc:  # noqa: BLE001 - model internals must not crash a scan
            _LOGGER.exception("Anomaly model failed")
            raise AIError(f"Anomaly detection failed: {exc}") from exc
        threshold = self._config.anomaly_alert_threshold
        return [
            (event, score)
            for event, score in zip(events, scores, strict=True)
            if score >= threshold
        ]

    def build_anomaly_alerts(
        self, anomalies: list[tuple[LogEvent, float]]
    ) -> list[Alert]:
        """Convert anomalous events into structured AI alerts.

        Anomalies are grouped by source IP (or user, or host) so a burst
        of related outliers becomes one alert.
        """
        groups: dict[str, list[tuple[LogEvent, float]]] = {}
        for event, score in anomalies:
            key = event.ip or event.user or event.hostname or "unknown"
            groups.setdefault(key, []).append((event, score))
        alerts: list[Alert] = []
        for subject, items in groups.items():
            items.sort(key=lambda pair: pair[0].timestamp)
            events = [event for event, _ in items]
            top_score = max(score for _, score in items)
            first = events[0]
            alerts.append(
                Alert(
                    rule_id=ANOMALY_RULE_ID,
                    rule_name="AI Behavioral Anomaly",
                    title=f"Anomalous behavior involving {subject}",
                    description=(
                        f"The anomaly model ({self._config.model}) flagged "
                        f"{len(events)} event(s) involving {subject} as "
                        f"statistical outliers (max score {top_score:.2f}). "
                        f"The behavior deviates from the baseline of this log set."
                    ),
                    category=first.category
                    if first.category is not EventCategory.UNKNOWN
                    else EventCategory.SYSTEM,
                    severity=Severity.WARNING,
                    first_seen=events[0].timestamp,
                    last_seen=events[-1].timestamp,
                    ip=first.ip,
                    user=first.user,
                    hostname=first.hostname,
                    event_count=len(events),
                    sample_events=events[-5:],
                    recommendation=(
                        "Review the sampled events; anomalies without a "
                        "matching rule may indicate novel attacker behavior."
                    ),
                    ai=AIInsight(
                        anomaly_score=top_score,
                        is_anomaly=True,
                        model=self._config.model,
                    ),
                    created_at=datetime.now(timezone.utc),
                )
            )
        return alerts

    def recognize_patterns(self, alerts: list[Alert]) -> list[AttackPattern]:
        """Find multi-stage attack narratives across *alerts*."""
        for alert in alerts:
            if alert.ai is None:
                alert.ai = AIInsight(model=self._config.model)
        return self._patterns.recognize(alerts)

    def explain(self, alert: Alert) -> AIInsight:
        """Attach (and return) a natural-language explanation for *alert*."""
        explanation, source, confidence, outcome = self._explainer.explain_full(alert)
        if alert.ai is None:
            alert.ai = AIInsight(model=self._config.model)
        alert.ai.explanation = explanation
        alert.ai.explanation_source = source
        alert.ai.confidence = confidence
        if outcome is not None:
            alert.ai.triage = {
                **outcome.result.to_dict(),
                "source": outcome.source,
                "language": outcome.language,
                "valid_llm": outcome.valid_llm,
                "cached": outcome.cached,
                "rejection": outcome.rejection,
            }
        return alert.ai

    def close(self) -> None:
        """Release the triage engine and cache (safe to call repeatedly)."""
        self._explainer.close()
        triage, self._triage = self._triage, None
        if triage is not None:
            triage.close()
        cache, self._triage_cache = self._triage_cache, None
        if cache is not None:
            try:
                cache.close()
            except StorageError as exc:
                _LOGGER.warning("Triage cache close failed: %s", exc)
