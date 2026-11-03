"""The analysis pipeline: parse → detect → enrich → score → respond.

This is the composition root of the platform. Every subsystem is
injected, so tests and plugins can substitute any stage.
"""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from sentinelai.ai.behavior import BehaviorAnalyzer
from sentinelai.ai.engine import AIEngine
from sentinelai.ai.patterns import AttackPattern
from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import AIError
from sentinelai.core.models import Alert, LogEvent
from sentinelai.core.store import AlertStore
from sentinelai.detection.engine import RuleEngine
from sentinelai.firewall.adapters import create_firewall
from sentinelai.firewall.responder import AutoResponder
from sentinelai.intel.aggregator import ThreatIntelAggregator
from sentinelai.risk.engine import RiskEngine
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("core.pipeline")

#: Upper bound on events buffered for batch anomaly detection.
_AI_BUFFER_LIMIT = 100_000


@dataclass(slots=True)
class ScanStatistics:
    """Aggregate statistics of one analysis run."""

    total_events: int = 0
    categories: Counter[str] = field(default_factory=Counter)
    severities: Counter[str] = field(default_factory=Counter)
    unique_ips: set[str] = field(default_factory=set)
    unique_users: set[str] = field(default_factory=set)
    unique_hosts: set[str] = field(default_factory=set)
    first_event: datetime | None = None
    last_event: datetime | None = None
    suppressed: Counter[str] = field(default_factory=Counter)

    def observe(self, event: LogEvent) -> None:
        self.total_events += 1
        self.categories[event.category.value] += 1
        self.severities[event.severity.value] += 1
        if event.ip:
            self.unique_ips.add(event.ip)
        if event.user:
            self.unique_users.add(event.user)
        if event.hostname:
            self.unique_hosts.add(event.hostname)
        if self.first_event is None or event.timestamp < self.first_event:
            self.first_event = event.timestamp
        if self.last_event is None or event.timestamp > self.last_event:
            self.last_event = event.timestamp


@dataclass(slots=True)
class ScanResult:
    """Everything produced by one analysis run."""

    alerts: list[Alert]
    patterns: list[AttackPattern]
    statistics: ScanStatistics
    anomaly_count: int = 0
    ai_used: bool = False
    behavior: BehaviorAnalyzer | None = None


class AnalysisPipeline:
    """Wires detection, intel, risk, AI and response together."""

    def __init__(self, config: SentinelConfig) -> None:
        self._config = config
        state_dir = config.resolve_state_dir()
        self.store = AlertStore(state_dir / "alerts.db")
        self.rule_engine = RuleEngine(config.detection)
        self.risk_engine = RiskEngine(rule_weights=config.risk.rule_weights)
        self.intel = ThreatIntelAggregator(config.intel, state_dir)
        self.ai = AIEngine(config.ai)
        self.firewall = create_firewall(config.firewall)
        self.responder = AutoResponder(config.response, self.firewall)

    def process_event(self, event: LogEvent) -> list[Alert]:
        """Run one event through detection and full alert enrichment.

        This is the real-time path used by live monitoring; scans use it
        too, adding a batch anomaly pass afterwards.
        """
        self.ai.observe(event)
        alerts = self.rule_engine.process(event)
        for alert in alerts:
            self._enrich_and_persist(alert)
        return alerts

    def _enrich_and_persist(self, alert: Alert) -> None:
        if alert.ip and self.intel.enabled:
            alert.intel = self.intel.lookup(alert.ip)
        self.risk_engine.score(alert)
        self.store.save(alert)
        self.responder.consider(alert)
        if alert.context.get("response"):
            self.store.update(alert)

    def run_scan(self, events: Iterable[LogEvent], use_ai: bool = True) -> ScanResult:
        """Analyze a finite event stream and correlate the results.

        Events stream through detection one at a time; only a bounded
        buffer is retained for the batch anomaly pass, so arbitrarily
        large logs stay memory-safe.
        """
        stats = ScanStatistics()
        alerts: list[Alert] = []
        buffer: deque[LogEvent] = deque(maxlen=_AI_BUFFER_LIMIT)
        for event in events:
            stats.observe(event)
            buffer.append(event)
            alerts.extend(self.process_event(event))

        anomaly_count = 0
        ai_used = False
        if use_ai and self.ai.anomaly_detection_available:
            try:
                anomalies = self.ai.detect_anomalies(list(buffer))
                ai_used = True
                anomaly_count = len(anomalies)
                for ai_alert in self.ai.build_anomaly_alerts(anomalies):
                    self._enrich_and_persist(ai_alert)
                    alerts.append(ai_alert)
            except AIError as exc:
                _LOGGER.warning("Anomaly detection skipped: %s", exc)

        patterns = self.ai.recognize_patterns(alerts)
        for alert in alerts:
            if alert.ai and alert.ai.patterns and alert.id is not None:
                self.store.update(alert)
        stats.suppressed = Counter(self.rule_engine.suppressed_by_rule)
        _LOGGER.debug(
            "Scan complete: %d events, %d alerts, %d patterns",
            stats.total_events,
            len(alerts),
            len(patterns),
        )
        return ScanResult(
            alerts=alerts,
            patterns=patterns,
            statistics=stats,
            anomaly_count=anomaly_count,
            ai_used=ai_used,
            behavior=self.ai.behavior,
        )

    def close(self) -> None:
        """Release database handles."""
        self.store.close()
        self.intel.close()
