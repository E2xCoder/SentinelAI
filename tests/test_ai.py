"""Tests for the AI engine: anomaly detection, behavior, patterns, explain."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinelai.ai.engine import AIEngine
from sentinelai.ai.features import FeatureExtractor
from sentinelai.ai.isolation_forest import SKLEARN_AVAILABLE
from sentinelai.config.models import AIConfig
from sentinelai.core.models import Alert, EventCategory, EventType, Severity
from tests.conftest import make_event

pytestmark = pytest.mark.skipif(
    not SKLEARN_AVAILABLE, reason="scikit-learn (the AI extra) is not installed"
)

BASE = datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)


def _normal_login(i: int):
    """A routine daytime login from the internal network."""
    return make_event(
        base=BASE,
        offset=i * 30,
        event_type=EventType.AUTH_SUCCESS,
        category=EventCategory.AUTHENTICATION,
        severity=Severity.INFO,
        ip=f"10.0.0.{i % 20 + 2}",
        user="alice",
    )


class TestFeatureExtractor:
    def test_vector_shape(self) -> None:
        events = [_normal_login(i) for i in range(5)]
        matrix = FeatureExtractor().extract(events)
        assert len(matrix) == 5
        assert all(len(row) == 12 for row in matrix)

    def test_empty(self) -> None:
        assert FeatureExtractor().extract([]) == []


class TestAnomalyDetection:
    def test_flags_the_outlier(self) -> None:
        engine = AIEngine(AIConfig(min_events=50, anomaly_alert_threshold=0.6))
        events = [_normal_login(i) for i in range(80)]
        # One clear outlier: 3am root login from an external IP.
        outlier = make_event(
            base=BASE.replace(hour=3),
            event_type=EventType.ROOT_LOGIN,
            category=EventCategory.AUTHENTICATION,
            severity=Severity.WARNING,
            ip="198.51.100.7",
            user="root",
        )
        events.append(outlier)
        anomalies = engine.detect_anomalies(events)
        flagged_ips = {e.ip for e, _ in anomalies}
        assert "198.51.100.7" in flagged_ips

    def test_below_min_events_returns_nothing(self) -> None:
        engine = AIEngine(AIConfig(min_events=50))
        assert engine.detect_anomalies([_normal_login(i) for i in range(10)]) == []

    def test_build_anomaly_alerts_groups_by_subject(self) -> None:
        engine = AIEngine(AIConfig(min_events=50, anomaly_alert_threshold=0.6))
        events = [_normal_login(i) for i in range(80)]
        events.append(
            make_event(
                base=BASE.replace(hour=3), event_type=EventType.ROOT_LOGIN,
                ip="198.51.100.7", user="root", severity=Severity.WARNING,
            )
        )
        anomalies = engine.detect_anomalies(events)
        alerts = engine.build_anomaly_alerts(anomalies)
        assert all(a.rule_id == "AI001" for a in alerts)
        assert all(a.ai is not None and a.ai.is_anomaly for a in alerts)


class TestBehaviorAnalysis:
    def test_profiles_track_failures(self) -> None:
        engine = AIEngine(AIConfig())
        for _ in range(5):
            engine.observe(
                make_event(
                    event_type=EventType.AUTH_FAILURE, ip="203.0.113.5", user="root"
                )
            )
        profile = engine.behavior.ip_profile("203.0.113.5")
        assert profile is not None
        assert profile.failure_count == 5
        assert profile.failure_ratio == 1.0


class TestPatternRecognition:
    def test_brute_force_then_login(self) -> None:
        engine = AIEngine(AIConfig())
        brute = Alert(
            rule_id="R001", rule_name="SSH Brute Force", title="bf",
            description="", category=EventCategory.AUTHENTICATION,
            severity=Severity.ERROR, first_seen=BASE, last_seen=BASE + timedelta(minutes=1),
            ip="203.0.113.5",
        )
        login = Alert(
            rule_id="R005", rule_name="Root Login", title="root",
            description="", category=EventCategory.AUTHENTICATION,
            severity=Severity.WARNING, first_seen=BASE + timedelta(minutes=2),
            last_seen=BASE + timedelta(minutes=2), ip="203.0.113.5",
        )
        patterns = engine.recognize_patterns([brute, login])
        assert any("brute force" in p.name.lower() for p in patterns)


class TestExplanation:
    def test_template_fallback_always_works(self) -> None:
        # LLM disabled by default -> deterministic template explanation.
        engine = AIEngine(AIConfig())
        alert = Alert(
            rule_id="R031", rule_name="Reverse Shell Indicator", title="rev shell",
            description="reverse shell payload observed",
            category=EventCategory.NETWORK, severity=Severity.CRITICAL,
            first_seen=BASE, last_seen=BASE, mitre_techniques=["T1059.004"],
            recommendation="Isolate the host.",
        )
        insight = engine.explain(alert)
        assert insight.explanation is not None
        assert insight.explanation_source == "template"
        assert "WHY SUSPICIOUS" in insight.explanation
        assert 0.0 <= (insight.confidence or 0) <= 1.0
