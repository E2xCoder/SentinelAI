"""Tests for the risk engine: scoring, explanations, level assignment."""

from __future__ import annotations

from datetime import timedelta

from sentinelai.core.models import (
    AIInsight,
    Alert,
    EventCategory,
    IPReputation,
    RiskLevel,
    Severity,
)
from sentinelai.risk.engine import RiskEngine
from tests.conftest import BASE_TS


def make_alert(
    *,
    severity: Severity = Severity.WARNING,
    event_count: int = 1,
    ip: str | None = "203.0.113.5",
    user: str | None = "root",
    category: EventCategory = EventCategory.AUTHENTICATION,
    span_seconds: float = 0.0,
    **kw,
) -> Alert:
    return Alert(
        rule_id="RTEST",
        rule_name="Test Rule",
        title="test",
        description="test",
        category=category,
        severity=severity,
        first_seen=BASE_TS,
        last_seen=BASE_TS + timedelta(seconds=span_seconds),
        ip=ip,
        user=user,
        event_count=event_count,
        **kw,
    )


class TestRiskLevelMapping:
    def test_boundaries(self) -> None:
        assert RiskLevel.from_score(0) is RiskLevel.INFORMATIONAL
        assert RiskLevel.from_score(14) is RiskLevel.INFORMATIONAL
        assert RiskLevel.from_score(15) is RiskLevel.LOW
        assert RiskLevel.from_score(40) is RiskLevel.MEDIUM
        assert RiskLevel.from_score(65) is RiskLevel.HIGH
        assert RiskLevel.from_score(85) is RiskLevel.CRITICAL
        assert RiskLevel.from_score(100) is RiskLevel.CRITICAL


class TestScoring:
    def test_severity_drives_base_score(self) -> None:
        engine = RiskEngine()
        low = engine.score(make_alert(severity=Severity.NOTICE, user=None, ip=None))
        engine.reset()
        high = engine.score(make_alert(severity=Severity.CRITICAL, user=None, ip=None))
        assert high.score > low.score

    def test_score_bounded_0_100(self) -> None:
        engine = RiskEngine()
        alert = make_alert(
            severity=Severity.CRITICAL, event_count=500, span_seconds=1.0,
            intel=IPReputation(ip="203.0.113.5", malicious=True, score=100,
                               sources={"abuseipdb": {"score": 100}}),
            ai=AIInsight(anomaly_score=1.0, is_anomaly=True, model="isolation_forest"),
        )
        assessment = engine.score(alert)
        assert 0.0 <= assessment.score <= 100.0

    def test_every_factor_has_reason(self) -> None:
        engine = RiskEngine()
        assessment = engine.score(make_alert(severity=Severity.ERROR, event_count=10))
        assert assessment.factors
        assert all(f.reason for f in assessment.factors)
        assert all(f.name for f in assessment.factors)

    def test_explanation_is_multiline(self) -> None:
        engine = RiskEngine()
        assessment = engine.score(make_alert(severity=Severity.ERROR, event_count=5))
        text = assessment.explain()
        assert "Risk score" in text
        assert "\n" in text

    def test_malicious_intel_raises_score(self) -> None:
        clean = RiskEngine().score(make_alert(severity=Severity.WARNING))
        with_intel = RiskEngine().score(
            make_alert(
                severity=Severity.WARNING,
                intel=IPReputation(
                    ip="203.0.113.5", malicious=True, score=90,
                    sources={"abuseipdb": {"score": 90}},
                ),
            )
        )
        assert with_intel.score > clean.score
        assert any(f.name == "threat_intelligence" for f in with_intel.factors)

    def test_privileged_target_factor(self) -> None:
        engine = RiskEngine()
        assessment = engine.score(make_alert(severity=Severity.WARNING, user="root"))
        assert any(f.name == "privileged_target" for f in assessment.factors)

    def test_recurrence_escalates(self) -> None:
        engine = RiskEngine()
        first = engine.score(make_alert(severity=Severity.WARNING, ip="203.0.113.5"))
        second = engine.score(make_alert(severity=Severity.WARNING, ip="203.0.113.5"))
        # The second alert for the same IP should include a recurrence factor.
        assert any(f.name == "repeated_behavior" for f in second.factors)
        assert second.score >= first.score

    def test_assessment_attached_to_alert(self) -> None:
        engine = RiskEngine()
        alert = make_alert(severity=Severity.ERROR)
        assessment = engine.score(alert)
        assert alert.risk is assessment
        assert alert.risk.level is RiskLevel.from_score(assessment.score)
