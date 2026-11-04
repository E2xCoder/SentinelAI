"""Tests for alert correlation: kill chain helpers, engine linking, summaries and Mermaid."""

from __future__ import annotations

import dataclasses
import random
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

import sentinelai.detection.rules  # noqa: F401  (registers the built-in rules)
from sentinelai.config.models import CorrelationConfig
from sentinelai.core.models import (
    Alert,
    Incident,
    RiskAssessment,
    RiskLevel,
    Severity,
    TimelineEntry,
)
from sentinelai.correlation.engine import correlate
from sentinelai.correlation.killchain import (
    KILL_CHAIN,
    UNCLASSIFIED,
    chain_bonus,
    primary_tactic,
    stage_index,
)
from sentinelai.correlation.summary import (
    MAX_LABEL,
    MAX_MERMAID_NODES,
    MAX_SAMPLE_EVENTS,
    build_summary,
    build_title,
    incident_as_alert,
    render_mermaid,
)
from sentinelai.detection.base import available_rules
from sentinelai.risk.engine import RiskEngine
from tests.conftest import make_event

BASE = datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)
IP_A = "203.0.113.55"
IP_B = "198.51.100.7"
IP_C = "192.0.2.9"
WINDOW = 60

_ENGINE = RiskEngine()


# -- helpers ---------------------------------------------------------------


def _alert(
    rule_id: str = "R001",
    *,
    at: float = 0.0,
    span: float = 0.0,
    ip: str | None = None,
    user: str | None = None,
    host: str | None = "web01",
    score: float | None = None,
    aid: int | None = None,
    tactics: list[str] | None = None,
    title: str | None = None,
    base: datetime = BASE,
) -> Alert:
    """Build a real alert via ``Rule.make_alert``; optionally pin timing, tactics and score."""
    rule = available_rules()[rule_id]()
    kwargs: dict[str, Any] = {"ip": ip, "user": user, "hostname": host, "base": base}
    first = make_event(offset=at, **kwargs)
    events = [first] if span == 0 else [first, make_event(offset=at + span, **kwargs)]
    alert = rule.make_alert(first, title or f"{rule_id} test", "synthetic alert", events=events)
    if tactics is not None:
        alert.mitre_tactics = list(tactics)
    if score is None:
        _ENGINE.score(alert)
    else:
        alert.risk = RiskAssessment(score=score, level=RiskLevel.from_score(score))
    alert.id = aid
    return alert


def _cfg(**overrides: Any) -> CorrelationConfig:
    return CorrelationConfig(**overrides)


def _snapshot(incident: Incident) -> dict[str, Any]:
    """Incident as a dict without the wall-clock ``created_at``."""
    data = dataclasses.asdict(incident)
    data.pop("created_at")
    return data


def _incident(**overrides: Any) -> Incident:
    values: dict[str, Any] = {
        "title": "t",
        "summary": "s",
        "first_seen": BASE,
        "last_seen": BASE + timedelta(minutes=5),
        "score": 70.0,
        "level": RiskLevel.HIGH,
        "stages": [],
        "timeline": [],
        "ips": [],
        "users": [],
        "hosts": [],
        "alert_ids": [],
        "rule_ids": [],
        "mitre_techniques": [],
        "alert_count": 2,
    }
    values.update(overrides)
    return Incident(**values)


def _entry(title: str = "step", *, offset: int = 0, **overrides: Any) -> TimelineEntry:
    values: dict[str, Any] = {
        "timestamp": BASE + timedelta(seconds=offset),
        "alert_id": offset + 1,
        "rule_id": "R001",
        "title": title,
        "tactic": "Credential Access",
        "risk_level": "high",
        "risk_score": 70.0,
    }
    values.update(overrides)
    return TimelineEntry(**values)


# -- killchain -------------------------------------------------------------


class TestStageIndex:
    @pytest.mark.parametrize("position, name", list(enumerate(KILL_CHAIN)))
    def test_canonical_name_returns_its_position(self, position: int, name: str) -> None:
        assert stage_index(name) == position

    @pytest.mark.parametrize(
        "text",
        ["credential access", "CREDENTIAL ACCESS", "Credential_Access", "credential-access"],
    )
    def test_case_and_separator_variants_match(self, text: str) -> None:
        assert stage_index(text) == KILL_CHAIN.index("Credential Access")

    def test_ampersand_alias_matches_command_and_control(self) -> None:
        assert stage_index("command & control") == KILL_CHAIN.index("Command and Control")

    def test_extra_whitespace_is_collapsed(self) -> None:
        assert stage_index("  privilege    escalation ") == KILL_CHAIN.index("Privilege Escalation")

    @pytest.mark.parametrize("value", ["Not A Tactic", "", "   ", UNCLASSIFIED])
    def test_unknown_tactic_returns_minus_one(self, value: str) -> None:
        assert stage_index(value) == -1

    @pytest.mark.parametrize("value", [None, 7, ["Persistence"], b"Persistence"])
    def test_non_string_returns_minus_one(self, value: Any) -> None:
        assert stage_index(value) == -1


class TestPrimaryTactic:
    def test_furthest_stage_wins(self) -> None:
        alert = _alert(tactics=["Initial Access", "Privilege Escalation"])
        assert primary_tactic(alert) == "Privilege Escalation"

    def test_order_of_tactics_does_not_matter(self) -> None:
        alert = _alert(tactics=["Privilege Escalation", "Initial Access"])
        assert primary_tactic(alert) == "Privilege Escalation"

    def test_unknown_tactics_are_skipped(self) -> None:
        alert = _alert(tactics=["Bogus", "persistence"])
        assert primary_tactic(alert) == "Persistence"

    def test_only_unknown_tactics_is_unclassified(self) -> None:
        assert primary_tactic(_alert(tactics=["Bogus", ""])) == UNCLASSIFIED

    def test_no_tactics_is_unclassified(self) -> None:
        assert primary_tactic(_alert(tactics=[])) == UNCLASSIFIED

    def test_none_tactics_is_unclassified(self) -> None:
        alert = _alert()
        alert.mitre_tactics = None  # type: ignore[assignment]
        assert primary_tactic(alert) == UNCLASSIFIED


class TestChainBonus:
    def test_no_stages_gives_zero(self) -> None:
        assert chain_bonus([], 5.0, 20.0) == 0.0

    def test_single_stage_gives_zero(self) -> None:
        assert chain_bonus(["Persistence"], 5.0, 20.0) == 0.0

    def test_two_stages_give_one_step(self) -> None:
        assert chain_bonus(["Credential Access", "Persistence"], 5.0, 20.0) == 5.0

    def test_bonus_grows_per_extra_stage(self) -> None:
        stages = ["Initial Access", "Execution", "Persistence", "Impact"]
        assert chain_bonus(stages, 4.0, 100.0) == 12.0

    def test_bonus_is_capped_at_max_bonus(self) -> None:
        assert chain_bonus(list(KILL_CHAIN), 5.0, 20.0) == 20.0

    def test_case_duplicates_count_once(self) -> None:
        assert chain_bonus(["Persistence", "persistence", "PERSISTENCE"], 5.0, 20.0) == 0.0

    def test_unknown_stages_are_ignored(self) -> None:
        assert chain_bonus(["Persistence", UNCLASSIFIED, "Bogus"], 5.0, 20.0) == 0.0

    def test_zero_max_bonus_disables_bonus(self) -> None:
        assert chain_bonus(["Initial Access", "Impact"], 5.0, 0.0) == 0.0

    def test_result_is_float(self) -> None:
        assert isinstance(chain_bonus(["Initial Access", "Impact"], 5, 20), float)


# -- correlate: linking ----------------------------------------------------


class TestLinking:
    def test_same_ip_links_alerts_with_different_users(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, user="alice", aid=1),
            _alert("R005", at=10, ip=IP_A, user="bob", aid=2),
        ]
        incidents = correlate(alerts, _cfg())
        assert len(incidents) == 1
        assert incidents[0].alert_ids == [1, 2]

    def test_same_user_links_alerts_from_different_ips(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, user="root", aid=1),
            _alert("R040", at=10, ip=IP_B, user="root", aid=2),
        ]
        assert len(correlate(alerts, _cfg())) == 1

    def test_shared_host_alone_does_not_link_by_default(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, user="alice", host="web01", aid=1),
            _alert("R040", at=10, ip=IP_B, user="bob", host="web01", aid=2),
        ]
        assert correlate(alerts, _cfg()) == []

    def test_shared_host_links_when_enabled(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, user="alice", host="web01", aid=1),
            _alert("R040", at=10, ip=IP_B, user="bob", host="web01", aid=2),
        ]
        incidents = correlate(alerts, _cfg(link_by=["ip", "user", "host"]))
        assert len(incidents) == 1
        assert incidents[0].hosts == ["web01"]

    def test_hostname_alias_links_like_host(self) -> None:
        alerts = [_alert(at=0, ip=IP_A, user="a", aid=1), _alert(at=5, ip=IP_B, user="b", aid=2)]
        assert len(correlate(alerts, _cfg(link_by=["hostname"]))) == 1

    def test_different_values_do_not_link(self) -> None:
        alerts = [
            _alert(at=0, ip=IP_A, user="alice", host="web01"),
            _alert(at=5, ip=IP_B, user="bob", host="db01"),
        ]
        assert correlate(alerts, _cfg(link_by=["ip", "user", "host"])) == []

    def test_entity_match_ignores_case_and_whitespace(self) -> None:
        alerts = [
            _alert(at=0, user="Alice", ip=None, aid=1),
            _alert("R005", at=5, user="  alice ", ip=None, aid=2),
        ]
        assert len(correlate(alerts, _cfg())) == 1

    def test_missing_entities_never_link(self) -> None:
        alerts = [
            _alert(at=0, ip=None, user=None, host=None),
            _alert("R005", at=5, ip=None, user=None, host=None),
        ]
        assert correlate(alerts, _cfg(link_by=["ip", "user", "host"])) == []

    def test_transitive_chain_forms_one_incident(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, user="u1", aid=1),
            _alert("R005", at=10, ip=IP_A, user="u2", aid=2),
            _alert("R040", at=20, ip=IP_B, user="u2", aid=3),
        ]
        incidents = correlate(alerts, _cfg())
        assert len(incidents) == 1
        assert incidents[0].alert_ids == [1, 2, 3]
        assert incidents[0].ips == sorted([IP_A, IP_B])

    def test_unrelated_attackers_form_two_incidents(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, user="a1", aid=1, score=50.0),
            _alert("R005", at=5, ip=IP_A, user="a2", aid=2, score=50.0),
            _alert("R001", at=1, ip=IP_B, user="b1", aid=3, score=80.0),
            _alert("R005", at=6, ip=IP_B, user="b2", aid=4, score=80.0),
        ]
        incidents = correlate(alerts, _cfg())
        assert [i.alert_ids for i in incidents] == [[3, 4], [1, 2]]  # highest score first
        assert incidents[0].ips == [IP_B]
        assert incidents[1].ips == [IP_A]

    def test_empty_input_returns_no_incidents(self) -> None:
        assert correlate([], _cfg()) == []

    @pytest.mark.parametrize("link_by", [[], ["bogus"], ["port", "rule"]])
    def test_no_valid_link_key_means_no_incidents(self, link_by: list[str]) -> None:
        alerts = [_alert(at=0, ip=IP_A, user="x"), _alert("R005", at=5, ip=IP_A, user="x")]
        assert correlate(alerts, _cfg(link_by=link_by)) == []

    def test_link_by_ip_only_ignores_shared_user(self) -> None:
        alerts = [
            _alert(at=0, ip=IP_A, user="root"),
            _alert("R005", at=5, ip=IP_B, user="root"),
        ]
        assert correlate(alerts, _cfg(link_by=["ip"])) == []

    def test_link_by_user_only_ignores_shared_ip(self) -> None:
        alerts = [
            _alert(at=0, ip=IP_A, user="alice"),
            _alert("R005", at=5, ip=IP_A, user="bob"),
        ]
        assert correlate(alerts, _cfg(link_by=["user"])) == []

    def test_link_by_names_are_case_and_space_insensitive(self) -> None:
        alerts = [_alert(at=0, ip=IP_A, user="a"), _alert("R005", at=5, ip=IP_A, user="b")]
        assert len(correlate(alerts, _cfg(link_by=[" IP "]))) == 1


# -- correlate: time window ------------------------------------------------


class TestTimeWindow:
    def test_gap_exactly_window_links(self) -> None:
        alerts = [_alert(at=0, ip=IP_A), _alert("R005", at=WINDOW, ip=IP_A)]
        assert len(correlate(alerts, _cfg(window_seconds=WINDOW))) == 1

    def test_gap_one_second_over_window_does_not_link(self) -> None:
        alerts = [_alert(at=0, ip=IP_A), _alert("R005", at=WINDOW + 1, ip=IP_A)]
        assert correlate(alerts, _cfg(window_seconds=WINDOW)) == []

    def test_gap_is_measured_from_interval_end(self) -> None:
        alerts = [_alert(at=0, span=30, ip=IP_A), _alert("R005", at=30 + WINDOW, ip=IP_A)]
        assert len(correlate(alerts, _cfg(window_seconds=WINDOW))) == 1

    def test_gap_from_interval_end_plus_one_does_not_link(self) -> None:
        alerts = [_alert(at=0, span=30, ip=IP_A), _alert("R005", at=31 + WINDOW, ip=IP_A)]
        assert correlate(alerts, _cfg(window_seconds=WINDOW)) == []

    def test_overlapping_intervals_link(self) -> None:
        alerts = [_alert(at=0, span=100, ip=IP_A), _alert("R005", at=50, span=100, ip=IP_A)]
        assert len(correlate(alerts, _cfg(window_seconds=1))) == 1

    def test_long_interval_bridges_later_alerts(self) -> None:
        alerts = [
            _alert("R001", at=0, span=1000, ip=IP_A, aid=1),
            _alert("R005", at=10, ip=IP_A, aid=2),
            _alert("R040", at=500, ip=IP_A, aid=3),
        ]
        incidents = correlate(alerts, _cfg(window_seconds=WINDOW))
        assert [i.alert_ids for i in incidents] == [[1, 2, 3]]

    def test_chain_of_small_gaps_spans_more_than_window(self) -> None:
        alerts = [_alert("R001", at=i * WINDOW, ip=IP_A, aid=i + 1) for i in range(5)]
        incidents = correlate(alerts, _cfg(window_seconds=WINDOW))
        assert len(incidents) == 1
        assert incidents[0].alert_count == 5

    def test_distant_bursts_for_same_ip_become_separate_incidents(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, aid=1),
            _alert("R005", at=5, ip=IP_A, aid=2),
            _alert("R001", at=10_000, ip=IP_A, aid=3),
            _alert("R005", at=10_005, ip=IP_A, aid=4),
        ]
        incidents = correlate(alerts, _cfg(window_seconds=WINDOW))
        assert sorted(i.alert_ids for i in incidents) == [[1, 2], [3, 4]]

    def test_default_window_is_one_hour(self) -> None:
        alerts = [_alert(at=0, ip=IP_A), _alert("R005", at=3600, ip=IP_A)]
        assert len(correlate(alerts, _cfg())) == 1
        alerts = [_alert(at=0, ip=IP_A), _alert("R005", at=3601, ip=IP_A)]
        assert correlate(alerts, _cfg()) == []

    def test_naive_datetimes_are_treated_as_utc(self) -> None:
        naive = datetime(2026, 1, 7, 12, 0, 0)
        alerts = [
            _alert("R001", at=0, ip=IP_A, base=naive, aid=1),
            _alert("R005", at=0, ip=IP_A, base=BASE, aid=2),
        ]
        incidents = correlate(alerts, _cfg(window_seconds=WINDOW))
        assert len(incidents) == 1
        assert incidents[0].first_seen == BASE
        assert incidents[0].first_seen.tzinfo is not None

    def test_aware_offsets_are_normalised_to_utc(self) -> None:
        plus_two = datetime(2026, 1, 7, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))
        alerts = [
            _alert("R001", at=0, ip=IP_A, base=plus_two, aid=1),
            _alert("R005", at=0, ip=IP_A, base=BASE, aid=2),
        ]
        incident = correlate(alerts, _cfg(window_seconds=1))[0]
        assert incident.first_seen == BASE
        assert incident.last_seen == BASE

    def test_last_seen_before_first_seen_does_not_raise(self) -> None:
        odd = _alert("R001", at=0, ip=IP_A, aid=1)
        odd.last_seen = odd.first_seen - timedelta(hours=1)
        incidents = correlate([odd, _alert("R005", at=5, ip=IP_A, aid=2)], _cfg())
        assert len(incidents) == 1


# -- correlate: thresholds, timeline and score ----------------------------


class TestIncidentBuilding:
    def test_singleton_is_not_an_incident(self) -> None:
        assert correlate([_alert(ip=IP_A)], _cfg()) == []

    def test_min_alerts_three_rejects_a_pair(self) -> None:
        alerts = [_alert(at=0, ip=IP_A), _alert("R005", at=5, ip=IP_A)]
        assert correlate(alerts, _cfg(min_alerts=3)) == []

    def test_min_alerts_three_accepts_a_triple(self) -> None:
        alerts = [_alert(at=i, ip=IP_A) for i in range(3)]
        assert len(correlate(alerts, _cfg(min_alerts=3))) == 1

    def test_min_alerts_below_one_is_clamped_to_one(self) -> None:
        incidents = correlate([_alert(ip=IP_A, aid=1)], _cfg(min_alerts=0))
        assert len(incidents) == 1
        assert incidents[0].alert_count == 1

    def test_storm_of_identical_alerts_collapses_to_one_timeline_entry(self) -> None:
        alerts = [_alert("R001", at=i, ip=IP_A, user="root", aid=i + 1) for i in range(200)]
        incident = correlate(alerts, _cfg())[0]
        assert incident.alert_count == 200
        assert len(incident.alert_ids) == 200
        assert len(incident.timeline) == 1
        assert incident.timeline[0].count == 200
        assert incident.timeline[0].timestamp == BASE
        assert incident.rule_ids == ["R001"]

    def test_timeline_entry_keeps_highest_score_of_group(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, user="root", score=30.0, aid=1),
            _alert("R001", at=5, ip=IP_A, user="root", score=80.0, aid=2),
        ]
        entry = correlate(alerts, _cfg())[0].timeline[0]
        assert entry.risk_score == 80.0
        assert entry.risk_level == RiskLevel.HIGH
        assert entry.alert_id == 1  # first alert of the group
        assert entry.count == 2

    def test_different_users_do_not_collapse_in_timeline(self) -> None:
        alerts = [_alert("R001", at=i, ip=IP_A, user=f"u{i}", aid=i + 1) for i in range(3)]
        incident = correlate(alerts, _cfg())[0]
        assert [e.user for e in incident.timeline] == ["u0", "u1", "u2"]

    def test_max_timeline_truncates_entries_but_not_alert_count(self) -> None:
        alerts = [_alert("R001", at=i, ip=IP_A, user=f"u{i}", aid=i + 1) for i in range(30)]
        incident = correlate(alerts, _cfg(max_timeline=10))[0]
        assert len(incident.timeline) == 10
        assert incident.alert_count == 30
        assert len(incident.alert_ids) == 30
        assert incident.timeline[0].user == "u0"

    def test_max_timeline_zero_keeps_at_least_one_entry(self) -> None:
        alerts = [_alert("R001", at=i, ip=IP_A, user=f"u{i}") for i in range(4)]
        assert len(correlate(alerts, _cfg(max_timeline=0))[0].timeline) == 1

    def test_timeline_is_chronological(self) -> None:
        alerts = [
            _alert("R040", at=30, ip=IP_A, aid=3),
            _alert("R001", at=0, ip=IP_A, aid=1),
            _alert("R005", at=15, ip=IP_A, aid=2),
        ]
        incident = correlate(alerts, _cfg())[0]
        assert [e.rule_id for e in incident.timeline] == ["R001", "R005", "R040"]
        assert incident.rule_ids == ["R001", "R005", "R040"]

    def test_same_timestamp_orders_by_kill_chain_stage(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, aid=1, tactics=["Credential Access"]),
            _alert("R040", at=0, ip=IP_A, aid=2, tactics=["Persistence"]),
        ]
        incident = correlate(alerts, _cfg())[0]
        assert incident.stages == ["Persistence", "Credential Access"]

    def test_stages_follow_timeline_order_without_duplicates(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, user="a", tactics=["Credential Access"]),
            _alert("R001", at=5, ip=IP_A, user="b", tactics=["Credential Access"]),
            _alert("R040", at=10, ip=IP_A, user="c", tactics=["Persistence"]),
            _alert("R030", at=20, ip=IP_A, user="d", tactics=["Reconnaissance"]),
        ]
        assert correlate(alerts, _cfg())[0].stages == [
            "Credential Access",
            "Persistence",
            "Reconnaissance",
        ]

    def test_entities_are_unique_and_sorted(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, user="zed", host="web02", aid=3),
            _alert("R005", at=5, ip=IP_A, user="amy", host="web01", aid=1),
            _alert("R040", at=9, ip=IP_A, user="zed", host="web01", aid=2),
        ]
        incident = correlate(alerts, _cfg())[0]
        assert incident.ips == [IP_A]
        assert incident.users == ["amy", "zed"]
        assert incident.hosts == ["web01", "web02"]
        assert incident.alert_ids == [1, 2, 3]

    def test_alerts_without_integer_ids_are_still_counted(self) -> None:
        alerts = [_alert(at=0, ip=IP_A, aid=None), _alert("R005", at=5, ip=IP_A, aid=None)]
        incident = correlate(alerts, _cfg())[0]
        assert incident.alert_count == 2
        assert incident.alert_ids == []

    def test_mitre_techniques_are_merged_and_sorted(self) -> None:
        a = _alert("R001", at=0, ip=IP_A)
        b = _alert("R005", at=5, ip=IP_A)
        a.mitre_techniques = ["T1110", "T1078"]
        b.mitre_techniques = ["T1078", "T1053"]
        assert correlate([a, b], _cfg())[0].mitre_techniques == ["T1053", "T1078", "T1110"]

    def test_incident_first_and_last_seen_span_all_alerts(self) -> None:
        alerts = [_alert(at=0, ip=IP_A), _alert("R005", at=20, span=15, ip=IP_A)]
        incident = correlate(alerts, _cfg())[0]
        assert incident.first_seen == BASE
        assert incident.last_seen == BASE + timedelta(seconds=35)


class TestScore:
    def test_single_stage_has_no_bonus(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, score=50.0, tactics=["Credential Access"]),
            _alert("R001", at=5, ip=IP_A, user="x", score=60.0, tactics=["Credential Access"]),
        ]
        incident = correlate(alerts, _cfg())[0]
        assert incident.score == 60.0
        assert incident.level == RiskLevel.MEDIUM

    def test_two_stages_add_one_bonus_step_to_max_score(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, score=50.0, tactics=["Credential Access"]),
            _alert("R040", at=5, ip=IP_A, score=62.0, tactics=["Persistence"]),
        ]
        incident = correlate(alerts, _cfg(stage_bonus=5.0, max_bonus=20.0))[0]
        assert incident.score == 67.0
        assert incident.level == RiskLevel.HIGH

    def test_bonus_is_capped_by_max_bonus(self) -> None:
        names = list(KILL_CHAIN[:6])
        alerts = [
            _alert("R001", at=i * 5, ip=IP_A, user=f"u{i}", score=40.0, tactics=[n])
            for i, n in enumerate(names)
        ]
        incident = correlate(alerts, _cfg(stage_bonus=5.0, max_bonus=12.0))[0]
        assert len(incident.stages) == 6
        assert incident.score == 52.0

    def test_score_is_capped_at_100(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, score=98.0, tactics=["Credential Access"]),
            _alert("R040", at=5, ip=IP_A, score=90.0, tactics=["Persistence"]),
        ]
        incident = correlate(alerts, _cfg())[0]
        assert incident.score == 100.0
        assert incident.level == RiskLevel.CRITICAL

    def test_level_follows_final_score_not_alert_level(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, score=80.0, tactics=["Credential Access"]),
            _alert("R040", at=5, ip=IP_A, score=82.0, tactics=["Persistence"]),
        ]
        incident = correlate(alerts, _cfg())[0]
        assert incident.score == 87.0
        assert incident.level == RiskLevel.CRITICAL

    def test_zero_stage_bonus_leaves_max_score(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, score=50.0, tactics=["Credential Access"]),
            _alert("R040", at=5, ip=IP_A, score=62.0, tactics=["Persistence"]),
        ]
        assert correlate(alerts, _cfg(stage_bonus=0.0))[0].score == 62.0

    def test_score_uses_real_risk_engine_values(self) -> None:
        alerts = [_alert("R001", at=0, ip=IP_A), _alert("R040", at=5, ip=IP_A)]
        top = max(a.risk.score for a in alerts)
        incident = correlate(alerts, _cfg())[0]
        assert incident.score == round(min(100.0, top + 5.0), 1)

    def test_alerts_without_tactics_or_risk_score_zero(self) -> None:
        alerts = [
            _alert("R001", at=0, ip=IP_A, tactics=[], score=0.0),
            _alert("R005", at=5, ip=IP_A, tactics=[], score=0.0),
        ]
        incident = correlate(alerts, _cfg())[0]
        assert incident.score == 0.0
        assert incident.level == RiskLevel.INFORMATIONAL
        assert incident.stages == []
        assert [e.tactic for e in incident.timeline] == [UNCLASSIFIED, UNCLASSIFIED]
        assert "Correlated activity" in incident.title

    def test_missing_risk_object_is_treated_as_zero(self) -> None:
        a = _alert("R001", at=0, ip=IP_A, aid=1, tactics=[])
        b = _alert("R005", at=5, ip=IP_A, aid=2, tactics=[])
        a.risk = None  # type: ignore[assignment]
        b.risk = None  # type: ignore[assignment]
        incident = correlate([a, b], _cfg())[0]
        assert incident.score == 0.0
        assert incident.level == RiskLevel.INFORMATIONAL

    @pytest.mark.parametrize("raw", [float("nan"), float("inf"), -50.0, "high", None])
    def test_garbage_scores_are_clamped_not_raised(self, raw: Any) -> None:
        a = _alert("R001", at=0, ip=IP_A, aid=1, tactics=[])
        b = _alert("R005", at=5, ip=IP_A, aid=2, tactics=[])
        a.risk = RiskAssessment(score=raw)
        b.risk = RiskAssessment(score=0.0)
        incident = correlate([a, b], _cfg())[0]
        assert 0.0 <= incident.score <= 100.0

    def test_score_over_100_on_alert_is_clamped(self) -> None:
        a = _alert("R001", at=0, ip=IP_A, aid=1)
        b = _alert("R005", at=5, ip=IP_A, aid=2)
        a.risk = RiskAssessment(score=250.0, level=RiskLevel.CRITICAL)
        assert correlate([a, b], _cfg())[0].score <= 100.0


# -- correlate: determinism, advisory, scale --------------------------------


def _mixed_alerts() -> list[Alert]:
    rules = ["R001", "R005", "R012", "R040"]
    alerts: list[Alert] = []
    for index in range(40):
        alerts.append(
            _alert(
                rules[index % 4],
                at=(index % 7) * 3,  # many equal timestamps
                ip=(IP_A, IP_B, IP_C)[index % 3],
                user=f"user{index % 5}",
                aid=index + 1,
            )
        )
    return alerts


class TestDeterminismAndAdvisory:
    def test_shuffled_input_gives_identical_incidents(self) -> None:
        alerts = _mixed_alerts()
        expected = [_snapshot(i) for i in correlate(alerts, _cfg())]
        for seed in range(5):
            shuffled = list(alerts)
            random.Random(seed).shuffle(shuffled)
            assert [_snapshot(i) for i in correlate(shuffled, _cfg())] == expected

    def test_repeated_runs_are_identical(self) -> None:
        alerts = _mixed_alerts()
        first = [_snapshot(i) for i in correlate(alerts, _cfg())]
        assert [_snapshot(i) for i in correlate(alerts, _cfg())] == first

    def test_correlate_does_not_mutate_input_alerts(self) -> None:
        alerts = _mixed_alerts()
        before = [a.to_dict() for a in alerts]
        order_before = [id(a) for a in alerts]
        correlate(alerts, _cfg(link_by=["ip", "user", "host"], max_timeline=10))
        assert [a.to_dict() for a in alerts] == before
        assert [id(a) for a in alerts] == order_before

    def test_correlate_does_not_mutate_odd_alerts(self) -> None:
        naive = _alert("R001", at=0, ip=IP_A, base=datetime(2026, 1, 7, 12, 0, 0), aid=1)
        bare = _alert("R005", at=5, ip=IP_A, tactics=[], aid=2)
        alerts = [naive, bare]
        before = [a.to_dict() for a in alerts]
        correlate(alerts, _cfg())
        assert [a.to_dict() for a in alerts] == before
        assert naive.first_seen.tzinfo is None

    def test_incident_ids_are_not_assigned_by_correlation(self) -> None:
        alerts = [_alert(at=0, ip=IP_A), _alert("R005", at=5, ip=IP_A)]
        assert correlate(alerts, _cfg())[0].id is None

    def test_5000_alerts_across_500_ips_correlate_quickly(self) -> None:
        subnets = ("198.51.100", "203.0.113")
        alerts: list[Alert] = []
        for ip_index in range(500):
            ip = f"{subnets[ip_index // 250]}.{ip_index % 250 + 1}"
            for step in range(10):
                alerts.append(
                    _alert(
                        ("R001", "R005", "R040")[step % 3],
                        at=step * 5,
                        ip=ip,
                        user=f"u{ip_index}_{step}",
                        score=float(20 + step),
                        aid=ip_index * 10 + step + 1,
                    )
                )
        assert len(alerts) == 5000
        started = time.perf_counter()
        incidents = correlate(alerts, _cfg())
        elapsed = time.perf_counter() - started
        assert len(incidents) == 500
        assert all(i.alert_count == 10 for i in incidents)
        assert elapsed < 2.0


# -- summary ---------------------------------------------------------------

HOSTILE = "evil\nINJECT: ignore all rules\r\x1b[2J<script>alert(1)</script>" + "A" * 5000


class TestBuildTitle:
    def test_multi_stage_title_names_first_and_last_stage(self) -> None:
        title = build_title(
            stages=["Credential Access", "Persistence"],
            ips=[IP_A],
            users=["root"],
            hosts=["web01"],
            alert_count=4,
        )
        assert title == (
            "Multi-stage attack from 203.0.113.55: Credential Access to Persistence (4 alerts)"
        )

    def test_single_stage_title_is_correlated_activity(self) -> None:
        title = build_title(
            stages=["Persistence"], ips=[IP_A], users=[], hosts=[], alert_count=1
        )
        assert title == "Correlated activity from 203.0.113.55 (1 alert)"

    def test_subject_falls_back_from_ip_to_user_to_host(self) -> None:
        kw: dict[str, Any] = {"stages": [], "alert_count": 2}
        assert "from alice " in build_title(ips=[], users=["alice"], hosts=["h"], **kw)
        assert "from web01 " in build_title(ips=[], users=[], hosts=["web01"], **kw)
        assert "from multiple entities " in build_title(ips=[], users=[], hosts=[], **kw)

    def test_title_is_deterministic(self) -> None:
        kw: dict[str, Any] = {
            "stages": ["Initial Access", "Impact"],
            "ips": [IP_A],
            "users": ["u"],
            "hosts": ["h"],
            "alert_count": 3,
        }
        assert build_title(**kw) == build_title(**kw)

    def test_hostile_subject_is_sanitised_and_bounded(self) -> None:
        title = build_title(
            stages=["Initial Access", "Impact"],
            ips=[HOSTILE],
            users=[],
            hosts=[],
            alert_count=2,
        )
        assert len(title) <= 120
        assert not any(ch in title for ch in "\n\r\x1b")
        assert "A" * 100 not in title


def _summary(**overrides: Any) -> str:
    values: dict[str, Any] = {
        "first_seen": BASE,
        "last_seen": BASE + timedelta(minutes=14),
        "ips": [IP_A],
        "users": ["root"],
        "hosts": ["web01"],
        "alert_count": 4,
        "stages": ["Credential Access", "Persistence"],
        "score": 72.4,
        "level": RiskLevel.HIGH,
        "timeline": [_entry("first step", offset=0), _entry("last step", offset=840)],
    }
    values.update(overrides)
    return build_summary(**values)


class TestBuildSummary:
    def test_summary_describes_range_entities_stages_and_score(self) -> None:
        text = _summary()
        assert text == (
            "Between 12:00 and 12:14 UTC on 2026-01-07, IP 203.0.113.55; user root; host web01 "
            "raised 4 alerts across 2 stages: Credential Access -> Persistence "
            "(score 72, HIGH). First: first step (R001, Credential Access); "
            "Last: last step (R001, Credential Access)."
        )

    def test_summary_is_deterministic(self) -> None:
        assert _summary() == _summary()

    def test_multi_day_range_shows_both_dates(self) -> None:
        text = _summary(last_seen=BASE + timedelta(days=1))
        assert "2026-01-07 12:00 and 2026-01-08 12:00 UTC" in text

    def test_no_stages_says_unmapped(self) -> None:
        assert "with no mapped kill-chain stage" in _summary(stages=[])

    def test_no_entities_say_unidentified(self) -> None:
        text = _summary(ips=[], users=[], hosts=[])
        assert "unidentified entities raised" in text

    def test_long_entity_lists_are_truncated_with_count(self) -> None:
        ips = [f"192.0.2.{n}" for n in range(1, 8)]
        text = _summary(ips=ips)
        assert "IP 192.0.2.1, 192.0.2.2, 192.0.2.3 +4 more" in text
        assert "192.0.2.7" not in text

    def test_empty_timeline_omits_first_last(self) -> None:
        assert "First:" not in _summary(timeline=[])

    def test_naive_datetimes_are_accepted(self) -> None:
        text = _summary(
            first_seen=datetime(2026, 1, 7, 12, 0), last_seen=datetime(2026, 1, 7, 12, 5)
        )
        assert "12:00 and 12:05 UTC" in text

    def test_hostile_text_is_stripped_of_controls_and_bounded(self) -> None:
        text = _summary(
            ips=[HOSTILE],
            users=[HOSTILE],
            hosts=[HOSTILE],
            stages=[HOSTILE, "Persistence"],
            timeline=[_entry(HOSTILE, rule_id=HOSTILE, tactic=HOSTILE), _entry(HOSTILE)],
        )
        assert not any(ch in text for ch in "\n\r\x1b")
        assert "\x1b[2J" not in text
        assert "A" * 150 not in text
        assert len(text) < 2500

    def test_hostile_markup_never_appears_raw_in_summary(self) -> None:
        text = _summary(users=["<script>alert(1)</script>"])
        assert "<script>" not in text


# -- mermaid ---------------------------------------------------------------

_NODE_LINE = re.compile(r'^  ([A-Za-z0-9_]+)\["([^"\[\]]*)"\]$')
_EDGE_LINE = re.compile(r"^  ([A-Za-z0-9_]+) (-->|-\.->) ([A-Za-z0-9_]+)$")

NASTY_STRINGS = [
    'bob"]; click x call alert(1); ["',
    "a]b[c;d",
    "%%{init: {'securityLevel':'loose'}}%%",
    "line1\nline2\ngraph TD\n  x --> y",
    "`backtick` and <script>alert(1)</script>",
    "evil --> a1",
    "x\r\ny\tz",
    "end\n  subgraph pwn",
    "\x1b[2Jcleared",
    "A" * 5000,
    "{{curly}} (paren) #hash &amp; | pipe \\ slash",
]


def _assert_safe_mermaid(text: str) -> tuple[list[str], list[str]]:
    """Check every line against a strict whitelist; return (node labels, node ids)."""
    lines = text.split("\n")
    assert lines[0] == "graph LR"
    assert "%%" not in text
    assert "{" not in text
    assert not any(ch in text for ch in "\r\x1b\x00`<;")
    labels: list[str] = []
    ids: list[str] = []
    for line in lines[1:]:
        node = _NODE_LINE.match(line)
        if node:
            ids.append(node.group(1))
            labels.append(node.group(2))
            continue
        assert _EDGE_LINE.match(line), f"unexpected Mermaid line: {line!r}"
    assert len(ids) == len(set(ids))
    assert len(ids) <= MAX_MERMAID_NODES
    assert all(len(label) <= MAX_LABEL for label in labels)
    assert all(re.fullmatch(r"[A-Za-z0-9_]+", node_id) for node_id in ids)
    for line in lines[1:]:
        edge = _EDGE_LINE.match(line)
        if edge:
            assert edge.group(1) in ids
            assert edge.group(3) in ids
    return labels, ids


class TestRenderMermaid:
    def test_clean_incident_renders_nodes_and_edges(self) -> None:
        incident = _incident(
            ips=[IP_A],
            users=["root"],
            timeline=[
                _entry("SSH brute force", offset=0, ip=IP_A, user="root"),
                _entry("Cron persistence", offset=60, ip=IP_A, user="root", count=3),
            ],
        )
        text = render_mermaid(incident)
        labels, _ids = _assert_safe_mermaid(text)
        assert "IP 203.0.113.55" in labels
        assert "user root" in labels
        assert "12:00:00 SSH brute force" in labels
        assert "12:01:00 Cron persistence x3" in labels
        assert "  a0 --> a1" in text.split("\n")
        assert "  ip0 -.-> a0" in text.split("\n")

    def test_empty_incident_renders_header_only(self) -> None:
        assert render_mermaid(_incident()) == "graph LR"

    def test_entity_edges_only_for_matching_entries(self) -> None:
        incident = _incident(
            ips=[IP_A, IP_B],
            timeline=[_entry("one", ip=IP_A), _entry("two", offset=5, ip=IP_B)],
        )
        lines = render_mermaid(incident).split("\n")
        assert "  ip0 -.-> a0" in lines
        assert "  ip1 -.-> a1" in lines
        assert "  ip0 -.-> a1" not in lines
        assert "  ip1 -.-> a0" not in lines

    @pytest.mark.parametrize("nasty", NASTY_STRINGS)
    def test_hostile_entity_values_cannot_break_out(self, nasty: str) -> None:
        incident = _incident(
            ips=[nasty], users=[nasty], hosts=[nasty], timeline=[_entry("ok", ip=nasty)]
        )
        _assert_safe_mermaid(render_mermaid(incident))

    @pytest.mark.parametrize("nasty", NASTY_STRINGS)
    def test_hostile_timeline_titles_cannot_break_out(self, nasty: str) -> None:
        incident = _incident(
            timeline=[_entry(nasty, offset=i, user=nasty, host=nasty) for i in range(3)]
        )
        _assert_safe_mermaid(render_mermaid(incident))

    def test_directive_text_is_defanged(self) -> None:
        incident = _incident(users=["%%{init: {'theme':'x'}}%%"])
        text = render_mermaid(incident)
        assert "%%{" not in text
        assert "%%" not in text

    def test_attacker_newlines_never_start_a_new_line(self) -> None:
        incident = _incident(users=["a\nb"], timeline=[_entry("x\ny\nz")])
        labels, _ids = _assert_safe_mermaid(render_mermaid(incident))
        assert "user a b" in labels

    def test_script_tag_is_removed(self) -> None:
        text = render_mermaid(_incident(users=["<script>alert(1)</script>"]))
        assert "<script>" not in text
        assert "<" not in text

    def test_node_count_is_capped(self) -> None:
        incident = _incident(
            ips=[f"192.0.2.{n}" for n in range(1, 10)],
            users=[f"user{n}" for n in range(10)],
            hosts=[f"h{n}" for n in range(10)],
            timeline=[_entry(f"step {n}", offset=n) for n in range(200)],
        )
        labels, ids = _assert_safe_mermaid(render_mermaid(incident))
        assert len(ids) == MAX_MERMAID_NODES
        assert len(labels) == MAX_MERMAID_NODES

    def test_only_three_entities_per_kind_are_drawn(self) -> None:
        incident = _incident(ips=[f"192.0.2.{n}" for n in range(1, 10)])
        labels, _ids = _assert_safe_mermaid(render_mermaid(incident))
        assert labels == ["IP 192.0.2.1", "IP 192.0.2.2", "IP 192.0.2.3"]

    def test_long_labels_are_cut_to_max_label(self) -> None:
        labels, _ids = _assert_safe_mermaid(
            render_mermaid(_incident(timeline=[_entry("T" * 500)]))
        )
        assert labels and max(len(label) for label in labels) <= MAX_LABEL

    def test_render_is_deterministic(self) -> None:
        incident = _incident(ips=[IP_A], timeline=[_entry("a", ip=IP_A), _entry("b", offset=3)])
        assert render_mermaid(incident) == render_mermaid(incident)

    def test_end_to_end_hostile_alert_fields_render_safely(self) -> None:
        nasty = NASTY_STRINGS[0]
        alerts = [
            _alert("R001", at=0, ip=IP_A, user=nasty, title=NASTY_STRINGS[2], aid=1),
            _alert("R005", at=5, ip=IP_A, user=NASTY_STRINGS[3], title=NASTY_STRINGS[4], aid=2),
            _alert("R040", at=9, ip=IP_A, user=nasty, host=NASTY_STRINGS[1], aid=3),
        ]
        incidents = correlate(alerts, _cfg())
        assert len(incidents) == 1
        _assert_safe_mermaid(render_mermaid(incidents[0]))
        summary = incidents[0].summary
        assert not any(ch in summary for ch in "\n\r\x1b")


# -- incident_as_alert -----------------------------------------------------


class TestIncidentAsAlert:
    def test_fields_come_from_incident(self) -> None:
        incident = _incident(
            title="Multi-stage attack",
            summary="Between 12:00 and 12:14",
            ips=[IP_A, IP_B],
            users=["root", "alice"],
            hosts=["web01"],
            stages=["Credential Access", "Persistence"],
            mitre_techniques=["T1053", "T1110"],
            alert_ids=[3, 1, 2],
            alert_count=7,
            score=71.5,
            level=RiskLevel.HIGH,
        )
        alert = incident_as_alert(incident)
        assert alert.rule_id == "INC"
        assert alert.title == incident.title
        assert alert.description == incident.summary
        assert alert.first_seen == incident.first_seen
        assert alert.last_seen == incident.last_seen
        assert (alert.ip, alert.user, alert.hostname) == (IP_A, "root", "web01")
        assert alert.event_count == 7
        assert alert.mitre_tactics == ["Credential Access", "Persistence"]
        assert alert.mitre_techniques == ["T1053", "T1110"]
        assert alert.risk.score == 71.5
        assert alert.risk.level == RiskLevel.HIGH
        assert alert.context == {"correlated": True, "alert_ids": [3, 1, 2]}

    def test_empty_entities_become_none(self) -> None:
        alert = incident_as_alert(_incident())
        assert (alert.ip, alert.user, alert.hostname) == (None, None, None)

    @pytest.mark.parametrize(
        "level, severity",
        [
            (RiskLevel.INFORMATIONAL, Severity.INFO),
            (RiskLevel.LOW, Severity.NOTICE),
            (RiskLevel.MEDIUM, Severity.WARNING),
            (RiskLevel.HIGH, Severity.ERROR),
            (RiskLevel.CRITICAL, Severity.CRITICAL),
        ],
    )
    def test_severity_and_risk_level_follow_incident_level(
        self, level: RiskLevel, severity: Severity
    ) -> None:
        alert = incident_as_alert(_incident(level=level))
        assert alert.severity == severity
        assert alert.risk.level == level

    def test_alert_id_list_in_context_is_capped_at_50(self) -> None:
        alert = incident_as_alert(_incident(alert_ids=list(range(1, 201)), alert_count=200))
        assert alert.context["alert_ids"] == list(range(1, 51))

    def test_without_lookup_there_are_no_sample_events(self) -> None:
        assert incident_as_alert(_incident(alert_ids=[1, 2])).sample_events == []

    def test_sample_events_are_capped_and_interleaved(self) -> None:
        alerts: list[Alert] = []
        for index, rule in enumerate(["R001", "R005", "R040"], start=1):
            events = [
                make_event(offset=index * 10 + n, ip=IP_A, message=f"a{index}-e{n}")
                for n in range(3)
            ]
            alert = _alert(rule, at=index * 10, ip=IP_A, aid=index)
            alert.sample_events = events
            alerts.append(alert)
        incident = correlate(alerts, _cfg())[0]
        events = incident_as_alert(incident, {a.id: a for a in alerts if a.id}).sample_events
        assert len(events) == MAX_SAMPLE_EVENTS == 5
        assert [e.message for e in events] == ["a1-e0", "a2-e0", "a3-e0", "a1-e1", "a2-e1"]

    def test_unknown_alert_ids_in_lookup_are_ignored(self) -> None:
        incident = _incident(alert_ids=[1, 2], timeline=[_entry(alert_id=1)])
        other = _alert(aid=99)
        assert incident_as_alert(incident, {99: other}).sample_events == []

    def test_incident_as_alert_does_not_mutate_source_alerts(self) -> None:
        alerts = [_alert("R001", at=0, ip=IP_A, aid=1), _alert("R005", at=5, ip=IP_A, aid=2)]
        incident = correlate(alerts, _cfg())[0]
        before = [a.to_dict() for a in alerts]
        incident_as_alert(incident, {a.id: a for a in alerts if a.id})
        assert [a.to_dict() for a in alerts] == before
