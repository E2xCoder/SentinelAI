"""Tests for the tuning core: policy, feedback, proposals, overlay, history and replay."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinelai.config.models import DetectionConfig, SentinelConfig, parse_suppressions
from sentinelai.core.exceptions import ConfigError, StorageError
from sentinelai.core.store import AlertStore, FeedbackEntry
from sentinelai.detection.base import available_rules
from sentinelai.risk.engine import RiskEngine
from sentinelai.tuning.feedback import collect_feedback, evidence_value
from sentinelai.tuning.history import TuningHistory
from sentinelai.tuning.models import (
    DEFAULT_RISK_WEIGHT_STEP,
    FORCE_SEVERITIES,
    THRESHOLD_SPECS,
    Proposal,
    RuleFeedback,
)
from sentinelai.tuning.overlay import (
    OVERLAY_HEADER,
    apply_patch,
    merge_patch,
    parse_overlay,
    render_overlay,
)
from sentinelai.tuning.policy import FORCE_SUFFIX, check_proposal
from sentinelai.tuning.proposals import generate_proposals, proposals_to_yaml
from sentinelai.tuning.replay import LOUD_SCORE, ReplayContext
from tests.conftest import make_event

NOW = datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)
NARROW_IP = "198.51.100.7/32"


def _iso(days: float) -> str:
    return (NOW + timedelta(days=days)).isoformat()


# -- helpers ---------------------------------------------------------------


@pytest.fixture()
def store(tmp_path: Path) -> Iterator[AlertStore]:
    db = AlertStore(tmp_path / "alerts.db")
    try:
        yield db
    finally:
        db.close()


def _save_labelled(
    store: AlertStore,
    rule_id: str,
    label: str,
    *,
    ip: str | None = None,
    user: str | None = None,
    **context: Any,
) -> int:
    """Save a real, risk-scored alert and label it; return the alert id."""
    import sentinelai.detection.rules  # noqa: F401  (registers built-in rules)

    rule = available_rules()[rule_id]()
    event = make_event(ip=ip, user=user)
    alert = rule.make_alert(event, f"{rule_id} test", "synthetic alert")
    alert.context = dict(context)
    RiskEngine().score(alert)
    alert_id = store.save(alert)
    store.add_feedback(alert_id, label, ts=NOW)
    return alert_id


def _label_attempts(store: AlertStore, rule_id: str, label: str, attempts: list[int]) -> None:
    for index, value in enumerate(attempts):
        _save_labelled(
            store,
            rule_id,
            label,
            ip=f"203.0.{index + 1}.9",
            user=f"user{index}",
            attempts=value,
        )


def _proposal(kind: str, rule_id: str, patch: Any) -> Proposal:
    return Proposal(id="Ptest", kind=kind, rule_id=rule_id, patch=patch, rationale="r")


def _threshold(rule_id: str, value: Any, field: str | None = None) -> Proposal:
    name = field or THRESHOLD_SPECS[rule_id].field
    return _proposal("threshold", rule_id, {"detection": {name: value}})


def _suppression(rule: str = "R007", **overrides: Any) -> Proposal:
    entry: dict[str, Any] = {
        "rule": rule,
        "user": "alice",
        "ip": NARROW_IP,
        "expires": _iso(30),
    }
    entry.update(overrides)
    entry = {k: v for k, v in entry.items() if v is not None}
    return _proposal("suppression", rule, {"detection": {"suppressions": [entry]}})


def _weight(rule_id: str, value: Any) -> Proposal:
    return _proposal("risk_weight", rule_id, {"risk": {"rule_weights": {rule_id: value}}})


def _check(proposal: Proposal, config: SentinelConfig | None = None, **kwargs: Any) -> list[str]:
    return check_proposal(proposal, config or SentinelConfig(), now=NOW, **kwargs)


def _entry(rule_id: str, snapshot: dict[str, Any]) -> FeedbackEntry:
    return FeedbackEntry(
        id=1, alert_id=1, label="fp", note="", ts=NOW, rule_id=rule_id, snapshot=snapshot
    )


# -- policy: thresholds ------------------------------------------------------


class TestPolicyThreshold:
    @pytest.mark.parametrize("value", [3, 5, 10])
    def test_threshold_within_range_is_allowed(self, value: int) -> None:
        assert _check(_threshold("R001", value)) == []

    def test_threshold_above_double_default_is_waivable_violation(self) -> None:
        violations = _check(_threshold("R001", 11))
        assert len(violations) == 1
        assert violations[0].endswith(FORCE_SUFFIX)

    def test_threshold_above_double_default_disappears_with_force(self) -> None:
        assert _check(_threshold("R001", 11), force=True) == []

    def test_threshold_below_half_default_is_waivable_violation(self) -> None:
        violations = _check(_threshold("R001", 2))
        assert violations
        assert all(v.endswith(FORCE_SUFFIX) for v in violations)

    def test_threshold_wrong_field_for_rule_is_rejected_even_with_force(self) -> None:
        proposal = _threshold("R001", 5, field="port_scan_ports")
        violations = _check(proposal, force=True)
        assert violations
        assert not any(v.endswith(FORCE_SUFFIX) for v in violations)

    @pytest.mark.parametrize("value", ["8", 8.0, None, True, False, 0, -3])
    def test_threshold_non_int_or_bool_is_rejected_even_with_force(self, value: Any) -> None:
        assert _check(_threshold("R001", value), force=True)

    def test_threshold_for_rule_without_tunable_threshold_is_rejected(self) -> None:
        proposal = _proposal("threshold", "R007", {"detection": {"brute_force_attempts": 5}})
        assert _check(proposal, force=True)

    def test_threshold_patch_with_extra_keys_is_rejected(self) -> None:
        proposal = _proposal(
            "threshold",
            "R001",
            {"detection": {"brute_force_attempts": 5, "port_scan_ports": 10}},
        )
        assert _check(proposal, force=True)

    def test_unknown_kind_is_rejected_even_with_force(self) -> None:
        proposal = _proposal("code_change", "R001", {})
        assert _check(proposal, force=True)

    def test_unknown_rule_id_is_rejected_even_with_force(self) -> None:
        proposal = _proposal("threshold", "R999", {"detection": {"brute_force_attempts": 5}})
        assert _check(proposal, force=True)


# -- policy: suppressions ------------------------------------------------------


class TestPolicySuppression:
    def test_narrow_host_suppression_is_allowed(self) -> None:
        assert _check(_suppression(user=None, ip="198.51.100.7/32")) == []

    def test_narrow_24_suppression_is_allowed(self) -> None:
        assert _check(_suppression(user=None, ip="198.51.100.0/24")) == []

    @pytest.mark.parametrize("ip", ["10.0.0.0/8", "172.16.0.0/16", "0.0.0.0/0"])
    def test_broad_network_is_rejected_even_with_force(self, ip: str) -> None:
        assert _check(_suppression(user=None, ip=ip), force=True)

    def test_broad_ipv6_network_is_rejected_even_with_force(self) -> None:
        assert _check(_suppression(user=None, ip="2001:db8::/32"), force=True)

    def test_suppression_without_user_or_ip_is_rejected_even_with_force(self) -> None:
        assert _check(_suppression(user=None, ip=None), force=True)

    def test_suppression_rule_mismatch_is_rejected(self) -> None:
        proposal = _proposal("suppression", "R007", _suppression(rule="R020").patch)
        assert _check(proposal, force=True)

    def test_suppression_expiry_over_90_days_is_rejected_even_with_force(self) -> None:
        assert _check(_suppression(expires=_iso(91)), force=True)

    def test_suppression_expiry_at_90_days_is_allowed(self) -> None:
        assert _check(_suppression(expires=_iso(90))) == []

    def test_suppression_already_expired_is_rejected(self) -> None:
        assert _check(_suppression(expires=_iso(-1)), force=True)

    def test_sixth_suppression_for_rule_is_rejected_even_with_force(self) -> None:
        config = SentinelConfig()
        config.detection.suppressions = [
            {"rule": "R007", "user": f"user{i}", "expires": _iso(10)} for i in range(5)
        ]
        assert _check(_suppression(user="alice"), config, force=True)

    def test_fifth_suppression_for_rule_is_allowed(self) -> None:
        config = SentinelConfig()
        config.detection.suppressions = [
            {"rule": "R007", "user": f"user{i}", "expires": _iso(10)} for i in range(4)
        ]
        assert _check(_suppression(user="alice"), config) == []

    def test_expired_existing_suppressions_do_not_count_toward_limit(self) -> None:
        config = SentinelConfig()
        config.detection.suppressions = [
            {"rule": "R007", "user": f"user{i}", "expires": _iso(-5)} for i in range(5)
        ]
        assert _check(_suppression(user="alice"), config) == []

    def test_error_severity_rule_does_not_need_force(self) -> None:
        assert _check(_suppression(rule="R001")) == []

    def test_critical_rule_needs_force_and_is_waivable(self) -> None:
        assert FORCE_SEVERITIES == ("critical",)
        proposal = _suppression(rule="R031")
        violations = _check(proposal)
        assert violations
        assert all(v.endswith(FORCE_SUFFIX) for v in violations)
        assert _check(proposal, force=True) == []

    def test_notice_rule_does_not_need_force(self) -> None:
        assert _check(_suppression(rule="R007")) == []

    def test_broad_critical_suppression_still_rejected_with_force(self) -> None:
        proposal = _suppression(rule="R031", user=None, ip="10.0.0.0/8")
        assert _check(proposal, force=True)

    def test_user_only_suppression_is_rejected_and_not_waivable(self) -> None:
        proposal = _suppression(ip=None)
        for force in (False, True):
            violations = _check(proposal, force=force)
            assert any("source network" in v for v in violations)
            assert not any(v.endswith(FORCE_SUFFIX) for v in violations)

    def test_ip_only_suppression_is_allowed(self) -> None:
        assert _check(_suppression(user=None)) == []

    def test_ip_and_user_suppression_is_allowed(self) -> None:
        assert _check(_suppression(user="alice", ip=NARROW_IP)) == []

    @pytest.mark.parametrize("ip", ["::ffff:198.51.100.0/120", "::ffff:0:0/96", "::/0"])
    def test_ipv6_network_overlapping_ipv4_mapped_range_is_rejected_even_with_force(
        self, ip: str
    ) -> None:
        violations = _check(_suppression(user=None, ip=ip), force=True)
        assert any("IPv4-mapped" in v for v in violations)
        assert not any(v.endswith(FORCE_SUFFIX) for v in violations)


# -- policy: risk weights ------------------------------------------------------


class TestPolicyRiskWeight:
    @pytest.mark.parametrize("value", [0.5, 0.8, 1.0, 1.5])
    def test_weight_within_bounds_is_allowed(self, value: float) -> None:
        assert _check(_weight("R001", value)) == []

    @pytest.mark.parametrize(
        "value", [0.49, 1.51, 0, -1, float("nan"), float("inf"), "0.8", True]
    )
    def test_weight_out_of_bounds_or_wrong_type_is_rejected_even_with_force(
        self, value: Any
    ) -> None:
        assert _check(_weight("R001", value), force=True)

    def test_weight_on_critical_rule_is_waivable_violation(self) -> None:
        proposal = _weight("R031", 0.8)
        violations = _check(proposal)
        assert violations
        assert all(v.endswith(FORCE_SUFFIX) for v in violations)
        assert _check(proposal, force=True) == []

    def test_weight_on_non_critical_rule_is_allowed(self) -> None:
        assert _check(_weight("R001", 0.8)) == []

    def test_weight_patch_for_other_rule_is_rejected(self) -> None:
        proposal = _proposal("risk_weight", "R001", {"risk": {"rule_weights": {"R002": 0.8}}})
        assert _check(proposal, force=True)

    def test_weight_patch_with_wrong_shape_is_rejected(self) -> None:
        proposal = _proposal("risk_weight", "R001", {"risk": {"R001": 0.8}})
        assert _check(proposal, force=True)

    def test_non_mapping_patch_is_rejected(self) -> None:
        proposal = _proposal("risk_weight", "R001", [])
        assert _check(proposal, force=True)


# -- feedback --------------------------------------------------------------------


class TestFeedback:
    def test_collect_feedback_groups_by_rule_and_label(self, store: AlertStore) -> None:
        _save_labelled(store, "R007", "fp", user="a")
        _save_labelled(store, "R001", "tp", attempts=9)
        _save_labelled(store, "R001", "fp", attempts=6)
        _save_labelled(store, "R001", "fp", attempts=7)
        grouped = collect_feedback(store)
        assert list(grouped) == ["R001", "R007"]
        assert (len(grouped["R001"].tp), len(grouped["R001"].fp)) == (1, 2)
        assert (len(grouped["R007"].tp), len(grouped["R007"].fp)) == (0, 1)

    def test_collect_feedback_empty_store_returns_empty_dict(self, store: AlertStore) -> None:
        assert collect_feedback(store) == {}

    def test_rule_feedback_ratio_and_total(self, store: AlertStore) -> None:
        _label_attempts(store, "R001", "fp", [6, 6, 7])
        _label_attempts(store, "R001", "tp", [40, 50])
        fb = collect_feedback(store)["R001"]
        assert fb.total == 5
        assert fb.fp_ratio == pytest.approx(0.6)

    def test_rule_feedback_empty_ratio_is_zero(self) -> None:
        assert RuleFeedback(rule_id="R001").fp_ratio == 0.0

    def test_evidence_value_reads_count(self, store: AlertStore) -> None:
        _save_labelled(store, "R001", "fp", attempts=6)
        entry = store.list_feedback()[0]
        assert evidence_value(entry.snapshot, THRESHOLD_SPECS["R001"]) == 6

    def test_evidence_value_uses_list_length_for_distinct_users(self) -> None:
        snapshot = {"context": {"distinct_users": ["a", "b", "c"]}}
        assert evidence_value(snapshot, THRESHOLD_SPECS["R002"]) == 3

    def test_evidence_value_list_for_plain_count_spec_is_none(self) -> None:
        snapshot = {"context": {"attempts": [1, 2, 3]}}
        assert evidence_value(snapshot, THRESHOLD_SPECS["R001"]) is None

    @pytest.mark.parametrize(
        "snapshot",
        [
            {},
            {"context": None},
            {"context": []},
            {"context": {}},
            {"context": {"attempts": "six"}},
            {"context": {"attempts": True}},
            {"context": {"attempts": None}},
            {"context": {"attempts": float("nan")}},
            {"context": {"attempts": float("inf")}},
        ],
    )
    def test_evidence_value_missing_or_garbage_is_none(self, snapshot: dict[str, Any]) -> None:
        assert evidence_value(snapshot, THRESHOLD_SPECS["R001"]) is None


# -- proposals -------------------------------------------------------------------


def _by_kind(proposals: list[Proposal], kind: str) -> list[Proposal]:
    return [p for p in proposals if p.kind == kind]


class TestProposals:
    def test_threshold_proposal_raises_above_largest_false_positive(
        self, store: AlertStore
    ) -> None:
        _label_attempts(store, "R001", "fp", [6, 6, 7])
        _label_attempts(store, "R001", "tp", [40, 50])
        proposals = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        assert len(proposals) == 1
        assert proposals[0].kind == "threshold"
        assert proposals[0].rule_id == "R001"
        assert proposals[0].patch == {"detection": {"brute_force_attempts": 8}}
        assert len(proposals[0].evidence_alert_ids) == 3
        assert _check(proposals[0]) == []

    def test_ids_and_ordering_are_deterministic(self, store: AlertStore) -> None:
        for _ in range(3):
            _save_labelled(store, "R007", "fp", ip="10.0.0.5", user="svc")
        _label_attempts(store, "R001", "fp", [6, 6, 7])
        _label_attempts(store, "R001", "tp", [40, 50])
        feedback = collect_feedback(store)
        first = generate_proposals(feedback, SentinelConfig(), now=NOW)
        second = generate_proposals(feedback, SentinelConfig(), now=NOW)
        assert first == second
        assert [p.id for p in first] == [p.id for p in second]
        assert [p.rule_id for p in first] == ["R001", "R007"]
        assert all(p.id.startswith("P") and len(p.id) == 9 for p in first)
        assert len({p.id for p in first}) == len(first)

    def test_no_threshold_proposal_when_true_positive_below_false_positive_max(
        self, store: AlertStore
    ) -> None:
        _label_attempts(store, "R001", "fp", [6, 6, 7])
        _label_attempts(store, "R001", "tp", [7, 50])
        proposals = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        assert _by_kind(proposals, "threshold") == []

    def test_no_threshold_proposal_when_it_would_exceed_double_default(
        self, store: AlertStore
    ) -> None:
        _label_attempts(store, "R001", "fp", [9, 10, 10])
        proposals = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        assert _by_kind(proposals, "threshold") == []

    def test_no_threshold_proposal_when_threshold_already_high_enough(
        self, store: AlertStore
    ) -> None:
        _label_attempts(store, "R001", "fp", [6, 6, 7])
        config = SentinelConfig()
        config.detection.brute_force_attempts = 8
        proposals = generate_proposals(collect_feedback(store), config, now=NOW)
        assert _by_kind(proposals, "threshold") == []

    def test_threshold_and_suppression_both_proposed_for_narrow_scope_without_weight(
        self, store: AlertStore
    ) -> None:
        for value in (6, 6, 7):
            _save_labelled(store, "R001", "fp", ip="10.0.0.5", user="svc", attempts=value)
        _label_attempts(store, "R001", "tp", [40, 50])
        proposals = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        assert [p.kind for p in proposals] == ["threshold", "suppression"]
        assert all(p.rule_id == "R001" for p in proposals)

    def test_suppression_proposal_for_common_user_and_host(self, store: AlertStore) -> None:
        for _ in range(3):
            _save_labelled(store, "R007", "fp", ip="10.0.0.5", user="svc-backup")
        proposals = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        assert len(proposals) == 1
        assert proposals[0].kind == "suppression"
        (entry,) = proposals[0].patch["detection"]["suppressions"]
        assert entry["rule"] == "R007"
        assert entry["user"] == "svc-backup"
        assert entry["ip"] == "10.0.0.5/32"
        assert entry["expires"] == "2026-02-06"
        assert _check(proposals[0]) == []

    def test_suppression_proposal_for_common_24_network(self, store: AlertStore) -> None:
        for index in range(3):
            _save_labelled(store, "R007", "fp", ip=f"10.0.0.{index + 5}", user=f"user{index}")
        proposals = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        assert len(proposals) == 1
        (entry,) = proposals[0].patch["detection"]["suppressions"]
        assert entry["ip"] == "10.0.0.0/24"
        assert "user" not in entry
        assert _check(proposals[0]) == []

    def test_suppression_proposal_with_ip_and_user_names_both(self, store: AlertStore) -> None:
        for _ in range(3):
            _save_labelled(store, "R007", "fp", ip="192.0.2.9", user="svc-ci")
        (proposal,) = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        assert proposal.kind == "suppression"
        (entry,) = proposal.patch["detection"]["suppressions"]
        assert (entry["user"], entry["ip"]) == ("svc-ci", "192.0.2.9/32")
        assert _check(proposal) == []

    def test_no_suppression_when_false_positives_share_only_a_user(
        self, store: AlertStore
    ) -> None:
        for index in range(3):
            _save_labelled(store, "R007", "fp", ip=f"10.{index}.0.5", user="svc-shared")
        proposals = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        assert _by_kind(proposals, "suppression") == []

    def test_no_suppression_when_false_positives_have_no_ip(self, store: AlertStore) -> None:
        for _ in range(3):
            _save_labelled(store, "R007", "fp", ip=None, user="svc-shared")
        proposals = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        assert _by_kind(proposals, "suppression") == []

    def test_no_suppression_when_true_positive_matches_scope(self, store: AlertStore) -> None:
        for _ in range(3):
            _save_labelled(store, "R007", "fp", ip="10.0.0.5", user="svc-backup")
        _save_labelled(store, "R007", "tp", ip="10.0.0.5", user="svc-backup")
        proposals = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        assert _by_kind(proposals, "suppression") == []

    def test_risk_weight_fallback_lowers_by_step(self, store: AlertStore) -> None:
        for index in range(3):
            _save_labelled(store, "R007", "fp", ip=f"10.{index}.0.5", user=f"user{index}")
        proposals = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        assert len(proposals) == 1
        assert proposals[0].kind == "risk_weight"
        assert proposals[0].patch == {"risk": {"rule_weights": {"R007": 0.8}}}
        assert DEFAULT_RISK_WEIGHT_STEP == 0.8
        assert _check(proposals[0]) == []

    def test_risk_weight_fallback_never_goes_below_floor(self, store: AlertStore) -> None:
        for index in range(3):
            _save_labelled(store, "R007", "fp", ip=f"10.{index}.0.5", user=f"user{index}")
        config = SentinelConfig()
        config.risk.rule_weights = {"R007": 0.5}
        assert generate_proposals(collect_feedback(store), config, now=NOW) == []
        config.risk.rule_weights = {"R007": 0.6}
        (proposal,) = generate_proposals(collect_feedback(store), config, now=NOW)
        assert proposal.patch == {"risk": {"rule_weights": {"R007": 0.5}}}

    def test_nothing_proposed_below_min_labelled(self, store: AlertStore) -> None:
        for _ in range(2):
            _save_labelled(store, "R007", "fp", ip="10.0.0.5", user="svc")
        assert generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW) == []

    def test_nothing_proposed_below_min_false_positives(self, store: AlertStore) -> None:
        for _ in range(2):
            _save_labelled(store, "R007", "fp", ip="10.0.0.5", user="svc")
        _save_labelled(store, "R007", "tp", ip="10.9.9.9", user="mallory")
        assert generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW) == []

    def test_nothing_proposed_below_min_fp_ratio(self, store: AlertStore) -> None:
        for _ in range(3):
            _save_labelled(store, "R007", "fp", ip="10.0.0.5", user="svc")
        for _ in range(3):
            _save_labelled(store, "R007", "tp", ip="10.9.9.9", user="mallory")
        assert generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW) == []

    def test_no_feedback_proposes_nothing(self) -> None:
        assert generate_proposals({}, SentinelConfig(), now=NOW) == []

    def test_proposals_to_yaml_round_trips_with_header(self, store: AlertStore) -> None:
        _label_attempts(store, "R001", "fp", [6, 6, 7])
        proposals = generate_proposals(collect_feedback(store), SentinelConfig(), now=NOW)
        text = proposals_to_yaml(proposals)
        assert text.startswith("# Proposed changes")
        loaded = yaml.safe_load(text)
        assert isinstance(loaded, list)
        assert loaded[0]["id"] == proposals[0].id
        assert loaded[0]["kind"] == "threshold"
        assert loaded[0]["rule"] == "R001"
        assert loaded[0]["patch"] == proposals[0].patch
        assert loaded[0]["evidence_alerts"] == list(proposals[0].evidence_alert_ids)

    def test_proposals_to_yaml_empty_is_empty_list(self) -> None:
        text = proposals_to_yaml([])
        assert text.startswith("# Proposed changes")
        assert yaml.safe_load(text) == []

    def test_proposal_to_dict_lists_evidence(self) -> None:
        proposal = Proposal("P1", "threshold", "R001", {}, "why", (3, 4))
        assert proposal.to_dict()["evidence_alert_ids"] == [3, 4]


# -- overlay ---------------------------------------------------------------------


class TestOverlay:
    def test_parse_empty_text_is_empty_dict(self) -> None:
        assert parse_overlay("") == {}
        assert parse_overlay("   \n") == {}
        assert parse_overlay("# only a comment\n") == {}

    @pytest.mark.parametrize(
        "text",
        [
            "evil: {a: 1}\n",
            "detection:\n  unknown_key: 3\n",
            "detection:\n  brute_force_attempts: lots\n",
            "detection:\n  brute_force_attempts: true\n",
            "detection:\n  suppressions: nope\n",
            "risk:\n  other: 1\n",
            "risk:\n  rule_weights:\n    bad: 1.0\n",
            "risk:\n  rule_weights:\n    R001: high\n",
            "- a\n- b\n",
            "detection: [1\n",
        ],
    )
    def test_parse_rejects_unknown_or_malformed_overlay(self, text: str) -> None:
        with pytest.raises(ConfigError):
            parse_overlay(text)

    def test_render_empty_overlay_is_empty_string(self) -> None:
        assert render_overlay({}) == ""

    def test_render_is_deterministic_and_order_independent(self) -> None:
        one = {
            "risk": {"rule_weights": {"R002": 0.9, "R001": 0.8}},
            "detection": {"brute_force_attempts": 8},
        }
        two = {
            "detection": {"brute_force_attempts": 8},
            "risk": {"rule_weights": {"R001": 0.8, "R002": 0.9}},
        }
        assert render_overlay(one) == render_overlay(two)
        assert render_overlay(one) == render_overlay(one)

    def test_render_uses_header_lf_newlines_and_parses_back(self) -> None:
        data = {
            "detection": {
                "brute_force_attempts": 8,
                "suppressions": [{"rule": "R007", "user": "svc", "expires": "2026-02-06"}],
            },
            "risk": {"rule_weights": {"R001": 0.8}},
        }
        text = render_overlay(data)
        assert text.startswith(OVERLAY_HEADER)
        assert "\r" not in text
        parsed = parse_overlay(text)
        assert parsed["risk"] == data["risk"]
        assert parsed["detection"]["brute_force_attempts"] == 8

    def test_merge_appends_suppressions_without_duplicates(self) -> None:
        entry = {"rule": "R007", "user": "svc", "expires": "2026-02-06"}
        overlay = {"detection": {"suppressions": [entry]}}
        other = {"rule": "R007", "user": "bob", "expires": "2026-02-06"}
        merged = merge_patch(overlay, {"detection": {"suppressions": [dict(entry), other]}})
        assert merged["detection"]["suppressions"] == [entry, other]
        again = merge_patch(merged, {"detection": {"suppressions": [dict(other)]}})
        assert again == merged

    def test_merge_does_not_modify_inputs(self) -> None:
        overlay = {"detection": {"brute_force_attempts": 6}}
        patch = {"detection": {"brute_force_attempts": 8}}
        merged = merge_patch(overlay, patch)
        assert merged["detection"]["brute_force_attempts"] == 8
        assert overlay == {"detection": {"brute_force_attempts": 6}}
        assert patch == {"detection": {"brute_force_attempts": 8}}

    def test_merge_weight_of_one_removes_entry_and_prunes_empty_sections(self) -> None:
        overlay = {"risk": {"rule_weights": {"R001": 0.8}}}
        assert merge_patch(overlay, {"risk": {"rule_weights": {"R001": 1.0}}}) == {}

    def test_merge_weight_of_one_keeps_other_weights(self) -> None:
        overlay = {"risk": {"rule_weights": {"R001": 0.8, "R002": 0.9}}}
        merged = merge_patch(overlay, {"risk": {"rule_weights": {"R001": 1.0}}})
        assert merged == {"risk": {"rule_weights": {"R002": 0.9}}}

    def test_merge_rejects_unknown_patch_keys(self) -> None:
        with pytest.raises(ConfigError):
            merge_patch({}, {"logging": {"level": "debug"}})

    def test_apply_patch_leaves_input_config_untouched(self) -> None:
        config = SentinelConfig()
        patch = {
            "detection": {
                "brute_force_attempts": 8,
                "suppressions": [{"rule": "R007", "user": "svc", "expires": "2099-01-01"}],
            },
            "risk": {"rule_weights": {"R001": 0.8}},
        }
        candidate = apply_patch(config, patch)
        assert candidate is not config
        assert candidate.detection.brute_force_attempts == 8
        assert candidate.risk.rule_weights == {"R001": 0.8}
        assert len(candidate.detection.suppressions) == 1
        assert config.detection.brute_force_attempts == 5
        assert config.detection.suppressions == []
        assert config.risk.rule_weights == {}

    def test_apply_patch_weight_of_one_removes_existing_weight(self) -> None:
        config = SentinelConfig()
        config.risk.rule_weights = {"R001": 0.8}
        candidate = apply_patch(config, {"risk": {"rule_weights": {"R001": 1.0}}})
        assert candidate.risk.rule_weights == {}
        assert config.risk.rule_weights == {"R001": 0.8}

    def test_apply_patch_validates_result(self) -> None:
        config = SentinelConfig()
        with pytest.raises(ConfigError):
            apply_patch(config, {"risk": {"rule_weights": {"R001": 5.0}}})
        with pytest.raises(ConfigError):
            apply_patch(config, {"detection": {"brute_force_attempts": -1}})
        assert config.detection.brute_force_attempts == 5

    def test_apply_patch_rejects_invalid_suppression(self) -> None:
        with pytest.raises(ConfigError):
            apply_patch(SentinelConfig(), {"detection": {"suppressions": [{"rule": "R007"}]}})

    @pytest.mark.parametrize("value", [float("nan"), float("inf")])
    def test_detection_validate_rejects_non_finite_threshold(self, value: float) -> None:
        detection = DetectionConfig()
        detection.brute_force_attempts = value  # type: ignore[assignment]
        with pytest.raises(ConfigError):
            detection.validate()

    def test_parse_suppressions_out_of_range_expiry_raises_config_error(self) -> None:
        entry = {"rule": "R007", "ip": NARROW_IP, "expires": "9999-12-31T23:59:59-12:00"}
        with pytest.raises(ConfigError):
            parse_suppressions([entry])

    def test_apply_patch_rejects_unknown_keys(self) -> None:
        with pytest.raises(ConfigError):
            apply_patch(SentinelConfig(), {"detection": {"state_dir": 1}})


# -- history ---------------------------------------------------------------------


def _history(tmp_path: Path, store: AlertStore) -> TuningHistory:
    return TuningHistory(tmp_path, store, now=lambda: NOW)


def _audit_lines(history: TuningHistory) -> list[str]:
    if not history.audit_file.exists():
        return []
    return history.audit_file.read_text(encoding="utf-8").splitlines()


class TestHistory:
    def test_apply_writes_overlay_backup_history_row_and_audit_line(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        history_id = history.apply("a: 1\n", ["P1", "P2"], note="first")
        assert history.overlay_file.read_bytes() == b"a: 1\n"
        backups = sorted((tmp_path / "tuning" / "history").glob("*.yaml"))
        assert [b.name for b in backups] == [f"{history_id:04d}-before-apply.yaml"]
        assert backups[0].read_bytes() == b""
        (row,) = history.history()
        assert (row.id, row.action, row.rolled_back) == (history_id, "apply", False)
        assert row.proposal_ids == ["P1", "P2"]
        assert (row.previous_text, row.new_text, row.note) == ("", "a: 1\n", "first")
        (line,) = _audit_lines(history)
        record = json.loads(line)
        assert record["event"] == "apply"
        assert record["proposal_ids"] == ["P1", "P2"]
        assert record["history_id"] == history_id

    def test_second_apply_backs_up_first_overlay(self, tmp_path: Path, store: AlertStore) -> None:
        history = _history(tmp_path, store)
        first = history.apply("a: 1\n", ["P1"])
        second = history.apply("a: 2\n", ["P2"])
        assert second > first
        assert history.overlay_file.read_bytes() == b"a: 2\n"
        backup = tmp_path / "tuning" / "history" / f"{second:04d}-before-apply.yaml"
        assert backup.read_bytes() == b"a: 1\n"
        assert [e.previous_text for e in history.history()] == ["", "a: 1\n"]
        assert len(_audit_lines(history)) == 2

    def test_rollback_restores_previous_text_byte_for_byte(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        history.apply("a: 1\n", ["P1"])
        before = history.overlay_file.read_bytes()
        history.apply("a: 2\n", ["P2"])
        original = history.rollback()
        assert history.overlay_file.read_bytes() == before
        assert original.proposal_ids == ["P2"]

    def test_rollback_restores_crlf_previous_text_byte_for_byte(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        history.overlay_file.write_bytes(b"# edited by hand\r\ndetection:\r\n  a: 1\r\n")
        before = history.overlay_file.read_bytes()
        history.apply("detection:\n  a: 2\n", ["P1"])
        assert history.overlay_file.read_bytes() == b"detection:\n  a: 2\n"
        history.rollback()
        assert history.overlay_file.read_bytes() == before
        assert b"\r\n" in history.overlay_file.read_bytes()

    def test_rollback_marks_row_rolled_back_and_records_rollback_row(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        applied = history.apply("a: 1\n", ["P1"])
        history.rollback()
        rows = history.history()
        assert [r.action for r in rows] == ["apply", "rollback"]
        assert rows[0].id == applied
        assert rows[0].rolled_back is True
        assert rows[1].rolled_back is False
        assert rows[1].new_text == ""

    def test_rollback_to_absent_overlay_deletes_file(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        assert not history.overlay_file.exists()
        history.apply("a: 1\n", ["P1"])
        assert history.overlay_file.exists()
        history.rollback()
        assert not history.overlay_file.exists()
        assert history.current_text() == ""

    def test_rollbacks_walk_back_through_applies_in_order(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        history.apply("a: 1\n", ["P1"])
        history.apply("a: 2\n", ["P2"])
        history.rollback()
        assert history.overlay_file.read_bytes() == b"a: 1\n"
        history.rollback()
        assert not history.overlay_file.exists()
        with pytest.raises(ConfigError):
            history.rollback()

    def test_rollback_with_nothing_applied_raises_config_error(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        with pytest.raises(ConfigError, match="nothing to roll back"):
            _history(tmp_path, store).rollback()

    def test_rollback_does_not_target_an_already_rolled_back_apply(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        history.apply("a: 1\n", ["P1"])
        history.rollback()
        with pytest.raises(ConfigError):
            history.rollback()
        assert not history.overlay_file.exists()

    def test_audit_log_only_grows_and_every_line_is_valid_json(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        counts = [len(_audit_lines(history))]
        history.apply("a: 1\n", ["P1"])
        counts.append(len(_audit_lines(history)))
        history.apply("a: 2\n", ["P2"])
        counts.append(len(_audit_lines(history)))
        history.rollback()
        counts.append(len(_audit_lines(history)))
        history.rollback()
        counts.append(len(_audit_lines(history)))
        with pytest.raises(ConfigError):
            history.rollback()
        counts.append(len(_audit_lines(history)))
        assert counts == sorted(counts)
        assert counts[-1] == 4
        events = []
        for line in _audit_lines(history):
            record = json.loads(line)
            assert {"ts", "event", "user"} <= set(record)
            assert record["user"]
            assert record["ts"] == NOW.isoformat()
            events.append(record["event"])
        assert events == ["apply", "apply", "rollback", "rollback"]

    def test_audit_prefix_is_preserved_across_operations(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        history.apply("a: 1\n", ["P1"])
        snapshot = _audit_lines(history)
        history.apply("a: 2\n", ["P2"])
        history.rollback()
        assert _audit_lines(history)[: len(snapshot)] == snapshot

    def test_current_text_tolerates_invalid_utf8_bytes(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        history.overlay_file.write_bytes(b"a: \xff\xfe\n")
        text = history.current_text()
        assert text.startswith("a: ")
        assert "\ufffd" in text

    def test_fresh_lock_file_blocks_apply(self, tmp_path: Path, store: AlertStore) -> None:
        history = _history(tmp_path, store)
        lock = tmp_path / "tuning" / ".lock"
        lock.parent.mkdir(parents=True)
        lock.write_text(str(os.getpid()), encoding="ascii")
        with pytest.raises(ConfigError, match="another sentinel tune"):
            history.apply("a: 1\n", ["P1"])
        assert lock.exists()
        assert not history.overlay_file.exists()

    def test_stale_lock_file_is_taken_over(self, tmp_path: Path, store: AlertStore) -> None:
        history = _history(tmp_path, store)
        lock = tmp_path / "tuning" / ".lock"
        lock.parent.mkdir(parents=True)
        lock.write_text("99999", encoding="ascii")
        old = time.time() - 700
        os.utime(lock, (old, old))
        history.apply("a: 1\n", ["P1"])
        assert history.overlay_file.read_bytes() == b"a: 1\n"
        assert not lock.exists()

    def test_lock_file_is_removed_after_normal_apply(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        history.apply("a: 1\n", ["P1"])
        assert not (tmp_path / "tuning" / ".lock").exists()

    def test_lock_file_is_removed_after_failing_apply(
        self, tmp_path: Path, store: AlertStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        history = _history(tmp_path, store)

        def boom(*args: Any, **kwargs: Any) -> int:
            raise StorageError("disk full")

        monkeypatch.setattr(store, "add_config_history", boom)
        with pytest.raises(StorageError):
            history.apply("a: 1\n", ["P1"])
        assert not (tmp_path / "tuning" / ".lock").exists()
        assert not history.overlay_file.exists()

    def test_audit_never_raises_when_log_cannot_be_written(
        self, tmp_path: Path, store: AlertStore
    ) -> None:
        history = _history(tmp_path, store)
        (tmp_path / "tuning").write_text("not a directory", encoding="utf-8")
        history.audit("custom", detail=1)  # must not raise


# -- replay ----------------------------------------------------------------------


def _snapshot(
    *,
    score: float = 50.0,
    severity: str = "error",
    ip: str | None = "198.51.100.7",
    user: str | None = "alice",
    **context: Any,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "ip": ip,
        "user": user,
        "risk": {"score": score},
        "context": dict(context),
    }


def _config_with(**detection: Any) -> SentinelConfig:
    config = SentinelConfig()
    for name, value in detection.items():
        setattr(config.detection, name, value)
    return config


class TestReplay:
    def test_alert_below_raised_threshold_would_not_alert(self) -> None:
        replay = ReplayContext(_config_with(brute_force_attempts=8), NOW)
        assert replay.would_alert(_entry("R001", _snapshot(attempts=6))) is False

    def test_alert_at_or_above_threshold_would_alert(self) -> None:
        replay = ReplayContext(_config_with(brute_force_attempts=8), NOW)
        assert replay.would_alert(_entry("R001", _snapshot(attempts=8))) is True
        assert replay.would_alert(_entry("R001", _snapshot(attempts=40))) is True

    def test_alert_without_usable_evidence_still_alerts(self) -> None:
        replay = ReplayContext(_config_with(brute_force_attempts=8), NOW)
        assert replay.would_alert(_entry("R001", _snapshot())) is True
        assert replay.would_alert(_entry("R001", {})) is True

    def test_list_evidence_threshold_for_password_spray(self) -> None:
        replay = ReplayContext(_config_with(password_spray_users=6), NOW)
        few = _entry("R002", _snapshot(distinct_users=["a", "b", "c", "d"]))
        many = _entry("R002", _snapshot(distinct_users=list("abcdefg")))
        assert replay.would_alert(few) is False
        assert replay.would_alert(many) is True

    def test_active_suppression_stops_alert(self) -> None:
        config = SentinelConfig()
        config.detection.suppressions = [{"rule": "R007", "user": "alice", "expires": _iso(5)}]
        replay = ReplayContext(config, NOW)
        assert replay.would_alert(_entry("R007", _snapshot(severity="notice"))) is False
        other = _entry("R007", _snapshot(severity="notice", user="bob"))
        assert replay.would_alert(other) is True

    def test_ip_scoped_suppression_matches_only_inside_network(self) -> None:
        config = SentinelConfig()
        config.detection.suppressions = [
            {"rule": "R007", "ip": "198.51.100.0/24", "expires": _iso(5)}
        ]
        replay = ReplayContext(config, NOW)
        inside = _entry("R007", _snapshot(severity="notice", ip="198.51.100.200"))
        outside = _entry("R007", _snapshot(severity="notice", ip="203.0.113.1"))
        no_ip = _entry("R007", _snapshot(severity="notice", ip=None))
        assert replay.would_alert(inside) is False
        assert replay.would_alert(outside) is True
        assert replay.would_alert(no_ip) is True

    def test_expired_suppression_does_not_stop_alert(self) -> None:
        config = SentinelConfig()
        config.detection.suppressions = [{"rule": "R007", "user": "alice", "expires": _iso(-1)}]
        replay = ReplayContext(config, NOW)
        assert replay.would_alert(_entry("R007", _snapshot(severity="notice"))) is True

    def test_critical_alert_is_never_suppressed(self) -> None:
        config = SentinelConfig()
        config.detection.suppressions = [
            {"rule": "R031", "user": "alice", "ip": NARROW_IP, "expires": _iso(5)}
        ]
        replay = ReplayContext(config, NOW)
        assert replay.would_alert(_entry("R031", _snapshot(severity="critical"))) is True

    def test_critical_rule_class_severity_overrides_lower_snapshot_severity(self) -> None:
        config = SentinelConfig()
        config.detection.suppressions = [
            {"rule": "R031", "user": "alice", "ip": NARROW_IP, "expires": _iso(5)}
        ]
        replay = ReplayContext(config, NOW)
        assert replay.would_alert(_entry("R031", _snapshot(severity="error"))) is True
        assert replay.would_alert(_entry("R031", _snapshot(severity="notice"))) is True

    def test_snapshot_without_severity_is_never_suppressed(self) -> None:
        config = SentinelConfig()
        config.detection.suppressions = [
            {"rule": "R007", "user": "alice", "ip": NARROW_IP, "expires": _iso(5)}
        ]
        replay = ReplayContext(config, NOW)
        with_severity = _snapshot(severity="notice")
        assert replay.would_alert(_entry("R007", with_severity)) is False
        without_severity = {k: v for k, v in with_severity.items() if k != "severity"}
        assert replay.would_alert(_entry("R007", without_severity)) is True

    def test_threshold_unverifiable_true_without_evidence_false_with_it(self) -> None:
        replay = ReplayContext(SentinelConfig(), NOW)
        assert replay.threshold_unverifiable(_entry("R001", _snapshot())) is True
        assert replay.threshold_unverifiable(_entry("R001", _snapshot(attempts=6))) is False

    def test_threshold_unverifiable_false_for_rule_without_threshold(self) -> None:
        replay = ReplayContext(SentinelConfig(), NOW)
        assert replay.threshold_unverifiable(_entry("R007", _snapshot())) is False

    def test_critical_stored_alert_round_trip_is_never_suppressed(
        self, store: AlertStore
    ) -> None:
        _save_labelled(store, "R031", "fp", ip="198.51.100.7", user="alice")
        entry = store.list_feedback()[0]
        config = SentinelConfig()
        config.detection.suppressions = [
            {"rule": "R031", "ip": "198.51.100.7/32", "expires": _iso(5)}
        ]
        assert ReplayContext(config, NOW).would_alert(entry) is True

    def test_score_applies_rule_weight(self) -> None:
        config = SentinelConfig()
        config.risk.rule_weights = {"R001": 0.5}
        replay = ReplayContext(config, NOW)
        assert replay.score(_entry("R001", _snapshot(score=60.0))) == pytest.approx(30.0)
        assert replay.score(_entry("R002", _snapshot(score=60.0))) == pytest.approx(60.0)

    def test_score_is_clamped_and_tolerates_bad_snapshots(self) -> None:
        config = SentinelConfig()
        config.risk.rule_weights = {"R001": 1.5}
        replay = ReplayContext(config, NOW)
        assert replay.score(_entry("R001", _snapshot(score=90.0))) == 100.0
        assert replay.score(_entry("R001", {})) == 0.0
        assert replay.score(_entry("R001", {"risk": {"score": "high"}})) == 0.0
        assert replay.score(_entry("R001", {"risk": {"score": True}})) == 0.0

    def test_stored_real_alert_score_matches_snapshot(self, store: AlertStore) -> None:
        _save_labelled(store, "R001", "fp", ip="198.51.100.7", user="alice", attempts=6)
        entry = store.list_feedback()[0]
        stored = entry.snapshot["risk"]["score"]
        assert stored > 0
        assert ReplayContext(SentinelConfig(), NOW).score(entry) == pytest.approx(stored)

    def test_alerts_loudly_requires_alert_and_score_at_threshold(self) -> None:
        replay = ReplayContext(SentinelConfig(), NOW)
        loud = _entry("R001", _snapshot(score=LOUD_SCORE, attempts=9))
        quiet = _entry("R001", _snapshot(score=LOUD_SCORE - 0.1, attempts=9))
        assert replay.alerts_loudly(loud) is True
        assert replay.alerts_loudly(quiet) is False

    def test_lowered_weight_makes_alert_quiet(self) -> None:
        config = SentinelConfig()
        config.risk.rule_weights = {"R001": 0.5}
        replay = ReplayContext(config, NOW)
        assert replay.alerts_loudly(_entry("R001", _snapshot(score=60.0, attempts=9))) is False

    def test_suppressed_or_below_threshold_alert_is_not_loud(self) -> None:
        config = _config_with(brute_force_attempts=8)
        config.detection.suppressions = [{"rule": "R001", "user": "bob", "expires": _iso(5)}]
        replay = ReplayContext(config, NOW)
        below = _entry("R001", _snapshot(score=90.0, attempts=6))
        suppressed = _entry(
            "R001", _snapshot(score=90.0, attempts=9, user="bob", severity="warning")
        )
        assert replay.alerts_loudly(below) is False
        assert replay.alerts_loudly(suppressed) is False
