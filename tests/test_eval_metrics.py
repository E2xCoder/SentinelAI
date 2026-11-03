"""Tests for sentinelai.evaluation.metrics (pure metric computation)."""

from __future__ import annotations

from typing import Any

from sentinelai.evaluation.metrics import compute_metrics
from sentinelai.evaluation.models import (
    RISK_LEVEL_ORDER,
    AlertOutcome,
    RuleInfo,
    ScenarioResult,
)

RULES: dict[str, RuleInfo] = {
    "R001": RuleInfo("R001", "Brute Force", ("T1110.001",)),
    "R002": RuleInfo("R002", "Spraying", ("T1110.003", "T1110")),
    "R003": RuleInfo("R003", "Stuffing", ("T1110",)),
}


def _alert(rule_id: str, score: float, level: str) -> AlertOutcome:
    return AlertOutcome(rule_id=rule_id, risk_score=score, risk_level=level)


def _attack(
    name: str,
    expected: list[str],
    alerts: list[AlertOutcome],
    events: int = 100,
) -> ScenarioResult:
    fired = sorted({a.rule_id for a in alerts})
    return ScenarioResult(
        name=name,
        kind="attack",
        events=events,
        alerts=alerts,
        fired_rules=fired,
        expected_rules=sorted(expected),
        missing_rules=sorted(set(expected) - set(fired)),
        unexpected_rules=[],
    )


def _benign(name: str, alerts: list[AlertOutcome], events: int = 500) -> ScenarioResult:
    fired = sorted({a.rule_id for a in alerts})
    return ScenarioResult(
        name=name,
        kind="benign",
        events=events,
        alerts=alerts,
        fired_rules=fired,
        expected_rules=[],
        missing_rules=[],
        unexpected_rules=fired,
    )


def _sample_results() -> list[ScenarioResult]:
    return [
        _attack("a1", ["R001"], [_alert("R001", 80.0, "high")]),
        _attack("a2", ["R001", "R002"], [_alert("R001", 60.5, "medium")]),
        _benign("b1", [_alert("R001", 20.0, "low")]),
        _benign("b2", []),
    ]


def _compute(
    results: list[ScenarioResult] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any], dict[str, Any], dict[str, Any]]:
    return compute_metrics(_sample_results() if results is None else results, RULES)


class TestRuleMetrics:
    def test_detected_rule_counts_tp_fp_fn_exactly(self) -> None:
        rules, _, _, _ = _compute()
        r001 = rules["R001"]
        assert (r001["tp"], r001["fp"], r001["fn"]) == (2, 1, 0)
        assert r001["precision"] == 0.6667
        assert r001["recall"] == 1.0
        assert r001["name"] == "Brute Force"
        assert r001["attack_scenarios"] == 2

    def test_missed_rule_has_zero_recall_and_none_precision(self) -> None:
        rules, _, _, _ = _compute()
        r002 = rules["R002"]
        assert (r002["tp"], r002["fp"], r002["fn"]) == (0, 0, 1)
        assert r002["recall"] == 0.0
        assert r002["precision"] is None

    def test_rule_without_any_data_has_none_precision_and_recall(self) -> None:
        rules, _, _, _ = _compute()
        r003 = rules["R003"]
        assert (r003["tp"], r003["fp"], r003["fn"]) == (0, 0, 0)
        assert r003["precision"] is None
        assert r003["recall"] is None
        assert r003["attack_scenarios"] == 0

    def test_empty_results_yield_all_rules_with_none_ratios(self) -> None:
        rules, _, _, _ = _compute([])
        assert sorted(rules) == ["R001", "R002", "R003"]
        assert all(m["precision"] is None and m["recall"] is None for m in rules.values())

    def test_unknown_rule_id_is_included_with_empty_name(self) -> None:
        results = [
            _attack("a1", ["R001"], [_alert("R001", 80.0, "high")]),
            _benign("b1", [_alert("AI001", 30.0, "low")]),
        ]
        rules, _, _, _ = _compute(results)
        assert rules["AI001"]["name"] == ""
        assert rules["AI001"]["fp"] == 1
        assert rules["AI001"]["precision"] == 0.0

    def test_rule_keys_are_sorted(self) -> None:
        results = [_benign("b1", [_alert("AI001", 30.0, "low")])]
        rules, _, _, _ = _compute(results)
        assert list(rules) == sorted(rules)

    def test_scenario_counts_once_per_rule_despite_multiple_alerts(self) -> None:
        alerts = [_alert("R001", 70.0, "high"), _alert("R001", 71.0, "high")]
        rules, _, _, _ = _compute([_attack("a1", ["R001"], alerts)])
        assert rules["R001"]["tp"] == 1


class TestSummary:
    def test_micro_recall_and_precision_aggregate_all_rules(self) -> None:
        _, summary, _, _ = _compute()
        # tp=2, fp=1, fn=1
        assert summary["attack_recall"] == 0.6667
        assert summary["precision"] == 0.6667

    def test_scenario_counters(self) -> None:
        _, summary, _, _ = _compute()
        assert summary["scenarios_total"] == 4
        assert summary["scenarios_passed"] == 2
        assert summary["attack_scenarios"] == 2
        assert summary["benign_scenarios"] == 2

    def test_fp_per_1k_benign_events_arithmetic(self) -> None:
        _, summary, _, _ = _compute()
        # 1 benign alert over 1000 benign events
        assert summary["benign_events"] == 1000
        assert summary["benign_alerts"] == 1
        assert summary["fp_per_1k_benign_events"] == 1.0

    def test_fp_per_1k_rounds_to_four_digits(self) -> None:
        results = [_benign("b1", [_alert("R001", 10.0, "low")], events=3)]
        _, summary, _, _ = _compute(results)
        assert summary["fp_per_1k_benign_events"] == 333.3333

    def test_fp_per_1k_is_zero_without_benign_events(self) -> None:
        results = [_attack("a1", ["R001"], [_alert("R001", 80.0, "high")])]
        _, summary, _, _ = _compute(results)
        assert summary["fp_per_1k_benign_events"] == 0.0

    def test_uncovered_rules_lists_rules_no_attack_expects(self) -> None:
        _, summary, _, _ = _compute()
        assert summary["uncovered_rules"] == ["R003"]

    def test_uncovered_rules_ignores_benign_scenarios(self) -> None:
        _, summary, _, _ = _compute([_benign("b1", [])])
        assert summary["uncovered_rules"] == ["R001", "R002", "R003"]

    def test_empty_results_have_none_aggregate_ratios(self) -> None:
        _, summary, _, _ = _compute([])
        assert summary["attack_recall"] is None
        assert summary["precision"] is None
        assert summary["scenarios_total"] == 0


class TestRiskBlocks:
    def test_attack_block_min_max_mean(self) -> None:
        _, _, risk, _ = _compute()
        block = risk["attack"]
        assert block["alerts"] == 2
        assert block["min"] == 60.5
        assert block["max"] == 80.0
        assert block["mean"] == 70.25

    def test_benign_block_single_alert(self) -> None:
        _, _, risk, _ = _compute()
        block = risk["benign"]
        assert block["alerts"] == 1
        assert block["min"] == block["max"] == block["mean"] == 20.0

    def test_empty_block_has_none_stats(self) -> None:
        _, _, risk, _ = _compute([])
        assert risk["attack"]["alerts"] == 0
        assert risk["attack"]["min"] is None
        assert risk["attack"]["max"] is None
        assert risk["attack"]["mean"] is None

    def test_by_level_contains_every_level_in_order(self) -> None:
        _, _, risk, _ = _compute()
        by_level = risk["attack"]["by_level"]
        assert list(by_level) == list(RISK_LEVEL_ORDER)
        assert by_level == {
            "informational": 0,
            "low": 0,
            "medium": 1,
            "high": 1,
            "critical": 0,
        }

    def test_unknown_risk_level_is_not_counted_in_by_level(self) -> None:
        results = [_attack("a1", ["R001"], [_alert("R001", 50.0, "bogus")])]
        _, _, risk, _ = _compute(results)
        assert risk["attack"]["alerts"] == 1
        assert sum(risk["attack"]["by_level"].values()) == 0


class TestMitre:
    def test_detected_covered_and_total(self) -> None:
        _, _, _, mitre = _compute()
        assert mitre["total"] == 3
        assert mitre["covered"] == 1
        assert mitre["techniques"]["T1110.001"] == {"rules": ["R001"], "detected": True}
        assert mitre["techniques"]["T1110.003"] == {"rules": ["R002"], "detected": False}
        assert mitre["techniques"]["T1110"] == {"rules": ["R002", "R003"], "detected": False}

    def test_techniques_are_sorted(self) -> None:
        _, _, _, mitre = _compute()
        assert list(mitre["techniques"]) == sorted(mitre["techniques"])

    def test_benign_false_positive_does_not_count_as_detection(self) -> None:
        results = [_benign("b1", [_alert("R001", 20.0, "low")])]
        _, _, _, mitre = _compute(results)
        assert mitre["covered"] == 0

    def test_shared_technique_is_detected_by_any_member_rule(self) -> None:
        results = [_attack("a1", ["R003"], [_alert("R003", 70.0, "high")])]
        _, _, _, mitre = _compute(results)
        assert mitre["techniques"]["T1110"]["detected"] is True


class TestDeterminism:
    def test_same_input_twice_gives_equal_output(self) -> None:
        assert _compute() == _compute()

    def test_result_order_does_not_change_output(self) -> None:
        forward = _compute(_sample_results())
        backward = _compute(list(reversed(_sample_results())))
        assert forward == backward
