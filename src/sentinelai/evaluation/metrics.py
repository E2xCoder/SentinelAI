"""Pure metric computation for the evaluation harness.

Counting is scenario-level: a scenario contributes at most once per rule
to that rule's true/false positive/negative tallies. Everything returned
is deterministic (sorted keys and lists, rounded floats, no clock or I/O)
so reports can be diffed against a committed baseline.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sentinelai.evaluation.models import (
    KIND_ATTACK,
    KIND_BENIGN,
    RISK_LEVEL_ORDER,
    AlertOutcome,
    RuleInfo,
    ScenarioResult,
)

_RATIO_DIGITS = 4
_RISK_DIGITS = 2


def _ratio(numerator: int, denominator: int) -> float | None:
    """Return ``numerator / denominator`` rounded, or None for an empty base."""
    if denominator == 0:
        return None
    return round(numerator / denominator, _RATIO_DIGITS)


def _known_rule_ids(
    results: Sequence[ScenarioResult], rules: Mapping[str, RuleInfo]
) -> list[str]:
    """Every rule id from the registry plus any id seen in the results."""
    ids: set[str] = set(rules)
    for res in results:
        ids.update(res.fired_rules)
        ids.update(res.expected_rules)
        ids.update(res.missing_rules)
        ids.update(res.unexpected_rules)
    return sorted(ids)


def _true_positives(res: ScenarioResult) -> set[str]:
    return set(res.expected_rules) & set(res.fired_rules)


def _rule_metrics(
    results: Sequence[ScenarioResult], rules: Mapping[str, RuleInfo]
) -> dict[str, dict[str, Any]]:
    metrics: dict[str, dict[str, Any]] = {}
    for rule_id in _known_rule_ids(results, rules):
        tp = sum(1 for r in results if rule_id in _true_positives(r))
        fn = sum(1 for r in results if rule_id in r.missing_rules)
        fp = sum(1 for r in results if rule_id in r.unexpected_rules)
        attack = sum(1 for r in results if r.kind == KIND_ATTACK and rule_id in r.expected_rules)
        info = rules.get(rule_id)
        metrics[rule_id] = {
            "name": info.name if info is not None else "",
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "attack_scenarios": attack,
        }
    return metrics


def _summary(
    results: Sequence[ScenarioResult],
    rules: Mapping[str, RuleInfo],
    rules_metrics: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    tp = sum(m["tp"] for m in rules_metrics.values())
    fp = sum(m["fp"] for m in rules_metrics.values())
    fn = sum(m["fn"] for m in rules_metrics.values())
    benign = [r for r in results if r.kind == KIND_BENIGN]
    benign_events = sum(r.events for r in benign)
    benign_alerts = sum(len(r.alerts) for r in benign)
    fp_per_1k = (
        round(benign_alerts / benign_events * 1000, _RATIO_DIGITS) if benign_events else 0.0
    )
    expected_by_attacks: set[str] = set()
    for res in results:
        if res.kind == KIND_ATTACK:
            expected_by_attacks.update(res.expected_rules)
    return {
        "scenarios_total": len(results),
        "scenarios_passed": sum(1 for r in results if r.passed),
        "attack_scenarios": sum(1 for r in results if r.kind == KIND_ATTACK),
        "benign_scenarios": len(benign),
        "attack_recall": _ratio(tp, tp + fn),
        "precision": _ratio(tp, tp + fp),
        "benign_events": benign_events,
        "benign_alerts": benign_alerts,
        "fp_per_1k_benign_events": fp_per_1k,
        "uncovered_rules": sorted(set(rules) - expected_by_attacks),
    }


def _risk_block(alerts: Iterable[AlertOutcome]) -> dict[str, Any]:
    items = list(alerts)
    scores = [a.risk_score for a in items]
    by_level = {level: 0 for level in RISK_LEVEL_ORDER}
    for alert in items:
        if alert.risk_level in by_level:
            by_level[alert.risk_level] += 1
    return {
        "alerts": len(items),
        "min": round(min(scores), _RISK_DIGITS) if scores else None,
        "max": round(max(scores), _RISK_DIGITS) if scores else None,
        "mean": round(sum(scores) / len(scores), _RISK_DIGITS) if scores else None,
        "by_level": by_level,
    }


def _risk(results: Sequence[ScenarioResult]) -> dict[str, Any]:
    return {
        kind: _risk_block(a for r in results if r.kind == kind for a in r.alerts)
        for kind in (KIND_ATTACK, KIND_BENIGN)
    }


def _mitre(
    results: Sequence[ScenarioResult], rules: Mapping[str, RuleInfo]
) -> dict[str, Any]:
    detected_rules: set[str] = set()
    for res in results:
        if res.kind == KIND_ATTACK:
            detected_rules |= _true_positives(res)

    technique_rules: dict[str, set[str]] = {}
    for rule_id, info in rules.items():
        for technique in info.mitre_techniques:
            technique_rules.setdefault(technique, set()).add(rule_id)

    techniques: dict[str, dict[str, Any]] = {}
    for technique in sorted(technique_rules):
        members = technique_rules[technique]
        techniques[technique] = {
            "rules": sorted(members),
            "detected": bool(members & detected_rules),
        }
    return {
        "techniques": techniques,
        "covered": sum(1 for t in techniques.values() if t["detected"]),
        "total": len(techniques),
    }


def compute_metrics(
    results: Sequence[ScenarioResult],
    rules: Mapping[str, RuleInfo],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Return ``(rules_metrics, summary, risk, mitre)`` for *results*.

    Pure and deterministic: the same inputs always yield identical output.
    """
    rules_metrics = _rule_metrics(results, rules)
    summary = _summary(results, rules, rules_metrics)
    return rules_metrics, summary, _risk(results), _mitre(results, rules)
