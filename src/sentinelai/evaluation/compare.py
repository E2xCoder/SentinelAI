"""Baseline regression gate.

Compares a freshly produced ``EvalReport.to_dict()`` document against a
committed baseline and reports every metric that got worse. Performance
numbers are deliberately ignored.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelai.core.exceptions import EvaluationError

#: Tolerance for float comparisons.
_EPS = 1e-9


@dataclass(frozen=True, slots=True)
class Thresholds:
    """Allowed degradation before a change counts as a regression."""

    #: Max tolerated recall drop (0..1 units).
    max_recall_drop: float = 0.0
    #: Max tolerated rise of ``fp_per_1k_benign_events``.
    max_fp_increase: float = 0.0

    def __post_init__(self) -> None:
        for field_name in ("max_recall_drop", "max_fp_increase"):
            value = getattr(self, field_name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                raise EvaluationError(
                    f"Threshold {field_name} must be a finite number >= 0, got {value!r}"
                )


@dataclass(frozen=True, slots=True)
class Regression:
    """One detected regression."""

    kind: str
    subject: str
    message: str


def load_baseline(path: Path) -> dict[str, Any]:
    """Load a baseline JSON report; raise :class:`EvaluationError` if unusable."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise EvaluationError(f"Baseline not found: {path}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise EvaluationError(f"Cannot read baseline {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EvaluationError(f"Baseline {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise EvaluationError(f"Baseline {path} must be a JSON object")
    required: tuple[tuple[str, type[Any]], ...] = (
        ("schema_version", int),
        ("summary", dict),
        ("rules", dict),
        ("scenarios", list),
    )
    for key, expected in required:
        if key not in data:
            raise EvaluationError(f"Baseline {path} is missing required key {key!r}")
        value = data[key]
        if not isinstance(value, expected) or isinstance(value, bool):
            raise EvaluationError(
                f"Baseline {path} has invalid {key!r}: expected {expected.__name__}"
            )
    return data


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _check_recall(
    subject: str, old: Any, new: Any, thresholds: Thresholds
) -> Regression | None:
    old_f = _as_float(old)
    if old_f is None:
        return None
    new_f = _as_float(new)
    if new_f is None or old_f - new_f > thresholds.max_recall_drop + _EPS:
        return Regression(
            "recall",
            subject,
            f"recall dropped for {subject}: {_fmt(old_f)} -> {_fmt(new_f)}",
        )
    return None


def _check_fp(old: Any, new: Any, thresholds: Thresholds) -> Regression | None:
    old_f = _as_float(old)
    if old_f is None:
        return None
    new_f = _as_float(new)
    if new_f is None or new_f - old_f > thresholds.max_fp_increase + _EPS:
        return Regression(
            "false_positives",
            "overall",
            f"fp_per_1k_benign_events rose: {_fmt(old_f)} -> {_fmt(new_f)}",
        )
    return None


def _scenarios_by_name(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    items = report.get("scenarios")
    result: dict[str, dict[str, Any]] = {}
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                result[item["name"]] = item
    return result


def _scenario_detail(scenario: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("missing_rules", "unexpected_rules"):
        value = scenario.get(key)
        if isinstance(value, list) and value:
            parts.append(f"{key}={sorted(str(v) for v in value)}")
    if scenario.get("risk_ok") is False:
        parts.append("risk_ok=False")
    return f" ({', '.join(parts)})" if parts else ""


def compare_reports(
    current: dict[str, Any], baseline: dict[str, Any], thresholds: Thresholds
) -> list[Regression]:
    """Return all regressions of ``current`` versus ``baseline`` in a stable order."""
    found: list[Regression] = []

    old_schema = baseline.get("schema_version")
    new_schema = current.get("schema_version")
    if old_schema != new_schema:
        found.append(
            Regression(
                "schema",
                "schema_version",
                f"schema_version changed: {old_schema} -> {new_schema}",
            )
        )

    old_ai = baseline.get("ai_used")
    new_ai = current.get("ai_used")
    if isinstance(old_ai, bool) and isinstance(new_ai, bool) and old_ai != new_ai:
        found.append(
            Regression(
                "ai_used",
                "ai_used",
                f"ai_used changed: {old_ai} -> {new_ai} (results are not comparable)",
            )
        )

    old_summary = _as_dict(baseline.get("summary"))
    new_summary = _as_dict(current.get("summary"))

    reg = _check_recall(
        "overall", old_summary.get("attack_recall"), new_summary.get("attack_recall"), thresholds
    )
    if reg is not None:
        found.append(reg)

    old_rules = _as_dict(baseline.get("rules"))
    new_rules = _as_dict(current.get("rules"))
    for rule_id in sorted(old_rules):
        reg = _check_recall(
            rule_id,
            _as_dict(old_rules[rule_id]).get("recall"),
            _as_dict(new_rules.get(rule_id)).get("recall"),
            thresholds,
        )
        if reg is not None:
            found.append(reg)

    fp_reg = _check_fp(
        old_summary.get("fp_per_1k_benign_events"),
        new_summary.get("fp_per_1k_benign_events"),
        thresholds,
    )
    if fp_reg is not None:
        found.append(fp_reg)

    old_scenarios = _scenarios_by_name(baseline)
    new_scenarios = _scenarios_by_name(current)
    for name in sorted(old_scenarios):
        if old_scenarios[name].get("passed") is not True:
            continue
        if name not in new_scenarios:
            found.append(
                Regression(
                    "scenario_missing",
                    name,
                    f"scenario missing from current report: {name} (baseline: passed)",
                )
            )
        elif new_scenarios[name].get("passed") is not True:
            found.append(
                Regression(
                    "scenario",
                    name,
                    f"scenario regressed: {name} passed -> failed"
                    f"{_scenario_detail(new_scenarios[name])}",
                )
            )
    # Baseline scenarios that were already failing but are now gone are still missing.
    for name in sorted(old_scenarios):
        if old_scenarios[name].get("passed") is not True and name not in new_scenarios:
            found.append(
                Regression(
                    "scenario_missing",
                    name,
                    f"scenario missing from current report: {name} (baseline: failed)",
                )
            )
    return found
