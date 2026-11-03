"""Data contracts for the evaluation harness.

A *scenario* is a directory of log files plus a ``labels.yaml`` that says
what the detection pipeline must (and must not) do with them. Running a
scenario yields a :class:`ScenarioResult`; aggregating all results yields
an :class:`EvalReport`, the JSON document that is compared against a
committed baseline to gate regressions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Bumped whenever the JSON layout of :class:`EvalReport` changes.
SCHEMA_VERSION = 1

KIND_ATTACK = "attack"
KIND_BENIGN = "benign"
VALID_KINDS = (KIND_ATTACK, KIND_BENIGN)

#: Risk levels ordered from least to most severe.
RISK_LEVEL_ORDER = ("informational", "low", "medium", "high", "critical")


@dataclass(frozen=True, slots=True)
class ScenarioLabel:
    """Parsed ``labels.yaml`` of one scenario."""

    name: str
    kind: str
    description: str
    #: Log files, relative to the scenario directory.
    files: tuple[str, ...]
    #: Rule IDs that must fire (attack scenarios only).
    expect_rules: tuple[str, ...] = ()
    #: At least one alert from ``expect_rules`` must reach this risk level.
    min_risk_level: str | None = None
    #: Rule IDs that must NOT fire. Benign scenarios forbid every rule.
    forbid_rules: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Scenario:
    """A label bound to the directory it was loaded from."""

    label: ScenarioLabel
    directory: Path


@dataclass(frozen=True, slots=True)
class RuleInfo:
    """Static facts about a registered rule, taken from the rule registry."""

    rule_id: str
    name: str
    mitre_techniques: tuple[str, ...]


@dataclass(slots=True)
class AlertOutcome:
    """The part of an alert the evaluation cares about."""

    rule_id: str
    risk_score: float
    risk_level: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level,
        }


@dataclass(slots=True)
class ScenarioResult:
    """Outcome of running one scenario through the pipeline."""

    name: str
    kind: str
    events: int
    alerts: list[AlertOutcome] = field(default_factory=list)
    #: Sorted unique rule IDs that fired.
    fired_rules: list[str] = field(default_factory=list)
    expected_rules: list[str] = field(default_factory=list)
    #: Expected rules that did not fire (false negatives).
    missing_rules: list[str] = field(default_factory=list)
    #: Rules that fired but must not have (false positives). For benign
    #: scenarios this is every rule that fired.
    unexpected_rules: list[str] = field(default_factory=list)
    #: True when ``min_risk_level`` is unset or reached by an expected alert.
    risk_ok: bool = True

    @property
    def passed(self) -> bool:
        return not self.missing_rules and not self.unexpected_rules and self.risk_ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "events": self.events,
            "alerts": [a.to_dict() for a in self.alerts],
            "fired_rules": list(self.fired_rules),
            "expected_rules": list(self.expected_rules),
            "missing_rules": list(self.missing_rules),
            "unexpected_rules": list(self.unexpected_rules),
            "risk_ok": self.risk_ok,
            "passed": self.passed,
        }


@dataclass(slots=True)
class EvalReport:
    """Full benchmark result. ``to_dict`` is the baseline JSON format.

    ``rules``, ``summary``, ``risk`` and ``mitre`` come from
    :func:`sentinelai.evaluation.metrics.compute_metrics`. ``performance``
    holds wall-clock numbers and is never part of regression comparison.
    """

    version: str
    ai_used: bool
    scenarios: list[ScenarioResult]
    rules: dict[str, dict[str, Any]]
    summary: dict[str, Any]
    risk: dict[str, Any]
    mitre: dict[str, Any]
    performance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, *, include_performance: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "sentinelai_version": self.version,
            "ai_used": self.ai_used,
            "scenarios": [s.to_dict() for s in self.scenarios],
            "rules": self.rules,
            "summary": self.summary,
            "risk": self.risk,
            "mitre": self.mitre,
        }
        if include_performance:
            data["performance"] = self.performance
        return data
