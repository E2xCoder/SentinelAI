"""Scenario loading and benchmark execution for the evaluation harness.

Scenarios are directories containing log files and a strictly validated
``labels.yaml``. Each scenario runs through a fresh, isolated
:class:`~sentinelai.core.pipeline.AnalysisPipeline` (no threat intel, no
automatic response, no plugins) so results are deterministic and the run
never touches the operator's real state directory.
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import yaml

import sentinelai.detection.rules  # noqa: F401  (registers the built-in rules)
from sentinelai import __version__
from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import EvaluationError
from sentinelai.core.models import LogEvent
from sentinelai.core.pipeline import AnalysisPipeline
from sentinelai.detection.base import available_rules
from sentinelai.evaluation.metrics import compute_metrics
from sentinelai.evaluation.models import (
    KIND_ATTACK,
    KIND_BENIGN,
    RISK_LEVEL_ORDER,
    VALID_KINDS,
    AlertOutcome,
    EvalReport,
    RuleInfo,
    Scenario,
    ScenarioLabel,
    ScenarioResult,
)
from sentinelai.parsers.reader import read_events
from sentinelai.utils.logging import get_logger

_log = get_logger(__name__)

LABELS_FILENAME = "labels.yaml"

#: Rule ID of the AI anomaly alerts, which are not in the rule registry.
AI_RULE_ID = "AI001"

_TOP_LEVEL_KEYS = frozenset({"name", "kind", "description", "files", "expect", "forbid"})
_EXPECT_KEYS = frozenset({"rules", "min_risk_level"})
_FORBID_KEYS = frozenset({"rules"})


def _fail(scenario: str, message: str) -> EvaluationError:
    return EvaluationError(f"Scenario {scenario!r}: {message}")


def _read_yaml(path: Path, scenario: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise _fail(scenario, f"cannot read {LABELS_FILENAME}: {exc}") from exc
    if not isinstance(data, dict):
        raise _fail(scenario, f"{LABELS_FILENAME} must contain a mapping")
    return data


def _section(
    data: dict[str, Any], key: str, allowed: frozenset[str], scenario: str
) -> dict[str, Any]:
    raw = data.get(key)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise _fail(scenario, f"{key!r} must be a mapping")
    unknown = sorted(str(k) for k in raw if k not in allowed)
    if unknown:
        raise _fail(scenario, f"unknown keys in {key!r}: {', '.join(unknown)}")
    return raw


def _string_list(value: object, field_name: str, scenario: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise _fail(scenario, f"{field_name!r} must be a list of non-empty strings")
    return tuple(value)


def _rule_ids(value: object, field_name: str, scenario: str) -> tuple[str, ...]:
    ids = _string_list(value, field_name, scenario)
    known = set(available_rules()) | {AI_RULE_ID}
    for rule_id in ids:
        if rule_id not in known:
            raise _fail(scenario, f"{field_name!r} references unknown rule {rule_id!r}")
    return tuple(sorted(set(ids)))


def _validate_files(files: tuple[str, ...], directory: Path, scenario: str) -> None:
    if not files:
        raise _fail(scenario, "'files' must be a non-empty list")
    base = directory.resolve()
    for name in files:
        if Path(name).is_absolute() or Path(name).drive or ".." in Path(name).parts:
            raise _fail(scenario, f"file {name!r} must be a relative path inside the scenario")
        resolved = (directory / name).resolve()
        if not resolved.is_relative_to(base):
            raise _fail(scenario, f"file {name!r} escapes the scenario directory")
        if not resolved.is_file():
            raise _fail(scenario, f"file {name!r} does not exist")


def _load_label(directory: Path) -> ScenarioLabel:
    scenario = directory.name
    data = _read_yaml(directory / LABELS_FILENAME, scenario)

    unknown = sorted(str(k) for k in data if k not in _TOP_LEVEL_KEYS)
    if unknown:
        raise _fail(scenario, f"unknown top-level keys: {', '.join(unknown)}")

    name = data.get("name")
    if name != scenario:
        raise _fail(scenario, f"name {name!r} must equal the directory name")
    kind = data.get("kind")
    if kind not in VALID_KINDS:
        raise _fail(scenario, f"kind must be one of: {', '.join(VALID_KINDS)}")
    description = data.get("description", "")
    if not isinstance(description, str):
        raise _fail(scenario, "'description' must be a string")

    files = _string_list(data.get("files"), "files", scenario)
    _validate_files(files, directory, scenario)

    expect = _section(data, "expect", _EXPECT_KEYS, scenario)
    forbid = _section(data, "forbid", _FORBID_KEYS, scenario)
    expect_rules = _rule_ids(expect.get("rules"), "expect.rules", scenario)
    forbid_rules = _rule_ids(forbid.get("rules"), "forbid.rules", scenario)

    if kind == KIND_BENIGN and expect_rules:
        raise _fail(scenario, "benign scenarios must not have expect.rules")
    if kind == KIND_ATTACK and not expect_rules:
        raise _fail(scenario, "attack scenarios require a non-empty expect.rules")

    min_risk_level = expect.get("min_risk_level")
    if min_risk_level is not None:
        if min_risk_level not in RISK_LEVEL_ORDER:
            raise _fail(
                scenario,
                f"expect.min_risk_level must be one of: {', '.join(RISK_LEVEL_ORDER)}",
            )
        if kind == KIND_BENIGN:
            raise _fail(scenario, "benign scenarios must not set expect.min_risk_level")

    return ScenarioLabel(
        name=scenario,
        kind=str(kind),
        description=description,
        files=files,
        expect_rules=expect_rules,
        min_risk_level=min_risk_level,
        forbid_rules=forbid_rules,
    )


def load_scenarios(root: Path) -> list[Scenario]:
    """Load and strictly validate every scenario directly under *root*."""
    if not root.is_dir():
        raise EvaluationError(f"Benchmark directory not found: {root}")
    directories = sorted(
        (d for d in root.iterdir() if d.is_dir() and (d / LABELS_FILENAME).is_file()),
        key=lambda d: d.name,
    )
    if not directories:
        raise EvaluationError(f"No scenarios (directories with {LABELS_FILENAME}) in {root}")
    return [Scenario(label=_load_label(d), directory=d) for d in directories]


def _chain_events(scenario: Scenario) -> Iterator[LogEvent]:
    for name in scenario.label.files:
        yield from read_events(scenario.directory / name)


def _build_config(scenario: Scenario, state_root: Path) -> SentinelConfig:
    scenario_state = state_root / scenario.label.name
    config = SentinelConfig()
    config.state_dir = str(scenario_state)
    config.intel.enabled = False
    config.response.enabled = False
    config.report.output_dir = str(scenario_state / "reports")
    config.validate()
    return config


def _risk_reached(outcomes: list[AlertOutcome], label: ScenarioLabel) -> bool:
    if label.min_risk_level is None:
        return True
    threshold = RISK_LEVEL_ORDER.index(label.min_risk_level)
    expected = set(label.expect_rules)
    return any(
        o.rule_id in expected and RISK_LEVEL_ORDER.index(o.risk_level) >= threshold
        for o in outcomes
    )


def run_scenario(scenario: Scenario, state_root: Path) -> tuple[ScenarioResult, bool]:
    """Run one scenario; return its result and whether AI anomaly detection ran."""
    label = scenario.label
    pipeline: AnalysisPipeline | None = None
    try:
        pipeline = AnalysisPipeline(_build_config(scenario, state_root))
        scan = pipeline.run_scan(_chain_events(scenario), use_ai=True)
    finally:
        if pipeline is not None:
            try:
                pipeline.close()
            except Exception as exc:
                _log.warning("Failed to close pipeline for scenario %s: %s", label.name, exc)

    outcomes = sorted(
        (AlertOutcome(a.rule_id, a.risk.score, a.risk.level.value) for a in scan.alerts),
        key=lambda o: (o.rule_id, o.risk_score),
    )
    fired = {o.rule_id for o in outcomes}
    expected = set(label.expect_rules)
    unexpected = fired if label.kind == KIND_BENIGN else fired & set(label.forbid_rules)

    result = ScenarioResult(
        name=label.name,
        kind=label.kind,
        events=scan.statistics.total_events,
        alerts=outcomes,
        fired_rules=sorted(fired),
        expected_rules=sorted(expected),
        missing_rules=sorted(expected - fired),
        unexpected_rules=sorted(unexpected),
        risk_ok=_risk_reached(outcomes, label),
    )
    return result, scan.ai_used


def _rule_catalog() -> Mapping[str, RuleInfo]:
    return {
        rule_id: RuleInfo(rule_id, cls.name, tuple(cls.mitre_techniques))
        for rule_id, cls in sorted(available_rules().items())
    }


def run_benchmark(root: Path) -> EvalReport:
    """Run every scenario under *root* and aggregate the metrics."""
    scenarios = load_scenarios(root)
    results: list[ScenarioResult] = []
    ai_used = False
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        state_root = Path(tmp)
        started = time.perf_counter()
        for scenario in scenarios:
            result, used_ai = run_scenario(scenario, state_root)
            results.append(result)
            ai_used = ai_used or used_ai
        elapsed = time.perf_counter() - started

    rules, summary, risk, mitre = compute_metrics(results, _rule_catalog())
    total_events = sum(r.events for r in results)
    performance: dict[str, Any] = {
        "events": total_events,
        "seconds": round(elapsed, 3),
        "events_per_sec": round(total_events / elapsed, 1) if elapsed > 0 else 0.0,
    }
    return EvalReport(
        version=__version__,
        ai_used=ai_used,
        scenarios=results,
        rules=rules,
        summary=summary,
        risk=risk,
        mitre=mitre,
        performance=performance,
    )
