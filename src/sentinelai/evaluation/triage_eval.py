"""Informational LLM triage evaluation over the attack scenarios.

Every alert raised by an attack scenario is a true detection, so a triage
verdict of "benign" is counted as a disagreement with the label. The numbers
are advisory only: they never feed the deterministic regression report.
"""

from __future__ import annotations

import math
import tempfile
from collections import Counter
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from sentinelai.ai.triage_engine import TriageEngine
from sentinelai.ai.triage_models import VERDICTS, TriageOutcome
from sentinelai.config.models import LLMConfig, SentinelConfig
from sentinelai.core.models import Alert, LogEvent
from sentinelai.core.pipeline import AnalysisPipeline
from sentinelai.evaluation.models import KIND_ATTACK, Scenario
from sentinelai.evaluation.runner import load_scenarios
from sentinelai.parsers.reader import read_events
from sentinelai.utils.logging import get_logger

_log = get_logger(__name__)

_MAX_REJECTIONS = 10
_MAX_REASON_CHARS = 80


def percentile(values: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile of *values* (``0.0`` when empty)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100.0 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def _ratio(part: int, total: int) -> float:
    return round(part / total, 4) if total else 0.0


def _short_reason(reason: str) -> str:
    text = " ".join(reason.split())
    if len(text) > _MAX_REASON_CHARS:
        text = text[: _MAX_REASON_CHARS - 3] + "..."
    return text


def _events(scenario: Scenario) -> Iterator[LogEvent]:
    for name in scenario.label.files:
        yield from read_events(scenario.directory / name)


def _isolated_config(scenario: Scenario, state_root: Path) -> SentinelConfig:
    state = state_root / scenario.label.name
    config = SentinelConfig()
    config.state_dir = str(state)
    config.intel.enabled = False
    config.response.enabled = False
    config.report.output_dir = str(state / "reports")
    config.validate()
    return config


def _scenario_alerts(scenario: Scenario, state_root: Path) -> list[Alert]:
    pipeline: AnalysisPipeline | None = None
    try:
        pipeline = AnalysisPipeline(_isolated_config(scenario, state_root))
        scan = pipeline.run_scan(_events(scenario), use_ai=False)
        return list(scan.alerts)
    finally:
        if pipeline is not None:
            try:
                pipeline.close()
            except Exception as exc:
                _log.warning(
                    "Failed to close pipeline for scenario %s: %s", scenario.label.name, exc
                )


def _collect_alerts(root: Path, limit: int | None) -> list[tuple[str, Alert]]:
    scenarios = [s for s in load_scenarios(root) if s.label.kind == KIND_ATTACK]
    collected: list[tuple[str, Alert]] = []
    cap = None if limit is None else max(0, limit)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        for scenario in scenarios:
            if cap is not None and len(collected) >= cap:
                break
            for alert in _scenario_alerts(scenario, Path(tmp)):
                if cap is not None and len(collected) >= cap:
                    break
                collected.append((scenario.label.name, alert))
    return collected


def _per_alert(scenario: str, rule_id: str, outcome: TriageOutcome) -> dict[str, Any]:
    return {
        "scenario": scenario,
        "rule_id": rule_id,
        "verdict": outcome.result.verdict,
        "confidence": round(outcome.result.confidence, 4),
        "source": outcome.source,
        "valid_llm": outcome.valid_llm,
        "attempts": outcome.attempts,
        "latency_seconds": round(outcome.latency_seconds, 4),
        "rejection": None if outcome.rejection is None else _short_reason(outcome.rejection),
    }


def _latency_stats(outcomes: Sequence[TriageOutcome]) -> dict[str, Any]:
    values = [o.latency_seconds for o in outcomes if o.source.startswith("llm:")]
    if not values:
        return {"count": 0, "mean": 0.0, "p50": 0.0, "p95": 0.0}
    return {
        "count": len(values),
        "mean": round(sum(values) / len(values), 4),
        "p50": round(percentile(values, 50), 4),
        "p95": round(percentile(values, 95), 4),
    }


def summarize(
    llm: LLMConfig, entries: Sequence[tuple[str, str, TriageOutcome]]
) -> dict[str, Any]:
    """Aggregate triage outcomes (``(scenario, rule_id, outcome)``) into the report dict."""
    outcomes = [o for _, _, o in entries]
    total = len(outcomes)
    valid = sum(1 for o in outcomes if o.valid_llm)
    fallbacks = sum(1 for o in outcomes if o.source == "template")
    verdicts = {name: 0 for name in VERDICTS}
    for outcome in outcomes:
        verdicts[outcome.result.verdict] = verdicts.get(outcome.result.verdict, 0) + 1
    agreed = verdicts.get("suspicious", 0) + verdicts.get("malicious", 0)
    reasons = Counter(_short_reason(o.rejection) for o in outcomes if o.rejection)
    top = sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:_MAX_REJECTIONS]
    return {
        "model": llm.model,
        "provider": llm.provider,
        "language": llm.language,
        "alerts": total,
        "llm_valid": valid,
        "schema_valid_rate": _ratio(valid, total),
        "fallback_rate": _ratio(fallbacks, total),
        "agreement_rate": _ratio(agreed, total),
        "malicious_rate": _ratio(verdicts.get("malicious", 0), total),
        "verdicts": verdicts,
        "latency": _latency_stats(outcomes),
        "rejections": dict(top),
        "per_alert": [_per_alert(s, r, o) for s, r, o in entries],
    }


def run_triage_eval(
    scenarios_root: Path,
    llm: LLMConfig,
    *,
    limit: int | None = None,
    engine: TriageEngine | None = None,
) -> dict[str, Any]:
    """Triage the alerts of every attack scenario and return advisory metrics."""
    alerts = _collect_alerts(scenarios_root, limit)
    owned = engine is None
    active = TriageEngine(llm) if engine is None else engine
    entries: list[tuple[str, str, TriageOutcome]] = []
    try:
        for scenario, alert in alerts:
            entries.append((scenario, alert.rule_id, active.triage(alert)))
    finally:
        if owned:
            active.close()
    return summarize(llm, entries)
