"""Gate that every tuning proposal must pass before it may be applied.

Order: policy limits, frozen benchmark (no recall/scenario regression), then
the analyst's own feedback (fewer loud false positives, no true positive lost).
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path

from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import ConfigError, SentinelError
from sentinelai.core.store import FeedbackEntry
from sentinelai.evaluation.compare import Thresholds, compare_reports
from sentinelai.evaluation.manifest import verify_manifest
from sentinelai.evaluation.models import EvalReport
from sentinelai.evaluation.runner import run_benchmark
from sentinelai.tuning.models import THRESHOLD_SPECS, GateResult, Proposal
from sentinelai.tuning.overlay import apply_patch
from sentinelai.tuning.policy import check_proposal
from sentinelai.tuning.replay import ReplayContext

_BLOCKING_KINDS = frozenset({"recall", "scenario", "scenario_missing"})


def _configure_with(source: SentinelConfig) -> Callable[[SentinelConfig], None]:
    """Build a ``configure`` hook that copies detection/risk settings into a scenario."""

    def configure(scenario_config: SentinelConfig) -> None:
        scenario_config.detection = copy.deepcopy(source.detection)
        scenario_config.risk = copy.deepcopy(source.risk)

    return configure


def _recall(report: EvalReport) -> float | None:
    value = report.summary.get("attack_recall")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"


def _rejected(ids: tuple[str, ...], reasons: list[str]) -> GateResult:
    return GateResult(proposal_ids=ids, accepted=False, reasons=reasons)


def _tp_lost(
    entry: FeedbackEntry,
    config: SentinelConfig,
    candidate: SentinelConfig,
    before: ReplayContext,
    after: ReplayContext,
) -> bool:
    """True if a true-positive-labelled alert would be lost (or cannot be proven kept)."""
    if before.would_alert(entry) and not after.would_alert(entry):
        return True
    spec = THRESHOLD_SPECS.get(entry.rule_id)
    if spec is None or not after.threshold_unverifiable(entry):
        return False
    return bool(getattr(candidate.detection, spec.field) > getattr(config.detection, spec.field))


def evaluate(
    proposals: Sequence[Proposal],
    config: SentinelConfig,
    feedback: Sequence[FeedbackEntry],
    benchmarks_root: Path,
    *,
    force: bool = False,
    now: datetime | None = None,
) -> GateResult:
    """Gate ``proposals`` (applied together, in order) against ``config``."""
    moment = now if now is not None else datetime.now(timezone.utc)
    ids = tuple(p.id for p in proposals)

    # 1. Something to evaluate.
    if not proposals:
        return _rejected(ids, ["nothing to evaluate"])

    # 2. Policy limits.
    violations = [
        f"{p.id}: {message}"
        for p in proposals
        for message in check_proposal(p, config, force=force, now=moment)
    ]
    if violations:
        return _rejected(ids, violations)

    # 3. Frozen benchmark must exist.
    scenarios_dir = benchmarks_root / "scenarios"
    if not scenarios_dir.is_dir():
        return _rejected(
            ids,
            [
                f"frozen benchmark not found at {scenarios_dir}; "
                "refusing to apply unverified changes"
            ],
        )

    # 4. Candidate configuration.
    candidate = config
    try:
        for proposal in proposals:
            candidate = apply_patch(candidate, proposal.patch)
    except ConfigError as exc:
        return _rejected(ids, [str(exc)])

    result = GateResult(proposal_ids=ids, accepted=False)
    reasons = result.reasons

    # 5. Frozen benchmark: before vs. after.
    try:
        problems = verify_manifest(benchmarks_root)
        if problems:
            return _rejected(
                ids,
                ["frozen benchmark failed verification: " + "; ".join(problems[:3])],
            )
        before = run_benchmark(scenarios_dir, configure=_configure_with(config))
        summary = before.summary
        if (
            not summary.get("scenarios_total")
            or not summary.get("attack_scenarios")
            or summary.get("attack_recall") is None
        ):
            return _rejected(ids, ["benchmark has no attack scenarios"])
        failing = [s.name for s in before.scenarios if not s.passed]
        if failing:
            return _rejected(
                ids,
                [
                    "benchmark already failing under the current configuration: "
                    + ", ".join(failing)
                    + "; fix that before tuning"
                ],
            )
        after = run_benchmark(scenarios_dir, configure=_configure_with(candidate))
        regressions = compare_reports(
            after.to_dict(include_performance=False),
            before.to_dict(include_performance=False),
            Thresholds(),
        )
    except SentinelError as exc:
        return _rejected(ids, [str(exc)])

    result.benchmark_recall_before = _recall(before)
    result.benchmark_recall_after = _recall(after)
    for regression in regressions:
        if regression.kind in _BLOCKING_KINDS:
            result.benchmark_regressions.append(f"{regression.kind}: {regression.subject}")
    benchmark_ok = not result.benchmark_regressions
    if not benchmark_ok:
        reasons.append(
            "benchmark regressions: " + "; ".join(result.benchmark_regressions)
        )

    # 6. Analyst feedback replay.
    feedback_ok = False
    if not feedback:
        reasons.append("no analyst feedback to verify against")
    else:
        current_ctx = ReplayContext(config, moment)
        candidate_ctx = ReplayContext(candidate, moment)
        result.fp_before = sum(
            1 for e in feedback if e.label == "fp" and current_ctx.alerts_loudly(e)
        )
        result.fp_after = sum(
            1 for e in feedback if e.label == "fp" and candidate_ctx.alerts_loudly(e)
        )
        result.tp_lost = sum(
            1
            for e in feedback
            if e.label == "tp" and _tp_lost(e, config, candidate, current_ctx, candidate_ctx)
        )
        feedback_ok = True
        if result.tp_lost > 0:
            feedback_ok = False
            reasons.append(f"{result.tp_lost} analyst-confirmed true positive(s) would be lost")
        if result.fp_after >= result.fp_before:
            feedback_ok = False
            reasons.append(
                "false positives did not measurably decrease "
                f"({result.fp_before} -> {result.fp_after})"
            )

    # 7. Verdict.
    if benchmark_ok and feedback_ok:
        result.accepted = True
        recall_text = _fmt(result.benchmark_recall_after)
        reasons.append(f"benchmark attack recall unchanged at {recall_text}")
        reasons.append(f"analyst false positives {result.fp_before} -> {result.fp_after}")
        reasons.append("no analyst-confirmed true positive lost")
    return result
