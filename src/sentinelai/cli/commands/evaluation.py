"""Evaluation command: ``sentinel eval`` runs the frozen detection benchmark.

The command is fully offline: it loads no plugins and makes no network
calls. It verifies the benchmark manifest, runs every scenario through an
isolated pipeline, renders the metrics, and optionally gates the result
against a committed baseline.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from sentinelai.cli import console as ui
from sentinelai.cli.common import fail, load_context
from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import EvaluationError, SentinelError
from sentinelai.detection.base import Rule
from sentinelai.evaluation.compare import Regression, Thresholds, compare_reports, load_baseline
from sentinelai.evaluation.manifest import verify_manifest, write_manifest
from sentinelai.evaluation.models import EvalReport, ScenarioResult
from sentinelai.evaluation.runner import load_scenarios, run_benchmark
from sentinelai.evaluation.triage_eval import run_triage_eval

ConfigureFn = Callable[[SentinelConfig], None]


def _pct(value: object) -> str:
    """Format a 0..1 ratio as a percentage; ``-`` when undefined."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "-"
    return f"{value * 100:.1f}%"


def _join(items: list[str]) -> str:
    return ", ".join(items) if items else "-"


def _write_json(path: Path, data: dict[str, Any]) -> None:
    """Write *data* as UTF-8 JSON with LF line endings and a trailing newline."""
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    except OSError as exc:
        raise EvaluationError(f"Cannot write {path}: {exc}") from exc


def _check_manifest(root: Path) -> None:
    problems = verify_manifest(root)
    if not problems:
        return
    for problem in problems:
        ui.error_console.print(f"  [red]{escape(problem)}[/red]")
    raise EvaluationError(
        "The frozen benchmark changed (manifest mismatch). Rerun with --update-manifest "
        "only if the change is intentional."
    )


def _details(result: ScenarioResult) -> str:
    parts: list[str] = []
    if result.missing_rules:
        parts.append("missing: " + ", ".join(result.missing_rules))
    if result.unexpected_rules:
        parts.append("unexpected: " + ", ".join(result.unexpected_rules))
    if not result.risk_ok:
        parts.append("risk below minimum")
    return "; ".join(parts) if parts else "-"


def _scenarios_table(report: EvalReport) -> Table:
    table = Table(title="Scenarios", header_style="bold")
    table.add_column("Scenario")
    table.add_column("Kind")
    table.add_column("Events", justify="right")
    table.add_column("Fired rules")
    table.add_column("Result")
    table.add_column("Missing / unexpected")
    for result in report.scenarios:
        status = "[green]PASS[/green]" if result.passed else "[bold red]FAIL[/bold red]"
        table.add_row(
            escape(result.name),
            escape(result.kind),
            f"{result.events:,}",
            escape(_join(result.fired_rules)),
            status,
            escape(_details(result)),
        )
    return table


def _rules_table(report: EvalReport) -> Table:
    table = Table(title="Per-rule metrics", header_style="bold")
    table.add_column("Rule")
    table.add_column("TP", justify="right")
    table.add_column("FP", justify="right")
    table.add_column("FN", justify="right")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    for rule_id, metrics in sorted(report.rules.items()):
        table.add_row(
            escape(str(rule_id)),
            str(metrics.get("tp", 0)),
            str(metrics.get("fp", 0)),
            str(metrics.get("fn", 0)),
            _pct(metrics.get("precision")),
            _pct(metrics.get("recall")),
        )
    return table


def _summary_panel(report: EvalReport) -> Panel:
    summary = report.summary
    uncovered = [str(r) for r in summary.get("uncovered_rules", [])]
    lines = [
        f"[bold]Scenarios passed:[/bold] {summary.get('scenarios_passed', 0)}"
        f"/{summary.get('scenarios_total', 0)}",
        f"[bold]Attack recall:[/bold] {_pct(summary.get('attack_recall'))}",
        f"[bold]Precision:[/bold] {_pct(summary.get('precision'))}",
        f"[bold]FP per 1k benign events:[/bold] "
        f"{summary.get('fp_per_1k_benign_events', 0.0):.2f}",
        f"[bold]Uncovered rules:[/bold] {len(uncovered)}"
        + (f" ({escape(', '.join(uncovered))})" if uncovered else ""),
        f"[bold]MITRE techniques covered:[/bold] "
        f"{report.mitre.get('covered', 0)}/{report.mitre.get('total', 0)}",
        f"[bold]Throughput:[/bold] "
        f"{report.performance.get('events_per_sec', 0.0):,.1f} events/sec",
    ]
    return Panel("\n".join(lines), title="Evaluation Summary", border_style="cyan")


def _print_regressions(regressions: list[Regression], *, to_stderr: bool) -> None:
    out = ui.error_console if to_stderr else ui.console
    if not regressions:
        out.print("[green]No regressions against baseline.[/green]")
        return
    out.print(f"[bold red]{len(regressions)} regression(s) against baseline:[/bold red]")
    for reg in regressions:
        out.print(f"  [red]{escape(reg.kind)}[/red] {escape(reg.message)}")


def _triage_table(data: dict[str, Any]) -> Table:
    latency = data.get("latency", {})
    table = Table(title="LLM triage (advisory)", header_style="bold")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Model", escape(f"{data.get('provider', '-')}/{data.get('model', '-')}"))
    table.add_row("Alerts triaged", str(data.get("alerts", 0)))
    table.add_row("Valid-answer rate", _pct(data.get("schema_valid_rate")))
    table.add_row("Agreement (not benign)", _pct(data.get("agreement_rate")))
    table.add_row("Malicious rate", _pct(data.get("malicious_rate")))
    table.add_row("Fallbacks (template)", _pct(data.get("fallback_rate")))
    table.add_row("Latency p50", f"{float(latency.get('p50', 0.0)):.2f}s")
    table.add_row("Latency p95", f"{float(latency.get('p95', 0.0)):.2f}s")
    rejections = data.get("rejections", {})
    for reason, count in list(rejections.items())[:5]:
        table.add_row(f"Rejected: {escape(str(reason))}", str(count))
    return table


def _require_triage_llm(config: SentinelConfig) -> None:
    if not config.ai.llm.enabled:
        raise EvaluationError(
            "--triage needs the LLM to be enabled. Set ai.llm.enabled: true (plus "
            "ai.llm.model and ai.llm.endpoint) in config.yaml. Nothing was sent anywhere."
        )


def _run_triage(
    config: SentinelConfig,
    benchmarks: Path,
    limit: int,
    output: Path | None,
    *,
    to_stderr: bool,
) -> None:
    data = run_triage_eval(benchmarks / "scenarios", config.ai.llm, limit=limit)
    out = ui.error_console if to_stderr else ui.console
    out.print(_triage_table(data))
    out.print("[dim]Triage verdicts are advisory and do not affect the exit code.[/dim]")
    if output is not None:
        _write_json(output, data)


def _load_sigma(directory: Path, *, to_stderr: bool) -> tuple[list[Rule], ConfigureFn]:
    """Load Sigma rules for the benchmark; return them plus a config callback enabling them."""
    from sentinelai.sigma import load_rules

    try:
        loaded = load_rules(directory)
    except OSError as exc:
        raise EvaluationError(f"Cannot load Sigma rules from {directory}: {exc}") from exc
    out = ui.error_console if to_stderr else ui.console
    out.print(
        f"[bold]Sigma rules:[/bold] {len(loaded.rules)} loaded, "
        f"{len(loaded.unsupported)} unsupported "
        f"({loaded.files_scanned} file(s) scanned in {ui._safe(directory)})"
    )
    rules_dir = str(directory)

    def configure(config: SentinelConfig) -> None:
        config.sigma.enabled = True
        config.sigma.rules_dir = rules_dir

    return list(loaded.rules), configure


@click.command("eval")
@click.option(
    "--benchmarks",
    "benchmarks",
    type=click.Path(path_type=Path),
    default=Path("benchmarks"),
    show_default=True,
    help="Benchmark root containing scenarios/.",
)
@click.option(
    "--baseline",
    type=click.Path(path_type=Path),
    help="Compare against this baseline JSON and fail on regressions.",
)
@click.option(
    "--write-baseline",
    type=click.Path(path_type=Path),
    help="Write the deterministic report (no performance data) to this path.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    help="Write the full JSON report (with performance) to this path.",
)
@click.option(
    "--update-manifest",
    is_flag=True,
    help="Rewrite MANIFEST.sha256 instead of verifying it (intentional changes only).",
)
@click.option(
    "--max-recall-drop",
    type=float,
    default=0.0,
    show_default=True,
    help="Tolerated recall drop (0..1) before it counts as a regression.",
)
@click.option(
    "--max-fp-increase",
    type=float,
    default=0.0,
    show_default=True,
    help="Tolerated rise of FP per 1k benign events.",
)
@click.option("--json", "as_json", is_flag=True, help="Print the JSON report to stdout.")
@click.option(
    "--sigma-rules",
    "sigma_rules_dir",
    type=click.Path(path_type=Path),
    help="Also score the Sigma rules in this directory (enabled for every scenario).",
)
@click.option(
    "--triage",
    is_flag=True,
    help="Also triage attack-scenario alerts with the configured LLM (advisory, needs ai.llm).",
)
@click.option(
    "--triage-limit",
    type=click.IntRange(min=1),
    default=25,
    show_default=True,
    help="Maximum number of alerts to triage.",
)
@click.option(
    "--triage-output",
    type=click.Path(path_type=Path),
    help="Write the triage evaluation JSON to this path.",
)
@click.pass_context
def eval_cmd(
    ctx: click.Context,
    benchmarks: Path,
    baseline: Path | None,
    write_baseline: Path | None,
    output: Path | None,
    update_manifest: bool,
    max_recall_drop: float,
    max_fp_increase: float,
    as_json: bool,
    sigma_rules_dir: Path | None,
    triage: bool,
    triage_limit: int,
    triage_output: Path | None,
) -> None:
    """Run the frozen detection benchmark and report precision/recall."""
    regressions: list[Regression] = []
    config = load_context(ctx).config
    try:
        if triage:
            _require_triage_llm(config)
        thresholds = Thresholds(max_recall_drop=max_recall_drop, max_fp_increase=max_fp_increase)
        if update_manifest:
            # Validate the benchmark first so an invalid one never gets a fresh manifest.
            load_scenarios(benchmarks / "scenarios")
            manifest_path = write_manifest(benchmarks)
            ui.error_console.print(
                f"[yellow]Manifest rewritten:[/yellow] {escape(str(manifest_path))}"
            )
        else:
            _check_manifest(benchmarks)

        configure: ConfigureFn | None = None
        sigma_rules: list[Rule] = []
        if sigma_rules_dir is not None:
            sigma_rules, configure = _load_sigma(sigma_rules_dir, to_stderr=as_json)

        if configure is None and not sigma_rules:
            report = run_benchmark(benchmarks / "scenarios")
        else:
            report = run_benchmark(
                benchmarks / "scenarios", configure=configure, sigma_rules=sigma_rules
            )
        failed = any(not s.passed for s in report.scenarios)

        if as_json:
            click.echo(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        else:
            ui.console.print(_scenarios_table(report))
            ui.console.print(_rules_table(report))
            ui.console.print(_summary_panel(report))

        if output is not None:
            _write_json(output, report.to_dict())
        if write_baseline is not None:
            if failed:
                ui.error_console.print(
                    "[bold red]Error:[/bold red] baseline NOT written to "
                    f"{escape(str(write_baseline))} because scenarios fail."
                )
            else:
                _write_json(write_baseline, report.to_dict(include_performance=False))

        if baseline is not None:
            regressions = compare_reports(
                report.to_dict(), load_baseline(baseline), thresholds
            )
            _print_regressions(regressions, to_stderr=as_json)

        if triage:
            _run_triage(config, benchmarks, triage_limit, triage_output, to_stderr=as_json)
    except SentinelError as exc:
        fail(exc)

    if failed or regressions:
        sys.exit(1)
