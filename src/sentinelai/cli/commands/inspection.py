"""Inspection commands: explain, report, search, rules, config, version."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.table import Table

from sentinelai import __version__
from sentinelai.cli import console as ui
from sentinelai.cli.common import build_pipeline, fail, load_context
from sentinelai.core.exceptions import SentinelError


@click.command()
@click.argument("alert_id", type=int)
@click.pass_context
def explain(ctx: click.Context, alert_id: int) -> None:
    """Explain a stored alert (AI-assisted when a local LLM is configured)."""
    from sentinelai.ai.engine import AIEngine

    context = load_context(ctx)
    pipeline = build_pipeline(context.config)
    try:
        alert = pipeline.store.get(alert_id)
        if alert is None:
            fail(SentinelError(f"No alert with id {alert_id}. Run a scan first."))
        engine = AIEngine(context.config.ai, state_dir=context.config.resolve_state_dir())
        try:
            engine.explain(alert)
        finally:
            engine.close()
        pipeline.store.update(alert)
        ui.print_alert_detail(alert)
    except SentinelError as exc:
        fail(exc)
    finally:
        pipeline.close()


@click.command()
@click.argument("report_file", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def report(ctx: click.Context, report_file: str) -> None:
    """Summarize a previously generated JSON report."""
    try:
        data = json.loads(Path(report_file).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail(SentinelError(f"Cannot read report {report_file}: {exc}"))

    summary = data.get("summary", {})
    ui.console.print(f"[bold]{data.get('title', 'Report')}[/bold]")
    ui.console.print(f"[dim]Generated {data.get('generated_at', 'n/a')}[/dim]\n")
    table = Table(header_style="bold")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Events analyzed", f"{summary.get('events_analyzed', 0):,}")
    table.add_row("Alerts", str(summary.get("alerts_total", 0)))
    table.add_row("Attack patterns", str(summary.get("attack_patterns", 0)))
    table.add_row("Unique source IPs", str(summary.get("unique_source_ips", 0)))
    ui.console.print(table)
    for level, count in summary.get("alerts_by_level", {}).items():
        ui.console.print(f"  {level}: {count}")
    if data.get("recommendations"):
        ui.console.print("\n[bold]Recommendations:[/bold]")
        for rec in data["recommendations"]:
            ui.console.print(f"  • {rec}")


@click.command()
@click.argument("logfile", type=click.Path(exists=True, dir_okay=False))
@click.option("--ip", help="Filter by source IP.")
@click.option("--user", help="Filter by username.")
@click.option("--event-type", help="Filter by event type.")
@click.option("--category", help="Filter by category.")
@click.option("--severity", "min_severity", help="Minimum severity.")
@click.option("--since", help="Only events on/after this date (YYYY-MM-DD).")
@click.option("--until", help="Only events on/before this date (YYYY-MM-DD).")
@click.option("--text", help="Substring match on the message.")
@click.option("--failed-logins", is_flag=True, help="Only failed logins.")
@click.option("--today", is_flag=True, help="Only today's events.")
@click.option("--limit", default=50, show_default=True, help="Max rows to show.")
@click.option("--parser", "parser_name", help="Force a specific parser.")
@click.pass_context
def search(
    ctx: click.Context,
    logfile: str,
    ip: str | None,
    user: str | None,
    event_type: str | None,
    category: str | None,
    min_severity: str | None,
    since: str | None,
    until: str | None,
    text: str | None,
    failed_logins: bool,
    today: bool,
    limit: int,
    parser_name: str | None,
) -> None:
    """Search and filter events in a log file."""
    from sentinelai.parsers.reader import read_events
    from sentinelai.search.query import build_query

    table = Table(title=f"Matches in {Path(logfile).name}", header_style="bold")
    shown = 0
    total = 0
    try:
        query = build_query(
            ip=ip, user=user, event_type=event_type, category=category,
            min_severity=min_severity, since=since, until=until, text=text,
            failed_only=failed_logins, today=today,
        )
        for col in ("Time", "Severity", "Type", "IP", "User", "Message"):
            table.add_column(col)
        for event in query.filter(read_events(logfile, parser_name=parser_name)):
            total += 1
            if shown < limit:
                table.add_row(
                    f"{event.timestamp:%Y-%m-%d %H:%M:%S}",
                    event.severity.value,
                    event.event_type.value,
                    event.ip or "-",
                    event.user or "-",
                    event.message[:80],
                )
                shown += 1
    except SentinelError as exc:
        fail(exc)
    ui.console.print(table)
    ui.console.print(f"[dim]Showing {shown} of {total} matching events.[/dim]")


@click.command(name="rules")
def rules_cmd() -> None:
    """List available detection rules."""
    from sentinelai.detection.base import available_rules

    table = Table(title="Detection Rules", header_style="bold")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("MITRE")
    for rule_id, cls in sorted(available_rules().items()):
        table.add_row(
            rule_id,
            cls.name,
            cls.category.value,
            cls.severity.value,
            ", ".join(cls.mitre_techniques) or "-",
        )
    ui.console.print(table)


@click.command(name="config")
@click.pass_context
def config_cmd(ctx: click.Context) -> None:
    """Show the effective configuration and component status."""
    from sentinelai.ai.base import available_models
    from sentinelai.detection.base import available_rules
    from sentinelai.parsers.base import available_parsers
    from sentinelai.reporting.renderers import available_formats

    config = load_context(ctx).config
    ui.print_banner()
    table = Table(title="Effective configuration", header_style="bold", show_lines=False)
    table.add_column("Setting")
    table.add_column("Value")
    table.add_row("Config source", config.source_path or "built-in defaults")
    table.add_row("State directory", str(config.resolve_state_dir()))
    table.add_row("Detection rules loaded", str(len(available_rules())))
    table.add_row("Parsers available", ", ".join(sorted(available_parsers())))
    table.add_row("Report formats", ", ".join(available_formats()))
    table.add_row("AI enabled", str(config.ai.enabled))
    table.add_row(
        "AI models", ", ".join(available_models()) or "none (install sentinelai[ai])"
    )
    table.add_row("Local LLM explain", str(config.ai.llm.enabled))
    table.add_row(
        "Threat intel providers",
        ", ".join(
            name
            for name, cfg in (
                ("abuseipdb", config.intel.abuseipdb),
                ("virustotal", config.intel.virustotal),
                ("otx", config.intel.otx),
            )
            if cfg.enabled
        )
        or "none configured",
    )
    table.add_row("Firewall adapter", config.firewall.adapter)
    table.add_row("Auto-response", str(config.response.enabled))
    if config.response.enabled:
        table.add_row("Response threshold", config.response.min_risk_level)
    ui.console.print(table)


@click.command(name="version")
def version_cmd() -> None:
    """Show the SentinelAI version."""
    ui.console.print(f"SentinelAI {__version__}")
