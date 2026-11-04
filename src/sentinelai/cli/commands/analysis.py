"""Analysis commands: scan, analyze, replay, live."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

import click
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from sentinelai.cli import console as ui
from sentinelai.cli.common import build_pipeline, fail, load_context
from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import SentinelError
from sentinelai.core.models import Alert

if TYPE_CHECKING:
    from sentinelai.parsers.reader import ReaderLimits


def limits_from_config(config: SentinelConfig) -> ReaderLimits:
    """Build reader limits from the configured ``limits`` section."""
    from sentinelai.parsers.reader import ReaderLimits

    return ReaderLimits(
        max_line_chars=config.limits.max_line_chars,
        max_decompressed_bytes=config.limits.max_decompressed_mb * 1024 * 1024,
    )


@click.command()
@click.argument("logfile", type=click.Path(exists=True, dir_okay=False))
@click.option("--parser", "parser_name", help="Force a specific parser.")
@click.option("--no-ai", is_flag=True, help="Skip AI anomaly detection.")
@click.option(
    "--format", "formats", multiple=True,
    type=click.Choice(["json", "csv", "html"]),
    help="Also write a report in this format (repeatable).",
)
@click.option("--output-dir", type=click.Path(file_okay=False), help="Report output dir.")
@click.pass_context
def scan(
    ctx: click.Context,
    logfile: str,
    parser_name: str | None,
    no_ai: bool,
    formats: tuple[str, ...],
    output_dir: str | None,
) -> None:
    """Analyze a log file and report detected threats."""
    context = load_context(ctx)
    run_scan(context.config, logfile, parser_name, not no_ai, list(formats), output_dir)


@click.command()
@click.argument("logfile", type=click.Path(exists=True, dir_okay=False))
@click.option("--parser", "parser_name", help="Force a specific parser.")
@click.pass_context
def analyze(ctx: click.Context, logfile: str, parser_name: str | None) -> None:
    """Parse a log file and show event statistics (no detection)."""
    from sentinelai.parsers.reader import read_events

    limits = limits_from_config(load_context(ctx).config)
    events = 0
    categories: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    ips: Counter[str] = Counter()
    try:
        for event in read_events(logfile, parser_name=parser_name, limits=limits):
            events += 1
            categories[event.category.value] += 1
            severities[event.severity.value] += 1
            if event.ip:
                ips[event.ip] += 1
    except SentinelError as exc:
        fail(exc)

    ui.console.print(f"[bold]Parsed {events:,} events from {logfile}[/bold]\n")
    table = Table(title="Events by category", header_style="bold")
    table.add_column("Category")
    table.add_column("Count", justify="right")
    for name, count in categories.most_common():
        table.add_row(name, f"{count:,}")
    ui.console.print(table)
    if ips:
        top = Table(title="Top source IPs", header_style="bold")
        top.add_column("IP")
        top.add_column("Events", justify="right")
        for ip, count in ips.most_common(10):
            top.add_row(ip, f"{count:,}")
        ui.console.print(top)


@click.command()
@click.argument("logfile", type=click.Path(exists=True, dir_okay=False))
@click.option("--speed", default=10.0, show_default=True, help="Replay speed factor.")
@click.option("--parser", "parser_name", help="Force a specific parser.")
@click.pass_context
def replay(ctx: click.Context, logfile: str, speed: float, parser_name: str | None) -> None:
    """Replay a historical log through detection as if it were live."""
    from sentinelai.monitor.replay import LogReplayer
    from sentinelai.parsers.reader import read_events

    context = load_context(ctx)
    pipeline = build_pipeline(context.config)

    def on_alert(alert: Alert) -> None:
        ui.console.print(
            f"[{ui.style_for_level(alert.risk.level)}]"
            f"ALERT[/] {alert.rule_id} · {alert.title} "
            f"(risk {alert.risk.score:.0f})"
        )

    try:
        replayer = LogReplayer(pipeline, speed=speed, on_alert=on_alert)
        ui.console.print(f"[cyan]Replaying {logfile} at {speed}x…[/cyan]")
        replayer.replay(
            read_events(
                logfile, parser_name=parser_name, limits=limits_from_config(context.config)
            )
        )
        ui.console.print(
            f"[green]Done.[/green] {replayer.events_replayed:,} events, "
            f"{replayer.alerts_raised} alerts."
        )
    except SentinelError as exc:
        fail(exc)
    finally:
        pipeline.close()


@click.command()
@click.option("--from-beginning", is_flag=True, help="Read existing content first.")
@click.option(
    "--path", "paths", multiple=True, type=click.Path(),
    help="Override configured log paths (repeatable).",
)
@click.pass_context
def live(ctx: click.Context, from_beginning: bool, paths: tuple[str, ...]) -> None:
    """Continuously monitor logs in real time."""
    from sentinelai.monitor.live import LiveMonitor

    context = load_context(ctx)
    config = context.config
    if paths:
        config.live.paths = list(paths)
    if from_beginning:
        config.live.from_beginning = True
    config.live.validate()
    pipeline = build_pipeline(config)

    def on_alert(alert: Alert) -> None:
        ui.console.print(
            f"[{ui.style_for_level(alert.risk.level)}]ALERT[/] "
            f"{alert.last_seen:%H:%M:%S} {alert.rule_id} · {alert.title} "
            f"(risk {alert.risk.score:.0f}, ip {alert.ip or 'n/a'})"
        )

    monitor = LiveMonitor(
        config.live,
        pipeline,
        on_alert=on_alert,
        max_line_chars=config.limits.max_line_chars,
    )
    ui.print_banner()
    ui.console.print(
        f"[cyan]Watching {len(config.live.paths)} log(s). Press Ctrl-C to stop.[/cyan]"
    )
    try:
        monitor.run()
    except KeyboardInterrupt:
        monitor.stop()
        ui.console.print("\n[yellow]Stopped.[/yellow]")
    finally:
        pipeline.close()


def run_scan(
    config: SentinelConfig,
    logfile: str,
    parser_name: str | None,
    use_ai: bool,
    formats: list[str],
    output_dir: str | None,
) -> None:
    """Execute a scan and render results plus optional report files."""
    from sentinelai.parsers.reader import read_events
    from sentinelai.reporting.report import build_report
    from sentinelai.reporting.writer import write_reports

    pipeline = build_pipeline(config)
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Analyzing {task.description}…[/cyan]"),
            transient=True,
            console=ui.console,
        ) as progress:
            progress.add_task(Path(logfile).name, total=None)
            result = pipeline.run_scan(
                read_events(
                    logfile, parser_name=parser_name, limits=limits_from_config(config)
                ),
                use_ai=use_ai,
            )
        report_formats = formats or config.report.formats
        report_obj = build_report(
            result,
            title=config.report.title,
            source=str(Path(logfile).resolve()),
            max_events_per_alert=config.report.max_events_per_alert,
        )
        ui.console.print(ui.summary_panel(report_obj))
        if result.alerts:
            ui.console.print(ui.alerts_table(result.alerts))
        else:
            ui.console.print("[green]No threats detected.[/green]")
        if result.patterns:
            ui.console.print("\n[bold red]Attack patterns detected:[/bold red]")
            for pattern in result.patterns:
                ui.console.print(
                    f"  • {pattern.name} "
                    f"[dim](confidence {pattern.confidence:.0%})[/dim]: "
                    f"{pattern.description}"
                )
        if report_formats:
            written = write_reports(
                report_obj,
                report_formats,
                output_dir or config.report.output_dir,
            )
            for fmt, path in written.items():
                ui.console.print(f"[green]Wrote {fmt} report:[/green] {path}")
    except SentinelError as exc:
        fail(exc)
    finally:
        pipeline.close()
