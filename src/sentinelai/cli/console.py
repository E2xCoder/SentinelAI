"""Rich console helpers shared across CLI commands."""

from __future__ import annotations

import contextlib
import sys

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinelai.core.models import Alert, RiskLevel
from sentinelai.reporting.report import Report

# Ensure Unicode output works even on legacy Windows code pages (cp1252),
# where box-drawing and arrow glyphs would otherwise raise UnicodeEncodeError.
for _stream in (sys.stdout, sys.stderr):
    reconfigure = getattr(_stream, "reconfigure", None)
    if reconfigure is not None:
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8", errors="replace")

console = Console()
error_console = Console(stderr=True)

_LEVEL_STYLE = {
    RiskLevel.CRITICAL: "bold white on red",
    RiskLevel.HIGH: "bold red",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.LOW: "cyan",
    RiskLevel.INFORMATIONAL: "dim",
}

_LEVEL_ORDER = [
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.INFORMATIONAL,
]


def print_banner() -> None:
    """Render the SentinelAI banner."""
    from sentinelai import __version__

    console.print(
        Panel.fit(
            Text.assemble(
                ("SentinelAI", "bold cyan"),
                (f"  v{__version__}\n", "cyan"),
                ("AI-assisted security log analysis & response", "dim"),
            ),
            border_style="cyan",
        )
    )


def style_for_level(level: RiskLevel) -> str:
    """Return the rich style string associated with a risk level."""
    return _LEVEL_STYLE[level]


def level_text(level: RiskLevel) -> Text:
    """A colored label for a risk level."""
    return Text(level.value.upper(), style=_LEVEL_STYLE[level])


def alerts_table(alerts: list[Alert], title: str = "Alerts") -> Table:
    """Build a rich table summarizing alerts (highest risk first)."""
    table = Table(title=title, show_lines=False, header_style="bold")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Risk")
    table.add_column("Score", justify="right")
    table.add_column("Rule")
    table.add_column("Source IP")
    table.add_column("User")
    table.add_column("Events", justify="right")
    table.add_column("Title")
    for alert in sorted(alerts, key=lambda a: a.risk.score, reverse=True):
        table.add_row(
            str(alert.id if alert.id is not None else "-"),
            level_text(alert.risk.level),
            f"{alert.risk.score:.0f}",
            alert.rule_id,
            alert.ip or "-",
            alert.user or "-",
            str(alert.event_count),
            alert.title,
        )
    return table


def summary_panel(report: Report) -> Panel:
    """A compact scan-summary panel."""
    summary = report.summary
    by_level = summary.get("alerts_by_level", {})
    lines = [
        f"[bold]Events analyzed:[/bold] {summary.get('events_analyzed', 0):,}",
        f"[bold]Alerts:[/bold] {summary.get('alerts_total', 0)}",
        f"[bold]Attack patterns:[/bold] {summary.get('attack_patterns', 0)}",
        f"[bold]Unique source IPs:[/bold] {summary.get('unique_source_ips', 0)}",
    ]
    level_bits = [
        f"[{_LEVEL_STYLE[level]}]{by_level[level.value]} {level.value}[/]"
        for level in _LEVEL_ORDER
        if by_level.get(level.value)
    ]
    if level_bits:
        lines.append("[bold]By risk:[/bold] " + "  ".join(level_bits))
    if summary.get("ai_used"):
        lines.append(f"[bold]AI anomalies:[/bold] {summary.get('ai_anomalies', 0)}")
    suppressed = summary.get("suppressed_alerts") or {}
    suppressed_total = int(suppressed.get("total", 0) or 0)
    if suppressed_total > 0:
        by_rule = suppressed.get("by_rule", {})
        detail = ", ".join(
            f"{escape(str(rule))}: {count}" for rule, count in sorted(by_rule.items())
        )
        lines.append(
            f"[bold]Suppressed (analyst rules):[/bold] {suppressed_total}"
            + (f" ({detail})" if detail else "")
        )
    return Panel("\n".join(lines), title="Scan Summary", border_style="cyan")


def print_alert_detail(alert: Alert) -> None:
    """Print a full breakdown of a single alert."""
    console.print()
    console.print(
        Panel(
            _alert_body(alert),
            title=f"[bold]Alert #{alert.id} · {alert.rule_id}[/bold]",
            border_style=_LEVEL_STYLE[alert.risk.level].split()[-1],
        )
    )


def _alert_body(alert: Alert) -> str:
    lines = [
        f"[bold]{alert.title}[/bold]",
        "",
        alert.description,
        "",
        f"Risk: {alert.risk.score:.0f}/100 ({alert.risk.level.value})   "
        f"Severity: {alert.severity.value}",
        f"Source IP: {alert.ip or 'n/a'}   User: {alert.user or 'n/a'}   "
        f"Host: {alert.hostname or 'n/a'}",
        f"Events: {alert.event_count}   "
        f"Window: {alert.first_seen:%Y-%m-%d %H:%M} - {alert.last_seen:%H:%M} UTC",
    ]
    if alert.mitre_techniques:
        lines.append(
            f"MITRE ATT&CK: {', '.join(alert.mitre_techniques)} "
            f"({', '.join(alert.mitre_tactics)})"
        )
    if alert.risk.factors:
        lines.append("\n[bold]Why this score:[/bold]")
        lines.extend(
            f"  {f.points:+.0f}  {f.reason}" for f in alert.risk.factors
        )
    if alert.intel and alert.intel.sources:
        verdict = "[red]MALICIOUS[/red]" if alert.intel.malicious else "[green]clean[/green]"
        lines.append(
            f"\n[bold]Threat intel:[/bold] {verdict} "
            f"(score {alert.intel.score:.0f}/100 from "
            f"{', '.join(sorted(alert.intel.sources))})"
        )
    if alert.ai and alert.ai.explanation:
        lines.append(
            f"\n[bold]AI explanation[/bold] "
            f"([italic]{alert.ai.explanation_source}[/italic]):\n{alert.ai.explanation}"
        )
    if alert.recommendation:
        lines.append(f"\n[bold]Recommendation:[/bold] {alert.recommendation}")
    return "\n".join(lines)
