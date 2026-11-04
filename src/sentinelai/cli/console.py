"""Rich console helpers shared across CLI commands."""

from __future__ import annotations

import contextlib
import re
import sys
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinelai.core.models import Alert, Incident, RiskLevel
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


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _safe(value: object) -> str:
    """Strip terminal control chars (keeps newline/tab), then escape Rich markup."""
    return escape(_CONTROL_CHARS.sub("", str(value)))


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
            _safe(alert.rule_id),
            _safe(alert.ip or "-"),
            _safe(alert.user or "-"),
            str(alert.event_count),
            _safe(alert.title),
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
            f"{_safe(rule)}: {count}" for rule, count in sorted(by_rule.items())
        )
        lines.append(
            f"[bold]Suppressed (analyst rules):[/bold] {suppressed_total}"
            + (f" ({detail})" if detail else "")
        )
    incident_line = _incident_summary_line(report)
    if incident_line:
        lines.append(incident_line)
    return Panel("\n".join(lines), title="Scan Summary", border_style="cyan")


def _incident_summary_line(report: Report) -> str:
    """``Incidents: N (highest: LEVEL score)`` or ``""`` when there are none."""
    total = int(report.summary.get("incidents_total", 0) or 0)
    if total <= 0:
        return ""
    line = f"[bold]Incidents:[/bold] {total}"
    best: dict[str, Any] | None = None
    for item in report.incidents:
        if best is None or _num(item.get("score")) > _num(best.get("score")):
            best = item
    if best is not None:
        top_level = _safe(str(best.get("level", "?")).upper())
        line += f" (highest: {top_level} {_num(best.get('score')):.0f})"
    return line


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _fmt_dt(value: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    return value.strftime(fmt) if isinstance(value, datetime) else "-"


def _entities(incident: Incident) -> str:
    bits = [*incident.ips[:2], *incident.users[:2], *incident.hosts[:1]]
    extra = len(incident.ips) + len(incident.users) + len(incident.hosts) - len(bits)
    text = ", ".join(_safe(b) for b in bits) or "-"
    return f"{text} (+{extra})" if extra > 0 else text


def incidents_table(incidents: list[Incident], title: str = "Incidents") -> Table:
    """Build a rich table summarizing incidents (highest risk first)."""
    table = Table(title=title, show_lines=False, header_style="bold")
    table.add_column("ID", justify="right", style="dim")
    table.add_column("Risk")
    table.add_column("Score", justify="right")
    table.add_column("Window (UTC)")
    table.add_column("Entities")
    table.add_column("Alerts", justify="right")
    table.add_column("Title")
    for inc in sorted(incidents, key=lambda i: i.score, reverse=True):
        window = f"{_fmt_dt(inc.first_seen)} - {_fmt_dt(inc.last_seen, '%H:%M')}"
        table.add_row(
            _safe(inc.id if inc.id is not None else "-"),
            level_text(inc.level),
            f"{inc.score:.0f}",
            window,
            _entities(inc),
            str(inc.alert_count),
            _safe(inc.title),
        )
    return table


def print_incident_detail(incident: Incident, *, graph: bool = False) -> None:
    """Print a full breakdown of one incident (optionally with Mermaid source)."""
    incident_id = _safe(incident.id if incident.id is not None else "-")
    console.print()
    console.print(
        Panel(
            _incident_body(incident),
            title=f"[bold]Incident #{incident_id}[/bold]",
            border_style=_LEVEL_STYLE[incident.level].split()[-1],
        )
    )
    if incident.timeline:
        table = Table(title="Timeline", show_lines=False, header_style="bold")
        table.add_column("Time (UTC)")
        table.add_column("Stage")
        table.add_column("Rule")
        table.add_column("Risk")
        table.add_column("Count", justify="right")
        table.add_column("Title")
        for entry in incident.timeline:
            table.add_row(
                _fmt_dt(entry.timestamp, "%Y-%m-%d %H:%M:%S"),
                _safe(entry.tactic),
                _safe(entry.rule_id),
                _safe(f"{_level_value(entry.risk_level)} {entry.risk_score:.0f}"),
                str(entry.count),
                _safe(entry.title),
            )
        console.print(table)
    if graph:
        from sentinelai.correlation.summary import render_mermaid

        console.print("[bold]Mermaid graph source:[/bold]")
        console.print(Text(_CONTROL_CHARS.sub("", render_mermaid(incident))))


def _level_value(level: object) -> str:
    return str(getattr(level, "value", level))


def _incident_body(incident: Incident) -> str:
    lines = [
        f"[bold]{_safe(incident.title)}[/bold]",
        "",
        _safe(incident.summary),
        "",
        f"Risk: {incident.score:.0f}/100 ({_safe(incident.level.value)})   "
        f"Alerts: {incident.alert_count}",
        f"Window: {_fmt_dt(incident.first_seen, '%Y-%m-%d %H:%M:%S')} - "
        f"{_fmt_dt(incident.last_seen, '%Y-%m-%d %H:%M:%S')} UTC",
        f"IPs: {_safe(', '.join(incident.ips) or 'n/a')}   "
        f"Users: {_safe(', '.join(incident.users) or 'n/a')}   "
        f"Hosts: {_safe(', '.join(incident.hosts) or 'n/a')}",
    ]
    if incident.stages:
        lines.append("Kill chain: " + " > ".join(_safe(s) for s in incident.stages))
    if incident.mitre_techniques:
        lines.append(f"MITRE ATT&CK: {_safe(', '.join(incident.mitre_techniques))}")
    triage = incident.triage
    if triage:
        confidence = _num(triage.get("confidence")) * 100
        origin = "model" if triage.get("valid_llm") else "template fallback"
        lines.append(
            f"\n[bold]Triage verdict (advisory):[/bold] {_safe(triage.get('verdict', '?'))} "
            f"({confidence:.0f}% confidence, {origin}). "
            "[dim]It does not change the risk score or trigger any response.[/dim]"
        )
    return "\n".join(lines)


def print_alert_detail(alert: Alert) -> None:
    """Print a full breakdown of a single alert."""
    console.print()
    console.print(
        Panel(
            _alert_body(alert),
            title=f"[bold]Alert #{_safe(alert.id)} · {_safe(alert.rule_id)}[/bold]",
            border_style=_LEVEL_STYLE[alert.risk.level].split()[-1],
        )
    )


def _alert_body(alert: Alert) -> str:
    lines = [
        f"[bold]{_safe(alert.title)}[/bold]",
        "",
        _safe(alert.description),
        "",
        f"Risk: {alert.risk.score:.0f}/100 ({_safe(alert.risk.level.value)})   "
        f"Severity: {_safe(alert.severity.value)}",
        f"Source IP: {_safe(alert.ip or 'n/a')}   User: {_safe(alert.user or 'n/a')}   "
        f"Host: {_safe(alert.hostname or 'n/a')}",
        f"Events: {alert.event_count}   "
        f"Window: {alert.first_seen:%Y-%m-%d %H:%M} - {alert.last_seen:%H:%M} UTC",
    ]
    if alert.mitre_techniques:
        lines.append(
            f"MITRE ATT&CK: {_safe(', '.join(alert.mitre_techniques))} "
            f"({_safe(', '.join(alert.mitre_tactics))})"
        )
    if alert.risk.factors:
        lines.append("\n[bold]Why this score:[/bold]")
        lines.extend(
            f"  {f.points:+.0f}  {_safe(f.reason)}" for f in alert.risk.factors
        )
    if alert.intel and alert.intel.sources:
        verdict = "[red]MALICIOUS[/red]" if alert.intel.malicious else "[green]clean[/green]"
        lines.append(
            f"\n[bold]Threat intel:[/bold] {verdict} "
            f"(score {alert.intel.score:.0f}/100 from "
            f"{_safe(', '.join(sorted(alert.intel.sources)))})"
        )
    if alert.ai and alert.ai.explanation:
        lines.append(
            f"\n[bold]AI explanation[/bold] "
            f"([italic]{_safe(alert.ai.explanation_source)}[/italic]):\n{_safe(alert.ai.explanation)}"
        )
    triage = alert.ai.triage if alert.ai else None
    if triage:
        confidence = float(triage.get("confidence", 0.0) or 0.0) * 100
        origin = "model" if triage.get("valid_llm") else "template fallback"
        lines.append(
            f"\n[bold]Triage verdict (advisory):[/bold] "
            f"{_safe(triage.get('verdict', '?'))} "
            f"({confidence:.0f}% confidence, {origin}). "
            "[dim]It does not change the risk score or trigger any response.[/dim]"
        )
    if alert.recommendation:
        lines.append(f"\n[bold]Recommendation:[/bold] {_safe(alert.recommendation)}")
    return "\n".join(lines)
