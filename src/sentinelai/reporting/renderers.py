"""Report renderers: JSON, CSV and self-contained HTML.

Renderers share a registry so ``sentinel report --format`` and plugins
can add new output formats without touching existing code.
"""

from __future__ import annotations

import csv
import html
import io
import json
from collections.abc import Callable

from sentinelai.core.models import RiskLevel
from sentinelai.reporting.report import Report

Renderer = Callable[[Report], str]

_RENDERERS: dict[str, Renderer] = {}


def register_renderer(fmt: str, renderer: Renderer) -> None:
    """Register a renderer for output format *fmt*."""
    _RENDERERS[fmt] = renderer


def get_renderer(fmt: str) -> Renderer:
    """Return the renderer for *fmt*, or raise ValueError."""
    try:
        return _RENDERERS[fmt]
    except KeyError:
        raise ValueError(
            f"No renderer for format {fmt!r}; available: {', '.join(sorted(_RENDERERS))}"
        ) from None


def available_formats() -> list[str]:
    """Names of all registered output formats."""
    return sorted(_RENDERERS)


def render_json(report: Report) -> str:
    """Pretty-printed JSON report."""
    return json.dumps(report.to_dict(include_events=True), indent=2, default=str)


def render_csv(report: Report) -> str:
    """One row per alert, suitable for spreadsheets and SIEM import."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "id", "rule_id", "rule_name", "title", "severity", "risk_level",
            "risk_score", "ip", "user", "hostname", "event_count",
            "first_seen", "last_seen", "mitre_techniques",
            "intel_malicious", "intel_score", "recommendation",
        ]
    )
    for alert in report.alerts:
        writer.writerow(
            [
                alert.id or "",
                alert.rule_id,
                alert.rule_name,
                alert.title,
                alert.severity.value,
                alert.risk.level.value,
                f"{alert.risk.score:.1f}",
                alert.ip or "",
                alert.user or "",
                alert.hostname or "",
                alert.event_count,
                alert.first_seen.isoformat(),
                alert.last_seen.isoformat(),
                ";".join(alert.mitre_techniques),
                "yes" if alert.intel and alert.intel.malicious else "",
                f"{alert.intel.score:.0f}" if alert.intel else "",
                alert.recommendation.replace("\n", " "),
            ]
        )
    return buffer.getvalue()


_LEVEL_COLOR = {
    RiskLevel.CRITICAL: "#b91c1c",
    RiskLevel.HIGH: "#ea580c",
    RiskLevel.MEDIUM: "#ca8a04",
    RiskLevel.LOW: "#2563eb",
    RiskLevel.INFORMATIONAL: "#6b7280",
}


def _esc(value: object) -> str:
    return html.escape(str(value))


def render_html(report: Report) -> str:
    """Self-contained HTML report (no external assets)."""
    summary = report.summary
    parts: list[str] = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>{_esc(report.title)}</title>",
        _HTML_STYLE,
        "</head><body><div class='wrap'>",
        f"<h1>{_esc(report.title)}</h1>",
        f"<p class='muted'>Generated {_esc(report.generated_at.isoformat())} · "
        f"source: {_esc(report.source)}</p>",
    ]

    parts.append("<div class='cards'>")
    cards = [
        ("Events analyzed", summary.get("events_analyzed", 0)),
        ("Alerts", summary.get("alerts_total", 0)),
        ("Attack patterns", summary.get("attack_patterns", 0)),
        ("Unique source IPs", summary.get("unique_source_ips", 0)),
    ]
    for label, value in cards:
        parts.append(f"<div class='card'><div class='num'>{_esc(value)}</div>"
                     f"<div class='lbl'>{_esc(label)}</div></div>")
    parts.append("</div>")

    by_level = summary.get("alerts_by_level", {})
    if by_level:
        parts.append("<h2>Risk breakdown</h2><div class='levels'>")
        for level in RiskLevel:
            count = by_level.get(level.value, 0)
            if count:
                parts.append(
                    f"<span class='pill' style='background:{_LEVEL_COLOR[level]}'>"
                    f"{_esc(level.value)}: {_esc(count)}</span>"
                )
        parts.append("</div>")

    if report.recommendations:
        parts.append("<h2>Recommendations</h2><ul class='recs'>")
        parts.extend(f"<li>{_esc(rec)}</li>" for rec in report.recommendations)
        parts.append("</ul>")

    if report.patterns:
        parts.append("<h2>Detected attack patterns</h2>")
        for pattern in report.patterns:
            parts.append(
                f"<div class='pattern'><strong>{_esc(pattern.name)}</strong> "
                f"<span class='muted'>(confidence {pattern.confidence:.0%})</span>"
                f"<p>{_esc(pattern.description)}</p></div>"
            )

    behavior = summary.get("behavior_analysis", {})
    noisiest = behavior.get("noisiest_source_ips", [])
    targeted = behavior.get("most_targeted_users", [])
    if noisiest or targeted:
        parts.append("<h2>Behavior analysis</h2><div class='cols'>")
        if noisiest:
            parts.append("<div><h3>Noisiest source IPs</h3><table class='data'>")
            parts.append(
                "<tr><th>IP</th><th>Events</th><th>Failures</th>"
                "<th>Top categories</th></tr>"
            )
            for profile in noisiest:
                cats = ", ".join(profile.get("top_categories", {}))
                parts.append(
                    f"<tr><td>{_esc(profile.get('subject'))}</td>"
                    f"<td>{_esc(profile.get('events'))}</td>"
                    f"<td>{_esc(profile.get('failures'))}</td>"
                    f"<td>{_esc(cats)}</td></tr>"
                )
            parts.append("</table></div>")
        if targeted:
            parts.append("<div><h3>Most targeted accounts</h3><table class='data'>")
            parts.append(
                "<tr><th>User</th><th>Failures</th><th>Successes</th>"
                "<th>Failure ratio</th></tr>"
            )
            for profile in targeted:
                parts.append(
                    f"<tr><td>{_esc(profile.get('subject'))}</td>"
                    f"<td>{_esc(profile.get('failures'))}</td>"
                    f"<td>{_esc(profile.get('successes'))}</td>"
                    f"<td>{_esc(profile.get('failure_ratio'))}</td></tr>"
                )
            parts.append("</table></div>")
        parts.append("</div>")

    parts.append("<h2>Alerts</h2>")
    if not report.alerts:
        parts.append("<p class='muted'>No alerts were raised.</p>")
    for alert in report.alerts:
        color = _LEVEL_COLOR[alert.risk.level]
        parts.append(f"<div class='alert' style='border-left-color:{color}'>")
        parts.append(
            f"<div class='alert-head'><span class='badge' style='background:{color}'>"
            f"{_esc(alert.risk.level.value)} · {alert.risk.score:.0f}</span>"
            f"<strong>{_esc(alert.title)}</strong>"
            f"<span class='muted'>{_esc(alert.rule_id)}</span></div>"
        )
        parts.append(f"<p>{_esc(alert.description)}</p>")
        meta = []
        if alert.ip:
            meta.append(f"IP: {_esc(alert.ip)}")
        if alert.user:
            meta.append(f"User: {_esc(alert.user)}")
        if alert.hostname:
            meta.append(f"Host: {_esc(alert.hostname)}")
        meta.append(f"Events: {alert.event_count}")
        if alert.mitre_techniques:
            meta.append("MITRE: " + _esc(", ".join(alert.mitre_techniques)))
        parts.append(f"<p class='muted'>{' · '.join(meta)}</p>")
        if alert.intel and alert.intel.sources:
            verdict = "malicious" if alert.intel.malicious else "clean"
            parts.append(
                f"<p class='intel'>Threat intel: <strong>{_esc(verdict)}</strong> "
                f"(score {alert.intel.score:.0f}/100 from "
                f"{_esc(', '.join(sorted(alert.intel.sources)))})</p>"
            )
        if alert.ai and alert.ai.explanation:
            parts.append(
                f"<details><summary>AI explanation "
                f"({_esc(alert.ai.explanation_source or 'n/a')})</summary>"
                f"<pre>{_esc(alert.ai.explanation)}</pre></details>"
            )
        if alert.risk.factors:
            parts.append("<details><summary>Risk factors</summary><ul>")
            parts.extend(
                f"<li>{_esc(f.reason)} <span class='muted'>({f.points:+.0f})</span></li>"
                for f in alert.risk.factors
            )
            parts.append("</ul></details>")
        parts.append("</div>")

    parts.append("</div></body></html>")
    return "".join(parts)


_HTML_STYLE = """<style>
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
margin:0;background:#0f172a;color:#e2e8f0;line-height:1.5}
.wrap{max-width:1000px;margin:0 auto;padding:2rem}
h1{margin:0 0 .25rem}h2{margin-top:2rem;border-bottom:1px solid #334155;padding-bottom:.35rem}
.muted{color:#94a3b8;font-size:.9rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-top:1.5rem}
.card{background:#1e293b;border-radius:12px;padding:1.2rem;text-align:center}
.card .num{font-size:2rem;font-weight:700}
.card .lbl{color:#94a3b8;font-size:.85rem;margin-top:.25rem}
.levels{display:flex;flex-wrap:wrap;gap:.5rem}
.pill,.badge{color:#fff;border-radius:999px;padding:.2rem .7rem;font-size:.8rem;font-weight:600}
.recs li{margin:.3rem 0}
.pattern{background:#1e293b;border-radius:10px;padding:1rem;margin:.6rem 0}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:1.5rem}
.cols h3{margin:.5rem 0}
table.data{width:100%;border-collapse:collapse;font-size:.85rem}
table.data th,table.data td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #334155}
table.data th{color:#94a3b8}
.alert{background:#1e293b;border-left:5px solid #666;border-radius:8px;
padding:1rem 1.2rem;margin:.8rem 0}
.alert-head{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.intel{color:#fca5a5}
pre{white-space:pre-wrap;background:#0f172a;padding:.8rem;border-radius:8px;overflow:auto}
details{margin-top:.5rem}summary{cursor:pointer;color:#93c5fd}
</style>"""


register_renderer("json", render_json)
register_renderer("csv", render_csv)
register_renderer("html", render_html)
