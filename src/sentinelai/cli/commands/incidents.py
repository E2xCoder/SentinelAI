"""Incident commands: ``sentinel incidents`` and ``sentinel incident ID``.

Incidents are correlated chains of alerts (a kill-chain view). They are stored
by scans next to the alerts. ``--triage`` asks the configured LLM for an
ADVISORY verdict on one incident; it never changes the score and never triggers
a response.
"""

from __future__ import annotations

import json
import re
from typing import Any

import click

from sentinelai.cli import console as ui
from sentinelai.cli.common import fail, load_context
from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import SentinelError
from sentinelai.core.models import Alert, Incident, RiskLevel
from sentinelai.core.store import AlertStore

_LEVEL_CHOICES = ["low", "medium", "high", "critical"]
_MAX_TRIAGE_TEXT = 2000
_MAX_ACTIONS = 10
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _open_store(config: SentinelConfig) -> AlertStore | None:
    """Open ``<state_dir>/alerts.db``; ``None`` when it does not exist yet."""
    db_path = config.resolve_state_dir() / "alerts.db"
    if not db_path.exists():
        return None
    return AlertStore(db_path)


def _echo_json(data: Any) -> None:
    click.echo(json.dumps(data, indent=2, default=str))


def _clean(value: object, limit: int = _MAX_TRIAGE_TEXT) -> str:
    """Control-char-free, length-capped text (safe to store and print)."""
    return _CONTROL_CHARS.sub("", str(value))[:limit]


# -- triage -------------------------------------------------------------------


def _triage_to_dict(outcome: Any) -> dict[str, Any]:
    """Flatten a ``TriageOutcome`` into the dict stored on ``incident.triage``."""
    result = outcome.result
    verdict = getattr(result, "verdict", "")
    actions = getattr(result, "recommended_actions", None) or []
    confidence = getattr(result, "confidence", 0.0)
    return {
        "verdict": _clean(getattr(verdict, "value", verdict), 100),
        "confidence": float(confidence) if isinstance(confidence, (int, float)) else 0.0,
        "summary": _clean(getattr(result, "summary", "")),
        "reasoning": _clean(getattr(result, "reasoning", "")),
        "recommended_actions": [_clean(a, 300) for a in list(actions)[:_MAX_ACTIONS]],
        "source": _clean(getattr(outcome, "source", ""), 100),
        "valid_llm": bool(getattr(outcome, "valid_llm", False)),
    }


def _run_triage(config: SentinelConfig, store: AlertStore, incident: Incident) -> bool:
    """Triage the incident, persist the result on it; return False if not possible."""
    if not config.ai.llm.enabled:
        ui.error_console.print(
            "[yellow]Triage needs an LLM.[/yellow] Set `ai.llm.enabled: true` (and a "
            "provider/model) in the config, then re-run with --triage."
        )
        return False
    from sentinelai.ai.triage_engine import TriageEngine
    from sentinelai.correlation.summary import incident_as_alert

    alerts_by_id: dict[int, Alert] = {}
    for alert_id in incident.alert_ids:
        member = store.get(alert_id)
        if member is not None:
            alerts_by_id[alert_id] = member
    synthetic = incident_as_alert(incident, alerts_by_id)
    outcome = TriageEngine(config.ai.llm).triage(synthetic)
    incident.triage = _triage_to_dict(outcome)
    store.update_incident(incident)
    return True


def _print_triage(triage: dict[str, Any]) -> None:
    confidence = triage.get("confidence", 0.0)
    pct = float(confidence) * 100 if isinstance(confidence, (int, float)) else 0.0
    origin = "model" if triage.get("valid_llm") else "template fallback"
    ui.console.print(
        f"\n[bold]Triage (ADVISORY)[/bold] source: {ui._safe(triage.get('source', '?'))} "
        f"({origin})"
    )
    ui.console.print(
        f"Verdict: [bold]{ui._safe(triage.get('verdict', '?'))}[/bold] "
        f"({pct:.0f}% confidence)"
    )
    if triage.get("summary"):
        ui.console.print(ui._safe(triage["summary"]))
    if triage.get("reasoning"):
        ui.console.print(f"[bold]Reasoning:[/bold] {ui._safe(triage['reasoning'])}")
    for action in triage.get("recommended_actions") or []:
        ui.console.print(f"  - {ui._safe(action)}")
    ui.console.print(
        "[dim]Advisory only: it does not change the risk score or trigger any response.[/dim]"
    )


# -- commands -----------------------------------------------------------------


@click.command(name="incidents")
@click.option(
    "--limit",
    type=click.IntRange(min=1),
    default=20,
    show_default=True,
    help="Maximum number of incidents to list.",
)
@click.option("--ip", metavar="IP", help="Only incidents involving this source IP.")
@click.option("--user", metavar="USER", help="Only incidents involving this user.")
@click.option(
    "--min-level",
    type=click.Choice(_LEVEL_CHOICES, case_sensitive=False),
    help="Only incidents at or above this risk level.",
)
@click.option("--json", "as_json", is_flag=True, help="Output JSON instead of a table.")
@click.pass_context
def incidents_cmd(
    ctx: click.Context,
    limit: int,
    ip: str | None,
    user: str | None,
    min_level: str | None,
    as_json: bool,
) -> None:
    """List stored incidents (correlated attack chains), highest risk first."""
    config = load_context(ctx).config
    level = RiskLevel(min_level.lower()) if min_level else None
    try:
        store = _open_store(config)
        incidents: list[Incident] = []
        if store is not None:
            try:
                incidents = store.list_incidents(
                    limit=limit, ip=ip, user=user, min_level=level
                )
            finally:
                store.close()
    except SentinelError as exc:
        fail(exc)
    if as_json:
        _echo_json([i.to_dict() for i in incidents])
        return
    if not incidents:
        ui.console.print(
            "No incidents found. Run `sentinel scan` on a log with related alerts "
            "(or loosen the filters) to create some."
        )
        return
    ui.console.print(ui.incidents_table(incidents))
    ui.console.print("Details: `sentinel incident ID` (add --graph or --triage).")


@click.command(name="incident")
@click.argument("incident_id", type=click.IntRange(min=1))
@click.option("--graph", is_flag=True, help="Print the Mermaid graph source.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON instead of formatted text.")
@click.option(
    "--triage",
    is_flag=True,
    help="Run the advisory LLM triage on this incident (needs ai.llm.enabled).",
)
@click.pass_context
def incident_cmd(
    ctx: click.Context,
    incident_id: int,
    graph: bool,
    as_json: bool,
    triage: bool,
) -> None:
    """Show one incident: summary, kill chain and timeline.

    --triage asks the configured LLM for an ADVISORY verdict and stores it on
    the incident; it never changes the risk score or triggers any response.
    """
    config = load_context(ctx).config
    triage_ok = True
    try:
        store = _open_store(config)
        if store is None:
            ui.error_console.print(f"[red]Error:[/red] incident #{incident_id} not found.")
            raise SystemExit(1)
        try:
            incident = store.get_incident(incident_id)
            if incident is None:
                ui.error_console.print(f"[red]Error:[/red] incident #{incident_id} not found.")
                raise SystemExit(1)
            if triage:
                triage_ok = _run_triage(config, store, incident)
        finally:
            store.close()
    except SentinelError as exc:
        fail(exc)

    if as_json:
        _echo_json(incident.to_dict())
    else:
        ui.print_incident_detail(incident, graph=graph)
        if triage and triage_ok and incident.triage:
            _print_triage(incident.triage)
    if as_json and graph:
        from sentinelai.correlation.summary import render_mermaid

        click.echo(render_mermaid(incident), err=True)
    if triage and not triage_ok:
        raise SystemExit(1)
