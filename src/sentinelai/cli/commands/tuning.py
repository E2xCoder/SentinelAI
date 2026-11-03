"""Tuning-loop commands: ``sentinel feedback``, ``sentinel review``, ``sentinel tune``.

The loop is human-approved: analysts label alerts (``feedback`` / ``review``),
``tune`` turns the labels into bounded proposals and gates each one against the
frozen benchmark and the labels themselves. Nothing is written unless
``sentinel tune --apply`` is used, and every apply can be undone with
``sentinel tune --rollback``.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import click
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from sentinelai.cli import console as ui
from sentinelai.cli.common import fail, load_context
from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import SentinelError, StorageError
from sentinelai.core.models import Alert
from sentinelai.core.store import AlertStore, FeedbackEntry
from sentinelai.tuning import gate
from sentinelai.tuning.feedback import collect_feedback
from sentinelai.tuning.history import TuningHistory
from sentinelai.tuning.models import (
    MIN_FALSE_POSITIVES,
    MIN_FP_RATIO,
    MIN_LABELLED_PER_RULE,
    GateResult,
    Proposal,
)
from sentinelai.tuning.overlay import merge_patch, parse_overlay, render_overlay
from sentinelai.tuning.proposals import generate_proposals, proposals_to_yaml

_LABEL_NAMES = {"tp": "true positive", "fp": "false positive"}
_REVIEW_CHOICES = ("t", "f", "s", "q")
_SAMPLE_EVENTS_SHOWN = 2
_MESSAGE_WIDTH = 120
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _clean(text: str) -> str:
    """Strip control characters (ESC, C0, DEL, C1) except tab and newline."""
    return _CONTROL_CHARS.sub("", text)


def _save_label(
    store: AlertStore,
    history: TuningHistory,
    alert_id: int,
    rule_id: str,
    label: str,
    note: str,
) -> None:
    """Store a label and append an audit record (audit never raises)."""
    previous = next((e.label for e in store.list_feedback() if e.alert_id == alert_id), None)
    store.add_feedback(alert_id, label, note)
    history.audit(
        "feedback",
        alert_id=alert_id,
        label=label,
        previous_label=previous,
        rule_id=rule_id,
    )


def _open_store(config: SentinelConfig) -> AlertStore:
    """Open ``<state_dir>/alerts.db``, creating the state directory if needed."""
    state_dir = config.resolve_state_dir()
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StorageError(f"Cannot create state directory {state_dir}: {exc}") from exc
    return AlertStore(state_dir / "alerts.db")


# -- feedback -----------------------------------------------------------------


@click.command(name="feedback")
@click.argument("alert_id", type=int)
@click.option("--tp", "is_tp", is_flag=True, help="Label the alert a true positive.")
@click.option("--fp", "is_fp", is_flag=True, help="Label the alert a false positive.")
@click.option("--note", default="", help="Optional free-text reason (stored with the label).")
@click.pass_context
def feedback_cmd(
    ctx: click.Context, alert_id: int, is_tp: bool, is_fp: bool, note: str
) -> None:
    """Label a stored alert as a true (--tp) or false (--fp) positive.

    Labels feed `sentinel tune`. Labelling an alert again replaces the
    previous verdict. Exactly one of --tp / --fp is required.
    """
    if is_tp == is_fp:
        raise click.UsageError("Specify exactly one of --tp or --fp.")
    label = "tp" if is_tp else "fp"
    config = load_context(ctx).config
    try:
        store = _open_store(config)
        try:
            alert = store.get(alert_id)
            if alert is None:
                raise StorageError(f"No alert with id {alert_id}. Run a scan first.")
            history = TuningHistory(config.resolve_state_dir(), store)
            _save_label(store, history, alert_id, alert.rule_id, label, note)
        finally:
            store.close()
    except SentinelError as exc:
        fail(exc)
    ui.console.print(
        f"[green]Recorded[/green] alert #{alert_id} ({escape(alert.rule_id)}) "
        f"as {_LABEL_NAMES[label]}."
    )


# -- review -------------------------------------------------------------------


def _review_panel(alert: Alert, position: int, total: int) -> Panel:
    level = alert.risk.level
    lines = [
        f"[bold]{escape(_clean(alert.title))}[/bold]",
        f"Risk: [{ui.style_for_level(level)}]{level.value.upper()}[/] "
        f"({alert.risk.score:.0f}/100)   Events: {alert.event_count}",
        f"Source IP: {escape(_clean(alert.ip or 'n/a'))}   "
        f"User: {escape(_clean(alert.user or 'n/a'))}",
    ]
    for event in alert.sample_events[:_SAMPLE_EVENTS_SHOWN]:
        lines.append(f"[dim]  {escape(_clean(event.message)[:_MESSAGE_WIDTH])}[/dim]")
    return Panel(
        "\n".join(lines),
        title=(
            f"[bold]Alert #{alert.id} · {escape(_clean(alert.rule_id))}[/bold] "
            f"({position}/{total})"
        ),
        border_style=ui.style_for_level(level).split()[-1],
    )


def _pending_alerts(store: AlertStore, limit: int) -> list[Alert]:
    labelled = {entry.alert_id for entry in store.list_feedback()}
    return [a for a in store.recent(limit) if a.id is not None and a.id not in labelled]


@click.command(name="review")
@click.option(
    "--limit",
    type=click.IntRange(min=1),
    default=20,
    show_default=True,
    help="How many of the most recent alerts to look through.",
)
@click.pass_context
def review_cmd(ctx: click.Context, limit: int) -> None:
    """Interactively label recent, not yet labelled alerts.

    For each alert choose: t = true positive, f = false positive (an optional
    note is asked), s = skip, q = quit. Labels are saved immediately and feed
    `sentinel tune`. Needs an interactive terminal.
    """
    config = load_context(ctx).config
    labelled = 0
    try:
        store = _open_store(config)
        try:
            pending = _pending_alerts(store, limit)
            if not pending:
                ui.console.print("Nothing to review: no unlabelled alerts among the recent ones.")
                return
            if not sys.stdin.isatty():
                ui.console.print(
                    f"{len(pending)} alert(s) await review, but stdin is not a terminal. "
                    "Run `sentinel review` interactively or use `sentinel feedback`."
                )
                return
            history = TuningHistory(config.resolve_state_dir(), store)
            labelled = _review_loop(store, pending, history)
        finally:
            store.close()
    except SentinelError as exc:
        fail(exc)
    ui.console.print(f"Labelled {labelled} alert(s).")


def _review_loop(store: AlertStore, pending: Sequence[Alert], history: TuningHistory) -> int:
    """Prompt for each alert; return how many were labelled."""
    labelled = 0
    for index, alert in enumerate(pending, start=1):
        if alert.id is None:
            continue
        ui.console.print(_review_panel(alert, index, len(pending)))
        try:
            choice = click.prompt(
                "[t]rue positive / [f]alse positive / [s]kip / [q]uit",
                type=click.Choice(_REVIEW_CHOICES, case_sensitive=False),
                show_choices=False,
            ).lower()
            if choice == "q":
                break
            if choice == "s":
                continue
            note = ""
            if choice == "f":
                note = click.prompt("Note (optional)", default="", show_default=False)
        except click.Abort:
            ui.console.print()
            break
        _save_label(store, history, alert.id, alert.rule_id, "fp" if choice == "f" else "tp", note)
        labelled += 1
    return labelled


# -- tune ---------------------------------------------------------------------


def _describe_suppression(entry: Mapping[str, Any]) -> str:
    scope = ", ".join(f"{key}={entry[key]}" for key in ("user", "ip") if entry.get(key))
    until = f" until {entry['expires']}" if entry.get("expires") else ""
    return f"suppress {entry.get('rule', '?')} ({scope or 'any'}){until}"


def _describe_patch(patch: Mapping[str, Any], config: SentinelConfig) -> str:
    """One-line human summary of what a proposal patch changes."""
    parts: list[str] = []
    for name, value in (patch.get("detection") or {}).items():
        if name == "suppressions":
            parts.extend(_describe_suppression(e) for e in value)
        else:
            parts.append(f"{name}: {getattr(config.detection, name, '?')} -> {value}")
    for rule, weight in ((patch.get("risk") or {}).get("rule_weights") or {}).items():
        parts.append(f"risk weight {rule}: {config.risk.rule_weights.get(rule, 1.0)} -> {weight}")
    return "; ".join(parts) or "-"


def _print_history(history: TuningHistory) -> None:
    entries = history.history()
    if not entries:
        ui.console.print("No tuning changes recorded yet.")
        return
    table = Table(title="Tuning history", header_style="bold")
    table.add_column("ID", justify="right")
    table.add_column("Time (UTC)")
    table.add_column("Action")
    table.add_column("Proposals")
    table.add_column("Rolled back")
    for entry in entries:
        table.add_row(
            str(entry.id),
            f"{entry.ts:%Y-%m-%d %H:%M:%S}",
            escape(entry.action),
            escape(", ".join(entry.proposal_ids) or "-"),
            "yes" if entry.rolled_back else "no",
        )
    ui.console.print(table)


def _rollback(history: TuningHistory) -> None:
    entry = history.rollback()
    ids = escape(", ".join(entry.proposal_ids) or "-")
    ui.console.print(f"[green]Rolled back[/green] change #{entry.id} (proposals: {ids}).")
    if entry.previous_text:
        ui.console.print(f"Restored previous overlay: {escape(str(history.overlay_file))}")
    else:
        ui.console.print("There was no overlay before that change, so it was removed.")


def _explain_no_proposals(labelled: int) -> None:
    ui.console.print("[yellow]No proposals.[/yellow] A rule is only tuned when it has:")
    ui.console.print(f"  - at least {MIN_LABELLED_PER_RULE} labelled alerts,")
    ui.console.print(f"  - at least {MIN_FALSE_POSITIVES} of them labelled false positives,")
    ui.console.print(f"  - a false-positive share of at least {MIN_FP_RATIO:.0%}.")
    ui.console.print(f"Labelled alerts so far: {labelled}. Use `sentinel review` to add more.")


def _results_table(
    results: Sequence[tuple[Proposal, GateResult]], config: SentinelConfig
) -> Table:
    table = Table(title="Tuning proposals", header_style="bold")
    table.add_column("ID")
    table.add_column("Rule")
    table.add_column("Kind")
    table.add_column("Change")
    table.add_column("Verdict")
    table.add_column("Reason")
    for proposal, result in results:
        verdict = "[green]ACCEPT[/green]" if result.accepted else "[bold red]REJECT[/bold red]"
        table.add_row(
            escape(proposal.id),
            escape(proposal.rule_id),
            escape(proposal.kind),
            escape(_describe_patch(proposal.patch, config)),
            verdict,
            escape(result.reasons[0] if result.reasons else "-"),
        )
    return table


def _write_yaml(path: Path, text: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise StorageError(f"Cannot write {path}: {exc}") from exc


def _select(proposals: list[Proposal], only: tuple[str, ...]) -> list[Proposal]:
    """Restrict *proposals* to the ``--only`` ids; unknown ids are an error."""
    if not only:
        return proposals
    known = {p.id for p in proposals}
    unknown = sorted(set(only) - known)
    if unknown:
        raise SentinelError(
            f"Unknown proposal id(s): {', '.join(unknown)}. "
            f"Available: {', '.join(sorted(known)) or 'none'}."
        )
    wanted = set(only)
    return [p for p in proposals if p.id in wanted]


def _apply(
    accepted: list[Proposal],
    config: SentinelConfig,
    history: TuningHistory,
    entries: Sequence[FeedbackEntry],
    benchmarks: Path,
    force: bool,
) -> None:
    final = gate.evaluate(accepted, config, entries, benchmarks, force=force)
    if not final.accepted:
        ui.error_console.print("[bold red]Aborted:[/bold red] the accepted set fails the gate.")
        for reason in final.reasons:
            ui.error_console.print(f"  [red]{escape(reason)}[/red]")
        sys.exit(1)

    overlay = parse_overlay(history.current_text())
    for proposal in accepted:
        overlay = merge_patch(overlay, proposal.patch)
    ids = [p.id for p in accepted]
    note = "sentinel tune --apply" + (" --force" if force else "")
    history_id = history.apply(render_overlay(overlay), ids, note)

    ui.console.print(f"[green]Applied[/green] {escape(', '.join(ids))}.")
    ui.console.print(f"Overlay: {escape(str(history.overlay_file))}")
    ui.console.print(f"History id: {history_id}")
    ui.console.print("Undo with: sentinel tune --rollback")


def _run_tune(
    config: SentinelConfig,
    store: AlertStore,
    history: TuningHistory,
    *,
    benchmarks: Path,
    apply: bool,
    only: tuple[str, ...],
    force: bool,
    yaml_out: Path | None,
) -> None:
    feedback = collect_feedback(store)
    proposals = _select(generate_proposals(feedback, config), only)
    if not proposals:
        _explain_no_proposals(sum(fb.total for fb in feedback.values()))
        return

    entries = store.list_feedback()
    results = [
        (p, gate.evaluate([p], config, entries, benchmarks, force=force)) for p in proposals
    ]
    accepted = [p for p, r in results if r.accepted]
    ui.console.print(_results_table(results, config))

    if accepted:
        yaml_text = proposals_to_yaml(accepted)
        ui.console.print("\n[bold]Accepted proposals (YAML):[/bold]")
        ui.console.print(yaml_text, markup=False, highlight=False)
        if yaml_out is not None:
            _write_yaml(yaml_out, yaml_text)
            ui.console.print(f"YAML written to {escape(str(yaml_out))}")
    elif yaml_out is not None:
        ui.console.print("[yellow]No accepted proposals; --yaml-out file not written.[/yellow]")

    if not apply:
        if accepted:
            ui.console.print("\nNothing was changed. Re-run with --apply to write the overlay.")
        return
    if not accepted:
        ui.error_console.print("[bold red]Error:[/bold red] no proposal passed the gate.")
        sys.exit(1)
    _apply(accepted, config, history, entries, benchmarks, force)


@click.command(name="tune")
@click.option(
    "--benchmarks",
    type=click.Path(path_type=Path),
    default=Path("benchmarks"),
    show_default=True,
    help="Frozen benchmark root (containing scenarios/) used by the gate.",
)
@click.option("--apply", "apply", is_flag=True, help="Write the accepted proposals to the overlay.")
@click.option(
    "--only",
    multiple=True,
    metavar="ID",
    help="Restrict to this proposal id (repeatable); unknown ids are an error.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Relax soft policy limits (never the hard ones). Use with care.",
)
@click.option("--rollback", is_flag=True, help="Undo the latest applied change and exit.")
@click.option("--history", "show_history", is_flag=True, help="Show applied/rolled-back changes.")
@click.option(
    "--yaml-out",
    type=click.Path(path_type=Path),
    help="Also write the accepted proposals as YAML to this path.",
)
@click.pass_context
def tune_cmd(
    ctx: click.Context,
    benchmarks: Path,
    apply: bool,
    only: tuple[str, ...],
    force: bool,
    rollback: bool,
    show_history: bool,
    yaml_out: Path | None,
) -> None:
    """Propose, gate and (with --apply) apply feedback-driven tuning.

    Proposals come from your `feedback` / `review` labels and are bounded
    edits to a managed overlay (<state_dir>/tuning.yaml). Each one is checked
    against the frozen benchmark and your own labels; without --apply nothing
    is changed. Undo an apply with --rollback; list changes with --history.
    """
    if show_history and rollback:
        raise click.UsageError("--history and --rollback cannot be combined.")
    config = load_context(ctx).config
    try:
        store = _open_store(config)
        try:
            history = TuningHistory(config.resolve_state_dir(), store)
            if show_history:
                _print_history(history)
            elif rollback:
                _rollback(history)
            else:
                if force and apply:
                    ui.error_console.print(
                        "[bold yellow]WARNING:[/bold yellow] --force relaxes safety limits "
                        "for this apply."
                    )
                _run_tune(
                    config,
                    store,
                    history,
                    benchmarks=benchmarks,
                    apply=apply,
                    only=only,
                    force=force,
                    yaml_out=yaml_out,
                )
        finally:
            store.close()
    except SentinelError as exc:
        fail(exc)
