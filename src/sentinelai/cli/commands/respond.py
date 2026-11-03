"""Response command: ``sentinel respond`` manages human-approved firewall responses.

Automatic response is OFF unless ``response.enabled: true``. Pending proposals
are listed, approved or denied here; approvals re-check the lockout and
allowlist rules before anything is blocked. Every decision is audited and
blocks can be undone with ``--rollback``.
"""

from __future__ import annotations

import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import click
from rich.table import Table

from sentinelai.cli import console as ui
from sentinelai.cli.common import build_pipeline, fail, load_context
from sentinelai.core.exceptions import SentinelError
from sentinelai.firewall.operator import ResponseOperator

_RELATIVE = re.compile(r"^(\d{1,6})([mhd])$")
_UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86400}
_MAX_TEXT = 200
_MAX_LISTED = 50
_LINE_BREAKS = re.compile(r"[\r\n\t\v\f\x85  ]")


def _one_line(value: object, limit: int = _MAX_TEXT) -> str:
    """Single-line, terminal-safe text: line breaks/tabs become a space, then capped."""
    return ui._safe(_LINE_BREAKS.sub(" ", str(value)))[:limit]


def _text(value: object) -> str:
    """Terminal-safe single-line text (control chars stripped, markup escaped, capped)."""
    return _one_line(value)


def _enum_text(value: object) -> str:
    """Render an enum by its value, anything else with ``str``."""
    return _text(getattr(value, "value", value))


def _fmt_time(value: object) -> str:
    if isinstance(value, datetime):
        return f"{value:%Y-%m-%d %H:%M:%S}"
    return _text(value if value not in (None, "") else "-")


def _fmt_duration(seconds: object) -> str:
    if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or seconds <= 0:
        return "permanent"
    total = int(seconds)
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if total >= size and total % size == 0:
            return f"{total // size}{unit}"
    return f"{total}s"


def parse_since(value: str) -> datetime:
    """Parse ``30m`` / ``2h`` / ``3d`` or ISO-8601 into an aware UTC datetime."""
    raw = value.strip()
    match = _RELATIVE.match(raw.lower())
    if match:
        seconds = int(match.group(1)) * _UNIT_SECONDS[match.group(2)]
        try:
            return datetime.now(timezone.utc) - timedelta(seconds=seconds)
        except OverflowError:
            raise click.BadParameter(f"{value!r} is out of range.", param_hint="--since") from None
    iso = raw[:-1] + "+00:00" if raw[-1:] in ("Z", "z") else raw
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        raise click.BadParameter(
            f"{value!r} is neither relative (30m, 2h, 3d) nor ISO-8601.",
            param_hint="--since",
        ) from None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


# -- read-only views -----------------------------------------------------------


def _show_pending(operator: ResponseOperator) -> None:
    items = operator.pending()
    if not items:
        ui.console.print("No pending responses.")
        return
    table = Table(title="Pending responses", header_style="bold")
    table.add_column("ID", justify="right")
    table.add_column("Time (UTC)")
    table.add_column("IP")
    table.add_column("Rule")
    table.add_column("Risk")
    table.add_column("Action")
    table.add_column("Duration")
    for item in items:
        table.add_row(
            _text(item.id),
            _fmt_time(item.ts),
            _text(item.ip),
            _text(item.rule_id),
            f"{_enum_text(item.risk_level)} ({_text(f'{float(item.risk_score):.0f}')})",
            _enum_text(item.action),
            _fmt_duration(item.duration_seconds),
        )
    ui.console.print(table)
    ui.console.print("Approve with `sentinel respond --approve ID`, deny with `--deny ID`.")


def _show_history(operator: ResponseOperator, limit: int) -> None:
    records: list[dict[str, Any]] = operator.history(limit)
    if not records:
        ui.console.print("No response decisions recorded yet.")
        return
    table = Table(title="Response history", header_style="bold")
    table.add_column("Time (UTC)")
    table.add_column("Decision")
    table.add_column("IP")
    table.add_column("Rule")
    table.add_column("Reason")
    for rec in records:
        table.add_row(
            _fmt_time(rec.get("ts")),
            _text(rec.get("decision", "-")),
            _text(rec.get("ip", "-")),
            _text(rec.get("rule_id", rec.get("rule", "-"))),
            _text(rec.get("reason", rec.get("note", "-"))),
        )
    ui.console.print(table)


# -- mutating actions ----------------------------------------------------------


def _report_action(action: Any, prefix: str = "") -> bool:
    """Print one firewall action result; return its success flag."""
    ok = bool(action.success)
    state = "[green]OK[/green]" if ok else "[bold red]FAILED[/bold red]"
    line = f"{prefix}{state} {_enum_text(action.action)} {_text(action.ip)}"
    if action.detail:
        line += f": {_text(action.detail)}"
    (ui.console if ok else ui.error_console).print(line)
    return ok


def _approve(operator: ResponseOperator, ids: list[int], note: str) -> bool:
    all_ok = True
    for pending_id in ids:
        try:
            action = operator.approve(pending_id, note)
        except SentinelError as exc:
            ui.error_console.print(f"#{pending_id} [bold red]FAILED[/bold red]: {_text(exc)}")
            all_ok = False
            continue
        all_ok = _report_action(action, f"#{pending_id} approved: ") and all_ok
    return all_ok


def _deny(operator: ResponseOperator, ids: list[int], note: str) -> bool:
    all_ok = True
    for pending_id in ids:
        try:
            operator.deny(pending_id, note)
        except SentinelError as exc:
            ui.error_console.print(f"#{pending_id} [bold red]FAILED[/bold red]: {_text(exc)}")
            all_ok = False
            continue
        ui.console.print(f"#{pending_id} [green]OK[/green] denied; nothing was blocked.")
    return all_ok


def _report_actions(actions: list[Any], empty: str) -> bool:
    if not actions:
        ui.console.print(empty)
        return True
    results = [_report_action(a) for a in actions]
    ui.console.print(f"{sum(results)}/{len(results)} action(s) succeeded.")
    return all(results)


def _confirm(prompt: str, yes: bool) -> None:
    """Ask before a mutating action; abort (exit 1) when declined or non-interactive."""
    if yes:
        return
    if not sys.stdin.isatty():
        ui.error_console.print(
            "[bold red]Error:[/bold red] confirmation needs an interactive terminal; "
            "re-run with --yes to proceed."
        )
        raise SystemExit(1)
    click.confirm(prompt, abort=True)


def _confirm_ids(operator: ResponseOperator, ids: list[int], verb: str, yes: bool) -> list[int]:
    """List what each id will do, confirm, and return the known ids to act on.

    Unknown (or already decided / expired) ids are reported before asking.
    With ``--yes`` nothing is looked up; the operator reports bad ids itself.
    """
    if yes:
        return ids
    pending = {item.id: item for item in operator.pending()}
    known: list[int] = []
    for pending_id in ids:
        item = pending.get(pending_id)
        if item is None:
            ui.error_console.print(
                f"#{pending_id} is not a pending response (unknown, decided or expired)."
            )
            continue
        detail = f"{_text(item.rule_id)}, {_enum_text(item.risk_level)}"
        ui.console.print(f"  #{pending_id} {_text(item.ip)} ({detail})")
        known.append(pending_id)
    if known:
        _confirm(f"{verb} {len(known)} response(s)?", yes)
    return known


def _find_store(pipeline: Any, operator: Any) -> Any:
    """Return the alert store (public ``pipeline.store`` first), or ``None``."""
    for owner, name in ((pipeline, "store"), (operator, "_store")):
        candidate = getattr(owner, name, None)
        if candidate is not None and hasattr(candidate, "list_response_actions"):
            return candidate
    return None


def _selected_ips(
    pipeline: Any, operator: Any, since: datetime | None, run_id: str | None
) -> list[str] | None:
    """IPs a reap (``since``/``run_id`` both ``None``) or rollback would unblock.

    Returns ``None`` when the lookup is not possible.
    """
    store = _find_store(pipeline, operator)
    if store is None:
        return None
    try:
        if since is None and run_id is None:
            rows = store.due_response_actions(datetime.now(timezone.utc))
        else:
            rows = store.list_response_actions(status="applied", since=since, run_id=run_id)
        return list(dict.fromkeys(_text(row.ip) for row in rows))
    except (SentinelError, sqlite3.Error, AttributeError, TypeError):
        return None


def _confirm_unblock(
    pipeline: Any,
    operator: Any,
    prompt: str,
    yes: bool,
    since: datetime | None,
    run_id: str | None,
) -> None:
    """Show the IPs that will be unblocked (if known), then confirm."""
    if yes:
        return
    ips = _selected_ips(pipeline, operator, since, run_id)
    if ips is None:
        ui.console.print("Could not look up the affected IPs; the count is unknown.")
    elif not ips:
        ui.console.print("No matching blocks; nothing will be unblocked.")
    else:
        ui.console.print(f"{len(ips)} IP(s) will be unblocked:")
        for ip in ips[:_MAX_LISTED]:
            ui.console.print(f"  {ip}")
        if len(ips) > _MAX_LISTED:
            ui.console.print(f"  ... and {len(ips) - _MAX_LISTED} more")
    _confirm(prompt, yes)


# -- command -------------------------------------------------------------------


@click.command(name="respond")
@click.option("--pending", "show_pending", is_flag=True, help="List responses awaiting approval.")
@click.option(
    "--approve",
    "approve_ids",
    type=click.IntRange(min=1),
    multiple=True,
    metavar="ID",
    help="Approve a pending response and block its IP (repeatable).",
)
@click.option(
    "--deny",
    "deny_ids",
    type=click.IntRange(min=1),
    multiple=True,
    metavar="ID",
    help="Deny a pending response; nothing is blocked (repeatable).",
)
@click.option("--note", default="", help="Optional reason stored with --approve / --deny.")
@click.option("--reap", is_flag=True, help="Unblock expired temporary blocks now.")
@click.option("--rollback", is_flag=True, help="Undo blocks; needs --since or --run.")
@click.option(
    "--since",
    metavar="TEXT",
    help="With --rollback: blocks made since 30m / 2h / 3d ago or an ISO-8601 time.",
)
@click.option("--run", "run_id", metavar="RUN_ID", help="With --rollback: blocks of this run id.")
@click.option("--history", "show_history", is_flag=True, help="Show the response audit trail.")
@click.option(
    "--limit",
    type=click.IntRange(min=1),
    default=20,
    show_default=True,
    help="With --history: how many records to show.",
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@click.pass_context
def respond_cmd(
    ctx: click.Context,
    show_pending: bool,
    approve_ids: tuple[int, ...],
    deny_ids: tuple[int, ...],
    note: str,
    reap: bool,
    rollback: bool,
    since: str | None,
    run_id: str | None,
    show_history: bool,
    limit: int,
    yes: bool,
) -> None:
    """Review and decide firewall responses (human-approved blocking).

    Automatic response is OFF unless `response.enabled: true` is set in the
    config; nothing is blocked without it. Approvals re-check the lockout
    and allowlist rules, so a protected IP is refused even if approved.
    Exactly one action per call: --pending, --approve, --deny, --reap,
    --rollback (with --since or --run) or --history. Mutating actions ask
    for confirmation unless --yes is given. Exit code 1 if any action failed.
    """
    chosen = [
        name
        for name, active in (
            ("--pending", show_pending),
            ("--approve", bool(approve_ids)),
            ("--deny", bool(deny_ids)),
            ("--reap", reap),
            ("--rollback", rollback),
            ("--history", show_history),
        )
        if active
    ]
    if len(chosen) != 1:
        raise click.UsageError(
            "Specify exactly one of --pending, --approve, --deny, --reap, --rollback, --history."
        )
    if note and not (approve_ids or deny_ids):
        raise click.UsageError("--note only applies to --approve / --deny.")
    if run_id is not None and not run_id.strip():
        raise click.UsageError("--run needs a non-empty RUN_ID.")
    if (since is not None or run_id is not None) and not rollback:
        raise click.UsageError("--since / --run only apply to --rollback.")
    since_dt: datetime | None = None
    if rollback:
        if since is None and run_id is None:
            raise click.UsageError("--rollback needs --since TEXT or --run RUN_ID.")
        if since is not None:
            since_dt = parse_since(since)

    approve_list = list(dict.fromkeys(approve_ids))
    deny_list = list(dict.fromkeys(deny_ids))

    all_ok = True
    config = load_context(ctx).config
    try:
        pipeline = build_pipeline(config)
        try:
            operator = pipeline.operator
            if show_pending:
                _show_pending(operator)
            elif show_history:
                _show_history(operator, limit)
            elif approve_list:
                known = _confirm_ids(operator, approve_list, "Approve and apply", yes)
                all_ok = _approve(operator, known, note) if known else False
            elif deny_list:
                known = _confirm_ids(operator, deny_list, "Deny", yes)
                all_ok = _deny(operator, known, note) if known else False
            elif reap:
                _confirm_unblock(
                    pipeline,
                    operator,
                    "Unblock these expired temporary blocks now?",
                    yes,
                    None,
                    None,
                )
                all_ok = _report_actions(operator.reap(), "No expired blocks to remove.")
            else:
                _confirm_unblock(
                    pipeline,
                    operator,
                    "Roll back the selected blocks (unblock these IPs)?",
                    yes,
                    since_dt,
                    run_id,
                )
                all_ok = _report_actions(
                    operator.rollback(since=since_dt, run_id=run_id),
                    "Nothing to roll back for that selection.",
                )
        finally:
            pipeline.close()
    except SentinelError as exc:
        fail(exc)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    if not all_ok:
        sys.exit(1)
