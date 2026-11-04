"""Digest command: ``sentinel digest`` builds (and optionally sends) an alert summary.

Without ``--send`` the digest is only printed; nothing leaves the machine.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from typing import Any

import click

from sentinelai.cli import console as ui
from sentinelai.cli.common import fail, load_context
from sentinelai.core.exceptions import SentinelError
from sentinelai.core.store import AlertStore
from sentinelai.notify.base import DigestMessage, NotifyError, build_notifiers, clean_text
from sentinelai.notify.digest import build_digest

_CHANNELS = ("telegram", "slack", "email")
_LANGUAGES = ("en", "tr", "de")
_MAX_ERROR_CHARS = 200


def _show(text: str, *, error: bool = False) -> None:
    """Print ``text`` verbatim: no markup, emoji codes or highlighting."""
    target = ui.error_console if error else ui.console
    target.print(text, markup=False, highlight=False, emoji=False, soft_wrap=True)


def _safe_line(value: object) -> str:
    """Single-line, control-character-free text for terminal output."""
    return " ".join(clean_text(value, _MAX_ERROR_CHARS).split())


def _configured_channels(raw: object) -> list[str]:
    """Normalised channel names from ``notify.channels`` (list or comma string)."""
    if isinstance(raw, str):
        items: list[object] = list(raw.split(","))
    elif isinstance(raw, (list, tuple)):
        items = list(raw)
    else:
        return []
    names = (str(item).strip().lower() for item in items)
    return list(dict.fromkeys(name for name in names if name))


def _print_digest(message: DigestMessage) -> None:
    _show(f"Subject: {_safe_line(message.subject)}")
    _show("")
    for line in message.body.split("\n"):
        _show(line)


def _deliver(notifiers: list[Any], message: DigestMessage) -> bool:
    """Send to every notifier; print one result line each. ``True`` if all succeeded."""
    all_ok = True
    for notifier in notifiers:
        name = _safe_line(getattr(notifier, "name", "channel"))
        try:
            notifier.send(message)
        except NotifyError as exc:
            _show(f"{name}: FAILED - {_safe_line(exc)}", error=True)
            all_ok = False
            continue
        _show(f"{name}: sent")
    return all_ok


@click.command("digest")
@click.option(
    "--hours",
    type=click.IntRange(1, 720),
    default=24,
    show_default=True,
    help="How many hours back to summarise.",
)
@click.option(
    "--language",
    type=click.Choice(_LANGUAGES),
    default=None,
    help="Language of the digest (default: notify.language from the config).",
)
@click.option("--send", is_flag=True, help="Send the digest through the configured channels.")
@click.option(
    "--channel",
    "channels",
    type=click.Choice(_CHANNELS),
    multiple=True,
    help="With --send: only use this configured channel (repeatable).",
)
@click.pass_context
def digest_cmd(
    ctx: click.Context,
    hours: int,
    language: str | None,
    send: bool,
    channels: tuple[str, ...],
) -> None:
    """Summarise recent alerts in plain language.

    Prints the digest to the terminal; nothing is sent unless --send is given.
    With --send it goes to the channels listed in `notify.channels` (restrict
    them with --channel). Exit code 1 if any channel failed.
    """
    if channels and not send:
        raise click.UsageError("--channel only applies together with --send.")

    config = load_context(ctx).config
    notify = config.notify
    requested = list(dict.fromkeys(channels))
    if requested:
        configured = _configured_channels(notify.channels)
        missing = [name for name in requested if name not in configured]
        if missing:
            raise click.UsageError(
                "channel(s) not in notify.channels: " + ", ".join(missing)
            )

    all_ok = True
    try:
        notifiers: list[Any] = []
        if send:
            if requested:
                overrides: dict[str, Any] = {"channels": requested}
                notifiers = list(build_notifiers(replace(notify, **overrides)))
            else:
                notifiers = list(build_notifiers(notify))
            if not notifiers:
                raise NotifyError("no notify channels are configured (notify.channels is empty)")

        store = AlertStore(config.resolve_state_dir() / "alerts.db")
        try:
            message = build_digest(
                store,
                hours=hours,
                language=language or str(notify.language),
                max_alerts=int(notify.max_alerts),
            )
        finally:
            store.close()

        if send:
            all_ok = _deliver(notifiers, message)
        else:
            _print_digest(message)
            _show("")
            _show("Nothing was sent (use --send to deliver this digest).")
    except SentinelError as exc:
        fail(exc)
    if not all_ok:
        sys.exit(1)
