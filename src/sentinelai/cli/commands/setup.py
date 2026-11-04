"""First-run commands: ``sentinel init`` and ``sentinel doctor``.

``init`` detects the host, generates a validated ``config.yaml`` and writes it
atomically with owner-only permissions; it never prompts. ``doctor`` runs the
environment diagnostics and exits non-zero only when a check failed.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from pathlib import Path

import click
from rich.markup import escape
from rich.table import Table

from sentinelai.cli import console as ui
from sentinelai.cli.common import fail, load_context
from sentinelai.config.loader import load_config
from sentinelai.core.exceptions import ConfigError, SentinelError
from sentinelai.setup.detect import detect_environment, explain_choices, render_config
from sentinelai.setup.doctor import FAIL, OK, WARN, CheckResult, run_checks, summarize

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_MAX_FIELD = 300
_STATUS_STYLE = {OK: ("green", "OK"), WARN: ("yellow", "WARN"), FAIL: ("red", "FAIL")}


def _clean(text: str) -> str:
    """Strip control characters (ESC, C0, DEL, C1) except tab and newline."""
    return _CONTROL_CHARS.sub("", text)


def _single_line(text: str) -> str:
    """Sanitise and collapse to one bounded line for terminal display."""
    flat = " ".join(_clean(text).split())
    return flat if len(flat) <= _MAX_FIELD else flat[: _MAX_FIELD - 3] + "..."


# -- init ---------------------------------------------------------------------


def _validate_config(content: str, directory: Path) -> None:
    """Load ``content`` through the real loader via a temp file; always cleans up."""
    fd, name = tempfile.mkstemp(dir=directory, prefix=".sentinel-init-", suffix=".yaml")
    temp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        load_config(temp)
    except OSError as exc:
        raise ConfigError(f"Cannot validate the generated config: {exc}") from exc
    finally:
        with contextlib.suppress(OSError):
            temp.unlink()


def _write_atomic(content: str, target: Path) -> None:
    """Write ``content`` to ``target`` via a same-directory temp file (mode 0600)."""
    fd, name = tempfile.mkstemp(dir=target.parent, prefix=".sentinel-init-", suffix=".yaml")
    temp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        with contextlib.suppress(OSError):  # not supported on every OS / filesystem
            os.chmod(temp, 0o600)
        os.replace(temp, target)
    except OSError as exc:
        with contextlib.suppress(OSError):
            temp.unlink()
        raise ConfigError(f"Cannot write {target}: {exc}") from exc


def _write_exclusive(content: str, target: Path) -> None:
    """Create ``target`` (mode 0600) only if it does not exist; never overwrite."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise ConfigError(f"{target} already exists. Use --force to overwrite it.") from exc
    except OSError as exc:
        raise ConfigError(f"Cannot write {target}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    except OSError as exc:
        with contextlib.suppress(OSError):
            target.unlink()
        raise ConfigError(f"Cannot write {target}: {exc}") from exc


def _prepare_directory(target: Path, *, create: bool) -> Path:
    """Return the directory for temp files; create it only when ``create``."""
    parent = target.parent
    if parent.is_dir():
        return parent
    if not create:
        return Path(tempfile.gettempdir())
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(f"Cannot create directory {parent}: {exc}") from exc
    return parent


@click.command(name="init")
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    default=Path("config.yaml"),
    show_default=True,
    help="Where to write the generated config.",
)
@click.option("--force", is_flag=True, help="Overwrite the output file if it already exists.")
@click.option("--dry-run", is_flag=True, help="Print the generated config and write nothing.")
@click.option("--state-dir", default="", help="State directory to record in the config.")
@click.option(
    "--llm/--no-llm",
    "enable_llm",
    default=False,
    help="Enable the local LLM triage block (off by default).",
)
@click.option("--llm-model", default="llama3.1:8b", show_default=True, help="Local model name.")
def init_cmd(
    output: Path,
    force: bool,
    dry_run: bool,
    state_dir: str,
    enable_llm: bool,
    llm_model: str,
) -> None:
    """Generate a config.yaml tailored to this host (never prompts).

    Detects log sources and security tools, writes a validated config
    (owner-only on POSIX) and prints the next steps. Automatic blocking
    stays OFF.
    """
    target = output.expanduser()
    if target.exists() and not force and not dry_run:
        fail(ConfigError(f"{target} already exists. Use --force to overwrite it."))

    detection = detect_environment()
    summary = ui.error_console if dry_run else ui.console
    summary.print("[bold]Detected environment[/bold]")
    for line in explain_choices(detection):
        text = escape(_single_line(line))
        summary.print(f"    {text}" if line.startswith(" ") else f"  - {text}")

    content = render_config(
        detection,
        state_dir=state_dir,
        enable_llm=enable_llm,
        llm_model=llm_model,
    )
    try:
        directory = _prepare_directory(target, create=not dry_run)
        _validate_config(content, directory)
        if dry_run:
            click.echo(_clean(content))
            return
        if force:
            _write_atomic(content, target)
        else:
            _write_exclusive(content, target)
    except SentinelError as exc:
        fail(exc)

    note = " (owner-only permissions)" if os.name == "posix" else ""
    ui.console.print(f"[green]Wrote[/green] {escape(_single_line(str(target)))}{note}")
    ui.console.print("[bold]Next steps[/bold]")
    ui.console.print("  1. sentinel doctor          check the environment")
    ui.console.print("  2. sentinel scan <file>     analyze a log file")
    ui.console.print("  3. sentinel live            monitor logs in real time")
    ui.console.print(
        "  Hint: for a system location, the service user must be able to read the "
        "file (chown/chmod as needed)."
    )
    ui.console.print(
        "[yellow]Automatic blocking is OFF.[/yellow] Use `sentinel respond` to review "
        "and approve firewall actions (approval mode)."
    )


# -- doctor -------------------------------------------------------------------


def _result_dict(result: CheckResult) -> dict[str, str]:
    return {
        "name": _single_line(result.name),
        "status": _single_line(result.status),
        "detail": _single_line(result.detail),
        "hint": _single_line(result.hint),
    }


def _render_table(results: list[CheckResult]) -> Table:
    table = Table(title="SentinelAI doctor")
    table.add_column("Status")
    table.add_column("Check")
    table.add_column("Detail", overflow="fold")
    for result in results:
        style, word = _STATUS_STYLE.get(result.status, ("white", "?"))
        detail = escape(_single_line(result.detail))
        if result.hint and result.status in (WARN, FAIL):
            detail += f"\n[dim]hint: {escape(_single_line(result.hint))}[/dim]"
        table.add_row(f"[{style}]{word}[/{style}]", escape(_single_line(result.name)), detail)
    return table


@click.command(name="doctor")
@click.option("--json", "as_json", is_flag=True, help="Print results as a JSON list.")
@click.pass_context
def doctor_cmd(ctx: click.Context, as_json: bool) -> None:
    """Check the environment (logs, state dir, LLM, firewall, notifications).

    Exits 1 when any check failed; warnings do not fail.
    """
    results = run_checks(load_context(ctx).config)
    ok, warn, failed = summarize(results)
    if as_json:
        click.echo(json.dumps([_result_dict(r) for r in results], sort_keys=True, indent=2))
    else:
        ui.console.print(_render_table(results))
        ui.console.print(f"{ok} ok, {warn} warning(s), {failed} failed")
    if failed:
        raise SystemExit(1)
