#!/usr/bin/env python3
"""Regenerate the README terminal screenshots (SVG) from the REAL CLI.

Usage::

    python scripts/make_screenshots.py [--out docs/screenshots]

Each screenshot is produced by running the actual ``sentinel`` command
in-process, with the shared Rich consoles swapped for recording consoles
(100 columns, truecolor), then exported with ``Console.save_svg``. No extra
dependencies are needed beyond SentinelAI itself.

Everything runs in an ISOLATED sandbox: a temporary HOME (so state, overlay
and plugin directories are empty), a temporary config file, no plugins
(``--no-plugins``), and all API-key-looking environment variables removed so
no network/LLM/intel lookups can happen.

The SVGs are committed and referenced by the README. RE-RUN THIS SCRIPT
whenever command output changes (new columns, wording, rules, version) and
commit the refreshed images, otherwise the README will show stale output.
"""

from __future__ import annotations

import argparse
import io
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WIDTH = 100

_SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.IGNORECASE)

_PLAIN_CONFIG = "{}\n"
_RESPONSE_CONFIG = (
    "firewall:\n  adapter: dry_run\n"
    "response:\n  enabled: true\n  mode: approval\n  min_risk_level: medium\n"
)

# A table row of the alerts table starts with its numeric id cell.
_ROW_ID = re.compile(r"^[│┃|]\s*(\d+)\s*[│┃|]")


class ScreenshotError(Exception):
    """A capture failed or produced unusable output."""


@dataclass
class Capture:
    """One screenshot: output name, title, CLI args and accepted exit codes."""

    name: str
    title: str
    args: list[str]
    ok_codes: tuple[int, ...] = (0,)
    config: str = "plain"


def _sandbox_environment(home: Path, plugins: Path) -> None:
    """Point HOME/plugins at temp dirs and drop anything that looks like a secret."""
    for key in list(os.environ):
        if key.startswith("SENTINELAI_") or _SECRET_ENV.search(key):
            del os.environ[key]
    os.environ["HOME"] = str(home)
    os.environ["USERPROFILE"] = str(home)
    os.environ["XDG_CONFIG_HOME"] = str(home / ".config")
    os.environ["XDG_DATA_HOME"] = str(home / ".local" / "share")
    os.environ["SENTINELAI_PLUGINS_DIR"] = str(plugins)
    os.environ.pop("NO_COLOR", None)


def _new_console(*, record: bool = True) -> object:
    from rich.console import Console

    return Console(
        record=record,
        width=WIDTH,
        file=io.StringIO(),
        force_terminal=True,
        color_system="truecolor",
    )


def _run_cli(args: list[str], config_path: Path) -> int:
    """Invoke the real CLI in-process and return its exit code."""
    import click

    from sentinelai.cli.app import cli
    from sentinelai.core.exceptions import SentinelError

    full = ["--config", str(config_path), "--no-plugins", *args]
    try:
        result = cli.main(args=full, prog_name="sentinel", standalone_mode=False)
    except SentinelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return int(exc.exit_code)
    except click.ClickException as exc:
        exc.show()
        return int(exc.exit_code)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    return result if isinstance(result, int) else 0


def _execute(capture: Capture, config_path: Path) -> tuple[int, object, str]:
    """Run one command with recording consoles swapped in.

    Returns ``(exit_code, stdout_console, stderr_text)``.
    """
    from sentinelai.cli import console as ui

    out_console = _new_console()
    err_console = _new_console(record=False)
    original = (ui.console, ui.error_console)
    ui.console, ui.error_console = out_console, err_console  # type: ignore[assignment]
    try:
        code = _run_cli(capture.args, config_path)
    finally:
        ui.console, ui.error_console = original
    stderr_text = err_console.file.getvalue()  # type: ignore[attr-defined]
    return code, out_console, stderr_text


_RULE_ROW = re.compile(r"^\W*(\d+)\s*[\u2502|].*\bR031\b")


def _find_reverse_shell_id(console: object) -> str:
    """Find the stored alert id of the reverse-shell (R031) alert in a scan table."""
    text = console.export_text()  # type: ignore[attr-defined]
    for line in text.splitlines():
        match = _RULE_ROW.match(line)
        if match:
            return match.group(1)
    raise ScreenshotError("could not find a reverse-shell alert id in the scan output")


def _save(console: object, capture: Capture, out_dir: Path) -> Path:
    path = out_dir / f"{capture.name}.svg"
    console.save_svg(str(path), title=capture.title, clear=False)  # type: ignore[attr-defined]
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Regenerate README terminal screenshots.")
    parser.add_argument(
        "--out", default=str(REPO_ROOT / "docs" / "screenshots"),
        help="Output directory (default: docs/screenshots).",
    )
    options = parser.parse_args(argv)
    out_dir = Path(options.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    auth_log = str(REPO_ROOT / "examples" / "auth.log")
    baseline = str(REPO_ROOT / "benchmarks" / "baseline.json")

    written: list[Path] = []
    failures: list[str] = []

    with tempfile.TemporaryDirectory(prefix="sentinelai-shots-") as tmp:
        tmp_path = Path(tmp)
        home = tmp_path / "home"
        plugins = tmp_path / "plugins"
        home.mkdir()
        plugins.mkdir()
        plain_cfg = tmp_path / "plain.yaml"
        plain_cfg.write_text(_PLAIN_CONFIG, encoding="utf-8")
        response_cfg = tmp_path / "response.yaml"
        response_cfg.write_text(_RESPONSE_CONFIG, encoding="utf-8")

        _sandbox_environment(home, plugins)
        os.chdir(REPO_ROOT)

        def run(capture: Capture, cfg: Path, *, save: bool = True) -> object | None:
            code, console, stderr_text = _execute(capture, cfg)
            if code not in capture.ok_codes:
                failures.append(f"{capture.name}: exit code {code} (expected {capture.ok_codes})")
                if stderr_text.strip():
                    print(stderr_text, file=sys.stderr)
                return None
            if save:
                written.append(_save(console, capture, out_dir))
            return console

        scan = run(
            Capture("scan", "sentinel scan examples/auth.log",
                    ["scan", auth_log], ok_codes=(0, 1)),
            plain_cfg,
        )
        if scan is not None:
            try:
                alert_id = _find_reverse_shell_id(scan)
            except ScreenshotError as exc:
                failures.append(f"explain: {exc}")
            else:
                run(
                    Capture("explain", f"sentinel explain {alert_id}", ["explain", alert_id]),
                    plain_cfg,
                )

        run(
            Capture("eval", "sentinel eval --baseline benchmarks/baseline.json",
                    ["eval", "--baseline", baseline], ok_codes=(0, 1)),
            plain_cfg,
        )
        run(Capture("rules", "sentinel rules", ["rules"]), plain_cfg)

        # Scan again with approval-mode response enabled (output discarded) so
        # the dry-run adapter has queued requests for `respond --pending`.
        run(
            Capture("respond-scan", "sentinel scan", ["scan", auth_log], ok_codes=(0, 1)),
            response_cfg,
            save=False,
        )
        run(
            Capture("respond", "sentinel respond --pending", ["respond", "--pending"]),
            response_cfg,
        )
        run(Capture("doctor", "sentinel doctor", ["doctor"], ok_codes=(0, 1)), plain_cfg)

    for path in written:
        print(f"wrote {path}")
    for failure in failures:
        print(f"FAILED {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
