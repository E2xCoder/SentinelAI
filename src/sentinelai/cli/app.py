"""SentinelAI command-line interface (root group and entry point).

Commands live in :mod:`sentinelai.cli.commands`; this module only wires
them onto the root group, loads configuration/plugins, and translates
:class:`SentinelError` into clean messages with meaningful exit codes —
never tracebacks.
"""

from __future__ import annotations

import sys

import click

from sentinelai import __version__
from sentinelai.cli import console as ui
from sentinelai.cli.commands import ALL_COMMANDS
from sentinelai.cli.common import Context
from sentinelai.config.loader import load_config
from sentinelai.core.exceptions import SentinelError
from sentinelai.plugins.loader import load_plugins
from sentinelai.utils.logging import setup_logging


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.option(
    "--config", "config_path", type=click.Path(dir_okay=False),
    help="Path to config.yaml (else auto-detected).",
)
@click.option("--debug", is_flag=True, help="Enable debug logging.")
@click.option("--no-plugins", is_flag=True, help="Do not load plugins.")
@click.version_option(__version__, "-V", "--version", prog_name="sentinel")
@click.pass_context
def cli(ctx: click.Context, config_path: str | None, debug: bool, no_plugins: bool) -> None:
    """SentinelAI — AI-assisted security log analysis and response."""
    try:
        config = load_config(config_path)
    except SentinelError as exc:
        ui.error_console.print(f"[red]Configuration error:[/red] {exc}")
        raise SystemExit(exc.exit_code) from exc
    config.debug = config.debug or debug
    setup_logging(debug=config.debug, log_file=config.log_file or None)
    if not no_plugins:
        load_plugins()
    ctx.obj = Context(config)
    if ctx.invoked_subcommand is None:
        ui.print_banner()
        click.echo(ctx.get_help())


for _command in ALL_COMMANDS:
    cli.add_command(_command)


def main() -> None:
    """Entry point for the ``sentinel`` console script."""
    try:
        cli.main(standalone_mode=False)
    except SentinelError as exc:
        ui.error_console.print(f"[red]Error:[/red] {exc}")
        sys.exit(exc.exit_code)
    except click.ClickException as exc:
        exc.show()
        sys.exit(exc.exit_code)
    except click.exceptions.Abort:
        ui.error_console.print("\n[yellow]Aborted.[/yellow]")
        sys.exit(130)
    except KeyboardInterrupt:
        ui.error_console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
