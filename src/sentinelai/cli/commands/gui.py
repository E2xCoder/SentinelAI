"""``sentinel gui`` - open the desktop interface."""

from __future__ import annotations

import click


@click.command("gui")
@click.option("--port", default=0, show_default=True, help="Local port (0 picks a free one).")
@click.option("--no-window", is_flag=True, help="Only print the address; open no window.")
def gui_cmd(port: int, no_window: bool) -> None:
    """Open the desktop interface (scan logs and browse results)."""
    from sentinelai.gui import run_gui

    run_gui(port=port, open_window=not no_window)
