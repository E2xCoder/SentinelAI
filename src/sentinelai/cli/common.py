"""Shared CLI helpers used across command modules.

Keeping these here (rather than in ``app.py``) lets each command module
depend on the helpers without importing the click group, which would
create a circular import.
"""

from __future__ import annotations

from typing import NoReturn

import click

from sentinelai.cli import console as ui
from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import SentinelError
from sentinelai.core.pipeline import AnalysisPipeline


class Context:
    """Shared state passed to subcommands via click's context object."""

    def __init__(self, config: SentinelConfig) -> None:
        self.config = config


def load_context(ctx: click.Context) -> Context:
    """Return the :class:`Context` attached to the click context."""
    obj: Context = ctx.obj
    return obj


def build_pipeline(config: SentinelConfig) -> AnalysisPipeline:
    """Construct the analysis pipeline for a command invocation."""
    return AnalysisPipeline(config)


def fail(exc: SentinelError) -> NoReturn:
    """Print a clean error and exit with the exception's code."""
    ui.error_console.print(f"[red]Error:[/red] {exc}")
    raise SystemExit(exc.exit_code)
