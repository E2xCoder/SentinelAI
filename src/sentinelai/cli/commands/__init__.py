"""CLI command implementations, grouped by concern.

``analysis`` holds the commands that run the pipeline (scan, analyze,
replay, live); ``inspection`` holds the read-only commands (explain,
report, search, rules, config, version); ``evaluation`` holds the offline
benchmark command (eval); ``tuning`` holds the feedback-driven tuning loop
(feedback, review, tune). ``app.py`` registers them on
the root group, so adding a command is a local change here.
"""

from sentinelai.cli.commands.analysis import analyze, live, replay, scan
from sentinelai.cli.commands.evaluation import eval_cmd
from sentinelai.cli.commands.inspection import (
    config_cmd,
    explain,
    report,
    rules_cmd,
    search,
    version_cmd,
)
from sentinelai.cli.commands.tuning import feedback_cmd, review_cmd, tune_cmd

#: Every command registered on the root CLI group, in help order.
ALL_COMMANDS = [
    scan,
    analyze,
    live,
    replay,
    search,
    explain,
    report,
    rules_cmd,
    config_cmd,
    version_cmd,
    eval_cmd,
    feedback_cmd,
    review_cmd,
    tune_cmd,
]

__all__ = ["ALL_COMMANDS"]
