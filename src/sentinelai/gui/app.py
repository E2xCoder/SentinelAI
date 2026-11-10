"""Entry point of the windowed program (``SentinelAI.exe`` / ``SentinelAI.app``)."""

from __future__ import annotations

import os
import sys


def _ensure_streams() -> None:
    """A windowed program has no console: give ``print`` and logging a sink."""
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115


def main() -> None:
    """Open the interface; ``--selftest [FILE]`` runs the packaging self-test."""
    _ensure_streams()
    from sentinelai.gui.launcher import run_gui, self_test

    args = sys.argv[1:]
    if args and args[0] == "--selftest":
        sys.exit(self_test(args[1] if len(args) > 1 else None))
    run_gui()


if __name__ == "__main__":
    main()
