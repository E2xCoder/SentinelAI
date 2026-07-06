"""Structured logging for SentinelAI internals.

Application logs (about SentinelAI itself, not the analyzed logs) are
emitted as single-line ``key=value`` records so they can be shipped to
any log pipeline. In debug mode a human-friendly rich handler is used.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

_CONFIGURED = False


class KeyValueFormatter(logging.Formatter):
    """Format records as ``ts=... level=... logger=... msg="..." key=value``."""

    def format(self, record: logging.LogRecord) -> str:
        base = (
            f"ts={self.formatTime(record, '%Y-%m-%dT%H:%M:%S%z')} "
            f"level={record.levelname.lower()} "
            f"logger={record.name} "
            f'msg="{record.getMessage()}"'
        )
        extra = getattr(record, "ctx", None)
        if isinstance(extra, dict):
            for key, value in extra.items():
                base += f" {key}={value}"
        if record.exc_info and record.exc_info[0] is not None:
            base += f" exc={record.exc_info[0].__name__}"
        return base


def setup_logging(debug: bool = False, log_file: str | Path | None = None) -> None:
    """Configure the ``sentinelai`` logger hierarchy once.

    Args:
        debug: When true, emit DEBUG records to stderr with rich tracebacks.
        log_file: Optional file to append structured records to.
    """
    global _CONFIGURED
    root = logging.getLogger("sentinelai")
    root.setLevel(logging.DEBUG)
    if _CONFIGURED:
        root.handlers.clear()

    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(logging.DEBUG if debug else logging.WARNING)
    stream.setFormatter(KeyValueFormatter())
    root.addHandler(stream)

    if log_file is not None:
        path = Path(log_file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(KeyValueFormatter())
        root.addHandler(file_handler)

    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger under the ``sentinelai`` hierarchy."""
    if not name.startswith("sentinelai"):
        name = f"sentinelai.{name}"
    return logging.getLogger(name)


def log_context(logger: logging.Logger, level: int, msg: str, **ctx: Any) -> None:
    """Log a message with structured ``key=value`` context fields."""
    logger.log(level, msg, extra={"ctx": ctx})
