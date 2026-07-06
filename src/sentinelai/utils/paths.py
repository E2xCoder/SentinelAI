"""Filesystem safety helpers.

SentinelAI reads operator-supplied paths (log files, report targets) and
writes reports and state. These helpers keep those operations inside
expected boundaries and produce clear errors instead of tracebacks.
"""

from __future__ import annotations

import os
from pathlib import Path

from sentinelai.core.exceptions import LogSourceError


def resolve_input_file(path: str | Path, must_exist: bool = True) -> Path:
    """Resolve a user-supplied input file path safely.

    Expands ``~``, resolves symlinks and validates that the target is a
    readable regular file. Raises :class:`LogSourceError` with a clear
    message otherwise.
    """
    try:
        resolved = Path(path).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise LogSourceError(f"Invalid path {str(path)!r}: {exc}") from exc
    if must_exist:
        if not resolved.exists():
            raise LogSourceError(f"File not found: {resolved}")
        if resolved.is_dir():
            raise LogSourceError(f"Expected a file but got a directory: {resolved}")
        if not os.access(resolved, os.R_OK):
            raise LogSourceError(f"File is not readable (permission denied): {resolved}")
    return resolved


def resolve_output_file(path: str | Path, base_dir: str | Path | None = None) -> Path:
    """Resolve an output path, optionally confined below *base_dir*.

    When *base_dir* is given, the resolved path must stay inside it —
    this protects against path traversal when the output location comes
    from configuration or templated report names.
    """
    resolved = Path(path).expanduser().resolve()
    if base_dir is not None:
        base = Path(base_dir).expanduser().resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            raise LogSourceError(
                f"Output path {resolved} escapes the allowed directory {base}"
            ) from None
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def default_state_dir() -> Path:
    """Directory for SentinelAI runtime state (alert DB, caches, models)."""
    override = os.environ.get("SENTINELAI_STATE_DIR")
    base = Path(override).expanduser() if override else Path.home() / ".sentinelai"
    base.mkdir(parents=True, exist_ok=True)
    return base
