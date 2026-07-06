"""Streaming log-file reading.

Files are always read line-by-line so multi-gigabyte logs never need to
fit in memory. Gzip-compressed rotated logs (``auth.log.1.gz``) are
transparently supported.
"""

from __future__ import annotations

import gzip
from collections.abc import Iterator
from pathlib import Path
from typing import IO

from sentinelai.core.exceptions import LogSourceError
from sentinelai.core.models import LogEvent
from sentinelai.parsers.base import LogParser, detect_parser, get_parser
from sentinelai.utils.logging import get_logger
from sentinelai.utils.paths import resolve_input_file

_LOGGER = get_logger("parsers.reader")

_SAMPLE_SIZE = 50


def _open_text(path: Path) -> IO[str]:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def stream_lines(path: str | Path) -> Iterator[str]:
    """Yield lines from a (possibly gzipped) log file, streaming."""
    resolved = resolve_input_file(path)
    try:
        with _open_text(resolved) as handle:
            yield from handle
    except OSError as exc:
        raise LogSourceError(f"Failed reading {resolved}: {exc}") from exc


def sample_lines(path: str | Path, limit: int = _SAMPLE_SIZE) -> list[str]:
    """Read up to *limit* non-empty lines for format detection."""
    sample: list[str] = []
    for line in stream_lines(path):
        stripped = line.rstrip("\r\n")
        if stripped.strip():
            sample.append(stripped)
        if len(sample) >= limit:
            break
    return sample


def resolve_parser(path: str | Path, parser_name: str | None = None) -> LogParser:
    """Return the parser to use for *path* (explicit or auto-detected)."""
    if parser_name:
        return get_parser(parser_name)
    resolved = resolve_input_file(path)
    return detect_parser(resolved.name, sample_lines(resolved))


def read_events(
    path: str | Path,
    parser: LogParser | None = None,
    parser_name: str | None = None,
) -> Iterator[LogEvent]:
    """Stream structured events from a log file.

    The parser is auto-detected from content unless supplied. Malformed
    lines are counted and skipped, never fatal.
    """
    resolved = resolve_input_file(path)
    active = parser or resolve_parser(resolved, parser_name)
    _LOGGER.debug("Reading %s with parser %s", resolved, active.name)
    yield from active.parse_lines(stream_lines(resolved), source=str(resolved))
