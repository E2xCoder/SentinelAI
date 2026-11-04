"""Streaming log-file reading.

Files are always read line-by-line so multi-gigabyte logs never need to
fit in memory. Gzip-compressed rotated logs (``auth.log.1.gz``) are
transparently supported.
"""

from __future__ import annotations

import gzip
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from sentinelai.core.exceptions import LogSourceError
from sentinelai.core.models import LogEvent
from sentinelai.parsers.base import LogParser, detect_parser, get_parser
from sentinelai.utils.logging import get_logger
from sentinelai.utils.paths import resolve_input_file

_LOGGER = get_logger("parsers.reader")

_SAMPLE_SIZE = 50


@dataclass(frozen=True, slots=True)
class ReaderLimits:
    """Resource limits applied while reading attacker-controlled logs."""

    max_line_chars: int = 65_536
    max_decompressed_bytes: int = 2 * 1024**3

    def __post_init__(self) -> None:
        if self.max_line_chars < 1 or self.max_decompressed_bytes < 1:
            raise ValueError("ReaderLimits values must be positive")


DEFAULT_LIMITS = ReaderLimits()


def _open_text(path: Path) -> IO[str]:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _bounded_lines(
    handle: IO[str], limits: ReaderLimits, *, is_gzip: bool, source: Path
) -> Iterator[str]:
    """Yield lines holding at most ``max_line_chars`` chars of any line."""
    max_chars = limits.max_line_chars
    total = 0
    oversized = 0
    skipping = False
    try:
        while True:
            chunk = handle.readline(max_chars + 1)
            if not chunk:
                break
            total += len(chunk)
            if is_gzip and total > limits.max_decompressed_bytes:
                raise LogSourceError(f"{source} exceeds the decompression limit")
            terminated = chunk.endswith("\n")
            if skipping:
                skipping = not terminated
                continue
            if terminated or len(chunk) <= max_chars:
                yield chunk
            else:
                oversized += 1
                skipping = True
    finally:
        if oversized:
            _LOGGER.warning("%s: %d oversized lines skipped", source, oversized)


def stream_lines(path: str | Path, limits: ReaderLimits | None = None) -> Iterator[str]:
    """Yield lines from a (possibly gzipped) log file, streaming.

    Memory per line is bounded by ``limits.max_line_chars``; longer lines
    are dropped and reported once per file.
    """
    active = limits or DEFAULT_LIMITS
    resolved = resolve_input_file(path)
    try:
        with _open_text(resolved) as handle:
            yield from _bounded_lines(
                handle, active, is_gzip=resolved.suffix == ".gz", source=resolved
            )
    except (OSError, EOFError, zlib.error) as exc:
        raise LogSourceError(f"Failed reading {resolved}: {exc}") from exc


def sample_lines(
    path: str | Path, limit: int = _SAMPLE_SIZE, limits: ReaderLimits | None = None
) -> list[str]:
    """Read up to *limit* non-empty lines for format detection."""
    sample: list[str] = []
    for line in stream_lines(path, limits):
        stripped = line.rstrip("\r\n")
        if stripped.strip():
            sample.append(stripped)
        if len(sample) >= limit:
            break
    return sample


def resolve_parser(
    path: str | Path,
    parser_name: str | None = None,
    limits: ReaderLimits | None = None,
) -> LogParser:
    """Return the parser to use for *path* (explicit or auto-detected)."""
    if parser_name:
        return get_parser(parser_name)
    resolved = resolve_input_file(path)
    return detect_parser(resolved.name, sample_lines(resolved, limits=limits))


def read_events(
    path: str | Path,
    parser: LogParser | None = None,
    parser_name: str | None = None,
    limits: ReaderLimits | None = None,
) -> Iterator[LogEvent]:
    """Stream structured events from a log file.

    The parser is auto-detected from content unless supplied. Malformed
    lines are counted and skipped, never fatal.
    """
    resolved = resolve_input_file(path)
    active = parser or resolve_parser(resolved, parser_name, limits)
    _LOGGER.debug("Reading %s with parser %s", resolved, active.name)
    active.reset_stream_state()
    yield from active.parse_lines(stream_lines(resolved, limits), source=str(resolved))
