"""Rotation-aware log file tailing (a pure-Python ``tail -F``).

Polling keeps the implementation dependency-free and works on every
filesystem. Rotation and truncation are detected via inode changes and
size regression, so logrotate never silently kills the stream.

The file is read in binary mode so ``_position`` is always a real byte
offset (a text-mode ``tell()`` is an opaque cookie and breaks the
size-regression check).
"""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import IO

from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("monitor.tailer")

# Upper bound on BYTES consumed per poll; the rest is read next poll.
# (Name kept for backwards compatibility with existing callers/tests.)
_MAX_READ_CHARS = 8 * 1024 * 1024

# Longest UTF-8 encoding of one character.
_MAX_BYTES_PER_CHAR = 4

# Minimum seconds between oversized-line summary warnings.
_WARN_INTERVAL_SECONDS = 60.0


class LogTailer:
    """Incrementally reads new lines appended to one file.

    Call :meth:`poll` periodically; it returns whatever complete new
    lines appeared since the last call. A missing file is tolerated and
    picked up when it (re)appears.
    """

    def __init__(
        self,
        path: str | Path,
        from_beginning: bool = False,
        *,
        max_line_chars: int = 65_536,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_line_chars < 1:
            raise ValueError("max_line_chars must be positive")
        self._path = Path(path)
        self._handle: IO[bytes] | None = None
        self._inode: int | None = None
        self._position = 0
        self._from_beginning = from_beginning
        self._max_line_chars = max_line_chars
        self._max_line_bytes = max_line_chars * _MAX_BYTES_PER_CHAR
        self._clock = clock
        self._partial = b""
        self._discarding = False
        self._oversized = 0
        self._last_warned_at: float | None = None
        self._last_warned_count = 0
        self._open(initial=True)

    @property
    def path(self) -> Path:
        return self._path

    def _open(self, initial: bool = False) -> None:
        try:
            handle = self._path.open("rb")
        except OSError:
            self._handle = None
            return
        try:
            stat = os.fstat(handle.fileno())
            if initial and not self._from_beginning:
                handle.seek(0, os.SEEK_END)
            position = handle.tell()
        except OSError:
            with contextlib.suppress(OSError):
                handle.close()
            self._handle = None
            return
        except BaseException:
            with contextlib.suppress(OSError):
                handle.close()
            raise
        self._inode = stat.st_ino
        self._position = position
        self._handle = handle

    def _rotated(self) -> bool:
        try:
            stat = self._path.stat()
        except OSError:
            return True
        if self._inode is not None and stat.st_ino != self._inode:
            return True
        return stat.st_size < self._position

    def poll(self) -> list[str]:
        """Return complete new lines appended since the previous poll."""
        if self._handle is None:
            self._open()
            if self._handle is None:
                return []
        elif self._rotated():
            _LOGGER.debug("Rotation detected on %s; reopening", self._path)
            self._close_handle()
            self._partial = b""
            self._discarding = False
            self._open()
            if self._handle is None:
                return []
        assert self._handle is not None
        try:
            chunk = self._handle.read(_MAX_READ_CHARS)
        except (OSError, ValueError):
            self._close_handle()
            return []
        if not chunk:
            return []
        self._position += len(chunk)
        if self._discarding:
            # Skip the remainder of an oversized line up to its newline.
            newline = chunk.find(b"\n")
            if newline < 0:
                return []
            chunk = chunk[newline + 1 :]
            self._discarding = False
        lines = (self._partial + chunk).split(b"\n")
        # The final element is either empty (chunk ended on a newline) or
        # an incomplete line to carry into the next poll.
        self._partial = lines.pop()
        if len(self._partial) > self._max_line_bytes:
            # No character is wider than 4 bytes, so this line is surely
            # longer than max_line_chars once decoded.
            self._partial = b""
            self._discarding = True
            self._note_oversized()
        return self._decode_lines(lines)

    def _decode_lines(self, lines: list[bytes]) -> list[str]:
        limit = self._max_line_chars
        kept: list[str] = []
        for raw in lines:
            if len(raw) > self._max_line_bytes:
                self._note_oversized()
                continue
            line = raw.decode("utf-8", errors="replace")
            if len(line) > limit:
                self._note_oversized()
            elif line.strip():
                kept.append(line.rstrip("\r"))
        return kept

    def _note_oversized(self) -> None:
        """Count an oversized line; warn on the first, then at most once a minute."""
        self._oversized += 1
        now = self._clock()
        if self._last_warned_at is None:
            _LOGGER.warning(
                "%s: oversized line dropped (> %d chars)",
                self._path,
                self._max_line_chars,
            )
        elif now - self._last_warned_at >= _WARN_INTERVAL_SECONDS:
            _LOGGER.warning(
                "%s: %d oversized lines dropped (> %d chars), %d total",
                self._path,
                self._oversized - self._last_warned_count,
                self._max_line_chars,
                self._oversized,
            )
        else:
            return
        self._last_warned_at = now
        self._last_warned_count = self._oversized

    def _close_handle(self) -> None:
        if self._handle is not None:
            with contextlib.suppress(OSError):
                self._handle.close()
        self._handle = None
        self._inode = None
        self._position = 0

    def close(self) -> None:
        """Stop tailing and release the file handle."""
        self._close_handle()
