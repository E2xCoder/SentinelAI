"""Rotation-aware log file tailing (a pure-Python ``tail -F``).

Polling keeps the implementation dependency-free and works on every
filesystem. Rotation and truncation are detected via inode changes and
size regression, so logrotate never silently kills the stream.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import IO

from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("monitor.tailer")


class LogTailer:
    """Incrementally reads new lines appended to one file.

    Call :meth:`poll` periodically; it returns whatever complete new
    lines appeared since the last call. A missing file is tolerated and
    picked up when it (re)appears.
    """

    def __init__(self, path: str | Path, from_beginning: bool = False) -> None:
        self._path = Path(path)
        self._handle: IO[str] | None = None
        self._inode: int | None = None
        self._position = 0
        self._from_beginning = from_beginning
        self._partial = ""
        self._open(initial=True)

    @property
    def path(self) -> Path:
        return self._path

    def _open(self, initial: bool = False) -> None:
        try:
            handle = self._path.open("r", encoding="utf-8", errors="replace")
        except OSError:
            self._handle = None
            return
        stat = os.fstat(handle.fileno())
        self._inode = stat.st_ino
        if initial and not self._from_beginning:
            handle.seek(0, os.SEEK_END)
        self._position = handle.tell()
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
            self._partial = ""
            self._open()
            if self._handle is None:
                return []
        assert self._handle is not None
        try:
            chunk = self._handle.read()
        except (OSError, ValueError):
            self._close_handle()
            return []
        if not chunk:
            return []
        self._position = self._handle.tell()
        text = self._partial + chunk
        lines = text.split("\n")
        # The final element is either empty (chunk ended on a newline) or
        # an incomplete line to carry into the next poll.
        self._partial = lines.pop()
        return [line.rstrip("\r") for line in lines if line.strip()]

    def _close_handle(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:
                pass
        self._handle = None
        self._inode = None
        self._position = 0

    def close(self) -> None:
        """Stop tailing and release the file handle."""
        self._close_handle()
