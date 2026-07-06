"""Sliding-window state used by stateful detection rules.

Windows operate on **event time**, not wall-clock time, so the same
rules work identically for historical scans, replays and live tailing.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any


@dataclass(slots=True)
class WindowEntry:
    """One observation inside a sliding window."""

    timestamp: datetime
    payload: dict[str, Any]


class SlidingWindowStore:
    """Keyed sliding windows of timestamped observations.

    Keys are arbitrary strings (rules typically use ``"<rule>:<ip>"``).
    Old entries are pruned lazily on access relative to the newest
    timestamp seen for that key, which keeps memory bounded during
    long-running live monitoring.
    """

    def __init__(self, max_entries_per_key: int = 5000) -> None:
        self._windows: dict[str, deque[WindowEntry]] = defaultdict(deque)
        self._max_entries = max_entries_per_key

    def add(self, key: str, timestamp: datetime, **payload: Any) -> None:
        """Record an observation for *key* at *timestamp*."""
        window = self._windows[key]
        window.append(WindowEntry(timestamp, payload))
        if len(window) > self._max_entries:
            window.popleft()

    def prune(self, key: str, now: datetime, window_seconds: int) -> None:
        """Drop entries older than the window relative to *now*."""
        window = self._windows.get(key)
        if not window:
            return
        cutoff = now - timedelta(seconds=window_seconds)
        while window and window[0].timestamp < cutoff:
            window.popleft()

    def entries(self, key: str, now: datetime, window_seconds: int) -> list[WindowEntry]:
        """Return in-window entries for *key* (after pruning)."""
        self.prune(key, now, window_seconds)
        return list(self._windows.get(key, ()))

    def count(self, key: str, now: datetime, window_seconds: int) -> int:
        """Number of in-window observations for *key*."""
        self.prune(key, now, window_seconds)
        return len(self._windows.get(key, ()))

    def distinct(self, key: str, now: datetime, window_seconds: int, field: str) -> set[Any]:
        """Distinct payload values of *field* within the window."""
        return {
            entry.payload.get(field)
            for entry in self.entries(key, now, window_seconds)
            if entry.payload.get(field) is not None
        }

    def span_seconds(self, key: str, now: datetime, window_seconds: int) -> float:
        """Seconds between oldest and newest in-window entries."""
        entries = self.entries(key, now, window_seconds)
        if len(entries) < 2:
            return 0.0
        return (entries[-1].timestamp - entries[0].timestamp).total_seconds()

    def clear_key(self, key: str) -> None:
        """Reset one window (used after a rule fires to avoid re-alerting)."""
        self._windows.pop(key, None)

    def clear(self) -> None:
        """Reset all state."""
        self._windows.clear()
