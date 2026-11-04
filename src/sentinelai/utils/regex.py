"""Regex helpers: bounded-window search against quadratic backtracking (ReDoS)."""

from __future__ import annotations

import re

DEFAULT_WINDOW = 2048
DEFAULT_OVERLAP = 512


def search_windowed(
    pattern: re.Pattern[str],
    text: str,
    *,
    window: int = DEFAULT_WINDOW,
    overlap: int = DEFAULT_OVERLAP,
) -> re.Match[str] | None:
    """Search ``text`` with ``pattern`` over overlapping fixed-size windows.

    An unanchored search whose alternatives contain a line-long gap rescans the rest of the
    line from every start position (O(n^2)). Capping each scan at ``window`` characters
    bounds the total cost to O(len(text) * window). Matches up to ``overlap`` characters
    long are always fully contained in at least one window; longer matches may be cut at a
    window edge. Text of at most ``window`` characters is searched exactly once, unchanged.

    The scan uses ``pos``/``endpos`` (not slicing), so the returned match refers to the
    original ``text`` and lookbehind/``\\b`` still see the characters before a window.
    """
    if window <= 0 or overlap < 0 or window <= overlap:
        raise ValueError("window must be > overlap and overlap must be >= 0")
    length = len(text)
    if length <= window:
        return pattern.search(text)
    step = window - overlap
    start = 0
    while True:
        end = min(start + window, length)
        match = pattern.search(text, start, end)
        if match is not None:
            return match
        if end >= length:
            return None
        start += step
