"""Simple token-bucket rate limiter for outbound API calls."""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Token bucket allowing *rate_per_minute* acquisitions per minute.

    ``acquire`` blocks (up to *max_wait* seconds) until a token is
    available. Thread-safe so live monitoring can share one limiter.
    """

    def __init__(self, rate_per_minute: int, max_wait: float = 30.0) -> None:
        self._capacity = max(1, rate_per_minute)
        self._tokens = float(self._capacity)
        self._fill_rate = self._capacity / 60.0
        self._max_wait = max_wait
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        self._tokens = min(
            float(self._capacity), self._tokens + (now - self._updated) * self._fill_rate
        )
        self._updated = now

    def try_acquire(self) -> bool:
        """Take a token if one is available, without blocking."""
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    def acquire(self) -> bool:
        """Block until a token is available or *max_wait* elapses."""
        deadline = time.monotonic() + self._max_wait
        while time.monotonic() < deadline:
            if self.try_acquire():
                return True
            with self._lock:
                self._refill()
                missing = 1.0 - self._tokens
                wait = missing / self._fill_rate if self._fill_rate else self._max_wait
            time.sleep(min(max(wait, 0.05), deadline - time.monotonic(), 1.0))
        return self.try_acquire()
