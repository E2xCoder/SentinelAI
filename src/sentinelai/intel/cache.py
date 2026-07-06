"""SQLite-backed TTL cache for threat-intelligence lookups.

Free-tier TI APIs have tight quotas; caching verdicts on disk lets scans
and live monitoring reuse results across runs.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("intel.cache")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_cache (
    provider   TEXT NOT NULL,
    ip         TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (provider, ip)
);
"""


class IntelCache:
    """Per-provider, per-IP JSON cache with time-to-live expiry."""

    def __init__(self, db_path: str | Path, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def get(self, provider: str, ip: str) -> dict[str, Any] | None:
        """Return the cached payload, or None on miss/expiry."""
        try:
            row = self._conn.execute(
                "SELECT payload, created_at FROM intel_cache "
                "WHERE provider = ? AND ip = ?",
                (provider, ip),
            ).fetchone()
        except sqlite3.Error:
            _LOGGER.exception("Cache read failed")
            return None
        if row is None:
            return None
        payload, created_at = row
        if self._ttl and time.time() - created_at > self._ttl:
            self.delete(provider, ip)
            return None
        try:
            result: dict[str, Any] = json.loads(payload)
        except json.JSONDecodeError:
            self.delete(provider, ip)
            return None
        return result

    def put(self, provider: str, ip: str, payload: dict[str, Any]) -> None:
        """Store a payload, replacing any previous entry."""
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO intel_cache "
                "(provider, ip, payload, created_at) VALUES (?, ?, ?, ?)",
                (provider, ip, json.dumps(payload), time.time()),
            )
            self._conn.commit()
        except (sqlite3.Error, TypeError):
            _LOGGER.exception("Cache write failed")

    def delete(self, provider: str, ip: str) -> None:
        """Remove a cache entry."""
        try:
            self._conn.execute(
                "DELETE FROM intel_cache WHERE provider = ? AND ip = ?",
                (provider, ip),
            )
            self._conn.commit()
        except sqlite3.Error:
            _LOGGER.exception("Cache delete failed")

    def purge_expired(self) -> int:
        """Drop all expired rows; returns the number removed."""
        if not self._ttl:
            return 0
        try:
            cursor = self._conn.execute(
                "DELETE FROM intel_cache WHERE created_at < ?",
                (time.time() - self._ttl,),
            )
            self._conn.commit()
            return cursor.rowcount
        except sqlite3.Error:
            _LOGGER.exception("Cache purge failed")
            return 0

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()
