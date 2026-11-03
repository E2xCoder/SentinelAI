"""SQLite-backed TTL cache for validated triage verdicts.

Entries are keyed by alert fingerprint, model, language and prompt hash, so
a changed prompt, model or language never serves a stale verdict.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sentinelai.ai.triage_models import (
    MAX_ACTION_CHARS,
    MAX_ACTIONS,
    MAX_REASONING_CHARS,
    MAX_SUMMARY_CHARS,
    VERDICTS,
    TriageResult,
)
from sentinelai.core.exceptions import StorageError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS triage_cache (
    fingerprint TEXT NOT NULL,
    model       TEXT NOT NULL,
    language    TEXT NOT NULL,
    prompt_sha  TEXT NOT NULL,
    result      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (fingerprint, model, language, prompt_sha)
);
"""

_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f+00:00"


def prompt_sha(system: str, user: str) -> str:
    """Return the sha256 hex digest of the system and user prompts."""
    digest = hashlib.sha256()
    digest.update(system.encode("utf-8", errors="replace"))
    digest.update(b"\x00")
    digest.update(user.encode("utf-8", errors="replace"))
    return digest.hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime(_TIME_FORMAT)


def _from_iso(text: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _result_from_json(text: str) -> TriageResult | None:
    """Rebuild a :class:`TriageResult`; None when the JSON is not a valid one."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    verdict = data.get("verdict")
    confidence = data.get("confidence")
    summary = data.get("summary")
    reasoning = data.get("reasoning")
    actions = data.get("recommended_actions")
    event_ids = data.get("referenced_event_ids")
    if verdict not in VERDICTS:
        return None
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not math.isfinite(confidence)
        or not 0.0 <= confidence <= 1.0
    ):
        return None
    # Re-apply the output contract: a row that could not have been produced by
    # parse_triage (tampered or from an older version) is corrupt.
    if not isinstance(summary, str) or not 0 < len(summary) <= MAX_SUMMARY_CHARS:
        return None
    if not isinstance(reasoning, str) or not 0 < len(reasoning) <= MAX_REASONING_CHARS:
        return None
    if (
        not isinstance(actions, list)
        or not _is_str_list(actions)
        or len(actions) > MAX_ACTIONS
        or any(not 0 < len(action) <= MAX_ACTION_CHARS for action in actions)
    ):
        return None
    if (
        not isinstance(event_ids, list)
        or not all(
            isinstance(item, int) and not isinstance(item, bool) and item > 0
            for item in event_ids
        )
        or len(set(event_ids)) != len(event_ids)
    ):
        return None
    return TriageResult(
        verdict=verdict,
        confidence=float(confidence),
        summary=summary,
        reasoning=reasoning,
        recommended_actions=tuple(actions),
        referenced_event_ids=tuple(event_ids),
    )


class TriageCache:
    """Persistent cache of triage verdicts with time-to-live expiry."""

    def __init__(
        self,
        db_path: Path | str,
        ttl_seconds: int,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._ttl = max(0, int(ttl_seconds))
        self._now = now or _utc_now
        try:
            path = Path(db_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(path))
            self._conn.execute(_SCHEMA)
            self._conn.commit()
        except (sqlite3.Error, OSError) as exc:
            raise StorageError(f"Cannot open triage cache: {exc}") from exc

    def get(
        self, fingerprint: str, model: str, language: str, prompt_sha: str
    ) -> TriageResult | None:
        """Return the cached verdict, or None on miss, expiry or corruption."""
        if self._ttl == 0:
            return None
        key = (fingerprint, model, language, prompt_sha)
        try:
            row = self._conn.execute(
                "SELECT result, created_at FROM triage_cache "
                "WHERE fingerprint = ? AND model = ? AND language = ? AND prompt_sha = ?",
                key,
            ).fetchone()
            if row is None:
                return None
            result_text, created_text = row
            created = _from_iso(created_text)
            if created is None:
                self._delete(key)
                return None
            age = self._now() - created
            if age < timedelta(0) or age > timedelta(seconds=self._ttl):
                self._delete(key)
                return None
            result = _result_from_json(result_text)
            if result is None:
                self._delete(key)
            return result
        except sqlite3.Error as exc:
            raise StorageError(f"Triage cache read failed: {exc}") from exc

    def put(
        self,
        fingerprint: str,
        model: str,
        language: str,
        prompt_sha: str,
        result: TriageResult,
    ) -> None:
        """Store a verdict, replacing any previous entry for the same key."""
        if self._ttl == 0:
            return
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO triage_cache "
                "(fingerprint, model, language, prompt_sha, result, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    fingerprint,
                    model,
                    language,
                    prompt_sha,
                    json.dumps(result.to_dict(), ensure_ascii=False),
                    _to_iso(self._now()),
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError(f"Triage cache write failed: {exc}") from exc

    def purge_expired(self) -> int:
        """Drop all expired rows; returns the number removed."""
        if self._ttl == 0:
            return 0
        cutoff = _to_iso(self._now() - timedelta(seconds=self._ttl))
        try:
            cursor = self._conn.execute(
                "DELETE FROM triage_cache WHERE created_at < ?", (cutoff,)
            )
            self._conn.commit()
            return cursor.rowcount
        except sqlite3.Error as exc:
            raise StorageError(f"Triage cache purge failed: {exc}") from exc

    def close(self) -> None:
        """Close the underlying database connection."""
        try:
            self._conn.close()
        except sqlite3.Error as exc:
            raise StorageError(f"Triage cache close failed: {exc}") from exc

    def _delete(self, key: tuple[str, str, str, str]) -> None:
        self._conn.execute(
            "DELETE FROM triage_cache "
            "WHERE fingerprint = ? AND model = ? AND language = ? AND prompt_sha = ?",
            key,
        )
        self._conn.commit()
