"""Append-only JSONL audit trail for automatic responses.

Each line is one JSON object with ``event == "response"`` and a
``decision`` which is one of: ``blocked``, ``skipped``, ``queued``,
``approved``, ``denied``, ``failed``, ``reaped``, ``rolled_back``,
``expired``, ``circuit_breaker``.

Strings are sanitised (control characters removed, length capped) so
log-derived text can never forge extra lines.  Writing never raises.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections import deque
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("firewall.audit")

_MAX_STRING = 500


def _clean(value: Any) -> Any:
    """Strip control characters from strings and cap their length."""
    if isinstance(value, str):
        text = "".join(" " if ch in "\r\n\t" else ch for ch in value)
        text = "".join(ch for ch in text if ch.isprintable())
        return text[:_MAX_STRING]
    if isinstance(value, (list, tuple)):
        return [_clean(item) for item in value]
    if isinstance(value, dict):
        return {_clean(str(key)): _clean(item) for key, item in value.items()}
    return value


class ResponseAudit:
    """Append-only response audit log stored as JSON lines."""

    def __init__(
        self,
        path: Path | str,
        now: Callable[[], datetime] | None = None,
        *,
        max_bytes: int = 10_000_000,
        keep: int = 5,
    ) -> None:
        self._path = Path(path)
        self._now: Callable[[], datetime] = now or (lambda: datetime.now(timezone.utc))
        self._max_bytes = max_bytes
        self._keep = max(1, keep)

    @property
    def path(self) -> Path:
        return self._path

    def _rotated(self, index: int) -> Path:
        return self._path.with_name(f"{self._path.name}.{index}")

    def _rotate_if_needed(self) -> None:
        """Rotate the active file when it reached ``max_bytes``; never raises."""
        try:
            if self._max_bytes <= 0 or not self._path.exists():
                return
            if self._path.stat().st_size < self._max_bytes:
                return
            oldest = self._rotated(self._keep)
            if oldest.exists():
                oldest.unlink()
            for index in range(self._keep - 1, 0, -1):
                source = self._rotated(index)
                if source.exists():
                    os.replace(source, self._rotated(index + 1))
            os.replace(self._path, self._rotated(1))
        except OSError as exc:
            _LOGGER.warning("Could not rotate response audit log: %s", exc)

    def record(
        self,
        decision: str,
        *,
        ip: str | None = None,
        reason: str = "",
        alert_id: int | None = None,
        rule_id: str | None = None,
        risk_level: str | None = None,
        mode: str | None = None,
        run_id: str | None = None,
        **extra: Any,
    ) -> None:
        """Append one JSON line to the audit log; never raises."""
        try:
            stamp = self._now()
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            fields: dict[str, Any] = {
                "decision": decision,
                "ip": ip,
                "reason": reason,
                "alert_id": alert_id,
                "rule_id": rule_id,
                "risk_level": risk_level,
                "mode": mode,
                "run_id": run_id,
                **extra,
            }
            record: dict[str, Any] = {
                key: _clean(value) for key, value in fields.items() if value is not None
            }
            record["ts"] = stamp.astimezone(timezone.utc).isoformat()
            record["event"] = "response"
            line = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate_if_needed()
            with self._path.open("a",encoding="utf-8", newline="") as handle:
                handle.write(line + "\n")
                handle.flush()
                with contextlib.suppress(OSError):
                    os.fsync(handle.fileno())
        except (OSError, TypeError, ValueError, OverflowError) as exc:
            _LOGGER.warning("Could not write response audit record (%s): %s", decision, exc)

    def read(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the last *limit* records (oldest first); malformed lines are skipped.

        Reads the active file and, when it holds fewer than *limit* records,
        continues into the rotated files ``.1``, ``.2``, ...
        """
        if limit <= 0:
            return []
        result: list[dict[str, Any]] = []
        index = 0
        while len(result) < limit:
            path = self._path if index == 0 else self._rotated(index)
            if index > 0 and not path.exists():
                break
            result = self._read_file(path, limit - len(result)) + result
            index += 1
        return result

    @staticmethod
    def _read_file(path: Path, limit: int) -> list[dict[str, Any]]:
        """Return the last *limit* valid records of one file."""
        records: deque[dict[str, Any]] = deque(maxlen=limit)
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(obj, dict):
                        records.append(obj)
        except OSError:
            return []
        return list(records)
