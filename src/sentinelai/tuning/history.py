"""Durable history, backups and audit trail for the tuning overlay.

Every apply/rollback is recorded in the SQLite ``config_history`` table, in
a backup file of the previous overlay text and in an append-only JSONL
audit log.
"""

from __future__ import annotations

import contextlib
import getpass
import hashlib
import json
import os
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelai.core.exceptions import ConfigError, StorageError
from sentinelai.core.store import AlertStore, ConfigHistoryEntry
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("tuning.history")

_OVERLAY_FILENAME = "tuning.yaml"
_LOCK_STALE_SECONDS = 600


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_text(path: Path, text: str, delete_if_empty: bool = True) -> None:
    """Atomically write *text* byte-for-byte (no newline translation).

    An empty *text* deletes the file instead unless *delete_if_empty* is false.
    """
    if text == "" and delete_if_empty:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise ConfigError(f"Cannot remove {path}: {exc}") from exc
        return
    tmp_name = ""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except OSError as exc:
        if tmp_name:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
        raise ConfigError(f"Cannot write {path}: {exc}") from exc


class TuningHistory:
    """Applies and rolls back overlay text with history, backups and audit."""

    def __init__(
        self,
        state_dir: Path,
        store: AlertStore,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._store = store
        self._now: Callable[[], datetime] = now or (lambda: datetime.now(timezone.utc))

    # -- paths ------------------------------------------------------------

    @property
    def overlay_file(self) -> Path:
        return self._state_dir / _OVERLAY_FILENAME

    @property
    def audit_file(self) -> Path:
        return self._state_dir / "tuning" / "audit.jsonl"

    @property
    def _lock_file(self) -> Path:
        return self._state_dir / "tuning" / ".lock"

    @property
    def _backup_dir(self) -> Path:
        return self._state_dir / "tuning" / "history"

    # -- reading ----------------------------------------------------------

    def current_text(self) -> str:
        """Overlay text exactly as stored on disk, ``""`` when absent."""
        try:
            with self.overlay_file.open(
                "r", encoding="utf-8", errors="replace", newline=""
            ) as handle:
                return handle.read()
        except FileNotFoundError:
            return ""
        except OSError as exc:
            raise ConfigError(f"Cannot read tuning overlay {self.overlay_file}: {exc}") from exc

    def history(self) -> list[ConfigHistoryEntry]:
        return self._store.list_config_history()

    # -- mutations --------------------------------------------------------

    def apply(self, new_text: str, proposal_ids: Sequence[str], note: str = "") -> int:
        """Write *new_text* as the overlay; return the history id."""
        with self._locked():
            return self._apply_locked(new_text, proposal_ids, note)

    def rollback(self) -> ConfigHistoryEntry:
        """Undo the latest non-rolled-back apply; return that original entry."""
        with self._locked():
            return self._rollback_locked()

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        """Hold the cross-process ``<state_dir>/tuning/.lock`` file."""
        path = self._lock_file
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ConfigError(f"Cannot create {path.parent}: {exc}") from exc
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            fd = os.open(path, flags)
        except FileExistsError:
            try:
                age = time.time() - path.stat().st_mtime
            except OSError:
                age = _LOCK_STALE_SECONDS  # vanished meanwhile: take over
            if age < _LOCK_STALE_SECONDS:
                raise ConfigError(f"another sentinel tune is running (lock {path})") from None
            try:
                path.unlink(missing_ok=True)
                fd = os.open(path, flags)
            except FileExistsError:
                raise ConfigError(f"another sentinel tune is running (lock {path})") from None
            except OSError as exc:
                raise ConfigError(f"Cannot take over stale lock {path}: {exc}") from exc
        except OSError as exc:
            raise ConfigError(f"Cannot create lock {path}: {exc}") from exc
        try:
            with contextlib.suppress(OSError):
                os.write(fd, str(os.getpid()).encode("ascii"))
        finally:
            os.close(fd)
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                path.unlink(missing_ok=True)

    def _apply_locked(self, new_text: str, proposal_ids: Sequence[str], note: str) -> int:
        previous = self.current_text()
        guess = len(self.history()) + 1
        backup = self._backup_dir / f"{guess:04d}-before-apply.yaml"
        _write_text(backup, previous, delete_if_empty=False)

        _write_text(self.overlay_file, new_text)
        try:
            history_id = self._store.add_config_history(
                "apply", proposal_ids, previous, new_text, note, ts=self._now()
            )
        except StorageError:
            _write_text(self.overlay_file, previous)
            raise
        if history_id != guess:
            self._rename_backup(backup, history_id)

        self.audit(
            "apply",
            proposal_ids=[str(p) for p in proposal_ids],
            history_id=history_id,
            before_sha256=_sha256(previous),
            after_sha256=_sha256(new_text),
            note=note,
        )
        return history_id

    def _rollback_locked(self) -> ConfigHistoryEntry:
        pending =[e for e in self.history() if e.action == "apply" and not e.rolled_back]
        if not pending:
            raise ConfigError("nothing to roll back")
        original = max(pending, key=lambda e: e.id)

        before = self.current_text()
        restored = original.previous_text
        _write_text(self.overlay_file, restored)
        try:
            rollback_id = self._store.add_config_history(
                "rollback",
                original.proposal_ids,
                before,
                restored,
                note=f"rolls back #{original.id}",
                ts=self._now(),
            )
            self._store.mark_rolled_back(original.id)
        except StorageError:
            _write_text(self.overlay_file, before)
            raise

        self.audit(
            "rollback",
            proposal_ids=list(original.proposal_ids),
            history_id=rollback_id,
            rolled_back_id=original.id,
            before_sha256=_sha256(before),
            after_sha256=_sha256(restored),
        )
        return original

    # -- audit ------------------------------------------------------------

    def audit(self, event: str, **fields: Any) -> None:
        """Append one JSON line to the audit log; never raises."""
        try:
            try:
                user = getpass.getuser()
            except Exception:  # noqa: BLE001 - getuser fails in many ways
                user = "unknown"
            stamp = self._now()
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            record = {
                **fields,
                "ts": stamp.astimezone(timezone.utc).isoformat(),
                "event": event,
                "user": user,
            }
            line = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
            self.audit_file.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_file.open("a", encoding="utf-8", newline="") as handle:
                handle.write(line + "\n")
                handle.flush()
                with contextlib.suppress(OSError):
                    os.fsync(handle.fileno())
        except (OSError, TypeError, ValueError) as exc:
            _LOGGER.warning("Could not write tuning audit record (%s): %s", event, exc)

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _rename_backup(backup: Path, history_id: int) -> None:
        target = backup.with_name(f"{history_id:04d}-before-apply.yaml")
        try:
            os.replace(backup, target)
        except OSError as exc:
            _LOGGER.warning("Could not rename backup %s: %s", backup, exc)
