"""Human-in-the-loop control of firewall responses.

:class:`ResponseOperator` approves or denies queued block requests,
reaps expired temporary blocks, rolls back applied blocks and exposes the
audit history. Every approval is re-validated against the current safety
rails, because the world may have changed since the request was queued.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinelai.config.models import ResponseConfig
from sentinelai.core.exceptions import FirewallError
from sentinelai.core.store import AlertStore, PendingResponse, ResponseActionRow
from sentinelai.firewall.audit import ResponseAudit
from sentinelai.firewall.interface import FirewallAction, FirewallController
from sentinelai.firewall.lockout import LockoutGuard
from sentinelai.firewall.responder import execute_block, failure_detail, hourly_breaker_reason
from sentinelai.utils.logging import get_logger
from sentinelai.utils.net import blockable_reason, canonical_ip, ip_in_networks

_LOGGER = get_logger("firewall.operator")

_RUN_ID = "operator"
_UNTRACKED_REASON = "could not record the block; refusing to apply an untracked block"
_COVERED_DETAIL = "IP stays blocked by a longer-lived block"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ResponseOperator:
    """Operator-facing actions on queued and applied firewall responses."""

    def __init__(
        self,
        config: ResponseConfig,
        firewall: FirewallController,
        store: AlertStore,
        audit: ResponseAudit | None,
        guard: LockoutGuard | None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._firewall = firewall
        self._store = store
        self._audit = audit
        self._guard = guard
        self._clock: Callable[[], datetime] = clock or _utc_now

    # -- pending queue ---------------------------------------------------

    def pending(self) -> list[PendingResponse]:
        """Return open pending requests after expiring stale ones."""
        self._expire_stale()
        return self._store.list_pending("pending")

    def approve(self, pending_id: int, note: str = "") -> FirewallAction:
        """Approve a pending request and apply the block.

        Raises :class:`FirewallError` for an unknown or already-decided
        request, when the block is no longer permitted, or when the
        firewall refuses it.
        """
        self._expire_stale()
        row = self._store.get_pending(pending_id)
        if row is None:
            raise FirewallError(f"pending response #{pending_id} not found")
        if row.status != "pending":
            raise FirewallError(f"pending response #{pending_id} already {row.status}")
        ip = canonical_ip(row.ip)
        permanent = "no valid source IP" if ip is None else self._permanent_reason(ip)
        if permanent is not None:
            try:
                self._store.decide_pending(
                    pending_id, "denied", note=permanent, decided_at=self._clock()
                )
            except Exception as exc:  # noqa: BLE001 - lost a race with another decision
                raise FirewallError(f"request #{pending_id} is no longer pending") from exc
            self._audit_event("denied", row, permanent)
            raise FirewallError(permanent)
        if ip is None:  # unreachable: permanent reason is set for an invalid IP
            raise FirewallError("no valid source IP")

        if not self._store.claim_pending(pending_id, note):
            raise FirewallError(f"request #{pending_id} is no longer pending")
        try:
            return self._apply_claimed(row, ip, note)
        except FirewallError:
            raise  # known failure paths have already released the claim
        except Exception as exc:
            self._release(pending_id)
            _LOGGER.error("Approval of #%s failed: %s", pending_id, type(exc).__name__)
            self._audit_event("failed", row, f"internal error ({type(exc).__name__})")
            raise FirewallError(f"approval of #{pending_id} failed; try again later") from exc

    def _apply_claimed(self, row: PendingResponse, ip: str, note: str) -> FirewallAction:
        """Apply a block for a request this call has claimed."""
        pending_id = row.id
        transient = self._transient_reason(ip)
        if transient is not None:
            self._release(pending_id)
            self._audit_event("skipped", row, transient)
            raise FirewallError(f"{transient}; try again later")

        duration = row.duration_seconds if row.action == "temporary_block" else None
        action_name = "block_ip" if duration is None else "temporary_block"
        detail_ok = f"approved #{pending_id} ({row.rule_id})"
        now = self._clock()
        expires_at = now + timedelta(seconds=duration) if duration is not None else None
        action_id = self._track(row, ip, action_name, duration, expires_at, detail_ok, now)
        if action_id is None:
            self._release(pending_id)
            self._audit_event("failed", row, _UNTRACKED_REASON)
            raise FirewallError(_UNTRACKED_REASON)

        self._audit_event("approved", row, note or "approved by operator")
        action = execute_block(self._firewall, ip, duration, detail_ok)
        if not action.success:
            self._mark_failed(action_id, action.detail)
            self._release(pending_id)
            self._audit_event("failed", row, action.detail)
            raise FirewallError(
                f"firewall could not block {ip}: {action.detail}"
                if action.detail
                else f"firewall could not block {ip}"
            )
        self._audit_event("blocked", row, action.detail)
        _LOGGER.warning("Operator approved block of %s (#%s)", ip, pending_id)
        return action

    def _track(
        self,
        row: PendingResponse,
        ip: str,
        action_name: str,
        duration: int | None,
        expires_at: datetime | None,
        detail: str,
        now: datetime,
    ) -> int | None:
        """Insert the ``applied`` row before blocking; None when it cannot be stored."""
        try:
            return self._store.add_response_action(
                action=action_name,
                ip=ip,
                duration_seconds=duration,
                expires_at=expires_at,
                status="applied",
                alert_id=row.alert_id,
                rule_id=row.rule_id,
                run_id=_RUN_ID,
                detail=detail,
                ts=now,
            )
        except Exception as exc:  # noqa: BLE001 - fail closed
            _LOGGER.error("Could not record response action for %s: %s", ip, exc)
            return None

    def _mark_failed(self, action_id: int, detail: str) -> None:
        try:
            self._store.set_response_action_status(action_id, "failed", detail)
        except Exception as exc:  # noqa: BLE001 - keep the operator flow going
            _LOGGER.error("Could not mark response action #%s failed: %s", action_id, exc)

    def _release(self, pending_id: int) -> None:
        try:
            self._store.release_pending(pending_id)
        except Exception as exc:  # noqa: BLE001 - report the original problem instead
            _LOGGER.error("Could not release pending response #%s: %s", pending_id, exc)

    def deny(self, pending_id: int, note: str = "") -> None:
        """Deny a pending request without touching the firewall."""
        row = self._store.get_pending(pending_id)
        if row is None:
            raise FirewallError(f"pending response #{pending_id} not found")
        if row.status != "pending":
            raise FirewallError(f"pending response #{pending_id} already {row.status}")
        self._store.decide_pending(pending_id, "denied", note=note, decided_at=self._clock())
        self._audit_event("denied", row, note or "denied by operator")

    # -- expiry and rollback --------------------------------------------

    def reap(self) -> list[FirewallAction]:
        """Unblock temporary blocks whose time is up; also expire stale requests."""
        self._expire_stale()
        actions: list[FirewallAction] = []
        failure_audited = False
        for row in self._store.due_response_actions(self._clock()):
            action = self._retire(row, "reaped", "block expired")
            actions.append(action)
            if not action.success and not failure_audited:
                failure_audited = True
                self._audit_row("failed", row.ip, action.detail, row.alert_id, row.rule_id)
        return actions

    def rollback(
        self, *, since: datetime | None = None, run_id: str | None = None
    ) -> list[FirewallAction]:
        """Unblock applied blocks from a time window and/or a run."""
        if since is None and run_id is None:
            raise ValueError("rollback needs 'since' or 'run_id'")
        if run_id == "":
            raise ValueError("rollback 'run_id' must not be empty")
        actions: list[FirewallAction] = []
        rows = self._store.list_response_actions(status="applied", since=since, run_id=run_id)
        for row in rows:
            action = self._retire(row, "rolled_back", "rolled back by operator")
            actions.append(action)
            if not action.success:
                self._audit_row("failed", row.ip, action.detail, row.alert_id, row.rule_id)
        return actions

    def history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent audit entries (empty without an audit log)."""
        if self._audit is None:
            return []
        return self._audit.read(limit)

    # -- internals -------------------------------------------------------

    def _permanent_reason(self, ip: str) -> str | None:
        """Reasons that will not change: the request is denied outright."""
        unblockable = blockable_reason(ip)
        if unblockable is not None:
            return unblockable
        if ip_in_networks(ip, self._config.allowlist):
            return f"{ip} is allowlisted"
        if self._guard is not None:
            protected = self._guard.protected_reason(ip)
            if protected:
                return f"self-lockout protection: {protected}"
        return None

    def _transient_reason(self, ip: str) -> str | None:
        """Reasons that may clear later: the request stays pending."""
        breaker = hourly_breaker_reason(self._config, self._store, self._clock())
        if breaker is not None:
            return breaker
        try:
            if self._firewall.is_blocked(ip):
                return f"{ip} already blocked"
        except Exception as exc:  # noqa: BLE001 - a broken query must not abort approval
            _LOGGER.warning("Could not query block state for %s: %s", ip, type(exc).__name__)
        return None

    def _retire(
        self, row: ResponseActionRow, final_status: str, detail_ok: str
    ) -> FirewallAction:
        """Unblock one tracked row; one bad row never aborts the batch."""
        try:
            ip = canonical_ip(row.ip)
            if ip is None:
                return FirewallAction(
                    action="unblock", ip=row.ip, success=False, detail="stored IP is invalid"
                )
            covering = self._store.covering_response_actions(
                ip, exclude_id=row.id, expires_after=row.expires_at
            )
            if covering:
                self._store.set_response_action_status(row.id, final_status, _COVERED_DETAIL)
                self._audit_row(final_status, ip, _COVERED_DETAIL, row.alert_id, row.rule_id)
                return FirewallAction(
                    action="unblock", ip=ip, success=True, detail=_COVERED_DETAIL
                )
            action = self._unblock(ip, detail_ok)
            if action.success:
                self._store.set_response_action_status(row.id, final_status, detail_ok)
                self._audit_row(final_status, ip, detail_ok, row.alert_id, row.rule_id)
            return action
        except Exception as exc:  # noqa: BLE001 - isolate the failure to this row
            _LOGGER.error("Could not retire response action #%s: %s", row.id, type(exc).__name__)
            return FirewallAction(
                action="unblock",
                ip=row.ip,
                success=False,
                detail=f"error handling this block ({type(exc).__name__})",
            )

    def _unblock(self, ip: str, detail_ok: str) -> FirewallAction:
        try:
            success = bool(self._firewall.unblock_ip(ip))
            detail = detail_ok if success else "firewall reported failure"
        except Exception as exc:  # noqa: BLE001 - any adapter fault is a failed action
            success = False
            detail = failure_detail(exc)
            _LOGGER.error("Unblock failed for %s: %s", ip, type(exc).__name__)
        return FirewallAction(action="unblock", ip=ip, success=success, detail=detail)

    def _expire_stale(self) -> None:
        older_than = self._clock() - timedelta(seconds=self._config.pending_expire_seconds)
        expired = self._store.expire_pending(older_than)
        if expired:
            self._audit_row("expired", None, f"{expired} pending request(s) expired", None, None)

    def _audit_event(self, decision: str, row: PendingResponse, reason: str) -> None:
        self._audit_row(
            decision,
            row.ip,
            reason,
            row.alert_id,
            row.rule_id,
            risk_level=row.risk_level,
            pending_id=row.id,
        )

    def _audit_row(
        self,
        decision: str,
        ip: str | None,
        reason: str,
        alert_id: int | None,
        rule_id: str | None,
        **extra: Any,
    ) -> None:
        if self._audit is None:
            return
        try:
            self._audit.record(
                decision,
                ip=ip,
                reason=reason,
                alert_id=alert_id,
                rule_id=rule_id,
                mode=self._config.mode,
                run_id=_RUN_ID,
                **extra,
            )
        except Exception as exc:  # noqa: BLE001 - auditing must not abort operator actions
            _LOGGER.warning("Could not write response audit entry: %s", exc)
