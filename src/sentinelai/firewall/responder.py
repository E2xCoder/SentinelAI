"""Automatic response policy.

Decides *whether* an alert warrants blocking its source, then delegates
the *how* to the firewall boundary. Safety rails:

* risk threshold (``response.min_risk_level``)
* allowlisted networks are never blocked
* invalid or missing IPs are never blocked
* self-lockout protection (:class:`~sentinelai.firewall.lockout.LockoutGuard`)
* a per-run budget caps how many blocks one scan can trigger
* an hourly circuit breaker caps blocks across runs (needs the store)
* per-IP cooldown prevents block/unblock thrash

``response.mode`` selects the outcome: ``auto`` blocks immediately,
``approval`` queues a pending request for a human to approve.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinelai.config.models import ResponseConfig
from sentinelai.core.exceptions import FirewallError
from sentinelai.core.models import Alert, RiskLevel
from sentinelai.core.store import AlertStore
from sentinelai.firewall.audit import ResponseAudit
from sentinelai.firewall.interface import FirewallAction, FirewallController
from sentinelai.firewall.lockout import LockoutGuard
from sentinelai.utils.logging import get_logger
from sentinelai.utils.net import blockable_reason, canonical_ip, ip_in_networks

_LOGGER = get_logger("firewall.responder")

_HOUR = timedelta(hours=1)
_AUDIT_SKIP_INTERVAL = timedelta(seconds=60)
_MAX_CONSECUTIVE_FAILURES = 5
_MIN_QUEUE_CAP = 100
_MAX_DETAIL_LEN = 200
_AUDIT_SKIP_MAP_LIMIT = 5000
_UNTRACKED_REASON = "could not record the block; refusing to apply an untracked block"
_BREAKER_UNREADABLE = "could not read the block history; refusing to block"
_SIGMA_RULE_ID_RE = re.compile(r"SIGMA-[0-9a-f]{8}")
_SIGMA_SKIP_REASON = (
    "alerts from imported Sigma rules do not trigger automatic blocking "
    "(response.include_sigma_rules is false)"
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def failure_detail(exc: Exception) -> str:
    """Short, safe description of a firewall failure for records and audit.

    Our own :class:`FirewallError` messages are kept (truncated); any other
    exception is reduced to its class name so raw adapter output never leaks.
    """
    if isinstance(exc, FirewallError):
        return str(exc)[:_MAX_DETAIL_LEN] or type(exc).__name__
    return type(exc).__name__


def hourly_breaker_reason(
    config: ResponseConfig, store: AlertStore | None, now: datetime
) -> str | None:
    """Return the circuit-breaker skip reason when the hourly cap is reached.

    Fails closed: if the block history cannot be read, blocking is refused.
    """
    if store is None:
        return None
    try:
        count = store.count_response_actions_since(now - _HOUR)
    except Exception as exc:  # noqa: BLE001 - fail closed on a broken store
        _LOGGER.warning("Could not read hourly block count: %s", exc)
        return _BREAKER_UNREADABLE
    if count >= config.max_blocks_per_hour:
        return f"hourly circuit breaker open ({count} blocks in the last hour)"
    return None


def execute_block(
    firewall: FirewallController,
    ip: str,
    duration: int | None,
    detail_ok: str,
) -> FirewallAction:
    """Apply one block through the firewall boundary; never raises on failure."""
    action_name = "block_ip" if duration is None else "temporary_block"
    try:
        if duration is not None:
            success = bool(firewall.temporary_block(ip, duration))
        else:
            success = bool(firewall.block_ip(ip))
        detail = detail_ok if success else "firewall reported failure"
    except Exception as exc:  # noqa: BLE001 - any adapter fault is a failed action
        success = False
        detail = failure_detail(exc)
        _LOGGER.error("Firewall action failed for %s: %s", ip, type(exc).__name__)
    return FirewallAction(
        action=action_name,
        ip=ip,
        success=success,
        detail=detail,
        duration_seconds=duration,
    )


class AutoResponder:
    """Applies the configured response policy to scored alerts."""

    def __init__(
        self,
        config: ResponseConfig,
        firewall: FirewallController,
        *,
        store: AlertStore | None = None,
        audit: ResponseAudit | None = None,
        guard: LockoutGuard | None = None,
        run_id: str = "",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._firewall = firewall
        self._store = store
        self._audit = audit
        self._guard = guard
        self._run_id = run_id
        self._clock: Callable[[], datetime] = clock or _utc_now
        self._min_level = RiskLevel(config.min_risk_level)
        self._last_action: dict[str, float] = {}
        self._blocks_this_run = 0
        self._budget_start: datetime | None = None
        self._consecutive_failures = 0
        self._audit_skip_seen: dict[tuple[str, str], datetime] = {}
        self.actions: list[FirewallAction] = []

    def consider(self, alert: Alert) -> FirewallAction | None:
        """Evaluate one alert; block its source (or queue it) per policy.

        Returns the action taken (successful or failed), or ``None``
        when policy decided not to act or queued the request for approval.
        Never raises: any internal fault is logged and audited as a failure.
        """
        if not self._config.enabled:
            return None
        try:
            ip = canonical_ip(alert.ip) if alert.ip else None
            decision = self._decide(alert, ip)
            if decision is not None or ip is None:
                _LOGGER.debug("No response for alert %s: %s", alert.rule_id, decision)
                return None
            if self._config.mode == "approval":
                self._queue(alert, ip)
                return None
            return self._apply(alert, ip)
        except Exception as exc:  # noqa: BLE001 - the responder must never crash detection
            _LOGGER.error("Response handling failed for alert %s: %s", alert.rule_id, exc)
            detail = f"internal error ({type(exc).__name__})"
            self._audit_event("failed", alert, self._audit_ip(alert.ip), detail)
            return None

    # -- internals -------------------------------------------------------

    def _duration(self) -> int | None:
        return self._config.block_duration_seconds if self._config.temporary_block else None

    def _roll_budget(self, now: datetime) -> None:
        """Reset the block budget (and failure streak) every hour of clock time."""
        start = self._budget_start
        if start is None:
            self._budget_start = now
        elif now - start >= _HOUR:
            self._budget_start = now
            self._blocks_this_run = 0
            self._consecutive_failures = 0

    def _track(
        self,
        alert: Alert,
        ip: str,
        action_name: str,
        duration: int | None,
        expires_at: datetime | None,
        detail: str,
    ) -> int | None:
        """Insert the ``applied`` row before blocking; None when it cannot be stored."""
        store = self._store
        if store is None:
            return None
        try:
            return store.add_response_action(
                action=action_name,
                ip=ip,
                duration_seconds=duration,
                expires_at=expires_at,
                status="applied",
                alert_id=alert.id,
                rule_id=alert.rule_id,
                run_id=self._run_id,
                detail=detail,
                ts=self._clock(),
            )
        except Exception as exc:  # noqa: BLE001 - fail closed, never crash detection
            _LOGGER.error("Could not record response action for %s: %s", ip, exc)
            return None

    def _mark_failed(self, row_id: int | None, detail: str) -> None:
        if row_id is None or self._store is None:
            return
        try:
            self._store.set_response_action_status(row_id, "failed", detail)
        except Exception as exc:  # noqa: BLE001 - never crash detection
            _LOGGER.error("Could not mark response action #%s failed: %s", row_id, exc)

    def _apply(self, alert: Alert, ip: str) -> FirewallAction:
        level = alert.risk.level.value
        duration = self._duration()
        action_name = "block_ip" if duration is None else "temporary_block"
        detail_ok = f"triggered by {alert.rule_id} ({level})"
        now = self._clock()
        expires_at = now + timedelta(seconds=duration) if duration is not None else None
        row_id: int | None = None
        if self._store is not None:
            row_id = self._track(alert, ip, action_name, duration, expires_at, detail_ok)
            if row_id is None:
                action = FirewallAction(
                    action=action_name,
                    ip=ip,
                    success=False,
                    detail=_UNTRACKED_REASON,
                    duration_seconds=duration,
                )
                return self._failed(alert, ip, action)
        action = execute_block(self._firewall, ip, duration, detail_ok)
        if not action.success:
            self._mark_failed(row_id, action.detail)
            return self._failed(alert, ip, action)
        self.actions.append(action)
        alert.context["response"] = action.to_dict()
        self._blocks_this_run += 1
        self._consecutive_failures = 0
        self._last_action[ip] = time.monotonic()
        _LOGGER.warning("Blocked %s (%s) after alert %s", ip, action.action, alert.rule_id)
        self._audit_event("blocked", alert, ip, action.detail)
        return action

    def _failed(self, alert: Alert, ip: str, action: FirewallAction) -> FirewallAction:
        """Book-keeping for a failed attempt: cooldown, failure streak, audit."""
        self.actions.append(action)
        alert.context["response"] = action.to_dict()
        self._consecutive_failures += 1
        self._last_action[ip] = time.monotonic()
        self._audit_event("failed", alert, ip, action.detail)
        return action

    def _queue(self, alert: Alert, ip: str) -> None:
        store = self._store
        if store is None:
            self._skip(alert, ip, "approval mode needs the alert store")
            return
        try:
            existing = store.has_open_pending(ip)
            if existing is not None:
                self._skip(alert, ip, f"already pending approval (#{existing})")
                return
            cap = max(_MIN_QUEUE_CAP, self._config.max_blocks_per_hour * 10)
            if store.pending_count() >= cap:
                self._skip(alert, ip, "approval queue is full")
                return
            duration = self._duration()
            pending_id = store.add_pending(
                ip=ip,
                alert_id=alert.id,
                rule_id=alert.rule_id,
                risk_level=alert.risk.level.value,
                risk_score=alert.risk.score,
                action="temporary_block" if duration is not None else "block_ip",
                duration_seconds=duration,
                ts=self._clock(),
            )
        except Exception as exc:  # noqa: BLE001 - never crash detection
            _LOGGER.error("Could not queue pending response for %s: %s", ip, exc)
            self._audit_event("failed", alert, ip, "could not queue approval request")
            return
        alert.context["response"] = {"status": "pending", "pending_id": pending_id}
        self._audit_event(
            "queued",
            alert,
            ip,
            f"awaiting approval (#{pending_id})",
            pending_id=pending_id,
        )
        _LOGGER.info("Queued block of %s for approval (#%s)", ip, pending_id)

    @staticmethod
    def _audit_ip(raw: str | None) -> str | None:
        """Canonical form when valid, else a truncated raw value for the audit trail."""
        if not raw:
            return None
        return canonical_ip(raw) or str(raw)[:64]

    def _decide(self, alert: Alert, ip: str | None) -> str | None:
        """Return a skip reason, or None when the alert should be acted on.

        *ip* is the canonical form of ``alert.ip`` (None when invalid).
        """
        if alert.risk.level.weight < self._min_level.weight:
            # Not a blocking candidate: no audit record (it would only be noise).
            return self._skip(
                alert,
                alert.ip,
                f"risk {alert.risk.level.value} below threshold",
                audit=False,
            )
        if ip is None:
            return self._skip(alert, self._audit_ip(alert.ip), "no valid source IP")
        if (
            self._config.mode == "auto"
            and not self._config.include_sigma_rules
            and _SIGMA_RULE_ID_RE.fullmatch(alert.rule_id or "") is not None
        ):
            return self._skip(alert, ip, _SIGMA_SKIP_REASON)
        unblockable = blockable_reason(ip)
        if unblockable is not None:
            return self._skip(alert, ip, unblockable)
        if ip_in_networks(ip, self._config.allowlist):
            return self._skip(alert, ip, f"{ip} is allowlisted")
        if self._guard is not None:
            protected = self._guard.protected_reason(ip)
            if protected:
                return self._skip(alert, ip, f"self-lockout protection: {protected}")
        now = self._clock()
        self._roll_budget(now)
        if self._blocks_this_run >= self._config.max_blocks_per_run:
            return self._skip(alert, ip, "per-run block budget exhausted")
        if self._consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            limit = _MAX_CONSECUTIVE_FAILURES
            return self._skip(
                alert, ip, f"firewall failing repeatedly ({limit} consecutive failures)"
            )
        breaker = hourly_breaker_reason(self._config, self._store, now)
        if breaker is not None:
            return self._skip(alert, ip, breaker, decision="circuit_breaker")
        last = self._last_action.get(ip)
        if last is not None and time.monotonic() - last < self._config.cooldown_seconds:
            return self._skip(alert, ip, f"{ip} in cooldown")
        try:
            if self._firewall.is_blocked(ip):
                return self._skip(alert, ip, f"{ip} already blocked")
        except Exception as exc:  # noqa: BLE001 - a broken query must not crash detection
            _LOGGER.warning("Could not query block state for %s: %s", ip, type(exc).__name__)
            self._audit_event(
                "failed", alert, ip, f"could not query block state ({failure_detail(exc)})"
            )
        return None

    def _skip(
        self,
        alert: Alert,
        ip: str | None,
        reason: str,
        decision: str = "skipped",
        *,
        audit: bool = True,
    ) -> str:
        if audit and self._should_audit_skip(ip, reason):
            self._audit_event(decision, alert, ip, reason)
        return reason

    def _should_audit_skip(self, ip: str | None, reason: str) -> bool:
        """Allow one identical (ip, reason) skip record per minute."""
        if self._audit is None:
            return False
        now = self._clock()
        seen = self._audit_skip_seen
        key = (ip or "", reason)
        last = seen.get(key)
        if last is not None and now - last < _AUDIT_SKIP_INTERVAL:
            return False
        if len(seen) >= _AUDIT_SKIP_MAP_LIMIT:
            for stale in [k for k, t in seen.items() if now - t >= _AUDIT_SKIP_INTERVAL]:
                del seen[stale]
            if len(seen) >= _AUDIT_SKIP_MAP_LIMIT:
                seen.clear()
        seen[key] = now
        return True

    def _audit_event(
        self, decision: str, alert: Alert, ip: str | None, reason: str, **extra: Any
    ) -> None:
        if self._audit is None:
            return
        try:
            self._audit.record(
                decision,
                ip=ip,
                reason=reason,
                alert_id=alert.id,
                rule_id=alert.rule_id,
                risk_level=alert.risk.level.value,
                mode=self._config.mode,
                run_id=self._run_id,
                **extra,
            )
        except Exception as exc:  # noqa: BLE001 - auditing must never crash detection
            _LOGGER.warning("Could not write response audit entry: %s", exc)
