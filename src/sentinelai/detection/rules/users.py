"""User management detections: account creation, deletion, locking."""

from __future__ import annotations

import logging

from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent, Severity
from sentinelai.detection.accounts import AccountKind, classify_account, read_uid_min
from sentinelai.detection.base import Rule, RuleContext, register_rule

_logger = logging.getLogger("sentinelai.detection.rules.users")


@register_rule
class NewUserRule(Rule):
    """A new local account was created."""

    rule_id = "R020"
    name = "New User Created"
    description = (
        "A new local account was created. Attackers create accounts for "
        "persistence; a UID-0 account is an immediate red flag. "
        "Well-known service accounts (e.g. sshd, www-data, systemd-*) "
        "are suppressed to reduce false positives."
    )
    category = EventCategory.USER_MANAGEMENT
    severity = Severity.NOTICE
    mitre_tactics = ("Persistence",)
    mitre_techniques = ("T1136.001",)
    recommendation = (
        "Confirm the account was created through an approved process; "
        "delete unexpected accounts and audit how they were created."
    )

    _uid_min: int | None = None

    def _get_uid_min(self, ctx: RuleContext) -> int:
        if self._uid_min is not None:
            return self._uid_min
        configured = ctx.config.uid_min
        self._uid_min = configured if configured > 0 else read_uid_min()
        return self._uid_min

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type is not EventType.USER_ADDED:
            return None

        uid = str(event.extra.get("uid", ""))
        username = event.user
        uid_min = self._get_uid_min(ctx)
        allowlist = ctx.config.service_account_allowlist

        kind = classify_account(
            username, uid or None, uid_min=uid_min, service_allowlist=allowlist,
        )

        if kind in (AccountKind.SERVICE, AccountKind.SYSTEM):
            _logger.info(
                "Suppressed R020 for %s account %r (uid=%s, kind=%s)",
                kind.value, username, uid or "?", kind.value,
            )
            return None

        if kind is AccountKind.PRIVILEGED:
            return self.make_alert(
                event,
                title=f"UID-0 account '{username}' created",
                description=(
                    f"Account '{username}' was created with UID 0 — a "
                    f"root-equivalent backdoor account."
                ),
                severity=Severity.CRITICAL,
                uid=uid,
            )

        return self.make_alert(
            event,
            title=f"New user account '{username}' created",
            description=(
                f"Account '{username}' was created"
                + (f" with UID {uid}" if uid else "")
                + (f", shell {event.extra['shell']}" if event.extra.get("shell") else "")
                + "."
            ),
            uid=uid or None,
            shell=event.extra.get("shell"),
        )


@register_rule
class UserDeletedRule(Rule):
    """A local account was deleted."""

    rule_id = "R021"
    name = "User Account Deleted"
    description = (
        "A local account was deleted. Attackers remove accounts to "
        "destroy evidence or lock out administrators."
    )
    category = EventCategory.USER_MANAGEMENT
    severity = Severity.WARNING
    mitre_tactics = ("Impact",)
    mitre_techniques = ("T1531",)
    recommendation = (
        "Verify the deletion was authorized; preserve the account's home "
        "directory and audit logs before they age out."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type is not EventType.USER_DELETED:
            return None
        return self.make_alert(
            event,
            title=f"User account '{event.user}' deleted",
            description=f"Account '{event.user}' was deleted from the system.",
        )


@register_rule
class AccountLockedRule(Rule):
    """An account was locked (manually or by failed-login policy)."""

    rule_id = "R022"
    name = "Account Locked"
    description = (
        "An account was locked, either manually or automatically after "
        "consecutive authentication failures — often collateral of a "
        "brute-force attack in progress."
    )
    category = EventCategory.USER_MANAGEMENT
    severity = Severity.WARNING
    mitre_tactics = ("Credential Access", "Impact")
    mitre_techniques = ("T1110", "T1531")
    recommendation = (
        "Check for an accompanying brute-force alert against this "
        "account before unlocking it."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type is not EventType.ACCOUNT_LOCKED:
            return None
        return self.make_alert(
            event,
            title=f"Account '{event.user}' locked",
            description=f"Account '{event.user}' was locked. Message: {event.message}",
        )
