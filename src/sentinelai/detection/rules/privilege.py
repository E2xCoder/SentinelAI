"""Privilege escalation and sudo abuse detections."""

from __future__ import annotations

import re

from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent, Severity
from sentinelai.detection.base import Rule, RuleContext, register_rule

_NOT_IN_SUDOERS = re.compile(r"NOT in sudoers|command not allowed", re.IGNORECASE)

_DANGEROUS_SUDO = re.compile(
    r"""
    (?:^|[\s/])(?:
        chmod\s+(?:u\+s|[0-7]*[4567][0-7]{3})   # setuid bits
        | visudo
        | usermod\s+.*-a?G?\s*(?:sudo|wheel|admin|root)
        | (?:bash|sh|zsh|dash)\s*(?:-i)?\s*$    # sudo into a shell
        | su\s*(?:-|\s|$)
        | passwd\s+root
        | sed\s+.*(?:/etc/sudoers|/etc/shadow|/etc/passwd)
        | tee\s+.*(?:/etc/sudoers|/etc/cron)
        | nano\s+.*/etc/sudoers | vi(?:m)?\s+.*/etc/sudoers
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_PRIV_GROUPS = frozenset({"sudo", "wheel", "admin", "root", "docker"})


@register_rule
class UnauthorizedSudoRule(Rule):
    """A user outside the sudoers policy attempted sudo."""

    rule_id = "R010"
    name = "Unauthorized Sudo Attempt"
    description = (
        "A user who is not authorized in the sudoers policy attempted to "
        "execute a command with elevated privileges."
    )
    category = EventCategory.PRIVILEGE_ESCALATION
    severity = Severity.ERROR
    mitre_tactics = ("Privilege Escalation",)
    mitre_techniques = ("T1548.003",)
    recommendation = (
        "Investigate why the account attempted privileged access; if the "
        "account is compromised, disable it and rotate its credentials."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type is not EventType.SUDO_FAILURE:
            return None
        if not _NOT_IN_SUDOERS.search(event.message):
            return None
        return self.make_alert(
            event,
            title=f"Unauthorized sudo by '{event.user or 'unknown'}'",
            description=(
                f"User '{event.user or 'unknown'}' attempted sudo without "
                f"authorization. Command: {event.extra.get('command', 'unknown')}"
            ),
            command=event.extra.get("command"),
        )


@register_rule
class SudoAbuseRule(Rule):
    """Repeated sudo failures or sudo used to obtain a root shell."""

    rule_id = "R011"
    name = "Sudo Abuse"
    description = (
        "Repeated sudo authentication failures or sudo invocations that "
        "grant an unrestricted root shell / modify privileged files."
    )
    category = EventCategory.PRIVILEGE_ESCALATION
    severity = Severity.WARNING
    mitre_tactics = ("Privilege Escalation",)
    mitre_techniques = ("T1548.003",)
    recommendation = (
        "Review the sudo activity with the account owner; restrict "
        "sudoers entries to specific commands instead of full shells."
    )

    _FAILURE_THRESHOLD = 3
    _FAILURE_WINDOW = 600

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type is EventType.SUDO_COMMAND:
            command = str(event.extra.get("command", ""))
            if command and _DANGEROUS_SUDO.search(command):
                return self.make_alert(
                    event,
                    title=f"Sensitive sudo command by '{event.user or 'unknown'}'",
                    description=(
                        f"User '{event.user or 'unknown'}' ran a sudo command that "
                        f"grants shell access or alters privileged configuration: "
                        f"{command}"
                    ),
                    command=command,
                    target_user=event.extra.get("target_user"),
                )
            return None
        if event.event_type is EventType.SUDO_FAILURE and event.user:
            key = f"{self.rule_id}:{event.user}"
            ctx.state.add(key, event.timestamp, event=event)
            count = ctx.state.count(key, event.timestamp, self._FAILURE_WINDOW)
            if count < self._FAILURE_THRESHOLD:
                return None
            entries = ctx.state.entries(key, event.timestamp, self._FAILURE_WINDOW)
            events = [e.payload["event"] for e in entries]
            ctx.state.clear_key(key)
            return self.make_alert(
                event,
                title=f"Repeated sudo failures by '{event.user}'",
                description=(
                    f"{count} failed sudo attempts by '{event.user}' within "
                    f"{self._FAILURE_WINDOW} seconds."
                ),
                severity=Severity.ERROR,
                events=events,
                attempts=count,
            )
        return None


@register_rule
class PrivilegeEscalationRule(Rule):
    """Grants of privileged group membership or su to root."""

    rule_id = "R012"
    name = "Privilege Escalation"
    description = (
        "An account was added to a privileged group, or an interactive "
        "switch to the root user occurred — both expand privileges and "
        "are common attacker follow-on actions."
    )
    category = EventCategory.PRIVILEGE_ESCALATION
    severity = Severity.ERROR
    mitre_tactics = ("Privilege Escalation", "Persistence")
    mitre_techniques = ("T1098", "T1548")
    recommendation = (
        "Verify the change against change-management records; if "
        "unexpected, remove the privilege and audit the account's activity."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type is EventType.USER_MODIFIED:
            group = str(event.extra.get("group", "")).lower()
            if group in _PRIV_GROUPS:
                return self.make_alert(
                    event,
                    title=f"User '{event.user}' added to privileged group '{group}'",
                    description=(
                        f"Account '{event.user}' was granted membership of the "
                        f"privileged group '{group}', enabling elevated access."
                    ),
                    group=group,
                )
            return None
        if (
            event.event_type in (EventType.SUDO_COMMAND, EventType.SESSION_OPENED)
            and event.service in ("su", "su-l")
            and event.extra.get("target_user") == "root"
        ):
            return self.make_alert(
                event,
                title=f"Switch to root by '{event.user or 'unknown'}'",
                description=(
                    f"User '{event.user or 'unknown'}' switched to the root "
                    f"account with su."
                ),
                severity=Severity.WARNING,
                target_user="root",
            )
        return None
