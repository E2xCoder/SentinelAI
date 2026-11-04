"""Persistence detections: cron abuse, SSH key manipulation, autostarts."""

# ReDoS hardening: \s+ before the [^\n|;]* gap is forced maximal so a failed
# match cannot re-scan per split.

from __future__ import annotations

import re

from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent, Severity
from sentinelai.detection.base import Rule, RuleContext, register_rule
from sentinelai.utils.regex import search_windowed

_SUSPICIOUS_CRON_CMD = re.compile(
    r"""
    (?:
        (?:curl|wget)\s+(?!\s)[^\n|;]*\|\s*(?:ba)?sh      # download piped to shell
        | base64\s+(?:-d|--decode)                  # encoded payloads
        | /tmp/[^\s;|]+                             # executing from /tmp
        | /dev/shm/[^\s;|]+                         # executing from tmpfs
        | \bnc\b|\bncat\b|/dev/tcp/                 # network tooling in cron
        | python[\d.]*\s+-c\s
        | chmod\s+\+x\s+/(?:tmp|var/tmp|dev/shm)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_SSH_KEY_TOUCH = re.compile(
    r"authorized_keys|\.ssh/(?:id_[a-z0-9]+|config)|ssh-keygen\s", re.IGNORECASE
)

_PERSISTENCE_PATHS = re.compile(
    r"""
    (?:
        /etc/systemd/system/\S+\.service
        | /lib/systemd/system/\S+\.service
        | systemctl\s+(?:enable|daemon-reload)
        | /etc/rc\.local
        | /etc/init\.d/\S+
        | /etc/profile(?:\.d/\S+)?
        | (?:\.bashrc|\.bash_profile|\.profile|\.zshrc)\b
        | /etc/ld\.so\.preload
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _command_text(event: LogEvent) -> str:
    parts = [str(event.extra.get("command", "")), event.message]
    return " ".join(p for p in parts if p)


@register_rule
class SuspiciousCronRule(Rule):
    """Cron jobs with attacker tradecraft, or crontab modifications."""

    rule_id = "R040"
    name = "Suspicious Cron Activity"
    description = (
        "A cron job executed content matching common attacker tradecraft "
        "(downloads piped to shells, /tmp binaries, encoded payloads), or "
        "a crontab was modified."
    )
    category = EventCategory.CRON
    severity = Severity.ERROR
    mitre_tactics = ("Persistence", "Execution")
    mitre_techniques = ("T1053.003",)
    recommendation = (
        "Review the crontab of the affected user, remove unauthorized "
        "entries and inspect the executed payloads."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type is EventType.CRON_JOB:
            command = str(event.extra.get("command", ""))
            # Windowed search: bounds the per-line rescan cost (quadratic on repeated curl/wget).
            match = search_windowed(_SUSPICIOUS_CRON_CMD, command)
            if match:
                return self.make_alert(
                    event,
                    title=f"Suspicious cron job for '{event.user or 'unknown'}'",
                    description=(
                        f"Cron executed a command with suspicious content "
                        f"(matched {match.group(0).strip()!r}): {command}"
                    ),
                    command=command,
                    matched=match.group(0).strip(),
                )
            return None
        if event.event_type is EventType.CRON_EDIT:
            action = str(event.extra.get("action", ""))
            if action in ("REPLACE", "DELETE"):
                return self.make_alert(
                    event,
                    title=f"Crontab {action.lower()} by '{event.user or 'unknown'}'",
                    description=(
                        f"User '{event.user or 'unknown'}' performed a crontab "
                        f"{action.lower()} on "
                        f"'{event.extra.get('target') or 'own crontab'}'."
                    ),
                    severity=Severity.NOTICE,
                    action=action,
                )
        return None


@register_rule
class SSHKeyManipulationRule(Rule):
    """Commands touching SSH keys or authorized_keys files."""

    rule_id = "R041"
    name = "SSH Key Manipulation"
    description = (
        "A command referenced SSH private keys or authorized_keys files. "
        "Planting a key is the most common Linux persistence technique."
    )
    category = EventCategory.SSH
    severity = Severity.ERROR
    mitre_tactics = ("Persistence", "Credential Access")
    mitre_techniques = ("T1098.004", "T1552.004")
    recommendation = (
        "Diff authorized_keys files against a known-good baseline and "
        "remove any unrecognized keys immediately."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type not in (EventType.SUDO_COMMAND, EventType.CRON_JOB):
            return None
        text = _command_text(event)
        match = _SSH_KEY_TOUCH.search(text)
        if not match:
            return None
        return self.make_alert(
            event,
            title=f"SSH key material touched by '{event.user or 'unknown'}'",
            description=(
                f"A command referencing SSH key material was executed "
                f"(matched {match.group(0)!r}): "
                f"{event.extra.get('command', event.message)}"
            ),
            command=event.extra.get("command"),
            matched=match.group(0),
        )


@register_rule
class PersistenceIndicatorRule(Rule):
    """Commands writing to autostart locations."""

    rule_id = "R042"
    name = "Persistence Indicator"
    description = (
        "A command wrote to or enabled an autostart location (systemd "
        "units, rc.local, shell profiles, ld.so.preload) — classic "
        "persistence establishment."
    )
    category = EventCategory.SYSTEM
    severity = Severity.ERROR
    mitre_tactics = ("Persistence",)
    mitre_techniques = ("T1543.002", "T1546.004")
    recommendation = (
        "Inspect the referenced autostart entry and compare it against "
        "your configuration baseline before the next reboot."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type not in (EventType.SUDO_COMMAND, EventType.CRON_JOB):
            return None
        command = str(event.extra.get("command", ""))
        if not command:
            return None
        match = _PERSISTENCE_PATHS.search(command)
        if not match:
            return None
        return self.make_alert(
            event,
            title=f"Autostart modification by '{event.user or 'unknown'}'",
            description=(
                f"Command touched an autostart location "
                f"(matched {match.group(0).strip()!r}): {command}"
            ),
            command=command,
            matched=match.group(0).strip(),
        )
