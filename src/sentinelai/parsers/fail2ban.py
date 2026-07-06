"""Parser for Fail2Ban logs.

Example line::

    2024-01-07 03:14:15,123 fail2ban.actions [123]: NOTICE [sshd] Ban 1.2.3.4
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sentinelai.core.models import EventCategory, EventType, LogEvent, Severity
from sentinelai.parsers.base import LogParser, register_parser

_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)?\s+"
    r"(?P<component>fail2ban\.\w+)\s*(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<level>[A-Z]+)\s+(?P<msg>.*)$"
)

_ACTION = re.compile(
    r"\[(?P<jail>[\w-]+)\]\s+(?P<action>Ban|Unban|Found|Ignore|Restore Ban)\s+"
    r"(?P<ip>[0-9a-fA-F.:]+)"
)

_LEVEL_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.ERROR,
    "WARNING": Severity.WARNING,
    "NOTICE": Severity.NOTICE,
    "INFO": Severity.INFO,
    "DEBUG": Severity.DEBUG,
}

_ACTION_EVENT = {
    "Ban": EventType.BAN,
    "Restore Ban": EventType.BAN,
    "Unban": EventType.UNBAN,
    "Found": EventType.AUTH_FAILURE,
    "Ignore": EventType.GENERIC,
}


@register_parser
class Fail2BanParser(LogParser):
    """Fail2Ban log parser producing ban/unban/found events."""

    name = "fail2ban"
    description = "Fail2Ban log (bans, unbans, detections)"
    filename_hints = ("fail2ban",)

    def match_score(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        return sum(1 for line in sample_lines if _LINE.match(line)) / len(sample_lines)

    def parse_line(self, line: str) -> LogEvent | None:
        match = _LINE.match(line)
        if not match:
            return None
        try:
            timestamp = datetime.strptime(
                match.group("ts"), "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        message = match.group("msg")
        extra: dict[str, object] = {"component": match.group("component")}
        event_type = EventType.GENERIC
        ip: str | None = None
        action = _ACTION.search(message)
        if action:
            extra["jail"] = action.group("jail")
            extra["action"] = action.group("action")
            event_type = _ACTION_EVENT.get(action.group("action"), EventType.GENERIC)
            ip = action.group("ip")
        return LogEvent(
            timestamp=timestamp,
            message=message,
            raw=line,
            service="fail2ban",
            pid=int(match.group("pid")) if match.group("pid") else None,
            event_type=event_type,
            category=EventCategory.FIREWALL,
            ip=ip,
            severity=_LEVEL_SEVERITY.get(match.group("level"), Severity.INFO),
            extra=extra,
        )
