"""Parser for the syslog family: auth.log, syslog, SSH, cron, kernel.

Handles both the classic BSD header (``Jan  7 03:14:15 host sshd[42]:``)
and the RFC 3339 header modern rsyslog emits
(``2024-01-07T03:14:15.123456+02:00 host sshd[42]:``).
"""

from __future__ import annotations

import re

from sentinelai.core.models import EventType, LogEvent, Severity
from sentinelai.parsers.base import LogParser, register_parser
from sentinelai.parsers.classify import classify_message
from sentinelai.utils.timeparse import parse_iso_timestamp, parse_syslog_timestamp

_HEADER_BSD = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s"
    r"(?P<msg>.*)$"
)

_HEADER_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s"
    r"(?P<msg>.*)$"
)

_ROOT_USERS = frozenset({"root"})


@register_parser
class SyslogParser(LogParser):
    """Parses BSD and RFC 3339 syslog lines into classified events."""

    name = "syslog"
    description = "Linux syslog family (auth.log, syslog, ssh, cron, kernel)"
    filename_hints = ("auth", "syslog", "secure", "messages", "ssh", "cron", "kern")

    def match_score(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        hits = sum(
            1
            for line in sample_lines
            if _HEADER_BSD.match(line) or _HEADER_ISO.match(line)
        )
        # Syslog is the generic base format: dedicated formats such as UFW
        # (kernel netfilter messages) are *also* valid syslog. Scale the
        # confidence slightly below 1.0 so a specialized parser that fully
        # matches the same lines wins the tie and extracts richer fields.
        return 0.9 * (hits / len(sample_lines))

    def parse_line(self, line: str) -> LogEvent | None:
        match = _HEADER_BSD.match(line) or _HEADER_ISO.match(line)
        if not match:
            return None
        ts_raw = match.group("ts")
        timestamp = (
            parse_iso_timestamp(ts_raw.replace(",", "."))
            or parse_syslog_timestamp(ts_raw)
        )
        if timestamp is None:
            return None
        service = match.group("service")
        message = match.group("msg")
        pid_raw = match.group("pid")

        result = classify_message(service, message)
        event = LogEvent(
            timestamp=timestamp,
            message=message,
            raw=line,
            hostname=match.group("host"),
            service=service,
            pid=int(pid_raw) if pid_raw else None,
            event_type=result.event_type,
            category=result.category,
            user=result.user,
            ip=result.ip,
            port=result.port,
            severity=result.severity,
            extra=result.extra,
        )
        # Successful authentication as root is its own event type: several
        # rules and the risk engine treat it specially.
        if event.event_type is EventType.AUTH_SUCCESS and event.user in _ROOT_USERS:
            event.event_type = EventType.ROOT_LOGIN
            event.severity = Severity.WARNING
        return event
