"""Parsers for Nginx access and error logs."""

# ReDoS hardening: regexes only see line[:MAX_LINE]; raw keeps the full line.

from __future__ import annotations

import re
from datetime import datetime, timezone

from sentinelai.core.models import EventCategory, EventType, LogEvent, Severity
from sentinelai.parsers.apache import _ACCESS, ACCESS_MAX_LINE, MAX_LINE, build_access_event
from sentinelai.parsers.base import LogParser, register_parser

# 2024/01/07 03:14:15 [error] 123#123: *45 msg, client: 1.2.3.4, server: x,
#   request: "GET / HTTP/1.1", host: "example.com"
_ERROR = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<level>\w+)\]\s+(?P<pid>\d+)#\d+:\s+"
    r"(?:\*\d+\s+)?(?P<msg>.*)$"
)

_CLIENT = re.compile(r"client:\s*(?P<ip>[0-9a-fA-F.:]+)")
_REQUEST = re.compile(r'request:\s*"(?P<method>[A-Z]+)\s+(?P<path>\S+)')

_LEVEL_SEVERITY = {
    "emerg": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "error": Severity.ERROR,
    "warn": Severity.WARNING,
    "notice": Severity.NOTICE,
    "info": Severity.INFO,
    "debug": Severity.DEBUG,
}


@register_parser
class NginxAccessParser(LogParser):
    """Nginx access log in the default (combined) format."""

    name = "nginx_access"
    description = "Nginx access log (combined format)"
    filename_hints = ("access.log", "nginx")

    def match_score(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        hits = sum(1 for line in sample_lines if _ACCESS.match(line[:ACCESS_MAX_LINE]))
        return hits / len(sample_lines)

    def parse_line(self, line: str) -> LogEvent | None:
        return build_access_event(line, "nginx")


@register_parser
class NginxErrorParser(LogParser):
    """Nginx error log parser."""

    name = "nginx_error"
    description = "Nginx error log"
    filename_hints = ("error.log", "nginx")

    def match_score(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        return sum(1 for line in sample_lines if _ERROR.match(line[:MAX_LINE])) / len(sample_lines)

    def parse_line(self, line: str) -> LogEvent | None:
        match = _ERROR.match(line[:MAX_LINE])
        if not match:
            return None
        try:
            timestamp = datetime.strptime(
                match.group("ts"), "%Y/%m/%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        message = match.group("msg")
        level = match.group("level").lower()
        client = _CLIENT.search(message)
        request = _REQUEST.search(message)
        extra: dict[str, object] = {"level": level}
        if request:
            extra["method"] = request.group("method")
            extra["path"] = request.group("path")
        return LogEvent(
            timestamp=timestamp,
            message=message,
            raw=line,
            service="nginx",
            pid=int(match.group("pid")),
            event_type=EventType.WEB_ERROR,
            category=EventCategory.WEB,
            ip=client.group("ip") if client else None,
            severity=_LEVEL_SEVERITY.get(level, Severity.ERROR),
            extra=extra,
        )
