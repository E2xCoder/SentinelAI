"""Parsers for Apache HTTP Server access and error logs."""

# ReDoS hardening: request-line part of _ACCESS made deterministic (no overlapping
# quantifiers); regexes only see line[:MAX_LINE]; raw keeps the full line.

from __future__ import annotations

import re

from sentinelai.core.models import EventCategory, EventType, LogEvent, Severity
from sentinelai.parsers.base import LogParser, register_parser
from sentinelai.utils.timeparse import parse_clf_timestamp

#: Upper bound on the line length handed to the regex engine.
MAX_LINE = 8192
# Access-log lines carry the attacker-controlled request in the middle and the
# status/size at the END, so truncating them drops the whole event (evasion by
# padding). The access regex is linear, so it may look at the reader's full limit.
ACCESS_MAX_LINE = 65_536

# Common/Combined Log Format:
# 1.2.3.4 - frank [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.0" 200 2326 "ref" "ua"
_ACCESS = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"
    # Each quantifier is forced maximal by a lookahead, so a failed match cannot
    # re-split method/whitespace/path/rest (was cubic on an unterminated quote).
    r'"(?:(?P<method>[A-Z]+)(?![A-Z]))?\s*(?!\s)(?P<path>[^"\s]*)(?![^"\s])[^"]*"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# [Sat Jan 07 03:14:15.123456 2024] [core:error] [pid 42:tid 7] [client 1.2.3.4:5678] msg
_ERROR = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\[(?:(?P<module>[\w-]+):)?(?P<level>\w+)\]\s+"
    r"(?:\[pid (?P<pid>\d+)(?::tid \d+)?\]\s+)?"
    r"(?:\[client (?P<ip>[^\]:]+)(?::(?P<port>\d+))?\]\s+)?"
    r"(?P<msg>.*)$"
)

_ERROR_TS_FORMAT = "%a %b %d %H:%M:%S.%f %Y"

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


def status_severity(status: int) -> Severity:
    """Map an HTTP status code onto an event severity."""
    if status >= 500:
        return Severity.ERROR
    if status in (401, 403):
        return Severity.WARNING
    if status >= 400:
        return Severity.NOTICE
    return Severity.INFO


def build_access_event(line: str, source_name: str) -> LogEvent | None:
    """Shared builder for CLF access lines (Apache and Nginx)."""
    match = _ACCESS.match(line[:ACCESS_MAX_LINE])
    if not match:
        return None
    timestamp = parse_clf_timestamp(match.group("ts"))
    if timestamp is None:
        return None
    status = int(match.group("status"))
    user = match.group("user")
    size_raw = match.group("size")
    return LogEvent(
        timestamp=timestamp,
        message=f"{match.group('method') or '?'} {match.group('path')} -> {status}",
        raw=line,
        service=source_name,
        event_type=EventType.WEB_REQUEST,
        category=EventCategory.WEB,
        user=None if user in ("-", "") else user,
        ip=match.group("ip"),
        severity=status_severity(status),
        extra={
            "method": match.group("method") or "",
            "path": match.group("path"),
            "status": status,
            "size": None if size_raw == "-" else int(size_raw),
            "referer": match.group("referer") or "",
            "user_agent": match.group("agent") or "",
        },
    )


@register_parser
class ApacheAccessParser(LogParser):
    """Apache access log in Common or Combined Log Format."""

    name = "apache_access"
    description = "Apache HTTP Server access log (CLF / combined)"
    filename_hints = ("access.log", "access_log", "apache")

    def match_score(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        hits = sum(1 for line in sample_lines if _ACCESS.match(line[:ACCESS_MAX_LINE]))
        return hits / len(sample_lines)

    def parse_line(self, line: str) -> LogEvent | None:
        return build_access_event(line, "apache")


@register_parser
class ApacheErrorParser(LogParser):
    """Apache error log parser."""

    name = "apache_error"
    description = "Apache HTTP Server error log"
    filename_hints = ("error.log", "error_log")

    def match_score(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        hits = 0
        for line in sample_lines:
            match = _ERROR.match(line[:MAX_LINE])
            if match and self._parse_ts(match.group("ts")) is not None:
                hits += 1
        return hits / len(sample_lines)

    @staticmethod
    def _parse_ts(value: str) -> object | None:
        from datetime import datetime, timezone

        for fmt in (_ERROR_TS_FORMAT, "%a %b %d %H:%M:%S %Y"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    def parse_line(self, line: str) -> LogEvent | None:
        match = _ERROR.match(line[:MAX_LINE])
        if not match:
            return None
        timestamp = self._parse_ts(match.group("ts"))
        if timestamp is None:
            return None
        level = (match.group("level") or "error").lower()
        port_raw = match.group("port")
        return LogEvent(
            timestamp=timestamp,  # type: ignore[arg-type]
            message=match.group("msg"),
            raw=line,
            service="apache",
            pid=int(match.group("pid")) if match.group("pid") else None,
            event_type=EventType.WEB_ERROR,
            category=EventCategory.WEB,
            ip=match.group("ip"),
            port=int(port_raw) if port_raw else None,
            severity=_LEVEL_SEVERITY.get(level, Severity.ERROR),
            extra={"module": match.group("module") or "", "level": level},
        )
