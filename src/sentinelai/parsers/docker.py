"""Parser for the Docker daemon log (logfmt style).

Example line::

    time="2024-01-07T03:14:15.123456789Z" level=info msg="Container started"
"""

# ReDoS hardening: msg trailer stripped in code (no lazy .*? + \s*$),
# _PRIVILEGED has no adjacent \s*, line capped.

from __future__ import annotations

import re

from sentinelai.core.models import EventCategory, EventType, LogEvent, Severity
from sentinelai.parsers.base import LogParser, register_parser
from sentinelai.utils.timeparse import parse_iso_timestamp

#: Upper bound on the line length handed to the regex engine.
_MAX_LINE = 8192

# The message is captured greedily; the optional closing quote and trailing
# whitespace are removed by _clean_msg (equivalent to the former lazy
# ``(?P<msg>.*?)"?\s*$`` but linear instead of quadratic on whitespace runs).
_LINE = re.compile(
    r'^time="(?P<ts>[^"]+)"\s+level=(?P<level>\w+)\s+msg="?(?P<msg>.*)$'
)

_FIELD = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

_LEVEL_SEVERITY = {
    "fatal": Severity.CRITICAL,
    "panic": Severity.CRITICAL,
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "warn": Severity.WARNING,
    "info": Severity.INFO,
    "debug": Severity.DEBUG,
}

_CONTAINER_ID = re.compile(r"container(?:=|\s+)(?P<cid>[0-9a-f]{12,64})")
_PRIVILEGED = re.compile(r"privileged(?!\s*(?:[:=]\s*)?(?:false|no|0|off)\b)", re.IGNORECASE)


def _clean_msg(raw_msg: str) -> str:
    """Drop trailing whitespace and at most one closing quote."""
    msg = raw_msg.rstrip()
    if msg.endswith('"'):
        msg = msg[:-1]
    return msg


@register_parser
class DockerParser(LogParser):
    """Docker daemon (dockerd) log parser."""

    name = "docker"
    description = "Docker daemon log (logfmt)"
    filename_hints = ("docker",)

    def match_score(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        return sum(1 for line in sample_lines if _LINE.match(line[:_MAX_LINE])) / len(sample_lines)

    def parse_line(self, line: str) -> LogEvent | None:
        text = line[:_MAX_LINE]
        match = _LINE.match(text)
        if not match:
            return None
        timestamp = parse_iso_timestamp(match.group("ts"))
        if timestamp is None:
            return None
        message = _clean_msg(match.group("msg"))
        level = match.group("level").lower()
        extra: dict[str, object] = {"level": level}
        cid = _CONTAINER_ID.search(text)
        if cid:
            extra["container_id"] = cid.group("cid")
        if _PRIVILEGED.search(text):
            extra["privileged"] = True
        return LogEvent(
            timestamp=timestamp,
            message=message,
            raw=line,
            service="docker",
            event_type=EventType.CONTAINER_EVENT,
            category=EventCategory.DOCKER,
            severity=_LEVEL_SEVERITY.get(level, Severity.INFO),
            extra=extra,
        )
