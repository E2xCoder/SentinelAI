"""Parser for dedicated UFW logs (/var/log/ufw.log).

UFW log lines are kernel messages in syslog framing::

    Jan  7 03:14:15 host kernel: [1234.567] [UFW BLOCK] IN=eth0 OUT= ...
        SRC=1.2.3.4 DST=10.0.0.5 ... PROTO=TCP SPT=54321 DPT=22 ...

The syslog parser also understands these when they appear inline in
``syslog``; this dedicated parser scores highly on pure UFW files and
extracts the full netfilter field set.
"""

from __future__ import annotations

import re

from sentinelai.core.models import EventCategory, EventType, LogEvent, Severity
from sentinelai.parsers.base import LogParser, register_parser
from sentinelai.utils.timeparse import parse_iso_timestamp, parse_syslog_timestamp

_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|"
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+kernel:\s*(?:\[\s*[\d.]+\]\s*)?"
    r"\[UFW (?P<action>BLOCK|ALLOW|AUDIT|DENY)\]\s*(?P<fields>.*)$"
)

_FIELD = re.compile(r"([A-Z]+)=(\S*)")

_ACTION_EVENT = {
    "BLOCK": EventType.FIREWALL_BLOCK,
    "DENY": EventType.FIREWALL_BLOCK,
    "AUDIT": EventType.CONNECTION,
    "ALLOW": EventType.CONNECTION,
}


@register_parser
class UFWParser(LogParser):
    """UFW (netfilter) log parser."""

    name = "ufw"
    description = "UFW firewall log (kernel netfilter messages)"
    filename_hints = ("ufw",)

    def match_score(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        return sum(1 for line in sample_lines if _HEADER.match(line)) / len(sample_lines)

    def parse_line(self, line: str) -> LogEvent | None:
        match = _HEADER.match(line)
        if not match:
            return None
        ts_raw = match.group("ts")
        timestamp = (
            parse_iso_timestamp(ts_raw.replace(",", "."))
            or parse_syslog_timestamp(ts_raw)
        )
        if timestamp is None:
            return None
        fields = dict(_FIELD.findall(match.group("fields")))
        action = match.group("action")
        dpt = fields.get("DPT")
        return LogEvent(
            timestamp=timestamp,
            message=f"UFW {action} {fields.get('PROTO', '?')} "
            f"{fields.get('SRC', '?')}:{fields.get('SPT', '?')} -> "
            f"{fields.get('DST', '?')}:{dpt or '?'}",
            raw=line,
            hostname=match.group("host"),
            service="ufw",
            event_type=_ACTION_EVENT.get(action, EventType.FIREWALL_BLOCK),
            category=EventCategory.FIREWALL,
            ip=fields.get("SRC"),
            port=int(dpt) if dpt and dpt.isdigit() else None,
            severity=Severity.NOTICE if action in ("BLOCK", "DENY") else Severity.INFO,
            extra={
                "action": action,
                "interface_in": fields.get("IN", ""),
                "interface_out": fields.get("OUT", ""),
                "dst": fields.get("DST", ""),
                "proto": fields.get("PROTO", ""),
                "src_port": fields.get("SPT", ""),
            },
        )
