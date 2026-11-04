"""Parser for the syslog family: auth.log, syslog, SSH, cron, kernel.

Handles both the classic BSD header (``Jan  7 03:14:15 host sshd[42]:``)
and the RFC 3339 header modern rsyslog emits
(``2024-01-07T03:14:15.123456+02:00 host sshd[42]:``).
"""

# ReDoS hardening: header regexes only ever see line[:_MAX_LINE]; raw keeps the full line.

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable, Iterator
from datetime import timedelta

from sentinelai.core.models import EventType, LogEvent, Severity
from sentinelai.parsers.base import LogParser, register_parser
from sentinelai.parsers.classify import classify_message
from sentinelai.utils.timeparse import SyslogYearTracker, parse_iso_timestamp

_HEADER_BSD = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[\w./-]+?)(?:\([\w./:-]{1,32}\))?(?:\[(?P<pid>\d+)\])?:\s"
    r"(?P<msg>.*)$"
)

_HEADER_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[\w./-]+?)(?:\([\w./:-]{1,32}\))?(?:\[(?P<pid>\d+)\])?:\s"
    r"(?P<msg>.*)$"
)

_ROOT_USERS = frozenset({"root"})

#: A PAM failure and its sshd "Failed ..." partner are at most this far apart.
_PAM_WINDOW = timedelta(seconds=10)
#: Cap on events held while waiting for a PAM partner (bounded memory).
_MAX_HELD = 5000


def _partner_kind(event: LogEvent) -> str | None:
    """Return "pam"/"inv" for lines that sshd later repeats as ``Failed ...``."""
    if not (event.service or "").startswith("sshd"):
        return None
    is_failure = event.event_type is EventType.AUTH_FAILURE
    if is_failure and "authentication failure;" in event.message:
        return "pam"
    if event.event_type is EventType.INVALID_USER:
        return "inv"
    return None


def _pending_key(event: LogEvent) -> tuple[str, int] | None:
    kind = _partner_kind(event)
    if kind is None or event.pid is None:
        return None
    return (kind, event.pid)


def _is_sshd_failed(event: LogEvent) -> bool:
    return (
        event.event_type is EventType.AUTH_FAILURE
        and (event.service or "").startswith("sshd")
        and event.message.startswith("Failed ")
    )


#: Upper bound on the line length handed to the regex engine.
_MAX_LINE = 8192


@register_parser
class SyslogParser(LogParser):
    """Parses BSD and RFC 3339 syslog lines into classified events."""

    name = "syslog"
    description = "Linux syslog family (auth.log, syslog, ssh, cron, kernel)"
    filename_hints = ("auth", "syslog", "secure", "messages", "ssh", "cron", "kern")

    def __init__(self) -> None:
        self._years = SyslogYearTracker()

    def reset_stream_state(self) -> None:
        self._years.reset()

    def parse_lines(self, lines: Iterable[str], source: str = "") -> Iterator[LogEvent]:
        """Parse lines, collapsing the PAM+sshd double report of one failed login.

        Modern OpenSSH reports one failed password several times: a
        ``pam_unix(sshd:auth): authentication failure`` line, an ``Invalid user``
        line for unknown accounts, and the ``Failed password for ...`` line.
        Counting each would halve every failure threshold, so the PAM and
        ``Invalid user`` lines are held back briefly and dropped when the
        matching ``Failed ...`` line of the same sshd process follows. Old sshd
        versions that only emit the PAM line still count: a held line is released
        unchanged once no partner shows up. Event order is preserved.
        """
        held: deque[LogEvent] = deque()
        pending: dict[tuple[str, int], LogEvent] = {}
        dropped: set[int] = set()
        for event in super().parse_lines(lines, source):
            pid = event.pid
            if pid is not None:
                kind = _partner_kind(event)
                if kind is not None:
                    pending[(kind, pid)] = event
                elif _is_sshd_failed(event):
                    for partner_kind in ("pam", "inv"):
                        partner = pending.pop((partner_kind, pid), None)
                        gap = event.timestamp - partner.timestamp if partner else None
                        if partner is not None and gap is not None and gap <= _PAM_WINDOW:
                            dropped.add(id(partner))
                            event.extra["collapsed_" + partner_kind] = True
            held.append(event)
            while held:
                head = held[0]
                key = _pending_key(head)
                waiting = key is not None and pending.get(key) is head
                fresh = event.timestamp - head.timestamp <= _PAM_WINDOW
                if waiting and fresh and len(held) < _MAX_HELD:
                    break
                held.popleft()
                if key is not None and pending.get(key) is head:
                    del pending[key]
                if id(head) in dropped:
                    dropped.discard(id(head))
                    continue
                yield head
        for head in held:
            if id(head) not in dropped:
                yield head

    def match_score(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        hits = sum(
            1
            for line in sample_lines
            if _HEADER_BSD.match(line[:_MAX_LINE]) or _HEADER_ISO.match(line[:_MAX_LINE])
        )
        # Syslog is the generic base format: dedicated formats such as UFW
        # (kernel netfilter messages) are *also* valid syslog. Scale the
        # confidence slightly below 1.0 so a specialized parser that fully
        # matches the same lines wins the tie and extracts richer fields.
        return 0.9 * (hits / len(sample_lines))

    def parse_line(self, line: str) -> LogEvent | None:
        text = line[:_MAX_LINE]
        match = _HEADER_BSD.match(text) or _HEADER_ISO.match(text)
        if not match:
            return None
        ts_raw = match.group("ts")
        timestamp = (
            parse_iso_timestamp(ts_raw.replace(",", "."))
            if ts_raw[:1].isdigit()
            else self._years.resolve(ts_raw)
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
