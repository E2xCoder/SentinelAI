"""Timestamp parsing helpers for the many formats found in Linux logs."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

# "Jan  7 03:14:15" — classic BSD syslog, no year.
_SYSLOG_BSD = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# "10/Oct/2000:13:55:36 -0700" — Apache/Nginx CLF.
_CLF = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<year>\d{4}):"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s*(?P<tz>[+-]\d{4})?"
)


def parse_syslog_timestamp(value: str, reference_year: int | None = None) -> datetime | None:
    """Parse a BSD syslog timestamp such as ``Jan  7 03:14:15``.

    Classic syslog omits the year, so we borrow it from *reference_year*
    (default: current year) and roll back one year if the result would be
    in the future — which happens when reading December logs in January.
    """
    match = _SYSLOG_BSD.match(value.strip())
    if not match:
        return None
    now = datetime.now(timezone.utc)
    year = reference_year or now.year
    hour, minute, second = (int(p) for p in match.group("time").split(":"))
    try:
        result = datetime(
            year, _MONTHS[match.group("mon")], int(match.group("day")),
            hour, minute, second, tzinfo=timezone.utc,
        )
    except ValueError:
        return None
    if reference_year is None and result > now:
        result = result.replace(year=year - 1)
    return result


class SyslogYearTracker:
    """Infer the missing year of BSD syslog timestamps across ONE log stream.

    Per-line inference (``parse_syslog_timestamp``) cannot tell December from
    the following January, so a log that crosses New Year (or is older than a
    year) would jump back and forth in time. The tracker anchors the first
    line like ``parse_syslog_timestamp`` does, then follows the stream: when a
    line is more than half a year *earlier* than the previous one the year
    rolled over, and when it is more than half a year *later* it is a stray
    older line. Small out-of-order jitter is tolerated.
    """

    _HALF_YEAR = timedelta(days=183)

    def __init__(self) -> None:
        self._last: datetime | None = None

    def reset(self) -> None:
        self._last = None

    def resolve(self, value: str) -> datetime | None:
        match = _SYSLOG_BSD.match(value.strip())
        if not match:
            return None
        if self._last is None:
            first = parse_syslog_timestamp(value)
            self._last = first
            return first
        hour, minute, second = (int(p) for p in match.group("time").split(":"))
        month, day = _MONTHS[match.group("mon")], int(match.group("day"))
        year = self._last.year
        result = _safe_datetime(year, month, day, hour, minute, second)
        if result is None:
            return None
        if result < self._last - self._HALF_YEAR:
            result = _safe_datetime(year + 1, month, day, hour, minute, second) or result
        elif result > self._last + self._HALF_YEAR:
            result = _safe_datetime(year - 1, month, day, hour, minute, second) or result
        if result > self._last or result < self._last - self._HALF_YEAR:
            self._last = result
        return result


def _safe_datetime(
    year: int, month: int, day: int, hour: int, minute: int, second: int
) -> datetime | None:
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


_FRACTION = re.compile(r"\.(\d+)")


def parse_iso_timestamp(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp, tolerating a trailing ``Z``.

    The fractional part is normalized to microseconds first: Docker emits
    nanoseconds, which ``datetime.fromisoformat`` rejects before Python 3.11.
    """
    candidate = _FRACTION.sub(
        lambda m: "." + m.group(1)[:6].ljust(6, "0"),
        value.strip().replace("Z", "+00:00"),
        count=1,
    )
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_clf_timestamp(value: str) -> datetime | None:
    """Parse an Apache/Nginx CLF timestamp such as ``10/Oct/2000:13:55:36 -0700``."""
    match = _CLF.match(value.strip())
    if not match:
        return None
    try:
        naive = datetime.strptime(
            f"{match.group('day')}/{match.group('mon')}/{match.group('year')} "
            f"{match.group('time')}",
            "%d/%b/%Y %H:%M:%S",
        )
    except ValueError:
        return None
    tz_raw = match.group("tz")
    if tz_raw:
        sign = 1 if tz_raw[0] == "+" else -1
        offset_min = sign * (int(tz_raw[1:3]) * 60 + int(tz_raw[3:5]))
        from datetime import timedelta

        return naive.replace(tzinfo=timezone(timedelta(minutes=offset_min)))
    return naive.replace(tzinfo=timezone.utc)


def parse_any_timestamp(value: str, reference_year: int | None = None) -> datetime | None:
    """Try all known timestamp formats and return the first match."""
    for parser in (parse_iso_timestamp, parse_clf_timestamp):
        parsed = parser(value)
        if parsed is not None:
            return parsed
    return parse_syslog_timestamp(value, reference_year)


def ensure_utc(value: datetime) -> datetime:
    """Return *value* converted to UTC, assuming UTC when naive."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
