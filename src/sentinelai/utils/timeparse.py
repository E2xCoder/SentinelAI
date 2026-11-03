"""Timestamp parsing helpers for the many formats found in Linux logs."""

from __future__ import annotations

import re
from datetime import datetime, timezone

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
