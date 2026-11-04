"""Regressions found by running SentinelAI over real Loghub OpenSSH/Linux logs.

All lines are anonymized (documentation IPs, generic hosts and users).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinelai.core.models import EventType
from sentinelai.parsers.base import get_parser
from sentinelai.utils.timeparse import SyslogYearTracker


def _parse(lines: list[str]) -> list:  # type: ignore[type-arg]
    parser = get_parser("syslog")
    parser.reset_stream_state()
    return list(parser.parse_lines(lines))


def test_service_with_parenthesised_module_is_parsed() -> None:
    events = _parse(
        [
            "Jun 10 17:16:34 host1 sshd(pam_unix)[3353]: authentication failure; "
            "logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=203.0.113.9  user=root"
        ]
    )
    assert len(events) == 1
    assert events[0].service == "sshd"
    assert events[0].pid == 3353
    assert events[0].event_type is EventType.AUTH_FAILURE
    assert events[0].ip == "203.0.113.9"


def test_extra_space_before_username_still_classified() -> None:
    events = _parse(
        [
            "Dec 10 08:24:35 host1 sshd[1]: Failed password for invalid user  0101 "
            "from 203.0.113.9 port 36279 ssh2"
        ]
    )
    assert events[0].event_type is EventType.AUTH_FAILURE
    assert events[0].user == "0101"


def _triplet(pid: int, sec: int) -> list[str]:
    ts = f"Jun  9 08:00:{sec:02d} host1 sshd[{pid}]:"
    return [
        f"{ts} Invalid user admin from 203.0.113.9",
        f"{ts} pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
        "tty=ssh ruser= rhost=203.0.113.9 ",
        f"Jun  9 08:00:{sec + 2:02d} host1 sshd[{pid}]: Failed password for invalid user "
        f"admin from 203.0.113.9 port 4000 ssh2",
    ]


def test_openssh_triplet_counts_as_one_failure() -> None:
    events = _parse(_triplet(10, 10) + _triplet(11, 20))
    failures = [
        e for e in events if e.event_type in (EventType.AUTH_FAILURE, EventType.INVALID_USER)
    ]
    assert len(failures) == 2
    assert all(e.message.startswith("Failed password") for e in failures)


def test_event_order_is_preserved_while_pairing() -> None:
    lines = _triplet(10, 10) + ["Jun  9 08:00:13 host1 cron[5]: (root) CMD (x)"] + _triplet(11, 20)
    stamps = [e.timestamp for e in _parse(lines)]
    assert stamps == sorted(stamps)


def test_legacy_pam_only_failures_are_still_counted() -> None:
    lines = [
        f"Jun 10 17:16:{10 + i:02d} host1 sshd(pam_unix)[{3300 + i}]: authentication failure; "
        "logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=203.0.113.9  user=root"
        for i in range(5)
    ]
    assert len(_parse(lines)) == 5


def test_invalid_user_without_password_attempt_is_kept() -> None:
    events = _parse(["Jun  9 08:00:10 host1 sshd[9]: Invalid user admin from 203.0.113.9"])
    assert [e.event_type for e in events] == [EventType.INVALID_USER]


def test_year_rolls_over_inside_one_stream() -> None:
    tracker = SyslogYearTracker()
    first = tracker.resolve("Dec 31 23:59:50")
    second = tracker.resolve("Jan  1 00:00:10")
    third = tracker.resolve("Jan  1 00:00:05")  # small jitter, same year as second
    assert first is not None and second is not None and third is not None
    assert second.year == first.year + 1
    assert third.year == second.year
    assert second > first


def test_multi_year_log_is_monotonic() -> None:
    tracker = SyslogYearTracker()
    months = [
        "Jun  9 06:00:00",
        "Sep  1 00:00:00",
        "Dec 20 00:00:00",
        "Jan 15 00:00:00",
        "Feb 28 00:00:00",
    ]
    stamps = [tracker.resolve(m) for m in months]
    assert all(s is not None for s in stamps)
    assert stamps == sorted(s for s in stamps if s is not None)


def test_tracker_reset_forgets_previous_stream() -> None:
    tracker = SyslogYearTracker()
    tracker.resolve("Dec 31 23:59:50")
    tracker.reset()
    now = datetime.now(timezone.utc)
    resolved = tracker.resolve("Jan  1 00:00:00")
    assert resolved is not None and resolved <= now


def test_store_batch_defers_commits_but_persists_everything(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import sqlite3

    from sentinelai.core.store import AlertStore
    from tests.test_response_hardening import make_alert

    db = tmp_path / "alerts.db"
    store = AlertStore(db)
    with store.batch():
        for _ in range(5):
            store.save(make_alert("203.0.113.9", alert_id=None))
        # not yet visible to another connection: the commit is deferred
        other = sqlite3.connect(str(db))
        assert other.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
        other.close()
    other = sqlite3.connect(str(db))
    assert other.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 5
    other.close()
    store.close()


def test_unreadable_route_file_warns_instead_of_failing_silently(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    import sys

    from sentinelai.firewall import lockout

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(lockout, "_ROUTE_FILE", str(tmp_path / "missing-route"))
    with caplog.at_level("WARNING"):
        assert lockout.default_gateways() == set()
    assert "gateway protection is OFF" in caplog.text
