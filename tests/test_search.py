"""Tests for the event search and filter engine."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sentinelai.core.exceptions import SentinelError
from sentinelai.core.models import EventCategory, EventType, Severity
from sentinelai.search.query import build_query, parse_date_bound

from tests.conftest import make_event


@pytest.fixture()
def events():
    return [
        make_event(
            offset=0, event_type=EventType.AUTH_FAILURE,
            category=EventCategory.AUTHENTICATION, severity=Severity.WARNING,
            ip="203.0.113.5", user="root", message="Failed password for root",
        ),
        make_event(
            offset=60, event_type=EventType.AUTH_SUCCESS,
            category=EventCategory.AUTHENTICATION, severity=Severity.INFO,
            ip="10.0.0.9", user="alice", message="Accepted password for alice",
        ),
        make_event(
            offset=120, event_type=EventType.WEB_REQUEST,
            category=EventCategory.WEB, severity=Severity.NOTICE,
            ip="198.51.100.7", user=None, message="GET /admin -> 403",
        ),
        make_event(
            offset=180, event_type=EventType.SERVICE_STOPPED,
            category=EventCategory.SERVICE_MANAGEMENT, severity=Severity.ERROR,
            ip=None, user=None, message="Stopped ufw.service",
        ),
    ]


class TestFilters:
    def test_by_ip(self, events) -> None:
        query = build_query(ip="203.0.113.5")
        results = list(query.filter(events))
        assert len(results) == 1
        assert results[0].user == "root"

    def test_by_user(self, events) -> None:
        results = list(build_query(user="alice").filter(events))
        assert len(results) == 1
        assert results[0].event_type is EventType.AUTH_SUCCESS

    def test_by_category(self, events) -> None:
        results = list(build_query(category="web").filter(events))
        assert len(results) == 1

    def test_by_event_type(self, events) -> None:
        results = list(build_query(event_type="service_stopped").filter(events))
        assert len(results) == 1

    def test_by_min_severity(self, events) -> None:
        results = list(build_query(min_severity="warning").filter(events))
        # WARNING and ERROR events (2 of 4).
        assert len(results) == 2

    def test_by_text(self, events) -> None:
        results = list(build_query(text="Failed password").filter(events))
        assert len(results) == 1

    def test_failed_logins_only(self, events) -> None:
        results = list(build_query(failed_only=True).filter(events))
        assert len(results) == 1
        assert results[0].event_type is EventType.AUTH_FAILURE

    def test_combined_filters(self, events) -> None:
        results = list(
            build_query(category="authentication", min_severity="warning").filter(events)
        )
        assert len(results) == 1

    def test_no_filter_matches_all(self, events) -> None:
        assert len(list(build_query().filter(events))) == len(events)

    def test_since_until_bounds(self, events) -> None:
        results = list(build_query(since="2026-01-07", until="2026-01-07").filter(events))
        assert len(results) == len(events)  # all events fall on that UTC day


class TestValidation:
    def test_invalid_category_raises(self) -> None:
        with pytest.raises(SentinelError):
            build_query(category="not_a_category")

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(SentinelError):
            build_query(min_severity="ultra")

    def test_invalid_date_raises(self) -> None:
        with pytest.raises(SentinelError):
            build_query(since="not-a-date")


class TestDateBound:
    def test_bare_date_start(self) -> None:
        dt = parse_date_bound("2026-01-07")
        assert dt == datetime(2026, 1, 7, 0, 0, tzinfo=timezone.utc)

    def test_bare_date_end_of_day(self) -> None:
        dt = parse_date_bound("2026-01-07", end_of_day=True)
        assert dt.hour == 23 and dt.minute == 59
