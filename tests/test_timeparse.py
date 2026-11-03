"""Tests for ISO-8601 timestamp parsing, including Docker's nanosecond form."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinelai.utils.timeparse import parse_iso_timestamp


class TestParseIsoTimestamp:
    @pytest.mark.parametrize(
        ("raw", "microsecond"),
        [
            ("2026-01-07T03:14:15.123456789Z", 123456),  # Docker nanoseconds
            ("2026-01-07T03:14:15.123456Z", 123456),
            ("2026-01-07T03:14:15.123Z", 123000),
            ("2026-01-07T03:14:15.5Z", 500000),
            ("2026-01-07T03:14:15Z", 0),
            ("2026-01-07T03:14:15.123456789+00:00", 123456),
        ],
    )
    def test_fraction_lengths_normalized(self, raw: str, microsecond: int) -> None:
        parsed = parse_iso_timestamp(raw)
        assert parsed is not None
        assert parsed.microsecond == microsecond
        assert parsed.utcoffset() == timedelta(0)

    def test_offset_preserved(self) -> None:
        parsed = parse_iso_timestamp("2026-01-07T03:14:15.123456789+02:00")
        assert parsed == datetime(2026, 1, 7, 1, 14, 15, 123456, tzinfo=timezone.utc)

    def test_naive_timestamp_assumed_utc(self) -> None:
        parsed = parse_iso_timestamp("2026-01-07T03:14:15")
        assert parsed is not None
        assert parsed.tzinfo is timezone.utc

    @pytest.mark.parametrize("raw", ["", "not a time", "2026-13-45T99:00:00Z"])
    def test_garbage_returns_none(self, raw: str) -> None:
        assert parse_iso_timestamp(raw) is None
