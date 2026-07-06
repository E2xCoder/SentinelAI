"""Shared pytest fixtures for the SentinelAI test suite."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from sentinelai.config.models import DetectionConfig, SentinelConfig
from sentinelai.core.models import EventCategory, EventType, LogEvent, Severity
from sentinelai.detection.base import RuleContext

#: Deterministic base timestamp for tests (noon UTC, a Wednesday).
BASE_TS = datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)


def make_event(
    *,
    offset: float = 0.0,
    event_type: EventType = EventType.GENERIC,
    category: EventCategory = EventCategory.SYSTEM,
    severity: Severity = Severity.INFO,
    ip: str | None = None,
    user: str | None = None,
    hostname: str = "web01",
    service: str | None = "sshd",
    port: int | None = None,
    message: str = "test event",
    base: datetime = BASE_TS,
    **extra: Any,
) -> LogEvent:
    """Build a LogEvent with sensible defaults for rule/engine tests."""
    return LogEvent(
        timestamp=base + timedelta(seconds=offset),
        message=message,
        raw=message,
        hostname=hostname,
        service=service,
        event_type=event_type,
        category=category,
        severity=severity,
        ip=ip,
        user=user,
        port=port,
        extra=dict(extra),
    )


@pytest.fixture()
def event_factory():
    """Expose :func:`make_event` as a fixture."""
    return make_event


@pytest.fixture()
def rule_ctx() -> RuleContext:
    """A fresh rule context with default detection thresholds."""
    return RuleContext(DetectionConfig())


@pytest.fixture()
def test_config(tmp_path) -> SentinelConfig:
    """A full config isolated to a temporary state directory.

    Threat intel and auto-response stay disabled so tests never touch
    the network or a firewall.
    """
    config = SentinelConfig()
    config.state_dir = str(tmp_path / "state")
    config.report.output_dir = str(tmp_path / "reports")
    config.validate()
    return config
