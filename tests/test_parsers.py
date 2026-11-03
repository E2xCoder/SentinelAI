"""Tests for all eight log parsers: valid lines, malformed lines, detection."""

from __future__ import annotations

import pytest

from sentinelai.core.models import EventCategory, EventType, Severity
from sentinelai.parsers.apache import ApacheAccessParser, ApacheErrorParser
from sentinelai.parsers.base import available_parsers, detect_parser, get_parser
from sentinelai.parsers.docker import DockerParser
from sentinelai.parsers.fail2ban import Fail2BanParser
from sentinelai.parsers.nginx import NginxAccessParser, NginxErrorParser
from sentinelai.parsers.syslog import SyslogParser
from sentinelai.parsers.ufw import UFWParser

MALFORMED_LINES = [
    "",
    "   ",
    "complete garbage with no structure",
    "@@@###!!!",
    "Jan 99 99:99:99 broken",
    '{"json": "but not a log"}',
    "\x00\x01\x02 binary noise",
]


class TestSyslogParser:
    def test_ssh_failed_password(self) -> None:
        line = (
            "Jan  7 03:14:05 web01 sshd[1203]: "
            "Failed password for root from 203.0.113.55 port 51004 ssh2"
        )
        event = SyslogParser().parse_line(line)
        assert event is not None
        assert event.event_type is EventType.AUTH_FAILURE
        assert event.category is EventCategory.AUTHENTICATION
        assert event.ip == "203.0.113.55"
        assert event.user == "root"
        assert event.port == 51004
        assert event.hostname == "web01"
        assert event.pid == 1203

    def test_root_login_promoted(self) -> None:
        line = (
            "Jan  7 03:14:20 web01 sshd[1210]: "
            "Accepted password for root from 203.0.113.55 port 51020 ssh2"
        )
        event = SyslogParser().parse_line(line)
        assert event is not None
        assert event.event_type is EventType.ROOT_LOGIN
        assert event.severity is Severity.WARNING

    def test_iso_timestamp_header(self) -> None:
        line = (
            "2026-01-07T03:14:15.123456+00:00 web01 sshd[7]: "
            "Invalid user oracle from 198.51.100.9 port 40000"
        )
        event = SyslogParser().parse_line(line)
        assert event is not None
        assert event.event_type is EventType.INVALID_USER
        assert event.timestamp.year == 2026

    def test_sudo_command_extraction(self) -> None:
        line = (
            "Jan  7 03:16:30 web01 sudo[1700]:   alice : TTY=pts/0 ; "
            "PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
        )
        event = SyslogParser().parse_line(line)
        assert event is not None
        assert event.event_type is EventType.SUDO_COMMAND
        assert event.user == "alice"
        assert event.extra["command"] == "/usr/bin/apt update"
        assert event.extra["target_user"] == "root"

    def test_useradd_new_user(self) -> None:
        line = (
            "Jan  7 03:15:30 web01 useradd[1400]: "
            "new user: name=backdoor, UID=0, GID=0, home=/home/backdoor, shell=/bin/bash"
        )
        event = SyslogParser().parse_line(line)
        assert event is not None
        assert event.event_type is EventType.USER_ADDED
        assert event.user == "backdoor"
        assert event.extra["uid"] == "0"

    def test_cron_job(self) -> None:
        line = "Jan  7 03:16:05 web01 CRON[1600]: (root) CMD (/usr/local/bin/backup.sh)"
        event = SyslogParser().parse_line(line)
        assert event is not None
        assert event.event_type is EventType.CRON_JOB
        assert event.category is EventCategory.CRON
        assert event.extra["command"] == "/usr/local/bin/backup.sh"

    def test_systemd_service_stopped(self) -> None:
        event = SyslogParser().parse_line(
            "Jan  7 03:17:01 web01 systemd[1]: Stopped ufw.service."
        )
        assert event is not None
        assert event.event_type is EventType.SERVICE_STOPPED

    def test_sshd_pam_faillock_lock_is_account_locked(self) -> None:
        line = (
            "2026-01-07T12:00:05+00:00 web01 sshd[2301]: pam_faillock(sshd:auth): "
            "Consecutive login failures for user bob account temporarily locked"
        )
        event = SyslogParser().parse_line(line)
        assert event is not None
        assert event.event_type is EventType.ACCOUNT_LOCKED
        assert event.user == "bob"

    @pytest.mark.parametrize("line", MALFORMED_LINES)
    def test_malformed(self, line: str) -> None:
        assert SyslogParser().parse_line(line) is None


class TestApacheParsers:
    ACCESS = (
        '203.0.113.9 - frank [07/Jan/2026:13:55:36 +0000] '
        '"GET /admin HTTP/1.1" 403 2326 "-" "curl/8.0"'
    )
    ERROR = (
        "[Wed Jan 07 03:14:15.123456 2026] [core:error] [pid 42:tid 7] "
        "[client 203.0.113.9:5678] File does not exist: /var/www/html/.env"
    )

    def test_access_line(self) -> None:
        event = ApacheAccessParser().parse_line(self.ACCESS)
        assert event is not None
        assert event.event_type is EventType.WEB_REQUEST
        assert event.ip == "203.0.113.9"
        assert event.user == "frank"
        assert event.extra["status"] == 403
        assert event.extra["method"] == "GET"
        assert event.severity is Severity.WARNING  # 403 is auth-relevant

    def test_error_line(self) -> None:
        event = ApacheErrorParser().parse_line(self.ERROR)
        assert event is not None
        assert event.event_type is EventType.WEB_ERROR
        assert event.ip == "203.0.113.9"
        assert event.port == 5678
        assert event.severity is Severity.ERROR
        assert event.pid == 42

    @pytest.mark.parametrize("line", MALFORMED_LINES)
    def test_malformed(self, line: str) -> None:
        assert ApacheAccessParser().parse_line(line) is None
        assert ApacheErrorParser().parse_line(line) is None


class TestNginxParsers:
    ACCESS = (
        '198.51.100.23 - - [07/Jan/2026:11:00:04 +0000] '
        '"POST /wp-login.php HTTP/1.1" 401 153 "-" "python-requests/2.31"'
    )
    ERROR = (
        '2026/01/07 03:14:15 [error] 123#123: *45 open() failed, '
        'client: 203.0.113.9, server: example.com, request: "GET /x HTTP/1.1"'
    )

    def test_access_line(self) -> None:
        event = NginxAccessParser().parse_line(self.ACCESS)
        assert event is not None
        assert event.event_type is EventType.WEB_REQUEST
        assert event.extra["status"] == 401
        assert event.extra["path"] == "/wp-login.php"

    def test_error_line(self) -> None:
        event = NginxErrorParser().parse_line(self.ERROR)
        assert event is not None
        assert event.event_type is EventType.WEB_ERROR
        assert event.ip == "203.0.113.9"
        assert event.extra["method"] == "GET"

    @pytest.mark.parametrize("line", MALFORMED_LINES)
    def test_malformed(self, line: str) -> None:
        assert NginxAccessParser().parse_line(line) is None
        assert NginxErrorParser().parse_line(line) is None


class TestDockerParser:
    def test_daemon_line(self) -> None:
        line = (
            'time="2026-01-07T03:14:15.123456789Z" level=warning '
            'msg="Running privileged container abcdef123456789012"'
        )
        event = DockerParser().parse_line(line)
        assert event is not None
        assert event.event_type is EventType.CONTAINER_EVENT
        assert event.category is EventCategory.DOCKER
        assert event.severity is Severity.WARNING
        assert event.extra.get("privileged") is True

    @pytest.mark.parametrize("line", MALFORMED_LINES)
    def test_malformed(self, line: str) -> None:
        assert DockerParser().parse_line(line) is None


class TestFail2BanParser:
    def test_ban_line(self) -> None:
        line = (
            "2026-01-07 03:14:15,123 fail2ban.actions [123]: "
            "NOTICE [sshd] Ban 203.0.113.99"
        )
        event = Fail2BanParser().parse_line(line)
        assert event is not None
        assert event.event_type is EventType.BAN
        assert event.ip == "203.0.113.99"
        assert event.extra["jail"] == "sshd"

    def test_unban_line(self) -> None:
        line = (
            "2026-01-07 04:14:15,123 fail2ban.actions [123]: "
            "NOTICE [sshd] Unban 203.0.113.99"
        )
        event = Fail2BanParser().parse_line(line)
        assert event is not None
        assert event.event_type is EventType.UNBAN

    @pytest.mark.parametrize("line", MALFORMED_LINES)
    def test_malformed(self, line: str) -> None:
        assert Fail2BanParser().parse_line(line) is None


class TestUFWParser:
    LINE = (
        "Jan  7 03:14:15 web01 kernel: [1234.567] [UFW BLOCK] IN=eth0 OUT= "
        "MAC=00:11 SRC=203.0.113.5 DST=10.0.0.5 LEN=40 PROTO=TCP SPT=54321 DPT=22"
    )

    def test_block_line(self) -> None:
        event = UFWParser().parse_line(self.LINE)
        assert event is not None
        assert event.event_type is EventType.FIREWALL_BLOCK
        assert event.category is EventCategory.FIREWALL
        assert event.ip == "203.0.113.5"
        assert event.port == 22
        assert event.extra["proto"] == "TCP"

    @pytest.mark.parametrize("line", MALFORMED_LINES)
    def test_malformed(self, line: str) -> None:
        assert UFWParser().parse_line(line) is None


class TestRegistryAndDetection:
    def test_all_eight_parsers_registered(self) -> None:
        names = set(available_parsers())
        assert names == {
            "syslog", "apache_access", "apache_error", "nginx_access",
            "nginx_error", "docker", "fail2ban", "ufw",
        }

    def test_get_parser_unknown_raises(self) -> None:
        from sentinelai.core.exceptions import ParserError

        with pytest.raises(ParserError):
            get_parser("nonexistent")

    def test_detect_prefers_content(self) -> None:
        sample = [TestUFWParser.LINE] * 5
        assert detect_parser("mystery.log", sample).name == "ufw"

    def test_detect_syslog(self) -> None:
        sample = [
            "Jan  7 03:14:05 web01 sshd[1203]: "
            "Failed password for root from 203.0.113.55 port 51004 ssh2"
        ] * 5
        assert detect_parser("auth.log", sample).name == "syslog"

    def test_parse_lines_skips_malformed(self) -> None:
        parser = SyslogParser()
        lines = MALFORMED_LINES + [
            "Jan  7 03:14:05 web01 sshd[1]: Failed password for root "
            "from 203.0.113.55 port 22 ssh2"
        ]
        events = list(parser.parse_lines(lines, source="test"))
        assert len(events) == 1
        assert events[0].source == "test"
