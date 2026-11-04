"""Property-based fuzzing of parsers, classifier, reader and the triage sanitizer.

Invariants (security-critical: every input here is attacker-controlled):

* parsers never raise and return ``None`` or a ``LogEvent`` with an aware timestamp
* ``match_score`` always stays within 0..1
* ``classify_message`` never raises
* the reader only ever raises ``LogSourceError`` and never yields over-long lines
* ``sanitize_text`` never raises, strips control characters and honours ``max_len``
"""

from __future__ import annotations

import gzip
import tempfile
import unicodedata
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sentinelai.ai.triage import sanitize_text
from sentinelai.core.exceptions import LogSourceError, ParserError
from sentinelai.core.models import LogEvent
from sentinelai.parsers import available_parsers, get_parser
from sentinelai.parsers.classify import classify_message
from sentinelai.parsers.reader import ReaderLimits, read_events, stream_lines

FUZZ = settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    database=None,
)

PARSER_NAMES = sorted(available_parsers())

# --------------------------------------------------------------------------
# Seeds: one or more valid lines per parser (taken from tests/test_parsers.py)
# --------------------------------------------------------------------------

_SYSLOG = [
    "Jan  7 03:14:05 web01 sshd[1203]: Failed password for root from 203.0.113.55 port 51004 ssh2",
    "Jan  7 03:14:20 web01 sshd[1210]: "
    "Accepted password for root from 203.0.113.55 port 51020 ssh2",
    "2026-01-07T03:14:15.123456+00:00 web01 sshd[7]: "
    "Invalid user oracle from 198.51.100.9 port 40000",
    "Jan  7 03:16:30 web01 sudo[1700]:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
    "COMMAND=/usr/bin/apt update",
    "Jan  7 03:15:30 web01 useradd[1400]: new user: name=backdoor, UID=0, GID=0, "
    "home=/home/backdoor, shell=/bin/bash",
    "Jan  7 03:16:05 web01 CRON[1600]: (root) CMD (/usr/local/bin/backup.sh)",
    "Jan  7 03:17:01 web01 systemd[1]: Stopped ufw.service.",
    "2026-01-07T12:00:05+00:00 web01 sshd[2301]: pam_faillock(sshd:auth): "
    "Consecutive login failures for user bob account temporarily locked",
]
_APACHE_ACCESS = [
    '203.0.113.9 - frank [07/Jan/2026:13:55:36 +0000] '
    '"GET /admin HTTP/1.1" 403 2326 "-" "curl/8.0"',
]
_APACHE_ERROR = [
    "[Wed Jan 07 03:14:15.123456 2026] [core:error] [pid 42:tid 7] "
    "[client 203.0.113.9:5678] File does not exist: /var/www/html/.env",
]
_NGINX_ACCESS = [
    '198.51.100.23 - - [07/Jan/2026:11:00:04 +0000] "POST /wp-login.php HTTP/1.1" 401 153 '
    '"-" "python-requests/2.31"',
]
_NGINX_ERROR = [
    '2026/01/07 03:14:15 [error] 123#123: *45 open() failed, client: 203.0.113.9, '
    'server: example.com, request: "GET /x HTTP/1.1"',
]
_DOCKER = [
    'time="2026-01-07T03:14:15.123456789Z" level=warning '
    'msg="Running privileged container abcdef123456789012"',
]
_FAIL2BAN = [
    "2026-01-07 03:14:15,123 fail2ban.actions [123]: NOTICE [sshd] Ban 203.0.113.99",
    "2026-01-07 04:14:15,123 fail2ban.actions [123]: NOTICE [sshd] Unban 203.0.113.99",
]
_UFW = [
    "Jan  7 03:14:15 web01 kernel: [1234.567] [UFW BLOCK] IN=eth0 OUT= MAC=00:11 "
    "SRC=203.0.113.5 DST=10.0.0.5 LEN=40 PROTO=TCP SPT=54321 DPT=22",
]

ALL_SEEDS = (
    _SYSLOG + _APACHE_ACCESS + _APACHE_ERROR + _NGINX_ACCESS
    + _NGINX_ERROR + _DOCKER + _FAIL2BAN + _UFW
)
SEEDS_BY_PARSER: dict[str, list[str]] = {
    "syslog": _SYSLOG,
    "apache_access": _APACHE_ACCESS,
    "apache_error": _APACHE_ERROR,
    "nginx_access": _NGINX_ACCESS,
    "nginx_error": _NGINX_ERROR,
    "docker": _DOCKER,
    "fail2ban": _FAIL2BAN,
    "ufw": _UFW,
}


def seeds_for(name: str) -> list[str]:
    """Own seeds plus every other parser's seeds (cross-format confusion)."""
    own = SEEDS_BY_PARSER.get(name, [])
    return own + [s for s in ALL_SEEDS if s not in own]


# --------------------------------------------------------------------------
# Strategies
# --------------------------------------------------------------------------

_SAFE_CHARS = st.characters(blacklist_categories=("Cs",))  # no lone surrogates
_NASTY_PIECES = [
    "\x00",
    "\x1b[31m",
    "\x1b[2J\x1b[H",
    "\x1b]0;title\x07",
    "\x1b",
    "\r",
    "\t",
    "‮",
    "﻿",
    "\u0085",
    "\\",
    '"',
    "'",
    "[",
    "]",
    " ",
    "=",
    "%s%n",
    "../../etc/passwd",
    "\U0001f4a5",
    "9" * 400,
    "A" * 2000,
    " " * 3000,
    "\t" * 1500,
    '"' * 1000,
]

arbitrary_text = st.one_of(
    st.text(alphabet=_SAFE_CHARS, max_size=400),
    st.text(max_size=400).filter(lambda s: not any("\ud800" <= c <= "\udfff" for c in s)),
    st.lists(st.sampled_from(_NASTY_PIECES), max_size=12).map("".join),
)

_edit = st.tuples(
    st.sampled_from(["insert", "delete", "replace", "truncate", "duplicate"]),
    st.integers(min_value=0, max_value=10_000),
    st.one_of(
        st.sampled_from(_NASTY_PIECES),
        st.text(alphabet=_SAFE_CHARS, max_size=8),
    ),
    st.integers(min_value=1, max_value=40),
)


def _apply_edits(seed: str, edits: list[tuple[str, int, str, int]]) -> str:
    text = seed
    for kind, pos, payload, span in edits:
        index = pos % (len(text) + 1)
        if kind == "insert":
            text = text[:index] + payload + text[index:]
        elif kind == "delete":
            text = text[:index] + text[index + span :]
        elif kind == "replace":
            text = text[:index] + payload + text[index + span :]
        elif kind == "truncate":
            text = text[:index]
        else:  # duplicate a slice (grows the line, repeats tokens)
            text = text[:index] + text[index : index + span] * 8 + text[index:]
    return text


def mutated_from(seeds: list[str]) -> st.SearchStrategy[str]:
    return st.builds(
        _apply_edits,
        st.sampled_from(seeds),
        st.lists(_edit, min_size=0, max_size=8),
    )


def _assert_event_ok(event: object) -> None:
    assert event is None or isinstance(event, LogEvent)
    if event is not None:
        assert event.timestamp.tzinfo is not None
        assert event.timestamp.utcoffset() is not None


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", PARSER_NAMES)
class TestParserFuzz:
    @FUZZ
    @given(data=st.data())
    def test_arbitrary_text_never_raises_and_timestamp_is_aware(
        self, name: str, data: st.DataObject
    ) -> None:
        text = data.draw(arbitrary_text)
        _assert_event_ok(get_parser(name).parse_line(text))

    @FUZZ
    @given(data=st.data())
    def test_mutated_seed_never_raises_and_timestamp_is_aware(
        self, name: str, data: st.DataObject
    ) -> None:
        text = data.draw(mutated_from(seeds_for(name)))
        _assert_event_ok(get_parser(name).parse_line(text))

    @FUZZ
    @given(data=st.data())
    def test_match_score_stays_between_zero_and_one(
        self, name: str, data: st.DataObject
    ) -> None:
        lines = data.draw(
            st.lists(st.one_of(arbitrary_text, mutated_from(seeds_for(name))), max_size=20)
        )
        score = get_parser(name).match_score(lines)
        assert 0.0 <= score <= 1.0

    @FUZZ
    @given(data=st.data())
    def test_parse_lines_yields_only_log_events(
        self, name: str, data: st.DataObject
    ) -> None:
        lines = data.draw(
            st.lists(st.one_of(arbitrary_text, mutated_from(seeds_for(name))), max_size=20)
        )
        events = list(get_parser(name).parse_lines(lines, source="fuzz.log"))
        assert all(isinstance(event, LogEvent) for event in events)
        assert len(events) <= len(lines)

    @pytest.mark.parametrize("seed_index", range(3))
    def test_valid_seed_unmutated_is_safe(self, name: str, seed_index: int) -> None:
        seeds = seeds_for(name)
        _assert_event_ok(get_parser(name).parse_line(seeds[seed_index % len(seeds)]))


class TestClassifyFuzz:
    @FUZZ
    @given(
        service=st.one_of(
            st.none(),
            st.sampled_from(
                ["sshd", "sudo", "su", "useradd", "passwd", "CRON", "systemd", "kernel",
                 "dpkg", "docker", "ufw", "su-l", "systemd-logind", ""]
            ),
            arbitrary_text,
        ),
        message=st.one_of(arbitrary_text, mutated_from(_SYSLOG)),
    )
    def test_classify_message_never_raises(self, service: str | None, message: str) -> None:
        result = classify_message(service, message)
        assert result is not None

    @FUZZ
    @given(
        service=st.sampled_from(["sshd", "sudo", "su", "useradd", "CRON", "systemd", "kernel"]),
        message=arbitrary_text,
    )
    def test_known_service_with_arbitrary_message_never_raises(
        self, service: str, message: str
    ) -> None:
        classify_message(service, message)


# --------------------------------------------------------------------------
# Reader
# --------------------------------------------------------------------------

_MAX_CHARS = 512
_LIMITS = ReaderLimits(max_line_chars=_MAX_CHARS)

_gzip_prefixed = st.binary(max_size=20_000).map(lambda b: b"\x1f\x8b\x08" + b)
_valid_gzip = st.binary(max_size=20_000).map(gzip.compress)
_truncated_gzip = st.tuples(_valid_gzip, st.integers(min_value=0, max_value=400)).map(
    lambda pair: pair[0][: max(0, len(pair[0]) - pair[1])]
)
_corrupt_gzip = st.tuples(
    _valid_gzip, st.integers(min_value=0, max_value=200), st.binary(min_size=1, max_size=8)
).map(lambda t: t[0][: t[1] % (len(t[0]) + 1)] + t[2] + t[0][t[1] % (len(t[0]) + 1) :])
_long_line_bytes = st.tuples(st.binary(max_size=2_000), st.integers(1, 5)).map(
    lambda t: (b"x" * 700 + b"\n") * t[1] + t[0]
)
file_payloads = st.one_of(
    st.binary(max_size=20_000),
    _gzip_prefixed,
    _valid_gzip,
    _truncated_gzip,
    _corrupt_gzip,
    _long_line_bytes,
)


def _write_tmp(directory: str, suffix: str, payload: bytes) -> Path:
    path = Path(directory) / f"fuzz{suffix}"
    path.write_bytes(payload)
    return path


class TestReaderFuzz:
    @FUZZ
    @given(payload=file_payloads, suffix=st.sampled_from([".log", ".gz"]))
    def test_stream_lines_only_raises_log_source_error_and_respects_limit(
        self, payload: bytes, suffix: str
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_tmp(tmp, suffix, payload)
            try:
                for line in stream_lines(path, _LIMITS):
                    assert len(line) <= _MAX_CHARS + 1  # +1: trailing newline
                    assert len(line.rstrip("\r\n")) <= _MAX_CHARS
            except LogSourceError:
                pass

    @FUZZ
    @given(
        payload=file_payloads,
        suffix=st.sampled_from([".log", ".gz"]),
        parser_name=st.sampled_from(PARSER_NAMES),
    )
    def test_read_events_explicit_parser_only_raises_log_source_error(
        self, payload: bytes, suffix: str, parser_name: str
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_tmp(tmp, suffix, payload)
            try:
                for event in read_events(path, parser_name=parser_name, limits=_LIMITS):
                    assert isinstance(event, LogEvent)
                    _assert_event_ok(event)
            except LogSourceError:
                pass

    @FUZZ
    @given(payload=file_payloads, suffix=st.sampled_from([".log", ".gz"]))
    def test_read_events_autodetect_only_raises_expected_domain_errors(
        self, payload: bytes, suffix: str
    ) -> None:
        # Auto-detection may legitimately say "unknown format" (ParserError).
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_tmp(tmp, suffix, payload)
            try:
                for event in read_events(path, limits=_LIMITS):
                    assert isinstance(event, LogEvent)
            except (LogSourceError, ParserError):
                pass

    @FUZZ
    @given(
        lines=st.lists(
            st.one_of(arbitrary_text.map(lambda s: s.replace("\n", " ")), mutated_from(_SYSLOG)),
            max_size=30,
        ),
        parser_name=st.sampled_from(PARSER_NAMES),
    )
    def test_text_file_roundtrip_yields_only_log_events(
        self, lines: list[str], parser_name: str
    ) -> None:
        body = "\n".join(line.replace("\r", " ") for line in lines)
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_tmp(tmp, ".log", body.encode("utf-8", errors="replace"))
            try:
                events = list(read_events(path, parser_name=parser_name, limits=_LIMITS))
            except LogSourceError:
                return
            assert all(isinstance(event, LogEvent) for event in events)


# --------------------------------------------------------------------------
# sanitize_text
# --------------------------------------------------------------------------

_arbitrary_object = st.one_of(
    st.none(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.binary(max_size=200),
    arbitrary_text,
    st.text(max_size=300),  # includes surrogates / any code point
    st.lists(arbitrary_text, max_size=5),
    st.dictionaries(st.text(max_size=5), arbitrary_text, max_size=4),
    st.just(object()),
)


class TestSanitizeTextFuzz:
    @FUZZ
    @given(value=_arbitrary_object, max_len=st.integers(min_value=0, max_value=400))
    def test_result_is_bounded_and_control_free(self, value: object, max_len: int) -> None:
        result = sanitize_text(value, max_len=max_len)
        assert isinstance(result, str)
        assert len(result) <= max_len
        assert "\n" not in result and "\r" not in result and "\t" not in result
        assert all(unicodedata.category(ch)[0] != "C" for ch in result)
        assert "\x1b" not in result and "\x00" not in result

    @FUZZ
    @given(value=_arbitrary_object)
    def test_default_max_len_is_respected(self, value: object) -> None:
        assert len(sanitize_text(value)) <= 300

    @FUZZ
    @given(value=st.lists(st.sampled_from(_NASTY_PIECES), max_size=30).map("".join))
    def test_sanitize_is_idempotent_on_its_own_output(self, value: str) -> None:
        once = sanitize_text(value, max_len=500)
        assert sanitize_text(once, max_len=500) == once

    @pytest.mark.parametrize("bad_len", [-5, 0, 1, 2, 3, 4])
    def test_tiny_or_negative_max_len_does_not_raise(self, bad_len: int) -> None:
        result = sanitize_text("hello world " * 10, max_len=bad_len)
        assert len(result) <= max(0, bad_len)
