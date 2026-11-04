"""Safe interpreter for the supported Sigma subset.

Rules are plain data (:class:`Detection`); nothing here compiles or executes
rule content. Text matching is substring/prefix/suffix plus an own-written
wildcard matcher: the pattern is split on ``*`` into segments, plain segments
use ``str.find`` (linear, C speed), segments with ``?`` use a bounded scan. The
``re`` module is never fed rule data. All event text is capped before matching
and every evaluation runs under a step budget, so a hostile rule cannot stall
the caller.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

from sentinelai.core.models import EventCategory, EventType, LogEvent

#: Wildcard patterns see the first and the last N characters of an event text.
MAX_TEXT = 8192

#: Plain (non-wildcard) tests run on the text up to this many characters.
MAX_PLAIN_TEXT = 65_536

#: Character-comparison budget shared by all value tests of one evaluation.
STEP_BUDGET = 500_000

#: A glob token: ``None`` = ``?`` (one char), ``""`` = ``*`` (any run), else one literal char.
Token = str | None
Glob = tuple[Token, ...]
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


# --------------------------------------------------------------------------- model


@dataclass(frozen=True, slots=True)
class Segment:
    """A run of literal characters and ``?`` (``None``) between two ``*``."""

    tokens: Glob
    plain: str | None  # the joined text when the segment has no ``?``


@dataclass(frozen=True, slots=True)
class ValueTest:
    """One compiled value comparison (already lower-cased)."""

    mode: str  # eq | contains | startswith | endswith | null
    literal: str | None = None  # set when the value has no wildcard
    segments: tuple[Segment, ...] = ()  # glob segments (mode already folded in) otherwise
    anchor_start: bool = False  # glob does not begin with ``*``
    anchor_end: bool = False  # glob does not end with ``*``


class StepBudgetExceededError(Exception):
    """Raised internally when one evaluation used up its step budget."""


class _Steps:
    """Mutable step counter shared by all value tests of one evaluation."""

    __slots__ = ("left",)

    def __init__(self, limit: int) -> None:
        self.left = limit

    def charge(self, cost: int) -> None:
        self.left -= cost
        if self.left < 0:
            raise StepBudgetExceededError


@dataclass(frozen=True, slots=True)
class FieldCheck:
    """One ``field|modifiers: values`` test, or a keyword test (name ``keywords``)."""

    name: str
    kind: str  # text | cidr | exists
    tests: tuple[ValueTest, ...] = ()
    require_all: bool = False
    networks: tuple[IPNetwork, ...] = ()
    expect_exists: bool = True


#: OR of AND-groups of field checks.
Selection = tuple[tuple[FieldCheck, ...], ...]


@dataclass(frozen=True, slots=True)
class Cond:
    """Condition AST node: ``sel`` | ``not`` | ``and`` | ``or`` | ``of``."""

    op: str
    name: str = ""
    children: tuple[Cond, ...] = ()
    names: tuple[str, ...] = ()
    need_all: bool = False


@dataclass(frozen=True, slots=True)
class Detection:
    """A fully compiled Sigma detection plus its logsource gates."""

    selections: dict[str, Selection]
    condition: Cond
    gates: tuple[str, ...]


# --------------------------------------------------------------------------- globbing


def glob_tokens(pattern: str) -> Glob:
    """Turn a Sigma wildcard string into glob tokens (``\\*``/``\\?`` are literals)."""
    tokens: list[Token] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt in "*?":
                tokens.append(nxt)
                i += 2
                continue
            if nxt == "\\" and i + 2 < n and pattern[i + 2] in "*?":
                tokens.append("\\")
                i += 2
                continue
        if ch == "*":
            if not tokens or tokens[-1] != "":
                tokens.append("")
        elif ch == "?":
            tokens.append(None)
        else:
            tokens.append(ch)
        i += 1
    return tuple(tokens)


def glob_match(tokens: Glob, text: str) -> bool:
    """Full-match *text* against *tokens*; iterative with star backtracking."""
    t = 0
    p = 0
    star = -1
    mark = 0
    n = len(text)
    m = len(tokens)
    while t < n:
        token = tokens[p] if p < m else False
        if token == "":
            star = p
            mark = t
            p += 1
        elif token is None or (token is not False and token == text[t]):
            p += 1
            t += 1
        elif star != -1:
            p = star + 1
            mark += 1
            t = mark
        else:
            return False
    while p < m and tokens[p] == "":
        p += 1
    return p == m


def _segment(chars: list[Token]) -> Segment:
    plain = None if None in chars else "".join(c for c in chars if c is not None)
    return Segment(tuple(chars), plain)


def _split_segments(tokens: Glob) -> tuple[tuple[Segment, ...], bool, bool]:
    """Split glob tokens on ``*`` into segments plus start/end anchoring flags."""
    segments: list[Segment] = []
    current: list[Token] = []
    for token in tokens:
        if token == "":
            if current:
                segments.append(_segment(current))
                current = []
        else:
            current.append(token)
    if current:
        segments.append(_segment(current))
    anchor_start = bool(tokens) and tokens[0] != ""
    anchor_end = bool(tokens) and tokens[-1] != ""
    return tuple(segments), anchor_start, anchor_end


def build_value_test(mode: str, text: str) -> ValueTest:
    """Compile one string value for *mode* (eq/contains/startswith/endswith)."""
    tokens = glob_tokens(text.lower())
    if all(t is not None and t != "" for t in tokens):
        return ValueTest(mode, literal="".join(t for t in tokens if t))
    if mode == "contains":
        tokens = ("", *tokens, "")
    elif mode == "startswith":
        tokens = (*tokens, "")
    elif mode == "endswith":
        tokens = ("", *tokens)
    segments, anchor_start, anchor_end = _split_segments(tokens)
    return ValueTest(mode, segments=segments, anchor_start=anchor_start, anchor_end=anchor_end)


def _seg_at(seg: Segment, text: str, start: int, steps: _Steps) -> bool:
    """True when *seg* matches *text* exactly at index *start*."""
    size = len(seg.tokens)
    steps.charge(size)
    if start < 0 or start + size > len(text):
        return False
    if seg.plain is not None:
        return text.startswith(seg.plain, start)
    for offset, token in enumerate(seg.tokens):
        if token is not None and token != text[start + offset]:
            return False
    return True


def _seg_find(seg: Segment, text: str, pos: int, steps: _Steps) -> int:
    """Leftmost index >= *pos* where *seg* matches, or ``-1``."""
    size = len(seg.tokens)
    span = len(text) - pos - size + 1
    if span <= 0:
        return -1
    if seg.plain is not None:
        # str.find runs at C speed; weight it far below a Python-level comparison.
        steps.charge(size + (span >> 6) + 1)
        return text.find(seg.plain, pos)
    for start in range(pos, pos + span):
        steps.charge(size)  # conservative upper bound of comparisons at this start
        for offset, token in enumerate(seg.tokens):
            if token is not None and token != text[start + offset]:
                break
        else:
            return start
    return -1


def _glob_run(test: ValueTest, text: str, steps: _Steps) -> bool:
    """Full-match *text* against the segmented glob (greedy leftmost, no backtracking)."""
    segments = test.segments
    if not segments:
        return True
    length = len(text)
    last = len(segments) - 1
    pos = 0
    for index, seg in enumerate(segments):
        size = len(seg.tokens)
        if index == 0 and test.anchor_start:
            if index == last and test.anchor_end:
                return length == size and _seg_at(seg, text, 0, steps)
            if not _seg_at(seg, text, 0, steps):
                return False
            pos = size
            continue
        if index == last and test.anchor_end:
            start = length - size
            return start >= pos and _seg_at(seg, text, start, steps)
        found = _seg_find(seg, text, pos, steps)
        if found < 0:
            return False
        pos = found + size
    return True


def _glob_windows(test: ValueTest, text: str) -> tuple[str, ...]:
    """Text windows a wildcard test examines (head and/or tail of long texts)."""
    if len(text) <= MAX_TEXT or (test.anchor_start and test.anchor_end):
        return (text,)
    if test.anchor_start:
        return (text[:MAX_TEXT],)
    if test.anchor_end:
        return (text[-MAX_TEXT:],)
    return (text[:MAX_TEXT], text[-MAX_TEXT:])


def _match_text(test: ValueTest, text: str, steps: _Steps) -> bool:
    literal = test.literal
    if literal is None:
        return any(_glob_run(test, window, steps) for window in _glob_windows(test, text))
    steps.charge(1 + (len(text) >> 8))
    mode = test.mode
    if mode == "eq":
        return text == literal
    if mode == "contains":
        return literal in text
    if mode == "startswith":
        return text.startswith(literal)
    return text.endswith(literal)


# --------------------------------------------------------------------------- fields

_FIELD_MAP: dict[str, str] = {
    "commandline": "command",
    "command": "command",
    "cmd": "command",
    "image": "image",
    "process.name": "image",
    "processname": "image",
    "user": "user",
    "targetuser": "user",
    "accountname": "user",
    "sourceip": "ip",
    "src_ip": "ip",
    "ipaddress": "ip",
    "clientip": "ip",
    "c-ip": "ip",
    "computer": "hostname",
    "hostname": "hostname",
    "host": "hostname",
    "message": "message",
    "msg": "message",
    "raw": "raw",
    "service": "service",
    "program": "service",
    "dst_port": "port",
    "destinationport": "port",
    "port": "port",
    "request": "path",
    "cs-uri-query": "path",
    "url": "path",
    "path": "path",
}


def canonical_field(name: str) -> str | None:
    """Map a Sigma field name onto an internal event field, or ``None`` if unavailable."""
    return _FIELD_MAP.get(name.strip().lower())


def _texts(*values: str | None) -> tuple[str, ...]:
    return tuple(v[:MAX_PLAIN_TEXT].lower() for v in values if v)


def _command(event: LogEvent) -> str | None:
    raw = event.extra.get("command")
    return raw if isinstance(raw, str) and raw else None


def _resolve(event: LogEvent, name: str) -> tuple[str, ...]:
    if name == "command":
        cmd = _command(event)
        return _texts(cmd if cmd is not None else event.message)
    if name == "image":
        cmd = _command(event)
        if cmd is None:
            return ()
        parts = cmd[:MAX_PLAIN_TEXT].split(None, 1)
        if not parts:
            return ()
        first = parts[0]
        base = first.rsplit("/", 1)[-1]
        return _texts(first) if base == first else _texts(first, base)
    if name == "user":
        return _texts(event.user)
    if name == "ip":
        return _texts(event.ip)
    if name == "hostname":
        return _texts(event.hostname)
    if name == "message":
        return _texts(event.message)
    if name == "raw":
        return _texts(event.raw)
    if name == "service":
        return _texts(event.service)
    if name == "port":
        return _texts(None if event.port is None else str(event.port))
    if name == "path":
        value = event.extra.get("path")
        return _texts(value if isinstance(value, str) and value else event.message)
    if name == "keywords":
        return _texts(event.message, event.raw)
    return ()


class _EventView:
    """Per-event cache of resolved, capped, lower-cased field texts."""

    __slots__ = ("_cache", "_event", "steps")

    def __init__(self, event: LogEvent, steps: _Steps) -> None:
        self._event = event
        self.steps = steps
        self._cache: dict[str, tuple[str, ...]] = {}

    def get(self, name: str) -> tuple[str, ...]:
        cached = self._cache.get(name)
        if cached is None:
            cached = _resolve(self._event, name)
            self._cache[name] = cached
        return cached


# --------------------------------------------------------------------------- logsource


def _svc(event: LogEvent) -> str:
    return (event.service or "").lower()


def _any_event(event: LogEvent) -> bool:
    return True


def _service_in(*names: str) -> Callable[[LogEvent], bool]:
    wanted = frozenset(names)

    def gate(event: LogEvent) -> bool:
        return _svc(event) in wanted

    return gate


_AUTH_SERVICES = frozenset({"sshd", "sshd-session", "sudo", "su", "su-l", "login", "passwd"})
_AUTH_CATEGORIES = frozenset(
    {EventCategory.AUTHENTICATION, EventCategory.SSH, EventCategory.PRIVILEGE_ESCALATION}
)


def _gate_auth(event: LogEvent) -> bool:
    svc = _svc(event)
    return svc in _AUTH_SERVICES or svc.startswith("pam") or event.category in _AUTH_CATEGORIES


def _gate_docker(event: LogEvent) -> bool:
    return event.category is EventCategory.DOCKER or _svc(event) in {
        "docker",
        "dockerd",
        "containerd",
    }


def _gate_fail2ban(event: LogEvent) -> bool:
    return _svc(event).startswith("fail2ban") or event.event_type in (
        EventType.BAN,
        EventType.UNBAN,
    )


def _gate_ufw(event: LogEvent) -> bool:
    return _svc(event) == "ufw" or event.category is EventCategory.FIREWALL


def _gate_nginx(event: LogEvent) -> bool:
    svc = _svc(event)
    return svc.startswith("nginx") or (not svc and event.category is EventCategory.WEB)


def _gate_apache(event: LogEvent) -> bool:
    svc = _svc(event)
    is_web = not svc and event.category is EventCategory.WEB
    return svc in {"apache", "apache2", "httpd"} or is_web


def _gate_process_creation(event: LogEvent) -> bool:
    return _command(event) is not None or event.event_type in (
        EventType.SUDO_COMMAND,
        EventType.CRON_JOB,
        EventType.CRON_EDIT,
    )


def _gate_webserver(event: LogEvent) -> bool:
    return event.category is EventCategory.WEB or _svc(event) in {
        "nginx",
        "apache",
        "apache2",
        "httpd",
    }


def _gate_firewall(event: LogEvent) -> bool:
    return event.category is EventCategory.FIREWALL


_SERVICE_GATES: dict[str, Callable[[LogEvent], bool]] = {
    "auth": _gate_auth,
    "secure": _gate_auth,
    "sudo": _service_in("sudo"),
    "su": _service_in("su", "su-l"),
    "sshd": _service_in("sshd", "sshd-session"),
    "cron": _service_in("cron", "crond", "crontab", "anacron"),
    "syslog": _any_event,
    "messages": _any_event,
    "daemon": _any_event,
    "kern": _any_event,
    "docker": _gate_docker,
    "nginx": _gate_nginx,
    "apache": _gate_apache,
    "fail2ban": _gate_fail2ban,
    "ufw": _gate_ufw,
}
_CATEGORY_GATES: dict[str, Callable[[LogEvent], bool]] = {
    "process_creation": _gate_process_creation,
    "webserver": _gate_webserver,
    "firewall": _gate_firewall,
}

LOGSOURCE_SERVICES = frozenset(_SERVICE_GATES)
LOGSOURCE_CATEGORIES = frozenset(_CATEGORY_GATES)


def event_in_logsource(gates: tuple[str, ...], event: LogEvent) -> bool:
    """True when *event* satisfies every ``service:x`` / ``category:y`` gate."""
    for gate in gates:
        kind, _, name = gate.partition(":")
        table = _SERVICE_GATES if kind == "service" else _CATEGORY_GATES
        check = table.get(name)
        if check is None or not check(event):
            return False
    return True


# --------------------------------------------------------------------------- evaluation


def _test_matches(test: ValueTest, candidates: tuple[str, ...], steps: _Steps) -> bool:
    if test.mode == "null":
        return not candidates
    return any(_match_text(test, text, steps) for text in candidates)


def _cidr_matches(networks: tuple[IPNetwork, ...], candidates: tuple[str, ...]) -> bool:
    for text in candidates:
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            continue
        if any(address in network for network in networks):
            return True
    return False


def _check_matches(check: FieldCheck, view: _EventView) -> bool:
    candidates = view.get(check.name)
    if check.kind == "exists":
        return bool(candidates) == check.expect_exists
    if check.kind == "cidr":
        return _cidr_matches(check.networks, candidates)
    steps = view.steps
    if check.require_all:
        return all(_test_matches(test, candidates, steps) for test in check.tests)
    return any(_test_matches(test, candidates, steps) for test in check.tests)


def _selection_matches(selection: Selection, view: _EventView) -> bool:
    return any(all(_check_matches(check, view) for check in group) for group in selection)


def _eval(
    cond: Cond,
    selections: dict[str, Selection],
    view: _EventView,
    cache: dict[str, bool],
) -> bool:
    def select(name: str) -> bool:
        result = cache.get(name)
        if result is None:
            result = _selection_matches(selections[name], view)
            cache[name] = result
        return result

    op = cond.op
    if op == "sel":
        return select(cond.name)
    if op == "not":
        return not _eval(cond.children[0], selections, view, cache)
    if op == "and":
        return all(_eval(child, selections, view, cache) for child in cond.children)
    if op == "or":
        return any(_eval(child, selections, view, cache) for child in cond.children)
    if op == "of":
        if cond.need_all:
            return all(select(name) for name in cond.names)
        return any(select(name) for name in cond.names)
    return False


#: Total steps all Sigma rules together may spend on ONE event, so a pack of
#: many hostile rules cannot multiply the per-rule budget.
EVENT_STEP_POOL = 5_000_000
_pool_event: LogEvent | None = None
_pool_left = EVENT_STEP_POOL


def evaluate_detection(
    detection: Detection, event: LogEvent, step_limit: int = STEP_BUDGET
) -> tuple[bool, bool]:
    """Return ``(matched, budget_exhausted)``; an exhausted evaluation never matches."""
    global _pool_event, _pool_left  # noqa: PLW0603 - per-event pool, single-threaded engine
    if not event_in_logsource(detection.gates, event):
        return False, False
    if _pool_event is not event:
        _pool_event, _pool_left = event, EVENT_STEP_POOL
    if _pool_left <= 0:
        return False, True
    steps = _Steps(min(step_limit, _pool_left))
    try:
        return _eval(detection.condition, detection.selections, _EventView(event, steps), {}), False
    except StepBudgetExceededError:
        return False, True
    finally:
        _pool_left -= max(0, min(step_limit, _pool_left) - max(steps.left, 0))


def matches(detection: Detection, event: LogEvent) -> bool:
    """True when *event* passes the logsource gates and the detection condition."""
    return evaluate_detection(detection, event)[0]
