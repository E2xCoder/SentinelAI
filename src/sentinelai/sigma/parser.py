"""Validate and compile one untrusted Sigma document into the safe matcher model.

Anything outside the supported subset raises :class:`SigmaUnsupportedError`
with a short, precise human reason; nothing is silently approximated.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from sentinelai.core.models import EventCategory
from sentinelai.sigma.matcher import (
    LOGSOURCE_CATEGORIES,
    LOGSOURCE_SERVICES,
    Cond,
    Detection,
    FieldCheck,
    IPNetwork,
    Selection,
    ValueTest,
    build_value_test,
    canonical_field,
    glob_match,
    glob_tokens,
)

MAX_VALUES_PER_LIST = 1000
MAX_SELECTIONS = 100
MAX_CONDITION_LENGTH = 500
MAX_NESTING_DEPTH = 20
_MAX_TOTAL_VALUES = 5000
_MAX_VALUE_LENGTH = 4096
_MAX_PATTERN_LENGTH = 512
_MAX_RULE_CHARS = 65_536
_MAX_NAME_LENGTH = 100
_MAX_FIELD_KEY_LENGTH = 200
_MAX_LEVEL_LENGTH = 32
_MAX_CIDR_LENGTH = 100
_MAX_TITLE = 200
_MAX_DESCRIPTION = 2000
_MAX_TAGS = 100
_MAX_REFERENCES = 20

_LEVELS = frozenset({"informational", "low", "medium", "high", "critical"})

_UNSUPPORTED_MODIFIERS = frozenset(
    {
        "re",
        "base64",
        "base64offset",
        "windash",
        "utf16",
        "utf16le",
        "utf16be",
        "wide",
        "fieldref",
        "expand",
        "gt",
        "lt",
        "gte",
        "lte",
    }
)
_TEXT_MODIFIERS = frozenset({"contains", "startswith", "endswith"})
_PRIMARY_MODIFIERS = _TEXT_MODIFIERS | {"cidr", "exists"}

_AGGREGATION_REASON = "aggregation/temporal conditions are not supported"

_SERVICE_CATEGORY: dict[str, EventCategory] = {
    "auth": EventCategory.AUTHENTICATION,
    "secure": EventCategory.AUTHENTICATION,
    "sudo": EventCategory.PRIVILEGE_ESCALATION,
    "su": EventCategory.PRIVILEGE_ESCALATION,
    "sshd": EventCategory.SSH,
    "cron": EventCategory.CRON,
    "docker": EventCategory.DOCKER,
    "ufw": EventCategory.FIREWALL,
    "nginx": EventCategory.WEB,
    "apache": EventCategory.WEB,
    "fail2ban": EventCategory.NETWORK,
}
_CATEGORY_CATEGORY: dict[str, EventCategory] = {
    "process_creation": EventCategory.SYSTEM,
    "webserver": EventCategory.WEB,
    "firewall": EventCategory.FIREWALL,
}

_TACTICS = {
    name.lower(): name
    for name in (
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    )
}
_TECHNIQUE_TAG = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$")


class SigmaUnsupportedError(Exception):
    """Raised when a Sigma document uses something outside the supported subset."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ParsedRule:
    """Validated, compiled Sigma rule metadata plus its detection."""

    title: str
    sigma_id: str | None
    description: str
    author: str
    references: tuple[str, ...]
    level: str
    mitre_tactics: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    category: EventCategory
    logsource_text: str
    detection: Detection
    pattern_chars: int = 0


def _short(value: object, limit: int = 60) -> str:
    """Printable, length-capped form of *value*; non-strings are never stringified."""
    if not isinstance(value, str):
        return f"<{type(value).__name__}>"
    return "".join(ch if ch.isprintable() else "?" for ch in value[:limit])


class _Budget:
    """Caps on compiled values and on pattern text, so a hostile rule stays small."""

    def __init__(self) -> None:
        self.used = 0
        self.chars = 0

    def take(self, count: int = 1) -> None:
        self.used += count
        if self.used > _MAX_TOTAL_VALUES:
            raise SigmaUnsupportedError("rule exceeds the allowed total number of values")

    def take_chars(self, count: int) -> None:
        self.chars += count
        if self.chars > _MAX_RULE_CHARS:
            raise SigmaUnsupportedError("rule exceeds the allowed total pattern text size")


# --------------------------------------------------------------------------- metadata


def _scalar_text(value: object, limit: int) -> str:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value).strip()[:limit]
    return ""


def _str_list(value: object, limit: int, max_items: int) -> tuple[str, ...]:
    items: list[object]
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, list):
        items = list(value[:max_items])
    else:
        return ()
    out = [item.strip()[:limit] for item in items if isinstance(item, str) and item.strip()]
    return tuple(out[:max_items])


def _title(doc: dict[Any, Any]) -> str:
    raw = doc.get("title")
    if raw is None:
        raise SigmaUnsupportedError("missing required field 'title'")
    if not isinstance(raw, str) or not raw.strip():
        raise SigmaUnsupportedError("'title' must be a non-empty string")
    return raw.strip()[:_MAX_TITLE]


def _level(doc: dict[Any, Any]) -> str:
    raw = doc.get("level")
    if raw is None:
        return "medium"
    if not isinstance(raw, str) or len(raw) > _MAX_LEVEL_LENGTH:
        raise SigmaUnsupportedError(f"unsupported level '{_short(raw)}'")
    level = raw.strip().lower()
    if level not in _LEVELS:
        raise SigmaUnsupportedError(f"unsupported level '{_short(raw)}'")
    return level


def _sigma_id(doc: dict[Any, Any]) -> str | None:
    raw = doc.get("id")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()[:64]
    return None


def _mitre(tags: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    tactics: list[str] = []
    techniques: list[str] = []
    for tag in tags:
        low = tag.lower()
        if len(low) > 40:
            continue
        match = _TECHNIQUE_TAG.match(low)
        if match:
            technique = f"T{match.group(1)}" + (f".{match.group(2)}" if match.group(2) else "")
            if technique not in techniques:
                techniques.append(technique)
        elif low.startswith("attack."):
            tactic = _TACTICS.get(low[len("attack.") :].replace("_", " "))
            if tactic and tactic not in tactics:
                tactics.append(tactic)
    return tuple(tactics), tuple(techniques)


# --------------------------------------------------------------------------- logsource


def _logsource_value(raw: dict[Any, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise SigmaUnsupportedError(f"logsource {key} must be a single string")
    return value.strip().lower()


def _compile_logsource(raw: object) -> tuple[tuple[str, ...], EventCategory, str]:
    if not isinstance(raw, dict):
        raise SigmaUnsupportedError("logsource is missing or not a mapping")
    product = _logsource_value(raw, "product")
    if product is not None and product != "linux":
        raise SigmaUnsupportedError(f"logsource product '{_short(product)}' is not supported")
    service = _logsource_value(raw, "service")
    category = _logsource_value(raw, "category")
    gates: list[str] = []
    parts: list[str] = []
    if product is not None:
        parts.append(f"product={product}")
    sigma_category = EventCategory.SYSTEM
    if service is not None:
        if service not in LOGSOURCE_SERVICES:
            raise SigmaUnsupportedError(
                f"no SentinelAI parser for logsource service {_short(service)}"
            )
        gates.append(f"service:{service}")
        parts.append(f"service={service}")
        sigma_category = _SERVICE_CATEGORY.get(service, sigma_category)
    if category is not None:
        if category not in LOGSOURCE_CATEGORIES:
            raise SigmaUnsupportedError(f"logsource category '{_short(category)}' is not supported")
        gates.append(f"category:{category}")
        parts.append(f"category={category}")
        if service is None:
            sigma_category = _CATEGORY_CATEGORY.get(category, sigma_category)
    return tuple(gates), sigma_category, " ".join(parts)


# --------------------------------------------------------------------------- selections


def _scalar_to_text(value: object) -> str | None:
    """Text form of a scalar value; ``None`` for non-scalars."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return None


def _value_list(value: object, budget: _Budget) -> list[object]:
    if isinstance(value, list):
        if not value:
            raise SigmaUnsupportedError("empty value list is not supported")
        if len(value) > MAX_VALUES_PER_LIST:
            raise SigmaUnsupportedError(f"value list longer than {MAX_VALUES_PER_LIST} entries")
        budget.take(len(value))
        return list(value)
    budget.take()
    return [value]


def _parse_modifiers(parts: list[str]) -> tuple[str | None, bool]:
    primary: str | None = None
    require_all = False
    for raw in parts:
        mod = raw.strip().lower()
        if mod in _UNSUPPORTED_MODIFIERS:
            raise SigmaUnsupportedError(f"field modifier '{mod}' is not supported")
        if mod == "all":
            require_all = True
        elif mod in _PRIMARY_MODIFIERS:
            if primary is not None:
                raise SigmaUnsupportedError("multiple value modifiers are not supported")
            primary = mod
        else:
            raise SigmaUnsupportedError(f"field modifier '{_short(mod)}' is not supported")
    return primary, require_all


def _compile_cidr(name: str, value: object, budget: _Budget) -> FieldCheck:
    networks: list[IPNetwork] = []
    for item in _value_list(value, budget):
        if not isinstance(item, str) or len(item) > _MAX_CIDR_LENGTH:
            raise SigmaUnsupportedError("cidr values must be short strings")
        budget.take_chars(len(item))
        try:
            networks.append(ipaddress.ip_network(item.strip(), strict=False))
        except ValueError:
            raise SigmaUnsupportedError("invalid CIDR value") from None
    return FieldCheck(name, "cidr", networks=tuple(networks))


def _compile_value(mode: str, text: str, budget: _Budget) -> ValueTest:
    """Validate and compile one string value; enforces length and text budgets."""
    if not text:
        raise SigmaUnsupportedError("empty value would match every event")
    if len(text) > _MAX_VALUE_LENGTH:
        raise SigmaUnsupportedError(f"value longer than {_MAX_VALUE_LENGTH} characters")
    budget.take_chars(len(text))
    test = build_value_test(mode, text)
    if test.literal is None and len(text) > _MAX_PATTERN_LENGTH:
        raise SigmaUnsupportedError("pattern too long")
    return test


def _compile_text(
    name: str, mode: str, require_all: bool, value: object, budget: _Budget
) -> FieldCheck:
    tests: list[ValueTest] = []
    for item in _value_list(value, budget):
        if item is None:
            if mode != "eq":
                raise SigmaUnsupportedError("null value cannot be combined with a modifier")
            tests.append(ValueTest("null"))
            continue
        text = _scalar_to_text(item)
        if text is None:
            raise SigmaUnsupportedError("nested or non-scalar field values are not supported")
        tests.append(_compile_value(mode, text, budget))
    return FieldCheck(name, "text", tests=tuple(tests), require_all=require_all)


def _compile_field(key: object, value: object, budget: _Budget) -> FieldCheck:
    if not isinstance(key, str):
        raise SigmaUnsupportedError("field names must be strings")
    if len(key) > _MAX_FIELD_KEY_LENGTH:
        raise SigmaUnsupportedError("field name too long")
    parts = key.split("|")
    sigma_name = parts[0].strip()
    name = canonical_field(sigma_name)
    if name is None:
        raise SigmaUnsupportedError(
            f"field {_short(sigma_name)} is not available in SentinelAI events"
        )
    primary, require_all = _parse_modifiers(parts[1:])
    if primary == "exists":
        if require_all:
            raise SigmaUnsupportedError("modifier 'all' cannot be combined with 'exists'")
        if not isinstance(value, bool):
            raise SigmaUnsupportedError("modifier 'exists' needs a true/false value")
        budget.take()
        return FieldCheck(name, "exists", expect_exists=value)
    if primary == "cidr":
        if require_all:
            raise SigmaUnsupportedError("modifier 'all' cannot be combined with 'cidr'")
        return _compile_cidr(name, value, budget)
    return _compile_text(name, primary or "eq", require_all, value, budget)


def _compile_mapping(mapping: dict[Any, Any], budget: _Budget) -> tuple[FieldCheck, ...]:
    if not mapping:
        raise SigmaUnsupportedError("empty selection is not supported")
    return tuple(_compile_field(key, value, budget) for key, value in mapping.items())


def _compile_keyword(item: object, budget: _Budget) -> tuple[FieldCheck, ...]:
    if isinstance(item, bool) or item is None or not isinstance(item, (str, int, float)):
        raise SigmaUnsupportedError("keyword entries must be strings")
    text = str(item)
    budget.take()
    test = _compile_value("contains", text, budget)
    return (FieldCheck("keywords", "text", tests=(test,)),)


def _compile_selection(value: object, budget: _Budget) -> Selection:
    if isinstance(value, dict):
        return (_compile_mapping(value, budget),)
    if isinstance(value, list):
        if not value:
            raise SigmaUnsupportedError("empty selection is not supported")
        if len(value) > MAX_VALUES_PER_LIST:
            raise SigmaUnsupportedError(f"list longer than {MAX_VALUES_PER_LIST} entries")
        mappings = [isinstance(item, dict) for item in value]
        if all(mappings):
            return tuple(_compile_mapping(item, budget) for item in value)
        if not any(mappings):
            return tuple(_compile_keyword(item, budget) for item in value)
        raise SigmaUnsupportedError("selection mixes keyword strings and field mappings")
    raise SigmaUnsupportedError("selection must be a mapping or a list")


# --------------------------------------------------------------------------- condition


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    for ch in text:
        if ch.isspace() or ch in "()":
            if current:
                tokens.append("".join(current))
                current = []
            if ch in "()":
                tokens.append(ch)
        else:
            current.append(ch)
    if current:
        tokens.append("".join(current))
    return tokens


class _ConditionParser:
    """Recursive-descent parser for the Sigma condition grammar (depth-capped)."""

    def __init__(self, tokens: list[str], names: list[str]) -> None:
        self._tokens = tokens
        self._names = names
        self._pos = 0
        self._depth = 0

    def parse(self) -> Cond:
        if not self._tokens:
            raise SigmaUnsupportedError("empty condition")
        node = self._or()
        if self._pos != len(self._tokens):
            raise SigmaUnsupportedError(
                f"unexpected '{_short(self._tokens[self._pos])}' in condition"
            )
        return node

    def _peek_is(self, word: str) -> bool:
        return self._pos < len(self._tokens) and self._tokens[self._pos].lower() == word

    def _next(self) -> str:
        if self._pos >= len(self._tokens):
            raise SigmaUnsupportedError("unexpected end of condition")
        token = self._tokens[self._pos]
        self._pos += 1
        return token

    def _descend(self) -> None:
        self._depth += 1
        if self._depth > MAX_NESTING_DEPTH:
            raise SigmaUnsupportedError(f"condition nesting deeper than {MAX_NESTING_DEPTH}")

    def _or(self) -> Cond:
        parts = [self._and()]
        while self._peek_is("or"):
            self._pos += 1
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else Cond("or", children=tuple(parts))

    def _and(self) -> Cond:
        parts = [self._not()]
        while self._peek_is("and"):
            self._pos += 1
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else Cond("and", children=tuple(parts))

    def _not(self) -> Cond:
        if self._peek_is("not"):
            self._pos += 1
            self._descend()
            child = self._not()
            self._depth -= 1
            return Cond("not", children=(child,))
        return self._atom()

    def _atom(self) -> Cond:
        token = self._next()
        if token == "(":
            self._descend()
            inner = self._or()
            if self._next() != ")":
                raise SigmaUnsupportedError("unbalanced parentheses in condition")
            self._depth -= 1
            return inner
        low = token.lower()
        if token == ")" or low in ("and", "or", "not", "of", "them"):
            raise SigmaUnsupportedError(f"unexpected '{_short(token)}' in condition")
        if self._peek_is("of") and (low in ("all", "any") or (token.isascii() and token.isdigit())):
            if token.isdigit() and token != "1":
                raise SigmaUnsupportedError(f"quantifier '{token} of' is not supported")
            self._pos += 1
            names = self._targets(self._next())
            return Cond("of", names=names, need_all=low == "all")
        if token not in self._names:
            raise SigmaUnsupportedError(
                f"condition references undefined selection '{_short(token)}'"
            )
        return Cond("sel", name=token)

    def _targets(self, target: str) -> tuple[str, ...]:
        if target.lower() == "them":
            names = tuple(n for n in self._names if not n.startswith("_"))
        else:
            pattern = glob_tokens(target)
            names = tuple(n for n in self._names if glob_match(pattern, n))
        if not names:
            raise SigmaUnsupportedError(f"pattern '{_short(target)}' matches no selection")
        return names


def _compile_detection(raw: object, gates: tuple[str, ...]) -> tuple[Detection, int]:
    """Compile the detection; also return the pattern characters it consumed."""
    if not isinstance(raw, dict):
        raise SigmaUnsupportedError("detection is missing or not a mapping")
    if "timeframe" in raw:
        raise SigmaUnsupportedError(_AGGREGATION_REASON)
    condition = raw.get("condition")
    if condition is None:
        raise SigmaUnsupportedError("detection has no condition")
    if isinstance(condition, list):
        raise SigmaUnsupportedError("multiple conditions are not supported")
    if not isinstance(condition, str):
        raise SigmaUnsupportedError("condition must be a string")
    if len(condition) > MAX_CONDITION_LENGTH:
        raise SigmaUnsupportedError(f"condition longer than {MAX_CONDITION_LENGTH} characters")
    if "|" in condition:
        raise SigmaUnsupportedError(_AGGREGATION_REASON)
    keys = [key for key in raw if key != "condition"]
    if not keys:
        raise SigmaUnsupportedError("detection has no selections")
    if len(keys) > MAX_SELECTIONS:
        raise SigmaUnsupportedError(f"more than {MAX_SELECTIONS} selections")
    budget = _Budget()
    selections: dict[str, Selection] = {}
    for key in keys:
        if not isinstance(key, str) or len(key) > _MAX_NAME_LENGTH:
            raise SigmaUnsupportedError(
                f"selection names must be strings of at most {_MAX_NAME_LENGTH} characters"
            )
        selections[key] = _compile_selection(raw[key], budget)
    node = _ConditionParser(_tokenize(condition), list(selections)).parse()
    return Detection(selections=selections, condition=node, gates=gates), budget.chars


# --------------------------------------------------------------------------- entry point


def parse_rule(doc: object) -> ParsedRule:
    """Compile one Sigma document, or raise :class:`SigmaUnsupportedError`."""
    if not isinstance(doc, dict):
        raise SigmaUnsupportedError("document is not a mapping")
    if "action" in doc:
        raise SigmaUnsupportedError("Sigma collection documents (action) are not supported")
    if "correlation" in doc:
        raise SigmaUnsupportedError("Sigma correlation rules are not supported")
    if "filter" in doc:
        raise SigmaUnsupportedError("Sigma filter documents are not supported")
    title = _title(doc)
    level = _level(doc)
    gates, category, logsource_text = _compile_logsource(doc.get("logsource"))
    detection, pattern_chars = _compile_detection(doc.get("detection"), gates)
    tags = _str_list(doc.get("tags"), 100, _MAX_TAGS)
    tactics, techniques = _mitre(tags)
    return ParsedRule(
        title=title,
        sigma_id=_sigma_id(doc),
        description=_scalar_text(doc.get("description"), _MAX_DESCRIPTION),
        author=_scalar_text(doc.get("author"), 200) or "unknown",
        references=_str_list(doc.get("references"), 300, _MAX_REFERENCES),
        level=level,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        category=category,
        logsource_text=logsource_text,
        detection=detection,
        pattern_chars=pattern_chars,
    )
