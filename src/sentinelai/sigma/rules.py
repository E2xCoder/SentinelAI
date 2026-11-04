"""Sigma rules as SentinelAI detection rules, plus the safe directory loader.

Sigma files are untrusted input: size-capped, parsed with a ``yaml.SafeLoader``
subclass that rejects aliases and duplicate keys, never executed, and anything
outside the supported subset is reported (not approximated) as
:class:`Unsupported`. Load-time caps bound the files, bytes, pattern text and
reported entries.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import uuid
from collections.abc import Hashable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinelai.ai.triage import sanitize_text
from sentinelai.core.models import Alert, LogEvent, Severity
from sentinelai.detection.base import Rule, RuleContext
from sentinelai.sigma.matcher import evaluate_detection
from sentinelai.sigma.parser import ParsedRule, SigmaUnsupportedError, parse_rule

_log = logging.getLogger(__name__)

SIGMA_RULE_ID_RE = re.compile(r"^SIGMA-[0-9a-f]{8}$")

_MAX_DOCS_PER_FILE = 200
_TEXT_LIMIT = 500
_MAX_CANDIDATE_FILES = 5000
_MAX_TOTAL_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_PATTERN_CHARS = 8 * 1024 * 1024
_MAX_UNSUPPORTED = 500
_MAX_INT_LITERAL = 64

_LEVEL_SEVERITY: dict[str, Severity] = {
    "informational": Severity.INFO,
    "low": Severity.NOTICE,
    "medium": Severity.WARNING,
    "high": Severity.ERROR,
    "critical": Severity.CRITICAL,
}
_LICENSE_TEXT = "DRL 1.1 (assumed for SigmaHQ rules; check the rule file)"
_RECOMMENDATION = (
    "Review the matched event and the Sigma rule's false-positive notes; "
    "the rule is community-authored detection content."
)


def sigma_rule_id(sigma_id: str | None, title: str) -> str:
    """Stable ``SIGMA-xxxxxxxx`` id: first 8 hex chars of the Sigma UUID, else a title hash."""
    if sigma_id:
        try:
            return "SIGMA-" + uuid.UUID(sigma_id.strip()).hex[:8]
        except ValueError:
            pass
    return "SIGMA-" + hashlib.sha256(title.encode("utf-8")).hexdigest()[:8]


@dataclass(frozen=True, slots=True)
class Unsupported:
    """A Sigma rule or file that could not be loaded, with the reason."""

    path: str
    title: str
    reason: str


# --------------------------------------------------------------------------- YAML loading


class _SigmaYamlError(yaml.YAMLError):
    """A YAML construct Sigma rules do not need and we refuse to process."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _key_text(key: object) -> str:
    if isinstance(key, str):
        return sanitize_text(key[:40], 40)
    return f"<{type(key).__name__}>"


def _construct_int(loader: Any, node: Any) -> Any:
    """Reject absurdly long integer literals (big-int parsing is super-linear)."""
    if isinstance(node, yaml.ScalarNode) and len(node.value) > _MAX_INT_LITERAL:
        raise _SigmaYamlError("integer literal too long")
    return yaml.SafeLoader.construct_yaml_int(loader, node)


class _SigmaLoader(yaml.SafeLoader):
    """SafeLoader that refuses aliases (expansion bombs) and duplicate mapping keys."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):  # type: ignore[no-untyped-call]
            raise _SigmaYamlError("YAML aliases are not supported")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, Hashable):
                continue  # the base class reports unhashable keys
            if key in seen:
                raise _SigmaYamlError(f"duplicate key '{_key_text(key)}'")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


_SigmaLoader.add_constructor("tag:yaml.org,2002:int", _construct_int)


def _iter_documents(text: str) -> Iterator[object]:
    loader = _SigmaLoader(text)
    try:
        while loader.check_data():  # type: ignore[no-untyped-call]
            yield loader.get_data()  # type: ignore[no-untyped-call]
    finally:
        loader.dispose()  # type: ignore[no-untyped-call]


class SigmaRule(Rule):
    """One imported Sigma rule, interpreted by the safe matcher."""

    def __init__(self, parsed: ParsedRule, *, source_file: str = "") -> None:
        super().__init__()
        self._parsed = parsed
        self._error_logged = False
        self._budget_logged = False
        author = sanitize_text(parsed.author, _TEXT_LIMIT)
        title = sanitize_text(parsed.title, _TEXT_LIMIT)
        self.rule_id = sigma_rule_id(parsed.sigma_id, parsed.title)
        self.name = title
        self.description = sanitize_text(parsed.description, _TEXT_LIMIT)
        self.category = parsed.category
        self.severity = _LEVEL_SEVERITY.get(parsed.level, Severity.WARNING)
        self.mitre_tactics = parsed.mitre_tactics
        self.mitre_techniques = parsed.mitre_techniques
        self.recommendation = _RECOMMENDATION
        safe_id = sanitize_text(parsed.sigma_id, 64) if parsed.sigma_id else ""
        self.sigma_id: str | None = safe_id or None
        self.author = author
        self.references: tuple[str, ...] = tuple(
            sanitize_text(ref, _TEXT_LIMIT) for ref in parsed.references
        )
        self.source_file = source_file
        self.logsource_text = parsed.logsource_text

    def _alert_description(self) -> str:
        tail = (
            f'Matched Sigma rule "{self.name}" by {self.author}. '
            "Rule licensed under the Detection Rule License (DRL) 1.1 by its "
            "author(s) - see references."
        )
        return f"{self.description} {tail}" if self.description else tail

    def _warn_budget_exhausted(self) -> None:
        if not self._budget_logged:
            self._budget_logged = True
            _log.warning(
                "Sigma rule %s exceeded its evaluation step budget; treated as no match "
                "(further occurrences suppressed)",
                self.rule_id,
            )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        try:
            matched, exhausted = evaluate_detection(self._parsed.detection, event)
            if exhausted:
                self._warn_budget_exhausted()
                return None
            if not matched:
                return None
            return self.make_alert(
                event,
                title=self.name,
                description=self._alert_description(),
                severity=self.severity,
                sigma_id=self.sigma_id,
                sigma_author=self.author,
                sigma_license=_LICENSE_TEXT,
                sigma_reference=self.references[0] if self.references else None,
            )
        except Exception as exc:  # noqa: BLE001 - a rule must never break the engine
            if not self._error_logged:
                self._error_logged = True
                _log.warning(
                    "Sigma rule %s failed during evaluation (%s); further errors suppressed",
                    self.rule_id,
                    type(exc).__name__,
                )
            return None


@dataclass(slots=True)
class LoadReport:
    """Outcome of :func:`load_rules`."""

    rules: list[SigmaRule] = field(default_factory=list)
    unsupported: list[Unsupported] = field(default_factory=list)
    files_scanned: int = 0


@dataclass(slots=True)
class _LoadState:
    """Bookkeeping shared by all files of one :func:`load_rules` call."""

    seen: dict[str, str] = field(default_factory=dict)  # rule id -> source label
    pattern_chars: int = 0
    bytes_read: int = 0
    dropped: int = 0


def _add_unsupported(report: LoadReport, state: _LoadState, item: Unsupported) -> None:
    """Append *item* unless the list is full; the excess is only counted."""
    if len(report.unsupported) < _MAX_UNSUPPORTED:
        report.unsupported.append(item)
    else:
        state.dropped += 1


def _finalise_unsupported(report: LoadReport, state: _LoadState) -> None:
    """Replace the last listed entry by a summary of everything that was dropped."""
    if state.dropped and report.unsupported:
        report.unsupported[-1] = Unsupported(
            "", "", f"{state.dropped + 1} more unsupported rules not listed"
        )


def _doc_title(doc: object) -> str:
    if isinstance(doc, dict):
        raw = doc.get("title")
        if isinstance(raw, str):
            return sanitize_text(raw[:400].strip(), 200)
    return ""


def _file_size(path: Path, cap: int) -> int:
    try:
        return min(path.stat().st_size, cap + 1)
    except OSError:
        return 0


def _read_text(path: Path, max_bytes: int) -> tuple[str | None, str]:
    """Read a file safely; return ``(text, "")`` or ``(None, reason)``."""
    try:
        if path.stat().st_size > max_bytes:
            return None, "file too large"
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError:
        return None, "file could not be read"
    if len(data) > max_bytes:
        return None, "file too large"
    try:
        return data.decode("utf-8-sig"), ""
    except UnicodeDecodeError:
        return None, "file is not valid UTF-8"


def _candidate_files(root: Path, limit: int | None = None) -> list[Path]:
    """YAML files below *root*; with *limit*, stops once more than *limit* were found."""
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for filename in sorted(filenames):
            if filename.lower().endswith((".yml", ".yaml")):
                files.append(Path(dirpath) / filename)
                if limit is not None and len(files) > limit:
                    return files
    return files


def _load_documents(
    text: str,
    label: str,
    report: LoadReport,
    state: _LoadState,
    max_rules: int,
) -> bool:
    """Load every document of one file; return ``False`` once a global limit is hit."""

    def skip(path: str, title: str, reason: str) -> None:
        _add_unsupported(report, state, Unsupported(path, title, reason))

    try:
        for index, doc in enumerate(_iter_documents(text)):
            if index >= _MAX_DOCS_PER_FILE:
                skip(label, "", "too many YAML documents in file")
                break
            if doc is None:
                continue
            doc_label = label if index == 0 else f"{label}#{index + 1}"
            if len(report.rules) >= max_rules:
                skip(doc_label, "", "rule limit reached")
                return False
            try:
                parsed = parse_rule(doc)
            except SigmaUnsupportedError as exc:
                skip(doc_label, _doc_title(doc), exc.reason)
                continue
            except Exception:  # noqa: BLE001 - untrusted input must never raise
                skip(doc_label, _doc_title(doc), "rule structure could not be parsed")
                continue
            if state.pattern_chars + parsed.pattern_chars > _MAX_TOTAL_PATTERN_CHARS:
                skip(doc_label, _doc_title(doc), "pattern text limit reached")
                return False
            rule = SigmaRule(parsed, source_file=label)
            if not rule.name:
                skip(doc_label, "", "empty title")
                continue
            other = state.seen.get(rule.rule_id)
            if other is not None:
                reason = (
                    f"duplicate rule id {rule.rule_id} (also used by {sanitize_text(other, 100)})"
                )
                skip(doc_label, rule.name, reason)
                continue
            state.seen[rule.rule_id] = label
            state.pattern_chars += parsed.pattern_chars
            report.rules.append(rule)
    except _SigmaYamlError as exc:
        skip(label, "", exc.reason)
    except yaml.YAMLError:
        skip(label, "", "invalid YAML")
    except Exception:  # noqa: BLE001 - untrusted input must never raise
        skip(label, "", "YAML structure could not be parsed")
    return True


def load_rules(
    directory: Path,
    *,
    max_rules: int = 2000,
    max_file_bytes: int = 262_144,
) -> LoadReport:
    """Load Sigma rules from *directory* (recursively); never raises on bad input."""
    report = LoadReport()
    try:
        root = directory.resolve()
        if not root.is_dir():
            report.unsupported.append(Unsupported(str(directory), "", "not a directory"))
            return report
        files = _candidate_files(root, _MAX_CANDIDATE_FILES)
    except OSError:
        report.unsupported.append(Unsupported(str(directory), "", "directory could not be read"))
        return report

    truncated = len(files) > _MAX_CANDIDATE_FILES
    state = _LoadState()
    stopped = False
    for path in files[:_MAX_CANDIDATE_FILES]:
        if state.bytes_read >= _MAX_TOTAL_BYTES:
            _add_unsupported(report, state, Unsupported(".", "", "size limit reached"))
            stopped = True
            break
        try:
            resolved = path.resolve()
            label = path.relative_to(root).as_posix()
        except (OSError, ValueError, RuntimeError):
            _add_unsupported(
                report, state, Unsupported(path.name, "", "path could not be resolved")
            )
            continue
        report.files_scanned += 1
        if not resolved.is_relative_to(root) or not resolved.is_file():
            _add_unsupported(
                report, state, Unsupported(label, "", "path escapes the rules directory")
            )
            continue
        state.bytes_read += _file_size(resolved, max_file_bytes)
        text, reason = _read_text(resolved, max_file_bytes)
        if text is None:
            _add_unsupported(report, state, Unsupported(label, "", reason))
            continue
        if not _load_documents(text, label, report, state, max_rules):
            stopped = True
            break
    if truncated and not stopped:
        _add_unsupported(report, state, Unsupported(".", "", "file limit reached"))
    _finalise_unsupported(report, state)
    return report
