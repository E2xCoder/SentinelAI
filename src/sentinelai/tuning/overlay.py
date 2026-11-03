"""Pure helpers for the machine-managed tuning overlay (``tuning.yaml``).

Nothing here touches the filesystem: functions parse, validate, merge and
render overlay documents, and apply a proposal patch onto a config copy.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping
from typing import Any

import yaml

from sentinelai.config.models import TUNABLE_DETECTION_FIELDS, SentinelConfig
from sentinelai.core.exceptions import ConfigError

OVERLAY_HEADER = "# Managed by `sentinel tune`. Review changes with `sentinel tune --history`.\n"

_SECTIONS = ("detection", "risk")
_THRESHOLD_FIELDS = tuple(name for name in TUNABLE_DETECTION_FIELDS if name != "suppressions")
_RULE_ID_RE = re.compile(r"[A-Z]{1,3}[0-9]{3}")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_structure(data: Any, label: str) -> None:
    """Validate section/key names and basic value shapes of an overlay or patch."""
    if not isinstance(data, Mapping):
        raise ConfigError(f"{label} must be a mapping")
    for key, section in data.items():
        if key not in _SECTIONS:
            raise ConfigError(f"{label}: unknown top-level key {key!r}; allowed: detection, risk")
        if not isinstance(section, Mapping):
            raise ConfigError(f"{label}: section {key!r} must be a mapping")
        allowed = _THRESHOLD_FIELDS + ("suppressions",) if key == "detection" else ("rule_weights",)
        for sub_key, value in section.items():
            if sub_key not in allowed:
                raise ConfigError(f"{label}: unknown key {key}.{sub_key}")
            _check_value(key, str(sub_key), value, label)


def _check_value(section: str, name: str, value: Any, label: str) -> None:
    if name == "suppressions":
        if not isinstance(value, list) or not all(isinstance(e, Mapping) for e in value):
            raise ConfigError(f"{label}: detection.suppressions must be a list of mappings")
    elif name == "rule_weights":
        if not isinstance(value, Mapping):
            raise ConfigError(f"{label}: risk.rule_weights must be a mapping")
        for rule, weight in value.items():
            if not isinstance(rule, str) or not _RULE_ID_RE.fullmatch(rule):
                raise ConfigError(f"{label}: invalid rule id {rule!r} in risk.rule_weights")
            if not _is_number(weight):
                raise ConfigError(f"{label}: risk.rule_weights[{rule}] must be a number")
    elif not _is_number(value):
        raise ConfigError(f"{label}: {section}.{name} must be a number")


def parse_overlay(text: str) -> dict[str, Any]:
    """Parse overlay YAML; empty text gives ``{}``; anything off-allowlist is rejected."""
    if not text.strip():
        return {}
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"tuning overlay is not valid YAML: {exc}") from exc
    if data is None:
        return {}
    _check_structure(data, "tuning overlay")
    return dict(data)


def render_overlay(data: Mapping[str, Any]) -> str:
    """Deterministic overlay text (LF newlines); ``""`` for an empty mapping."""
    if not data:
        return ""
    body = yaml.safe_dump(
        dict(data), sort_keys=True, default_flow_style=False, allow_unicode=True
    )
    return (OVERLAY_HEADER + body).replace("\r\n", "\n")


def _canonical(entry: Any) -> str:
    return json.dumps(entry, sort_keys=True, default=str)


def _append_unique(existing: list[Any], new_entries: list[Any]) -> None:
    """Append *new_entries* to *existing*, skipping canonical duplicates."""
    seen = {_canonical(entry) for entry in existing}
    for entry in new_entries:
        key = _canonical(entry)
        if key not in seen:
            seen.add(key)
            existing.append(copy.deepcopy(entry))


def _set_weight(weights: dict[str, Any], rule: str, weight: Any) -> None:
    if weight == 1.0:
        weights.pop(rule, None)
    else:
        weights[rule] = weight


def merge_patch(overlay: Mapping[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    """Return a new overlay with *patch* merged in (inputs are not modified)."""
    _check_structure(overlay, "tuning overlay")
    _check_structure(patch, "patch")
    result: dict[str, Any] = copy.deepcopy(dict(overlay))

    detection_patch = patch.get("detection") or {}
    if detection_patch:
        detection: dict[str, Any] = result.setdefault("detection", {})
        for name, value in detection_patch.items():
            if name == "suppressions":
                current = detection.setdefault("suppressions", [])
                _append_unique(current, list(value))
            else:
                detection[name] = value

    weights_patch = (patch.get("risk") or {}).get("rule_weights") or {}
    if weights_patch:
        risk: dict[str, Any] = result.setdefault("risk", {})
        weights: dict[str, Any] = risk.setdefault("rule_weights", {})
        for rule, weight in weights_patch.items():
            _set_weight(weights, rule, weight)

    return _prune(result)


def _prune(data: dict[str, Any]) -> dict[str, Any]:
    """Drop empty sub-dicts / empty lists so an empty result is ``{}``."""
    for section in list(data):
        body = data[section]
        for key in list(body):
            if body[key] in ({}, []):
                del body[key]
        if not body:
            del data[section]
    return data


def apply_patch(config: SentinelConfig, patch: Mapping[str, Any]) -> SentinelConfig:
    """Return a validated deep copy of *config* with *patch* applied."""
    _check_structure(patch, "patch")
    candidate = copy.deepcopy(config)

    for name, value in (patch.get("detection") or {}).items():
        if name == "suppressions":
            _append_unique(candidate.detection.suppressions, list(value))
        else:
            setattr(candidate.detection, name, value)

    for rule, weight in ((patch.get("risk") or {}).get("rule_weights") or {}).items():
        _set_weight(candidate.risk.rule_weights, rule, weight)

    candidate.validate()
    return candidate
