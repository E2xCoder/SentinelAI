"""Hard limits of the tuning loop, enforced in code (not configurable)."""

from __future__ import annotations

import ipaddress
import math
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinelai.config.models import DetectionConfig, SentinelConfig, parse_suppressions
from sentinelai.core.exceptions import ConfigError
from sentinelai.tuning.models import (
    ALLOWED_KINDS,
    FORCE_SEVERITIES,
    KIND_RISK_WEIGHT,
    KIND_SUPPRESSION,
    KIND_THRESHOLD,
    MAX_RISK_WEIGHT,
    MAX_SUPPRESSION_DAYS,
    MAX_SUPPRESSIONS_PER_RULE,
    MAX_THRESHOLD_FACTOR,
    MIN_IPV4_PREFIX,
    MIN_IPV6_PREFIX,
    MIN_RISK_WEIGHT,
    MIN_THRESHOLD_FACTOR,
    THRESHOLD_SPECS,
    Proposal,
)

FORCE_SUFFIX = " [overridable with --force]"
_IPV4_MAPPED = ipaddress.IPv6Network("::ffff:0:0/96")


def rule_severity(rule_id: str) -> str | None:
    """Base severity value of a registered rule, ``None`` when unknown."""
    import sentinelai.detection.rules  # noqa: F401  (registers built-in rules)
    from sentinelai.detection.base import available_rules

    cls = available_rules().get(rule_id)
    return None if cls is None else cls.severity.value


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _single(mapping: Any, key: str) -> Any | None:
    """Value of *key* when *mapping* is a dict whose only key is *key*."""
    if isinstance(mapping, dict) and list(mapping) == [key]:
        return mapping[key]
    return None


def _check_threshold(proposal: Proposal, hard: list[str], soft: list[str]) -> None:
    spec = THRESHOLD_SPECS.get(proposal.rule_id)
    if spec is None:
        hard.append(f"rule {proposal.rule_id} has no tunable threshold")
        return
    inner = _single(proposal.patch, "detection")
    if not isinstance(inner, dict) or list(inner) != [spec.field]:
        hard.append(f'threshold patch must be exactly {{"detection": {{"{spec.field}": <int>}}}}')
        return
    value = inner[spec.field]
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        hard.append(f"detection.{spec.field} must be a positive integer")
        return
    default = int(getattr(DetectionConfig(), spec.field))
    low = math.ceil(default * MIN_THRESHOLD_FACTOR)
    high = math.floor(default * MAX_THRESHOLD_FACTOR)
    if not low <= value <= high:
        soft.append(
            f"detection.{spec.field}={value} is outside the allowed range "
            f"[{low}, {high}] (default {default})"
        )


def _check_ip_prefix(ip: str, hard: list[str]) -> None:
    try:
        network = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        hard.append(f"suppression ip is not a valid network: {ip!r}")
        return
    minimum = MIN_IPV4_PREFIX if network.version == 4 else MIN_IPV6_PREFIX
    if network.prefixlen < minimum:
        hard.append(
            f"suppression network {network} is too broad (minimum prefix /{minimum})"
        )
    if network.version == 6 and network.overlaps(_IPV4_MAPPED):
        hard.append(
            f"suppression network {network} overlaps the IPv4-mapped range {_IPV4_MAPPED}"
        )


def _check_suppression(
    proposal: Proposal, config: SentinelConfig, now: datetime, hard: list[str], soft: list[str]
) -> None:
    items = _single(_single(proposal.patch, "detection"), "suppressions")
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        hard.append(
            'suppression patch must be exactly {"detection": {"suppressions": [<one entry>]}}'
        )
        return
    entry = items[0]
    if entry.get("rule") != proposal.rule_id:
        hard.append(f"suppression rule must equal the proposal rule ({proposal.rule_id})")
        return
    try:
        parsed = parse_suppressions([entry])[0]
    except (ConfigError, ValueError, TypeError, OverflowError) as exc:
        hard.append(f"invalid suppression: {exc}")
        return

    if parsed.ip is None:
        hard.append(
            "a suppression must name a source network; "
            "a user-only scope would hide that account from every address"
        )
    else:
        _check_ip_prefix(parsed.ip, hard)
    if parsed.expires <= now:
        hard.append("suppression expiry must be in the future")
    elif parsed.expires > now + timedelta(days=MAX_SUPPRESSION_DAYS):
        hard.append(f"suppression expiry is more than {MAX_SUPPRESSION_DAYS} days away")

    try:
        existing = config.detection.parsed_suppressions()
    except (ConfigError, ValueError, TypeError, OverflowError) as exc:
        hard.append(f"existing suppressions are invalid: {exc}")
        return
    active = sum(1 for s in existing if s.rule == proposal.rule_id and s.expires > now)
    if active + 1 > MAX_SUPPRESSIONS_PER_RULE:
        hard.append(
            f"rule {proposal.rule_id} would have {active + 1} active suppressions "
            f"(maximum {MAX_SUPPRESSIONS_PER_RULE})"
        )

    severity = rule_severity(proposal.rule_id)
    if severity in FORCE_SEVERITIES:
        soft.append(
            f"{severity} rule {proposal.rule_id}: suppressing a critical rule needs --force"
        )


def _check_risk_weight(proposal: Proposal, hard: list[str], soft: list[str]) -> None:
    weights = _single(_single(proposal.patch, "risk"), "rule_weights")
    if not isinstance(weights, dict) or list(weights) != [proposal.rule_id]:
        hard.append(
            f'risk_weight patch must be exactly {{"risk": {{"rule_weights": '
            f'{{"{proposal.rule_id}": <weight>}}}}}}'
        )
        return
    weight = weights[proposal.rule_id]
    if (
        not _is_number(weight)
        or not math.isfinite(weight)
        or not MIN_RISK_WEIGHT <= weight <= MAX_RISK_WEIGHT
    ):
        hard.append(
            f"risk weight for {proposal.rule_id} must be a number between "
            f"{MIN_RISK_WEIGHT} and {MAX_RISK_WEIGHT}"
        )
    if rule_severity(proposal.rule_id) in FORCE_SEVERITIES:
        soft.append("lowering the risk weight of a critical rule needs --force")


def check_proposal(
    proposal: Proposal,
    config: SentinelConfig,
    *,
    force: bool = False,
    now: datetime | None = None,
) -> list[str]:
    """Return policy violations for *proposal* (empty list = allowed).

    Violations ending in :data:`FORCE_SUFFIX` can be waived with ``force``
    (and are then omitted); all others are never waivable.
    """
    moment = now if now is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    hard: list[str] = []
    soft: list[str] = []
    try:
        if proposal.kind not in ALLOWED_KINDS:
            hard.append(f"unknown proposal kind {proposal.kind!r}")
        if rule_severity(proposal.rule_id) is None:
            hard.append(f"unknown rule id {proposal.rule_id!r}")
        if not hard:
            if not isinstance(proposal.patch, dict):
                hard.append("patch must be a mapping")
            elif proposal.kind == KIND_THRESHOLD:
                _check_threshold(proposal, hard, soft)
            elif proposal.kind == KIND_SUPPRESSION:
                _check_suppression(proposal, config, moment, hard, soft)
            elif proposal.kind == KIND_RISK_WEIGHT:
                _check_risk_weight(proposal, hard, soft)
    except Exception as exc:  # noqa: BLE001 - policy checks must never raise
        hard.append(f"proposal could not be validated: {exc}")
    waivable = [] if force else [message + FORCE_SUFFIX for message in soft]
    return hard + waivable


__all__ = ["FORCE_SUFFIX", "check_proposal", "rule_severity"]
