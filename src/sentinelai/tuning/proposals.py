"""Deterministic generation of tuning proposals from analyst feedback.

Proposals are only *suggestions*: nothing here touches the configuration.
Every proposal is later checked by the policy and the gate before
``sentinel tune --apply`` may write it to the overlay.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import yaml

from sentinelai.config.models import DetectionConfig, SentinelConfig
from sentinelai.core.store import FeedbackEntry
from sentinelai.tuning.feedback import evidence_value
from sentinelai.tuning.models import (
    DEFAULT_RISK_WEIGHT_STEP,
    DEFAULT_SUPPRESSION_DAYS,
    KIND_RISK_WEIGHT,
    KIND_SUPPRESSION,
    KIND_THRESHOLD,
    MAX_THRESHOLD_FACTOR,
    MIN_FALSE_POSITIVES,
    MIN_FP_RATIO,
    MIN_LABELLED_PER_RULE,
    MIN_RISK_WEIGHT,
    THRESHOLD_SPECS,
    Proposal,
    RuleFeedback,
    ThresholdSpec,
)

_YAML_HEADER = "# Proposed changes - nothing is applied until you run: sentinel tune --apply\n"

_EVIDENCE_UNITS: dict[str, str] = {
    "attempts": "attempts",
    "distinct_users": "distinct users",
    "distinct_ports": "distinct ports",
}

_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def generate_proposals(
    feedback: Mapping[str, RuleFeedback],
    config: SentinelConfig,
    *,
    now: datetime | None = None,
) -> list[Proposal]:
    """Return reviewable proposals for rules with enough false-positive feedback."""
    moment = now if now is not None else datetime.now(timezone.utc)
    proposals: list[Proposal] = []
    for rule_id in sorted(feedback):
        fb = feedback[rule_id]
        if not _qualifies(fb):
            continue
        # A threshold change and a narrow suppression are offered side by
        # side: the gate may reject the threshold (it can cost real recall on
        # the frozen benchmark) while the suppression is still safe.
        made = False
        threshold = _threshold_proposal(rule_id, fb, config)
        if threshold is not None:
            proposals.append(threshold)
            made = True
        suppression = _suppression_proposal(rule_id, fb, moment)
        if suppression is not None:
            proposals.append(suppression)
            made = True
        if made:
            continue
        weight = _risk_weight_proposal(rule_id, fb, config)
        if weight is not None:
            proposals.append(weight)
    return proposals


def proposals_to_yaml(proposals: Sequence[Proposal]) -> str:
    """Render proposals as a human-reviewable YAML document."""
    items: list[dict[str, Any]] = [
        {
            "id": p.id,
            "kind": p.kind,
            "rule": p.rule_id,
            "rationale": p.rationale,
            "evidence_alerts": list(p.evidence_alert_ids),
            "patch": p.patch,
        }
        for p in proposals
    ]
    body = yaml.safe_dump(items, sort_keys=False, allow_unicode=True)
    return _YAML_HEADER + body


# -- helpers ----------------------------------------------------------------


def _qualifies(fb: RuleFeedback) -> bool:
    return (
        fb.total >= MIN_LABELLED_PER_RULE
        and len(fb.fp) >= MIN_FALSE_POSITIVES
        and fb.fp_ratio >= MIN_FP_RATIO
    )


def _make_proposal(
    kind: str,
    rule_id: str,
    patch: dict[str, Any],
    rationale: str,
    fp: Sequence[FeedbackEntry],
) -> Proposal:
    digest = hashlib.sha256(
        json.dumps([kind, rule_id, patch], sort_keys=True).encode("utf-8")
    ).hexdigest()
    return Proposal(
        id="P" + digest[:8],
        kind=kind,
        rule_id=rule_id,
        patch=patch,
        rationale=rationale,
        evidence_alert_ids=tuple(sorted(entry.alert_id for entry in fp)),
    )


def _fp_summary(rule_id: str, fb: RuleFeedback) -> str:
    return f"{len(fb.fp)} of {fb.total} labelled {rule_id} alerts were false positives"


# -- threshold --------------------------------------------------------------


def _values(entries: Sequence[FeedbackEntry], spec: ThresholdSpec) -> list[int]:
    found: list[int] = []
    for entry in entries:
        value = evidence_value(entry.snapshot, spec)
        if value is not None:
            found.append(value)
    return found


def _threshold_proposal(
    rule_id: str, fb: RuleFeedback, config: SentinelConfig
) -> Proposal | None:
    spec = THRESHOLD_SPECS.get(rule_id)
    if spec is None:
        return None
    fp_values = _values(fb.fp, spec)
    if not fp_values:
        return None
    tp_values = _values(fb.tp, spec)
    fp_max = max(fp_values)
    tp_min = min(tp_values) if tp_values else None

    current = int(getattr(config.detection, spec.field))
    default = int(getattr(DetectionConfig(), spec.field))
    new = fp_max + 1
    if new <= current:
        return None
    if tp_min is not None and new > tp_min:
        return None
    if new > int(default * MAX_THRESHOLD_FACTOR):
        return None

    unit = _EVIDENCE_UNITS.get(spec.evidence, "events")
    rationale = f"{_fp_summary(rule_id, fb)}; the largest false positive involved {fp_max} {unit}"
    if tp_min is not None:
        rationale += (
            f" while every true positive involved {tp_min} or more, "
            f"so raising the threshold from {current} to {new} separates them."
        )
    else:
        rationale += (
            f" and no true positive was recorded, so raising the threshold from "
            f"{current} to {new} removes them."
        )
    return _make_proposal(
        KIND_THRESHOLD,
        rule_id,
        {"detection": {spec.field: new}},
        rationale,
        fb.fp,
    )


# -- suppression ------------------------------------------------------------


def _parse_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _common_user(entries: Sequence[FeedbackEntry]) -> str | None:
    users = {entry.snapshot.get("user") for entry in entries}
    if len(users) != 1:
        return None
    user = next(iter(users))
    return user if isinstance(user, str) and user else None


def _common_network(entries: Sequence[FeedbackEntry]) -> _IPNetwork | None:
    addresses = [_parse_ip(entry.snapshot.get("ip")) for entry in entries]
    parsed = [addr for addr in addresses if addr is not None]
    if not parsed or len(parsed) != len(addresses):
        return None
    first = parsed[0]
    if all(addr == first for addr in parsed):
        return ipaddress.ip_network(f"{first}/{first.max_prefixlen}")
    if not all(isinstance(addr, ipaddress.IPv4Address) for addr in parsed):
        return None
    network = ipaddress.ip_network(f"{first}/24", strict=False)
    if all(addr in network for addr in parsed):
        return network
    return None


def _matches_scope(entry: FeedbackEntry, user: str | None, network: _IPNetwork | None) -> bool:
    if user is not None and entry.snapshot.get("user") != user:
        return False
    if network is not None:
        address = _parse_ip(entry.snapshot.get("ip"))
        if address is None or address not in network:
            return False
    return True


def _suppression_proposal(
    rule_id: str, fb: RuleFeedback, now: datetime
) -> Proposal | None:
    user = _common_user(fb.fp)
    network = _common_network(fb.fp)
    if network is None:
        # A user-only scope would hide that account from every address.
        return None
    if any(_matches_scope(entry, user, network) for entry in fb.tp):
        return None

    entry: dict[str, Any] = {"rule": rule_id}
    scope: list[str] = []
    if user is not None:
        entry["user"] = user
        scope.append(f"user {user}")
    if network is not None:
        entry["ip"] = str(network)
        scope.append(f"source {network}")
    entry["expires"] = (now + timedelta(days=DEFAULT_SUPPRESSION_DAYS)).date().isoformat()
    entry["note"] = f"analyst feedback: {len(fb.fp)} false positives"

    rationale = (
        f"{_fp_summary(rule_id, fb)}, all from {' and '.join(scope)}, "
        f"and no true positive matched that scope, so a {DEFAULT_SUPPRESSION_DAYS}-day "
        "suppression is proposed."
    )
    return _make_proposal(
        KIND_SUPPRESSION,
        rule_id,
        {"detection": {"suppressions": [entry]}},
        rationale,
        fb.fp,
    )


# -- risk weight ------------------------------------------------------------


def _risk_weight_proposal(
    rule_id: str, fb: RuleFeedback, config: SentinelConfig
) -> Proposal | None:
    current = float(config.risk.rule_weights.get(rule_id, 1.0))
    new = max(MIN_RISK_WEIGHT, round(current * DEFAULT_RISK_WEIGHT_STEP, 2))
    if new >= current:
        return None
    rationale = (
        f"{_fp_summary(rule_id, fb)} without a narrow scope or a separable threshold, "
        f"so lowering its risk weight from {current:g} to {new:g} is proposed."
    )
    return _make_proposal(
        KIND_RISK_WEIGHT,
        rule_id,
        {"risk": {"rule_weights": {rule_id: new}}},
        rationale,
        fb.fp,
    )
