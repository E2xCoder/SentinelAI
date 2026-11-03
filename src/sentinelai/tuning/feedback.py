"""Collect analyst feedback and read observed values out of alert snapshots."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sentinelai.core.store import AlertStore
from sentinelai.tuning.models import RuleFeedback, ThresholdSpec


def collect_feedback(store: AlertStore) -> dict[str, RuleFeedback]:
    """Group stored feedback by rule id (keys sorted)."""
    grouped: dict[str, RuleFeedback] = {}
    for entry in store.list_feedback():
        bucket = grouped.setdefault(entry.rule_id, RuleFeedback(rule_id=entry.rule_id))
        if entry.label == "tp":
            bucket.tp.append(entry)
        elif entry.label == "fp":
            bucket.fp.append(entry)
    return {rule_id: grouped[rule_id] for rule_id in sorted(grouped)}


def evidence_value(snapshot: Mapping[str, Any], spec: ThresholdSpec) -> int | None:
    """Observed count for *spec* from an alert snapshot, or ``None`` if unusable."""
    context = snapshot.get("context")
    if not isinstance(context, Mapping):
        return None
    value = context.get(spec.evidence)
    if spec.evidence_is_len and isinstance(value, list):
        return len(value)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return int(value)
    except (ValueError, OverflowError):
        return None
