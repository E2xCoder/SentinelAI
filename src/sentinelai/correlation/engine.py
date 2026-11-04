"""Alert correlation: entity + time-window linking into scored incidents.

Two alerts are linked when they share a non-empty entity value (ip, user
or host) and their ``[first_seen, last_seen]`` intervals are at most
``window_seconds`` apart. Linking is done per entity bucket with a running
"latest end" pointer, so the cost is O(n log n + n*k) instead of O(n^2).
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sentinelai.config.models import CorrelationConfig
from sentinelai.core.models import Alert, Incident, RiskLevel, TimelineEntry
from sentinelai.correlation.killchain import chain_bonus, primary_tactic, stage_index
from sentinelai.correlation.summary import as_utc, build_summary, build_title

_LINK_ATTR = {"ip": "ip", "user": "user", "host": "hostname", "hostname": "hostname"}


@dataclass(slots=True)
class _Node:
    """Alert plus pre-computed, normalised timing and risk."""

    alert: Alert
    seq: int
    start: datetime
    end: datetime
    s: float
    e: float
    score: float
    level: RiskLevel


class _UnionFind:
    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, item: int) -> int:
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Keep the smaller index as root for deterministic components.
            if ra < rb:
                self._parent[rb] = ra
            else:
                self._parent[ra] = rb


def _norm(value: object) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def _opt(value: object) -> str | None:
    text = value.strip() if isinstance(value, str) else ""
    return text or None


def _score_level(alert: Alert) -> tuple[float, RiskLevel]:
    risk = getattr(alert, "risk", None)
    raw = getattr(risk, "score", 0.0)
    try:
        score = float(raw)
    except (TypeError, ValueError):
        score = 0.0
    if not math.isfinite(score):
        score = 0.0
    score = min(100.0, max(0.0, score))
    level = getattr(risk, "level", None)
    return score, level if isinstance(level, RiskLevel) else RiskLevel.from_score(score)


def _prepare(alert: Alert, seq: int) -> _Node:
    start = as_utc(alert.first_seen)
    end = max(start, as_utc(alert.last_seen))
    score, level = _score_level(alert)
    return _Node(alert, seq, start, end, start.timestamp(), end.timestamp(), score, level)


def _order_key(node: _Node) -> tuple[float, str, int, int]:
    alert = node.alert
    ident = alert.id if isinstance(alert.id, int) else -1
    return (node.s, str(alert.rule_id), ident, node.seq)


def _entity_keys(alert: Alert, link_by: Sequence[str]) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    for name in link_by:
        attr = _LINK_ATTR.get(str(name).strip().lower())
        if attr is None:
            continue
        value = _norm(getattr(alert, attr, None))
        if value and (attr, value) not in keys:
            keys.append((attr, value))
    return keys


def _link(nodes: list[_Node], config: CorrelationConfig) -> _UnionFind:
    uf = _UnionFind(len(nodes))
    window = max(0.0, float(config.window_seconds))
    buckets: dict[tuple[str, str], list[int]] = {}
    for idx, node in enumerate(nodes):  # nodes are time-sorted, so buckets are too
        for key in _entity_keys(node.alert, config.link_by):
            buckets.setdefault(key, []).append(idx)
    for members in buckets.values():
        if len(members) < 2:
            continue
        best = members[0]
        best_end = nodes[best].e
        for idx in members[1:]:
            node = nodes[idx]
            # Any earlier alert in range is itself linked to the max-end holder.
            if node.s - best_end <= window:
                uf.union(best, idx)
            if node.e > best_end:
                best, best_end = idx, node.e
    return uf


def _unique_sorted(values: Sequence[object]) -> list[str]:
    return sorted({text for v in values if (text := _opt(v)) is not None})


def _build_timeline(members: list[_Node]) -> list[TimelineEntry]:
    groups: dict[tuple[str, str, str, str], list[_Node]] = {}
    for node in members:
        a = node.alert
        key = (str(a.rule_id), _norm(a.ip), _norm(a.user), _norm(a.hostname))
        groups.setdefault(key, []).append(node)
    keyed: list[tuple[tuple[float, int, str], TimelineEntry]] = []
    for group in groups.values():
        first = group[0]
        top = max(group, key=lambda n: n.score)  # first wins ties
        tactic = primary_tactic(top.alert)
        entry = TimelineEntry(
            timestamp=first.start,
            alert_id=first.alert.id if isinstance(first.alert.id, int) else 0,
            rule_id=str(first.alert.rule_id),
            title=str(first.alert.title),
            tactic=tactic,
            risk_level=top.level,
            risk_score=top.score,
            count=len(group),
            ip=_opt(first.alert.ip),
            user=_opt(first.alert.user),
            host=_opt(first.alert.hostname),
        )
        keyed.append(((first.s, stage_index(tactic), entry.rule_id), entry))
    keyed.sort(key=lambda item: item[0])
    return [entry for _key, entry in keyed]


def _stages(timeline: Sequence[TimelineEntry]) -> list[str]:
    stages: list[str] = []
    for entry in timeline:
        if stage_index(entry.tactic) >= 0 and entry.tactic not in stages:
            stages.append(entry.tactic)
    return stages


def _build_incident(members: list[_Node], config: CorrelationConfig) -> Incident:
    timeline = _build_timeline(members)
    stages = _stages(timeline)
    bonus = chain_bonus(stages, config.stage_bonus, config.max_bonus)
    score = round(min(100.0, max(n.score for n in members) + bonus), 1)
    level = RiskLevel.from_score(score)
    first_seen = min(n.start for n in members)
    last_seen = max(n.end for n in members)
    alerts = [n.alert for n in members]
    ips = _unique_sorted([a.ip for a in alerts])
    users = _unique_sorted([a.user for a in alerts])
    hosts = _unique_sorted([a.hostname for a in alerts])
    rule_ids: list[str] = []
    for entry in timeline:
        if entry.rule_id not in rule_ids:
            rule_ids.append(entry.rule_id)
    techniques = _unique_sorted([t for a in alerts for t in (a.mitre_techniques or [])])
    return Incident(
        title=build_title(
            stages=stages, ips=ips, users=users, hosts=hosts, alert_count=len(members)
        ),
        summary=build_summary(
            first_seen=first_seen,
            last_seen=last_seen,
            ips=ips,
            users=users,
            hosts=hosts,
            alert_count=len(members),
            stages=stages,
            score=score,
            level=level,
            timeline=timeline,
        ),
        first_seen=first_seen,
        last_seen=last_seen,
        score=score,
        level=level,
        stages=stages,
        timeline=timeline[: max(1, int(config.max_timeline))],
        ips=ips,
        users=users,
        hosts=hosts,
        alert_ids=sorted({a.id for a in alerts if isinstance(a.id, int)}),
        rule_ids=rule_ids,
        mitre_techniques=techniques,
        alert_count=len(members),
    )


def correlate(alerts: Sequence[Alert], config: CorrelationConfig) -> list[Incident]:
    """Group ``alerts`` into incidents; deterministic and never raises on odd alerts."""
    nodes = [_prepare(alert, seq) for seq, alert in enumerate(alerts)]
    nodes.sort(key=_order_key)
    uf = _link(nodes, config)
    components: dict[int, list[_Node]] = {}
    for idx, node in enumerate(nodes):
        components.setdefault(uf.find(idx), []).append(node)
    min_alerts = max(1, int(config.min_alerts))
    incidents = [
        _build_incident(members, config)
        for members in components.values()
        if len(members) >= min_alerts
    ]
    incidents.sort(key=lambda inc: (-inc.score, inc.first_seen.timestamp(), inc.alert_ids))
    return incidents
