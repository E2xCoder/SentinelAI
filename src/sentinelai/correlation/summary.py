"""Deterministic, injection-safe text rendering of correlated incidents.

Every attacker-controlled field (titles, users, hosts, IPs) is sanitised
before it reaches a summary, a Mermaid diagram or a synthetic alert.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone

from sentinelai.ai.triage import sanitize_text
from sentinelai.core.models import (
    Alert,
    EventCategory,
    Incident,
    LogEvent,
    RiskAssessment,
    RiskLevel,
    Severity,
    TimelineEntry,
)

MAX_MERMAID_NODES = 40
MAX_LABEL = 60
MAX_SAMPLE_EVENTS = 5
_MAX_ENTITY = 64
_MAX_TITLE = 120
_MAX_LISTED = 3

_LEVEL_SEVERITY: dict[RiskLevel, Severity] = {
    RiskLevel.INFORMATIONAL: Severity.INFO,
    RiskLevel.LOW: Severity.NOTICE,
    RiskLevel.MEDIUM: Severity.WARNING,
    RiskLevel.HIGH: Severity.ERROR,
    RiskLevel.CRITICAL: Severity.CRITICAL,
}

# Characters that can break or inject into a Mermaid definition.
_MERMAID_UNSAFE = re.compile(r"[\"\[\]<>(){};#`%&|\\\r\n\t]")
_ID_UNSAFE = re.compile(r"[^A-Za-z0-9_]")


def as_utc(value: datetime) -> datetime:
    """Return ``value`` as an aware UTC datetime (naive input is assumed UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _clean(value: object, max_len: int) -> str:
    if value is None:
        return ""
    cleaned = sanitize_text(str(value), max_len).strip()
    # Summaries are plain text: angle brackets are never needed and only invite markup.
    return cleaned.replace("<", "").replace(">", "")


def _clean_list(values: Sequence[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        text = _clean(value, _MAX_ENTITY)
        if text:
            out.append(text)
    return out


def _describe(ips: Sequence[str], users: Sequence[str], hosts: Sequence[str]) -> str:
    bits: list[str] = []
    for label, raw in (("IP", ips), ("user", users), ("host", hosts)):
        vals = _clean_list(raw)
        if not vals:
            continue
        bit = f"{label} {', '.join(vals[:_MAX_LISTED])}"
        if len(vals) > _MAX_LISTED:
            bit += f" +{len(vals) - _MAX_LISTED} more"
        bits.append(bit)
    return "; ".join(bits) or "unidentified entities"


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def build_title(
    *,
    stages: Sequence[str],
    ips: Sequence[str],
    users: Sequence[str],
    hosts: Sequence[str],
    alert_count: int,
) -> str:
    """Short one-line incident title."""
    subject = next(iter(_clean_list(ips) or _clean_list(users) or _clean_list(hosts)), "")
    subject = subject or "multiple entities"
    count = _plural(alert_count, "alert")
    if len(stages) >= 2:
        title = f"Multi-stage attack from {subject}: {stages[0]} to {stages[-1]} ({count})"
    else:
        title = f"Correlated activity from {subject} ({count})"
    return title[:_MAX_TITLE]


def _fmt_range(first: datetime, last: datetime) -> str:
    a, b = as_utc(first), as_utc(last)
    if a.date() == b.date():
        return f"{a:%H:%M} and {b:%H:%M} UTC on {a:%Y-%m-%d}"
    return f"{a:%Y-%m-%d %H:%M} and {b:%Y-%m-%d %H:%M} UTC"


def _entry_phrase(entry: TimelineEntry) -> str:
    title = _clean(entry.title, _MAX_TITLE) or "untitled alert"
    rule = _clean(entry.rule_id, 16) or "?"
    tactic = _clean(entry.tactic, 40) or "Unclassified"
    return f"{title} ({rule}, {tactic})"


def build_summary(
    *,
    first_seen: datetime,
    last_seen: datetime,
    ips: Sequence[str],
    users: Sequence[str],
    hosts: Sequence[str],
    alert_count: int,
    stages: Sequence[str],
    score: float,
    level: RiskLevel,
    timeline: Sequence[TimelineEntry],
) -> str:
    """Plain-language deterministic English summary of an incident."""
    who = _describe(ips, users, hosts)
    alerts = _plural(alert_count, "alert")
    head = f"Between {_fmt_range(first_seen, last_seen)}, {who} raised {alerts}"
    if stages:
        head += f" across {_plural(len(stages), 'stage')}: {' -> '.join(_clean_list(stages))}"
    else:
        head += " with no mapped kill-chain stage"
    text = f"{head} (score {score:.0f}, {level.value.upper()})."
    if timeline:
        text += f" First: {_entry_phrase(timeline[0])}; Last: {_entry_phrase(timeline[-1])}."
    return text


def _label(text: object, max_len: int = MAX_LABEL) -> str:
    cleaned = _MERMAID_UNSAFE.sub(" ", _clean(text, max_len * 2))
    cleaned = "".join(ch for ch in cleaned if ch.isprintable())
    return " ".join(cleaned.split())[:max_len]


def _node_id(prefix: str, index: int) -> str:
    return _ID_UNSAFE.sub("_", f"{prefix}{index}")


def _key(value: str | None) -> str:
    return value.strip().lower() if value else ""


def render_mermaid(incident: Incident) -> str:
    """Mermaid ``graph LR`` of entities and the alert timeline (injection-safe)."""
    entities: list[tuple[str, str, str, str]] = []  # (id, kind, label, match-key)
    for prefix, kind, values in (
        ("ip", "IP", incident.ips),
        ("u", "user", incident.users),
        ("h", "host", incident.hosts),
    ):
        for i, value in enumerate(values[:_MAX_LISTED]):
            label = _label(f"{kind} {value}")
            entities.append((_node_id(prefix, i), kind, label, _key(value)))
    room = max(0, MAX_MERMAID_NODES - len(entities))
    entries = list(incident.timeline[:room])

    lines = ["graph LR"]
    for node_id, _kind, label, _match in entities:
        lines.append(f'  {node_id}["{label}"]')
    alert_ids: list[str] = []
    for i, entry in enumerate(entries):
        node_id = _node_id("a", i)
        alert_ids.append(node_id)
        count = f" x{entry.count}" if entry.count > 1 else ""
        label = _label(f"{entry.timestamp:%H:%M:%S} {entry.title}{count}")
        lines.append(f'  {node_id}["{label}"]')
    for prev, nxt in zip(alert_ids, alert_ids[1:], strict=False):
        lines.append(f"  {prev} --> {nxt}")
    for node_id, kind, _label_text, match in entities:
        for entry, alert_node in zip(entries, alert_ids, strict=False):
            entity_values: dict[str, str | None] = {
                "IP": entry.ip,
                "user": entry.user,
                "host": entry.host,
            }
            if match and _key(entity_values[kind]) == match:
                lines.append(f"  {node_id} -.-> {alert_node}")
    return "\n".join(lines)


def _sample_events(
    incident: Incident, alerts_by_id: Mapping[int, Alert] | None
) -> list[LogEvent]:
    if not alerts_by_id:
        return []
    ordered: list[int] = []
    for entry in incident.timeline:
        if entry.alert_id is not None and entry.alert_id not in ordered:
            ordered.append(entry.alert_id)
    ordered.extend(i for i in incident.alert_ids if i not in ordered)
    members = [alerts_by_id[i] for i in ordered if i in alerts_by_id]
    events: list[LogEvent] = []
    depth = 0
    while len(events) < MAX_SAMPLE_EVENTS and any(len(a.sample_events) > depth for a in members):
        for alert in members:
            if len(alert.sample_events) > depth and len(events) < MAX_SAMPLE_EVENTS:
                events.append(alert.sample_events[depth])
        depth += 1
    return events


def incident_as_alert(
    incident: Incident, alerts_by_id: Mapping[int, Alert] | None = None
) -> Alert:
    """Synthetic ``Alert`` standing in for an incident (advisory triage input)."""
    return Alert(
        rule_id="INC",
        rule_name="Correlated incident",
        title=incident.title,
        description=incident.summary,
        category=EventCategory.UNKNOWN,
        severity=_LEVEL_SEVERITY.get(incident.level, Severity.WARNING),
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        ip=incident.ips[0] if incident.ips else None,
        user=incident.users[0] if incident.users else None,
        hostname=incident.hosts[0] if incident.hosts else None,
        event_count=incident.alert_count,
        mitre_tactics=list(incident.stages),
        mitre_techniques=list(incident.mitre_techniques),
        sample_events=_sample_events(incident, alerts_by_id),
        risk=RiskAssessment(score=incident.score, level=incident.level),
        context={"correlated": True, "alert_ids": list(incident.alert_ids)[:50]},
    )
