"""Report data model: distils a ScanResult into a serializable report."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sentinelai import __version__
from sentinelai.ai.patterns import AttackPattern
from sentinelai.core.models import Alert, RiskLevel
from sentinelai.core.pipeline import ScanResult


@dataclass(slots=True)
class Report:
    """Structured security report assembled from a scan."""

    title: str
    generated_at: datetime
    source: str
    alerts: list[Alert]
    patterns: list[AttackPattern]
    summary: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self, include_events: bool = True) -> dict[str, Any]:
        """Full JSON-serializable representation of the report."""
        return {
            "title": self.title,
            "generated_at": self.generated_at.isoformat(),
            "generator": f"SentinelAI {__version__}",
            "source": self.source,
            "summary": self.summary,
            "recommendations": self.recommendations,
            "attack_patterns": [p.to_dict() for p in self.patterns],
            "alerts": [a.to_dict(include_events=include_events) for a in self.alerts],
        }


def build_report(
    result: ScanResult,
    title: str,
    source: str,
    max_events_per_alert: int = 5,
) -> Report:
    """Assemble a :class:`Report` from a scan result."""
    alerts = sorted(
        result.alerts, key=lambda a: (a.risk.score, a.last_seen), reverse=True
    )
    for alert in alerts:
        if len(alert.sample_events) > max_events_per_alert:
            alert.sample_events = alert.sample_events[-max_events_per_alert:]

    stats = result.statistics
    level_counts: Counter[str] = Counter(a.risk.level.value for a in alerts)
    rule_counts: Counter[str] = Counter(a.rule_name for a in alerts)
    ip_counts: Counter[str] = Counter(a.ip for a in alerts if a.ip)
    user_counts: Counter[str] = Counter(a.user for a in alerts if a.user)

    timeline = [
        {
            "timestamp": a.first_seen.isoformat(),
            "rule": a.rule_name,
            "risk": a.risk.level.value,
            "ip": a.ip,
            "user": a.user,
            "title": a.title,
        }
        for a in sorted(alerts, key=lambda a: a.first_seen)
    ]

    # Behavior analysis: richer per-subject profiles across *all* events,
    # not just the ones that raised alerts. Falls back gracefully when the
    # AI/behavior layer is disabled.
    behavior_sources: list[dict[str, Any]] = []
    behavior_targets: list[dict[str, Any]] = []
    if result.behavior is not None:
        behavior_sources = [p.summarize() for p in result.behavior.noisiest_ips(10)]
        behavior_targets = [
            p.summarize()
            for p in result.behavior.most_targeted_users(10)
            if p.failure_count
        ]

    summary = {
        "events_analyzed": stats.total_events,
        "time_range": {
            "start": stats.first_event.isoformat() if stats.first_event else None,
            "end": stats.last_event.isoformat() if stats.last_event else None,
        },
        "alerts_total": len(alerts),
        "alerts_by_level": dict(level_counts),
        "alerts_by_rule": dict(rule_counts.most_common()),
        "attack_patterns": len(result.patterns),
        "ai_anomalies": result.anomaly_count,
        "ai_used": result.ai_used,
        "unique_source_ips": len(stats.unique_ips),
        "affected_users": sorted(stats.unique_users)[:50],
        "affected_hosts": sorted(stats.unique_hosts),
        "events_by_category": dict(stats.categories),
        "events_by_severity": dict(stats.severities),
        "top_source_ips": [
            {"ip": ip, "alerts": count} for ip, count in ip_counts.most_common(10)
        ],
        "top_targeted_users": [
            {"user": user, "alerts": count} for user, count in user_counts.most_common(10)
        ],
        "behavior_analysis": {
            "noisiest_source_ips": behavior_sources,
            "most_targeted_users": behavior_targets,
        },
        "timeline": timeline,
    }
    return Report(
        title=title,
        generated_at=datetime.now(timezone.utc),
        source=source,
        alerts=alerts,
        patterns=result.patterns,
        summary=summary,
        recommendations=_recommendations(alerts, result.patterns, level_counts),
    )


def _recommendations(
    alerts: list[Alert],
    patterns: list[AttackPattern],
    level_counts: Counter[str],
) -> list[str]:
    """Produce prioritized, de-duplicated remediation guidance."""
    recs: list[str] = []
    seen: set[str] = set()

    def add(text: str) -> None:
        if text not in seen:
            seen.add(text)
            recs.append(text)

    critical = level_counts.get(RiskLevel.CRITICAL.value, 0)
    high = level_counts.get(RiskLevel.HIGH.value, 0)
    if critical:
        add(
            f"Immediate action: {critical} critical alert(s) require "
            f"investigation now."
        )
    if high:
        add(f"Prioritize {high} high-risk alert(s) within your next shift.")
    for pattern in patterns:
        add(f"Multi-stage attack detected — {pattern.name}: {pattern.description}")
    malicious_ips = sorted(
        {a.ip for a in alerts if a.ip and a.intel and a.intel.malicious}
    )
    if malicious_ips:
        add(
            "Block these known-malicious source IPs at the perimeter: "
            + ", ".join(malicious_ips[:20])
        )
    # Surface the most common rule-specific recommendation.
    for alert in alerts:
        if alert.risk.level.weight >= RiskLevel.HIGH.weight and alert.recommendation:
            add(alert.recommendation)
    if not recs:
        add("No significant threats detected. Maintain routine monitoring.")
    return recs
