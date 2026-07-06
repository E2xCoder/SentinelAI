"""Individual risk factors.

Each factor is a small callable object examining one alert (plus scoring
context) and returning either a :class:`RiskFactor` contribution with a
human-readable reason, or ``None`` when it does not apply. New factors
plug in by appending to the engine's factor list.
"""

from __future__ import annotations

from typing import Protocol

from sentinelai.core.models import Alert, EventCategory, RiskFactor, Severity


class ScoringContext:
    """Cross-alert state available to factors during one analysis run."""

    def __init__(self) -> None:
        self.ip_alert_counts: dict[str, int] = {}
        self.user_alert_counts: dict[str, int] = {}

    def record(self, alert: Alert) -> None:
        """Register an alert so later alerts see prior activity."""
        if alert.ip:
            self.ip_alert_counts[alert.ip] = self.ip_alert_counts.get(alert.ip, 0) + 1
        if alert.user:
            self.user_alert_counts[alert.user] = (
                self.user_alert_counts.get(alert.user, 0) + 1
            )


class RiskFactorEvaluator(Protocol):
    """Interface every risk factor implements."""

    def evaluate(self, alert: Alert, ctx: ScoringContext) -> RiskFactor | None:
        """Return a scored contribution, or None when not applicable."""
        ...


class BaseSeverityFactor:
    """Anchor score derived from the detection rule's severity."""

    _POINTS = {
        Severity.DEBUG: 2.0,
        Severity.INFO: 5.0,
        Severity.NOTICE: 12.0,
        Severity.WARNING: 25.0,
        Severity.ERROR: 40.0,
        Severity.CRITICAL: 55.0,
    }

    def evaluate(self, alert: Alert, ctx: ScoringContext) -> RiskFactor | None:
        points = self._POINTS[alert.severity]
        return RiskFactor(
            name="base_severity",
            points=points,
            reason=f"Rule '{alert.rule_name}' has base severity {alert.severity.value}",
        )


class FrequencyFactor:
    """More correlated events means more confidence and more risk."""

    def evaluate(self, alert: Alert, ctx: ScoringContext) -> RiskFactor | None:
        count = alert.event_count
        if count <= 1:
            return None
        points = min(20.0, 4.0 * (count ** 0.5))
        return RiskFactor(
            name="attack_frequency",
            points=points,
            reason=f"Alert is backed by {count} correlated events",
        )


class VelocityFactor:
    """Fast attacks (short window, many events) score higher."""

    def evaluate(self, alert: Alert, ctx: ScoringContext) -> RiskFactor | None:
        span = (alert.last_seen - alert.first_seen).total_seconds()
        if alert.event_count < 3:
            return None
        rate = alert.event_count / max(span, 1.0)
        if rate < 0.2:
            return None
        points = min(12.0, rate * 6.0)
        return RiskFactor(
            name="attack_velocity",
            points=points,
            reason=f"Events arrived at {rate:.1f}/s over {span:.0f}s — automated tooling",
        )


class PrivilegedTargetFactor:
    """Attacks touching root or privileged operations are worse."""

    _PRIVILEGED_USERS = frozenset({"root", "admin", "administrator"})
    _PRIVILEGED_CATEGORIES = frozenset(
        {EventCategory.PRIVILEGE_ESCALATION, EventCategory.USER_MANAGEMENT}
    )

    def evaluate(self, alert: Alert, ctx: ScoringContext) -> RiskFactor | None:
        target = (alert.user or "").lower()
        targets_root = target in self._PRIVILEGED_USERS or "root" in {
            str(u).lower() for u in alert.context.get("targeted_users", [])
        }
        if targets_root:
            return RiskFactor(
                name="privileged_target",
                points=15.0,
                reason="Activity targets a privileged account (root/admin)",
            )
        if alert.category in self._PRIVILEGED_CATEGORIES:
            return RiskFactor(
                name="privileged_operation",
                points=10.0,
                reason=f"Alert concerns a privileged operation ({alert.category.value})",
            )
        return None


class CriticalServiceFactor:
    """Impact on security infrastructure raises the stakes."""

    def evaluate(self, alert: Alert, ctx: ScoringContext) -> RiskFactor | None:
        service = alert.context.get("critical_service")
        if service:
            return RiskFactor(
                name="critical_service",
                points=12.0,
                reason=f"A critical security service is affected ({service})",
            )
        if alert.category is EventCategory.FIREWALL:
            return RiskFactor(
                name="critical_service",
                points=8.0,
                reason="Alert affects the firewall layer",
            )
        return None


class ThreatIntelFactor:
    """Known-bad source IPs sharply increase risk."""

    def evaluate(self, alert: Alert, ctx: ScoringContext) -> RiskFactor | None:
        intel = alert.intel
        if intel is None or not intel.sources:
            return None
        if intel.malicious:
            points = 10.0 + min(15.0, intel.score * 0.15)
            names = ", ".join(sorted(intel.sources))
            return RiskFactor(
                name="threat_intelligence",
                points=points,
                reason=(
                    f"Source IP {intel.ip} is flagged malicious "
                    f"(score {intel.score:.0f}/100 across {names})"
                ),
            )
        return RiskFactor(
            name="threat_intelligence",
            points=-5.0,
            reason=f"Source IP {intel.ip} has a clean reputation",
        )


class RecurrenceFactor:
    """Sources or accounts that already triggered alerts keep climbing."""

    def evaluate(self, alert: Alert, ctx: ScoringContext) -> RiskFactor | None:
        prior_ip = ctx.ip_alert_counts.get(alert.ip or "", 0)
        prior_user = ctx.user_alert_counts.get(alert.user or "", 0)
        prior = max(prior_ip, prior_user)
        if prior == 0:
            return None
        points = min(15.0, 5.0 * prior)
        subject = alert.ip if prior_ip >= prior_user else f"account '{alert.user}'"
        return RiskFactor(
            name="repeated_behavior",
            points=points,
            reason=f"{subject} already triggered {prior} earlier alert(s) in this run",
        )


class AIAnomalyFactor:
    """Anomalous behavior according to the AI engine adds risk."""

    def evaluate(self, alert: Alert, ctx: ScoringContext) -> RiskFactor | None:
        ai = alert.ai
        if ai is None or ai.anomaly_score is None or not ai.is_anomaly:
            return None
        points = min(12.0, ai.anomaly_score * 12.0)
        return RiskFactor(
            name="ai_anomaly",
            points=points,
            reason=(
                f"AI model ({ai.model}) scored this behavior as anomalous "
                f"({ai.anomaly_score:.2f})"
            ),
        )


DEFAULT_FACTORS: tuple[RiskFactorEvaluator, ...] = (
    BaseSeverityFactor(),
    FrequencyFactor(),
    VelocityFactor(),
    PrivilegedTargetFactor(),
    CriticalServiceFactor(),
    ThreatIntelFactor(),
    RecurrenceFactor(),
    AIAnomalyFactor(),
)
