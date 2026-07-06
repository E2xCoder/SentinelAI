"""System-level detections: service outages, firewall tampering."""

from __future__ import annotations

import re

from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent, Severity
from sentinelai.detection.base import Rule, RuleContext, register_rule

#: Units whose loss degrades security posture directly.
_CRITICAL_UNITS = (
    "ssh", "sshd", "ufw", "firewalld", "fail2ban", "auditd", "rsyslog",
    "syslog", "apparmor", "docker", "containerd", "systemd-journald",
)

_FIREWALL_TAMPER = re.compile(
    r"""
    (?:
        ufw\s+(?:disable|delete|reset|allow)
        | iptables\s+(?:-F|--flush|-X|-D|--delete|-P\s+\w+\s+ACCEPT)
        | nft\s+(?:flush|delete)
        | systemctl\s+(?:stop|disable|mask)\s+(?:ufw|firewalld|fail2ban|nftables|iptables)
        | service\s+(?:ufw|firewalld|fail2ban|iptables)\s+stop
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _matches_critical_unit(unit: str) -> str | None:
    lowered = unit.lower()
    for critical in _CRITICAL_UNITS:
        if critical in lowered:
            return critical
    return None


@register_rule
class ServiceStoppedRule(Rule):
    """A security-relevant service stopped or failed."""

    rule_id = "R050"
    name = "Service Stopped Unexpectedly"
    description = (
        "A service stopped or entered a failed state. Loss of security "
        "services (firewall, audit, logging) often precedes or "
        "accompanies an intrusion."
    )
    category = EventCategory.SERVICE_MANAGEMENT
    severity = Severity.WARNING
    mitre_tactics = ("Defense Evasion", "Impact")
    mitre_techniques = ("T1489", "T1562.001")
    recommendation = (
        "Determine who or what stopped the service and restore it; check "
        "for gaps in logging while it was down."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type not in (EventType.SERVICE_STOPPED, EventType.SERVICE_FAILED):
            return None
        unit = str(event.extra.get("unit", "")).strip()
        critical = _matches_critical_unit(unit) if unit else None
        failed = event.event_type is EventType.SERVICE_FAILED
        if critical:
            return self.make_alert(
                event,
                title=f"Security service '{unit}' "
                f"{'failed' if failed else 'stopped'}",
                description=(
                    f"The security-relevant service '{unit}' "
                    f"{'entered a failed state' if failed else 'was stopped'}. "
                    f"Monitoring or protection may be degraded."
                ),
                severity=Severity.ERROR,
                unit=unit,
                critical_service=critical,
            )
        if failed:
            return self.make_alert(
                event,
                title=f"Service '{unit or 'unknown'}' failed",
                description=f"Service '{unit or 'unknown'}' entered a failed state.",
                severity=Severity.NOTICE,
                unit=unit or None,
            )
        return None


@register_rule
class FirewallModificationRule(Rule):
    """Firewall rules disabled, flushed or opened up."""

    rule_id = "R051"
    name = "Firewall Modification"
    description = (
        "A command disabled, flushed or altered the host firewall. "
        "Attackers weaken firewalls to open command-and-control paths."
    )
    category = EventCategory.FIREWALL
    severity = Severity.ERROR
    mitre_tactics = ("Defense Evasion",)
    mitre_techniques = ("T1562.004",)
    recommendation = (
        "Compare the current ruleset with the approved baseline and "
        "re-enable the firewall if the change was not sanctioned."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        text = " ".join(
            p for p in (str(event.extra.get("command", "")), event.message) if p
        )
        match = _FIREWALL_TAMPER.search(text)
        if not match:
            return None
        return self.make_alert(
            event,
            title=f"Firewall modified by '{event.user or 'unknown'}'",
            description=(
                f"Firewall-altering command observed "
                f"(matched {match.group(0).strip()!r}): "
                f"{event.extra.get('command', event.message)[:200]}"
            ),
            command=event.extra.get("command"),
            matched=match.group(0).strip(),
        )
