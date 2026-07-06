"""Authentication attack detections: brute force, spraying, stuffing."""

from __future__ import annotations

from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent, Severity
from sentinelai.detection.base import Rule, RuleContext, register_rule

_FAILURE_TYPES = frozenset({EventType.AUTH_FAILURE, EventType.INVALID_USER})
_SUCCESS_TYPES = frozenset({EventType.AUTH_SUCCESS, EventType.ROOT_LOGIN})


def _is_failure(event: LogEvent) -> bool:
    return event.event_type in _FAILURE_TYPES


@register_rule
class SSHBruteForceRule(Rule):
    """Many failed logins from one source against the same host."""

    rule_id = "R001"
    name = "SSH Brute Force"
    description = (
        "A single source IP generated an excessive number of failed "
        "authentication attempts within a short window, indicating an "
        "automated password-guessing attack."
    )
    category = EventCategory.AUTHENTICATION
    severity = Severity.ERROR
    mitre_tactics = ("Credential Access",)
    mitre_techniques = ("T1110.001",)
    recommendation = (
        "Block the source IP at the firewall, enforce key-based SSH "
        "authentication, and consider rate-limiting with Fail2Ban."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if not _is_failure(event) or not event.ip:
            return None
        key = f"{self.rule_id}:{event.ip}"
        ctx.state.add(key, event.timestamp, user=event.user, event=event)
        window = ctx.config.brute_force_window_seconds
        count = ctx.state.count(key, event.timestamp, window)
        if count < ctx.config.brute_force_attempts:
            return None
        entries = ctx.state.entries(key, event.timestamp, window)
        users = sorted({str(e.payload["user"]) for e in entries if e.payload.get("user")})
        events = [e.payload["event"] for e in entries]
        ctx.state.clear_key(key)
        return self.make_alert(
            event,
            title=f"SSH brute force from {event.ip}",
            description=(
                f"{count} failed authentication attempts from {event.ip} within "
                f"{window} seconds (threshold: {ctx.config.brute_force_attempts}). "
                f"Targeted account(s): {', '.join(users) or 'unknown'}."
            ),
            events=events,
            attempts=count,
            window_seconds=window,
            targeted_users=users,
        )


@register_rule
class PasswordSprayRule(Rule):
    """One source trying a few passwords across many accounts."""

    rule_id = "R002"
    name = "Password Spraying"
    description = (
        "A single source IP attempted authentication against many "
        "different accounts, the signature of a password-spraying attack "
        "designed to evade per-account lockouts."
    )
    category = EventCategory.AUTHENTICATION
    severity = Severity.ERROR
    mitre_tactics = ("Credential Access",)
    mitre_techniques = ("T1110.003",)
    recommendation = (
        "Block the source IP, review the targeted accounts for compromise "
        "and enable MFA wherever possible."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if not _is_failure(event) or not event.ip or not event.user:
            return None
        key = f"{self.rule_id}:{event.ip}"
        ctx.state.add(key, event.timestamp, user=event.user, event=event)
        window = ctx.config.password_spray_window_seconds
        users = ctx.state.distinct(key, event.timestamp, window, "user")
        if len(users) < ctx.config.password_spray_users:
            return None
        entries = ctx.state.entries(key, event.timestamp, window)
        events = [e.payload["event"] for e in entries]
        ctx.state.clear_key(key)
        return self.make_alert(
            event,
            title=f"Password spraying from {event.ip}",
            description=(
                f"{event.ip} attempted logins against {len(users)} distinct accounts "
                f"within {window} seconds "
                f"(threshold: {ctx.config.password_spray_users}). "
                f"Accounts: {', '.join(sorted(str(u) for u in users))}."
            ),
            events=events,
            distinct_users=sorted(str(u) for u in users),
            window_seconds=window,
        )


@register_rule
class CredentialStuffingRule(Rule):
    """One account attacked from many different sources."""

    rule_id = "R003"
    name = "Credential Stuffing"
    description = (
        "A single account received failed login attempts from multiple "
        "distinct source IPs, consistent with credential stuffing using "
        "leaked username/password lists across a botnet."
    )
    category = EventCategory.AUTHENTICATION
    severity = Severity.ERROR
    mitre_tactics = ("Credential Access",)
    mitre_techniques = ("T1110.004",)
    recommendation = (
        "Force a password reset for the targeted account, enable MFA and "
        "review successful logins for that account."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if not _is_failure(event) or not event.ip or not event.user:
            return None
        key = f"{self.rule_id}:{event.user}"
        ctx.state.add(key, event.timestamp, ip=event.ip, event=event)
        window = ctx.config.credential_stuffing_window_seconds
        entries = ctx.state.entries(key, event.timestamp, window)
        ips = {str(e.payload["ip"]) for e in entries}
        if len(entries) < ctx.config.credential_stuffing_attempts or len(ips) < 3:
            return None
        events = [e.payload["event"] for e in entries]
        ctx.state.clear_key(key)
        return self.make_alert(
            event,
            title=f"Credential stuffing against account '{event.user}'",
            description=(
                f"Account '{event.user}' received {len(entries)} failed logins from "
                f"{len(ips)} distinct IPs within {window} seconds. "
                f"Sources: {', '.join(sorted(ips))}."
            ),
            events=events,
            source_ips=sorted(ips),
            attempts=len(entries),
            window_seconds=window,
        )


@register_rule
class RepeatedAuthFailuresRule(Rule):
    """Sustained failed logins against one account from any source."""

    rule_id = "R004"
    name = "Repeated Authentication Failures"
    description = (
        "An account accumulated an abnormal number of failed logins, "
        "which may indicate a slow brute-force attack or a misconfigured "
        "client repeatedly locking the account."
    )
    category = EventCategory.AUTHENTICATION
    severity = Severity.WARNING
    mitre_tactics = ("Credential Access",)
    mitre_techniques = ("T1110",)
    recommendation = (
        "Verify whether the failures come from a legitimate but "
        "misconfigured client; otherwise treat as a brute-force attempt."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if not _is_failure(event) or not event.user:
            return None
        key = f"{self.rule_id}:{event.user}"
        ctx.state.add(key, event.timestamp, ip=event.ip, event=event)
        window = ctx.config.repeated_failure_window_seconds
        count = ctx.state.count(key, event.timestamp, window)
        if count < ctx.config.repeated_failure_attempts:
            return None
        entries = ctx.state.entries(key, event.timestamp, window)
        events = [e.payload["event"] for e in entries]
        ctx.state.clear_key(key)
        return self.make_alert(
            event,
            title=f"Repeated authentication failures for '{event.user}'",
            description=(
                f"{count} failed authentication attempts against '{event.user}' "
                f"within {window} seconds "
                f"(threshold: {ctx.config.repeated_failure_attempts})."
            ),
            events=events,
            attempts=count,
            window_seconds=window,
        )


@register_rule
class RootLoginRule(Rule):
    """Direct interactive root login."""

    rule_id = "R005"
    name = "Root Login"
    description = (
        "A successful direct login as root was observed. Direct root "
        "access removes accountability and is a common attacker goal."
    )
    category = EventCategory.AUTHENTICATION
    severity = Severity.WARNING
    mitre_tactics = ("Initial Access", "Privilege Escalation")
    mitre_techniques = ("T1078.003",)
    recommendation = (
        "Disable direct root SSH login (PermitRootLogin no) and require "
        "sudo from named accounts instead."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type is not EventType.ROOT_LOGIN:
            return None
        origin = f" from {event.ip}" if event.ip else ""
        return self.make_alert(
            event,
            title=f"Direct root login{origin}",
            description=(
                f"A successful root login occurred{origin} using "
                f"{event.extra.get('method', 'an unknown method')}."
            ),
            method=event.extra.get("method"),
        )


@register_rule
class ImpossibleFrequencyRule(Rule):
    """Login attempts arriving faster than any human could type."""

    rule_id = "R006"
    name = "Impossible Login Frequency"
    description = (
        "Authentication attempts from one source arrived at machine speed, "
        "proving the activity is scripted rather than a human mistyping a "
        "password."
    )
    category = EventCategory.AUTHENTICATION
    severity = Severity.ERROR
    mitre_tactics = ("Credential Access",)
    mitre_techniques = ("T1110",)
    recommendation = "Block the source IP; the traffic is automated."

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type not in (_FAILURE_TYPES | _SUCCESS_TYPES) or not event.ip:
            return None
        key = f"{self.rule_id}:{event.ip}"
        ctx.state.add(key, event.timestamp, event=event)
        window = ctx.config.impossible_frequency_window_seconds
        count = ctx.state.count(key, event.timestamp, window)
        if count < ctx.config.impossible_frequency_attempts:
            return None
        span = max(ctx.state.span_seconds(key, event.timestamp, window), 0.001)
        rate = count / span
        entries = ctx.state.entries(key, event.timestamp, window)
        events = [e.payload["event"] for e in entries]
        ctx.state.clear_key(key)
        return self.make_alert(
            event,
            title=f"Machine-speed login attempts from {event.ip}",
            description=(
                f"{count} authentication attempts from {event.ip} in "
                f"{span:.1f} seconds ({rate:.1f}/s) — far beyond human speed."
            ),
            events=events,
            attempts=count,
            attempts_per_second=round(rate, 2),
        )


@register_rule
class SuspiciousLoginHoursRule(Rule):
    """Successful logins during configured quiet hours."""

    rule_id = "R007"
    name = "Suspicious Login Hours"
    description = (
        "A successful login occurred during configured quiet hours, when "
        "legitimate interactive activity is not expected."
    )
    category = EventCategory.AUTHENTICATION
    severity = Severity.NOTICE
    mitre_tactics = ("Initial Access",)
    mitre_techniques = ("T1078",)
    recommendation = (
        "Confirm the login with the account owner; review commands "
        "executed during the session."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type not in _SUCCESS_TYPES:
            return None
        start = ctx.config.suspicious_hours_start
        end = ctx.config.suspicious_hours_end
        hour = event.timestamp.hour
        in_range = start <= hour <= end if start <= end else (hour >= start or hour <= end)
        if not in_range:
            return None
        return self.make_alert(
            event,
            title=f"Off-hours login for '{event.user or 'unknown'}'",
            description=(
                f"Successful login for '{event.user or 'unknown'}' at "
                f"{event.timestamp:%H:%M} UTC, inside the configured quiet "
                f"window {start:02d}:00-{end:02d}:59."
            ),
            login_hour=hour,
        )
