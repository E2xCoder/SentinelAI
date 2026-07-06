"""Network attack detections: scanning, reverse shells, lateral movement."""

from __future__ import annotations

import re

from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent, Severity
from sentinelai.detection.base import Rule, RuleContext, register_rule

#: Command patterns strongly associated with reverse/bind shells.
_REVERSE_SHELL = re.compile(
    r"""
    (?:
        (?:nc|ncat|netcat)\s+(?:[^\n]*\s)?-{1,2}\S*e\b   # nc -e /bin/sh
        | bash\s+-i\s+>&\s*/dev/tcp/                     # bash -i >& /dev/tcp/ip/port
        | /dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+            # any /dev/tcp connect-back
        | socat\s+[^\n]*exec:                             # socat ... EXEC:
        | python[\d.]*\s+-c\s+[^\n]*socket[^\n]*(?:subprocess|pty|os\.dup2)
        | perl\s+-e\s+[^\n]*socket[^\n]*exec
        | php\s+-r\s+[^\n]*fsockopen
        | ruby\s+-rsocket
        | mkfifo\s+\S+\s*;?\s*(?:nc|cat)                  # mkfifo pipe shells
        | rm\s+\S*/tmp/\S+;\s*mkfifo
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _command_text(event: LogEvent) -> str:
    """Extract any command-like content from an event."""
    parts = [str(event.extra.get("command", "")), str(event.extra.get("path", ""))]
    parts.append(event.message)
    return " ".join(p for p in parts if p)


@register_rule
class PortScanRule(Rule):
    """One source probing many distinct ports."""

    rule_id = "R030"
    name = "Port Scan"
    description = (
        "A single source IP was blocked while probing many distinct "
        "destination ports in a short window — reconnaissance scanning."
    )
    category = EventCategory.NETWORK
    severity = Severity.WARNING
    mitre_tactics = ("Reconnaissance", "Discovery")
    mitre_techniques = ("T1046", "T1595.001")
    recommendation = (
        "Block the scanning IP and verify no service answered on "
        "unexpected ports."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type not in (EventType.FIREWALL_BLOCK, EventType.PORT_PROBE):
            return None
        if not event.ip or event.port is None:
            return None
        key = f"{self.rule_id}:{event.ip}"
        ctx.state.add(key, event.timestamp, port=event.port, event=event)
        window = ctx.config.port_scan_window_seconds
        ports = ctx.state.distinct(key, event.timestamp, window, "port")
        if len(ports) < ctx.config.port_scan_ports:
            return None
        entries = ctx.state.entries(key, event.timestamp, window)
        events = [e.payload["event"] for e in entries]
        ctx.state.clear_key(key)
        sorted_ports = sorted(int(p) for p in ports)
        shown = ", ".join(str(p) for p in sorted_ports[:15])
        if len(sorted_ports) > 15:
            shown += ", …"
        return self.make_alert(
            event,
            title=f"Port scan from {event.ip}",
            description=(
                f"{event.ip} probed {len(ports)} distinct ports within "
                f"{window} seconds (threshold: {ctx.config.port_scan_ports}). "
                f"Ports: {shown}."
            ),
            events=events,
            distinct_ports=len(ports),
            ports=sorted_ports[:50],
            window_seconds=window,
        )


@register_rule
class ReverseShellRule(Rule):
    """Command content matching reverse-shell one-liners."""

    rule_id = "R031"
    name = "Reverse Shell Indicator"
    description = (
        "A command or request matched well-known reverse-shell payloads "
        "(netcat -e, /dev/tcp redirection, socat exec, scripted sockets)."
    )
    category = EventCategory.NETWORK
    severity = Severity.CRITICAL
    mitre_tactics = ("Execution", "Command and Control")
    mitre_techniques = ("T1059.004", "T1071")
    recommendation = (
        "Treat the host as compromised: isolate it, capture volatile "
        "state, and identify the remote endpoint of the shell."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        text = _command_text(event)
        match = _REVERSE_SHELL.search(text)
        if not match:
            return None
        return self.make_alert(
            event,
            title="Reverse shell indicator detected",
            description=(
                f"Content matching a reverse-shell payload was observed "
                f"(matched: {match.group(0).strip()!r}). "
                f"Source event: {event.message[:200]}"
            ),
            matched=match.group(0).strip(),
        )


@register_rule
class LateralMovementRule(Rule):
    """One internal source authenticating across many hosts."""

    rule_id = "R032"
    name = "Lateral Movement"
    description = (
        "A single source IP successfully authenticated to multiple "
        "distinct hosts in a short window — consistent with an attacker "
        "pivoting through the environment."
    )
    category = EventCategory.NETWORK
    severity = Severity.ERROR
    mitre_tactics = ("Lateral Movement",)
    mitre_techniques = ("T1021.004",)
    recommendation = (
        "Verify whether the source is a legitimate administration host; "
        "otherwise isolate it and audit every host it reached."
    )

    _HOST_THRESHOLD = 3
    _WINDOW = 1800

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type not in (EventType.AUTH_SUCCESS, EventType.ROOT_LOGIN):
            return None
        if not event.ip or not event.hostname:
            return None
        key = f"{self.rule_id}:{event.ip}"
        ctx.state.add(key, event.timestamp, host=event.hostname, event=event)
        hosts = ctx.state.distinct(key, event.timestamp, self._WINDOW, "host")
        if len(hosts) < self._HOST_THRESHOLD:
            return None
        entries = ctx.state.entries(key, event.timestamp, self._WINDOW)
        events = [e.payload["event"] for e in entries]
        ctx.state.clear_key(key)
        return self.make_alert(
            event,
            title=f"Possible lateral movement from {event.ip}",
            description=(
                f"{event.ip} successfully authenticated to {len(hosts)} distinct "
                f"hosts within {self._WINDOW // 60} minutes: "
                f"{', '.join(sorted(str(h) for h in hosts))}."
            ),
            events=events,
            hosts=sorted(str(h) for h in hosts),
        )
