"""Docker detections: privileged containers and sensitive mounts."""

from __future__ import annotations

import re

from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent, Severity
from sentinelai.detection.base import Rule, RuleContext, register_rule

_SENSITIVE = re.compile(
    r"""
    (?:
        privileged(?!\s*[:=]?\s*(?:false|no|0|off)\b)
        | docker\.sock
        | pid(?:=|\s+)host | pid_mode.*host
        | net(?:work)?(?:=|\s+|_mode.*)host
        | cap[-_]?add.*(?:SYS_ADMIN|SYS_PTRACE|ALL)
        | (?:-v|mount|bind).{0,40}(?:/etc|/root|/var/run|/proc|/sys|/(?:\s|:|"))
        | apparmor[=:]unconfined | seccomp[=:]unconfined
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


@register_rule
class SuspiciousDockerRule(Rule):
    """Container activity that weakens host isolation."""

    rule_id = "R060"
    name = "Suspicious Docker Activity"
    description = (
        "Container activity referenced privileged mode, host namespaces, "
        "the Docker socket or sensitive host mounts — all common "
        "container-escape vectors."
    )
    category = EventCategory.DOCKER
    severity = Severity.ERROR
    mitre_tactics = ("Privilege Escalation", "Execution")
    mitre_techniques = ("T1610", "T1611")
    recommendation = (
        "Identify the container and who launched it; privileged or "
        "socket-mounted containers are root-equivalent on the host."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        is_docker_event = event.event_type is EventType.CONTAINER_EVENT
        is_docker_command = event.event_type is EventType.SUDO_COMMAND and "docker" in str(
            event.extra.get("command", "")
        )
        if not (is_docker_event or is_docker_command):
            return None
        text = " ".join(
            p for p in (str(event.extra.get("command", "")), event.message) if p
        )
        if event.extra.get("privileged"):
            match_text = "privileged"
        else:
            match = _SENSITIVE.search(text)
            if not match:
                return None
            match_text = match.group(0).strip()
        return self.make_alert(
            event,
            title="Suspicious container configuration",
            description=(
                f"Docker activity with a host-isolation risk was observed "
                f"(matched {match_text!r}): {text[:200]}"
            ),
            matched=match_text,
            container_id=event.extra.get("container_id"),
        )
