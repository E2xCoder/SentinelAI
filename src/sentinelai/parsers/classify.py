"""Message classification for syslog-family services.

A table-driven classifier: each service family owns an ordered list of
``(compiled_regex, builder)`` pairs. The first matching pattern wins.
This keeps per-service knowledge in one place and makes new patterns a
one-line addition.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from re import Match, Pattern
from typing import Any

from sentinelai.core.models import EventCategory, EventType, Severity


@dataclass(slots=True)
class Classification:
    """Result of classifying one syslog message."""

    event_type: EventType = EventType.GENERIC
    category: EventCategory = EventCategory.SYSTEM
    severity: Severity = Severity.INFO
    user: str | None = None
    ip: str | None = None
    port: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


Builder = Callable[[Match[str]], Classification]


def _c(
    event_type: EventType,
    category: EventCategory,
    severity: Severity = Severity.INFO,
    **extra_fields: str,
) -> Builder:
    """Build a classifier that maps named regex groups onto fields.

    Named groups ``user``, ``ip`` and ``port`` map to those event fields;
    any name passed via *extra_fields* is copied from the match into
    ``extra`` under the given key.
    """

    def build(match: Match[str]) -> Classification:
        groups = match.groupdict()
        port_raw = groups.get("port")
        extra = {
            dest: groups[src]
            for dest, src in extra_fields.items()
            if groups.get(src) is not None
        }
        return Classification(
            event_type=event_type,
            category=category,
            severity=severity,
            user=groups.get("user"),
            ip=groups.get("ip"),
            port=int(port_raw) if port_raw and port_raw.isdigit() else None,
            extra=extra,
        )

    return build


_IP = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{3,45})"
_USER = r"(?P<user>[\w.@\\-]+)"
_PORT = r"(?P<port>\d{1,5})"

_SSHD_PATTERNS: list[tuple[Pattern[str], Builder]] = [
    (
        re.compile(rf"Failed (?:password|publickey|keyboard-interactive\S*) for invalid user {_USER} from {_IP}(?: port {_PORT})?"),
        _c(EventType.AUTH_FAILURE, EventCategory.AUTHENTICATION, Severity.WARNING),
    ),
    (
        re.compile(rf"Failed (?:password|publickey|keyboard-interactive\S*) for {_USER} from {_IP}(?: port {_PORT})?"),
        _c(EventType.AUTH_FAILURE, EventCategory.AUTHENTICATION, Severity.WARNING),
    ),
    (
        re.compile(rf"Accepted (?P<method>password|publickey|keyboard-interactive\S*) for {_USER} from {_IP}(?: port {_PORT})?"),
        _c(EventType.AUTH_SUCCESS, EventCategory.AUTHENTICATION, Severity.INFO, method="method"),
    ),
    (
        re.compile(rf"Invalid user {_USER} from {_IP}(?: port {_PORT})?"),
        _c(EventType.INVALID_USER, EventCategory.AUTHENTICATION, Severity.WARNING),
    ),
    (
        re.compile(rf"error: maximum authentication attempts exceeded for(?: invalid user)? {_USER} from {_IP}(?: port {_PORT})?"),
        _c(EventType.AUTH_FAILURE, EventCategory.AUTHENTICATION, Severity.ERROR),
    ),
    (
        re.compile(rf"authentication failure;.*rhost={_IP}(?:\s+user={_USER})?"),
        _c(EventType.AUTH_FAILURE, EventCategory.AUTHENTICATION, Severity.WARNING),
    ),
    (
        re.compile(rf"Connection closed by (?:authenticating|invalid) user {_USER} {_IP}(?: port {_PORT})?"),
        _c(EventType.DISCONNECTION, EventCategory.SSH, Severity.NOTICE),
    ),
    (
        re.compile(rf"Connection (?:closed|reset) by {_IP}(?: port {_PORT})?"),
        _c(EventType.DISCONNECTION, EventCategory.SSH),
    ),
    (
        re.compile(rf"(?:Received disconnect|Disconnected) from(?: (?:authenticating|invalid) user {_USER})? {_IP}(?: port {_PORT})?"),
        _c(EventType.DISCONNECTION, EventCategory.SSH),
    ),
    (
        re.compile(rf"Did not receive identification string from {_IP}"),
        _c(EventType.PORT_PROBE, EventCategory.NETWORK, Severity.NOTICE),
    ),
    (
        re.compile(rf"reverse mapping checking .* \[{_IP}\] .* POSSIBLE BREAK-IN ATTEMPT"),
        _c(EventType.CONNECTION, EventCategory.SSH, Severity.WARNING),
    ),
    (
        re.compile(rf"session opened for user {_USER}"),
        _c(EventType.SESSION_OPENED, EventCategory.SSH),
    ),
    (
        re.compile(rf"session closed for user {_USER}"),
        _c(EventType.SESSION_CLOSED, EventCategory.SSH),
    ),
]

_SUDO_PATTERNS: list[tuple[Pattern[str], Builder]] = [
    (
        re.compile(rf"^\s*{_USER}\s*:\s*user NOT in sudoers.*COMMAND=(?P<command>.+)$"),
        _c(EventType.SUDO_FAILURE, EventCategory.PRIVILEGE_ESCALATION, Severity.ERROR, command="command"),
    ),
    (
        re.compile(rf"^\s*{_USER}\s*:\s*command not allowed.*COMMAND=(?P<command>.+)$"),
        _c(EventType.SUDO_FAILURE, EventCategory.PRIVILEGE_ESCALATION, Severity.ERROR, command="command"),
    ),
    (
        re.compile(rf"^\s*{_USER}\s*:\s*(?P<attempts>\d+) incorrect password attempts?.*COMMAND=(?P<command>.+)$"),
        _c(EventType.SUDO_FAILURE, EventCategory.PRIVILEGE_ESCALATION, Severity.WARNING, command="command", attempts="attempts"),
    ),
    (
        re.compile(rf"^\s*{_USER}\s*:.*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$"),
        _c(EventType.SUDO_COMMAND, EventCategory.PRIVILEGE_ESCALATION, Severity.NOTICE, command="command", target_user="target_user"),
    ),
    (
        re.compile(rf"authentication failure;.*user={_USER}"),
        _c(EventType.SUDO_FAILURE, EventCategory.PRIVILEGE_ESCALATION, Severity.WARNING),
    ),
    (
        re.compile(rf"session opened for user (?P<target_user>\S+?)(?:\(uid=\d+\))? by {_USER}"),
        _c(EventType.SESSION_OPENED, EventCategory.PRIVILEGE_ESCALATION, Severity.INFO, target_user="target_user"),
    ),
]

_SU_PATTERNS: list[tuple[Pattern[str], Builder]] = [
    (
        re.compile(rf"FAILED su for (?P<target_user>\S+) by {_USER}"),
        _c(EventType.SUDO_FAILURE, EventCategory.PRIVILEGE_ESCALATION, Severity.WARNING, target_user="target_user"),
    ),
    (
        re.compile(rf"Successful su for (?P<target_user>\S+) by {_USER}"),
        _c(EventType.SUDO_COMMAND, EventCategory.PRIVILEGE_ESCALATION, Severity.NOTICE, target_user="target_user"),
    ),
    (
        re.compile(rf"session opened for user (?P<target_user>\S+?)(?:\(uid=\d+\))? by {_USER}"),
        _c(EventType.SESSION_OPENED, EventCategory.PRIVILEGE_ESCALATION, Severity.NOTICE, target_user="target_user"),
    ),
    (
        re.compile(rf"authentication failure;.*user={_USER}"),
        _c(EventType.AUTH_FAILURE, EventCategory.PRIVILEGE_ESCALATION, Severity.WARNING),
    ),
]

_USER_MGMT_PATTERNS: list[tuple[Pattern[str], Builder]] = [
    (
        re.compile(rf"new user: name={_USER}(?:, UID=(?P<uid>\d+))?(?:, GID=(?P<gid>\d+))?(?:, home=(?P<home>\S+?),)?(?:.*shell=(?P<shell>[^,\s]+))?"),
        _c(EventType.USER_ADDED, EventCategory.USER_MANAGEMENT, Severity.NOTICE, uid="uid", gid="gid", home="home", shell="shell"),
    ),
    (
        re.compile(rf"new group: name={_USER}"),
        _c(EventType.GROUP_ADDED, EventCategory.USER_MANAGEMENT, Severity.NOTICE),
    ),
    (
        re.compile(rf"delete user '{_USER}'"),
        _c(EventType.USER_DELETED, EventCategory.USER_MANAGEMENT, Severity.WARNING),
    ),
    (
        re.compile(rf"add '{_USER}' to (?:shadow )?group '(?P<group>[^']+)'"),
        _c(EventType.USER_MODIFIED, EventCategory.USER_MANAGEMENT, Severity.NOTICE, group="group"),
    ),
    (
        re.compile(rf"password for '{_USER}' changed"),
        _c(EventType.PASSWORD_CHANGED, EventCategory.USER_MANAGEMENT, Severity.NOTICE),
    ),
    (
        re.compile(rf"(?:account|password for) '{_USER}' locked"),
        _c(EventType.ACCOUNT_LOCKED, EventCategory.USER_MANAGEMENT, Severity.WARNING),
    ),
    (
        re.compile(rf"pam_faillock.*[Cc]onsecutive login failures for user {_USER}"),
        _c(EventType.ACCOUNT_LOCKED, EventCategory.AUTHENTICATION, Severity.WARNING),
    ),
    (
        re.compile(rf"changed user '{_USER}'"),
        _c(EventType.USER_MODIFIED, EventCategory.USER_MANAGEMENT, Severity.NOTICE),
    ),
]

_CRON_PATTERNS: list[tuple[Pattern[str], Builder]] = [
    (
        re.compile(rf"\({_USER}\) CMD \((?P<command>.+)\)"),
        _c(EventType.CRON_JOB, EventCategory.CRON, Severity.INFO, command="command"),
    ),
    (
        re.compile(rf"\({_USER}\) (?P<action>BEGIN EDIT|END EDIT|REPLACE|DELETE|LIST) \((?P<target>[^)]*)\)"),
        _c(EventType.CRON_EDIT, EventCategory.CRON, Severity.NOTICE, action="action", target="target"),
    ),
    (
        re.compile(rf"session opened for user {_USER}"),
        _c(EventType.SESSION_OPENED, EventCategory.CRON),
    ),
]

_SYSTEMD_PATTERNS: list[tuple[Pattern[str], Builder]] = [
    (
        re.compile(r"Failed to start (?P<unit>.+?)\.?$"),
        _c(EventType.SERVICE_FAILED, EventCategory.SERVICE_MANAGEMENT, Severity.ERROR, unit="unit"),
    ),
    (
        re.compile(r"(?P<unit>\S+): Main process exited, code=(?P<code>\S+), status=(?P<status>\S+)"),
        _c(EventType.SERVICE_FAILED, EventCategory.SERVICE_MANAGEMENT, Severity.ERROR, unit="unit", code="code", status="status"),
    ),
    (
        re.compile(r"Stopped (?:target )?(?P<unit>.+?)\.?$"),
        _c(EventType.SERVICE_STOPPED, EventCategory.SERVICE_MANAGEMENT, Severity.NOTICE, unit="unit"),
    ),
    (
        re.compile(r"Stopping (?P<unit>.+?)\.{3}$"),
        _c(EventType.SERVICE_STOPPED, EventCategory.SERVICE_MANAGEMENT, Severity.NOTICE, unit="unit"),
    ),
    (
        re.compile(r"Started (?P<unit>.+?)\.?$"),
        _c(EventType.SERVICE_STARTED, EventCategory.SERVICE_MANAGEMENT, Severity.INFO, unit="unit"),
    ),
    (
        re.compile(r"(?P<unit>\S+) entered failed state"),
        _c(EventType.SERVICE_FAILED, EventCategory.SERVICE_MANAGEMENT, Severity.ERROR, unit="unit"),
    ),
]

_KERNEL_PATTERNS: list[tuple[Pattern[str], Builder]] = [
    (
        re.compile(rf"\[UFW (?P<action>BLOCK|AUDIT|ALLOW)\].*SRC={_IP}\s+DST=(?P<dst>\S+).*?(?:SPT=(?P<spt>\d+))?\s*(?:DPT={_PORT})?"),
        _c(EventType.FIREWALL_BLOCK, EventCategory.FIREWALL, Severity.NOTICE, action="action", dst="dst", src_port="spt"),
    ),
]

_PACKAGE_PATTERNS: list[tuple[Pattern[str], Builder]] = [
    (
        re.compile(r"(?P<action>install|remove|upgrade|purge) (?P<package>\S+)"),
        _c(EventType.PACKAGE_EVENT, EventCategory.PACKAGE_MANAGEMENT, Severity.INFO, action="action", package="package"),
    ),
]

#: Maps a service-name regex to its pattern table and default category.
_SERVICE_TABLES: list[tuple[Pattern[str], list[tuple[Pattern[str], Builder]], EventCategory]] = [
    (re.compile(r"^sshd?$"), _SSHD_PATTERNS, EventCategory.SSH),
    (re.compile(r"^sudo$"), _SUDO_PATTERNS, EventCategory.PRIVILEGE_ESCALATION),
    (re.compile(r"^su(?:-l)?$"), _SU_PATTERNS, EventCategory.PRIVILEGE_ESCALATION),
    (
        re.compile(r"^(useradd|userdel|usermod|groupadd|groupdel|passwd|chpasswd|chage|adduser|deluser)$"),
        _USER_MGMT_PATTERNS,
        EventCategory.USER_MANAGEMENT,
    ),
    (re.compile(r"^(cron|crond|CRON|crontab|anacron)$"), _CRON_PATTERNS, EventCategory.CRON),
    (re.compile(r"^systemd(?:-\w+)?$"), _SYSTEMD_PATTERNS, EventCategory.SERVICE_MANAGEMENT),
    (re.compile(r"^kernel$"), _KERNEL_PATTERNS, EventCategory.SYSTEM),
    (re.compile(r"^(dpkg|apt|yum|dnf)$"), _PACKAGE_PATTERNS, EventCategory.PACKAGE_MANAGEMENT),
    (re.compile(r"^(docker|dockerd|containerd)$"), [], EventCategory.DOCKER),
    (re.compile(r"^ufw$"), _KERNEL_PATTERNS, EventCategory.FIREWALL),
]

# PAM lines appear under many services; fall back to these when the
# service table has no match.
_GENERIC_PATTERNS: list[tuple[Pattern[str], Builder]] = [
    (
        re.compile(rf"pam_faillock.*[Cc]onsecutive login failures for user {_USER}"),
        _c(EventType.ACCOUNT_LOCKED, EventCategory.AUTHENTICATION, Severity.WARNING),
    ),
    (
        re.compile(rf"authentication failure;.*rhost={_IP}(?:\s+user={_USER})?"),
        _c(EventType.AUTH_FAILURE, EventCategory.AUTHENTICATION, Severity.WARNING),
    ),
    (
        re.compile(rf"authentication failure;.*user={_USER}"),
        _c(EventType.AUTH_FAILURE, EventCategory.AUTHENTICATION, Severity.WARNING),
    ),
    (
        re.compile(rf"session opened for user (?P<target_user>\S+?)(?:\(uid=\d+\))? by {_USER}"),
        _c(EventType.SESSION_OPENED, EventCategory.AUTHENTICATION, target_user="target_user"),
    ),
    (
        re.compile(rf"session closed for user {_USER}"),
        _c(EventType.SESSION_CLOSED, EventCategory.AUTHENTICATION),
    ),
]


def classify_message(service: str | None, message: str) -> Classification:
    """Classify one syslog *message* emitted by *service*.

    Falls back to generic PAM patterns and finally to a best-effort
    category derived from the service name. Never raises.
    """
    default_category = EventCategory.SYSTEM
    if service:
        for service_re, table, category in _SERVICE_TABLES:
            if service_re.match(service):
                default_category = category
                for pattern, builder in table:
                    match = pattern.search(message)
                    if match:
                        return builder(match)
                break
    for pattern, builder in _GENERIC_PATTERNS:
        match = pattern.search(message)
        if match:
            classification = builder(match)
            if default_category is not EventCategory.SYSTEM:
                classification.category = default_category
            return classification
    return Classification(category=default_category)
