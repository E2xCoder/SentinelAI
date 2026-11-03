"""Account classification for user-management detection rules.

Distinguishes system accounts, well-known service accounts, human users,
and privileged users so R020 (and future rules) can suppress noise from
expected package-installed accounts while still catching real threats.
"""

from __future__ import annotations

import fnmatch
import logging
from enum import Enum
from pathlib import Path

_logger = logging.getLogger("sentinelai.detection.accounts")

_DEFAULT_UID_MIN = 1000

_BUILTIN_SERVICE_ACCOUNTS: tuple[str, ...] = (
    "nobody",
    "nogroup",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "backup",
    "list",
    "irc",
    "gnats",
    "_*",
    "systemd-*",
    "polkitd",
    "sshd",
    "www-data",
    "nginx",
    "apache",
    "httpd",
    "mysql",
    "postgres",
    "mongodb",
    "redis",
    "memcached",
    "rabbitmq",
    "elasticsearch",
    "logstash",
    "kibana",
    "grafana",
    "prometheus",
    "influxdb",
    "tcpdump",
    "messagebus",
    "dbus",
    "avahi",
    "avahi-autoipd",
    "colord",
    "cups",
    "hplip",
    "kernoops",
    "lightdm",
    "gdm",
    "sddm",
    "rtkit",
    "pulse",
    "pipewire",
    "speech-dispatcher",
    "saned",
    "nm-openconnect",
    "nm-openvpn",
    "ntp",
    "chrony",
    "tss",
    "usbmux",
    "geoclue",
    "gnome-initial-setup",
    "ftp",
    "postfix",
    "dovecot",
    "dovenull",
    "snap_daemon",
    "sssd",
    "gluster",
    "haproxy",
    "clamav",
    "openvpn",
    "strongswan",
    "unbound",
    "bind",
    "named",
    "dhcpd",
    "libvirt-*",
    "lxd",
    "cockpit-*",
    "flatpak",
)


class AccountKind(Enum):
    """Classification result for a username/UID pair."""

    PRIVILEGED = "privileged"
    HUMAN = "human"
    SERVICE = "service"
    SYSTEM = "system"


def read_uid_min(path: str = "/etc/login.defs") -> int:
    """Read UID_MIN from login.defs, defaulting to 1000 if unavailable."""
    try:
        p = Path(path)
        if not p.is_file():
            return _DEFAULT_UID_MIN
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[0] == "UID_MIN":
                try:
                    return int(parts[1])
                except ValueError:
                    pass
    except OSError:
        pass
    return _DEFAULT_UID_MIN


def _matches_allowlist(username: str, patterns: list[str]) -> bool:
    """Check if *username* matches any pattern in the allowlist.

    Patterns support shell-style wildcards via :func:`fnmatch.fnmatch`.
    """
    return any(fnmatch.fnmatch(username, pattern) for pattern in patterns)


def classify_account(
    username: str | None,
    uid: str | None,
    *,
    uid_min: int = _DEFAULT_UID_MIN,
    service_allowlist: list[str] | None = None,
) -> AccountKind:
    """Classify a newly created account.

    Priority order:
    1. UID 0 -> PRIVILEGED (always alert)
    2. UID present and < uid_min -> SYSTEM (suppress)
    3. Username on service allowlist -> SERVICE (suppress)
    4. Everything else -> HUMAN (alert)
    """
    if uid is not None and uid != "":
        try:
            uid_int = int(uid)
        except (ValueError, TypeError):
            pass
        else:
            if uid_int == 0:
                return AccountKind.PRIVILEGED
            if uid_int < uid_min:
                return AccountKind.SYSTEM

    patterns = list(_BUILTIN_SERVICE_ACCOUNTS)
    if service_allowlist:
        patterns.extend(service_allowlist)

    if username and _matches_allowlist(username, patterns):
        return AccountKind.SERVICE

    return AccountKind.HUMAN
