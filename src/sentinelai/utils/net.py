"""Network helpers: IP validation and address classification."""

from __future__ import annotations

import ipaddress
import re

_IP_CANDIDATE = re.compile(
    r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])"  # IPv4
    r"|((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4})"  # IPv6 (simplified)
)


def is_valid_ip(value: str | None) -> bool:
    """Return True when *value* is a syntactically valid IPv4/IPv6 address."""
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_public_ip(value: str) -> bool:
    """Return True for globally routable addresses (worth checking in TI)."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_global


def is_private_ip(value: str) -> bool:
    """Return True for RFC1918/loopback/link-local addresses."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def ip_in_networks(value: str, networks: list[str]) -> bool:
    """Return True when *value* falls inside any CIDR in *networks*.

    Invalid CIDR entries are skipped rather than raising, so a typo in an
    allowlist never disables response handling entirely.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    for net in networks:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


def extract_ips(text: str) -> list[str]:
    """Extract all valid IP addresses appearing in *text*, in order."""
    found: list[str] = []
    for match in _IP_CANDIDATE.finditer(text):
        candidate = match.group(0)
        if is_valid_ip(candidate) and candidate not in found:
            found.append(candidate)
    return found
