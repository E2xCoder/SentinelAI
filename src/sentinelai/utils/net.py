"""Network helpers: IP validation and address classification."""

from __future__ import annotations

import ipaddress
import re

_IP_CANDIDATE = re.compile(
    r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])"  # IPv4
    r"|((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4})"  # IPv6 (simplified)
)


_MAX_IP_TEXT = 64


def _canonical_address(
    value: object,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a plain textual IP into a canonical address object (or None)."""
    if not isinstance(value, str) or not value or len(value) > _MAX_IP_TEXT:
        return None
    if value != value.strip() or any(ch.isspace() for ch in value):
        return None
    if "%" in value or "/" in value:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def canonical_ip(value: str) -> str | None:
    """Return the canonical text of a plain IPv4/IPv6 address, else None.

    Rejects whitespace, ``%zone`` ids and ``/prefix`` suffixes. IPv4-mapped
    IPv6 (``::ffff:a.b.c.d``) is mapped to the IPv4 string; output is
    lower-case and compressed.
    """
    addr = _canonical_address(value)
    return str(addr) if addr is not None else None


def blockable_reason(ip: str) -> str | None:
    """Return why *ip* must never be blocked by core code, or None when it may be."""
    addr = _canonical_address(ip)
    if addr is None:
        return "not a valid IP address"
    text = str(addr)
    if addr.is_unspecified:
        kind = "an unspecified address"
    elif addr.is_loopback:
        kind = "a loopback address"
    elif addr.is_multicast:
        kind = "a multicast address"
    elif addr.is_link_local:
        kind = "a link-local address"
    elif text == "255.255.255.255":
        kind = "the broadcast address"
    elif addr.is_reserved:
        kind = "a reserved address"
    else:
        return None
    return f"{text} is {kind}; it is never blocked"


def is_valid_ip(value: str | None) -> bool:
    """Return True when *value* is a plain IPv4/IPv6 address (no zone or prefix)."""
    if not value:
        return False
    return canonical_ip(value) is not None


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
    addr = _canonical_address(value)
    if addr is None:
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
