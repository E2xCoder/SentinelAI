"""Self-lockout protection for automatic responses.

:class:`LockoutGuard` answers one question: could blocking this IP cut the
operator off from the machine?  It checks, in order and each only when its
config flag is on: configured admin ranges, the peer of the current SSH
session, the default gateway and the host's own addresses.  It never raises.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import sys
import time
from collections.abc import Callable, Iterable, Mapping

from sentinelai.config.models import ResponseConfig
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("firewall.lockout")

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_PROBE_ADDRESS = ("192.0.2.1", 9)  # RFC 5737 documentation address
_ROUTE_FILE = "/proc/net/route"
_CACHE_TTL = 300.0  # seconds before own addresses / gateways are re-read
_FAIL_CLOSED_REASON = "could not evaluate lockout protection"


def _normalize(value: object) -> _IPAddress | None:
    """Parse *value* into an address; map IPv4-mapped IPv6 to IPv4."""
    if not isinstance(value, str):
        return None
    text = value.strip().split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _normalize_all(values: Iterable[object]) -> set[_IPAddress]:
    result: set[_IPAddress] = set()
    for value in values:
        addr = _normalize(value)
        if addr is not None:
            result.add(addr)
    return result


def default_own_addresses() -> set[str]:
    """Best-effort set of this host's IP addresses, including loopback."""
    found: set[str] = {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
    except Exception:  # noqa: BLE001 - never raise
        hostname = ""
    if hostname:
        try:
            _, _, addrs = socket.gethostbyname_ex(hostname)
            found.update(addrs)
        except Exception:  # noqa: BLE001
            pass
        try:
            for info in socket.getaddrinfo(hostname, None):
                found.add(str(info[4][0]))
        except Exception:  # noqa: BLE001
            pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.connect(_PROBE_ADDRESS)  # UDP connect: no packet is sent
            found.add(str(sock.getsockname()[0]))
    except Exception:  # noqa: BLE001
        pass
    return found


def _gateway_from_hex(value: str) -> str | None:
    if len(value) != 8:
        return None
    try:
        raw = int(value, 16)
    except ValueError:
        return None
    return str(ipaddress.IPv4Address(int.from_bytes(raw.to_bytes(4, "big"), "little")))


def default_gateways() -> set[str]:
    """Default gateway(s) from ``/proc/net/route`` on Linux, else empty."""
    if not sys.platform.startswith("linux"):
        return set()
    gateways: set[str] = set()
    try:
        with open(_ROUTE_FILE, encoding="ascii", errors="replace") as handle:
            lines = handle.read().splitlines()
    except Exception as exc:  # noqa: BLE001
        _LOGGER.warning(
            "Cannot read %s (%s); default-gateway protection is OFF. "
            "Set response.admin_ranges to protect your gateway explicitly.",
            _ROUTE_FILE,
            type(exc).__name__,
        )
        return set()
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 3 or fields[1] != "00000000":
            continue
        gateway = _gateway_from_hex(fields[2])
        if gateway is not None and gateway != "0.0.0.0":
            gateways.add(gateway)
    return gateways


class LockoutGuard:
    """Decides whether blocking an IP could lock the operator out."""

    def __init__(
        self,
        config: ResponseConfig,
        *,
        env: Mapping[str, str] | None = None,
        own_addresses: Callable[[], set[str]] | None = None,
        gateways: Callable[[], set[str]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._clock = clock
        self._gateways_at = 0.0
        self._own_at = 0.0
        self._env: Mapping[str, str] = env if env is not None else os.environ
        self._own_fn: Callable[[], set[str]] = own_addresses or default_own_addresses
        self._gateway_fn: Callable[[], set[str]] = gateways or default_gateways
        self._admin_nets: list[tuple[str, _IPNetwork]] | None = None
        self._ssh_peers: set[_IPAddress] | None = None
        self._gateways: set[_IPAddress] | None = None
        self._own: set[_IPAddress] | None = None

    def refresh(self) -> None:
        """Drop all cached data so it is recomputed on next use."""
        self._admin_nets = None
        self._ssh_peers = None
        self._gateways = None
        self._own = None

    def protected_reason(self, ip: str) -> str | None:
        """Return a short reason when blocking *ip* is unsafe, else None.

        Fails closed: an unexpected internal error yields a reason, so callers
        refuse to block.
        """
        try:
            return self._protected_reason(ip)
        except Exception as exc:  # noqa: BLE001 - guard must never raise
            _LOGGER.warning("Lockout check failed for %r: %s", ip, exc)
            return _FAIL_CLOSED_REASON

    def describe_session_protection(self) -> str:
        """Short diagnostic string of what is currently protected; never raises."""
        try:
            cfg = self._config
            parts: list[str] = []
            if getattr(cfg, "protect_ssh_peer", False):
                peers = sorted(str(peer) for peer in self._get_ssh_peers())
                parts.append(f"ssh_peer={','.join(peers) if peers else 'none'}")
            if getattr(cfg, "protect_gateway", False):
                gws = sorted(str(gw) for gw in self._get_gateways())
                parts.append(f"gateway={','.join(gws) if gws else 'none'}")
            if getattr(cfg, "protect_own_addresses", False):
                parts.append(f"own_addresses={len(self._get_own())}")
            if getattr(cfg, "admin_ranges", None):
                ranges = [cidr for cidr, _ in self._get_admin_nets()]
                parts.append(f"admin_ranges={','.join(ranges) if ranges else 'none'}")
            return "; ".join(parts) if parts else "no lockout protection enabled"
        except Exception as exc:  # noqa: BLE001 - diagnostics must never raise
            return f"lockout protection state unavailable ({type(exc).__name__})"

    def _expired(self, stamp: float) -> bool:
        return (self._clock() - stamp) >= _CACHE_TTL

    # -- checks -----------------------------------------------------------

    def _protected_reason(self, ip: str) -> str | None:
        addr = _normalize(ip)
        if addr is None:
            return None
        cfg = self._config
        if getattr(cfg, "admin_ranges", None):
            for cidr, net in self._get_admin_nets():
                if addr.version == net.version and addr in net:
                    return f"inside admin range {cidr}"
        if getattr(cfg, "protect_ssh_peer", False) and addr in self._get_ssh_peers():
            return "is the address of the current SSH session"
        if getattr(cfg, "protect_gateway", False) and addr in self._get_gateways():
            return "is the default gateway"
        if getattr(cfg, "protect_own_addresses", False) and addr in self._get_own():
            return "is an address of this host"
        return None

    def _get_admin_nets(self) -> list[tuple[str, _IPNetwork]]:
        if self._admin_nets is None:
            nets: list[tuple[str, _IPNetwork]] = []
            for entry in getattr(self._config, "admin_ranges", None) or []:
                if not isinstance(entry, str):
                    continue
                try:
                    net = ipaddress.ip_network(entry.strip(), strict=False)
                except ValueError:
                    continue
                nets.append((str(net), net))
            self._admin_nets = nets
        return self._admin_nets

    def _get_ssh_peers(self) -> set[_IPAddress]:
        if self._ssh_peers is None:
            candidates: list[str] = []
            for key in ("SSH_CONNECTION", "SSH_CLIENT"):
                parts = str(self._env.get(key, "")).split()
                if parts:
                    candidates.append(parts[0])
            self._ssh_peers = _normalize_all(candidates)
        return self._ssh_peers

    def _get_gateways(self) -> set[_IPAddress]:
        if self._gateways is None or self._expired(self._gateways_at):
            # A failing provider is NOT cached as "no gateways": the error
            # propagates to protected_reason(), which then fails closed.
            self._gateways = _normalize_all(self._gateway_fn())
            self._gateways_at = self._clock()
        return self._gateways

    def _get_own(self) -> set[_IPAddress]:
        if self._own is None or self._expired(self._own_at):
            self._own = _normalize_all(self._own_fn())
            self._own_at = self._clock()
        return self._own
