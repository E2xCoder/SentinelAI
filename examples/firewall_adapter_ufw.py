"""Example UFW-backed firewall controller for SentinelAI.

This file is an EXAMPLE for the operator's own Firewall Automation project.
It lives outside the SentinelAI package and SentinelAI core never imports
it. Copy it into your firewall project (so it is importable, e.g. on
``PYTHONPATH``) and point SentinelAI at it in ``config.yaml``::

    firewall:
      adapter: python
      module: firewall_adapter_ufw        # wherever you copied this file
      attribute: UfwFirewall
      init_kwargs:
        sudo_prefix: ["sudo", "-n"]       # default; use [] when running as root
        ufw_binary: ufw
        timeout_seconds: 15

``UfwFirewall`` implements the ``FirewallController`` protocol
(``block_ip``, ``unblock_ip``, ``temporary_block``, ``list_blocked``,
``is_blocked``) using only list-argument ``subprocess.run`` calls
(``shell=False``). Every IP is validated with :mod:`ipaddress` first
(input containing ``%``, whitespace or ``/`` is rejected, IPv4-mapped IPv6
is canonicalised to IPv4) and private, loopback, multicast, unspecified
and link-local targets are refused, so no command is ever built from
unvalidated input.

Behaviour notes:

* Blocks use ``ufw insert 1 deny from <ip>``: UFW is first-match, so an
  appended rule could be shadowed by an earlier ALLOW. (UFW rejects
  ``insert 1`` on a completely empty rule set; that case returns False.)
* ``sudo -n`` is the default prefix so a missing NOPASSWD rule fails fast
  instead of waiting for a password on a tty. Allow only the needed
  ``ufw`` commands in sudoers.
* Every call runs with ``stdin`` closed and ``LC_ALL=C LANG=C`` so output
  parsing never depends on the locale.
* A block is refused (returns False, warning logged) while UFW reports
  ``Status: inactive``, because the rule would not be enforced.

Note on ``firewall_manager.py``: your existing script runs a top-level
``while True`` menu with no ``if __name__ == "__main__":`` guard, so
importing it would start the menu. If you want to reuse that file, wrap the
menu loop in ``if __name__ == "__main__":``. This example does not import
it and is self-contained.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import subprocess  # noqa: S404 - used without shell, args validated
from collections.abc import Callable

_LOGGER = logging.getLogger("ufw_firewall")

_Runner = Callable[..., "subprocess.CompletedProcess[str]"]

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
# Characters that never belong in a bare IP (zone ids, CIDR, padding/injection).
_FORBIDDEN = re.compile(r"[%/\s]")

# Optional "[ 1] " prefix printed by ``ufw status numbered``.
_NUMBER_PREFIX = re.compile(r"^\s*\[\s*\d+\s*\]\s*")
# Direction words UFW may print after the action ("DENY IN").
_DIRECTIONS = frozenset({"IN", "OUT", "FWD"})
# UFW is first-match: insert at the top so an earlier ALLOW cannot shadow the block.
_BLOCK_VERB = ("insert", "1", "deny")


def _canonical(addr: _IPAddress) -> _IPAddress:
    """Map IPv4-mapped IPv6 (``::ffff:a.b.c.d``) to plain IPv4."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _parse_target(ip: str) -> _IPAddress | None:
    """Return a parsed, canonical, blockable address or ``None`` if refused."""
    if not isinstance(ip, str) or not ip or _FORBIDDEN.search(ip):
        return None
    try:
        addr = _canonical(ipaddress.ip_address(ip))
    except ValueError:
        return None
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_link_local
    ):
        return None
    return addr


def _parse_status_line(line: str) -> str | None:
    """Extract the denied source IP from one ``ufw status`` line, if any.

    Handles ``Anywhere  DENY  1.2.3.4``, ``Anywhere (v6)  DENY  2001:db8::1``,
    ``[ 1] Anywhere  DENY IN  1.2.3.4`` and ignores everything else
    (headers, ALLOW rules, CIDR ranges, port rules, junk).
    """
    tokens = _NUMBER_PREFIX.sub("", line).split()
    if len(tokens) < 3 or tokens[0] != "Anywhere":
        return None
    try:
        idx = tokens.index("DENY")
    except ValueError:
        return None
    rest = [t for t in tokens[idx + 1 :] if t not in _DIRECTIONS]
    if not rest:
        return None
    try:
        return str(_canonical(ipaddress.ip_address(rest[0])))
    except ValueError:
        return None


class UfwFirewall:
    """``FirewallController`` implementation on top of the ``ufw`` CLI."""

    def __init__(
        self,
        sudo_prefix: tuple[str, ...] = ("sudo", "-n"),
        ufw_binary: str = "ufw",
        timeout_seconds: int = 15,
        runner: _Runner | None = None,
    ) -> None:
        """Configure the controller.

        ``sudo_prefix`` is prepended to every command (default ``sudo -n``
        so a missing NOPASSWD rule fails fast; pass ``()`` when already
        root). ``runner`` replaces ``subprocess.run`` (for tests).
        """
        if not ufw_binary or not isinstance(ufw_binary, str):
            raise ValueError("ufw_binary must be a non-empty string")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise ValueError("timeout_seconds must be an int")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        # Config files deliver lists; normalise to a tuple of strings.
        prefix = tuple(sudo_prefix)
        if not all(isinstance(p, str) and p for p in prefix):
            raise ValueError("sudo_prefix must contain non-empty strings")
        self._prefix: tuple[str, ...] = prefix
        self._ufw = ufw_binary
        self._timeout = timeout_seconds
        self._runner: _Runner = runner if runner is not None else subprocess.run

    # -- internals ---------------------------------------------------------

    def _run(self, *ufw_args: str) -> subprocess.CompletedProcess[str] | None:
        """Run ``[*sudo, ufw, *args]`` without a shell; ``None`` on failure."""
        args = [*self._prefix, self._ufw, *ufw_args]
        env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
        try:
            return self._runner(  # noqa: S603 - list args, shell=False, validated input
                args,
                shell=False,
                stdin=subprocess.DEVNULL,
                env=env,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None

    def _is_inactive(self) -> bool:
        """Return whether ``ufw status`` reports the firewall as inactive."""
        result = self._run("status")
        return result is not None and "Status: inactive" in str(result.stdout)

    def _rule(self, verb: tuple[str, ...], ip: str, name: str, *, block: bool = False) -> bool:
        addr = _parse_target(ip)
        if addr is None:
            _LOGGER.warning("%s refused for ip %r", name, str(ip)[:64])
            return False
        if block and self._is_inactive():
            _LOGGER.warning(
                "%s refused for %s: ufw is inactive, block would not be enforced", name, addr
            )
            return False
        result = self._run(*verb, "from", str(addr))
        ok = result is not None and result.returncode == 0
        _LOGGER.info("%s %s: %s", name, addr, "ok" if ok else "failed")
        return ok

    # -- FirewallController ------------------------------------------------

    def block_ip(self, ip: str) -> bool:
        """Block *ip* with ``ufw insert 1 deny from <ip>``. Returns success."""
        return self._rule(_BLOCK_VERB, ip, "block_ip", block=True)

    def unblock_ip(self, ip: str) -> bool:
        """Remove the block with ``ufw delete deny from <ip>``. Returns success."""
        return self._rule(("delete", "deny"), ip, "unblock_ip")

    def temporary_block(self, ip: str, duration_seconds: int) -> bool:
        """Install the deny rule for *ip*; expiry is NOT handled here.

        UFW has no native rule expiry. This method only validates that
        *duration_seconds* is a positive int and then adds the same
        ``insert 1 deny`` rule as :meth:`block_ip`. SentinelAI's reaper
        (``sentinel respond --reap``, also run periodically by
        ``sentinel live``) removes the rule through :meth:`unblock_ip`
        once the TTL expires.
        """
        if (
            isinstance(duration_seconds, bool)
            or not isinstance(duration_seconds, int)
            or duration_seconds <= 0
        ):
            _LOGGER.warning("temporary_block refused: duration must be a positive int")
            return False
        return self._rule(_BLOCK_VERB, ip, "temporary_block", block=True)

    def list_blocked(self) -> list[str]:
        """Return sorted unique IPs with a ``DENY`` rule in ``ufw status``.

        Returns an empty list if the command fails; unparsable lines are
        ignored.
        """
        result = self._run("status")
        if result is None or result.returncode != 0:
            _LOGGER.warning("list_blocked failed")
            return []
        found: set[str] = set()
        for line in str(result.stdout).splitlines():
            parsed = _parse_status_line(line)
            if parsed is not None:
                found.add(parsed)
        return sorted(found)

    def is_blocked(self, ip: str) -> bool:
        """Return whether *ip* currently has a deny rule."""
        addr = _parse_target(ip)
        if addr is None:
            return False
        return str(addr) in self.list_blocked()
