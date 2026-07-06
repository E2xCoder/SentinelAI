"""The firewall boundary: SentinelAI's only view of firewall capability.

SentinelAI never implements firewall logic. It depends exclusively on
this :class:`FirewallController` protocol; the concrete implementation
is the operator's own Firewall Automation project, bound at runtime via
an adapter (see :mod:`sentinelai.firewall.adapters`). This is classic
dependency inversion: the high-level response policy knows *what* to do
(block, unblock), never *how* it is done.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable


@dataclass(slots=True)
class FirewallAction:
    """Record of one action requested through the firewall boundary."""

    action: str
    ip: str
    success: bool
    detail: str = ""
    duration_seconds: int | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "ip": self.ip,
            "success": self.success,
            "detail": self.detail,
            "duration_seconds": self.duration_seconds,
            "timestamp": self.timestamp.isoformat(),
        }


@runtime_checkable
class FirewallController(Protocol):
    """What SentinelAI requires from any firewall implementation."""

    def block_ip(self, ip: str) -> bool:
        """Permanently block *ip*. Returns success."""
        ...

    def unblock_ip(self, ip: str) -> bool:
        """Remove any block for *ip*. Returns success."""
        ...

    def temporary_block(self, ip: str, duration_seconds: int) -> bool:
        """Block *ip* for a limited time. Returns success."""
        ...

    def list_blocked(self) -> list[str]:
        """Return currently blocked IPs."""
        ...

    def is_blocked(self, ip: str) -> bool:
        """Return whether *ip* is currently blocked."""
        ...
