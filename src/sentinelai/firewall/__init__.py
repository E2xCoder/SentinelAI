"""Firewall integration boundary (dependency inversion layer)."""

from sentinelai.firewall.adapters import (
    CommandAdapter,
    DryRunAdapter,
    PythonModuleAdapter,
    create_firewall,
)
from sentinelai.firewall.interface import FirewallAction, FirewallController
from sentinelai.firewall.responder import AutoResponder

__all__ = [
    "AutoResponder",
    "CommandAdapter",
    "DryRunAdapter",
    "FirewallAction",
    "FirewallController",
    "PythonModuleAdapter",
    "create_firewall",
]
