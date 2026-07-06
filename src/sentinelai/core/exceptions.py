"""Exception hierarchy for SentinelAI.

Every internal error derives from :class:`SentinelError` so the CLI can
catch a single base class, render a friendly message and exit cleanly
without ever showing a raw traceback to the operator.
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base class for all SentinelAI errors."""

    exit_code: int = 1


class ConfigError(SentinelError):
    """Raised when configuration is missing, malformed or invalid."""

    exit_code = 2


class ParserError(SentinelError):
    """Raised when a log source cannot be parsed at all."""

    exit_code = 3


class LogSourceError(SentinelError):
    """Raised when a log file cannot be opened or read."""

    exit_code = 4


class ThreatIntelError(SentinelError):
    """Raised for unrecoverable threat-intelligence failures."""

    exit_code = 5


class FirewallError(SentinelError):
    """Raised when the firewall integration layer fails."""

    exit_code = 6


class AIError(SentinelError):
    """Raised when an AI component fails irrecoverably."""

    exit_code = 7


class StorageError(SentinelError):
    """Raised when persistent alert storage fails."""

    exit_code = 8


class PluginError(SentinelError):
    """Raised when a plugin cannot be loaded."""

    exit_code = 9
