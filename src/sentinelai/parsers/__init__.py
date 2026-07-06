"""Log parser subsystem.

Importing this package registers all built-in parsers. Plugins can
register additional parsers with :func:`register_parser`.
"""

from sentinelai.parsers import (  # noqa: F401 - imported for registration side effects
    apache,
    docker,
    fail2ban,
    nginx,
    syslog,
    ufw,
)
from sentinelai.parsers.base import (
    LogParser,
    available_parsers,
    detect_parser,
    get_parser,
    register_parser,
)
from sentinelai.parsers.reader import read_events, sample_lines, stream_lines

__all__ = [
    "LogParser",
    "available_parsers",
    "detect_parser",
    "get_parser",
    "read_events",
    "register_parser",
    "sample_lines",
    "stream_lines",
]
