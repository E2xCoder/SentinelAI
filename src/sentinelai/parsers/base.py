"""Parser framework: base class, registry and format auto-detection.

Adding a new log format means subclassing :class:`LogParser` and
decorating it with :func:`register_parser` — nothing else in the
platform needs to change. Plugins use the exact same mechanism.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from typing import TypeVar

from sentinelai.core.exceptions import ParserError
from sentinelai.core.models import LogEvent
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("parsers")

_REGISTRY: dict[str, type[LogParser]] = {}

P = TypeVar("P", bound=type["LogParser"])


class LogParser(ABC):
    """Base class for all log parsers.

    Subclasses must be stateless with respect to individual lines so a
    single instance can be reused across files and live streams. Parsers
    must never raise on malformed input: return ``None`` for lines they
    cannot understand.
    """

    #: Unique identifier used in config, CLI and the registry.
    name: str = ""
    #: Human-readable description shown in ``sentinel config``.
    description: str = ""
    #: File-name fragments that hint at this format (for detection).
    filename_hints: tuple[str, ...] = ()

    @abstractmethod
    def match_score(self, sample_lines: list[str]) -> float:
        """Return 0..1 confidence that *sample_lines* are in this format."""

    @abstractmethod
    def parse_line(self, line: str) -> LogEvent | None:
        """Parse a single line into a :class:`LogEvent`, or ``None``."""

    def parse_lines(self, lines: Iterable[str], source: str = "") -> Iterator[LogEvent]:
        """Parse an iterable of lines, skipping malformed ones safely."""
        for line in lines:
            stripped = line.rstrip("\r\n")
            if not stripped.strip():
                continue
            try:
                event = self.parse_line(stripped)
            except Exception:  # noqa: BLE001 - a parser bug must not kill a scan
                _LOGGER.debug("Parser %s failed on line: %.120s", self.name, stripped)
                continue
            if event is not None:
                if source and not event.source:
                    event.source = source
                yield event

    def filename_score(self, filename: str) -> float:
        """Return 0..1 confidence based on the file name alone."""
        lowered = filename.lower()
        return 0.6 if any(hint in lowered for hint in self.filename_hints) else 0.0


def register_parser(cls: P) -> P:
    """Class decorator that adds a parser to the global registry."""
    if not cls.name:
        raise ParserError(f"Parser {cls.__name__} must define a non-empty 'name'")
    if cls.name in _REGISTRY:
        raise ParserError(f"Duplicate parser name: {cls.name!r}")
    _REGISTRY[cls.name] = cls
    return cls


def available_parsers() -> dict[str, type[LogParser]]:
    """Return a copy of the parser registry."""
    return dict(_REGISTRY)


def get_parser(name: str) -> LogParser:
    """Instantiate a parser by registry name."""
    try:
        return _REGISTRY[name]()
    except KeyError:
        known = ", ".join(sorted(_REGISTRY))
        raise ParserError(f"Unknown parser {name!r}. Available: {known}") from None


def detect_parser(filename: str, sample_lines: list[str]) -> LogParser:
    """Pick the best parser for a file using name hints + content sampling.

    Content evidence dominates; the file name only breaks ties. Raises
    :class:`ParserError` when nothing matches at all.
    """
    best: tuple[float, LogParser] | None = None
    for cls in _REGISTRY.values():
        parser = cls()
        try:
            score = parser.match_score(sample_lines) + 0.2 * parser.filename_score(filename)
        except Exception:  # noqa: BLE001 - detection must be resilient
            continue
        if best is None or score > best[0]:
            best = (score, parser)
    if best is None or best[0] < 0.15:
        raise ParserError(
            f"Could not detect log format of {filename!r}. "
            "Specify one explicitly with --parser "
            f"(available: {', '.join(sorted(_REGISTRY))})."
        )
    _LOGGER.debug("Detected parser %s (score=%.2f) for %s", best[1].name, best[0], filename)
    return best[1]
