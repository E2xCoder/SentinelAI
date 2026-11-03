"""Contracts for structured, injection-resistant alert triage.

A triage verdict is ADVISORY. It is shown to the analyst and stored with
the alert, but it never feeds risk scoring, alert generation or automated
response: those stay rule- and policy-based.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from sentinelai.core.exceptions import AIError

VERDICTS = ("benign", "suspicious", "malicious")
LANGUAGES = ("en", "tr", "de")

MAX_SUMMARY_CHARS = 400
MAX_REASONING_CHARS = 1500
MAX_ACTIONS = 5
MAX_ACTION_CHARS = 200


class TriageError(AIError):
    """Base class for triage failures (never fatal: callers fall back)."""


class TriageValidationError(TriageError):
    """The model answered, but the answer is not acceptable."""


class TriageProviderError(TriageError):
    """The provider could not be reached or returned an unusable response.

    ``transient`` is True for failures worth retrying (network errors,
    timeouts, HTTP 429 and 5xx) and False for permanent ones.
    """

    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


def api_key_endpoint_allowed(endpoint: object) -> bool:
    """True when an API key may be sent to ``endpoint``.

    That is the case for ``https://`` endpoints and for loopback hosts
    (``localhost``, ``127.0.0.0/8``, ``::1``) over any http(s) scheme.
    """
    if not isinstance(endpoint, str):
        return False
    try:
        parts = urlsplit(endpoint.strip())
        host = parts.hostname
    except ValueError:
        return False
    scheme = parts.scheme.lower()
    if scheme == "https":
        return bool(host)
    if scheme != "http" or not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class TriageResult:
    """A validated triage verdict."""

    verdict: str
    #: 0.0 .. 1.0
    confidence: float
    summary: str
    reasoning: str
    recommended_actions: tuple[str, ...] = ()
    #: Numbers of the events (1-based, as shown in the prompt) that the
    #: verdict relies on. Always a subset of the events actually provided.
    referenced_event_ids: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "summary": self.summary,
            "reasoning": self.reasoning,
            "recommended_actions": list(self.recommended_actions),
            "referenced_event_ids": list(self.referenced_event_ids),
        }


@dataclass(slots=True)
class TriageOutcome:
    """A verdict plus how it was obtained (needed for eval and auditing)."""

    result: TriageResult
    #: "llm:<model>", "cache:<model>" or "template".
    source: str
    #: True when a model answered AND the answer passed validation.
    valid_llm: bool = False
    cached: bool = False
    latency_seconds: float = 0.0
    attempts: int = 0
    #: Why the model output was not used (None when it was).
    rejection: str | None = None
    language: str = "en"
    notes: list[str] = field(default_factory=list)


class TriageProvider(Protocol):
    """A chat model that can be asked for schema-constrained JSON."""

    #: Short provider name, e.g. "ollama" or "openai".
    name: str
    #: Model identifier sent to the backend.
    model: str

    def complete(self, system: str, user: str, schema: Mapping[str, Any]) -> str:
        """Return the model's raw text answer (expected to be JSON).

        Raises :class:`TriageProviderError` on network errors, timeouts,
        HTTP errors or an unusable response envelope.
        """
        ...
