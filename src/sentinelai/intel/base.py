"""Threat-intelligence provider framework."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import requests

from sentinelai.config.models import IntelProviderConfig
from sentinelai.intel.ratelimit import RateLimiter
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("intel")


class ProviderResult(dict[str, Any]):
    """Normalized provider verdict.

    Keys every provider fills in:

    * ``score`` (float 0-100, higher = more malicious)
    * ``malicious`` (bool)
    * plus provider-specific detail fields.
    """


class ThreatIntelProvider(ABC):
    """Base class for a single TI source.

    Subclasses implement :meth:`_query`; the base class provides rate
    limiting and uniform error handling. A provider failure returns
    ``None`` — it never propagates and never blocks detection.
    """

    #: Registry/config name, e.g. ``abuseipdb``.
    name: str = ""

    def __init__(self, config: IntelProviderConfig, timeout: float) -> None:
        self._config = config
        self._timeout = timeout
        self._limiter = RateLimiter(config.requests_per_minute)
        self._session = requests.Session()

    @abstractmethod
    def _query(self, ip: str) -> ProviderResult:
        """Perform the actual API request. May raise; caller handles it."""

    def lookup(self, ip: str) -> ProviderResult | None:
        """Rate-limited, failure-safe lookup of one IP."""
        if not self._limiter.acquire():
            _LOGGER.warning("Rate limit saturated for provider %s; skipping %s", self.name, ip)
            return None
        try:
            return self._query(ip)
        except requests.RequestException as exc:
            _LOGGER.warning("Provider %s failed for %s: %s", self.name, ip, exc)
            return None
        except (KeyError, ValueError, TypeError) as exc:
            _LOGGER.warning("Provider %s returned unexpected data for %s: %s", self.name, ip, exc)
            return None

    def _get(self, url: str, **kwargs: Any) -> requests.Response:
        """HTTP GET with the provider timeout; raises for HTTP errors."""
        response = self._session.get(url, timeout=self._timeout, **kwargs)
        response.raise_for_status()
        return response
