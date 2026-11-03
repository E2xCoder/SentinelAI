"""Orchestration of structured alert triage: cache, provider, retries, fallback.

Triage is ADVISORY. The engine only reads an alert and returns a
:class:`TriageOutcome`; it never touches risk, severity, rules, the responder
or the firewall, and :meth:`TriageEngine.triage` never raises.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from sentinelai.ai.triage import (
    TRIAGE_SCHEMA,
    build_prompt,
    parse_triage,
    sanitize_text,
    template_triage,
)
from sentinelai.ai.triage_cache import TriageCache, prompt_sha
from sentinelai.ai.triage_models import (
    TriageOutcome,
    TriageProvider,
    TriageProviderError,
    TriageResult,
    TriageValidationError,
)
from sentinelai.ai.triage_providers import create_provider
from sentinelai.config.models import LLMConfig
from sentinelai.core.models import Alert
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("ai.triage_engine")

_REJECTION_CHARS = 160


def _describe(exc: Exception) -> str:
    """Short, safe description of *exc* (no prompt, no raw model output)."""
    return f"{type(exc).__name__}: {sanitize_text(exc, _REJECTION_CHARS)}"


def _is_transient(exc: Exception) -> bool:
    """True when *exc* is flagged as a retryable (transient) provider failure."""
    return bool(getattr(exc, "transient", False))


class TriageEngine:
    """Runs one alert through cache -> provider -> validation -> template."""

    def __init__(
        self,
        config: LLMConfig,
        *,
        provider: TriageProvider | None = None,
        cache: TriageCache | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._config = config
        self._provider = provider
        self._cache = cache
        self._sleep = sleep
        self._clock = clock
        #: Resources this engine created itself (and therefore closes).
        self._owned_provider: TriageProvider | None = None

    def triage(self, alert: Alert) -> TriageOutcome:
        """Return a triage outcome for *alert*; never raises."""
        try:
            return self._triage(alert)
        except Exception as exc:  # noqa: BLE001 - triage must never break a scan
            _LOGGER.warning("Unexpected triage failure (%s)", type(exc).__name__)
            return self._template(alert, f"unexpected error: {type(exc).__name__}")

    def close(self) -> None:
        """Release resources created by this engine (injected ones stay open)."""
        owned = self._owned_provider
        self._owned_provider = None
        if owned is None:
            return
        closer = getattr(owned, "close", None)
        if callable(closer):
            try:
                closer()
            except Exception:  # noqa: BLE001 - closing is best effort
                _LOGGER.debug("Triage provider close failed")

    # ------------------------------------------------------------------ #

    def _triage(self, alert: Alert) -> TriageOutcome:
        config = self._config
        if not config.enabled:
            return self._template(alert, "llm disabled")

        prompt = build_prompt(alert, config.language)
        digest = prompt_sha(prompt.system, prompt.user)

        cached = self._cache_get(alert.fingerprint, digest)
        if cached is not None:
            return TriageOutcome(
                result=cached,
                source=f"cache:{config.model}",
                valid_llm=True,
                cached=True,
                language=config.language,
            )

        try:
            provider = self._get_provider()
        except TriageProviderError as exc:
            return self._template(alert, _describe(exc))

        total = 1 + max(0, int(config.max_retries))
        budget = config.timeout_seconds * total
        rejection: str | None = None
        attempts = 0
        started = self._clock()
        for attempt in range(total):
            attempts = attempt + 1
            try:
                raw = provider.complete(prompt.system, prompt.user, TRIAGE_SCHEMA)
                result = parse_triage(raw, prompt.event_count)
            except (TriageProviderError, TriageValidationError) as exc:
                rejection = _describe(exc)
                # At temperature 0 only a transient transport failure can
                # change on a retry; a rejected or hard-failed answer cannot.
                if not (isinstance(exc, TriageProviderError) and _is_transient(exc)):
                    break
                if attempt >= total - 1 or self._clock() - started > budget:
                    break
                self._sleep(config.retry_backoff_seconds * 2**attempt)
                continue
            self._cache_put(alert.fingerprint, digest, result)
            return TriageOutcome(
                result=result,
                source=f"llm:{config.model}",
                valid_llm=True,
                latency_seconds=self._clock() - started,
                attempts=attempts,
                language=config.language,
            )

        outcome = self._template(alert, rejection or "no valid model answer")
        outcome.attempts = attempts
        outcome.latency_seconds = self._clock() - started
        return outcome

    def _template(self, alert: Alert, rejection: str) -> TriageOutcome:
        return TriageOutcome(
            result=template_triage(alert, self._config.language),
            source="template",
            valid_llm=False,
            rejection=rejection,
            language=self._config.language,
        )

    def _get_provider(self) -> TriageProvider:
        if self._provider is None:
            self._provider = create_provider(self._config)
            self._owned_provider = self._provider
        return self._provider

    def _cache_model(self) -> str:
        """Cache key component: switching provider/endpoint/model never reuses entries."""
        config = self._config
        return f"{config.provider}|{config.endpoint}|{config.model}"

    def _cache_get(self,fingerprint: str, digest: str) -> TriageResult | None:
        if self._cache is None:
            return None
        try:
            return self._cache.get(fingerprint, self._cache_model(), self._config.language, digest)
        except Exception as exc:  # noqa: BLE001 - a broken cache is just a miss
            _LOGGER.warning("Triage cache read failed (%s)", type(exc).__name__)
            return None

    def _cache_put(self, fingerprint: str, digest: str, result: TriageResult) -> None:
        if self._cache is None:
            return
        try:
            self._cache.put(
                fingerprint, self._cache_model(), self._config.language, digest, result
            )
        except Exception as exc:  # noqa: BLE001 - a failed write must not drop the verdict
            _LOGGER.warning("Triage cache write failed (%s)", type(exc).__name__)
