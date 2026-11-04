"""Fan-out threat-intelligence aggregation with caching and budgets."""

from __future__ import annotations

import json
import math
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from sentinelai.config.models import IntelConfig
from sentinelai.core.models import IPReputation
from sentinelai.intel.base import ThreatIntelProvider
from sentinelai.intel.cache import IntelCache
from sentinelai.intel.providers import AbuseIPDBProvider, OTXProvider, VirusTotalProvider
from sentinelai.utils.logging import get_logger
from sentinelai.utils.net import is_public_ip

_LOGGER = get_logger("intel.aggregator")

_MAX_LIST = 32
_MAX_STR = 100


def _open_readonly(path: Path) -> sqlite3.Connection | None:
    """Open the cache database read-only; None when it is missing/unreadable."""
    uri = f"file:{quote(path.as_posix(), safe='/:')}?mode=ro"
    try:
        return sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        _LOGGER.debug("Offline cache database unavailable: treating as no cache")
        return None


def _clean_strings(value: Any) -> list[str]:
    """Keep only string items, capped in count and length."""
    if not isinstance(value, list):
        return []
    return [item[:_MAX_STR] for item in value if isinstance(item, str)][:_MAX_LIST]


def _finite_score(raw: Any) -> float | None:
    """Return ``raw`` clamped to 0..100, or None when not a finite number."""
    if not isinstance(raw, (int, float)) or isinstance(raw, bool):
        return None
    try:
        value = float(raw)
    except OverflowError:
        return None
    return min(100.0, max(0.0, value)) if math.isfinite(value) else None


def _sanitize_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Validate a cached payload; returns ``(clean_payload, reliable)``."""
    clean: dict[str, Any] = {}
    reliable = True
    if "score" in payload:
        score = _finite_score(payload["score"])
        reliable = score is not None
        clean["score"] = 0.0 if score is None else score
    if "malicious" in payload:
        flag = payload["malicious"]
        clean["malicious"] = flag if isinstance(flag, bool) else False
        reliable = reliable and isinstance(flag, bool)
    for key in ("country", "isp"):
        if isinstance(payload.get(key), str):
            clean[key] = payload[key][:_MAX_STR]
    for key in ("tags", "sources"):
        if key in payload:
            clean[key] = _clean_strings(payload[key])
            reliable = reliable and isinstance(payload[key], list)
    return clean, reliable


class ThreatIntelAggregator:
    """Queries all enabled providers for an IP and merges the verdicts.

    * Private/reserved IPs are never sent to external services.
    * Every provider result is cached on disk with a TTL.
    * A per-run lookup budget prevents a huge scan from burning quotas.
    * Provider failures degrade to partial results, recorded in
      ``IPReputation.errors``.
    """

    def __init__(self, config: IntelConfig, state_dir: Path) -> None:
        self._config = config
        self._cache = IntelCache(state_dir / "intel_cache.db", config.cache_ttl_seconds)
        self._lookups_done = 0
        self._memo: dict[str, IPReputation] = {}
        self._providers: list[ThreatIntelProvider] = []
        if config.abuseipdb.enabled:
            self._providers.append(AbuseIPDBProvider(config.abuseipdb, config.timeout_seconds))
        if config.virustotal.enabled:
            self._providers.append(VirusTotalProvider(config.virustotal, config.timeout_seconds))
        if config.otx.enabled:
            self._providers.append(OTXProvider(config.otx, config.timeout_seconds))
        self._offline = bool(getattr(config, "offline", False))
        self._offline_conn: sqlite3.Connection | None = None
        if self._offline:
            # IntelCache.get() deletes expired rows, which offline mode must
            # keep; read the cache directly (the schema exists already).
            self._offline_conn = _open_readonly(state_dir / "intel_cache.db")
            _LOGGER.debug("Offline mode active: threat-intel lookups use the local cache only")

    def _offline_get(self, provider: str, ip: str) -> tuple[dict[str, Any], bool] | None:
        """Return ``(sanitised_payload, is_stale)`` from the cache, or None.

        ``is_stale`` is True for expired entries and for unreliable payloads.
        """
        if self._offline_conn is None:
            return None
        try:
            row = self._offline_conn.execute(
                "SELECT payload, created_at FROM intel_cache WHERE provider = ? AND ip = ?",
                (provider, ip),
            ).fetchone()
            if row is None:
                return None
            payload = json.loads(row[0])
            if not isinstance(payload, dict):
                return None
            clean, reliable = _sanitize_payload(payload)
            ttl = self._config.cache_ttl_seconds
            expired = bool(ttl and time.time() - float(row[1]) > ttl)
            return clean, expired or not reliable
        except (sqlite3.Error, ValueError, TypeError, RecursionError):
            _LOGGER.exception("Offline cache read failed")
            return None

    @property
    def enabled(self) -> bool:
        """True when at least one provider is configured."""
        return self._config.enabled and bool(self._providers)

    def lookup(self, ip: str) -> IPReputation:
        """Return the merged reputation for *ip* (never raises)."""
        if ip in self._memo:
            return self._memo[ip]
        reputation = IPReputation(ip=ip, checked_at=datetime.now(timezone.utc))
        if not is_public_ip(ip):
            reputation.tags.append("private-address")
            self._memo[ip] = reputation
            return reputation
        if self._offline:
            return self._lookup_offline(ip, reputation)
        scores: list[float] = []
        for provider in self._providers:
            result = self._cache.get(provider.name, ip)
            if result is None:
                if self._lookups_done >= self._config.max_lookups_per_run:
                    reputation.errors.append(
                        f"{provider.name}: lookup budget exhausted"
                    )
                    continue
                self._lookups_done += 1
                live = provider.lookup(ip)
                if live is None:
                    reputation.errors.append(f"{provider.name}: lookup failed")
                    continue
                result = dict(live)
                self._cache.put(provider.name, ip, result)
            reputation.sources[provider.name] = result
            scores.append(float(result.get("score", 0.0)))
            if result.get("malicious"):
                reputation.malicious = True
            reputation.country = reputation.country or result.get("country")
            reputation.isp = reputation.isp or result.get("isp")
            for tag in result.get("tags", []) or []:
                if tag not in reputation.tags:
                    reputation.tags.append(str(tag))
        if scores:
            reputation.score = max(scores)
        self._memo[ip] = reputation
        return reputation

    def _lookup_offline(self, ip: str, reputation: IPReputation) -> IPReputation:
        """Answer from the cache only; no provider call, no budget use."""
        scores: list[float] = []
        stale_flags: list[bool] = []
        for provider in self._providers:
            cached = self._offline_get(provider.name, ip)
            if cached is None:
                continue
            result, is_stale = cached
            stale_flags.append(is_stale)
            reputation.sources[provider.name] = result
            scores.append(float(result.get("score", 0.0)))
            if result.get("malicious"):
                reputation.malicious = True
            reputation.country = reputation.country or result.get("country")
            reputation.isp = reputation.isp or result.get("isp")
            for tag in result.get("tags", []) or []:
                if tag not in reputation.tags:
                    reputation.tags.append(str(tag))
        if not scores:
            # Nothing cached: same "not checked" result as with intel disabled.
            reputation = IPReputation(ip=ip)
        else:
            reputation.score = max(scores)
            if any(stale_flags):
                if "stale-cache" not in reputation.tags:
                    reputation.tags.append("stale-cache")
                if all(stale_flags):  # only expired data: discount it
                    reputation.score = reputation.score / 2
        self._memo[ip] = reputation
        return reputation

    def close(self) -> None:
        """Release the cache database handle."""
        if self._offline_conn is not None:
            self._offline_conn.close()
            self._offline_conn = None
        self._cache.close()
