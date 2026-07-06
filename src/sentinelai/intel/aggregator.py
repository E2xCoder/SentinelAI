"""Fan-out threat-intelligence aggregation with caching and budgets."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sentinelai.config.models import IntelConfig
from sentinelai.core.models import IPReputation
from sentinelai.intel.base import ThreatIntelProvider
from sentinelai.intel.cache import IntelCache
from sentinelai.intel.providers import AbuseIPDBProvider, OTXProvider, VirusTotalProvider
from sentinelai.utils.logging import get_logger
from sentinelai.utils.net import is_public_ip

_LOGGER = get_logger("intel.aggregator")


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

    def close(self) -> None:
        """Release the cache database handle."""
        self._cache.close()
