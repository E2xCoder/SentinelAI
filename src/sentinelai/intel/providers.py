"""Concrete threat-intelligence providers: AbuseIPDB, VirusTotal, OTX."""

from __future__ import annotations

from sentinelai.intel.base import ProviderResult, ThreatIntelProvider


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB /check endpoint (abuse confidence score)."""

    name = "abuseipdb"
    _URL = "https://api.abuseipdb.com/api/v2/check"

    def _query(self, ip: str) -> ProviderResult:
        response = self._get(
            self._URL,
            headers={"Key": self._config.api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
        )
        data = response.json()["data"]
        confidence = float(data.get("abuseConfidenceScore", 0))
        return ProviderResult(
            score=confidence,
            malicious=confidence >= 50,
            total_reports=data.get("totalReports", 0),
            country=data.get("countryCode"),
            isp=data.get("isp"),
            usage_type=data.get("usageType"),
            is_tor=data.get("isTor", False),
            last_reported=data.get("lastReportedAt"),
        )


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal v3 IP address report (vendor detections)."""

    name = "virustotal"
    _URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    def _query(self, ip: str) -> ProviderResult:
        response = self._get(
            self._URL.format(ip=ip),
            headers={"x-apikey": self._config.api_key},
        )
        attrs = response.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious_count = int(stats.get("malicious", 0))
        suspicious_count = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 1
        score = min(100.0, 100.0 * (malicious_count + 0.5 * suspicious_count) / total * 4)
        return ProviderResult(
            score=score,
            malicious=malicious_count >= 3,
            malicious_engines=malicious_count,
            suspicious_engines=suspicious_count,
            total_engines=total,
            country=attrs.get("country"),
            isp=attrs.get("as_owner"),
            reputation=attrs.get("reputation"),
            tags=attrs.get("tags", []),
        )


class OTXProvider(ThreatIntelProvider):
    """AlienVault OTX pulse membership for an IP."""

    name = "otx"
    _URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    def _query(self, ip: str) -> ProviderResult:
        response = self._get(
            self._URL.format(ip=ip),
            headers={"X-OTX-API-KEY": self._config.api_key},
        )
        data = response.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        score = min(100.0, float(pulses) * 12.0)
        tags: list[str] = []
        for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
            tags.extend(str(t) for t in pulse.get("tags", [])[:3])
        return ProviderResult(
            score=score,
            malicious=pulses >= 2,
            pulse_count=pulses,
            country=data.get("country_code"),
            isp=data.get("asn"),
            tags=sorted(set(tags))[:10],
        )
