"""Typed configuration models.

Configuration is expressed as plain dataclasses with defaults so the
platform runs out of the box, and every section can be overridden from
``config.yaml`` or ``SENTINELAI_*`` environment variables.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any

from sentinelai.core.exceptions import ConfigError
from sentinelai.utils.paths import default_state_dir

#: Detection fields the tuning loop (and the tuning overlay) may change.
TUNABLE_DETECTION_FIELDS: tuple[str, ...] = (
    "brute_force_attempts",
    "brute_force_window_seconds",
    "password_spray_users",
    "password_spray_window_seconds",
    "credential_stuffing_attempts",
    "credential_stuffing_window_seconds",
    "repeated_failure_attempts",
    "repeated_failure_window_seconds",
    "port_scan_ports",
    "port_scan_window_seconds",
    "impossible_frequency_attempts",
    "impossible_frequency_window_seconds",
    "suppressions",
)

_RULE_ID_RE = re.compile(r"[A-Z]{1,3}[0-9]{3}")
_USER_RE = re.compile(r"[A-Za-z0-9_.@-]{1,64}")
_SUPPRESSION_KEYS = frozenset({"rule", "user", "ip", "expires", "note"})
_MAX_NOTE_LENGTH = 200


@dataclass(frozen=True, slots=True)
class Suppression:
    """A time-boxed suppression of one rule for a user and/or an IP range."""

    rule: str
    user: str | None
    ip: str | None
    expires: datetime
    note: str = ""


def _parse_expires(value: Any, where: str) -> datetime:
    """Normalize an expiry value to a timezone-aware UTC datetime."""
    if isinstance(value, str):
        text = value.strip()
        try:
            if len(text) == 10:
                value = date.fromisoformat(text)
            else:
                if text[-1:] in ("Z", "z"):
                    text = text[:-1] + "+00:00"
                value = datetime.fromisoformat(text)
        except ValueError:
            raise ConfigError(
                f"{where}: 'expires' must be an ISO-8601 date or datetime, got {value!r}"
            ) from None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, date):
        return datetime.combine(value, time(23, 59, 59, 999999), tzinfo=timezone.utc)
    raise ConfigError(f"{where}: 'expires' must be a date, datetime or ISO-8601 string")


def _parse_suppression(entry: Any, where: str) -> Suppression:
    if not isinstance(entry, Mapping):
        raise ConfigError(f"{where} must be a mapping")
    unknown = sorted(str(key) for key in entry if key not in _SUPPRESSION_KEYS)
    if unknown:
        allowed = ", ".join(sorted(_SUPPRESSION_KEYS))
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}; allowed: {allowed}")

    rule = entry.get("rule")
    if not isinstance(rule, str) or not _RULE_ID_RE.fullmatch(rule):
        raise ConfigError(f"{where}: 'rule' is required and must look like R001")

    user = entry.get("user")
    ip = entry.get("ip")
    if user is None and ip is None:
        raise ConfigError(f"{where}: at least one of 'user' or 'ip' is required")
    if user is not None and (not isinstance(user, str) or not _USER_RE.fullmatch(user)):
        raise ConfigError(
            f"{where}: 'user' must be 1-64 characters of letters, digits, '_', '.', '@', '-'"
        )
    normalized_ip: str | None = None
    if ip is not None:
        if not isinstance(ip, str):
            raise ConfigError(f"{where}: 'ip' must be an IP address or CIDR string")
        try:
            normalized_ip = str(ipaddress.ip_network(ip.strip(), strict=False))
        except ValueError:
            raise ConfigError(
                f"{where}: 'ip' is not a valid IP address or CIDR: {ip!r}"
            ) from None

    if entry.get("expires") is None:
        raise ConfigError(f"{where}: 'expires' is required")
    try:
        expires = _parse_expires(entry["expires"], where)
    except (OverflowError, ValueError):
        raise ConfigError(
            f"{where}: 'expires' is out of the supported range: {entry['expires']!r}"
        ) from None

    note = entry.get("note", "")
    if not isinstance(note, str) or len(note) > _MAX_NOTE_LENGTH:
        raise ConfigError(
            f"{where}: 'note' must be a string of at most {_MAX_NOTE_LENGTH} characters"
        )
    return Suppression(rule=rule, user=user, ip=normalized_ip, expires=expires, note=note)


def parse_suppressions(raw: Sequence[Mapping[str, Any]]) -> list[Suppression]:
    """Validate raw suppression mappings and return normalized objects."""
    if not isinstance(raw, (list, tuple)):
        raise ConfigError("detection.suppressions must be a list")
    return [
        _parse_suppression(entry, f"detection.suppressions[{index}]")
        for index, entry in enumerate(raw)
    ]


@dataclass(slots=True)
class DetectionConfig:
    """Thresholds for the rule engine."""

    brute_force_attempts: int = 5
    brute_force_window_seconds: int = 300
    password_spray_users: int = 4
    password_spray_window_seconds: int = 600
    credential_stuffing_attempts: int = 8
    credential_stuffing_window_seconds: int = 300
    repeated_failure_attempts: int = 10
    repeated_failure_window_seconds: int = 900
    port_scan_ports: int = 10
    port_scan_window_seconds: int = 60
    impossible_frequency_attempts: int = 10
    impossible_frequency_window_seconds: int = 10
    suspicious_hours_start: int = 0
    suspicious_hours_end: int = 5
    alert_cooldown_seconds: int = 300
    enabled_rules: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    service_account_allowlist: list[str] = field(default_factory=list)
    uid_min: int = 0
    suppressions: list[dict[str, Any]] = field(default_factory=list)

    def parsed_suppressions(self) -> list[Suppression]:
        """Return the validated, normalized suppressions."""
        return parse_suppressions(self.suppressions)

    def validate(self) -> None:
        for name in (
            "brute_force_attempts",
            "brute_force_window_seconds",
            "password_spray_users",
            "password_spray_window_seconds",
            "credential_stuffing_attempts",
            "credential_stuffing_window_seconds",
            "repeated_failure_attempts",
            "repeated_failure_window_seconds",
            "port_scan_ports",
            "port_scan_window_seconds",
            "impossible_frequency_attempts",
            "impossible_frequency_window_seconds",
            "alert_cooldown_seconds",
        ):
            value = getattr(self, name)
            if not math.isfinite(value) or value <= 0:
                raise ConfigError(f"detection.{name} must be a positive integer")
        for name in ("suspicious_hours_start", "suspicious_hours_end"):
            if not 0 <= getattr(self, name) <= 23:
                raise ConfigError(f"detection.{name} must be an hour between 0 and 23")
        parse_suppressions(self.suppressions)


@dataclass(slots=True)
class RiskConfig:
    """Per-rule risk score multipliers."""

    rule_weights: dict[str, float] = field(default_factory=dict)

    def validate(self) -> None:
        if not isinstance(self.rule_weights, dict):
            raise ConfigError("risk.rule_weights must be a mapping of rule id to weight")
        for rule, weight in self.rule_weights.items():
            if not isinstance(rule, str) or not _RULE_ID_RE.fullmatch(rule):
                raise ConfigError(f"risk.rule_weights: invalid rule id {rule!r}")
            if (
                isinstance(weight, bool)
                or not isinstance(weight, (int, float))
                or not math.isfinite(weight)
                or not 0.5 <= weight <= 1.5
            ):
                raise ConfigError(
                    f"risk.rule_weights[{rule}] must be a number between 0.5 and 1.5"
                )


@dataclass(slots=True)
class IntelProviderConfig:
    """Settings for a single threat-intelligence provider."""

    enabled: bool = False
    api_key: str = ""
    requests_per_minute: int = 4

    def validate(self, name: str) -> None:
        if self.enabled and not self.api_key:
            raise ConfigError(
                f"intel.{name}.api_key is required when intel.{name}.enabled is true"
            )
        if self.requests_per_minute <= 0:
            raise ConfigError(f"intel.{name}.requests_per_minute must be positive")


@dataclass(slots=True)
class IntelConfig:
    """Threat-intelligence layer settings."""

    enabled: bool = True
    cache_ttl_seconds: int = 86400
    timeout_seconds: float = 10.0
    max_lookups_per_run: int = 50
    abuseipdb: IntelProviderConfig = field(default_factory=IntelProviderConfig)
    virustotal: IntelProviderConfig = field(default_factory=IntelProviderConfig)
    otx: IntelProviderConfig = field(default_factory=IntelProviderConfig)

    def validate(self) -> None:
        if self.cache_ttl_seconds < 0:
            raise ConfigError("intel.cache_ttl_seconds must not be negative")
        if self.timeout_seconds <= 0:
            raise ConfigError("intel.timeout_seconds must be positive")
        if self.max_lookups_per_run < 0:
            raise ConfigError("intel.max_lookups_per_run must not be negative")
        self.abuseipdb.validate("abuseipdb")
        self.virustotal.validate("virustotal")
        self.otx.validate("otx")

    @property
    def any_provider_enabled(self) -> bool:
        return self.enabled and (
            self.abuseipdb.enabled or self.virustotal.enabled or self.otx.enabled
        )


@dataclass(slots=True)
class LLMConfig:
    """Optional local LLM used to explain alerts."""

    enabled: bool = False
    endpoint: str = "http://localhost:11434"
    model: str = "llama3.1"
    timeout_seconds: float = 60.0
    max_tokens: int = 700
    provider: str = "ollama"
    language: str = "en"
    max_retries: int = 1
    retry_backoff_seconds: float = 1.0
    cache_ttl_seconds: int = 604800
    api_key: str = ""

    def validate(self) -> None:
        from sentinelai.ai.triage_models import LANGUAGES

        if self.enabled and not self.endpoint.startswith(("http://", "https://")):
            raise ConfigError("ai.llm.endpoint must be an http(s) URL")
        if self.timeout_seconds <= 0:
            raise ConfigError("ai.llm.timeout_seconds must be positive")
        if self.max_tokens <= 0:
            raise ConfigError("ai.llm.max_tokens must be positive")
        if self.provider not in ("ollama", "openai"):
            raise ConfigError("ai.llm.provider must be one of: ollama, openai")
        if self.language not in LANGUAGES:
            raise ConfigError(f"ai.llm.language must be one of: {', '.join(LANGUAGES)}")
        if (
            isinstance(self.max_retries, bool)
            or not isinstance(self.max_retries, int)
            or not 0 <= self.max_retries <= 3
        ):
            raise ConfigError("ai.llm.max_retries must be an integer between 0 and 3")
        backoff = self.retry_backoff_seconds
        if (
            isinstance(backoff, bool)
            or not isinstance(backoff, (int, float))
            or not math.isfinite(backoff)
            or backoff < 0
        ):
            raise ConfigError("ai.llm.retry_backoff_seconds must be a finite number >= 0")
        if (
            isinstance(self.cache_ttl_seconds, bool)
            or not isinstance(self.cache_ttl_seconds, int)
            or self.cache_ttl_seconds < 0
        ):
            raise ConfigError("ai.llm.cache_ttl_seconds must be an integer >= 0")
        if not isinstance(self.api_key, str):
            raise ConfigError("ai.llm.api_key must be a string")


@dataclass(slots=True)
class AIConfig:
    """AI engine settings."""

    enabled: bool = True
    model: str = "isolation_forest"
    contamination: float = 0.02
    min_events: int = 50
    anomaly_alert_threshold: float = 0.75
    llm: LLMConfig = field(default_factory=LLMConfig)

    def validate(self) -> None:
        if not 0.0 < self.contamination < 0.5:
            raise ConfigError("ai.contamination must be between 0 and 0.5")
        if self.min_events < 10:
            raise ConfigError("ai.min_events must be at least 10")
        if not 0.0 <= self.anomaly_alert_threshold <= 1.0:
            raise ConfigError("ai.anomaly_alert_threshold must be between 0 and 1")
        self.llm.validate()


@dataclass(slots=True)
class FirewallConfig:
    """Integration with the external Firewall Automation project.

    ``adapter`` selects how SentinelAI talks to it:

    * ``python`` — import a class/factory from the firewall project
      (``module`` + ``attribute``), the cleanest integration.
    * ``command`` — invoke the firewall project's CLI with argument
      templates (no shell involved, arguments are passed as a list).
    * ``dry_run`` — log intended actions without touching anything.
    """

    adapter: str = "dry_run"
    module: str = ""
    attribute: str = ""
    init_kwargs: dict[str, Any] = field(default_factory=dict)
    command: str = ""
    block_args: list[str] = field(default_factory=lambda: ["block", "{ip}"])
    unblock_args: list[str] = field(default_factory=lambda: ["unblock", "{ip}"])
    temp_block_args: list[str] = field(
        default_factory=lambda: ["block", "{ip}", "--duration", "{duration}"]
    )
    list_args: list[str] = field(default_factory=lambda: ["list"])
    timeout_seconds: float = 15.0

    def validate(self) -> None:
        if self.adapter not in ("python", "command", "dry_run"):
            raise ConfigError(
                "firewall.adapter must be one of: python, command, dry_run"
            )
        if self.adapter == "python" and not self.module:
            raise ConfigError("firewall.module is required for the python adapter")
        if self.adapter == "command" and not self.command:
            raise ConfigError("firewall.command is required for the command adapter")
        if self.timeout_seconds <= 0:
            raise ConfigError("firewall.timeout_seconds must be positive")


@dataclass(slots=True)
class ResponseConfig:
    """Automatic response policy applied on top of the firewall adapter."""

    enabled: bool = False
    min_risk_level: str = "high"
    temporary_block: bool = True
    block_duration_seconds: int = 3600
    cooldown_seconds: int = 600
    allowlist: list[str] = field(
        default_factory=lambda: ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    )
    max_blocks_per_run: int = 25

    def validate(self) -> None:
        from sentinelai.core.models import RiskLevel

        try:
            RiskLevel(self.min_risk_level)
        except ValueError:
            valid = ", ".join(level.value for level in RiskLevel)
            raise ConfigError(
                f"response.min_risk_level must be one of: {valid}"
            ) from None
        if self.block_duration_seconds <= 0:
            raise ConfigError("response.block_duration_seconds must be positive")
        if self.cooldown_seconds < 0:
            raise ConfigError("response.cooldown_seconds must not be negative")
        if self.max_blocks_per_run <= 0:
            raise ConfigError("response.max_blocks_per_run must be positive")


@dataclass(slots=True)
class ReportConfig:
    """Report generation settings."""

    output_dir: str = "reports"
    formats: list[str] = field(default_factory=lambda: ["json", "html"])
    include_events: bool = True
    max_events_per_alert: int = 5
    title: str = "SentinelAI Security Report"

    def validate(self) -> None:
        valid = {"json", "csv", "html"}
        for fmt in self.formats:
            if fmt not in valid:
                raise ConfigError(
                    f"report.formats contains unknown format {fmt!r}; valid: json, csv, html"
                )
        if self.max_events_per_alert < 0:
            raise ConfigError("report.max_events_per_alert must not be negative")


@dataclass(slots=True)
class LiveConfig:
    """Real-time monitoring settings."""

    paths: list[str] = field(
        default_factory=lambda: ["/var/log/auth.log", "/var/log/syslog"]
    )
    poll_interval_seconds: float = 1.0
    from_beginning: bool = False
    dedup_window_seconds: int = 300

    def validate(self) -> None:
        if self.poll_interval_seconds <= 0:
            raise ConfigError("live.poll_interval_seconds must be positive")
        if self.dedup_window_seconds < 0:
            raise ConfigError("live.dedup_window_seconds must not be negative")
        if not self.paths:
            raise ConfigError("live.paths must contain at least one log path")


@dataclass(slots=True)
class SentinelConfig:
    """Root configuration object."""

    state_dir: str = ""
    debug: bool = False
    log_file: str = ""
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    intel: IntelConfig = field(default_factory=IntelConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    live: LiveConfig = field(default_factory=LiveConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    source_path: str = ""
    tuning_overlay: str = ""

    def validate(self) -> None:
        """Validate the whole tree, raising :class:`ConfigError` on issues."""
        self.detection.validate()
        self.intel.validate()
        self.ai.validate()
        self.firewall.validate()
        self.response.validate()
        self.report.validate()
        self.live.validate()
        self.risk.validate()

    def resolve_state_dir(self) -> Path:
        """Return the state directory, creating it when needed."""
        if self.state_dir:
            path = Path(self.state_dir).expanduser()
            path.mkdir(parents=True, exist_ok=True)
            return path
        return default_state_dir()
