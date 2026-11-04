"""The detection engine: runs rules over events and de-duplicates alerts.

De-duplication uses alert fingerprints (rule + ip + user + host) with a
configurable cooldown measured in **event time**, so a brute force that
spans thousands of log lines produces one evolving alert, not thousands.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from sentinelai.config.models import DetectionConfig
from sentinelai.core.models import Alert, LogEvent
from sentinelai.detection import rules as _rules  # noqa: F401 - registers built-ins
from sentinelai.detection.base import Rule, RuleContext, available_rules
from sentinelai.detection.suppression import SuppressionMatcher
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("detection.engine")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RuleEngine:
    """Evaluates every enabled rule against a stream of events."""

    def __init__(
        self,
        config: DetectionConfig,
        now: Callable[[], datetime] | None = None,
        extra_rules: Sequence[Rule] | None = None,
    ) -> None:
        self._config = config
        self._ctx = RuleContext(config)
        self._rules = self._load_rules(config, extra_rules)
        self._recent: dict[str, tuple[Alert, datetime]] = {}
        clock = now if now is not None else _utc_now
        self._suppressor = SuppressionMatcher(config.parsed_suppressions(), clock)
        self._suppressed_total = 0
        self._suppressed_by_rule: dict[str, int] = {}

    @property
    def suppressed_total(self) -> int:
        """Number of alerts dropped by analyst-approved suppressions."""
        return self._suppressed_total

    @property
    def suppressed_by_rule(self) -> dict[str, int]:
        """Suppressed alert counts per rule id (a copy)."""
        return dict(self._suppressed_by_rule)

    @staticmethod
    def _load_rules(
        config: DetectionConfig,
        extra_rules: Sequence[Rule] | None = None,
    ) -> list[Rule]:
        enabled = set(config.enabled_rules)
        disabled = set(config.disabled_rules)
        loaded: list[Rule] = []
        seen: set[str] = set()
        for rule_id, cls in sorted(available_rules().items()):
            seen.add(rule_id)
            if enabled and rule_id not in enabled:
                continue
            if rule_id in disabled:
                continue
            loaded.append(cls())
        for extra in sorted(extra_rules or (), key=lambda rule: rule.rule_id):
            if extra.rule_id in seen:
                _LOGGER.warning("Skipping extra rule with duplicate id %s", extra.rule_id)
                continue
            seen.add(extra.rule_id)
            if enabled and extra.rule_id not in enabled:
                continue
            if extra.rule_id in disabled:
                continue
            loaded.append(extra)
        _LOGGER.debug("Loaded %d detection rules", len(loaded))
        return loaded

    @property
    def rules(self) -> list[Rule]:
        """The active rule instances."""
        return list(self._rules)

    def process(self, event: LogEvent) -> list[Alert]:
        """Run all rules against one event; return newly raised alerts.

        Alerts suppressed by the cooldown are merged into the previously
        raised alert (count and last_seen are updated in place) so the
        earlier alert object keeps reflecting reality.
        """
        raised: list[Alert] = []
        for rule in self._rules:
            try:
                alert = rule.evaluate(event, self._ctx)
            except Exception:  # noqa: BLE001 - one broken rule must not stop detection
                _LOGGER.exception("Rule %s crashed on event", rule.rule_id)
                continue
            if alert is None:
                continue
            if self._suppressor.match(alert) is not None:
                self._suppressed_total += 1
                self._suppressed_by_rule[alert.rule_id] = (
                    self._suppressed_by_rule.get(alert.rule_id, 0) + 1
                )
                _LOGGER.debug("Suppressed alert %s by analyst suppression", alert.rule_id)
                continue
            merged = self._dedup(alert)
            if merged is not None:
                raised.append(merged)
        return raised

    def _dedup(self, alert: Alert) -> Alert | None:
        fingerprint = alert.fingerprint
        cooldown = self._config.alert_cooldown_seconds
        previous = self._recent.get(fingerprint)
        if previous is not None:
            prev_alert, last_ts = previous
            elapsed = (alert.last_seen - last_ts).total_seconds()
            if 0 <= elapsed < cooldown:
                prev_alert.event_count += alert.event_count
                prev_alert.last_seen = max(prev_alert.last_seen, alert.last_seen)
                self._recent[fingerprint] = (prev_alert, alert.last_seen)
                _LOGGER.debug(
                    "Suppressed duplicate alert %s within cooldown", alert.rule_id
                )
                return None
        self._recent[fingerprint] = (alert, alert.last_seen)
        return alert

    def reset(self) -> None:
        """Clear all sliding-window and dedup state."""
        self._ctx.state.clear()
        self._recent.clear()
        self._suppressed_total = 0
        self._suppressed_by_rule.clear()
