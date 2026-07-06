"""Automatic response policy.

Decides *whether* an alert warrants blocking its source, then delegates
the *how* to the firewall boundary. Safety rails:

* risk threshold (``response.min_risk_level``)
* allowlisted networks are never blocked
* invalid or missing IPs are never blocked
* per-IP cooldown prevents block/unblock thrash
* a per-run budget caps how many blocks one scan can trigger
"""

from __future__ import annotations

import time

from sentinelai.config.models import ResponseConfig
from sentinelai.core.exceptions import FirewallError
from sentinelai.core.models import Alert, RiskLevel
from sentinelai.firewall.interface import FirewallAction, FirewallController
from sentinelai.utils.logging import get_logger
from sentinelai.utils.net import ip_in_networks, is_valid_ip

_LOGGER = get_logger("firewall.responder")


class AutoResponder:
    """Applies the configured response policy to scored alerts."""

    def __init__(self, config: ResponseConfig, firewall: FirewallController) -> None:
        self._config = config
        self._firewall = firewall
        self._min_level = RiskLevel(config.min_risk_level)
        self._last_action: dict[str, float] = {}
        self._blocks_this_run = 0
        self.actions: list[FirewallAction] = []

    def consider(self, alert: Alert) -> FirewallAction | None:
        """Evaluate one alert; block its source when policy demands it.

        Returns the action taken (successful or failed), or ``None``
        when policy decided not to act.
        """
        if not self._config.enabled:
            return None
        decision = self._decide(alert)
        if decision is not None:
            _LOGGER.debug("No response for alert %s: %s", alert.rule_id, decision)
            return None
        ip = alert.ip or ""
        action_name = "temporary_block" if self._config.temporary_block else "block_ip"
        duration = (
            self._config.block_duration_seconds if self._config.temporary_block else None
        )
        try:
            if duration is not None:
                success = self._firewall.temporary_block(ip, duration)
            else:
                success = self._firewall.block_ip(ip)
            detail = f"triggered by {alert.rule_id} ({alert.risk.level.value})"
        except FirewallError as exc:
            success = False
            detail = str(exc)
            _LOGGER.error("Firewall action failed for %s: %s", ip, exc)
        action = FirewallAction(
            action=action_name,
            ip=ip,
            success=success,
            detail=detail,
            duration_seconds=duration,
        )
        self.actions.append(action)
        alert.context["response"] = action.to_dict()
        if success:
            self._blocks_this_run += 1
            self._last_action[ip] = time.monotonic()
            _LOGGER.warning(
                "Blocked %s (%s) after alert %s", ip, action_name, alert.rule_id
            )
        return action

    def _decide(self, alert: Alert) -> str | None:
        """Return a skip reason, or None when the alert should be acted on."""
        if alert.risk.level.weight < self._min_level.weight:
            return f"risk {alert.risk.level.value} below threshold"
        ip = alert.ip
        if not ip or not is_valid_ip(ip):
            return "no valid source IP"
        if ip_in_networks(ip, self._config.allowlist):
            return f"{ip} is allowlisted"
        if self._blocks_this_run >= self._config.max_blocks_per_run:
            return "per-run block budget exhausted"
        last = self._last_action.get(ip)
        if last is not None and time.monotonic() - last < self._config.cooldown_seconds:
            return f"{ip} in cooldown"
        try:
            if self._firewall.is_blocked(ip):
                return f"{ip} already blocked"
        except FirewallError as exc:
            _LOGGER.warning("Could not query block state for %s: %s", ip, exc)
        return None
