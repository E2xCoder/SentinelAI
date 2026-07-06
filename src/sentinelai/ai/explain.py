"""Alert explanation: local LLM (Ollama) with a deterministic fallback.

When a local model is reachable, alerts are explained in natural
language; otherwise a structured template explanation is produced from
the rule metadata, risk factors and threat intelligence — so ``sentinel
explain`` always returns something useful.
"""

from __future__ import annotations

import json

import requests

from sentinelai.config.models import LLMConfig
from sentinelai.core.models import Alert
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("ai.explain")

_PROMPT_TEMPLATE = """You are a senior SOC analyst. Analyze this security alert and answer concisely.

ALERT
Title: {title}
Rule: {rule_name} ({rule_id})
Description: {description}
Severity: {severity} | Risk: {risk_score:.0f}/100 ({risk_level})
Source IP: {ip} | User: {user} | Host: {hostname}
Events correlated: {event_count} between {first_seen} and {last_seen}
MITRE ATT&CK: {mitre}
Risk factors:
{risk_factors}
Threat intelligence: {intel}
Recognized attack patterns: {patterns}

Respond in exactly this format:
WHY SUSPICIOUS: <2-3 sentences>
POTENTIAL ATTACK: <1-2 sentences naming the likely attack>
RECOMMENDED ACTIONS: <3 short imperative bullet points>
CONFIDENCE: <a number 0-100>"""


class AlertExplainer:
    """Produces the explanation block of an alert."""

    def __init__(self, config: LLMConfig) -> None:
        self._config = config

    def explain(self, alert: Alert) -> tuple[str, str, float]:
        """Return ``(explanation, source, confidence)`` for *alert*.

        Tries the local LLM first when enabled; always falls back to the
        template so the call never fails.
        """
        if self._config.enabled:
            generated = self._explain_llm(alert)
            if generated is not None:
                confidence = _extract_confidence(generated)
                return generated, f"llm:{self._config.model}", confidence
        return self._explain_template(alert), "template", 0.7

    def _build_prompt(self, alert: Alert) -> str:
        factors = "\n".join(
            f"- {f.name} ({f.points:+.0f}): {f.reason}" for f in alert.risk.factors
        ) or "- none recorded"
        intel = "not checked"
        if alert.intel is not None and alert.intel.sources:
            verdict = "MALICIOUS" if alert.intel.malicious else "clean"
            intel = (
                f"{verdict}, score {alert.intel.score:.0f}/100 from "
                f"{', '.join(sorted(alert.intel.sources))}"
            )
        patterns = ", ".join(alert.ai.patterns) if alert.ai and alert.ai.patterns else "none"
        return _PROMPT_TEMPLATE.format(
            title=alert.title,
            rule_name=alert.rule_name,
            rule_id=alert.rule_id,
            description=alert.description,
            severity=alert.severity.value,
            risk_score=alert.risk.score,
            risk_level=alert.risk.level.value,
            ip=alert.ip or "n/a",
            user=alert.user or "n/a",
            hostname=alert.hostname or "n/a",
            event_count=alert.event_count,
            first_seen=alert.first_seen.isoformat(),
            last_seen=alert.last_seen.isoformat(),
            mitre=", ".join(alert.mitre_techniques) or "n/a",
            risk_factors=factors,
            intel=intel,
            patterns=patterns,
        )

    def _explain_llm(self, alert: Alert) -> str | None:
        """Query a local Ollama-compatible endpoint; None on any failure."""
        url = f"{self._config.endpoint.rstrip('/')}/api/generate"
        payload = {
            "model": self._config.model,
            "prompt": self._build_prompt(alert),
            "stream": False,
            "options": {"num_predict": self._config.max_tokens, "temperature": 0.2},
        }
        try:
            response = requests.post(
                url, json=payload, timeout=self._config.timeout_seconds
            )
            response.raise_for_status()
            text = str(response.json().get("response", "")).strip()
            return text or None
        except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
            _LOGGER.warning("Local LLM unavailable (%s); using template explanation", exc)
            return None

    @staticmethod
    def _explain_template(alert: Alert) -> str:
        """Deterministic explanation assembled from alert structure."""
        why = [alert.description]
        for factor in alert.risk.factors:
            if factor.points > 0 and factor.name != "base_severity":
                why.append(factor.reason + ".")
        attack = (
            f"Consistent with MITRE ATT&CK {', '.join(alert.mitre_techniques)} "
            f"({', '.join(alert.mitre_tactics)})."
            if alert.mitre_techniques
            else "The behavior does not map to a single known technique."
        )
        actions = alert.recommendation or "Investigate the source and affected accounts."
        if alert.intel is not None and alert.intel.malicious:
            actions += " The source IP has a malicious reputation — block it."
        return (
            f"WHY SUSPICIOUS: {' '.join(why)}\n"
            f"POTENTIAL ATTACK: {attack}\n"
            f"RECOMMENDED ACTIONS: {actions}\n"
            f"CONFIDENCE: {min(95, int(alert.risk.score))}"
        )


def _extract_confidence(text: str) -> float:
    """Pull the CONFIDENCE number out of a formatted response."""
    for line in reversed(text.splitlines()):
        if "CONFIDENCE" in line.upper():
            digits = "".join(c for c in line if c.isdigit() or c == ".")
            try:
                return max(0.0, min(1.0, float(digits) / 100.0))
            except ValueError:
                break
    return 0.5
