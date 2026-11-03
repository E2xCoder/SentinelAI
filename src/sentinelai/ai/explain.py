"""Alert explanation: structured LLM triage with a deterministic fallback.

When the LLM is enabled, alerts are triaged by :class:`TriageEngine`
(schema-constrained, validated, cached; falls back to a deterministic
template on any failure). When it is disabled, a structured template
explanation is produced from the rule metadata, risk factors and threat
intelligence - so ``sentinel explain`` always returns something useful.
"""

from __future__ import annotations

from sentinelai.ai.triage import render_text
from sentinelai.ai.triage_engine import TriageEngine
from sentinelai.ai.triage_models import TriageOutcome
from sentinelai.config.models import LLMConfig
from sentinelai.core.models import Alert


class AlertExplainer:
    """Produces the explanation block of an alert."""

    def __init__(self, config: LLMConfig, triage: TriageEngine | None = None) -> None:
        self._config = config
        self._triage = triage
        self._owns_triage = False

    def explain(self, alert: Alert) -> tuple[str, str, float]:
        """Return ``(explanation, source, confidence)`` for *alert*.

        Never fails: any LLM problem falls back to the template.
        """
        explanation, source, confidence, _ = self.explain_full(alert)
        return explanation, source, confidence

    def explain_full(self, alert: Alert) -> tuple[str, str, float, TriageOutcome | None]:
        """Like :meth:`explain`, plus the triage outcome (None when disabled)."""
        if not self._config.enabled:
            return self._explain_template(alert), "template", 0.7, None
        outcome = self._engine().triage(alert)
        return (
            render_text(outcome.result, self._config.language),
            outcome.source,
            outcome.result.confidence,
            outcome,
        )

    def close(self) -> None:
        """Release the triage engine if this explainer created it."""
        if self._triage is not None and self._owns_triage:
            self._triage.close()
        if self._owns_triage:
            self._triage = None
            self._owns_triage = False

    def _engine(self) -> TriageEngine:
        if self._triage is None:
            self._triage = TriageEngine(self._config)
            self._owns_triage = True
        return self._triage

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
