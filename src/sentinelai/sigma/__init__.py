"""Sigma rule import: safe parser, matcher and loader for a Linux-relevant subset."""

from __future__ import annotations

from sentinelai.sigma.rules import (
    SIGMA_RULE_ID_RE,
    LoadReport,
    SigmaRule,
    Unsupported,
    load_rules,
    sigma_rule_id,
)

__all__ = [
    "SIGMA_RULE_ID_RE",
    "LoadReport",
    "SigmaRule",
    "Unsupported",
    "load_rules",
    "sigma_rule_id",
]
