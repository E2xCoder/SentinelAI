"""Example SentinelAI plugin: a custom detection rule.

This file is a complete, working plugin. It registers one rule, ``X001``,
which fires when a failed login targets an account listed in
``SENSITIVE_USERS``.

How to install
--------------
Copy this file into your plugins directory::

    mkdir -p ~/.sentinelai/plugins
    cp examples/plugins/example_rule.py ~/.sentinelai/plugins/

or point SentinelAI at any directory containing it::

    export SENTINELAI_PLUGINS_DIR=/path/to/my/plugins

Every ``*.py`` file in that directory (except names starting with ``_``)
is imported when the CLI starts. Pass ``--no-plugins`` to skip loading.
Check that the rule is active with ``sentinel rules``.

Security warning
----------------
Plugins are ordinary Python modules imported into the SentinelAI process:
they run with YOUR privileges and can read files, open network
connections and execute commands. Only install plugin code you wrote or
have reviewed and trust. A plugin that fails to import is logged and
skipped, but that isolation does not make malicious code safe.

How it works
------------
A rule subclasses :class:`~sentinelai.detection.base.Rule`, declares its
metadata as class attributes, and implements ``evaluate``. It receives one
event at a time and returns an alert (via ``make_alert``) or ``None``.
The ``@register_rule`` decorator adds it to the global registry; rule IDs
must be unique.
"""

from __future__ import annotations

from sentinelai.core.models import Alert, EventCategory, EventType, LogEvent, Severity
from sentinelai.detection.base import Rule, RuleContext, register_rule

#: Accounts that deserve extra attention. Edit this list for your site.
SENSITIVE_USERS: tuple[str, ...] = ("ceo", "finance")

_SENSITIVE_LOWER = frozenset(name.lower() for name in SENSITIVE_USERS)


@register_rule
class SensitiveAccountFailedLoginRule(Rule):
    """A login attempt failed for an account on the sensitive-user list."""

    rule_id = "X001"
    name = "Example: failed login for a sensitive account"
    description = (
        "A failed authentication attempt targeted an account listed in "
        "SENSITIVE_USERS. Attacks against high-value accounts are often "
        "targeted rather than opportunistic."
    )
    # Falls back to UNKNOWN if this SentinelAI version has no such member.
    category = getattr(EventCategory, "AUTHENTICATION", EventCategory.UNKNOWN)
    severity = Severity.WARNING
    mitre_tactics = ("Credential Access",)
    mitre_techniques = ("T1110",)
    recommendation = (
        "Confirm with the account owner whether the attempt was legitimate; "
        "enforce MFA on this account and review the source IP for other "
        "activity."
    )

    def evaluate(self, event: LogEvent, ctx: RuleContext) -> Alert | None:
        if event.event_type is not EventType.AUTH_FAILURE:
            return None
        user = (event.user or "").strip().lower()
        if user not in _SENSITIVE_LOWER:
            return None
        source = event.ip or "an unknown source"
        return self.make_alert(
            event,
            title=f"Failed login for sensitive account '{event.user}'",
            description=(
                f"A failed login for sensitive account '{event.user}' "
                f"was seen from {source}."
            ),
        )
