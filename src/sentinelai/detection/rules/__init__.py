"""Built-in detection rules.

Importing this package registers every built-in rule with the rule
registry. Add a new module here (or ship one as a plugin) and decorate
rules with ``@register_rule`` — the engine picks them up automatically.
"""

from sentinelai.detection.rules import (  # noqa: F401 - registration side effects
    authentication,
    docker_rules,
    network,
    persistence,
    privilege,
    system,
    users,
)
