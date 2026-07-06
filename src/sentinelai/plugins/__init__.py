"""Plugin subsystem.

Plugins are ordinary Python modules dropped into a plugins directory (by
default ``~/.sentinelai/plugins``, overridable with
``SENTINELAI_PLUGINS_DIR``). On load they simply import and use the
public registration decorators:

* ``@register_parser`` — new log formats
* ``@register_rule`` — new detection rules
* ``register_model`` — new AI anomaly models
* ``register_renderer`` — new report formats

No existing code changes to add capability; the loader just imports the
modules so their decorators run.
"""

from sentinelai.plugins.loader import load_plugins

__all__ = ["load_plugins"]
