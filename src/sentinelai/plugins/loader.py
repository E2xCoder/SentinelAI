"""Discovers and imports plugin modules from a directory."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

from sentinelai.core.exceptions import PluginError
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("plugins")


def default_plugins_dir() -> Path:
    """Return the plugins directory (env override or ~/.sentinelai/plugins)."""
    override = os.environ.get("SENTINELAI_PLUGINS_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".sentinelai" / "plugins"


def load_plugins(directory: str | Path | None = None) -> list[str]:
    """Import every ``*.py`` plugin in *directory*.

    Returns the names of successfully loaded plugins. A plugin that
    raises on import is logged and skipped — one broken plugin never
    prevents the platform from starting.
    """
    plugins_dir = Path(directory).expanduser() if directory else default_plugins_dir()
    if not plugins_dir.is_dir():
        _LOGGER.debug("No plugins directory at %s", plugins_dir)
        return []
    loaded: list[str] = []
    for path in sorted(plugins_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            _import_module_from_path(path)
            loaded.append(path.stem)
            _LOGGER.info("Loaded plugin %s", path.stem)
        except Exception as exc:  # noqa: BLE001 - isolate plugin failures
            _LOGGER.error("Failed to load plugin %s: %s", path.name, exc)
    return loaded


def _import_module_from_path(path: Path) -> None:
    module_name = f"sentinelai_plugin_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise PluginError(f"Cannot create import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
