"""Load and merge configuration from YAML files and environment variables.

Precedence (highest wins):

1. ``SENTINELAI_*`` environment variables (e.g. ``SENTINELAI_INTEL_ABUSEIPDB_API_KEY``)
2. The YAML config file (``--config``, ``./config.yaml`` or ``~/.sentinelai/config.yaml``)
3. Built-in defaults

API keys therefore never need to live on disk.
"""

from __future__ import annotations

import os
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml

from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import ConfigError
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("config")

_ENV_PREFIX = "SENTINELAI_"

_DEFAULT_LOCATIONS = (
    Path("config.yaml"),
    Path("sentinelai.yaml"),
    Path.home() / ".sentinelai" / "config.yaml",
    Path("/etc/sentinelai/config.yaml"),
)


def find_config_file(explicit: str | Path | None = None) -> Path | None:
    """Locate the configuration file, honoring an explicit override."""
    if explicit is not None:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"Config file not found: {path}")
        return path
    env_path = os.environ.get(f"{_ENV_PREFIX}CONFIG")
    if env_path:
        path = Path(env_path).expanduser()
        if not path.is_file():
            raise ConfigError(f"Config file from SENTINELAI_CONFIG not found: {path}")
        return path
    for candidate in _DEFAULT_LOCATIONS:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Cannot read config file {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"Top level of {path} must be a mapping")
    return data


def _coerce(value: str, target_type: Any) -> Any:
    """Coerce an environment-variable string to the target field type."""
    if target_type is bool or target_type == "bool":
        return value.strip().lower() in ("1", "true", "yes", "on")
    if target_type is int or target_type == "int":
        return int(value)
    if target_type is float or target_type == "float":
        return float(value)
    if target_type is list or (isinstance(target_type, str) and target_type.startswith("list")):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


def _apply_dict(obj: Any, data: dict[str, Any], path: str = "") -> None:
    """Recursively apply a mapping onto a dataclass tree in place."""
    valid = {f.name: f for f in fields(obj)}
    for key, value in data.items():
        dotted = f"{path}.{key}" if path else key
        if key not in valid:
            _LOGGER.warning("Unknown config key ignored: %s", dotted)
            continue
        current = getattr(obj, key)
        if is_dataclass(current) and not isinstance(current, type):
            if not isinstance(value, dict):
                raise ConfigError(f"Config section {dotted!r} must be a mapping")
            _apply_dict(current, value, dotted)
            continue
        if isinstance(current, bool) and not isinstance(value, bool):
            raise ConfigError(f"Config key {dotted!r} must be true/false")
        if isinstance(current, (int, float)) and not isinstance(current, bool):
            if not isinstance(value, (int, float)):
                raise ConfigError(f"Config key {dotted!r} must be a number")
        if isinstance(current, list) and not isinstance(value, list):
            raise ConfigError(f"Config key {dotted!r} must be a list")
        if isinstance(current, str) and not isinstance(value, (str, int, float)):
            raise ConfigError(f"Config key {dotted!r} must be a string")
        setattr(obj, key, value if not isinstance(current, str) else str(value))


def _apply_env(obj: Any, prefix: str = _ENV_PREFIX) -> None:
    """Apply ``SENTINELAI_SECTION_SUBSECTION_KEY`` environment overrides.

    Matching is greedy on section names: ``SENTINELAI_INTEL_ABUSEIPDB_API_KEY``
    resolves to ``config.intel.abuseipdb.api_key``.
    """
    for env_name, env_value in os.environ.items():
        if not env_name.startswith(prefix) or env_name == f"{_ENV_PREFIX}CONFIG":
            continue
        parts = env_name[len(prefix):].lower().split("_")
        _apply_env_parts(obj, parts, env_value, env_name)


def _apply_env_parts(obj: Any, parts: list[str], value: str, env_name: str) -> bool:
    """Walk the dataclass tree matching underscore-separated path segments."""
    if not parts:
        return False
    valid = {f.name for f in fields(obj)}
    # Try longest field-name match first: field names may contain underscores.
    for split in range(len(parts), 0, -1):
        candidate = "_".join(parts[:split])
        if candidate not in valid:
            continue
        current = getattr(obj, candidate)
        remaining = parts[split:]
        if is_dataclass(current) and not isinstance(current, type):
            if _apply_env_parts(current, remaining, value, env_name):
                return True
            continue
        if remaining:
            continue
        try:
            setattr(obj, candidate, _coerce(value, type(current)))
        except ValueError as exc:
            raise ConfigError(f"Invalid value for {env_name}: {exc}") from exc
        return True
    return False


def load_config(explicit_path: str | Path | None = None) -> SentinelConfig:
    """Build the full configuration with defaults, file and env merged."""
    config = SentinelConfig()
    config_file = find_config_file(explicit_path)
    if config_file is not None:
        _apply_dict(config, _read_yaml(config_file))
        config.source_path = str(config_file)
    _apply_env(config)
    config.validate()
    return config
