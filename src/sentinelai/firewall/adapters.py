"""Adapters binding the FirewallController protocol to real backends.

Three strategies, all configured in ``config.yaml`` — SentinelAI itself
contains zero firewall logic:

* :class:`PythonModuleAdapter` imports a controller class or factory
  from the operator's Firewall Automation project.
* :class:`CommandAdapter` invokes that project's CLI. Arguments are
  passed as a list (never through a shell) and IPs are validated first,
  so no injection is possible.
* :class:`DryRunAdapter` records intended actions without touching
  anything — the safe default.
"""

from __future__ import annotations

import importlib
import os
import subprocess  # noqa: S404 - used without shell, args validated
from typing import Any

from sentinelai.config.models import FirewallConfig
from sentinelai.core.exceptions import FirewallError
from sentinelai.firewall.interface import FirewallController
from sentinelai.utils.logging import get_logger
from sentinelai.utils.net import is_valid_ip

_LOGGER = get_logger("firewall")


class DryRunAdapter:
    """Records actions instead of executing them."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int | None]] = []
        self._blocked: set[str] = set()

    def block_ip(self, ip: str) -> bool:
        self.calls.append(("block_ip", ip, None))
        self._blocked.add(ip)
        _LOGGER.info("[dry-run] block_ip(%s)", ip)
        return True

    def unblock_ip(self, ip: str) -> bool:
        self.calls.append(("unblock_ip", ip, None))
        self._blocked.discard(ip)
        _LOGGER.info("[dry-run] unblock_ip(%s)", ip)
        return True

    def temporary_block(self, ip: str, duration_seconds: int) -> bool:
        self.calls.append(("temporary_block", ip, duration_seconds))
        self._blocked.add(ip)
        _LOGGER.info("[dry-run] temporary_block(%s, %ss)", ip, duration_seconds)
        return True

    def list_blocked(self) -> list[str]:
        return sorted(self._blocked)

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked


class PythonModuleAdapter:
    """Binds to a controller object exposed by the firewall project.

    Config example::

        firewall:
          adapter: python
          module: firewall_automation.api
          attribute: FirewallManager     # class or factory; optional
          init_kwargs: {profile: sentinel}

    The resolved object must provide the :class:`FirewallController`
    methods. Method presence is verified once at construction so a
    misconfiguration fails immediately with a clear message rather than
    mid-incident.
    """

    _REQUIRED = ("block_ip", "unblock_ip", "temporary_block", "list_blocked")

    def __init__(self, config: FirewallConfig) -> None:
        try:
            module = importlib.import_module(config.module)
        except ImportError as exc:
            raise FirewallError(
                f"Cannot import firewall module {config.module!r}: {exc}. "
                "Is your Firewall Automation project on PYTHONPATH?"
            ) from exc
        target: Any = module
        if config.attribute:
            try:
                target = getattr(module, config.attribute)
            except AttributeError:
                raise FirewallError(
                    f"{config.module!r} has no attribute {config.attribute!r}"
                ) from None
        if callable(target) and (isinstance(target, type) or not self._satisfies_protocol(target)):
            try:
                target = target(**config.init_kwargs)
            except Exception as exc:  # noqa: BLE001 - surface constructor errors clearly
                raise FirewallError(
                    f"Failed to construct firewall controller from "
                    f"{config.module}.{config.attribute}: {exc}"
                ) from exc
        missing = [m for m in self._REQUIRED if not callable(getattr(target, m, None))]
        if missing:
            raise FirewallError(
                f"Firewall controller from {config.module!r} is missing "
                f"required methods: {', '.join(missing)}"
            )
        self._inner = target

    @classmethod
    def _satisfies_protocol(cls, obj: Any) -> bool:
        return all(callable(getattr(obj, m, None)) for m in cls._REQUIRED)

    def block_ip(self, ip: str) -> bool:
        return bool(self._inner.block_ip(ip))

    def unblock_ip(self, ip: str) -> bool:
        return bool(self._inner.unblock_ip(ip))

    def temporary_block(self, ip: str, duration_seconds: int) -> bool:
        return bool(self._inner.temporary_block(ip, duration_seconds))

    def list_blocked(self) -> list[str]:
        return [str(ip) for ip in self._inner.list_blocked()]

    def is_blocked(self, ip: str) -> bool:
        inner_check = getattr(self._inner, "is_blocked", None)
        if callable(inner_check):
            return bool(inner_check(ip))
        return ip in self.list_blocked()


class CommandAdapter:
    """Invokes the firewall project's CLI with templated argument lists.

    Config example::

        firewall:
          adapter: command
          command: firewall-automation
          block_args: ["block", "{ip}"]
          temp_block_args: ["block", "{ip}", "--duration", "{duration}"]
          unblock_args: ["unblock", "{ip}"]
          list_args: ["list", "--plain"]

    Substitution only fills ``{ip}`` / ``{duration}`` into pre-split
    argument slots; nothing is ever interpreted by a shell. The tool runs
    with a minimal environment (PATH, locale, HOME), so API keys, webhooks
    and passwords from SentinelAI's own environment are not inherited.
    """

    def __init__(self, config: FirewallConfig) -> None:
        self._config = config

    @staticmethod
    def _minimal_env() -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
            "LC_ALL": "C",
            "LANG": "C",
        }
        home = os.environ.get("HOME")
        if home:
            env["HOME"] = home
        return env

    def _run(self, template: list[str], **values: str) -> subprocess.CompletedProcess[str]:
        args = [self._config.command]
        for part in template:
            filled = part
            for key, value in values.items():
                filled = filled.replace("{" + key + "}", value)
            args.append(filled)
        try:
            return subprocess.run(  # noqa: S603 - list args, shell=False, validated input
                args,
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds,
                shell=False,
                check=False,
                env=self._minimal_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallError(f"Firewall command failed to run: {exc}") from exc

    @staticmethod
    def _require_valid_ip(ip: str) -> None:
        if not is_valid_ip(ip):
            raise FirewallError(f"Refusing firewall action for invalid IP: {ip!r}")

    def block_ip(self, ip: str) -> bool:
        self._require_valid_ip(ip)
        result = self._run(self._config.block_args, ip=ip)
        return result.returncode == 0

    def unblock_ip(self, ip: str) -> bool:
        self._require_valid_ip(ip)
        result = self._run(self._config.unblock_args, ip=ip)
        return result.returncode == 0

    def temporary_block(self, ip: str, duration_seconds: int) -> bool:
        self._require_valid_ip(ip)
        result = self._run(
            self._config.temp_block_args, ip=ip, duration=str(int(duration_seconds))
        )
        return result.returncode == 0

    def list_blocked(self) -> list[str]:
        result = self._run(self._config.list_args)
        if result.returncode != 0:
            raise FirewallError(
                f"Firewall list command exited {result.returncode}: "
                f"{result.stderr.strip()[:200]}"
            )
        return [
            token
            for line in result.stdout.splitlines()
            for token in line.split()
            if is_valid_ip(token)
        ]

    def is_blocked(self, ip: str) -> bool:
        return ip in self.list_blocked()


def create_firewall(config: FirewallConfig) -> FirewallController:
    """Factory building the configured adapter."""
    if config.adapter == "python":
        return PythonModuleAdapter(config)
    if config.adapter == "command":
        return CommandAdapter(config)
    return DryRunAdapter()
