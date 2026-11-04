"""Environment diagnostics (``sentinel doctor``).

Every check is a small function that returns :class:`CheckResult` objects and
never raises: an unexpected exception becomes a ``fail`` result carrying only
the exception class name. All side effects (HTTP, environment, platform,
executable lookup) are injectable so the checks are testable offline. Secret
values (API keys, tokens, webhooks) are never printed, only their presence.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path
from typing import Any

import requests

from sentinelai.config.loader import _read_yaml, _restrict_overlay, overlay_path
from sentinelai.config.models import NotifyConfig, SentinelConfig, parse_suppressions
from sentinelai.core.store import AlertStore
from sentinelai.firewall.adapters import create_firewall
from sentinelai.notify.slack import validate_webhook_url

OK = "ok"
WARN = "warn"
FAIL = "fail"

_MIN_PYTHON = (3, 10)
_DB_FILENAME = "alerts.db"
_LLM_PROBE_TIMEOUT = 3.0
_LLM_PROBE_MAX_BYTES = 1_048_576
_TELEGRAM_TOKEN_RE = re.compile(r"^[0-9]{1,20}:[A-Za-z0-9_-]{10,128}$")  # = notify/telegram.py
_SMTPS_PORT = 465


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Outcome of one diagnostic check (``status``: ok, warn or fail)."""

    name: str
    status: str
    detail: str
    hint: str = ""


@dataclass(frozen=True, slots=True)
class _Context:
    http_get: Callable[..., Any]
    env: Mapping[str, str]
    platform: str
    which: Callable[[str], str | None]


_Check = Callable[[SentinelConfig, _Context], list[CheckResult]]


class _BoundedResponse:
    """Minimal response: status plus at most :data:`_LLM_PROBE_MAX_BYTES` of body."""

    def __init__(self, status_code: int, content: bytes) -> None:
        self.status_code = status_code
        self.content = content

    def json(self) -> Any:
        return json.loads(self.content)

    def close(self) -> None:
        """Nothing to release: the body is already read."""


def _bounded_get(url: str, **kwargs: Any) -> _BoundedResponse:
    """GET without proxies/netrc/redirects, reading at most 1 MB within the timeout."""
    timeout = float(kwargs.get("timeout", _LLM_PROBE_TIMEOUT))
    deadline = time.monotonic() + timeout
    with requests.Session() as session:
        session.trust_env = False
        response = session.get(url, timeout=timeout, allow_redirects=False, stream=True)
        try:
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_content(chunk_size=65_536):
                chunks.append(chunk[: _LLM_PROBE_MAX_BYTES - size])
                size += len(chunk)
                if size >= _LLM_PROBE_MAX_BYTES or time.monotonic() > deadline:
                    break
            return _BoundedResponse(response.status_code, b"".join(chunks))
        finally:
            response.close()


def _result(name: str, status: str, detail: str, hint: str = "") -> list[CheckResult]:
    return [CheckResult(name, status, detail, hint)]


# -- checks ---------------------------------------------------------------


def _check_python(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    version = ".".join(str(part) for part in sys.version_info[:3])
    if sys.version_info[:2] >= _MIN_PYTHON:
        return _result("python", OK, f"Python {version}")
    return _result(
        "python", FAIL, f"Python {version} is too old", "SentinelAI needs Python 3.10 or newer"
    )


def _check_config_source(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    source = config.source_path or "built-in defaults"
    return _result("config", OK, f"loaded from {source}")


def _check_ai_deps(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    missing = [name for name in ("sklearn", "numpy") if find_spec(name) is None]
    if not missing:
        return _result("ai dependencies", OK, "scikit-learn and numpy are importable")
    pretty = ", ".join("scikit-learn" if name == "sklearn" else name for name in missing)
    return _result(
        "ai dependencies",
        WARN,
        f"missing: {pretty} (anomaly detection unavailable)",
        "pip install 'sentinelai[ai]'",
    )


def _check_state_dir(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    state_dir = config.resolve_state_dir()
    if not state_dir.is_dir():
        return _result("state directory", FAIL, f"{state_dir} is not a directory")
    handle, temp_name = tempfile.mkstemp(prefix=".doctor-", dir=state_dir)
    os.close(handle)
    os.unlink(temp_name)
    return _result("state directory", OK, f"{state_dir} is writable")


def _check_database(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    db_path = config.resolve_state_dir() / _DB_FILENAME
    if not db_path.exists():
        return _result("alert database", OK, f"{db_path} not created yet (made on first run)")
    store = AlertStore(db_path)
    try:
        version = store.schema_version
    finally:
        store.close()
    return _result("alert database", OK, f"{db_path} opens, schema version {version}")


def _check_overlay(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    path = overlay_path(config)
    if not path.is_file():
        return _result("tuning overlay", OK, "none present")
    data = _read_yaml(path)
    detection = data.get("detection")
    raw_suppressions = detection.get("suppressions") if isinstance(detection, dict) else None
    _restrict_overlay(data)
    if raw_suppressions is not None:
        parse_suppressions(raw_suppressions)
    return _result("tuning overlay", OK, f"{path} is valid")


def _log_path_hint(path: str) -> str:
    if path.startswith("/var/log/"):
        return (
            "On Debian/Ubuntu add your user to the adm group "
            "(sudo usermod -aG adm $USER, then log in again) or run with sudo"
        )
    return "Grant read access to this file or run with sudo"


def _check_one_log_path(raw: str) -> CheckResult:
    name = f"log path {raw}"
    path = Path(raw).expanduser()
    if not path.exists():
        return CheckResult(name, WARN, "does not exist", "Check live.paths in config.yaml")
    try:
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode):
            return CheckResult(
                name, WARN, "not a regular file", "Point live.paths at a plain log file"
            )
        # O_NONBLOCK: never hang on a FIFO that replaced the file after the stat.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return CheckResult(
                    name, WARN, "not a regular file", "Point live.paths at a plain log file"
                )
        finally:
            os.close(fd)
        size = info.st_size
    except OSError:
        return CheckResult(name, FAIL, "exists but is not readable", _log_path_hint(raw))
    return CheckResult(name, OK, f"readable, {size} bytes")


def _check_live_paths(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    if ctx.platform.startswith("win"):
        return _result(
            "live log paths",
            WARN,
            "log monitoring is Linux-oriented; paths not checked on Windows",
            "Run SentinelAI on Linux, or analyze exported log files with the offline commands",
        )
    results: list[CheckResult] = []
    for raw in config.live.paths:
        try:
            results.append(_check_one_log_path(str(raw)))
        except Exception as exc:  # noqa: BLE001 - checks must never raise
            results.append(CheckResult(f"log path {raw}", FAIL, type(exc).__name__))
    return results


def _intel_env_name(provider: str) -> str:
    return f"SENTINELAI_INTEL_{provider.upper()}_API_KEY"


def _check_intel(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    intel = config.intel
    if not intel.enabled:
        return _result("threat intel", OK, "disabled")
    results: list[CheckResult] = []
    if getattr(intel, "offline", False):
        results.append(
            CheckResult("threat intel mode", OK, "offline mode: no external lookups are made")
        )
    enabled = 0
    for provider in ("abuseipdb", "virustotal", "otx"):
        settings = getattr(intel, provider)
        if not settings.enabled:
            continue
        enabled += 1
        env_name = _intel_env_name(provider)
        if settings.api_key or ctx.env.get(env_name):
            results.append(CheckResult(f"intel {provider}", OK, "enabled, API key present"))
        else:
            results.append(
                CheckResult(
                    f"intel {provider}",
                    FAIL,
                    "enabled but no API key found",
                    f"set via {env_name}",
                )
            )
    if enabled == 0:
        results.append(CheckResult("threat intel", OK, "no providers enabled"))
    return results


def _model_installed(model: str, names: list[str]) -> bool:
    if model in names:
        return True
    if ":" in model:
        return False
    return any(name.split(":", 1)[0] == model for name in names)


def _fetch_model_names(url: str, ctx: _Context) -> list[str] | str:
    """Return installed model names, or a short failure description."""
    try:
        response = ctx.http_get(url, timeout=_LLM_PROBE_TIMEOUT, allow_redirects=False)
    except Exception as exc:  # noqa: BLE001 - any transport failure means unreachable
        return f"unreachable ({type(exc).__name__})"
    try:
        status = int(response.status_code)
        if status != 200:
            return f"unexpected HTTP {status}"
        body = response.json()
    except Exception as exc:  # noqa: BLE001
        return f"unusable response ({type(exc).__name__})"
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()
    models = body.get("models") if isinstance(body, dict) else None
    if not isinstance(models, list):
        return "unusable response (no model list)"
    return [str(m["name"]) for m in models if isinstance(m, dict) and "name" in m]


def _check_llm(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    from sentinelai.ai.triage_models import api_key_endpoint_allowed

    llm = config.ai.llm
    if not llm.enabled:
        return _result("local llm", OK, "disabled")
    if llm.api_key and not api_key_endpoint_allowed(llm.endpoint):
        return _result(
            "local llm",
            FAIL,
            "an API key is configured for a non-https, non-loopback endpoint",
            "Use an https:// endpoint so the key is never sent in clear text",
        )
    if llm.provider != "ollama":
        return _result("local llm", OK, f"provider {llm.provider}; connectivity not probed")
    names = _fetch_model_names(llm.endpoint.rstrip("/") + "/api/tags", ctx)
    if isinstance(names, str):
        return _result(
            "local llm", WARN, f"{names}; alert explanations fall back to templates",
            "Start Ollama (ollama serve) or fix ai.llm.endpoint",
        )
    if _model_installed(llm.model, names):
        return _result("local llm", OK, f"{len(names)} model(s); '{llm.model}' installed")
    return _result(
        "local llm",
        WARN,
        f"{len(names)} model(s); '{llm.model}' is not installed",
        f"ollama pull {llm.model}",
    )


def _check_firewall(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    adapter = config.firewall.adapter
    response = config.response
    try:
        create_firewall(config.firewall)
    except Exception as exc:  # noqa: BLE001 - adapter construction can fail in many ways
        detail = f"adapter '{adapter}' failed to load ({type(exc).__name__})"
        return _result("firewall", FAIL, detail, "Check the firewall section of config.yaml")
    results = [CheckResult("firewall", OK, f"adapter '{adapter}' loaded")]
    if adapter == "command" and ctx.which(config.firewall.command) is None:
        results.append(
            CheckResult(
                "firewall command",
                FAIL if response.enabled else WARN,
                "configured command was not found on PATH",
                "Install the firewall tool or fix firewall.command",
            )
        )
    if response.enabled and adapter == "dry_run":
        results.append(
            CheckResult(
                "firewall response",
                WARN,
                "response is enabled but the adapter is dry_run: nothing will really be blocked",
                "Set firewall.adapter to python or command for real blocking",
            )
        )
    if response.enabled and response.mode == "auto":
        results.append(
            CheckResult(
                "response mode",
                WARN,
                "automatic blocking without human approval",
                "consider mode: approval first",
            )
        )
    return results


def _check_guard(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    from sentinelai.firewall.lockout import LockoutGuard

    guard = LockoutGuard(config.response, env=ctx.env)
    return _result("response guard", OK, guard.describe_session_protection())


def _notify_secret(config_value: str, env_name: str, ctx: _Context) -> str:
    """Return the secret from config or environment ("" when absent); never reported."""
    return config_value or ctx.env.get(env_name, "")


def _missing_result(label: str, missing: list[str], hint: str) -> CheckResult:
    return CheckResult(label, FAIL, "missing: " + ", ".join(missing), hint)


def _check_notify_telegram(notify: NotifyConfig, ctx: _Context) -> CheckResult:
    env_name = "SENTINELAI_NOTIFY_TELEGRAM_TOKEN"
    missing: list[str] = []
    token = _notify_secret(notify.telegram_token, env_name, ctx)
    if not token:
        missing.append(env_name)
    if not notify.telegram_chat_id:
        missing.append("notify.telegram_chat_id")
    if missing:
        return _missing_result("notify telegram", missing, f"set via {env_name} and config.yaml")
    if not _TELEGRAM_TOKEN_RE.fullmatch(token):
        return CheckResult(
            "notify telegram",
            FAIL,
            "token format is invalid (expected <digits>:<letters, digits, - or _>)",
            "Copy the token from @BotFather exactly",
        )
    return CheckResult("notify telegram", OK, "token and chat id present")


def _check_notify_slack(notify: NotifyConfig, ctx: _Context) -> CheckResult:
    env_name = "SENTINELAI_NOTIFY_SLACK_WEBHOOK"
    webhook = _notify_secret(notify.slack_webhook, env_name, ctx)
    if not webhook:
        return _missing_result("notify slack", [env_name], f"set via {env_name}")
    error = validate_webhook_url(webhook)
    if error is not None:
        return CheckResult(
            "notify slack", FAIL, error, "Use the https://hooks.slack.com/... webhook URL"
        )
    return CheckResult("notify slack", OK, "webhook present (https)")


def _check_notify_email(notify: NotifyConfig, ctx: _Context) -> CheckResult:
    env_name = "SENTINELAI_NOTIFY_EMAIL_PASSWORD"
    label = "notify email"
    missing: list[str] = []
    if not notify.email_host:
        missing.append("notify.email_host")
    if not notify.email_from:
        missing.append("notify.email_from")
    if not notify.email_to:
        missing.append("notify.email_to")
    has_password = bool(_notify_secret(notify.email_password, env_name, ctx))
    if notify.email_username and not has_password:
        missing.append(env_name)
    if missing:
        return _missing_result(label, missing, f"set in config.yaml; password via {env_name}")
    details: list[str] = []
    hints: list[str] = []
    if not notify.email_starttls and int(notify.email_port) != _SMTPS_PORT:
        details.append("plain SMTP: digest content is sent in cleartext")
        hints.append("Set notify.email_starttls: true, or use port 465 (SMTPS)")
    if not notify.email_username:
        details.append("no email_username set: mail is sent without authentication")
        hints.append(
            "Set notify.email_username and the password env var if your server requires login"
        )
    if details:
        return CheckResult(label, WARN, "; ".join(details), "; ".join(hints))
    return CheckResult(label, OK, "host, addresses and credentials present")


_NOTIFY_CHECKS: Mapping[str, Callable[[NotifyConfig, _Context], CheckResult]] = {
    "telegram": _check_notify_telegram,
    "slack": _check_notify_slack,
    "email": _check_notify_email,
}


def _check_notify(config: SentinelConfig, ctx: _Context) -> list[CheckResult]:
    notify = config.notify
    if not notify.channels:
        return _result("notifications", OK, "no notification channel configured (optional)")
    results: list[CheckResult] = []
    for channel in notify.channels:
        check = _NOTIFY_CHECKS.get(str(channel))
        if check is None:
            results.append(
                CheckResult(
                    "notify channel",
                    FAIL,
                    "unknown channel configured",
                    "Valid channels: telegram, slack, email",
                )
            )
        else:
            results.append(check(notify, ctx))
    return results


# -- runner ---------------------------------------------------------------

_CHECKS: tuple[tuple[str, _Check], ...] = (
    ("python", _check_python),
    ("config", _check_config_source),
    ("ai dependencies", _check_ai_deps),
    ("state directory", _check_state_dir),
    ("alert database", _check_database),
    ("tuning overlay", _check_overlay),
    ("live log paths", _check_live_paths),
    ("threat intel", _check_intel),
    ("local llm", _check_llm),
    ("firewall", _check_firewall),
    ("response guard", _check_guard),
    ("notifications", _check_notify),
)


def run_checks(
    config: SentinelConfig,
    *,
    http_get: Callable[..., Any] | None = None,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    which: Callable[[str], str | None] | None = None,
) -> list[CheckResult]:
    """Run every diagnostic in order; never raises."""
    ctx = _Context(
        http_get=http_get if http_get is not None else _bounded_get,
        env=env if env is not None else os.environ,
        platform=platform if platform is not None else sys.platform,
        which=which if which is not None else shutil.which,
    )
    results: list[CheckResult] = []
    for name, check in _CHECKS:
        try:
            results.extend(check(config, ctx))
        except Exception as exc:  # noqa: BLE001 - a broken check must not stop the doctor
            results.append(CheckResult(name, FAIL, type(exc).__name__))
    return results


def summarize(results: Sequence[CheckResult]) -> tuple[int, int, int]:
    """Return ``(ok, warn, fail)`` counts."""
    return (
        sum(1 for r in results if r.status == OK),
        sum(1 for r in results if r.status == WARN),
        sum(1 for r in results if r.status == FAIL),
    )
