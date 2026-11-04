"""Detect which log sources and security tools exist on this host.

Detection is read-only: it only checks that files exist, whether the current
user may read them (``os.access``) and their size (``stat``). File contents are
never opened. Every filesystem lookup goes through ``root`` so tests can build a
fake tree in a temporary directory.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_UNSUPPORTED_PLATFORMS = ("win32", "darwin")

_UNREADABLE_NOTE = (
    "not readable by this user; add the user to the 'adm' group "
    "(e.g. `sudo usermod -aG adm $USER`, then log in again) or run with enough privileges"
)

_DOCKER_SOCKET = "/var/run/docker.sock"

#: ``(kind, label, path)`` in priority order; per kind only the first existing file is kept.
_CANDIDATES: tuple[tuple[str, str, str], ...] = (
    ("auth", "Authentication log", "/var/log/auth.log"),
    ("auth", "Authentication log", "/var/log/secure"),
    ("syslog", "System log", "/var/log/syslog"),
    ("syslog", "System log", "/var/log/messages"),
    ("nginx_access", "Nginx access log", "/var/log/nginx/access.log"),
    ("nginx_error", "Nginx error log", "/var/log/nginx/error.log"),
    ("apache_access", "Apache access log", "/var/log/apache2/access.log"),
    ("apache_access", "Apache access log", "/var/log/httpd/access_log"),
    ("apache_error", "Apache error log", "/var/log/apache2/error.log"),
    ("apache_error", "Apache error log", "/var/log/httpd/error_log"),
    ("fail2ban", "Fail2ban log", "/var/log/fail2ban.log"),
    ("ufw", "UFW firewall log", "/var/log/ufw.log"),
)


@dataclass(frozen=True, slots=True)
class DetectedSource:
    """A log file found on the host."""

    path: str
    kind: str
    label: str
    readable: bool
    size_bytes: int
    note: str = ""


@dataclass(slots=True)
class Detection:
    """Result of probing the host."""

    sources: list[DetectedSource]
    docker_present: bool
    ufw_present: bool
    fail2ban_present: bool
    nginx_present: bool
    apache_present: bool
    notes: list[str]


def _resolve(root: Path, posix_path: str) -> Path:
    """Map a canonical absolute POSIX path onto ``root``."""
    return root.joinpath(*PurePosixPath(posix_path).parts[1:])


def _exists(root: Path, posix_path: str) -> bool:
    try:
        return _resolve(root, posix_path).exists()
    except OSError:
        return False


def _safe_which(which: Callable[[str], str | None], name: str) -> bool:
    try:
        return bool(which(name))
    except Exception:  # noqa: BLE001 - an injected lookup must never break detection
        return False


def _probe(root: Path, kind: str, label: str, posix_path: str) -> DetectedSource | None:
    """Return a :class:`DetectedSource` when the file exists, else ``None``."""
    real = _resolve(root, posix_path)
    try:
        if not real.is_file():
            return None
        size = int(real.stat().st_size)
        readable = bool(os.access(real, os.R_OK))
    except OSError:
        return None
    return DetectedSource(
        path=posix_path,
        kind=kind,
        label=label,
        readable=readable,
        size_bytes=size,
        note="" if readable else _UNREADABLE_NOTE,
    )


def _find_sources(root: Path) -> list[DetectedSource]:
    found: list[DetectedSource] = []
    seen_kinds: set[str] = set()
    for kind, label, path in _CANDIDATES:
        if kind in seen_kinds:
            continue
        source = _probe(root, kind, label, path)
        if source is not None:
            found.append(source)
            seen_kinds.add(kind)
    return found


def _detect(root: Path, which: Callable[[str], str | None]) -> Detection:
    sources = _find_sources(root)
    kinds = {source.kind for source in sources}
    notes: list[str] = []

    docker_present = _exists(root, _DOCKER_SOCKET) or _safe_which(which, "docker")
    if docker_present:
        notes.append(
            "Docker detected. Docker daemon logs come from journald, not a file: run "
            "`journalctl -u docker -o short-iso > docker.log` and then "
            "`sentinel scan docker.log`."
        )

    nginx_present = (
        bool(kinds & {"nginx_access", "nginx_error"})
        or _exists(root, "/var/log/nginx")
        or _safe_which(which, "nginx")
    )
    apache_present = (
        bool(kinds & {"apache_access", "apache_error"})
        or _exists(root, "/var/log/apache2")
        or _exists(root, "/var/log/httpd")
        or _safe_which(which, "apache2")
        or _safe_which(which, "httpd")
    )
    return Detection(
        sources=sources,
        docker_present=docker_present,
        ufw_present=_safe_which(which, "ufw"),
        fail2ban_present=_safe_which(which, "fail2ban-client") or "fail2ban" in kinds,
        nginx_present=nginx_present,
        apache_present=apache_present,
        notes=notes,
    )


def _empty(notes: list[str]) -> Detection:
    return Detection(
        sources=[],
        docker_present=False,
        ufw_present=False,
        fail2ban_present=False,
        nginx_present=False,
        apache_present=False,
        notes=notes,
    )


def detect_environment(
    *,
    root: Path = Path("/"),
    which: Callable[[str], str | None] = shutil.which,
    platform: str | None = None,
) -> Detection:
    """Probe the host for log files and security tools. Never raises."""
    try:
        current = platform if platform is not None else sys.platform
        if current in _UNSUPPORTED_PLATFORMS:
            return _empty(
                [
                    "SentinelAI's live monitoring targets Linux, so no log sources were "
                    "detected on this system. `sentinel scan <file>` works anywhere."
                ]
            )
        return _detect(Path(root), which)
    except Exception as exc:  # noqa: BLE001 - detection is best-effort by contract
        return _empty(
            [f"Detection failed unexpectedly ({type(exc).__name__}); nothing was changed."]
        )


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size / (1024 * 1024):.1f} MiB"


def explain_choices(detection: Detection) -> list[str]:
    """Plain-language summary of what was found and what will happen."""
    lines: list[str] = []
    readable = [s for s in detection.sources if s.readable]
    unreadable = [s for s in detection.sources if not s.readable]

    if detection.sources:
        lines.append(f"Found {len(detection.sources)} log file(s) on this machine.")
    else:
        lines.append("No known log files were found.")

    if readable:
        lines.append("Will monitor:")
        lines.extend(
            f"  - {s.path} ({s.label}, {_format_size(s.size_bytes)})" for s in readable
        )
    else:
        lines.append(
            "Nothing will be monitored automatically; the default paths stay in the "
            "config as comments."
        )

    if unreadable:
        lines.append("Skipped (cannot be read by this user):")
        lines.extend(f"  - {s.path}" for s in unreadable)
        lines.append(
            "  Fix: add your user to the 'adm' group "
            "(`sudo usermod -aG adm $USER`), log in again and re-run setup."
        )

    tools = [
        name
        for name, present in (
            ("Docker", detection.docker_present),
            ("UFW", detection.ufw_present),
            ("Fail2ban", detection.fail2ban_present),
            ("Nginx", detection.nginx_present),
            ("Apache", detection.apache_present),
        )
        if present
    ]
    if tools:
        lines.append(f"Also detected: {', '.join(tools)}.")

    lines.extend(detection.notes)
    lines.append(
        "Automatic blocking stays OFF. Responses are only proposed for your approval "
        "and the firewall adapter is a dry run."
    )
    return lines


def _quote(value: str) -> str:
    """Quote a string as a YAML double-quoted scalar (JSON escapes are valid YAML)."""
    return json.dumps(value, ensure_ascii=True)


def _live_section(detection: Detection) -> list[str]:
    paths: list[str] = []
    for source in detection.sources:
        if source.readable and source.path not in paths:
            paths.append(source.path)
    lines = [
        "# -----------------------------------------------------------------------------",
        "# Live monitoring (`sentinel live`)",
        "# -----------------------------------------------------------------------------",
        "live:",
    ]
    if paths:
        lines.append("  # Only log files that exist and are readable by the current user.")
        lines.append("  paths:")
        lines.extend(f"    - {_quote(path)}" for path in paths)
    else:
        lines.append("  # No readable log file was detected, so the built-in defaults apply.")
        lines.append("  # paths:")
        lines.append('  #   - "/var/log/auth.log"')
        lines.append('  #   - "/var/log/syslog"')
    lines.append("  # poll_interval_seconds: 1.0")
    lines.append("  from_beginning: false           # true = also process existing content")
    lines.append("  # dedup_window_seconds: 300")
    return lines


def render_config(
    detection: Detection,
    *,
    state_dir: str = "",
    enable_llm: bool = False,
    llm_model: str = "llama3.1:8b",
) -> str:
    """Return a commented ``config.yaml`` text that ``load_config`` accepts."""
    rule = "# " + "-" * 77
    lines: list[str] = [
        "# =============================================================================",
        "# SentinelAI configuration",
        "# =============================================================================",
        "# Generated by `sentinel init`. Safe to edit by hand; see config.example.yaml",
        "# for every available option. Values left commented out use the defaults.",
        "# Any value can be overridden by a SENTINELAI_<SECTION>_<KEY> environment variable.",
        "# =============================================================================",
        "",
    ]

    if state_dir:
        lines.append("# Directory for runtime state (alert DB, TI cache, saved models).")
        lines.append(f"state_dir: {_quote(state_dir)}")
    else:
        lines.append("# Directory for runtime state (default: ~/.sentinelai).")
        lines.append('# state_dir: "~/.sentinelai"')
    lines.append("")

    lines.extend(_live_section(detection))
    lines.append("")

    lines.extend(
        [
            rule,
            "# Detection thresholds (defaults shown; uncomment a line to change it)",
            "# `sentinel tune` stores approved changes in its own overlay, not in this file.",
            rule,
            "# detection:",
            "#   brute_force_attempts: 5",
            "#   brute_force_window_seconds: 300",
            "#   password_spray_users: 4",
            "#   password_spray_window_seconds: 600",
            "#   credential_stuffing_attempts: 8",
            "#   credential_stuffing_window_seconds: 300",
            "#   repeated_failure_attempts: 10",
            "#   repeated_failure_window_seconds: 900",
            "#   port_scan_ports: 10",
            "#   port_scan_window_seconds: 60",
            "#   impossible_frequency_attempts: 10",
            "#   impossible_frequency_window_seconds: 10",
            "",
            rule,
            "# Threat intelligence",
            "# All providers are OFF. To use one, set enabled: true for it and provide the",
            "# API key through an environment variable, never in this file, e.g.",
            "#   SENTINELAI_INTEL_ABUSEIPDB_API_KEY=xxxx",
            "#   SENTINELAI_INTEL_VIRUSTOTAL_API_KEY=xxxx",
            "#   SENTINELAI_INTEL_OTX_API_KEY=xxxx",
            rule,
            "intel:",
            "  enabled: true",
            "  abuseipdb:",
            "    enabled: false",
            "  virustotal:",
            "    enabled: false",
            "  otx:",
            "    enabled: false",
            "",
            rule,
            "# AI engine (anomaly detection needs: pip install 'sentinelai[ai]')",
            rule,
            "ai:",
            "  enabled: true",
            "  # Optional local LLM for `sentinel explain`. Its verdict is advisory only and",
            "  # never changes risk scores, alerts or responses. For provider: openai set the",
            "  # key via SENTINELAI_AI_LLM_API_KEY, never in this file.",
            "  llm:",
            f"    enabled: {'true' if enable_llm else 'false'}",
            '    provider: "ollama"',
            '    endpoint: "http://localhost:11434"',
            f"    model: {_quote(llm_model)}",
            "",
            rule,
            "# Firewall integration",
            "# dry_run only logs what would be blocked and changes nothing on this machine.",
            rule,
            "firewall:",
            '  adapter: "dry_run"',
            "",
            rule,
            "# Automatic response (OFF)",
            "# BEFORE enabling automatic response, read the \"Safe automated response\"",
            "# section of the README.",
            "#   - mode: approval queues blocks for `sentinel respond --approve ID`;",
            "#     mode: auto blocks immediately.",
            "#   - Lockout protection never blocks the current SSH session's client, the",
            "#     default gateway or this host's own addresses. List your own admin",
            "#     networks in admin_ranges so you can never lock yourself out.",
            rule,
            "response:",
            "  enabled: false",
            '  mode: "approval"',
            '  # admin_ranges: ["203.0.113.0/24"]   # never blocked; replace with your network',
            "  # protect_ssh_peer: true",
            "  # protect_gateway: true",
            "  # protect_own_addresses: true",
            "",
            rule,
            "# Reporting",
            rule,
            "report:",
            '  output_dir: "reports"',
            "",
            rule,
            "# Notifications (optional, not enabled by setup)",
            "# Configure a notification channel here once you need one, for example:",
            "# notify:",
            "#   # see the README for the available channels and their keys",
            rule,
            "",
        ]
    )
    return "\n".join(lines)
