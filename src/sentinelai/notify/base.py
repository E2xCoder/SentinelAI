"""Shared notification types, text sanitising and hardened HTTP helpers.

Error messages never contain secrets (tokens, webhook URLs, passwords) or the
message body.
"""

from __future__ import annotations

import contextlib
import time
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

import requests

from sentinelai.core.exceptions import SentinelError

if TYPE_CHECKING:
    from sentinelai.config.models import NotifyConfig

#: Response bodies are never read beyond this many bytes.
MAX_RESPONSE_BYTES = 65_536
_CHUNK_BYTES = 8_192
#: Tiny reads so the total deadline is re-checked often (a dripping server cannot hide).
_DRAIN_CHUNK_BYTES = 1
_ELLIPSIS = "…"
#: Control, format (bidi/zero-width), line- and paragraph-separator characters.
_STRIPPED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


class NotifyError(SentinelError):
    """Raised when a notification cannot be built or delivered."""

    exit_code = 11


@dataclass(frozen=True, slots=True)
class DigestMessage:
    """A plain-text digest: no markup, no attachments."""

    subject: str
    body: str


class Notifier(Protocol):
    """A delivery channel for :class:`DigestMessage`."""

    name: str

    def send(self, message: DigestMessage) -> None:
        """Deliver ``message`` or raise :class:`NotifyError` (secret-free text)."""
        ...


def clean_text(value: object, max_len: int) -> str:
    """Return ``value`` as text without control characters (newline kept), capped."""
    text = value if isinstance(value, str) else str(value)
    text = text.replace("\t", " ")
    text = "".join(
        ch for ch in text if ch == "\n" or unicodedata.category(ch) not in _STRIPPED_CATEGORIES
    )
    if max_len <= 0:
        return ""
    if len(text) > max_len:
        return text[: max_len - 1] + _ELLIPSIS if max_len > 1 else text[:max_len]
    return text


def new_session() -> requests.Session:
    """A session that ignores proxy environment variables and ``~/.netrc``."""
    session = requests.Session()
    session.trust_env = False
    return session


def _drain_limited(
    response: requests.Response,
    deadline: float | None = None,
    channel: str = "notify",
) -> None:
    """Read (and discard) at most :data:`MAX_RESPONSE_BYTES` of the body.

    When ``deadline`` (a :func:`time.monotonic` value) passes, the read is
    aborted with :class:`NotifyError`, so a server that drips bytes cannot
    stall the caller beyond the configured total timeout.
    """
    total = 0
    for chunk in response.iter_content(chunk_size=_DRAIN_CHUNK_BYTES):
        total += len(chunk)
        if total >= MAX_RESPONSE_BYTES:
            break
        if deadline is not None and time.monotonic() > deadline:
            raise NotifyError(f"{channel} response too slow")


def post_json(
    session: requests.Session,
    url: str,
    payload: Mapping[str, Any],
    timeout: float,
    channel: str,
) -> None:
    """POST ``payload`` as JSON; raise a secret-free :class:`NotifyError` on failure.

    ``url`` may contain a secret, so it is never included in any message.
    """
    deadline = time.monotonic() + max(0.0, float(timeout))
    try:
        response = session.post(
            url,
            json=dict(payload),
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
    except requests.RequestException as exc:
        raise NotifyError(f"{channel} request failed ({type(exc).__name__})") from None
    try:
        status = response.status_code
        if not 200 <= status < 300:
            raise NotifyError(f"{channel} returned HTTP {status}")
        if time.monotonic() > deadline:
            raise NotifyError(f"{channel} response too slow")
        # The message was accepted (2xx); an unreadable body is not a failure.
        with contextlib.suppress(requests.RequestException):
            _drain_limited(response, deadline, channel)
    finally:
        response.close()


def _as_names(channels: object) -> list[str]:
    if isinstance(channels, str):
        items: Sequence[object] = channels.split(",")
    elif isinstance(channels, Sequence):
        items = channels
    else:
        raise NotifyError("notify channels must be a list of names")
    names: list[str] = []
    for item in items:
        name = str(item).strip().lower()
        if name and name not in names:
            names.append(name)
    return names


def _as_recipients(value: object) -> list[str]:
    if isinstance(value, str):
        items: Sequence[object] = value.split(",")
    elif isinstance(value, Sequence):
        items = value
    else:
        return []
    return [text for text in (str(item).strip() for item in items) if text]


def build_notifiers(
    config: NotifyConfig, *, session: requests.Session | None = None
) -> list[Notifier]:
    """Build one notifier per enabled channel, in configured order.

    All channels with missing secrets/settings are reported in a single
    :class:`NotifyError` so nothing is partially sent.
    """
    # Imported here: the channel modules import this module.
    from sentinelai.notify.email import EmailNotifier
    from sentinelai.notify.slack import SlackNotifier
    from sentinelai.notify.telegram import TelegramNotifier

    names = _as_names(config.channels)
    unknown = [name for name in names if name not in ("telegram", "slack", "email")]
    if unknown:
        raise NotifyError(
            "unknown notify channel(s): " + ", ".join(clean_text(n, 32) for n in unknown)
        )

    timeout = float(config.timeout_seconds)
    recipients = _as_recipients(config.email_to)
    missing: list[str] = []
    email_ready = bool(
        config.email_host
        and config.email_from
        and recipients
        and (config.email_password or not config.email_username)
    )
    ready = {
        "telegram": bool(config.telegram_token and config.telegram_chat_id),
        "slack": bool(config.slack_webhook),
        "email": email_ready,
    }
    for name in names:
        if not ready[name]:
            missing.append(name)
    if missing:
        raise NotifyError(
            "notify channel(s) missing credentials or settings: " + ", ".join(missing)
        )

    notifiers: list[Notifier] = []
    for name in names:
        if name == "telegram":
            notifiers.append(
                TelegramNotifier(
                    config.telegram_token,
                    str(config.telegram_chat_id),
                    timeout,
                    session=session,
                )
            )
        elif name == "slack":
            notifiers.append(SlackNotifier(config.slack_webhook, timeout, session=session))
        else:
            notifiers.append(
                EmailNotifier(
                    config.email_host,
                    int(config.email_port),
                    config.email_username,
                    config.email_password,
                    config.email_from,
                    recipients,
                    bool(config.email_starttls),
                    timeout,
                )
            )
    return notifiers
