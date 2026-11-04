"""Slack incoming-webhook notifier (escaped plain text)."""

from __future__ import annotations

from urllib.parse import urlsplit

import requests

from sentinelai.notify.base import (
    DigestMessage,
    NotifyError,
    clean_text,
    new_session,
    post_json,
)

#: Kept well below Slack's own message limits.
MAX_TEXT_CHARS = 3500
_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;"}
_ELLIPSIS = "…"


def escape_slack(text: str, limit: int) -> str:
    """Escape ``& < >`` (so ``<!channel>`` and links are inert) within ``limit`` chars."""
    out: list[str] = []
    used = 0
    for ch in text:
        piece = _ESCAPES.get(ch, ch)
        if used + len(piece) > limit - 1:
            out.append(_ELLIPSIS)
            break
        out.append(piece)
        used += len(piece)
    return "".join(out)


def validate_webhook_url(url: str, allow_any_host: bool = False) -> str | None:
    """Return an error text (never containing the URL) if ``url`` is unusable, else ``None``.

    Rule: https, and the host is ``slack.com`` or ``*.slack.com`` (unless
    ``allow_any_host``).
    """
    if not isinstance(url, str) or any(ch.isspace() or ord(ch) < 32 for ch in url):
        return "slack webhook URL is invalid"
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return "slack webhook URL is invalid"
    if parts.scheme != "https" or not host:
        return "slack webhook URL must use https"
    if not allow_any_host and host != "slack.com" and not host.endswith(".slack.com"):
        return "slack webhook host is not under slack.com"
    return None


def _validate_webhook(url: str, allow_any_host: bool) -> None:
    error = validate_webhook_url(url, allow_any_host)
    if error is not None:
        raise NotifyError(error)


class SlackNotifier:
    """Post digests to a Slack webhook; the URL (a secret) is never exposed."""

    name = "slack"

    def __init__(
        self,
        webhook_url: str,
        timeout: float,
        session: requests.Session | None = None,
        allow_any_host: bool = False,
    ) -> None:
        _validate_webhook(webhook_url, allow_any_host)
        self._url = webhook_url
        self._timeout = timeout
        self._owns_session = session is None
        self._session = new_session() if session is None else session

    def __repr__(self) -> str:
        return "SlackNotifier()"

    def close(self) -> None:
        """Close the HTTP session if this notifier created it."""
        if self._owns_session:
            self._session.close()

    def send(self, message: DigestMessage) -> None:
        subject = clean_text(message.subject, 200)
        body = clean_text(message.body, MAX_TEXT_CHARS * 4)
        text = f"{subject}\n\n{body}" if subject else body
        # mrkdwn off: attacker text such as *bold* or :emoji: is not rendered.
        payload = {"text": escape_slack(text, MAX_TEXT_CHARS), "mrkdwn": False}
        post_json(self._session, self._url, payload, self._timeout, "slack")
