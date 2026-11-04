"""Telegram Bot API notifier (plain text, no parse_mode)."""

from __future__ import annotations

import re

import requests

from sentinelai.notify.base import (
    DigestMessage,
    NotifyError,
    clean_text,
    new_session,
    post_json,
)

#: Telegram rejects messages above 4096 characters.
MAX_TEXT_CHARS = 4000
_TOKEN_RE = re.compile(r"[0-9]{1,20}:[A-Za-z0-9_-]{10,128}")
_CHAT_ID_RE = re.compile(r"-?[0-9]{1,20}|@[A-Za-z0-9_]{5,64}")


class TelegramNotifier:
    """Send digests with ``sendMessage``; the bot token never leaves this class."""

    name = "telegram"

    def __init__(
        self,
        token: str,
        chat_id: str,
        timeout: float,
        session: requests.Session | None = None,
    ) -> None:
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            raise NotifyError("telegram bot token has an invalid format")
        chat = str(chat_id).strip()
        if not _CHAT_ID_RE.fullmatch(chat):
            raise NotifyError("telegram chat id has an invalid format")
        self._token = token
        self._chat_id = chat
        self._timeout = timeout
        self._owns_session = session is None
        self._session = new_session() if session is None else session

    def __repr__(self) -> str:
        return "TelegramNotifier()"

    def close(self) -> None:
        """Close the HTTP session if this notifier created it."""
        if self._owns_session:
            self._session.close()

    def send(self, message: DigestMessage) -> None:
        subject = clean_text(message.subject, 200)
        body = clean_text(message.body, MAX_TEXT_CHARS)
        text = clean_text(f"{subject}\n\n{body}" if subject else body, MAX_TEXT_CHARS)
        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        post_json(self._session, url, payload, self._timeout, "telegram")
