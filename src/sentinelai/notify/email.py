"""SMTP e-mail notifier (TLS required whenever credentials are used)."""

from __future__ import annotations

import smtplib
import ssl
from collections.abc import Sequence
from email.message import EmailMessage
from email.utils import formatdate

from sentinelai.notify.base import DigestMessage, NotifyError, clean_text

_SMTPS_PORT = 465
_MAX_BODY_CHARS = 100_000
_MAX_SUBJECT_CHARS = 200


def _check_header_value(value: str, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NotifyError(f"email {what} is empty")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise NotifyError(f"email {what} contains control characters")
    return value.strip()


def _check_address(value: str, what: str) -> str:
    address = _check_header_value(value, what)
    if "@" not in address:
        raise NotifyError(f"email {what} is not an address")
    return address


class EmailNotifier:
    """Send digests over SMTP using ``smtplib`` and ``EmailMessage``."""

    name = "email"

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        sender: str,
        recipients: Sequence[str],
        starttls: bool,
        timeout: float,
    ) -> None:
        if not isinstance(host, str) or not host.strip():
            raise NotifyError("email host is empty")
        if not 1 <= int(port) <= 65535:
            raise NotifyError("email port is out of range")
        if password and not starttls and int(port) != _SMTPS_PORT:
            raise NotifyError("email credentials require TLS (starttls or port 465)")
        self._host = host.strip()
        self._port = int(port)
        self._username = username
        self._password = password
        self._sender = _check_address(sender, "sender")
        self._recipients = [_check_address(r, "recipient") for r in recipients]
        if not self._recipients:
            raise NotifyError("email recipients are empty")
        self._starttls = bool(starttls)
        self._timeout = timeout

    def __repr__(self) -> str:
        return f"EmailNotifier(host={self._host!r}, port={self._port})"

    def _build(self, message: DigestMessage) -> EmailMessage:
        if "\r" in message.subject or "\n" in message.subject:
            raise NotifyError("email subject contains line breaks")
        msg = EmailMessage()
        msg["Subject"] = clean_text(message.subject, _MAX_SUBJECT_CHARS)
        msg["From"] = self._sender
        msg["To"] = ", ".join(self._recipients)
        msg["Date"] = formatdate(localtime=False)
        msg.set_content(
            clean_text(message.body, _MAX_BODY_CHARS), subtype="plain", charset="utf-8"
        )
        return msg

    def _deliver(self, msg: EmailMessage) -> None:
        context = ssl.create_default_context()
        if self._port == _SMTPS_PORT:
            with smtplib.SMTP_SSL(
                self._host, self._port, timeout=self._timeout, context=context
            ) as smtp:
                self._login_and_send(smtp, msg)
            return
        with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
            if self._starttls:
                smtp.starttls(context=context)
            self._login_and_send(smtp, msg)

    def _login_and_send(self, smtp: smtplib.SMTP, msg: EmailMessage) -> None:
        if self._username:
            smtp.login(self._username, self._password)
        smtp.send_message(msg, from_addr=self._sender, to_addrs=self._recipients)

    def send(self, message: DigestMessage) -> None:
        msg = self._build(message)
        try:
            self._deliver(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise NotifyError(f"email delivery failed ({type(exc).__name__})") from None
