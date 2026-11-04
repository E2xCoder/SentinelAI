"""Tests for notifications: config, secrets, channels, digest builder and CLI.

No network and no real SMTP: HTTP goes through hand-written fake sessions and
``smtplib`` is replaced by an in-memory fake. All tokens, webhooks and
passwords below are made-up values.
"""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
import traceback
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import requests
import yaml
from click.testing import CliRunner, Result

import sentinelai.detection.rules  # noqa: F401  (registers the built-in rules)
import sentinelai.notify.email as email_mod
from sentinelai.cli.app import cli
from sentinelai.config.loader import load_config
from sentinelai.config.models import NotifyConfig, SentinelConfig
from sentinelai.core.exceptions import ConfigError
from sentinelai.core.models import Alert, RiskAssessment, RiskLevel
from sentinelai.core.store import AlertStore
from sentinelai.detection.base import available_rules
from sentinelai.notify.base import (
    MAX_RESPONSE_BYTES,
    DigestMessage,
    NotifyError,
    build_notifiers,
    clean_text,
    new_session,
)
from sentinelai.notify.digest import MAX_BODY_CHARS, build_digest
from sentinelai.notify.email import EmailNotifier
from sentinelai.notify.slack import SlackNotifier
from sentinelai.notify.telegram import TelegramNotifier
from sentinelai.risk.engine import RiskEngine
from tests.conftest import make_event

NOW = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
TOKEN = "123456789:ABCdefGhIjKlMnOpQrStUvWxYz012345"
CHAT_ID = "-100123456"
WEBHOOK = "https://hooks.slack.com/services/T0FAKE000/B0FAKE000/FakeSecretPart123"
PASSWORD = "hunter2-fake-password"
MESSAGE = DigestMessage(subject="Daily summary", body="Line one\nLine two")


# -- fakes -----------------------------------------------------------------


class FakeResponse:
    """Just enough of ``requests.Response`` for ``post_json``."""

    def __init__(
        self,
        status_code: int = 200,
        *,
        chunks: int = 1,
        body_error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self.closed = False
        self.chunks_served = 0
        self.bytes_served = 0
        self.requested_chunk_sizes: set[int] = set()
        self._chunks = chunks
        self._body_error = body_error

    @property
    def content(self) -> bytes:
        raise AssertionError("the response body must not be read in one go")

    @property
    def text(self) -> str:
        raise AssertionError("the response body must not be read in one go")

    def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
        if self._body_error is not None:
            raise self._body_error
        self.requested_chunk_sizes.add(chunk_size)
        for _ in range(self._chunks):
            self.chunks_served += 1
            self.bytes_served += chunk_size
            yield b"x" * chunk_size

    def close(self) -> None:
        self.closed = True


class FakeSession:
    """Records ``post`` calls; returns a canned response or raises."""

    def __init__(
        self,
        response: FakeResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response if response is not None else FakeResponse()
        self.error = error
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        if self.error is not None:
            raise self.error
        return self.response

    def close(self) -> None:
        self.closed = True


class SmtpWorld:
    """In-memory replacement for the ``smtplib`` module used by the e-mail notifier."""

    def __init__(self) -> None:
        self.events: list[tuple[Any, ...]] = []
        self.messages: list[Any] = []
        self.fail_on: dict[str, Exception] = {}

    @property
    def kinds(self) -> list[str]:
        return [str(event[0]) for event in self.events]

    def _fail(self, stage: str) -> None:
        if stage in self.fail_on:
            raise self.fail_on[stage]

    def make(self, kind: str) -> type:
        world = self

        class _FakeSmtp:
            def __init__(
                self,
                host: str,
                port: int,
                timeout: float | None = None,
                context: Any = None,
            ) -> None:
                world._fail("connect")
                world.events.append((kind, host, port, timeout, context))

            def __enter__(self) -> _FakeSmtp:
                return self

            def __exit__(self, *exc: object) -> bool:
                world.events.append(("quit",))
                return False

            def starttls(self, context: Any = None) -> None:
                world._fail("starttls")
                world.events.append(("starttls", context))

            def login(self, user: str, password: str) -> None:
                world._fail("login")
                world.events.append(("login", user, password))

            def send_message(self, msg: Any, from_addr: str = "", to_addrs: Any = None) -> None:
                world._fail("send")
                world.messages.append(msg)
                world.events.append(("send", from_addr, list(to_addrs or [])))

        return _FakeSmtp


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("SENTINELAI_"):
            monkeypatch.delenv(name)


@pytest.fixture()
def smtp(monkeypatch: pytest.MonkeyPatch) -> SmtpWorld:
    world = SmtpWorld()
    fake = SimpleNamespace(
        SMTP=world.make("SMTP"),
        SMTP_SSL=world.make("SMTP_SSL"),
        SMTPException=smtplib.SMTPException,
    )
    monkeypatch.setattr(email_mod, "smtplib", fake)
    return world


@pytest.fixture()
def store(tmp_path: Path) -> Iterator[AlertStore]:
    db = AlertStore(tmp_path / "alerts.db")
    try:
        yield db
    finally:
        db.close()


def _notify(**changes: Any) -> NotifyConfig:
    return NotifyConfig(**changes)


def _telegram(session: FakeSession | None = None) -> TelegramNotifier:
    return TelegramNotifier(TOKEN, CHAT_ID, 5.0, session=session)  # type: ignore[arg-type]


def _slack(session: FakeSession | None = None, **kwargs: Any) -> SlackNotifier:
    return SlackNotifier(WEBHOOK, 5.0, session=session, **kwargs)  # type: ignore[arg-type]


def _email(**changes: Any) -> EmailNotifier:
    args: dict[str, Any] = {
        "host": "smtp.example.test",
        "port": 587,
        "username": "",
        "password": "",
        "sender": "sentinel@example.test",
        "recipients": ["ops@example.test"],
        "starttls": True,
        "timeout": 5.0,
    }
    args.update(changes)
    return EmailNotifier(**args)


# -- NotifyConfig validation -----------------------------------------------


class TestNotifyConfigValidation:
    def test_defaults_are_valid(self) -> None:
        _notify().validate()

    def test_enabled_channel_without_secrets_is_valid_at_config_time(self) -> None:
        _notify(channels=["slack"]).validate()

    def test_unknown_channel_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="unknown channel"):
            _notify(channels=["sms"]).validate()

    def test_channels_given_as_string_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="must be a list"):
            _notify(channels="slack").validate()  # type: ignore[arg-type]

    @pytest.mark.parametrize("language", ["fr", "", "EN"])
    def test_bad_language_is_rejected(self, language: str) -> None:
        with pytest.raises(ConfigError, match="language"):
            _notify(language=language).validate()

    @pytest.mark.parametrize("language", ["en", "tr", "de"])
    def test_supported_language_is_accepted(self, language: str) -> None:
        _notify(language=language).validate()

    @pytest.mark.parametrize("value", [0, -1, 51, True, "5", 2.5])
    def test_max_alerts_out_of_range_is_rejected(self, value: Any) -> None:
        with pytest.raises(ConfigError, match="max_alerts"):
            _notify(max_alerts=value).validate()

    @pytest.mark.parametrize("value", [1, 50])
    def test_max_alerts_bounds_are_accepted(self, value: int) -> None:
        _notify(max_alerts=value).validate()

    @pytest.mark.parametrize("value", [0, -5, 65_536, True, "587"])
    def test_email_port_out_of_range_is_rejected(self, value: Any) -> None:
        with pytest.raises(ConfigError, match="email_port"):
            _notify(email_port=value).validate()

    @pytest.mark.parametrize("value", [0, -1, 60.5, 61, float("nan"), float("inf"), True, "10"])
    def test_timeout_out_of_range_is_rejected(self, value: Any) -> None:
        with pytest.raises(ConfigError, match="timeout_seconds"):
            _notify(timeout_seconds=value).validate()

    def test_timeout_upper_bound_is_accepted(self) -> None:
        _notify(timeout_seconds=60).validate()

    def test_starttls_must_be_boolean(self) -> None:
        with pytest.raises(ConfigError, match="email_starttls"):
            _notify(email_starttls="yes").validate()  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "webhook",
        ["http://hooks.slack.com/services/x", "ftp://hooks.slack.com/x", "hooks.slack.com/x"],
    )
    def test_non_https_slack_webhook_is_rejected(self, webhook: str) -> None:
        with pytest.raises(ConfigError, match="https"):
            _notify(slack_webhook=webhook).validate()

    def test_https_slack_webhook_is_accepted(self) -> None:
        _notify(slack_webhook=WEBHOOK).validate()

    @pytest.mark.parametrize(
        "address",
        [
            "a@b@example.test",
            "ops@example.test\r\nBcc: evil@example.test",
            "ops@example.test\nBcc: evil@example.test",
            "ops@example.test\r",
            "ops example.test",
            "no-at-sign.example.test",
            "@example.test",
            "ops@",
            "ops @example.test",
            "",
        ],
    )
    def test_bad_email_to_address_is_rejected(self, address: str) -> None:
        with pytest.raises(ConfigError, match=r"email_to\[0\]"):
            _notify(email_to=[address]).validate()

    def test_bad_address_at_second_position_is_reported_with_its_index(self) -> None:
        with pytest.raises(ConfigError, match=r"email_to\[1\]"):
            _notify(email_to=["ok@example.test", "bad@@example.test"]).validate()

    @pytest.mark.parametrize(
        "address", ["a@b@example.test", "x@example.test\r\nBcc: y@example.test"]
    )
    def test_bad_email_from_is_rejected(self, address: str) -> None:
        with pytest.raises(ConfigError, match="email_from"):
            _notify(email_from=address).validate()

    def test_email_to_must_be_a_list(self) -> None:
        with pytest.raises(ConfigError, match="email_to"):
            _notify(email_to="ops@example.test").validate()  # type: ignore[arg-type]

    def test_telegram_enabled_without_chat_id_is_rejected(self) -> None:
        with pytest.raises(ConfigError, match="telegram_chat_id"):
            _notify(channels=["telegram"]).validate()

    @pytest.mark.parametrize(
        ("settings", "missing"),
        [
            ({"email_from": "s@example.test", "email_to": ["o@example.test"]}, "email_host"),
            ({"email_host": "smtp.example.test", "email_to": ["o@example.test"]}, "email_from"),
            ({"email_host": "smtp.example.test", "email_from": "s@example.test"}, "email_to"),
        ],
    )
    def test_email_enabled_without_settings_is_rejected(
        self, settings: dict[str, Any], missing: str
    ) -> None:
        with pytest.raises(ConfigError, match=missing):
            _notify(channels=["email"], **settings).validate()

    def test_fully_configured_channels_are_accepted(self) -> None:
        _notify(
            channels=["telegram", "slack", "email"],
            telegram_chat_id=CHAT_ID,
            email_host="smtp.example.test",
            email_from="s@example.test",
            email_to=["o@example.test"],
        ).validate()

    def test_secrets_never_appear_in_repr(self) -> None:
        cfg = _notify(slack_webhook=WEBHOOK, telegram_token=TOKEN, email_password=PASSWORD)

        text = repr(cfg) + repr(SentinelConfig(notify=cfg))

        for secret in (WEBHOOK, TOKEN, PASSWORD, "FakeSecretPart123"):
            assert secret not in text


# -- secrets only from the environment -------------------------------------


def _write_config(tmp_path: Path, notify: dict[str, Any]) -> Path:
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump({"state_dir": state.as_posix(), "notify": notify}), encoding="utf-8"
    )
    return path


ALL_CHANNELS_YAML: dict[str, Any] = {
    "channels": ["telegram", "slack", "email"],
    "telegram_chat_id": CHAT_ID,
    "email_host": "smtp.example.test",
    "email_username": "sentinel",
    "email_from": "sentinel@example.test",
    "email_to": ["ops@example.test"],
}


class TestSecretsFromEnvironment:
    def test_env_vars_fill_the_three_secret_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINELAI_NOTIFY_SLACK_WEBHOOK", WEBHOOK)
        monkeypatch.setenv("SENTINELAI_NOTIFY_TELEGRAM_TOKEN", TOKEN)
        monkeypatch.setenv("SENTINELAI_NOTIFY_EMAIL_PASSWORD", PASSWORD)

        config = load_config(_write_config(tmp_path, ALL_CHANNELS_YAML))

        assert config.notify.slack_webhook == WEBHOOK
        assert config.notify.telegram_token == TOKEN
        assert config.notify.email_password == PASSWORD

    def test_without_env_vars_secrets_stay_empty(self, tmp_path: Path) -> None:
        config = load_config(_write_config(tmp_path, ALL_CHANNELS_YAML))

        assert config.notify.slack_webhook == ""
        assert config.notify.telegram_token == ""
        assert config.notify.email_password == ""

    def test_loaded_config_repr_hides_env_secrets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINELAI_NOTIFY_SLACK_WEBHOOK", WEBHOOK)
        monkeypatch.setenv("SENTINELAI_NOTIFY_TELEGRAM_TOKEN", TOKEN)
        monkeypatch.setenv("SENTINELAI_NOTIFY_EMAIL_PASSWORD", PASSWORD)

        config = load_config(_write_config(tmp_path, ALL_CHANNELS_YAML))

        text = repr(config)
        assert TOKEN not in text
        assert PASSWORD not in text
        assert "FakeSecretPart123" not in text

    def test_env_http_webhook_fails_config_validation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINELAI_NOTIFY_SLACK_WEBHOOK", "http://hooks.slack.com/x")

        with pytest.raises(ConfigError, match="https"):
            load_config(_write_config(tmp_path, ALL_CHANNELS_YAML))

    def test_env_secrets_build_three_working_notifiers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINELAI_NOTIFY_SLACK_WEBHOOK", WEBHOOK)
        monkeypatch.setenv("SENTINELAI_NOTIFY_TELEGRAM_TOKEN", TOKEN)
        monkeypatch.setenv("SENTINELAI_NOTIFY_EMAIL_PASSWORD", PASSWORD)
        config = load_config(_write_config(tmp_path, ALL_CHANNELS_YAML))

        notifiers = build_notifiers(config.notify)
        try:
            assert [n.name for n in notifiers] == ["telegram", "slack", "email"]
        finally:
            for notifier in notifiers:
                close = getattr(notifier, "close", None)
                if close is not None:
                    close()


# -- build_notifiers ---------------------------------------------------------


def _full_notify(**changes: Any) -> NotifyConfig:
    settings: dict[str, Any] = {
        "channels": ["telegram", "slack", "email"],
        "telegram_chat_id": CHAT_ID,
        "telegram_token": TOKEN,
        "slack_webhook": WEBHOOK,
        "email_host": "smtp.example.test",
        "email_username": "sentinel",
        "email_password": PASSWORD,
        "email_from": "sentinel@example.test",
        "email_to": ["ops@example.test"],
    }
    settings.update(changes)
    return NotifyConfig(**settings)


class TestBuildNotifiers:
    def test_one_notifier_per_channel_in_configured_order(self) -> None:
        notifiers = build_notifiers(
            _full_notify(channels=["email", "telegram", "slack"]), session=FakeSession()  # type: ignore[arg-type]
        )

        assert [n.name for n in notifiers] == ["email", "telegram", "slack"]

    def test_no_channels_builds_nothing(self) -> None:
        assert build_notifiers(_notify()) == []

    def test_duplicate_and_mixed_case_channels_build_one_notifier(self) -> None:
        notifiers = build_notifiers(
            _full_notify(channels=["Slack", "slack", " SLACK "]),
            session=FakeSession(),  # type: ignore[arg-type]
        )

        assert [n.name for n in notifiers] == ["slack"]

    def test_all_channels_with_missing_secrets_are_listed_in_one_error(self) -> None:
        config = _full_notify(telegram_token="", slack_webhook="", email_password="")

        with pytest.raises(NotifyError) as excinfo:
            build_notifiers(config)

        message = str(excinfo.value)
        for name in ("telegram", "slack", "email"):
            assert name in message

    def test_missing_secrets_error_contains_names_only(self) -> None:
        config = _full_notify(telegram_token="", slack_webhook="", email_password="")

        with pytest.raises(NotifyError) as excinfo:
            build_notifiers(config)

        message = str(excinfo.value)
        for value in (CHAT_ID, "smtp.example.test", "ops@example.test", "sentinel@example.test"):
            assert value not in message

    def test_only_channels_that_are_missing_are_reported(self) -> None:
        config = _full_notify(channels=["telegram", "slack"], slack_webhook="")

        with pytest.raises(NotifyError) as excinfo:
            build_notifiers(config)

        message = str(excinfo.value)
        assert "slack" in message
        assert "telegram" not in message

    def test_no_notifier_is_built_when_any_channel_is_incomplete(self) -> None:
        session = FakeSession()
        config = _full_notify(channels=["slack", "telegram"], telegram_token="")

        with pytest.raises(NotifyError):
            build_notifiers(config, session=session)  # type: ignore[arg-type]

        assert session.calls == []

    def test_email_username_without_password_counts_as_missing(self) -> None:
        with pytest.raises(NotifyError, match="email"):
            build_notifiers(_full_notify(channels=["email"], email_password=""))

    def test_email_without_credentials_is_allowed(self) -> None:
        notifiers = build_notifiers(
            _full_notify(channels=["email"], email_username="", email_password="")
        )

        assert [n.name for n in notifiers] == ["email"]

    def test_unknown_channel_is_rejected(self) -> None:
        with pytest.raises(NotifyError, match="unknown notify channel"):
            build_notifiers(_notify(channels=["sms"]))

    def test_unknown_channel_name_is_sanitised_in_the_error(self) -> None:
        with pytest.raises(NotifyError) as excinfo:
            build_notifiers(_notify(channels=["bad\x1b[2Jname"]))

        assert "\x1b" not in str(excinfo.value)

    def test_notify_error_has_its_own_exit_code(self) -> None:
        assert NotifyError.exit_code == 11


# -- shared text helper -----------------------------------------------------


class TestCleanText:
    def test_control_characters_are_removed_but_newline_is_kept(self) -> None:
        assert clean_text("a\x1b[2Jb\x00c\nd\te", 100) == "a[2Jbc\nd e"

    def test_long_text_is_capped_with_an_ellipsis(self) -> None:
        out = clean_text("x" * 50, 10)

        assert len(out) == 10
        assert out.endswith("…")

    def test_non_positive_cap_gives_empty_text(self) -> None:
        assert clean_text("abc", 0) == ""


# -- Telegram ---------------------------------------------------------------


class TestTelegram:
    def test_sends_json_to_the_bot_api_url(self) -> None:
        session = FakeSession()

        _telegram(session).send(MESSAGE)

        assert len(session.calls) == 1
        call = session.calls[0]
        assert call["url"] == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        assert call["json"]["chat_id"] == CHAT_ID
        assert call["json"]["text"] == "Daily summary\n\nLine one\nLine two"
        assert call["json"]["disable_web_page_preview"] is True
        assert call["timeout"] == 5.0

    def test_payload_has_no_parse_mode(self) -> None:
        session = FakeSession()

        _telegram(session).send(MESSAGE)

        assert "parse_mode" not in session.calls[0]["json"]

    def test_long_body_is_capped(self) -> None:
        session = FakeSession()

        _telegram(session).send(DigestMessage(subject="s", body="word " * 5000))

        assert len(session.calls[0]["json"]["text"]) <= 4000

    def test_control_characters_are_stripped_from_the_text(self) -> None:
        session = FakeSession()

        _telegram(session).send(DigestMessage(subject="Hi\x1b[2J", body="a\x00b\tc"))

        text = session.calls[0]["json"]["text"]
        assert "\x1b" not in text
        assert "\x00" not in text
        assert "\t" not in text

    @pytest.mark.parametrize("status", [400, 401, 429, 500, 302])
    def test_http_error_raises_secret_free_notify_error(self, status: int) -> None:
        session = FakeSession(FakeResponse(status))

        with pytest.raises(NotifyError) as excinfo:
            _telegram(session).send(MESSAGE)

        assert str(excinfo.value) == f"telegram returned HTTP {status}"
        assert session.response.closed

    def test_request_exception_message_has_only_the_class_name(self) -> None:
        leaky = requests.ConnectionError(f"HTTPSConnectionPool: /bot{TOKEN}/sendMessage failed")
        session = FakeSession(error=leaky)

        with pytest.raises(NotifyError) as excinfo:
            _telegram(session).send(MESSAGE)

        assert str(excinfo.value) == "telegram request failed (ConnectionError)"
        assert excinfo.value.__cause__ is None
        assert TOKEN not in "".join(traceback.format_exception(excinfo.value))

    def test_token_never_appears_in_logs_errors_or_repr(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        notifier = _telegram(FakeSession(FakeResponse(500)))

        with pytest.raises(NotifyError) as excinfo:
            notifier.send(MESSAGE)
        _telegram(FakeSession()).send(MESSAGE)

        assert TOKEN not in caplog.text
        assert TOKEN not in str(excinfo.value)
        assert TOKEN not in repr(excinfo.value)
        assert TOKEN not in repr(notifier)
        assert "123456789" not in repr(notifier)

    @pytest.mark.parametrize("token", ["", "not-a-token", "123:short", "abc:ABCdefGhIjKlMnOp"])
    def test_invalid_token_format_is_rejected_without_echoing_it(self, token: str) -> None:
        with pytest.raises(NotifyError) as excinfo:
            TelegramNotifier(token, CHAT_ID, 5.0, session=FakeSession())  # type: ignore[arg-type]

        assert "invalid format" in str(excinfo.value)
        if token:
            assert token not in str(excinfo.value)

    @pytest.mark.parametrize("chat_id", ["", "abc", "12 34", "1234\n5"])
    def test_invalid_chat_id_is_rejected(self, chat_id: str) -> None:
        with pytest.raises(NotifyError, match="chat id"):
            TelegramNotifier(TOKEN, chat_id, 5.0, session=FakeSession())  # type: ignore[arg-type]

    @pytest.mark.parametrize("chat_id", ["12345", "-100123456", "@sentinel_channel"])
    def test_valid_chat_id_forms_are_accepted(self, chat_id: str) -> None:
        TelegramNotifier(TOKEN, chat_id, 5.0, session=FakeSession())  # type: ignore[arg-type]


# -- Slack ------------------------------------------------------------------


class TestSlack:
    def test_posts_escaped_text_to_the_webhook(self) -> None:
        session = FakeSession()

        _slack(session).send(MESSAGE)

        call = session.calls[0]
        assert call["url"] == WEBHOOK
        assert call["json"] == {
            "text": "Daily summary\n\nLine one\nLine two",
            "mrkdwn": False,
        }

    @pytest.mark.parametrize(
        "url",
        [
            "https://slack.com/api/hook",
            "https://hooks.slack.com/services/T/B/x",
            "https://a.b.slack.com/services/T/B/x",
            "https://HOOKS.SLACK.COM/services/T/B/x",
        ],
    )
    def test_slack_hosts_are_accepted(self, url: str) -> None:
        SlackNotifier(url, 5.0, session=FakeSession())  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "url",
        [
            "http://hooks.slack.com/services/T/B/x",
            "ftp://hooks.slack.com/x",
            "hooks.slack.com/services/T/B/x",
            "https://",
            "",
        ],
    )
    def test_non_https_webhook_is_rejected(self, url: str) -> None:
        with pytest.raises(NotifyError):
            SlackNotifier(url, 5.0, session=FakeSession())  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "url",
        [
            "https://evilslack.com/services/T/B/x",
            "https://slack.com.evil.example/services/T/B/x",
            "https://hooks.slack.com.evil.example/x",
            "https://hooks.slack.com@evil.example/x",
            "https://evil.example/hooks.slack.com",
            "https://evil.example/?h=.slack.com",
            "https://notslack.com/x",
            "https://hooks.slack.com\n.evil.example/x",
            "https://hooks.slack.com/x y",
        ],
    )
    def test_host_outside_slack_com_is_rejected(self, url: str) -> None:
        with pytest.raises(NotifyError) as excinfo:
            SlackNotifier(url, 5.0, session=FakeSession())  # type: ignore[arg-type]

        assert "evil" not in str(excinfo.value)

    def test_other_host_is_allowed_only_when_explicitly_requested(self) -> None:
        SlackNotifier(
            "https://chat.example.test/hook",
            5.0,
            session=FakeSession(),  # type: ignore[arg-type]
            allow_any_host=True,
        )

    def test_mentions_markup_and_ampersands_are_escaped(self) -> None:
        session = FakeSession()
        message = DigestMessage(subject="<!channel> & friends", body="<!here> <@U123> <script>")

        _slack(session).send(message)

        text = session.calls[0]["json"]["text"]
        assert "<" not in text
        assert ">" not in text
        assert "&lt;!channel&gt; &amp; friends" in text
        assert "&lt;!here&gt; &lt;@U123&gt; &lt;script&gt;" in text

    def test_text_is_capped_and_entities_are_never_split(self) -> None:
        session = FakeSession()

        _slack(session).send(DigestMessage(subject="s", body="<" * 20000))

        text = session.calls[0]["json"]["text"]
        assert len(text) <= 3500
        assert text.endswith("…")
        leftover = text.replace("&lt;", "").replace("s\n\n", "").replace("…", "")
        assert leftover == ""

    @pytest.mark.parametrize("status", [403, 404, 500, 302])
    def test_http_error_raises_secret_free_notify_error(self, status: int) -> None:
        session = FakeSession(FakeResponse(status))

        with pytest.raises(NotifyError) as excinfo:
            _slack(session).send(MESSAGE)

        assert str(excinfo.value) == f"slack returned HTTP {status}"

    def test_webhook_never_appears_in_logs_errors_or_repr(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        leaky = requests.ConnectionError(f"failed to reach {WEBHOOK}")
        notifier = _slack(FakeSession(error=leaky))

        with pytest.raises(NotifyError) as excinfo:
            notifier.send(MESSAGE)
        with pytest.raises(NotifyError) as bad_status:
            _slack(FakeSession(FakeResponse(500))).send(MESSAGE)

        for secret in (WEBHOOK, "FakeSecretPart123"):
            assert secret not in caplog.text
            assert secret not in str(excinfo.value)
            assert secret not in str(bad_status.value)
            assert secret not in repr(notifier)
            assert secret not in "".join(traceback.format_exception(excinfo.value))

    def test_invalid_webhook_error_does_not_echo_the_url(self) -> None:
        url = "http://hooks.slack.com/services/T/B/LeakyPart"

        with pytest.raises(NotifyError) as excinfo:
            SlackNotifier(url, 5.0, session=FakeSession())  # type: ignore[arg-type]

        assert "LeakyPart" not in str(excinfo.value)


# -- shared HTTP hardening ---------------------------------------------------


class TestHttpRules:
    @pytest.mark.parametrize("factory", [_telegram, _slack], ids=["telegram", "slack"])
    def test_redirects_are_not_followed(
        self, factory: Callable[[FakeSession | None], Any]
    ) -> None:
        session = FakeSession()

        factory(session).send(MESSAGE)

        assert session.calls[0]["allow_redirects"] is False

    @pytest.mark.parametrize("factory", [_telegram, _slack], ids=["telegram", "slack"])
    def test_response_is_streamed_with_the_configured_timeout(
        self, factory: Callable[[FakeSession | None], Any]
    ) -> None:
        session = FakeSession()

        factory(session).send(MESSAGE)

        assert session.calls[0]["stream"] is True
        assert session.calls[0]["timeout"] == 5.0

    def test_new_session_ignores_environment_settings(self) -> None:
        session = new_session()
        try:
            assert session.trust_env is False
        finally:
            session.close()

    @pytest.mark.parametrize("factory", [_telegram, _slack], ids=["telegram", "slack"])
    def test_self_created_session_has_trust_env_disabled(
        self,
        factory: Callable[[FakeSession | None], Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seen: list[bool] = []

        def fake_post(self: requests.Session, url: str, **kwargs: Any) -> FakeResponse:
            seen.append(self.trust_env)
            return FakeResponse()

        monkeypatch.setattr(requests.Session, "post", fake_post)
        notifier = factory(None)

        notifier.send(MESSAGE)
        notifier.close()

        assert seen == [False]

    @pytest.mark.parametrize("factory", [_telegram, _slack], ids=["telegram", "slack"])
    def test_close_leaves_a_caller_supplied_session_open(
        self, factory: Callable[[FakeSession | None], Any]
    ) -> None:
        session = FakeSession()

        factory(session).close()

        assert session.closed is False

    @pytest.mark.parametrize("factory", [_telegram, _slack], ids=["telegram", "slack"])
    def test_oversize_response_body_is_not_read_fully(
        self, factory: Callable[[FakeSession | None], Any]
    ) -> None:
        response = FakeResponse(200, chunks=100_000)
        session = FakeSession(response)

        factory(session).send(MESSAGE)

        assert response.requested_chunk_sizes == {1}  # tiny reads: the deadline is re-checked
        assert response.bytes_served <= MAX_RESPONSE_BYTES
        assert response.chunks_served < 100_000
        assert response.closed

    @pytest.mark.parametrize("factory", [_telegram, _slack], ids=["telegram", "slack"])
    def test_unreadable_body_after_success_is_not_a_failure(
        self, factory: Callable[[FakeSession | None], Any]
    ) -> None:
        response = FakeResponse(200, body_error=requests.ConnectionError("reset"))

        factory(FakeSession(response)).send(MESSAGE)

        assert response.closed

    @pytest.mark.parametrize("factory", [_telegram, _slack], ids=["telegram", "slack"])
    def test_response_is_closed_after_an_http_error(
        self, factory: Callable[[FakeSession | None], Any]
    ) -> None:
        response = FakeResponse(500)

        with pytest.raises(NotifyError):
            factory(FakeSession(response)).send(MESSAGE)

        assert response.closed
        assert response.chunks_served == 0


# -- E-mail -------------------------------------------------------------------


class TestEmail:
    def test_starttls_uses_a_verifying_default_context(self, smtp: SmtpWorld) -> None:
        _email(username="sentinel", password=PASSWORD).send(MESSAGE)

        assert smtp.kinds == ["SMTP", "starttls", "login", "send", "quit"]
        context = smtp.events[1][1]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED

    def test_connection_uses_host_port_and_timeout(self, smtp: SmtpWorld) -> None:
        _email().send(MESSAGE)

        assert smtp.events[0][:4] == ("SMTP", "smtp.example.test", 587, 5.0)

    def test_port_465_uses_smtp_ssl_with_a_verifying_context(self, smtp: SmtpWorld) -> None:
        _email(port=465, username="sentinel", password=PASSWORD).send(MESSAGE)

        assert smtp.kinds == ["SMTP_SSL", "login", "send", "quit"]
        context = smtp.events[0][4]
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is True

    def test_port_465_does_not_also_start_tls(self, smtp: SmtpWorld) -> None:
        _email(port=465, starttls=True).send(MESSAGE)

        assert "starttls" not in smtp.kinds

    def test_password_without_tls_is_refused(self, smtp: SmtpWorld) -> None:
        with pytest.raises(NotifyError) as excinfo:
            _email(port=25, starttls=False, username="sentinel", password=PASSWORD)

        assert "TLS" in str(excinfo.value)
        assert PASSWORD not in str(excinfo.value)
        assert smtp.events == []

    def test_no_password_and_no_tls_is_allowed_without_login(self, smtp: SmtpWorld) -> None:
        _email(port=25, starttls=False).send(MESSAGE)

        assert smtp.kinds == ["SMTP", "send", "quit"]

    def test_login_only_happens_when_a_username_is_set(self, smtp: SmtpWorld) -> None:
        _email(username="").send(MESSAGE)
        _email(username="sentinel", password=PASSWORD).send(MESSAGE)

        logins = [event for event in smtp.events if event[0] == "login"]
        assert logins == [("login", "sentinel", PASSWORD)]

    def test_message_headers_and_body(self, smtp: SmtpWorld) -> None:
        _email(recipients=["a@example.test", "b@example.test"]).send(MESSAGE)

        msg = smtp.messages[0]
        assert msg["Subject"] == "Daily summary"
        assert msg["From"] == "sentinel@example.test"
        assert msg["To"] == "a@example.test, b@example.test"
        assert msg["Date"]
        assert "Line one\nLine two" in msg.get_content()
        assert smtp.events[-2] == (
            "send",
            "sentinel@example.test",
            ["a@example.test", "b@example.test"],
        )

    def test_long_subject_is_capped(self, smtp: SmtpWorld) -> None:
        _email().send(DigestMessage(subject="s" * 500, body="b"))

        assert len(smtp.messages[0]["Subject"]) <= 200

    @pytest.mark.parametrize(
        "subject",
        ["Hello\nBcc: evil@example.test", "Hello\r\nBcc: evil@example.test", "Hello\rX: y"],
    )
    def test_line_breaks_in_subject_are_rejected_before_connecting(
        self, smtp: SmtpWorld, subject: str
    ) -> None:
        with pytest.raises(NotifyError, match="line breaks"):
            _email().send(DigestMessage(subject=subject, body="b"))

        assert smtp.events == []
        assert smtp.messages == []

    @pytest.mark.parametrize(
        "sender",
        ["a@example.test\r\nBcc: evil@example.test", "a@example.test\n", "no-at-sign", "  ", ""],
    )
    def test_bad_sender_is_rejected(self, sender: str) -> None:
        with pytest.raises(NotifyError):
            _email(sender=sender)

    @pytest.mark.parametrize(
        "recipient",
        ["a@example.test\r\nBcc: evil@example.test", "a@example.test\nb", "no-at-sign", ""],
    )
    def test_bad_recipient_is_rejected(self, recipient: str) -> None:
        with pytest.raises(NotifyError):
            _email(recipients=["ok@example.test", recipient])

    def test_empty_recipient_list_is_rejected(self) -> None:
        with pytest.raises(NotifyError, match="recipients"):
            _email(recipients=[])

    @pytest.mark.parametrize("port", [0, 65_536])
    def test_port_out_of_range_is_rejected(self, port: int) -> None:
        with pytest.raises(NotifyError, match="port"):
            _email(port=port)

    def test_empty_host_is_rejected(self) -> None:
        with pytest.raises(NotifyError, match="host"):
            _email(host="  ")

    @pytest.mark.parametrize("stage", ["connect", "starttls", "login", "send"])
    def test_smtp_failure_reports_only_the_exception_class(
        self, smtp: SmtpWorld, stage: str
    ) -> None:
        smtp.fail_on[stage] = smtplib.SMTPAuthenticationError(535, b"bad pw " + PASSWORD.encode())

        with pytest.raises(NotifyError) as excinfo:
            _email(username="sentinel", password=PASSWORD).send(MESSAGE)

        assert str(excinfo.value) == "email delivery failed (SMTPAuthenticationError)"
        assert PASSWORD not in str(excinfo.value)
        assert excinfo.value.__cause__ is None

    def test_os_error_is_wrapped_without_its_details(self, smtp: SmtpWorld) -> None:
        smtp.fail_on["connect"] = ConnectionRefusedError("internal-host.corp:25 refused")

        with pytest.raises(NotifyError) as excinfo:
            _email().send(MESSAGE)

        assert str(excinfo.value) == "email delivery failed (ConnectionRefusedError)"

    def test_repr_hides_password_and_username(self) -> None:
        notifier = _email(username="sentinel", password=PASSWORD)

        text = repr(notifier)

        assert PASSWORD not in text
        assert "sentinel'" not in text
        assert "smtp.example.test" in text


# -- digest builder ------------------------------------------------------------


def _save_alert(
    store: AlertStore,
    *,
    title: str = "Test alert",
    score: float = 50,
    age_hours: float = 1.0,
    ip: str | None = "203.0.113.9",
    user: str | None = None,
    rule_id: str = "R001",
) -> Alert:
    """Save a real, rule-built alert with a controlled score, level and age."""
    rule = available_rules()[rule_id]()
    alert = rule.make_alert(make_event(ip=ip, user=user), title, "synthetic alert")
    RiskEngine().score(alert)
    alert.risk = RiskAssessment(score=score, level=RiskLevel.from_score(score))
    alert.created_at = NOW - timedelta(hours=age_hours)
    store.save(alert)
    return alert


def _digest(store: AlertStore, **kwargs: Any) -> DigestMessage:
    kwargs.setdefault("now", NOW)
    return build_digest(store, **kwargs)


def _alert_lines(body: str) -> list[str]:
    return [line for line in body.splitlines() if line.startswith("  [")]


class TestDigestBasics:
    def test_empty_store_gives_a_quiet_message(self, store: AlertStore) -> None:
        message = _digest(store)

        assert message.subject == "SentinelAI daily summary: no alerts"
        assert "Quiet period, nothing to review." in message.body
        assert "Total alerts" not in message.body
        assert "What to do next" not in message.body

    def test_empty_store_with_pending_request_shows_it(self, store: AlertStore) -> None:
        store.add_pending(
            ip="203.0.113.50",
            alert_id=None,
            rule_id="R001",
            risk_level="high",
            risk_score=70,
            action="block_ip",
            duration_seconds=None,
            ts=NOW,
        )

        body = _digest(store).body

        assert "Quiet period" in body
        assert "Requests waiting for your approval: 1" in body
        assert "sentinel respond --pending" in body

    def test_counts_per_risk_level(self, store: AlertStore) -> None:
        for score in (90, 70, 66, 50, 25, 5):
            _save_alert(store, score=score, title=f"alert {score}")

        message = _digest(store)

        assert "Total alerts: 6 (1 critical, 2 high, 1 medium, 1 low, 1 informational)" in (
            message.body
        )
        assert message.subject == "SentinelAI daily summary: 6 alerts, 3 need attention"

    def test_subject_is_singular_for_one_alert_needing_attention(
        self, store: AlertStore
    ) -> None:
        _save_alert(store, score=90)

        assert _digest(store).subject == "SentinelAI daily summary: 1 alert, 1 needs attention"

    def test_subject_is_calm_without_critical_or_high_alerts(self, store: AlertStore) -> None:
        _save_alert(store, score=50)
        _save_alert(store, score=25, ip="203.0.113.10")

        assert _digest(store).subject == "SentinelAI daily summary: 2 alerts, nothing urgent"

    def test_top_alerts_are_ordered_by_score_then_recency(self, store: AlertStore) -> None:
        _save_alert(store, title="Title-A-older-high", score=70, age_hours=3, ip="203.0.113.1")
        _save_alert(store, title="Title-B-newer-high", score=70, age_hours=1, ip="203.0.113.2")
        _save_alert(store, title="Title-C-critical", score=90, age_hours=5, ip="203.0.113.3")
        _save_alert(store, title="Title-D-low", score=25, age_hours=0.5, ip="203.0.113.4")

        lines = _alert_lines(_digest(store).body)

        order = [next(t for t in ("Title-A", "Title-B", "Title-C", "Title-D") if t in ln)
                 for ln in lines]
        assert order == ["Title-C", "Title-B", "Title-A", "Title-D"]

    def test_max_alerts_limits_the_listed_alerts(self, store: AlertStore) -> None:
        for index in range(6):
            _save_alert(store, title=f"alert-{index}", score=50 + index, ip=f"203.0.113.{index}")

        body = _digest(store, max_alerts=2).body

        assert len(_alert_lines(body)) == 2
        assert "showing 2 of 6" in body

    def test_max_alerts_zero_lists_no_alerts(self, store: AlertStore) -> None:
        _save_alert(store, score=90)

        body = _digest(store, max_alerts=0).body

        assert _alert_lines(body) == []
        assert "Most important alerts" not in body
        assert "Total alerts: 1" in body

    def test_alert_line_shows_level_score_id_source_user_and_time(
        self, store: AlertStore
    ) -> None:
        alert = _save_alert(store, title="Brute force", score=90, user="bob", age_hours=1)

        line = _alert_lines(_digest(store).body)[0]

        assert line == (
            f"  [CRITICAL 90] #{alert.id} Brute force from 203.0.113.9 (user bob) at 11:00"
        )

    def test_longer_period_shows_dates_and_changes_the_heading(self, store: AlertStore) -> None:
        _save_alert(store, score=90, age_hours=30)

        message = _digest(store, hours=48)

        assert message.subject.startswith("SentinelAI summary (last 48 h):")
        assert _alert_lines(message.body)[0].endswith("at 03-09 06:00")

    def test_alerts_older_than_the_period_are_excluded(self, store: AlertStore) -> None:
        _save_alert(store, title="Title-old", score=90, age_hours=30, ip="203.0.113.1")
        _save_alert(store, title="Title-new", score=50, age_hours=2, ip="203.0.113.2")

        daily = _digest(store)
        longer = _digest(store, hours=48)

        assert "Title-old" not in daily.body
        assert "Title-new" in daily.body
        assert "Total alerts: 1 (" in daily.body
        assert "Title-old" in longer.body
        assert "Total alerts: 2 (" in longer.body

    def test_only_old_alerts_give_a_quiet_message(self, store: AlertStore) -> None:
        _save_alert(store, score=90, age_hours=100)

        assert _digest(store).subject.endswith("no alerts")

    def test_period_line_names_the_end_time_in_utc(self, store: AlertStore) -> None:
        assert "until 2026-03-10 12:00 UTC" in _digest(store).body

    def test_same_input_and_now_gives_identical_output(self, store: AlertStore) -> None:
        for index in range(5):
            _save_alert(
                store, title=f"alert-{index}", score=40 + index * 10, ip=f"203.0.113.{index}"
            )

        assert _digest(store) == _digest(store)

    def test_naive_now_is_treated_as_utc(self, store: AlertStore) -> None:
        _save_alert(store, score=90)

        aware = _digest(store, now=NOW)
        naive = _digest(store, now=NOW.replace(tzinfo=None))

        assert aware == naive


class TestDigestSanitising:
    EVIL_TITLE = (
        "Evil\x1b[2J\nINJECTED LINE\r\n<script>alert(1)</script> "
        "https://evil.example/x <!channel>"
    )

    def _hostile_store_digest(self, store: AlertStore) -> DigestMessage:
        _save_alert(store, title=self.EVIL_TITLE, score=90, user="u" * 5000 + "\n@everyone")
        return _digest(store)

    def test_control_characters_and_markup_are_removed(self, store: AlertStore) -> None:
        message = self._hostile_store_digest(store)

        for text in (message.body, message.subject):
            assert "\x1b" not in text
            assert "\r" not in text
            assert "<" not in text
            assert ">" not in text
            assert "://" not in text

    def test_attacker_text_cannot_add_lines(self, store: AlertStore) -> None:
        message = self._hostile_store_digest(store)

        assert not any(line.startswith("INJECTED") for line in message.body.splitlines())
        assert len(_alert_lines(message.body)) == 1
        assert "\n" not in message.subject

    def test_hostile_alert_renders_to_the_same_line_count_as_a_benign_one(
        self, store: AlertStore, tmp_path: Path
    ) -> None:
        hostile = self._hostile_store_digest(store)
        other = AlertStore(tmp_path / "benign.db")
        try:
            _save_alert(other, title="Plain title", score=90, user="bob")
            benign = _digest(other)
        finally:
            other.close()

        assert len(hostile.body.splitlines()) == len(benign.body.splitlines())

    def test_long_user_name_is_capped(self, store: AlertStore) -> None:
        message = self._hostile_store_digest(store)

        assert "u" * 33 not in message.body
        assert max(len(line) for line in message.body.splitlines()) < 300

    def test_link_is_defanged(self, store: AlertStore) -> None:
        message = self._hostile_store_digest(store)

        assert "https://evil.example/x" not in message.body
        assert "evil.example" in message.body

    def test_title_is_length_capped(self, store: AlertStore) -> None:
        _save_alert(store, title="T" * 1000, score=90)

        line = _alert_lines(_digest(store).body)[0]

        assert "T" * 81 not in line

    def test_hostile_source_address_is_sanitised(self, store: AlertStore) -> None:
        _save_alert(store, title="Odd ip", score=90, ip="203.0.113.9\x1b[31m<b>")

        body = _digest(store).body

        assert "\x1b" not in body
        assert "<" not in body

    def test_digest_is_safe_for_slack_after_escaping(self, store: AlertStore) -> None:
        message = self._hostile_store_digest(store)
        session = FakeSession()

        _slack(session).send(message)

        text = session.calls[0]["json"]["text"]
        assert "<!channel>" not in text
        assert "&lt;" not in text  # nothing to escape: the digest already dropped < and >


class TestDigestSize:
    def test_body_stays_within_the_cap_with_many_long_alerts(self, store: AlertStore) -> None:
        for index in range(40):
            _save_alert(
                store,
                title=f"Alert {index} " + "long title " * 20,
                score=50 + (index % 40),
                ip=f"203.0.113.{index}",
                user=f"user{index}" * 4,
            )

        message = _digest(store, max_alerts=50)

        assert len(message.body) <= MAX_BODY_CHARS == 3500
        assert "What to do next:" in message.body
        assert "Total alerts: 40" in message.body

    def test_heading_matches_the_number_of_alerts_actually_shown(
        self, store: AlertStore
    ) -> None:
        for index in range(40):
            _save_alert(
                store,
                title=f"Alert {index} " + "long title " * 20,
                score=50 + (index % 40),
                ip=f"203.0.113.{index}",
            )

        body = _digest(store, max_alerts=50).body

        shown = len(_alert_lines(body))
        assert 0 < shown < 40
        assert f"showing {shown} of 40" in body

    def test_highest_scores_survive_the_trimming(self, store: AlertStore) -> None:
        for index in range(40):
            _save_alert(
                store,
                title=f"Alert {index} " + "long title " * 20,
                score=40 + index,
                ip=f"203.0.113.{index}",
            )

        body = _digest(store, max_alerts=50).body

        assert "Alert 39 " in body
        assert "Alert 0 " not in body


class TestDigestLanguages:
    def _filled(self, store: AlertStore) -> None:
        _save_alert(store, score=90)

    def test_languages_produce_different_text(self, store: AlertStore) -> None:
        self._filled(store)

        messages = {lang: _digest(store, language=lang) for lang in ("en", "tr", "de")}

        assert len({m.subject for m in messages.values()}) == 3
        assert len({m.body for m in messages.values()}) == 3

    def test_turkish_and_german_use_their_own_words(self, store: AlertStore) -> None:
        self._filled(store)

        assert "günlük özet" in _digest(store, language="tr").subject
        assert "Tageszusammenfassung" in _digest(store, language="de").subject

    def test_unknown_language_falls_back_to_english(self, store: AlertStore) -> None:
        self._filled(store)

        assert _digest(store, language="fr") == _digest(store, language="en")

    def test_language_is_case_and_space_insensitive(self, store: AlertStore) -> None:
        self._filled(store)

        assert _digest(store, language=" DE ") == _digest(store, language="de")

    def test_quiet_message_is_translated_too(self, store: AlertStore) -> None:
        assert "Sakin bir dönem" in _digest(store, language="tr").body
        assert "Ruhiger Zeitraum" in _digest(store, language="de").body


class TestDigestResponseActivity:
    def _action(self, store: AlertStore, status: str, ip: str, age_hours: float = 1.0) -> None:
        store.add_response_action(
            action="temporary_block",
            ip=ip,
            duration_seconds=3600,
            expires_at=None,
            status=status,
            alert_id=None,
            rule_id="R001",
            run_id="run1",
            ts=NOW - timedelta(hours=age_hours),
        )

    def _pending(self, store: AlertStore, ip: str) -> None:
        store.add_pending(
            ip=ip,
            alert_id=None,
            rule_id="R001",
            risk_level="high",
            risk_score=70,
            action="block_ip",
            duration_seconds=None,
            ts=NOW,
        )

    def test_no_activity_says_so(self, store: AlertStore) -> None:
        _save_alert(store, score=50)

        assert "No firewall responses in this period." in _digest(store).body

    def test_blocks_expired_rolled_back_and_pending_are_counted(
        self, store: AlertStore
    ) -> None:
        _save_alert(store, score=50)
        self._action(store, "applied", "203.0.113.1")
        self._action(store, "applied", "203.0.113.2")
        self._action(store, "reaped", "203.0.113.3")
        self._action(store, "rolled_back", "203.0.113.4")
        self._action(store, "failed", "203.0.113.5")
        self._pending(store, "203.0.113.6")
        self._pending(store, "203.0.113.7")

        body = _digest(store).body

        assert "Blocks applied: 4" in body
        assert "Blocks expired and removed: 1" in body
        assert "Blocks rolled back: 1" in body
        assert "Requests waiting for your approval: 2" in body

    def test_actions_older_than_the_period_are_not_counted(self, store: AlertStore) -> None:
        _save_alert(store, score=50)
        self._action(store, "applied", "203.0.113.1", age_hours=30)

        assert "No firewall responses in this period." in _digest(store).body

    def test_pending_alone_replaces_the_no_responses_line(self, store: AlertStore) -> None:
        _save_alert(store, score=50)
        self._pending(store, "203.0.113.6")

        body = _digest(store).body

        assert "No firewall responses" not in body
        assert "Blocks applied: 0" in body
        assert "Requests waiting for your approval: 1" in body


class TestDigestNextSteps:
    def _steps(self, message: DigestMessage) -> list[str]:
        lines = message.body.splitlines()
        start = lines.index("What to do next:")
        return [line.strip() for line in lines[start + 1 :] if line.strip()]

    def _pending(self, store: AlertStore) -> None:
        store.add_pending(
            ip="203.0.113.60",
            alert_id=None,
            rule_id="R001",
            risk_level="high",
            risk_score=70,
            action="block_ip",
            duration_seconds=None,
            ts=NOW,
        )

    def test_critical_pending_and_missing_feedback_give_three_ordered_steps(
        self, store: AlertStore
    ) -> None:
        alert = _save_alert(store, score=90)
        self._pending(store)

        steps = self._steps(_digest(store))

        assert steps == [
            f"1. Look at the most serious alert: `sentinel explain {alert.id}`",
            "2. Decide on the waiting requests: `sentinel respond --pending`",
            "3. Tell SentinelAI which alerts were real or false: `sentinel review`",
        ]

    def test_critical_alert_is_preferred_over_a_high_one(self, store: AlertStore) -> None:
        _save_alert(store, score=70, ip="203.0.113.1")
        critical = _save_alert(store, score=90, ip="203.0.113.2")

        steps = self._steps(_digest(store))

        assert steps[0] == f"1. Look at the most serious alert: `sentinel explain {critical.id}`"

    def test_high_alert_is_suggested_when_nothing_is_critical(self, store: AlertStore) -> None:
        high = _save_alert(store, score=70)

        steps = self._steps(_digest(store))

        assert steps[0] == f"1. Look at the most serious alert: `sentinel explain {high.id}`"

    def test_review_step_disappears_once_feedback_exists(self, store: AlertStore) -> None:
        alert = _save_alert(store, score=90)
        store.add_feedback(int(alert.id or 0), "tp", ts=NOW)

        steps = self._steps(_digest(store))

        assert len(steps) == 1
        assert "sentinel review" not in " ".join(steps)

    def test_low_alerts_with_feedback_need_no_action(self, store: AlertStore) -> None:
        alert = _save_alert(store, score=25)
        store.add_feedback(int(alert.id or 0), "fp", ts=NOW)

        steps = self._steps(_digest(store))

        assert steps == ["Nothing urgent. No action needed."]

    def test_steps_are_deterministic(self, store: AlertStore) -> None:
        _save_alert(store, score=90, ip="203.0.113.1")
        _save_alert(store, score=90, ip="203.0.113.2")
        self._pending(store)

        assert self._steps(_digest(store)) == self._steps(_digest(store))

    def test_at_most_three_steps(self, store: AlertStore) -> None:
        _save_alert(store, score=90)
        self._pending(store)

        assert len(self._steps(_digest(store))) <= 3


# -- digest CLI ---------------------------------------------------------------


class FakeNotifier:
    def __init__(self, name: str, error: Exception | None = None) -> None:
        self.name = name
        self.error = error
        self.sent: list[DigestMessage] = []

    def send(self, message: DigestMessage) -> None:
        if self.error is not None:
            raise self.error
        self.sent.append(message)


class BuildRecorder:
    """Stands in for ``build_notifiers``; hands out the matching fake notifiers."""

    def __init__(self, notifiers: list[FakeNotifier]) -> None:
        self.notifiers = notifiers
        self.configs: list[NotifyConfig] = []

    def __call__(self, config: NotifyConfig, **_: Any) -> list[FakeNotifier]:
        self.configs.append(config)
        wanted = list(config.channels)
        return [n for name in wanted for n in self.notifiers if n.name == name]


def _cli_config(tmp_path: Path, **notify: Any) -> Path:
    settings: dict[str, Any] = {
        "channels": ["telegram", "slack", "email"],
        "telegram_chat_id": CHAT_ID,
        "email_host": "smtp.example.test",
        "email_from": "sentinel@example.test",
        "email_to": ["ops@example.test"],
    }
    settings.update(notify)
    path = _write_config(tmp_path, settings)
    seed = AlertStore(tmp_path / "state" / "alerts.db")
    try:
        rule = available_rules()["R001"]()
        item = rule.make_alert(make_event(ip="203.0.113.9"), "Brute force", "synthetic alert")
        RiskEngine().score(item)
        item.risk = RiskAssessment(score=90, level=RiskLevel.CRITICAL)
        item.created_at = datetime.now(timezone.utc) - timedelta(hours=1)
        seed.save(item)
    finally:
        seed.close()
    return path


def _run(cfg: Path, *args: str) -> Result:
    return CliRunner().invoke(cli, ["--config", str(cfg), "--no-plugins", "digest", *args])


@pytest.fixture()
def fake_build(monkeypatch: pytest.MonkeyPatch) -> BuildRecorder:
    names = ("telegram", "slack", "email")
    recorder = BuildRecorder([FakeNotifier(name) for name in names])
    monkeypatch.setattr("sentinelai.cli.commands.digest.build_notifiers", recorder)
    return recorder


class TestDigestCli:
    def test_default_prints_the_digest_and_sends_nothing(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        result = _run(_cli_config(tmp_path))

        assert result.exit_code == 0, result.output
        assert "Subject: SentinelAI daily summary" in result.output
        assert "Brute force" in result.output
        assert "Nothing was sent" in result.output
        assert fake_build.configs == []
        assert all(n.sent == [] for n in fake_build.notifiers)

    def test_default_on_empty_store_prints_the_quiet_message(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        cfg = _write_config(tmp_path, {"channels": []})

        result = _run(cfg)

        assert result.exit_code == 0, result.output
        assert "no alerts" in result.output
        assert "Nothing was sent" in result.output

    def test_send_delivers_once_per_configured_channel(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        result = _run(_cli_config(tmp_path), "--send")

        assert result.exit_code == 0, result.output
        for notifier in fake_build.notifiers:
            assert len(notifier.sent) == 1
        assert "telegram: sent" in result.output
        assert "slack: sent" in result.output
        assert "email: sent" in result.output
        assert "Nothing was sent" not in result.output

    def test_send_delivers_the_same_message_that_would_be_printed(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        _run(_cli_config(tmp_path), "--send")

        message = fake_build.notifiers[0].sent[0]
        assert message.subject.startswith("SentinelAI daily summary:")
        assert "Brute force" in message.body

    def test_channel_option_restricts_delivery(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        result = _run(_cli_config(tmp_path), "--send", "--channel", "slack")

        assert result.exit_code == 0, result.output
        sent = {n.name: len(n.sent) for n in fake_build.notifiers}
        assert sent == {"telegram": 0, "slack": 1, "email": 0}
        assert fake_build.configs[0].channels == ["slack"]

    def test_channel_option_may_repeat(self, tmp_path: Path, fake_build: BuildRecorder) -> None:
        result = _run(
            _cli_config(tmp_path), "--send", "--channel", "email", "--channel", "telegram"
        )

        assert result.exit_code == 0, result.output
        sent = {n.name: len(n.sent) for n in fake_build.notifiers}
        assert sent == {"telegram": 1, "slack": 0, "email": 1}

    def test_channel_outside_the_configured_ones_is_a_usage_error(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        cfg = _cli_config(tmp_path, channels=["slack"])

        result = _run(cfg, "--send", "--channel", "email")

        assert result.exit_code == 2
        assert "not in notify.channels" in result.output
        assert fake_build.configs == []
        assert all(n.sent == [] for n in fake_build.notifiers)

    def test_unknown_channel_name_is_a_usage_error(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        result = _run(_cli_config(tmp_path), "--send", "--channel", "sms")

        assert result.exit_code == 2

    def test_channel_without_send_is_a_usage_error(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        result = _run(_cli_config(tmp_path), "--channel", "slack")

        assert result.exit_code == 2
        assert "--send" in result.output
        assert fake_build.configs == []

    @pytest.mark.parametrize("hours", ["0", "721", "abc"])
    def test_hours_out_of_range_is_a_usage_error(
        self, tmp_path: Path, fake_build: BuildRecorder, hours: str
    ) -> None:
        assert _run(_cli_config(tmp_path), "--hours", hours).exit_code == 2

    def test_failing_channel_gives_exit_1_but_others_are_still_sent(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        fake_build.notifiers[0].error = NotifyError("telegram returned HTTP 500")

        result = _run(_cli_config(tmp_path), "--send")

        assert result.exit_code == 1
        assert "telegram: FAILED - telegram returned HTTP 500" in result.output
        assert "slack: sent" in result.output
        assert "email: sent" in result.output
        assert len(fake_build.notifiers[1].sent) == 1
        assert len(fake_build.notifiers[2].sent) == 1

    def test_failing_last_channel_still_gives_exit_1(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        fake_build.notifiers[2].error = NotifyError("email delivery failed (OSError)")

        result = _run(_cli_config(tmp_path), "--send")

        assert result.exit_code == 1
        assert "telegram: sent" in result.output

    def test_failure_text_is_sanitised_before_printing(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        fake_build.notifiers[0].error = NotifyError("boom\x1b[2J\nINJECTED")

        result = _run(_cli_config(tmp_path), "--send")

        assert "\x1b" not in result.output
        assert not any(line.startswith("INJECTED") for line in result.output.splitlines())

    def test_missing_secrets_give_a_clean_error_with_names_only(
        self, tmp_path: Path
    ) -> None:
        cfg = _cli_config(tmp_path, channels=["telegram", "slack"])

        result = _run(cfg, "--send")

        assert result.exit_code == NotifyError.exit_code
        assert "telegram" in result.output
        assert "slack" in result.output
        assert CHAT_ID not in result.output
        assert "Traceback" not in result.output

    def test_missing_secrets_send_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINELAI_NOTIFY_SLACK_WEBHOOK", WEBHOOK)
        session = FakeSession()
        monkeypatch.setattr("sentinelai.notify.slack.new_session", lambda: session)
        cfg = _cli_config(tmp_path, channels=["slack", "telegram"])

        result = _run(cfg, "--send")

        assert result.exit_code == NotifyError.exit_code
        assert session.calls == []
        assert WEBHOOK not in result.output

    def test_send_with_no_channels_configured_is_an_error(self, tmp_path: Path) -> None:
        cfg = _cli_config(tmp_path, channels=[])

        result = _run(cfg, "--send")

        assert result.exit_code == NotifyError.exit_code
        assert "no notify channels" in result.output

    def test_language_comes_from_config_and_can_be_overridden(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        cfg = _cli_config(tmp_path, language="tr")

        _run(cfg, "--send", "--channel", "slack")
        _run(cfg, "--send", "--channel", "slack", "--language", "de")

        slack = fake_build.notifiers[1]
        assert "günlük özet" in slack.sent[0].subject
        assert "Tageszusammenfassung" in slack.sent[1].subject

    def test_max_alerts_from_config_is_applied(
        self, tmp_path: Path, fake_build: BuildRecorder
    ) -> None:
        result = _run(_cli_config(tmp_path, max_alerts=1))

        assert result.exit_code == 0, result.output
        assert "showing 1 of 1" in result.output
