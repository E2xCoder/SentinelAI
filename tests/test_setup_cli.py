"""Tests for ``sentinel init`` / ``sentinel doctor`` and their helpers.

Detection runs against a fake filesystem root, doctor checks get injected
``http_get`` / ``env`` / ``which`` / ``platform``, and the CLI is driven through
``CliRunner``. All data is synthetic; the fake secret below must never appear in
any diagnostic output.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml
from click.testing import CliRunner, Result

from sentinelai.cli.app import cli
from sentinelai.cli.commands import setup as setup_command
from sentinelai.config.loader import load_config
from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import ConfigError
from sentinelai.notify.base import NotifyError
from sentinelai.notify.slack import SlackNotifier
from sentinelai.notify.telegram import TelegramNotifier
from sentinelai.setup import doctor as doctor_module
from sentinelai.setup.detect import (
    DetectedSource,
    Detection,
    detect_environment,
    explain_choices,
    render_config,
)
from sentinelai.setup.doctor import (
    FAIL,
    OK,
    WARN,
    CheckResult,
    run_checks,
    summarize,
)

FAKE_SECRET = "s3cr3t-FAKE-value-9f8e7d6c"
POSIX = os.name == "posix"


# -- helpers ---------------------------------------------------------------


def make_file(root: Path, posix_path: str, content: str = "line\n") -> Path:
    target = root.joinpath(*posix_path.strip("/").split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def no_tools(_name: str) -> str | None:
    return None


def detect(root: Path, which: Callable[[str], str | None] = no_tools) -> Detection:
    return detect_environment(root=root, which=which, platform="linux")


def by_kind(detection: Detection) -> dict[str, DetectedSource]:
    return {s.kind: s for s in detection.sources}


class FakeResponse:
    def __init__(self, status_code: int = 200, body: Any = None) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return self._body

    def close(self) -> None:
        return None


def http_returning(body: Any, status: int = 200) -> Callable[..., FakeResponse]:
    def _get(url: str, **_kwargs: Any) -> FakeResponse:
        return FakeResponse(status, body)

    return _get


def http_failing(url: str, **_kwargs: Any) -> FakeResponse:
    raise ConnectionError("connection refused")


def make_config(tmp_path: Path) -> SentinelConfig:
    """A config whose state dir and live paths live inside ``tmp_path``."""
    config = SentinelConfig()
    config.state_dir = str(tmp_path / "state")
    existing = tmp_path / "auth.log"
    existing.write_text("x\n", encoding="utf-8")
    config.live.paths = [str(existing)]
    return config


def check(results: list[CheckResult], name: str) -> CheckResult:
    matches = [r for r in results if r.name == name]
    assert matches, f"no result named {name!r}: {[r.name for r in results]}"
    return matches[0]


def checks_with_prefix(results: list[CheckResult], prefix: str) -> list[CheckResult]:
    return [r for r in results if r.name.startswith(prefix)]


def run_doctor(
    config: SentinelConfig,
    *,
    http_get: Callable[..., Any] = http_failing,
    env: dict[str, str] | None = None,
    which: Callable[[str], str | None] = no_tools,
    platform: str = "linux",
) -> list[CheckResult]:
    return run_checks(
        config,
        http_get=http_get,
        env={} if env is None else env,
        platform=platform,
        which=which,
    )


def cli_run(cfg: Path, *args: str) -> Result:
    return CliRunner().invoke(cli, ["--config", str(cfg), "--no-plugins", *args])


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    """A valid config file whose state dir is inside tmp_path."""
    state = tmp_path / "state"
    state.mkdir()
    path = tmp_path / "base.yaml"
    path.write_text(
        f'state_dir: "{state.as_posix()}"\n'
        "live:\n"
        f'  paths: ["{(tmp_path / "missing.log").as_posix()}"]\n',
        encoding="utf-8",
    )
    return path


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove host SENTINELAI_* overrides so the CLI runs are deterministic."""
    for name in list(os.environ):
        if name.startswith("SENTINELAI_"):
            monkeypatch.delenv(name)
    yield


# -- detect_environment ----------------------------------------------------


class TestDetectEnvironment:
    def test_auth_log_and_secure_only_auth_log_is_kept(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        make_file(root, "/var/log/auth.log")
        make_file(root, "/var/log/secure")

        found = detect(root)

        auth = [s for s in found.sources if s.kind == "auth"]
        assert [s.path for s in auth] == ["/var/log/auth.log"]

    def test_only_secure_present_is_used_for_auth(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        make_file(root, "/var/log/secure")

        assert [s.path for s in detect(root).sources] == ["/var/log/secure"]

    def test_web_and_security_logs_are_detected_with_kinds(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        make_file(root, "/var/log/nginx/access.log", "abc")
        make_file(root, "/var/log/nginx/error.log")
        make_file(root, "/var/log/apache2/access.log")
        make_file(root, "/var/log/httpd/error_log")
        make_file(root, "/var/log/fail2ban.log")
        make_file(root, "/var/log/ufw.log")

        found = detect(root)

        kinds = by_kind(found)
        assert set(kinds) == {
            "nginx_access",
            "nginx_error",
            "apache_access",
            "apache_error",
            "fail2ban",
            "ufw",
        }
        assert kinds["nginx_access"].path == "/var/log/nginx/access.log"
        assert kinds["nginx_access"].size_bytes == 3
        assert kinds["apache_error"].path == "/var/log/httpd/error_log"
        assert found.nginx_present and found.apache_present and found.fail2ban_present

    def test_empty_root_finds_nothing(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        root.mkdir()

        found = detect(root)

        assert found.sources == []
        assert not found.docker_present
        assert not found.nginx_present

    def test_directories_named_like_logs_are_ignored(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        (root / "var" / "log" / "auth.log").mkdir(parents=True)

        assert detect(root).sources == []

    @pytest.mark.skipif(
        not POSIX or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="needs POSIX permissions and a non-root user",
    )
    def test_unreadable_file_is_flagged_not_readable(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        target = make_file(root, "/var/log/auth.log")
        target.chmod(0o000)
        try:
            found = detect(root)
        finally:
            target.chmod(0o600)

        source = by_kind(found)["auth"]
        assert source.readable is False
        assert "adm" in source.note

    def test_readable_file_has_no_note(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        make_file(root, "/var/log/syslog")

        source = by_kind(detect(root))["syslog"]

        assert source.readable is True
        assert source.note == ""

    def test_docker_socket_sets_docker_present_and_journald_note(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        make_file(root, "/var/run/docker.sock", "")

        found = detect(root)

        assert found.docker_present
        assert any("journalctl" in note for note in found.notes)

    def test_which_docker_sets_docker_present_and_journald_note(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        root.mkdir()

        found = detect(root, which=lambda n: "/usr/bin/docker" if n == "docker" else None)

        assert found.docker_present
        assert any("journald" in note for note in found.notes)

    def test_which_tools_set_presence_flags(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        root.mkdir()
        present = {"ufw", "nginx", "httpd", "fail2ban-client"}

        found = detect(root, which=lambda n: f"/bin/{n}" if n in present else None)

        assert found.ufw_present and found.nginx_present
        assert found.apache_present and found.fail2ban_present
        assert not found.docker_present

    def test_failing_which_never_breaks_detection(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        make_file(root, "/var/log/auth.log")

        def boom(_name: str) -> str | None:
            raise RuntimeError("which exploded")

        found = detect_environment(root=root, which=boom, platform="linux")

        assert [s.kind for s in found.sources] == ["auth"]
        assert not found.docker_present

    @pytest.mark.parametrize("platform", ["win32", "darwin"])
    def test_unsupported_platform_returns_empty_sources_and_linux_note(
        self, tmp_path: Path, platform: str
    ) -> None:
        root = tmp_path / "fake_root"
        make_file(root, "/var/log/auth.log")

        found = detect_environment(root=root, which=no_tools, platform=platform)

        assert found.sources == []
        assert len(found.notes) == 1
        assert "Linux" in found.notes[0]

    def test_nonexistent_root_does_not_raise(self, tmp_path: Path) -> None:
        found = detect(tmp_path / "does" / "not" / "exist")

        assert found.sources == []

    def test_root_that_is_a_file_does_not_raise(self, tmp_path: Path) -> None:
        root_file = tmp_path / "a_file"
        root_file.write_text("x", encoding="utf-8")

        assert detect(root_file).sources == []


# -- explain_choices -------------------------------------------------------


class TestExplainChoices:
    def test_mentions_detected_sources_and_blocking_off(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        make_file(root, "/var/log/auth.log")
        make_file(root, "/var/log/nginx/access.log")

        text = "\n".join(explain_choices(detect(root)))

        assert "/var/log/auth.log" in text
        assert "/var/log/nginx/access.log" in text
        assert "Automatic blocking stays OFF" in text

    def test_no_sources_still_states_blocking_off(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        root.mkdir()

        text = "\n".join(explain_choices(detect(root)))

        assert "No known log files were found" in text
        assert "stays OFF" in text

    def test_unreadable_source_is_listed_as_skipped(self) -> None:
        detection = Detection(
            sources=[
                DetectedSource("/var/log/auth.log", "auth", "Authentication log", False, 10, "n")
            ],
            docker_present=False,
            ufw_present=False,
            fail2ban_present=False,
            nginx_present=False,
            apache_present=False,
            notes=[],
        )

        text = "\n".join(explain_choices(detection))

        assert "Skipped" in text
        assert "adm" in text
        assert "Will monitor" not in text

    def test_detected_tools_are_listed(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        root.mkdir()

        text = "\n".join(explain_choices(detect(root, which=lambda n: f"/bin/{n}")))

        assert "Docker" in text and "UFW" in text


# -- render_config ---------------------------------------------------------


def many_sources_detection(root: Path) -> Detection:
    for path in (
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/fail2ban.log",
        "/var/log/ufw.log",
    ):
        make_file(root, path)
    return detect(root)


def write_and_load(tmp_path: Path, text: str) -> SentinelConfig:
    path = tmp_path / "generated.yaml"
    path.write_text(text, encoding="utf-8", newline="\n")
    return load_config(path)


class TestRenderConfig:
    def test_no_sources_parses_and_loads(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        root.mkdir()
        text = render_config(detect(root))

        parsed = yaml.safe_load(text)
        loaded = write_and_load(tmp_path, text)

        assert isinstance(parsed, dict)
        assert loaded.live.paths  # built-in defaults still apply

    def test_many_sources_are_listed_in_live_paths(self, tmp_path: Path) -> None:
        detection = many_sources_detection(tmp_path / "fake_root")
        text = render_config(detection)

        loaded = write_and_load(tmp_path, text)

        assert yaml.safe_load(text)["live"]["paths"] == loaded.live.paths
        assert len(loaded.live.paths) == 8
        assert "/var/log/fail2ban.log" in loaded.live.paths

    def test_unreadable_sources_are_not_listed(self) -> None:
        detection = Detection(
            sources=[DetectedSource("/var/log/auth.log", "auth", "Auth", False, 1, "n")],
            docker_present=False,
            ufw_present=False,
            fail2ban_present=False,
            nginx_present=False,
            apache_present=False,
            notes=[],
        )

        parsed = yaml.safe_load(render_config(detection))

        assert "paths" not in parsed["live"]

    def test_enable_llm_true_turns_on_llm_block(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        root.mkdir()

        loaded = write_and_load(
            tmp_path, render_config(detect(root), enable_llm=True, llm_model="qwen2.5:7b")
        )

        assert loaded.ai.llm.enabled is True
        assert loaded.ai.llm.model == "qwen2.5:7b"

    def test_llm_is_off_by_default(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        root.mkdir()

        assert write_and_load(tmp_path, render_config(detect(root))).ai.llm.enabled is False

    @pytest.mark.parametrize(
        "state_dir",
        [
            'C:\\Users\\"quoted"\\state',
            "/tmp/with \"double\" and 'single' quotes",
            "/tmp/back\\slash\\dir",
            "/tmp/ünïcödé/状態/ディレクトリ",
            "/tmp/colon: hash # brace {x}",
        ],
    )
    def test_custom_state_dir_round_trips(self, tmp_path: Path, state_dir: str) -> None:
        root = tmp_path / "fake_root"
        root.mkdir()
        text = render_config(detect(root), state_dir=state_dir)

        parsed = yaml.safe_load(text)
        loaded = write_and_load(tmp_path, text)

        assert parsed["state_dir"] == state_dir
        assert loaded.state_dir == state_dir

    def test_safe_defaults_response_off_approval_dry_run(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        root.mkdir()

        loaded = write_and_load(tmp_path, render_config(detect(root)))

        assert loaded.response.enabled is False
        assert loaded.response.mode == "approval"
        assert loaded.firewall.adapter == "dry_run"

    def test_no_provider_is_enabled(self, tmp_path: Path) -> None:
        root = tmp_path / "fake_root"
        root.mkdir()

        loaded = write_and_load(tmp_path, render_config(detect(root)))

        assert not loaded.intel.abuseipdb.enabled
        assert not loaded.intel.virustotal.enabled
        assert not loaded.intel.otx.enabled

    def test_output_never_contains_an_api_key_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINELAI_INTEL_ABUSEIPDB_API_KEY", FAKE_SECRET)
        monkeypatch.setenv("SENTINELAI_AI_LLM_API_KEY", FAKE_SECRET)
        root = tmp_path / "fake_root"
        root.mkdir()

        text = render_config(detect(root), enable_llm=True)

        assert FAKE_SECRET not in text
        assert "api_key:" not in text


# -- run_checks ------------------------------------------------------------


class TestDoctorChecks:
    def test_healthy_default_config_has_no_failures(self, tmp_path: Path) -> None:
        results = run_doctor(make_config(tmp_path))

        ok, _warn, failed = summarize(results)
        assert failed == 0
        assert ok >= 5
        assert check(results, "state directory").status == OK

    def test_state_dir_blocked_by_a_file_fails(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        blocker = tmp_path / "state_is_a_file"
        blocker.write_text("x", encoding="utf-8")
        config.state_dir = str(blocker)

        results = run_doctor(config)

        assert check(results, "state directory").status == FAIL

    def test_missing_log_path_warns(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.live.paths = [str(tmp_path / "nope.log")]

        results = run_doctor(config)

        (item,) = checks_with_prefix(results, "log path ")
        assert item.status == WARN
        assert item.detail == "does not exist"

    def test_existing_log_path_is_ok(self, tmp_path: Path) -> None:
        results = run_doctor(make_config(tmp_path))

        (item,) = checks_with_prefix(results, "log path ")
        assert item.status == OK

    def test_windows_platform_skips_path_checks_with_warning(self, tmp_path: Path) -> None:
        results = run_doctor(make_config(tmp_path), platform="win32")

        assert check(results, "live log paths").status == WARN
        assert checks_with_prefix(results, "log path ") == []

    def test_llm_disabled_is_ok_and_never_probes_network(self, tmp_path: Path) -> None:
        calls: list[str] = []

        def spy(url: str, **_kwargs: Any) -> FakeResponse:
            calls.append(url)
            return FakeResponse()

        results = run_doctor(make_config(tmp_path), http_get=spy)

        assert check(results, "local llm").status == OK
        assert calls == []

    def test_ollama_unreachable_warns(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.ai.llm.enabled = True

        results = run_doctor(config, http_get=http_failing)

        item = check(results, "local llm")
        assert item.status == WARN
        assert "unreachable" in item.detail

    def test_ollama_http_error_status_warns(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.ai.llm.enabled = True

        results = run_doctor(config, http_get=http_returning({}, status=500))

        assert check(results, "local llm").status == WARN

    def test_ollama_model_missing_warns_with_pull_hint(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.ai.llm.enabled = True
        config.ai.llm.model = "llama3.1:8b"
        body = {"models": [{"name": "mistral:7b"}]}

        results = run_doctor(config, http_get=http_returning(body))

        item = check(results, "local llm")
        assert item.status == WARN
        assert "not installed" in item.detail
        assert item.hint == "ollama pull llama3.1:8b"

    def test_ollama_model_installed_is_ok(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.ai.llm.enabled = True
        config.ai.llm.model = "llama3.1:8b"
        body = {"models": [{"name": "llama3.1:8b"}]}

        results = run_doctor(config, http_get=http_returning(body))

        assert check(results, "local llm").status == OK

    def test_untagged_model_matches_any_installed_tag(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.ai.llm.enabled = True
        config.ai.llm.model = "llama3.1"

        results = run_doctor(
            config, http_get=http_returning({"models": [{"name": "llama3.1:latest"}]})
        )

        assert check(results, "local llm").status == OK

    def test_ollama_garbage_body_warns(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.ai.llm.enabled = True

        results = run_doctor(config, http_get=http_returning("not a dict"))

        assert check(results, "local llm").status == WARN

    def test_api_key_over_plain_http_fails(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.ai.llm.enabled = True
        config.ai.llm.provider = "openai"
        config.ai.llm.endpoint = "http://llm.example.com/v1"
        config.ai.llm.api_key = FAKE_SECRET

        results = run_doctor(config)

        item = check(results, "local llm")
        assert item.status == FAIL
        assert FAKE_SECRET not in repr(results)

    def test_enabled_provider_without_key_fails_and_names_env_var(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.intel.abuseipdb.enabled = True

        results = run_doctor(config, env={})

        item = check(results, "intel abuseipdb")
        assert item.status == FAIL
        assert "SENTINELAI_INTEL_ABUSEIPDB_API_KEY" in item.hint

    def test_enabled_provider_with_env_key_is_ok_without_leaking_it(
        self, tmp_path: Path
    ) -> None:
        config = make_config(tmp_path)
        config.intel.virustotal.enabled = True

        results = run_doctor(config, env={"SENTINELAI_INTEL_VIRUSTOTAL_API_KEY": FAKE_SECRET})

        assert check(results, "intel virustotal").status == OK
        assert FAKE_SECRET not in repr(results)

    def test_intel_disabled_is_ok(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.intel.enabled = False

        assert check(run_doctor(config), "threat intel").status == OK

    def test_offline_intel_is_reported(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.intel.offline = True

        item = check(run_doctor(config), "threat intel mode")

        assert item.status == OK
        assert "offline" in item.detail

    def test_response_enabled_with_dry_run_warns(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.response.enabled = True
        config.firewall.adapter = "dry_run"

        results = run_doctor(config)

        assert check(results, "firewall response").status == WARN

    def test_response_auto_mode_warns(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.response.enabled = True
        config.response.mode = "auto"

        assert check(run_doctor(config), "response mode").status == WARN

    def test_command_adapter_missing_binary_fails_when_response_enabled(
        self, tmp_path: Path
    ) -> None:
        config = make_config(tmp_path)
        config.firewall.adapter = "command"
        config.firewall.command = "fw-tool"
        config.response.enabled = True

        results = run_doctor(config, which=no_tools)

        assert check(results, "firewall command").status == FAIL

    def test_no_notify_channel_is_ok(self, tmp_path: Path) -> None:
        assert check(run_doctor(make_config(tmp_path)), "notifications").status == OK

    def test_slack_missing_secret_names_env_var(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.notify.channels = ["slack"]

        item = check(run_doctor(config, env={}), "notify slack")

        assert item.status == FAIL
        assert "SENTINELAI_NOTIFY_SLACK_WEBHOOK" in item.detail

    def test_telegram_missing_token_names_env_var(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.notify.channels = ["telegram"]
        config.notify.telegram_chat_id = "12345"

        item = check(run_doctor(config, env={}), "notify telegram")

        assert item.status == FAIL
        assert "SENTINELAI_NOTIFY_TELEGRAM_TOKEN" in item.detail

    def test_email_login_without_password_names_env_var(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.notify.channels = ["email"]
        config.notify.email_host = "smtp.example.invalid"
        config.notify.email_from = "a@example.invalid"
        config.notify.email_to = ["b@example.invalid"]
        config.notify.email_username = "user"

        item = check(run_doctor(config, env={}), "notify email")

        assert item.status == FAIL
        assert "SENTINELAI_NOTIFY_EMAIL_PASSWORD" in item.detail

    def test_unknown_notify_channel_fails(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.notify.channels = ["carrier-pigeon"]

        assert check(run_doctor(config), "notify channel").status == FAIL

    def test_notify_secrets_never_appear_in_any_result_field(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.notify.channels = ["slack", "telegram", "email"]
        config.notify.slack_webhook = f"http://hooks.example.invalid/{FAKE_SECRET}"
        config.notify.telegram_token = FAKE_SECRET
        config.notify.email_password = FAKE_SECRET
        config.notify.email_host = "smtp.example.invalid"
        config.notify.email_from = "a@example.invalid"
        config.notify.email_to = ["b@example.invalid"]
        env = {
            "SENTINELAI_NOTIFY_SLACK_WEBHOOK": FAKE_SECRET,
            "SENTINELAI_NOTIFY_TELEGRAM_TOKEN": FAKE_SECRET,
            "SENTINELAI_NOTIFY_EMAIL_PASSWORD": FAKE_SECRET,
            "SENTINELAI_INTEL_OTX_API_KEY": FAKE_SECRET,
        }

        results = run_doctor(config, env=env)

        for result in results:
            for value in (result.name, result.status, result.detail, result.hint):
                assert FAKE_SECRET not in value
        assert check(results, "notify slack").status == FAIL  # non-https webhook

    def test_broken_http_get_never_raises(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.ai.llm.enabled = True

        def weird(url: str, **_kwargs: Any) -> Any:
            raise ValueError("bad")

        results = run_doctor(config, http_get=weird)

        assert check(results, "local llm").status == WARN

    def test_every_result_has_a_valid_status(self, tmp_path: Path) -> None:
        results = run_doctor(make_config(tmp_path))

        assert {r.status for r in results} <= {OK, WARN, FAIL}


class TestSummarize:
    def test_counts_each_status(self) -> None:
        results = [
            CheckResult("a", OK, ""),
            CheckResult("b", OK, ""),
            CheckResult("c", WARN, ""),
            CheckResult("d", FAIL, ""),
            CheckResult("e", FAIL, ""),
            CheckResult("f", FAIL, ""),
        ]

        assert summarize(results) == (2, 1, 3)

    def test_empty_list_is_all_zero(self) -> None:
        assert summarize([]) == (0, 0, 0)


# -- sentinel init ---------------------------------------------------------


@pytest.mark.usefixtures("clean_env")
class TestInitCommand:
    def test_dry_run_prints_yaml_and_writes_nothing(self, cfg: Path, tmp_path: Path) -> None:
        out = tmp_path / "out" / "config.yaml"

        result = cli_run(cfg, "init", "--dry-run", "--output", str(out))

        assert result.exit_code == 0, result.output
        parsed = yaml.safe_load(result.stdout)
        assert parsed["response"]["enabled"] is False
        assert not out.exists()
        assert not out.parent.exists()
        assert [p.name for p in tmp_path.glob(".sentinel-init-*")] == []

    def test_dry_run_with_existing_output_does_not_need_force(
        self, cfg: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "config.yaml"
        out.write_text("# keep me\n", encoding="utf-8")

        result = cli_run(cfg, "init", "--dry-run", "--output", str(out))

        assert result.exit_code == 0, result.output
        assert out.read_text(encoding="utf-8") == "# keep me\n"

    def test_output_writes_a_loadable_file(self, cfg: Path, tmp_path: Path) -> None:
        out = tmp_path / "new" / "config.yaml"

        result = cli_run(cfg, "init", "--output", str(out))

        assert result.exit_code == 0, result.output
        loaded = load_config(out)
        assert loaded.response.enabled is False
        assert loaded.firewall.adapter == "dry_run"

    @pytest.mark.skipif(not POSIX, reason="POSIX file modes only")
    def test_output_file_mode_is_0600(self, cfg: Path, tmp_path: Path) -> None:
        out = tmp_path / "config.yaml"

        cli_run(cfg, "init", "--output", str(out))

        assert stat.S_IMODE(out.stat().st_mode) == 0o600

    def test_existing_output_without_force_is_refused_and_untouched(
        self, cfg: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "config.yaml"
        out.write_text("# original\n", encoding="utf-8")

        result = cli_run(cfg, "init", "--output", str(out))

        assert result.exit_code == ConfigError.exit_code
        assert result.exit_code != 0
        assert "--force" in result.output
        assert out.read_text(encoding="utf-8") == "# original\n"

    def test_force_overwrites_existing_output(self, cfg: Path, tmp_path: Path) -> None:
        out = tmp_path / "config.yaml"
        out.write_text("# original\n", encoding="utf-8")

        result = cli_run(cfg, "init", "--output", str(out), "--force")

        assert result.exit_code == 0, result.output
        assert "Generated by `sentinel init`" in out.read_text(encoding="utf-8")

    def test_state_dir_option_is_recorded(self, cfg: Path, tmp_path: Path) -> None:
        out = tmp_path / "config.yaml"
        state = tmp_path / "custom state"

        result = cli_run(cfg, "init", "--output", str(out), "--state-dir", str(state))

        assert result.exit_code == 0, result.output
        assert load_config(out).state_dir == str(state)

    def test_invalid_state_dir_leaves_no_partial_file(self, cfg: Path, tmp_path: Path) -> None:
        # A broken tuning overlay inside the chosen state dir makes load_config reject
        # the generated config, so nothing must be written.
        bad_state = tmp_path / "bad_state"
        bad_state.mkdir()
        (bad_state / "tuning.yaml").write_text("firewall:\n  adapter: x\n", encoding="utf-8")
        target = tmp_path / "out" / "config.yaml"
        target.parent.mkdir()

        result = cli_run(cfg, "init", "--output", str(target), "--state-dir", str(bad_state))

        assert result.exit_code != 0
        assert not target.exists()
        assert list(target.parent.iterdir()) == []

    def test_llm_flag_enables_llm_block(self, cfg: Path, tmp_path: Path) -> None:
        out = tmp_path / "config.yaml"

        result = cli_run(cfg, "init", "--output", str(out), "--llm", "--llm-model", "phi3:mini")

        assert result.exit_code == 0, result.output
        loaded = load_config(out)
        assert loaded.ai.llm.enabled is True
        assert loaded.ai.llm.model == "phi3:mini"


# -- sentinel doctor -------------------------------------------------------


@pytest.mark.usefixtures("clean_env")
class TestDoctorCommand:
    def test_warnings_only_exit_zero(self, cfg: Path) -> None:
        result = cli_run(cfg, "doctor", "--json")

        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        statuses = {item["status"] for item in data}
        assert FAIL not in statuses
        assert WARN in statuses  # the configured log path does not exist

    def test_state_dir_that_is_a_file_exits_one(self, tmp_path: Path) -> None:
        blocker = tmp_path / "state_file"
        blocker.write_text("x", encoding="utf-8")
        path = tmp_path / "bad.yaml"
        path.write_text(f'state_dir: "{blocker.as_posix()}"\n', encoding="utf-8")

        result = cli_run(path, "doctor", "--json")

        assert result.exit_code == 1, result.output
        data = json.loads(result.stdout)
        assert any(i["name"] == "state directory" and i["status"] == FAIL for i in data)

    def test_table_output_prints_summary_line(self, cfg: Path) -> None:
        result = cli_run(cfg, "doctor")

        assert result.exit_code == 0, result.output
        assert "warning(s)" in result.output
        assert "failed" in result.output

    def test_json_is_valid_with_sorted_keys(self, cfg: Path) -> None:
        result = cli_run(cfg, "doctor", "--json")

        data = json.loads(result.stdout)
        assert isinstance(data, list) and data
        for item in data:
            assert list(item) == sorted(item)
            assert set(item) == {"name", "status", "detail", "hint"}

    def test_json_output_has_no_control_characters(self, cfg: Path) -> None:
        result = cli_run(cfg, "doctor", "--json")

        assert "\x1b" not in result.stdout

# -- review fixes: doctor and init ------------------------------------------


class _ProbeResponse:
    def __init__(self, chunk_count: int = 1, body: bytes = b'{"models": []}') -> None:
        self.status_code = 200
        self.closed = False
        self.bytes_served = 0
        self._chunk_count = chunk_count
        self._body = body

    def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
        for _ in range(self._chunk_count):
            chunk = self._body if len(self._body) <= chunk_size else self._body[:chunk_size]
            self.bytes_served += len(chunk)
            yield chunk

    def close(self) -> None:
        self.closed = True


class _ProbeSession:
    """Stand-in for ``requests.Session`` that records how the probe configured it."""

    instances: ClassVar[list[_ProbeSession]] = []
    response: ClassVar[_ProbeResponse] = _ProbeResponse()

    def __init__(self) -> None:
        self.trust_env = True  # the real default
        self.get_calls: list[dict[str, Any]] = []
        self.trust_env_at_get: bool | None = None
        _ProbeSession.instances.append(self)

    def __enter__(self) -> _ProbeSession:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def get(self, url: str, **kwargs: Any) -> _ProbeResponse:
        self.trust_env_at_get = self.trust_env
        self.get_calls.append({"url": url, **kwargs})
        return _ProbeSession.response


def _set_slack(config: SentinelConfig, url: str) -> None:
    config.notify.channels = ["slack"]
    config.notify.slack_webhook = url


def _set_telegram(config: SentinelConfig, token: str) -> None:
    config.notify.channels = ["telegram"]
    config.notify.telegram_token = token
    config.notify.telegram_chat_id = "12345"


class TestDoctorReviewFixes:
    @pytest.mark.parametrize(
        "url",
        [
            "https://hooks.slack.com/services/T/B/x",
            "https://slack.com/api/hook",
            "https://HOOKS.SLACK.COM/services/T/B/x",
            "http://hooks.slack.com/services/T/B/x",
            "https://evilslack.com/x",
            "https://slack.com.evil.example/x",
            "https://hooks.slack.com@evil.example/x",
            "https://example.invalid/hook",
            "https://hooks.slack.com/x y",
            "https://",
            "ftp://hooks.slack.com/x",
        ],
    )
    def test_slack_host_rule_is_identical_to_the_notifier(
        self, tmp_path: Path, url: str
    ) -> None:
        config = make_config(tmp_path)
        _set_slack(config, url)
        try:
            SlackNotifier(url, 5.0)
            notifier_accepts = True
        except NotifyError:
            notifier_accepts = False

        item = check(run_doctor(config, env={}), "notify slack")

        assert (item.status == OK) is notifier_accepts
        assert (item.status == FAIL) is (not notifier_accepts)

    @pytest.mark.parametrize(
        "token",
        [
            "123456789:ABCdefGhIjKlMnOpQrStUvWxYz012345",
            "1:abcdefghij",
            "123:short",
            "abc:ABCdefGhIjKl",
            "123456789:ABCdef GhIjKl",
            "123456789:ABCdefGhIjKl\n",
            "123456789:ABCdefGhIjKl!",
            "123456789:" + "a" * 128,
            "123456789:" + "a" * 129,
            "1" * 21 + ":ABCdefGhIjKl",
            "123456789ABCdefGhIjKl",
            "١٢٣:ABCdefGhIjKl",
        ],
    )
    def test_telegram_token_regex_is_identical_to_the_notifier(
        self, tmp_path: Path, token: str
    ) -> None:
        config = make_config(tmp_path)
        _set_telegram(config, token)
        try:
            TelegramNotifier(token, "12345", 5.0)
            notifier_accepts = True
        except NotifyError:
            notifier_accepts = False

        item = check(run_doctor(config, env={}), "notify telegram")

        assert (item.status == OK) is notifier_accepts
        assert FAKE_SECRET not in item.detail

    def test_token_the_notifier_rejects_fails_the_doctor_without_echoing_it(
        self, tmp_path: Path
    ) -> None:
        config = make_config(tmp_path)
        _set_telegram(config, "not-a-token-" + FAKE_SECRET)

        item = check(run_doctor(config, env={}), "notify telegram")

        assert item.status == FAIL
        assert FAKE_SECRET not in item.detail + item.hint

    def _email_config(self, tmp_path: Path, **changes: Any) -> SentinelConfig:
        config = make_config(tmp_path)
        config.notify.channels = ["email"]
        config.notify.email_host = "smtp.example.invalid"
        config.notify.email_from = "a@example.invalid"
        config.notify.email_to = ["b@example.invalid"]
        config.notify.email_username = "user"
        config.notify.email_password = "fake-password"
        for name, value in changes.items():
            setattr(config.notify, name, value)
        return config

    def test_plain_smtp_without_starttls_warns_about_cleartext(self, tmp_path: Path) -> None:
        config = self._email_config(tmp_path, email_starttls=False, email_port=25)

        item = check(run_doctor(config, env={}), "notify email")

        assert item.status == WARN
        assert "plain SMTP" in item.detail
        assert "fake-password" not in item.detail + item.hint

    def test_starttls_email_does_not_warn(self, tmp_path: Path) -> None:
        config = self._email_config(tmp_path, email_starttls=True, email_port=587)

        assert check(run_doctor(config, env={}), "notify email").status == OK

    def test_smtps_port_without_starttls_does_not_warn(self, tmp_path: Path) -> None:
        config = self._email_config(tmp_path, email_starttls=False, email_port=465)

        assert check(run_doctor(config, env={}), "notify email").status == OK

    def test_llm_probe_session_ignores_proxy_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _ProbeSession.instances = []
        _ProbeSession.response = _ProbeResponse()
        monkeypatch.setattr(doctor_module.requests, "Session", _ProbeSession)

        response = doctor_module._bounded_get("http://127.0.0.1:11434/api/tags", timeout=1.0)

        (session,) = _ProbeSession.instances
        assert session.trust_env_at_get is False
        assert session.get_calls[0]["allow_redirects"] is False
        assert session.get_calls[0]["stream"] is True
        assert response.json() == {"models": []}
        assert _ProbeSession.response.closed

    def test_llm_probe_reads_at_most_one_megabyte(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _ProbeSession.instances = []
        _ProbeSession.response = _ProbeResponse(chunk_count=500, body=b"x" * 65_536)
        monkeypatch.setattr(doctor_module.requests, "Session", _ProbeSession)

        response = doctor_module._bounded_get("http://127.0.0.1:11434/api/tags", timeout=5.0)

        assert len(response.content) <= 1_048_576
        assert _ProbeSession.response.bytes_served <= 1_048_576 + 65_536

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo (POSIX)")
    def test_fifo_log_path_is_reported_not_a_regular_file_without_hanging(
        self, tmp_path: Path
    ) -> None:
        fifo = tmp_path / "pipe.log"
        os.mkfifo(fifo)  # type: ignore[attr-defined,unused-ignore]
        config = make_config(tmp_path)
        config.live.paths = [str(fifo)]

        results = run_doctor(config)

        (item,) = checks_with_prefix(results, "log path ")
        assert item.status == WARN
        assert "not a regular file" in item.detail

    def test_directory_log_path_is_reported_not_a_regular_file(self, tmp_path: Path) -> None:
        config = make_config(tmp_path)
        config.live.paths = [str(tmp_path)]

        (item,) = checks_with_prefix(run_doctor(config), "log path ")

        assert item.status == WARN
        assert "not a regular file" in item.detail


class _FakeOs:
    """Proxy for the ``os`` module with a chosen ``name`` (used by ``init``)."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, attribute: str) -> Any:
        return getattr(os, attribute)


@pytest.mark.usefixtures("clean_env")
class TestInitReviewFixes:
    def test_race_on_exclusive_create_gives_a_clean_error_and_keeps_the_winner(
        self, cfg: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "config.yaml"
        real_open = os.open
        flags_seen: list[int] = []

        def racing_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if Path(os.fspath(path)) == target:
                flags_seen.append(flags)
                target.write_text("# winner\n", encoding="utf-8")  # created in the gap
                raise FileExistsError(17, "File exists")
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", racing_open)

        result = cli_run(cfg, "init", "--output", str(target))

        assert result.exit_code == ConfigError.exit_code
        assert "--force" in result.output
        assert "Traceback" not in result.output
        assert target.read_text(encoding="utf-8") == "# winner\n"
        assert [p.name for p in tmp_path.glob(".sentinel-init-*")] == []
        assert flags_seen and flags_seen[0] & os.O_EXCL

    def test_without_force_the_file_is_created_with_o_excl(
        self, cfg: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "config.yaml"
        real_open = os.open
        flags_seen: list[int] = []

        def spy_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if Path(os.fspath(path)) == target:
                flags_seen.append(flags)
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)

        result = cli_run(cfg, "init", "--output", str(target))

        assert result.exit_code == 0, result.output
        assert len(flags_seen) == 1
        assert flags_seen[0] & os.O_EXCL
        assert target.is_file()

    def test_force_replaces_atomically_without_o_excl_on_the_target(
        self, cfg: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "config.yaml"
        target.write_text("# old\n", encoding="utf-8")
        real_open = os.open
        targets_opened: list[Path] = []

        def spy_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if Path(os.fspath(path)) == target:
                targets_opened.append(Path(os.fspath(path)))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy_open)

        result = cli_run(cfg, "init", "--output", str(target), "--force")

        assert result.exit_code == 0, result.output
        assert targets_opened == []  # written via a temp file + os.replace
        assert "Generated by `sentinel init`" in target.read_text(encoding="utf-8")

    @pytest.mark.parametrize("os_name", ["posix", "nt"])
    def test_owner_only_permissions_note_is_printed_only_on_posix(
        self, cfg: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, os_name: str
    ) -> None:
        monkeypatch.setattr(setup_command, "os", _FakeOs(os_name))
        target = tmp_path / "config.yaml"

        result = cli_run(cfg, "init", "--output", str(target))

        assert result.exit_code == 0, result.output
        shown = " ".join(result.output.split())
        assert ("owner-only permissions" in shown) is (os_name == "posix")

