"""Static guard-rail tests for the deployment files (Docker, systemd, CI, packaging).

These read the files as text and assert security-relevant properties so that a
later edit cannot silently weaken the container image, the systemd sandbox, the
CI gates or the secret hygiene. Nothing here starts Docker or systemd.
"""

from __future__ import annotations

import configparser
import fnmatch
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

import sentinelai
from sentinelai.config.loader import load_config

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        tomllib = pytest.importorskip("tomli")  # type: ignore[assignment]
    with path.open("rb") as handle:
        data: dict[str, Any] = tomllib.load(handle)
    return data


# ----------------------------------------------------------------- Dockerfile --


def _logical_lines(text: str) -> list[str]:
    """Join backslash continuations and drop comment-only / blank lines."""
    lines: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if stripped.startswith("#"):
            continue  # comment inside a continued instruction
        if stripped.endswith("\\"):
            buffer += stripped[:-1].rstrip() + " "
            continue
        lines.append(buffer + stripped)
        buffer = ""
    if buffer:
        lines.append(buffer.strip())
    return lines


def _dockerfile_stages() -> tuple[dict[str, str], list[list[str]]]:
    """Return (global ARG defaults, instructions grouped per build stage)."""
    args: dict[str, str] = {}
    stages: list[list[str]] = []
    for line in _logical_lines(_text(ROOT / "Dockerfile")):
        keyword = line.split(None, 1)[0].upper()
        if keyword == "FROM":
            stages.append([line])
        elif stages:
            stages[-1].append(line)
        elif keyword == "ARG":
            name, _, default = line.split(None, 1)[1].partition("=")
            args[name.strip()] = default.strip()
    return args, stages


def _instructions(stage: list[str], keyword: str) -> list[str]:
    return [i for i in stage if i.split(None, 1)[0].upper() == keyword]


class TestDockerfile:
    def test_multi_stage_build_has_at_least_two_stages(self) -> None:
        _, stages = _dockerfile_stages()
        assert len(stages) >= 2

    def test_every_from_has_explicit_non_latest_tag(self) -> None:
        args, stages = _dockerfile_stages()
        for stage in stages:
            image = stage[0].split()[1]
            image = re.sub(
                r"\$\{(\w+)\}", lambda m: args.get(m.group(1), "") or "UNSET", image
            )
            assert "UNSET" not in image, f"unresolved ARG in {stage[0]!r}"
            if "@sha256:" in image:
                continue
            name, sep, tag = image.partition(":")
            assert sep and tag, f"untagged base image: {image}"
            assert tag != "latest", f"floating :latest tag: {image}"
            assert name

    def test_final_stage_runs_as_non_root_user(self) -> None:
        _, stages = _dockerfile_stages()
        users = _instructions(stages[-1], "USER")
        assert users, "final stage never sets USER"
        user = users[-1].split(None, 1)[1].strip()
        assert user.split(":")[0] not in {"root", "0"}
        assert user.split(":")[-1] not in {"root", "0"}

    def test_user_is_set_before_entrypoint(self) -> None:
        _, stages = _dockerfile_stages()
        keywords = [i.split(None, 1)[0].upper() for i in stages[-1]]
        assert keywords.index("USER") < keywords.index("ENTRYPOINT")

    def test_entrypoint_is_exec_form_sentinel(self) -> None:
        _, stages = _dockerfile_stages()
        entry = _instructions(stages[-1], "ENTRYPOINT")
        assert len(entry) == 1
        assert entry[0].split(None, 1)[1].replace(" ", "") == '["sentinel"]'

    def test_final_stage_has_healthcheck(self) -> None:
        _, stages = _dockerfile_stages()
        assert _instructions(stages[-1], "HEALTHCHECK")

    def test_no_pipe_to_shell_installs(self) -> None:
        text = "\n".join(_logical_lines(_text(ROOT / "Dockerfile")))
        assert not re.search(r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b", text)

    def test_apt_get_install_uses_no_install_recommends_in_final_stage(self) -> None:
        _, stages = _dockerfile_stages()
        for line in stages[-1]:
            if "apt-get install" in line:
                assert "--no-install-recommends" in line

    def test_final_stage_does_not_copy_whole_build_context(self) -> None:
        _, stages = _dockerfile_stages()
        for line in _instructions(stages[-1], "COPY"):
            parts = [p for p in line.split()[1:] if not p.startswith("--")]
            assert parts[:2] != [".", "."], f"COPY . . in final stage: {line}"
            assert "--from=" in line or parts[0] != "."

    def test_final_stage_copies_only_from_builder(self) -> None:
        _, stages = _dockerfile_stages()
        for line in _instructions(stages[-1], "COPY") + _instructions(stages[-1], "ADD"):
            assert "--from=" in line, f"final stage pulls from build context: {line}"

    def test_no_secrets_baked_into_env_or_arg(self) -> None:
        pattern = re.compile(
            r"(API_?KEY|PASSWORD|PASSWD|TOKEN|SECRET|WEBHOOK)\w*\s*=\s*[^\s\"']+",
            re.IGNORECASE,
        )
        for line in _logical_lines(_text(ROOT / "Dockerfile")):
            if line.split(None, 1)[0].upper() in {"ENV", "ARG", "LABEL"}:
                assert not pattern.search(line), f"possible baked-in secret: {line}"

    def test_extras_build_arg_is_validated(self) -> None:
        text = _text(ROOT / "Dockerfile")
        assert "[!a-z,]" in text


class TestDockerignore:
    @staticmethod
    def _patterns() -> set[str]:
        lines = _text(ROOT / ".dockerignore").splitlines()
        return {ln.strip().rstrip("/") for ln in lines if ln.strip() and not ln.startswith("#")}

    @pytest.mark.parametrize(
        "entry",
        [".git", ".venv", "config.yaml", "*.db", ".claude", "linux-firewall-automation-main"],
    )
    def test_sensitive_or_irrelevant_path_is_excluded(self, entry: str) -> None:
        assert entry in self._patterns()

    def test_env_files_are_excluded(self) -> None:
        patterns = self._patterns()
        assert ".env" in patterns or "*.env" in patterns


# -------------------------------------------------------------- systemd units --


def _unit(name: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read_string(_text(DEPLOY / name))
    return parser


SERVICES = [
    ("sentinelai.service", "live"),
    ("sentinelai-digest.service", "digest --send"),
]


#: Each unit loads its own (optional) environment file: the digest unit holds the
#: notification secrets, the live daemon never sees them.
ENV_FILES = {
    "sentinelai.service": "-/etc/sentinelai/sentinelai.env",
    "sentinelai-digest.service": "-/etc/sentinelai/sentinelai-digest.env",
}


@pytest.mark.parametrize(("unit", "subcommand"), SERVICES)
class TestServiceHardening:
    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "yes"),
            ("PrivateTmp", "yes"),
            ("PrivateDevices", "yes"),
            ("LockPersonality", "yes"),
            ("RestrictSUIDSGID", "yes"),
            ("UMask", "0077"),
            ("CapabilityBoundingSet", ""),
        ],
    )
    def test_hardening_directive_has_required_value(
        self, unit: str, subcommand: str, key: str, value: str
    ) -> None:
        assert _unit(unit)["Service"][key].strip() == value

    def test_address_families_exclude_netlink_and_packet(
        self, unit: str, subcommand: str
    ) -> None:
        families = _unit(unit)["Service"]["RestrictAddressFamilies"].split()
        assert families
        assert not {"AF_NETLINK", "AF_PACKET"} & set(families)
        assert not any(f.startswith("~") for f in families)

    def test_runs_as_dedicated_non_root_user(self, unit: str, subcommand: str) -> None:
        service = _unit(unit)["Service"]
        assert service["User"] not in {"root", "0", ""}
        assert service["Group"] not in {"root", "0", ""}
        assert "User=root" not in _text(DEPLOY / unit)

    def test_write_access_limited_to_state_dir(self, unit: str, subcommand: str) -> None:
        paths = _unit(unit)["Service"]["ReadWritePaths"].split()
        assert paths == ["/var/lib/sentinelai"]

    def test_log_directory_is_read_only_only_for_the_log_reading_unit(
        self, unit: str, subcommand: str
    ) -> None:
        service = _unit(unit)["Service"]
        if unit == "sentinelai.service":
            assert service["ReadOnlyPaths"].split() == ["/var/log"]
            assert service["SupplementaryGroups"].split() == ["adm"]
        else:  # the digest reads no logs at all
            assert "ReadOnlyPaths" not in service
            assert "SupplementaryGroups" not in service
            assert "/var/log" not in _text(DEPLOY / unit).replace("# ", "#").split("[Service]")[1]

    def test_state_directory_is_private(self, unit: str, subcommand: str) -> None:
        service = _unit(unit)["Service"]
        assert service["StateDirectory"] == "sentinelai"
        assert service["StateDirectoryMode"] == "0700"

    def test_execstart_uses_config_and_expected_subcommand(
        self, unit: str, subcommand: str
    ) -> None:
        exec_start = _unit(unit)["Service"]["ExecStart"]
        assert "--config /etc/sentinelai/config.yaml" in exec_start
        assert exec_start.endswith(f" {subcommand}")
        assert exec_start.split()[0].startswith("/")

    def test_secrets_come_from_optional_environment_file(
        self, unit: str, subcommand: str
    ) -> None:
        assert _unit(unit)["Service"]["EnvironmentFile"] == ENV_FILES[unit]

    def test_no_secret_values_inline_in_unit(self, unit: str, subcommand: str) -> None:
        for line in _text(DEPLOY / unit).splitlines():
            if line.startswith("Environment="):
                assert not re.search(r"TOKEN|PASSWORD|API_KEY|WEBHOOK", line, re.IGNORECASE)


class TestDigestTimer:
    def test_timer_has_on_calendar_schedule(self) -> None:
        assert _unit("sentinelai-digest.timer")["Timer"]["OnCalendar"].strip()

    def test_timer_is_persistent(self) -> None:
        assert _unit("sentinelai-digest.timer")["Timer"]["Persistent"] == "true"

    def test_timer_targets_digest_service(self) -> None:
        assert _unit("sentinelai-digest.timer")["Timer"]["Unit"] == "sentinelai-digest.service"

    def test_digest_service_is_oneshot(self) -> None:
        assert _unit("sentinelai-digest.service")["Service"]["Type"] == "oneshot"


# ------------------------------------------------------------ env example file --

_ENV_LINE = re.compile(r"^\s*#?\s*(SENTINELAI_[A-Z0-9_]+)=(.*)$")
LIVE_ENV = "sentinelai.env.example"
DIGEST_ENV = "sentinelai-digest.env.example"
ENV_EXAMPLES = [LIVE_ENV, DIGEST_ENV]
NOTIFY_SECRETS = {
    "SENTINELAI_NOTIFY_TELEGRAM_TOKEN",
    "SENTINELAI_NOTIFY_SLACK_WEBHOOK",
    "SENTINELAI_NOTIFY_EMAIL_PASSWORD",
}


def _env_example_vars(name: str = LIVE_ENV) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in _text(DEPLOY / name).splitlines():
        match = _ENV_LINE.match(line)
        if match:
            found[match.group(1)] = match.group(2).strip()
    return found


@pytest.mark.parametrize("example", ENV_EXAMPLES)
class TestEnvExample:
    def test_every_assignment_is_commented_out(self, example: str) -> None:
        for line in _text(DEPLOY / example).splitlines():
            if re.match(r"^\s*[A-Za-z_][A-Za-z0-9_]*=", line):
                pytest.fail(f"active (uncommented) assignment: {line!r}")

    def test_secret_values_are_placeholders(self, example: str) -> None:
        variables = _env_example_vars(example)
        assert variables
        for name, value in variables.items():
            if re.search(r"KEY|TOKEN|WEBHOOK|PASSWORD|SECRET", name):
                assert value == "CHANGE_ME", f"{name} has a non-placeholder value"

    def test_documented_variables_populate_real_config_fields(
        self, example: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        for key in [k for k in __import__("os").environ if k.startswith("SENTINELAI_")]:
            monkeypatch.delenv(key)
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("{}\n", encoding="utf-8")
        monkeypatch.setenv("SENTINELAI_STATE_DIR", str(tmp_path / "state"))

        expected = {
            "SENTINELAI_INTEL_ABUSEIPDB_ENABLED": ("true", "intel.abuseipdb.enabled", True),
            "SENTINELAI_INTEL_ABUSEIPDB_API_KEY": (
                "fake-key", "intel.abuseipdb.api_key", "fake-key",
            ),
            "SENTINELAI_NOTIFY_TELEGRAM_TOKEN": (
                "fake-token", "notify.telegram_token", "fake-token",
            ),
            "SENTINELAI_NOTIFY_SLACK_WEBHOOK": (
                "https://hooks.example.invalid/fake",
                "notify.slack_webhook",
                "https://hooks.example.invalid/fake",
            ),
            "SENTINELAI_NOTIFY_EMAIL_PASSWORD": (
                "fake-pass", "notify.email_password", "fake-pass",
            ),
        }
        documented = set(_env_example_vars(example))
        unmapped = documented - set(expected)
        assert not unmapped, f"unmapped documented vars: {unmapped}"
        for name in documented:
            monkeypatch.setenv(name, expected[name][0])

        config = load_config(cfg_file, apply_overlay=False)
        for name in documented:
            _, path, want = expected[name]
            obj: Any = config
            for part in path.split("."):
                obj = getattr(obj, part)
            assert obj == want, f"{name} did not reach {path}"


class TestEnvExampleSplit:
    def test_live_env_example_has_no_notification_secrets(self) -> None:
        variables = set(_env_example_vars(LIVE_ENV))
        assert variables  # threat-intel / generic settings only
        assert not variables & NOTIFY_SECRETS
        assert not any("NOTIFY" in name for name in variables)

    def test_digest_env_example_has_exactly_the_three_notify_secrets(self) -> None:
        assert set(_env_example_vars(DIGEST_ENV)) == NOTIFY_SECRETS

    def test_digest_env_example_has_no_intel_keys(self) -> None:
        assert not any("INTEL" in name for name in _env_example_vars(DIGEST_ENV))

    @pytest.mark.parametrize("name", ["sentinelai.env", "sentinelai-digest.env"])
    def test_real_env_files_are_gitignored(self, name: str) -> None:
        assert _is_ignored(name)

    def test_secret_fields_are_hidden_from_repr(self) -> None:
        from sentinelai.config.models import NotifyConfig

        cfg = NotifyConfig(
            slack_webhook="https://hooks.example.invalid/x",
            telegram_token="tok-fake",
            email_password="pw-fake",
        )
        shown = repr(cfg)
        assert "tok-fake" not in shown
        assert "pw-fake" not in shown
        assert "hooks.example.invalid" not in shown


# ----------------------------------------------------------------- CI workflow --


def _workflow() -> dict[Any, Any]:
    data = yaml.safe_load(_text(ROOT / ".github" / "workflows" / "ci.yml"))
    assert isinstance(data, dict)
    return data


def _all_run_commands(workflow: dict[Any, Any]) -> str:
    runs = [
        str(step.get("run", ""))
        for job in workflow["jobs"].values()
        for step in job["steps"]
    ]
    return "\n".join(runs)


class TestCiWorkflow:
    def test_top_level_permissions_are_read_only_contents(self) -> None:
        assert _workflow()["permissions"] == {"contents": "read"}

    def test_runs_ruff_mypy_and_pytest(self) -> None:
        runs = _all_run_commands(_workflow())
        assert "ruff check" in runs
        assert "mypy" in runs
        assert "pytest" in runs

    def test_runs_detection_benchmark_regression_gate(self) -> None:
        assert "sentinel eval --baseline" in _all_run_commands(_workflow())

    def test_has_docker_job_that_builds_image(self) -> None:
        jobs = _workflow()["jobs"]
        assert "docker" in jobs
        assert "docker build" in "\n".join(str(s.get("run", "")) for s in jobs["docker"]["steps"])

    def test_matrix_covers_python_310_to_313(self) -> None:
        versions = {str(v) for v in _workflow()["jobs"]["test"]["strategy"]["matrix"][
            "python-version"
        ]}
        assert {"3.10", "3.11", "3.12", "3.13"} <= versions

    def test_actions_are_pinned_to_a_major_version(self) -> None:
        uses = [
            step["uses"]
            for job in _workflow()["jobs"].values()
            for step in job["steps"]
            if "uses" in step
        ]
        assert uses
        for ref in uses:
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@v\d+", ref), f"unpinned action: {ref}"

    def test_no_job_requests_write_permissions(self) -> None:
        for job in _workflow()["jobs"].values():
            perms = job.get("permissions", {})
            if isinstance(perms, dict):
                assert "write" not in perms.values()
            else:
                assert perms != "write-all"

    def test_workflow_does_not_use_pull_request_target(self) -> None:
        assert "pull_request_target" not in _text(ROOT / ".github" / "workflows" / "ci.yml")


# ------------------------------------------------------------------- pyproject --


class TestPyproject:
    @staticmethod
    def _data() -> dict[str, Any]:
        return _load_toml(ROOT / "pyproject.toml")

    def test_hypothesis_is_in_dev_extra(self) -> None:
        dev = self._data()["project"]["optional-dependencies"]["dev"]
        assert any(d.lower().startswith("hypothesis") for d in dev)

    def test_console_script_entry_point(self) -> None:
        assert self._data()["project"]["scripts"]["sentinel"] == "sentinelai.cli.app:main"

    def test_requires_python_is_310_or_newer(self) -> None:
        assert self._data()["project"]["requires-python"].replace(" ", "") == ">=3.10"

    def test_core_dependencies_are_exactly_the_known_four(self) -> None:
        deps = self._data()["project"]["dependencies"]
        names = {re.match(r"[A-Za-z0-9_.-]+", d).group(0).lower() for d in deps}  # type: ignore[union-attr]
        assert names == {"click", "rich", "pyyaml", "requests"}

    def test_heavy_ml_libraries_stay_optional(self) -> None:
        deps = " ".join(self._data()["project"]["dependencies"]).lower()
        for heavy in ("numpy", "scikit-learn", "scipy", "pandas", "torch"):
            assert heavy not in deps

    def test_version_matches_package_version(self) -> None:
        assert self._data()["project"]["version"] == sentinelai.__version__


# ------------------------------------------------------------------- .gitignore --


def _gitignore_patterns() -> list[str]:
    lines = _text(ROOT / ".gitignore").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith(("#", "!"))]


def _is_ignored(name: str) -> bool:
    for pattern in _gitignore_patterns():
        bare = pattern.rstrip("/")
        if fnmatch.fnmatch(name, bare) or name == bare:
            return True
    return False


class TestGitignore:
    @pytest.mark.parametrize("name", ["config.yaml", "alerts.db", "reports"])
    def test_runtime_or_secret_path_is_ignored(self, name: str) -> None:
        assert _is_ignored(name)

    def test_example_config_is_not_ignored(self) -> None:
        negations = [
            ln.strip() for ln in _text(ROOT / ".gitignore").splitlines() if ln.startswith("!")
        ]
        assert "!config.example.yaml" in negations

    def test_secrets_env_file_is_ignored(self) -> None:
        assert _is_ignored("sentinelai.env")


# --------------------------------------------------------------- config.example --

_SECRET_PATTERNS = {
    "long hex token": re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    "long base64/url token": re.compile(r"[A-Za-z0-9+/_]{40,}={0,2}"),
    "slack token": re.compile(r"xox[abprs]-"),
    "aws access key": re.compile(r"AKIA[0-9A-Z]{12,}"),
    "github token": re.compile(r"gh[pousr]_[A-Za-z0-9]{10,}"),
}


class TestConfigExample:
    def test_example_config_loads_through_load_config(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        for key in [k for k in __import__("os").environ if k.startswith("SENTINELAI_")]:
            monkeypatch.delenv(key)
        monkeypatch.setenv("SENTINELAI_STATE_DIR", str(tmp_path))
        config = load_config(ROOT / "config.example.yaml", apply_overlay=False)
        assert config.source_path is not None

    def test_example_config_keeps_automatic_response_disabled(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        for key in [k for k in __import__("os").environ if k.startswith("SENTINELAI_")]:
            monkeypatch.delenv(key)
        monkeypatch.setenv("SENTINELAI_STATE_DIR", str(tmp_path))
        config = load_config(ROOT / "config.example.yaml", apply_overlay=False)
        assert config.response.enabled is False

    @pytest.mark.parametrize("label", list(_SECRET_PATTERNS))
    def test_example_config_has_no_real_looking_secret(self, label: str) -> None:
        match = _SECRET_PATTERNS[label].search(_text(ROOT / "config.example.yaml"))
        assert match is None, f"{label} found: {match.group(0) if match else ''}"

    def test_example_config_has_no_filled_in_secret_fields(self) -> None:
        pattern = re.compile(
            r"^\s*(api_key|telegram_token|slack_webhook|email_password)\s*:\s*[\"']?(\S+?)[\"']?\s*$",
            re.MULTILINE,
        )
        for match in pattern.finditer(_text(ROOT / "config.example.yaml")):
            assert match.group(2).strip("\"'") in {"", "CHANGE_ME"}, match.group(0)
