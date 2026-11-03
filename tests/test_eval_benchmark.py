"""Acceptance tests for the real, committed detection benchmark (``benchmarks/``)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

import sentinelai.detection.rules  # noqa: F401  (registers the built-in rules)
from sentinelai.cli.app import cli
from sentinelai.detection.base import available_rules
from sentinelai.detection.rules.authentication import SSHBruteForceRule
from sentinelai.evaluation.compare import Thresholds, compare_reports, load_baseline
from sentinelai.evaluation.manifest import verify_manifest
from sentinelai.evaluation.models import KIND_ATTACK, KIND_BENIGN, EvalReport
from sentinelai.evaluation.runner import load_scenarios, run_benchmark

ROOT = Path(__file__).resolve().parent.parent / "benchmarks"
SCENARIOS = ROOT / "scenarios"
BASELINE = ROOT / "baseline.json"

MIN_BENIGN_SCENARIOS = 20
BROKEN_SCENARIO = "r001_ssh_bruteforce"


def _break_ssh_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SSHBruteForceRule, "evaluate", lambda self, event, ctx: None)


@pytest.fixture(scope="module")
def report() -> EvalReport:
    return run_benchmark(SCENARIOS)


@pytest.fixture
def benchmark_copy(tmp_path: Path) -> Path:
    target = tmp_path / "benchmarks"
    shutil.copytree(ROOT, target)
    return target


def _first_log(root: Path, scenario: str = BROKEN_SCENARIO) -> Path:
    logs = sorted(p for p in (root / "scenarios" / scenario).iterdir() if p.suffix == ".log")
    assert logs, f"no log file in scenario {scenario}"
    return logs[0]


def _tamper_harmlessly(root: Path) -> Path:
    """Add an unlisted file to a scenario: changes the manifest, not the results."""
    notes = root / "scenarios" / BROKEN_SCENARIO / "NOTES.txt"
    notes.write_text("unlisted note\n", encoding="utf-8")
    return notes


class TestCoverage:
    def test_every_registered_rule_is_expected_by_an_attack_scenario(self) -> None:
        expected: set[str] = set()
        for scenario in load_scenarios(SCENARIOS):
            if scenario.label.kind == KIND_ATTACK:
                expected.update(scenario.label.expect_rules)
        missing = sorted(set(available_rules()) - expected)
        assert missing == []

    def test_real_report_has_no_uncovered_rules(self, report: EvalReport) -> None:
        assert report.summary["uncovered_rules"] == []

    def test_attack_scenario_names_are_distinct_and_match_directory(self) -> None:
        attacks = [s for s in load_scenarios(SCENARIOS) if s.label.kind == KIND_ATTACK]
        assert attacks
        names = [s.label.name for s in attacks]
        assert len(names) == len(set(names))
        assert all(s.label.name == s.directory.name for s in attacks)

    def test_benchmark_has_enough_benign_scenarios(self) -> None:
        benign = [s for s in load_scenarios(SCENARIOS) if s.label.kind == KIND_BENIGN]
        assert len(benign) >= MIN_BENIGN_SCENARIOS


class TestFrozenBenchmark:
    def test_committed_manifest_matches_scenarios(self) -> None:
        assert verify_manifest(ROOT) == []

    def test_modified_scenario_log_is_reported_as_modified(self, benchmark_copy: Path) -> None:
        log = _first_log(benchmark_copy)
        with log.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write("tampered line\n")
        problems = verify_manifest(benchmark_copy)
        rel = log.relative_to(benchmark_copy).as_posix()
        assert problems == [f"modified: {rel}"]

    def test_added_file_is_reported_as_added(self, benchmark_copy: Path) -> None:
        notes = _tamper_harmlessly(benchmark_copy)
        rel = notes.relative_to(benchmark_copy).as_posix()
        problems = verify_manifest(benchmark_copy)
        assert problems == [f"added: {rel}"]

    def test_deleted_file_is_reported_as_removed(self, benchmark_copy: Path) -> None:
        log = _first_log(benchmark_copy)
        rel = log.relative_to(benchmark_copy).as_posix()
        log.unlink()
        problems = verify_manifest(benchmark_copy)
        assert problems == [f"removed: {rel}"]


class TestBaselineGate:
    def test_all_scenarios_pass(self, report: EvalReport) -> None:
        failed = [s.name for s in report.scenarios if not s.passed]
        assert failed == []

    def test_no_regressions_against_committed_baseline(self, report: EvalReport) -> None:
        baseline = load_baseline(BASELINE)
        regressions = compare_reports(report.to_dict(), baseline, Thresholds())
        assert regressions == []


class TestDeterminism:
    def test_two_runs_produce_identical_reports(self, report: EvalReport) -> None:
        second = run_benchmark(SCENARIOS)
        assert report.to_dict(include_performance=False) == second.to_dict(
            include_performance=False
        )


class TestBrokenRuleIsCaught:
    @pytest.fixture
    def broken(self, monkeypatch: pytest.MonkeyPatch) -> EvalReport:
        _break_ssh_rule(monkeypatch)
        return run_benchmark(SCENARIOS)

    def test_bruteforce_scenario_fails_with_r001_missing(self, broken: EvalReport) -> None:
        result = next(s for s in broken.scenarios if s.name == BROKEN_SCENARIO)
        assert not result.passed
        assert "R001" in result.missing_rules

    def test_compare_reports_flags_recall_and_scenario_regressions(
        self, broken: EvalReport
    ) -> None:
        regressions = compare_reports(broken.to_dict(), load_baseline(BASELINE), Thresholds())
        pairs = {(r.kind, r.subject) for r in regressions}
        assert ("recall", "R001") in pairs
        assert any(r.kind == "scenario" for r in regressions)
        assert ("scenario", BROKEN_SCENARIO) in pairs


class TestCli:
    @staticmethod
    def _invoke(root: Path, *extra: str) -> Any:
        args = [
            "--no-plugins",
            "eval",
            "--benchmarks",
            str(root),
            "--baseline",
            str(root / "baseline.json"),
            *extra,
        ]
        return CliRunner().invoke(cli, args, catch_exceptions=False)

    def test_eval_on_committed_benchmark_exits_zero(self) -> None:
        result = self._invoke(ROOT)
        assert result.exit_code == 0

    def test_eval_with_broken_rule_exits_one(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _break_ssh_rule(monkeypatch)
        result = self._invoke(ROOT)
        assert result.exit_code == 1

    def test_eval_on_tampered_benchmark_fails_mentioning_manifest(
        self, benchmark_copy: Path
    ) -> None:
        _tamper_harmlessly(benchmark_copy)
        result = self._invoke(benchmark_copy)
        assert result.exit_code != 0
        output = (result.output + getattr(result, "stderr", "")).lower()
        assert "manifest" in output or "frozen" in output

    def test_update_manifest_accepts_tampered_benchmark(self, benchmark_copy: Path) -> None:
        _tamper_harmlessly(benchmark_copy)
        assert verify_manifest(benchmark_copy) != []
        result = self._invoke(benchmark_copy, "--update-manifest")
        assert result.exit_code == 0
        assert verify_manifest(benchmark_copy) == []


_BENIGN_LINE = (
    "2026-01-07T12:00:03+00:00 web01 sshd[1234]: "
    "Accepted password for alice from 203.0.113.9 port 40003 ssh2\n"
)


def _tiny_bench(root: Path, scenario_name: str) -> Path:
    """Create a one-scenario benign benchmark root with the given scenario name."""
    directory = root / "scenarios" / scenario_name
    directory.mkdir(parents=True)
    (directory / "auth.log").write_text(_BENIGN_LINE, encoding="utf-8")
    labels = {
        "name": scenario_name,
        "kind": "benign",
        "description": "markup test",
        "files": ["auth.log"],
    }
    (directory / "labels.yaml").write_text(yaml.safe_dump(labels), encoding="utf-8")
    return root


def _invoke_raw(*args: str) -> Any:
    return CliRunner().invoke(cli, ["--no-plugins", "eval", *args])


def _assert_clean_exit(result: Any) -> None:
    assert result.exception is None or isinstance(result.exception, SystemExit)
    text = result.output + getattr(result, "stderr", "")
    assert "Traceback" not in text
    assert "MarkupError" not in text


class TestCliHardening:
    @pytest.mark.parametrize("value", ["nan", "-1", "inf"])
    def test_invalid_max_recall_drop_fails_cleanly(self, value: str) -> None:
        result = _invoke_raw("--benchmarks", str(ROOT), "--max-recall-drop", value)
        assert result.exit_code != 0
        _assert_clean_exit(result)

    @pytest.mark.parametrize("value", ["nan", "-1"])
    def test_invalid_max_fp_increase_fails_cleanly(self, value: str) -> None:
        result = _invoke_raw("--benchmarks", str(ROOT), "--max-fp-increase", value)
        assert result.exit_code != 0
        _assert_clean_exit(result)

    def test_markup_in_scenario_name_does_not_raise_markup_error(self, tmp_path: Path) -> None:
        name = "ab[bold]cd"
        root = _tiny_bench(tmp_path / "bench", name)
        result = _invoke_raw("--benchmarks", str(root), "--update-manifest")
        assert result.exit_code in (0, 1)
        _assert_clean_exit(result)
        assert name in result.output

    def test_markup_closing_tag_in_manifest_problem_does_not_raise(
        self, tmp_path: Path
    ) -> None:
        root = _tiny_bench(tmp_path / "bench", "calm")
        assert _invoke_raw("--benchmarks", str(root), "--update-manifest").exit_code == 0
        (root / "scenarios" / "calm" / "ab[x].txt").write_text("x\n", encoding="utf-8")
        result = _invoke_raw("--benchmarks", str(root))
        assert result.exit_code != 0
        _assert_clean_exit(result)

    def test_failing_scenario_does_not_write_baseline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _break_ssh_rule(monkeypatch)
        target = tmp_path / "out" / "new_baseline.json"
        result = _invoke_raw("--benchmarks", str(ROOT), "--write-baseline", str(target))
        assert result.exit_code == 1
        assert not target.exists()
        _assert_clean_exit(result)

    def test_passing_run_writes_baseline_equal_to_committed(self, tmp_path: Path) -> None:
        target = tmp_path / "new_baseline.json"
        result = _invoke_raw("--benchmarks", str(ROOT), "--write-baseline", str(target))
        assert result.exit_code == 0
        written = json.loads(target.read_text(encoding="utf-8"))
        assert written == json.loads(BASELINE.read_text(encoding="utf-8"))

    def test_update_manifest_with_invalid_labels_leaves_manifest_unchanged(
        self, benchmark_copy: Path
    ) -> None:
        manifest = benchmark_copy / "MANIFEST.sha256"
        before = manifest.read_bytes()
        labels = benchmark_copy / "scenarios" / BROKEN_SCENARIO / "labels.yaml"
        labels.write_text("kind: weird\n", encoding="utf-8")
        result = _invoke_raw("--benchmarks", str(benchmark_copy), "--update-manifest")
        assert result.exit_code != 0
        assert manifest.read_bytes() == before
        _assert_clean_exit(result)

    def test_update_manifest_with_invalid_labels_does_not_create_manifest(
        self, tmp_path: Path
    ) -> None:
        root = _tiny_bench(tmp_path / "bench", "calm")
        (root / "scenarios" / "calm" / "labels.yaml").write_text("- bad\n", encoding="utf-8")
        result = _invoke_raw("--benchmarks", str(root), "--update-manifest")
        assert result.exit_code != 0
        assert not (root / "MANIFEST.sha256").exists()
        _assert_clean_exit(result)
