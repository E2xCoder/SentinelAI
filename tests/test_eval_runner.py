"""Tests for sentinelai.evaluation.runner (scenario loading and execution)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinelai.cli.common import fail
from sentinelai.core.exceptions import EvaluationError
from sentinelai.core.pipeline import AnalysisPipeline
from sentinelai.evaluation.runner import load_scenarios, run_scenario

LOG_NAME = "auth.log"


def _failed_line(second: int) -> str:
    return (
        f"2026-01-07T12:00:{second:02d}+00:00 web01 sshd[1234]: "
        f"Failed password for root from 203.0.113.9 port {40000 + second} ssh2"
    )


def _write_scenario(
    root: Path,
    dirname: str = "sc",
    *,
    log_lines: list[str] | None = None,
    labels: dict[str, Any] | None = None,
    **overrides: Any,
) -> Path:
    """Create ``root/dirname`` with a log file and a valid attack labels.yaml."""
    directory = root / dirname
    directory.mkdir(parents=True)
    lines = [_failed_line(1)] if log_lines is None else log_lines
    (directory / LOG_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")
    data: dict[str, Any] = (
        {
            "name": dirname,
            "kind": "attack",
            "description": "test scenario",
            "files": [LOG_NAME],
            "expect": {"rules": ["R001"]},
        }
        if labels is None
        else dict(labels)
    )
    data.update(overrides)
    data = {k: v for k, v in data.items() if v is not None}
    (directory / "labels.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return directory


class TestLoadScenariosHappyPath:
    def test_valid_attack_scenario_is_loaded(self, tmp_path: Path) -> None:
        expect = {"rules": ["R001", "R001"], "min_risk_level": "low"}
        _write_scenario(tmp_path, "brute", expect=expect)
        scenarios = load_scenarios(tmp_path)
        assert len(scenarios) == 1
        label = scenarios[0].label
        assert label.name == "brute"
        assert label.kind == "attack"
        assert label.description == "test scenario"
        assert label.files == (LOG_NAME,)
        assert label.expect_rules == ("R001",)
        assert label.min_risk_level == "low"
        assert label.forbid_rules == ()
        assert scenarios[0].directory == tmp_path / "brute"

    def test_valid_benign_scenario_is_loaded(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, "calm", kind="benign", expect=None)
        label = load_scenarios(tmp_path)[0].label
        assert label.kind == "benign"
        assert label.expect_rules == ()

    def test_scenarios_are_sorted_by_name(self, tmp_path: Path) -> None:
        for name in ("zeta", "alpha", "mid"):
            _write_scenario(tmp_path, name)
        assert [s.label.name for s in load_scenarios(tmp_path)] == ["alpha", "mid", "zeta"]

    def test_directories_without_labels_are_ignored(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, "real")
        (tmp_path / "stray").mkdir()
        assert [s.label.name for s in load_scenarios(tmp_path)] == ["real"]

    def test_ai_rule_id_is_accepted_in_forbid(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, "sc", forbid={"rules": ["AI001"]})
        assert load_scenarios(tmp_path)[0].label.forbid_rules == ("AI001",)

    def test_empty_root_raises(self, tmp_path: Path) -> None:
        with pytest.raises(EvaluationError, match="No scenarios"):
            load_scenarios(tmp_path)

    def test_missing_root_raises(self, tmp_path: Path) -> None:
        with pytest.raises(EvaluationError, match="not found"):
            load_scenarios(tmp_path / "does-not-exist")


class TestLoadScenariosValidation:
    def test_unknown_top_level_key_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, bogus="x")
        with pytest.raises(EvaluationError, match="unknown top-level keys: bogus"):
            load_scenarios(tmp_path)

    def test_unknown_expect_key_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, expect={"rules": ["R001"], "extra": 1})
        with pytest.raises(EvaluationError, match="unknown keys in 'expect': extra"):
            load_scenarios(tmp_path)

    def test_unknown_forbid_key_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, forbid={"nope": []})
        with pytest.raises(EvaluationError, match="unknown keys in 'forbid'"):
            load_scenarios(tmp_path)

    def test_non_mapping_expect_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, expect=["R001"])
        with pytest.raises(EvaluationError, match="'expect' must be a mapping"):
            load_scenarios(tmp_path)

    def test_bad_kind_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, kind="weird")
        with pytest.raises(EvaluationError, match="kind must be one of"):
            load_scenarios(tmp_path)

    def test_name_not_matching_directory_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, "sc", name="other")
        with pytest.raises(EvaluationError, match="must equal the directory name"):
            load_scenarios(tmp_path)

    def test_non_string_description_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, description=["a"])
        with pytest.raises(EvaluationError, match="'description' must be a string"):
            load_scenarios(tmp_path)

    def test_benign_with_expect_rules_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, kind="benign")
        with pytest.raises(EvaluationError, match="benign scenarios must not have expect.rules"):
            load_scenarios(tmp_path)

    def test_attack_without_rules_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, expect=None)
        with pytest.raises(EvaluationError, match="attack scenarios require"):
            load_scenarios(tmp_path)

    def test_attack_with_empty_rules_list_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, expect={"rules": []})
        with pytest.raises(EvaluationError, match="attack scenarios require"):
            load_scenarios(tmp_path)

    def test_unregistered_expect_rule_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, expect={"rules": ["R999"]})
        with pytest.raises(EvaluationError, match="unknown rule 'R999'"):
            load_scenarios(tmp_path)

    def test_unregistered_forbid_rule_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, forbid={"rules": ["R999"]})
        with pytest.raises(EvaluationError, match="unknown rule 'R999'"):
            load_scenarios(tmp_path)

    def test_non_string_rule_entry_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, expect={"rules": [1]})
        with pytest.raises(EvaluationError, match="list of non-empty strings"):
            load_scenarios(tmp_path)

    def test_bad_min_risk_level_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, expect={"rules": ["R001"], "min_risk_level": "extreme"})
        with pytest.raises(EvaluationError, match="min_risk_level must be one of"):
            load_scenarios(tmp_path)

    def test_benign_with_min_risk_level_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, kind="benign", expect={"min_risk_level": "low"})
        with pytest.raises(EvaluationError, match="must not set expect.min_risk_level"):
            load_scenarios(tmp_path)

    def test_missing_file_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, files=["ghost.log"])
        with pytest.raises(EvaluationError, match="'ghost.log' does not exist"):
            load_scenarios(tmp_path)

    def test_empty_files_list_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, files=[])
        with pytest.raises(EvaluationError, match="non-empty list"):
            load_scenarios(tmp_path)

    def test_missing_files_key_is_rejected(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, files=None)
        with pytest.raises(EvaluationError, match="non-empty list"):
            load_scenarios(tmp_path)

    def test_parent_traversal_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "secret.log").write_text("x\n", encoding="utf-8")
        _write_scenario(tmp_path, "sc", files=["../secret.log"])
        with pytest.raises(EvaluationError, match="relative path inside the scenario"):
            load_scenarios(tmp_path)

    def test_absolute_path_is_rejected(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside.log"
        outside.write_text("x\n", encoding="utf-8")
        _write_scenario(tmp_path / "root", "sc", files=[str(outside)])
        with pytest.raises(EvaluationError, match="relative path inside the scenario"):
            load_scenarios(tmp_path / "root")

    def test_labels_not_a_mapping_is_rejected(self, tmp_path: Path) -> None:
        directory = _write_scenario(tmp_path)
        (directory / "labels.yaml").write_text("- just\n- a list\n", encoding="utf-8")
        with pytest.raises(EvaluationError, match="must contain a mapping"):
            load_scenarios(tmp_path)

    def test_invalid_yaml_is_rejected(self, tmp_path: Path) -> None:
        directory = _write_scenario(tmp_path)
        (directory / "labels.yaml").write_text("name: [unclosed\n", encoding="utf-8")
        with pytest.raises(EvaluationError, match="cannot read labels.yaml"):
            load_scenarios(tmp_path)

    def test_error_message_names_the_scenario(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path, "culprit", kind="weird")
        with pytest.raises(EvaluationError, match="'culprit'"):
            load_scenarios(tmp_path)


class TestRunScenario:
    def test_attack_scenario_fires_expected_rule_and_passes(self, tmp_path: Path) -> None:
        lines = [_failed_line(i) for i in range(6)]
        _write_scenario(tmp_path / "bench", "brute", log_lines=lines)
        scenario = load_scenarios(tmp_path / "bench")[0]

        result, ai_used = run_scenario(scenario, tmp_path / "state")

        assert isinstance(ai_used, bool)
        assert result.name == "brute"
        assert result.kind == "attack"
        assert result.events == 6
        assert "R001" in result.fired_rules
        assert result.expected_rules == ["R001"]
        assert result.missing_rules == []
        assert result.unexpected_rules == []
        assert result.risk_ok is True
        assert result.passed is True
        assert any(a.rule_id == "R001" for a in result.alerts)

    def test_attack_scenario_without_enough_failures_reports_missing_rule(
        self, tmp_path: Path
    ) -> None:
        _write_scenario(tmp_path / "bench", "weak", log_lines=[_failed_line(1)])
        scenario = load_scenarios(tmp_path / "bench")[0]

        result, _ = run_scenario(scenario, tmp_path / "state")

        assert result.missing_rules == ["R001"]
        assert "R001" not in result.fired_rules
        assert result.passed is False

    def test_unreachable_min_risk_level_fails_risk_check(self, tmp_path: Path) -> None:
        lines = [_failed_line(i) for i in range(6)]
        _write_scenario(
            tmp_path / "bench",
            "brute",
            log_lines=lines,
            expect={"rules": ["R001"]},
        )
        scenario = load_scenarios(tmp_path / "bench")[0]
        baseline, _ = run_scenario(scenario, tmp_path / "state_a")
        top = max(
            (a for a in baseline.alerts if a.rule_id == "R001"),
            key=lambda a: a.risk_score,
        )
        if top.risk_level == "critical":
            pytest.skip("alert already at the highest level; cannot test an unreachable level")

        levels = ["informational", "low", "medium", "high", "critical"]
        higher = levels[levels.index(top.risk_level) + 1]
        _write_scenario(
            tmp_path / "bench2",
            "brute",
            log_lines=lines,
            expect={"rules": ["R001"], "min_risk_level": higher},
        )
        result, _ = run_scenario(load_scenarios(tmp_path / "bench2")[0], tmp_path / "state_b")
        assert result.missing_rules == []
        assert result.risk_ok is False
        assert result.passed is False

    def test_benign_scenario_with_no_alerts_passes(self, tmp_path: Path) -> None:
        lines = [
            _failed_line(1).replace("root", "alice"),
            _failed_line(2).replace("root", "alice"),
            "2026-01-07T12:00:03+00:00 web01 sshd[1234]: "
            "Accepted password for alice from 203.0.113.9 port 40003 ssh2",
        ]
        _write_scenario(
            tmp_path / "bench", "calm", log_lines=lines, kind="benign", expect=None
        )
        scenario = load_scenarios(tmp_path / "bench")[0]

        result, _ = run_scenario(scenario, tmp_path / "state")

        assert result.kind == "benign"
        assert result.events == 3
        assert result.alerts == []
        assert result.fired_rules == []
        assert result.missing_rules == []
        assert result.unexpected_rules == []
        assert result.passed is True

    def test_benign_scenario_marks_every_fired_rule_unexpected(self, tmp_path: Path) -> None:
        lines = [_failed_line(i) for i in range(6)]
        _write_scenario(
            tmp_path / "bench", "noisy", log_lines=lines, kind="benign", expect=None
        )
        scenario = load_scenarios(tmp_path / "bench")[0]

        result, _ = run_scenario(scenario, tmp_path / "state")

        assert "R001" in result.unexpected_rules
        assert result.unexpected_rules == result.fired_rules
        assert result.passed is False

    def test_state_is_written_under_given_state_root_only(self, tmp_path: Path) -> None:
        _write_scenario(tmp_path / "bench", "brute")
        scenario = load_scenarios(tmp_path / "bench")[0]
        state_root = tmp_path / "state"

        run_scenario(scenario, state_root)

        assert (state_root / "brute").is_dir()

    def test_forbidden_rule_that_fires_in_attack_is_unexpected(self, tmp_path: Path) -> None:
        lines = [_failed_line(i) for i in range(6)]
        _write_scenario(
            tmp_path / "bench",
            "brute",
            log_lines=lines,
            expect={"rules": ["R001"]},
            forbid={"rules": ["R001"]},
        )
        scenario = load_scenarios(tmp_path / "bench")[0]

        result, _ = run_scenario(scenario, tmp_path / "state")

        assert result.unexpected_rules == ["R001"]
        assert result.passed is False

    def test_rerun_gives_identical_result(self, tmp_path: Path) -> None:
        lines = [_failed_line(i) for i in range(6)]
        _write_scenario(tmp_path / "bench", "brute", log_lines=lines)
        scenario = load_scenarios(tmp_path / "bench")[0]

        first, _ = run_scenario(scenario, tmp_path / "state_a")
        second, _ = run_scenario(scenario, tmp_path / "state_b")

        assert first.to_dict() == second.to_dict()

    def test_pipeline_is_closed_after_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[int] = []
        real_close = AnalysisPipeline.close

        def spy(self: AnalysisPipeline) -> None:
            calls.append(1)
            real_close(self)

        monkeypatch.setattr(AnalysisPipeline, "close", spy)
        _write_scenario(tmp_path / "bench", "brute")
        run_scenario(load_scenarios(tmp_path / "bench")[0], tmp_path / "state")
        assert calls == [1]

    def test_failing_close_does_not_mask_result(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(self: AnalysisPipeline) -> None:
            raise RuntimeError("close exploded")

        monkeypatch.setattr(AnalysisPipeline, "close", boom)
        lines = [_failed_line(i) for i in range(6)]
        _write_scenario(tmp_path / "bench", "brute", log_lines=lines)
        scenario = load_scenarios(tmp_path / "bench")[0]

        result, ai_used = run_scenario(scenario, tmp_path / "state")

        assert isinstance(ai_used, bool)
        assert result.name == "brute"
        assert "R001" in result.fired_rules
        assert result.passed is True


class TestFailEscapesMarkup:
    def test_markup_like_text_in_error_does_not_raise_markup_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as info:
            fail(EvaluationError("bad [/x] path"))
        assert info.value.code == 10
        captured = capsys.readouterr()
        assert "MarkupError" not in captured.out + captured.err
