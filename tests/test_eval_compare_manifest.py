"""Tests for sentinelai.evaluation.compare and sentinelai.evaluation.manifest."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from sentinelai.core.exceptions import EvaluationError
from sentinelai.evaluation.compare import (
    Regression,
    Thresholds,
    compare_reports,
    load_baseline,
)
from sentinelai.evaluation.manifest import (
    MANIFEST_NAME,
    compute_manifest,
    read_manifest,
    verify_manifest,
    write_manifest,
)

# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------


def _report(
    *,
    recall: float | None = 1.0,
    rule_recalls: dict[str, float | None] | None = None,
    fp: float | None = 0.0,
    scenarios: dict[str, bool] | None = None,
    schema: int = 1,
    ai_used: object = None,
) -> dict[str, Any]:
    rule_recalls = {"R001": 1.0, "R002": 1.0} if rule_recalls is None else rule_recalls
    scenarios = {"s1": True, "s2": True} if scenarios is None else scenarios
    doc: dict[str, Any] = {
        "schema_version": schema,
        "summary": {"attack_recall": recall, "fp_per_1k_benign_events": fp},
        "rules": {rid: {"recall": r} for rid, r in rule_recalls.items()},
        "scenarios": [{"name": n, "passed": p} for n, p in scenarios.items()],
    }
    if ai_used is not None:
        doc["ai_used"] = ai_used
    return doc


def _kinds(regs: list[Regression]) -> list[str]:
    return [r.kind for r in regs]


class TestCompareReports:
    def test_identical_reports_have_no_regressions(self) -> None:
        report = _report()
        assert compare_reports(copy.deepcopy(report), report, Thresholds()) == []

    def test_improvement_is_not_a_regression(self) -> None:
        base = _report(recall=0.5, rule_recalls={"R001": 0.5}, fp=5.0)
        cur = _report(recall=1.0, rule_recalls={"R001": 1.0}, fp=1.0)
        assert compare_reports(cur, base, Thresholds()) == []

    def test_overall_recall_drop_beyond_threshold_is_regression(self) -> None:
        regs = compare_reports(
            _report(recall=0.8), _report(recall=1.0), Thresholds(max_recall_drop=0.1)
        )
        overall = [r for r in regs if r.kind == "recall" and r.subject == "overall"]
        assert len(overall) == 1
        assert "1.0000 -> 0.8000" in overall[0].message

    def test_overall_recall_drop_within_threshold_is_tolerated(self) -> None:
        regs = compare_reports(
            _report(recall=0.95), _report(recall=1.0), Thresholds(max_recall_drop=0.1)
        )
        assert [r for r in regs if r.subject == "overall"] == []

    def test_recall_drop_exactly_at_threshold_is_tolerated(self) -> None:
        regs = compare_reports(
            _report(recall=0.9), _report(recall=1.0), Thresholds(max_recall_drop=0.1)
        )
        assert [r for r in regs if r.subject == "overall"] == []

    def test_any_recall_drop_regresses_with_default_thresholds(self) -> None:
        regs = compare_reports(_report(recall=0.99), _report(recall=1.0), Thresholds())
        assert "recall" in _kinds(regs)

    def test_per_rule_recall_drop_is_regression_with_rule_subject(self) -> None:
        cur = _report(rule_recalls={"R001": 1.0, "R002": 0.5})
        regs = compare_reports(cur, _report(), Thresholds())
        assert [(r.kind, r.subject) for r in regs] == [("recall", "R002")]

    def test_rule_missing_from_current_is_recall_regression(self) -> None:
        cur = _report(rule_recalls={"R001": 1.0})
        regs = compare_reports(cur, _report(), Thresholds())
        assert [(r.kind, r.subject) for r in regs] == [("recall", "R002")]
        assert "n/a" in regs[0].message

    def test_rule_recall_none_in_current_is_regression(self) -> None:
        cur = _report(rule_recalls={"R001": None, "R002": 1.0})
        regs = compare_reports(cur, _report(), Thresholds())
        assert [(r.kind, r.subject) for r in regs] == [("recall", "R001")]

    def test_rule_recall_none_in_baseline_is_ignored(self) -> None:
        base = _report(recall=None, rule_recalls={"R001": None})
        cur = _report(recall=0.0, rule_recalls={"R001": 0.0})
        assert compare_reports(cur, base, Thresholds()) == []

    def test_new_rule_only_in_current_is_ignored(self) -> None:
        cur = _report(rule_recalls={"R001": 1.0, "R002": 1.0, "R003": 0.0})
        assert compare_reports(cur, _report(), Thresholds()) == []

    def test_fp_increase_beyond_threshold_is_regression(self) -> None:
        regs = compare_reports(_report(fp=3.0), _report(fp=1.0), Thresholds(max_fp_increase=1.0))
        assert [(r.kind, r.subject) for r in regs] == [("false_positives", "overall")]
        assert "1.0000 -> 3.0000" in regs[0].message

    def test_fp_increase_within_threshold_is_tolerated(self) -> None:
        regs = compare_reports(_report(fp=1.5), _report(fp=1.0), Thresholds(max_fp_increase=1.0))
        assert regs == []

    def test_any_fp_increase_regresses_with_default_thresholds(self) -> None:
        regs = compare_reports(_report(fp=0.5), _report(fp=0.0), Thresholds())
        assert _kinds(regs) == ["false_positives"]

    def test_fp_decrease_is_not_a_regression(self) -> None:
        assert compare_reports(_report(fp=0.0), _report(fp=4.0), Thresholds()) == []

    def test_fp_missing_in_current_is_regression(self) -> None:
        regs = compare_reports(_report(fp=None), _report(fp=1.0), Thresholds())
        assert _kinds(regs) == ["false_positives"]

    def test_fp_none_in_baseline_is_ignored(self) -> None:
        assert compare_reports(_report(fp=9.0), _report(fp=None), Thresholds()) == []

    def test_scenario_passed_in_baseline_now_failing_is_regression(self) -> None:
        cur = _report(scenarios={"s1": True, "s2": False})
        cur["scenarios"][1]["missing_rules"] = ["R001"]
        cur["scenarios"][1]["risk_ok"] = False
        regs = compare_reports(cur, _report(), Thresholds())
        assert [(r.kind, r.subject) for r in regs] == [("scenario", "s2")]
        assert "passed -> failed" in regs[0].message
        assert "missing_rules=['R001']" in regs[0].message
        assert "risk_ok=False" in regs[0].message

    def test_scenario_failing_in_both_is_not_a_regression(self) -> None:
        base = _report(scenarios={"s1": False})
        cur = _report(scenarios={"s1": False})
        assert compare_reports(cur, base, Thresholds()) == []

    def test_scenario_absent_from_current_is_scenario_missing(self) -> None:
        cur = _report(scenarios={"s1": True})
        regs = compare_reports(cur, _report(), Thresholds())
        assert [(r.kind, r.subject) for r in regs] == [("scenario_missing", "s2")]
        assert "baseline: passed" in regs[0].message

    def test_failing_baseline_scenario_absent_from_current_is_scenario_missing(self) -> None:
        base = _report(scenarios={"s1": True, "s2": False})
        cur = _report(scenarios={"s1": True})
        regs = compare_reports(cur, base, Thresholds())
        assert [(r.kind, r.subject) for r in regs] == [("scenario_missing", "s2")]
        assert "baseline: failed" in regs[0].message

    def test_schema_mismatch_is_reported(self) -> None:
        regs = compare_reports(_report(schema=2), _report(schema=1), Thresholds())
        assert _kinds(regs) == ["schema"]
        assert "1 -> 2" in regs[0].message

    def test_empty_documents_do_not_crash(self) -> None:
        assert compare_reports({}, {}, Thresholds()) == []

    def test_non_dict_sections_are_treated_as_empty(self) -> None:
        base = _report()
        cur: dict[str, Any] = {
            "schema_version": 1,
            "summary": "oops",
            "rules": [],
            "scenarios": "nope",
        }
        regs = compare_reports(cur, base, Thresholds())
        kinds = _kinds(regs)
        assert "recall" in kinds
        assert "false_positives" in kinds
        assert kinds.count("scenario_missing") == 2

    def test_bool_metric_values_are_not_treated_as_numbers(self) -> None:
        base = _report()
        base["summary"]["attack_recall"] = True
        assert compare_reports(_report(recall=0.0), base, Thresholds()) == []

    def test_regression_order_is_stable(self) -> None:
        base = _report()
        cur = _report(
            schema=2,
            recall=0.5,
            rule_recalls={"R001": 0.5, "R002": 0.5},
            fp=9.0,
            scenarios={"s1": False},
        )
        kinds = _kinds(compare_reports(cur, base, Thresholds()))
        assert kinds == [
            "schema",
            "recall",
            "recall",
            "recall",
            "false_positives",
            "scenario",
            "scenario_missing",
        ]
        assert kinds == _kinds(compare_reports(cur, base, Thresholds()))

    @pytest.mark.parametrize(("old", "new"), [(False, True), (True, False)])
    def test_ai_used_change_is_regression(self, old: bool, new: bool) -> None:
        regs = compare_reports(_report(ai_used=new), _report(ai_used=old), Thresholds())
        assert [(r.kind, r.subject) for r in regs] == [("ai_used", "ai_used")]
        assert f"{old} -> {new}" in regs[0].message

    @pytest.mark.parametrize("value", [True, False])
    def test_ai_used_equal_is_not_regression(self, value: bool) -> None:
        regs = compare_reports(_report(ai_used=value), _report(ai_used=value), Thresholds())
        assert regs == []

    @pytest.mark.parametrize(
        ("old", "new"),
        [
            (None, True),
            (False, None),
            (None, None),
            ("yes", False),
            (True, "no"),
            (0, 1),
            (1, 0),
        ],
    )
    def test_ai_used_missing_or_non_bool_is_ignored(self, old: object, new: object) -> None:
        regs = compare_reports(_report(ai_used=new), _report(ai_used=old), Thresholds())
        assert regs == []

    def test_ai_used_regression_follows_schema_regression(self) -> None:
        cur = _report(schema=2, ai_used=True)
        regs = compare_reports(cur, _report(schema=1, ai_used=False), Thresholds())
        assert _kinds(regs) == ["schema", "ai_used"]

    def test_performance_section_is_ignored(self) -> None:
        base = _report()
        base["performance"] = {"seconds": 1.0}
        cur = _report()
        cur["performance"] = {"seconds": 999.0}
        assert compare_reports(cur, base, Thresholds()) == []


class TestThresholds:
    def test_defaults_are_zero(self) -> None:
        t = Thresholds()
        assert (t.max_recall_drop, t.max_fp_increase) == (0.0, 0.0)

    @pytest.mark.parametrize("value", [0, 0.0, 0.1, 1, 5.5])
    @pytest.mark.parametrize("field", ["max_recall_drop", "max_fp_increase"])
    def test_zero_and_positive_finite_are_accepted(self, field: str, value: float) -> None:
        assert getattr(Thresholds(**{field: value}), field) == value

    @pytest.mark.parametrize(
        "value", [float("nan"), float("inf"), float("-inf"), -1.0, -0.001, -1]
    )
    @pytest.mark.parametrize("field", ["max_recall_drop", "max_fp_increase"])
    def test_nan_inf_and_negative_are_rejected(self, field: str, value: float) -> None:
        with pytest.raises(EvaluationError, match=field):
            Thresholds(**{field: value})

    @pytest.mark.parametrize("field", ["max_recall_drop", "max_fp_increase"])
    def test_bool_and_non_numeric_are_rejected(self, field: str) -> None:
        with pytest.raises(EvaluationError, match=field):
            Thresholds(**{field: True})
        with pytest.raises(EvaluationError, match=field):
            Thresholds(**{field: "0.1"})


def _valid_baseline() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "summary": {"attack_recall": 1.0},
        "rules": {"R001": {"recall": 1.0}},
        "scenarios": [{"name": "s1", "passed": True}],
    }


def _write_json(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class TestLoadBaseline:
    def test_valid_object_is_returned(self, tmp_path: Path) -> None:
        data = _valid_baseline()
        path = _write_json(tmp_path / "baseline.json", data)
        assert load_baseline(path) == data

    @pytest.mark.parametrize("key", ["schema_version", "summary", "rules", "scenarios"])
    def test_missing_required_key_is_rejected_naming_the_key(
        self, tmp_path: Path, key: str
    ) -> None:
        data = _valid_baseline()
        del data[key]
        path = _write_json(tmp_path / "baseline.json", data)
        with pytest.raises(EvaluationError, match=f"missing required key '{key}'"):
            load_baseline(path)

    @pytest.mark.parametrize(
        ("key", "bad"),
        [
            ("schema_version", "1"),
            ("schema_version", 1.5),
            ("schema_version", True),
            ("schema_version", None),
            ("summary", []),
            ("summary", None),
            ("rules", []),
            ("rules", "x"),
            ("scenarios", {}),
            ("scenarios", "x"),
            ("scenarios", None),
        ],
    )
    def test_wrong_typed_key_is_rejected_naming_the_key(
        self, tmp_path: Path, key: str, bad: object
    ) -> None:
        data = _valid_baseline()
        data[key] = bad
        path = _write_json(tmp_path / "baseline.json", data)
        with pytest.raises(EvaluationError, match=f"invalid '{key}'"):
            load_baseline(path)

    def test_schema_version_alone_is_rejected(self, tmp_path: Path) -> None:
        path = _write_json(tmp_path / "baseline.json", {"schema_version": 1})
        with pytest.raises(EvaluationError, match="missing required key"):
            load_baseline(path)

    def test_empty_object_is_rejected(self, tmp_path: Path) -> None:
        path = _write_json(tmp_path / "baseline.json", {})
        with pytest.raises(EvaluationError, match="schema_version"):
            load_baseline(path)

    def test_empty_but_correctly_typed_sections_are_accepted(self, tmp_path: Path) -> None:
        data = {"schema_version": 1, "summary": {}, "rules": {}, "scenarios": []}
        assert load_baseline(_write_json(tmp_path / "b.json", data)) == data

    def test_missing_file_raises_evaluation_error(self, tmp_path: Path) -> None:
        with pytest.raises(EvaluationError, match="not found"):
            load_baseline(tmp_path / "nope.json")

    def test_invalid_json_raises_evaluation_error(self, tmp_path: Path) -> None:
        path = tmp_path / "baseline.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(EvaluationError, match="not valid JSON"):
            load_baseline(path)

    def test_non_object_json_raises_evaluation_error(self, tmp_path: Path) -> None:
        path = tmp_path / "baseline.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(EvaluationError, match="JSON object"):
            load_baseline(path)

    def test_empty_file_raises_evaluation_error(self, tmp_path: Path) -> None:
        path = tmp_path / "baseline.json"
        path.write_text("", encoding="utf-8")
        with pytest.raises(EvaluationError):
            load_baseline(path)

    def test_non_utf8_file_raises_evaluation_error(self, tmp_path: Path) -> None:
        path = tmp_path / "baseline.json"
        path.write_bytes(b"\xff\xfe\x00\x80")
        with pytest.raises(EvaluationError):
            load_baseline(path)


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------


def _make_bench(root: Path) -> Path:
    """Create a tiny benchmark tree with two scenario files."""
    (root / "scenarios" / "alpha").mkdir(parents=True)
    (root / "scenarios" / "beta").mkdir(parents=True)
    (root / "scenarios" / "alpha" / "auth.log").write_bytes(b"line one\nline two\n")
    (root / "scenarios" / "beta" / "labels.yaml").write_bytes(b"name: beta\n")
    return root


class TestManifestRoundtrip:
    def test_compute_manifest_hashes_files_with_posix_relative_keys(self, tmp_path: Path) -> None:
        root = _make_bench(tmp_path)
        entries = compute_manifest(root)
        assert list(entries) == ["scenarios/alpha/auth.log", "scenarios/beta/labels.yaml"]
        assert entries["scenarios/alpha/auth.log"] == hashlib.sha256(
            b"line one\nline two\n"
        ).hexdigest()

    def test_write_then_read_roundtrip(self, tmp_path: Path) -> None:
        root = _make_bench(tmp_path)
        target = write_manifest(root)
        assert target == root / MANIFEST_NAME
        assert read_manifest(root) == compute_manifest(root)

    def test_manifest_file_uses_lf_and_two_space_separator(self, tmp_path: Path) -> None:
        root = _make_bench(tmp_path)
        raw = write_manifest(root).read_bytes()
        assert b"\r" not in raw
        first = raw.decode("utf-8").splitlines()[0]
        digest, sep, rel = first.partition("  ")
        assert len(digest) == 64
        assert sep == "  "
        assert rel == "scenarios/alpha/auth.log"

    def test_verify_intact_tree_returns_no_problems(self, tmp_path: Path) -> None:
        root = _make_bench(tmp_path)
        write_manifest(root)
        assert verify_manifest(root) == []

    def test_empty_scenarios_dir_gives_empty_manifest(self, tmp_path: Path) -> None:
        (tmp_path / "scenarios").mkdir()
        write_manifest(tmp_path)
        assert read_manifest(tmp_path) == {}
        assert verify_manifest(tmp_path) == []


class TestManifestLineEndings:
    def test_crlf_and_lf_content_hash_identically(self, tmp_path: Path) -> None:
        lf_root = tmp_path / "lf"
        crlf_root = tmp_path / "crlf"
        (lf_root / "scenarios").mkdir(parents=True)
        (crlf_root / "scenarios").mkdir(parents=True)
        (lf_root / "scenarios" / "x.log").write_bytes(b"a\nb\nc\n")
        (crlf_root / "scenarios" / "x.log").write_bytes(b"a\r\nb\r\nc\r\n")
        assert compute_manifest(lf_root) == compute_manifest(crlf_root)

    def test_converting_to_crlf_after_manifest_still_verifies(self, tmp_path: Path) -> None:
        root = _make_bench(tmp_path)
        write_manifest(root)
        log = root / "scenarios" / "alpha" / "auth.log"
        log.write_bytes(log.read_bytes().replace(b"\n", b"\r\n"))
        assert verify_manifest(root) == []


class TestManifestVerification:
    def test_modified_file_is_reported(self, tmp_path: Path) -> None:
        root = _make_bench(tmp_path)
        write_manifest(root)
        (root / "scenarios" / "alpha" / "auth.log").write_bytes(b"tampered\n")
        assert verify_manifest(root) == ["modified: scenarios/alpha/auth.log"]

    def test_added_file_is_reported(self, tmp_path: Path) -> None:
        root = _make_bench(tmp_path)
        write_manifest(root)
        (root / "scenarios" / "alpha" / "extra.log").write_bytes(b"new\n")
        assert verify_manifest(root) == ["added: scenarios/alpha/extra.log"]

    def test_removed_file_is_reported(self, tmp_path: Path) -> None:
        root = _make_bench(tmp_path)
        write_manifest(root)
        (root / "scenarios" / "beta" / "labels.yaml").unlink()
        assert verify_manifest(root) == ["removed: scenarios/beta/labels.yaml"]

    def test_multiple_problems_are_sorted(self, tmp_path: Path) -> None:
        root = _make_bench(tmp_path)
        write_manifest(root)
        (root / "scenarios" / "alpha" / "auth.log").write_bytes(b"tampered\n")
        (root / "scenarios" / "beta" / "labels.yaml").unlink()
        (root / "scenarios" / "beta" / "new.log").write_bytes(b"x\n")
        problems = verify_manifest(root)
        assert problems == sorted(problems)
        assert problems == [
            "added: scenarios/beta/new.log",
            "modified: scenarios/alpha/auth.log",
            "removed: scenarios/beta/labels.yaml",
        ]


class TestManifestErrors:
    def test_missing_scenarios_dir_raises(self, tmp_path: Path) -> None:
        with pytest.raises(EvaluationError, match="scenarios directory not found"):
            compute_manifest(tmp_path)

    def test_write_manifest_without_scenarios_dir_raises(self, tmp_path: Path) -> None:
        with pytest.raises(EvaluationError):
            write_manifest(tmp_path)

    def test_missing_manifest_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(EvaluationError, match="manifest not found"):
            read_manifest(tmp_path)

    @pytest.mark.parametrize(
        "line",
        [
            "not-a-digest  scenarios/x.log",
            "abc123  scenarios/x.log",
            "a" * 64 + " scenarios/x.log",  # single space separator
            "a" * 64 + "  ",  # empty path
            "A" * 64 + "  scenarios/x.log",  # uppercase hex rejected
            "a" * 64 + "   scenarios/x.log",  # path with leading whitespace
            "just some words",
        ],
    )
    def test_malformed_manifest_line_raises(self, tmp_path: Path, line: str) -> None:
        (tmp_path / MANIFEST_NAME).write_text(line + "\n", encoding="utf-8")
        with pytest.raises(EvaluationError, match="Malformed manifest line 1"):
            read_manifest(tmp_path)

    def test_malformed_line_number_is_reported(self, tmp_path: Path) -> None:
        good = "a" * 64 + "  scenarios/x.log"
        (tmp_path / MANIFEST_NAME).write_text(good + "\nbroken\n", encoding="utf-8")
        with pytest.raises(EvaluationError, match="line 2"):
            read_manifest(tmp_path)

    def test_duplicate_entry_raises(self, tmp_path: Path) -> None:
        line = "a" * 64 + "  scenarios/x.log"
        (tmp_path / MANIFEST_NAME).write_text(f"{line}\n{line}\n", encoding="utf-8")
        with pytest.raises(EvaluationError, match="Duplicate"):
            read_manifest(tmp_path)

    def test_blank_lines_are_ignored(self, tmp_path: Path) -> None:
        line = "a" * 64 + "  scenarios/x.log"
        (tmp_path / MANIFEST_NAME).write_text(f"\n{line}\n\n", encoding="utf-8")
        assert read_manifest(tmp_path) == {"scenarios/x.log": "a" * 64}

    def test_non_utf8_manifest_raises(self, tmp_path: Path) -> None:
        (tmp_path / MANIFEST_NAME).write_bytes(b"\xff\xfe\x80")
        with pytest.raises(EvaluationError):
            read_manifest(tmp_path)

    def test_symlinked_file_is_rejected(self, tmp_path: Path) -> None:
        root = _make_bench(tmp_path)
        link = root / "scenarios" / "alpha" / "link.log"
        try:
            link.symlink_to(root / "scenarios" / "alpha" / "auth.log")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks cannot be created on this system")
        with pytest.raises(EvaluationError, match="Symlinks are not allowed"):
            compute_manifest(root)

    def test_symlinked_directory_is_rejected(self, tmp_path: Path) -> None:
        root = _make_bench(tmp_path)
        link = root / "scenarios" / "gamma"
        try:
            link.symlink_to(root / "scenarios" / "alpha", target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks cannot be created on this system")
        with pytest.raises(EvaluationError, match="Symlinks are not allowed"):
            compute_manifest(root)
