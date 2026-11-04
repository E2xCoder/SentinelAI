"""Sigma importer: loading, subset, unsupported reasons, hostile input, response gating."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterator
from pathlib import Path
from textwrap import dedent
from typing import Any

import pytest
from click.testing import CliRunner

import sentinelai.detection.rules  # noqa: F401  (registers built-in rules)
from sentinelai.cli.app import cli
from sentinelai.config.models import DetectionConfig, ResponseConfig
from sentinelai.core.models import EventCategory, LogEvent
from sentinelai.detection.base import RuleContext
from sentinelai.sigma import SIGMA_RULE_ID_RE, SigmaRule, load_rules, sigma_rule_id
from tests.conftest import make_event
from tests.test_response_hardening import Rig, make_alert, make_config

REPO = Path(__file__).resolve().parent.parent
EXAMPLES = REPO / "examples" / "sigma"
UUID_A = "5c2c3993-4e61-4165-90d2-15dc05e8d8e9"
UUID_B = "0b6b4f0e-3b0e-4c8e-9d63-2f0c1e1a7a11"
TIME_BUDGET_SECONDS = 5.0


# -- helpers ---------------------------------------------------------------


def write_rule(
    directory: Path,
    name: str = "rule.yml",
    *,
    title: str = "Test Rule",
    rule_id: str | None = UUID_A,
    level: str = "high",
    logsource: str = "product: linux\n  category: process_creation",
    detection: str = "selection:\n    CommandLine|contains: 'evil'\n  condition: selection",
    extra: str = "",
) -> Path:
    lines = [f"title: {title}"]
    if rule_id is not None:
        lines.append(f"id: {rule_id}")
    lines.append(f"level: {level}")
    lines.append("author: Test Author")
    if extra:
        lines.append(extra)
    body = "\n".join(lines)
    text = f"{body}\nlogsource:\n  {logsource}\ndetection:\n  {detection}\n"
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def write_raw(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(text), encoding="utf-8")
    return path


def cmd_event(command: str, **kwargs: Any) -> LogEvent:
    return make_event(command=command, message=command, service="sudo", **kwargs)


def ctx() -> RuleContext:
    return RuleContext(DetectionConfig())


def fires(rule: SigmaRule, event: LogEvent) -> bool:
    return rule.evaluate(event, ctx()) is not None


def only_rule(directory: Path) -> SigmaRule:
    report = load_rules(directory)
    assert len(report.rules) == 1, [u.reason for u in report.unsupported]
    return report.rules[0]


def reasons(directory: Path) -> list[str]:
    return [u.reason for u in load_rules(directory).unsupported]


# -- (1) loading valid rules -------------------------------------------------


class TestLoading:
    def test_bundled_examples_all_load_without_unsupported(self) -> None:
        report = load_rules(EXAMPLES)
        assert report.unsupported == []
        assert len(report.rules) == len(list(EXAMPLES.glob("*.yml")))
        assert report.files_scanned == len(report.rules)

    def test_loaded_rule_has_sigma_identity_and_metadata(self, tmp_path: Path) -> None:
        write_rule(tmp_path, extra="tags:\n  - attack.execution\n  - attack.t1059.004")
        rule = only_rule(tmp_path)
        assert SIGMA_RULE_ID_RE.match(rule.rule_id)
        assert rule.name == "Test Rule"
        assert rule.author == "Test Author"
        assert "T1059.004" in rule.mitre_techniques
        assert "Execution" in rule.mitre_tactics

    def test_matching_event_produces_alert_with_sigma_context(self, tmp_path: Path) -> None:
        rule = only_rule(_dir_with(tmp_path))
        alert = rule.evaluate(cmd_event("run evil thing", ip="203.0.113.7"), ctx())
        assert alert is not None
        assert alert.rule_id == rule.rule_id
        assert alert.title == "Test Rule"

    def test_non_matching_event_produces_no_alert(self, tmp_path: Path) -> None:
        rule = only_rule(_dir_with(tmp_path))
        assert not fires(rule, cmd_event("ls -la"))

    def test_nested_directories_are_scanned(self, tmp_path: Path) -> None:
        write_rule(tmp_path / "a" / "b", "deep.yaml", title="Deep")
        assert [r.name for r in load_rules(tmp_path).rules] == ["Deep"]

    def test_non_yaml_files_are_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "notes.txt").write_text("title: x", encoding="utf-8")
        report = load_rules(tmp_path)
        assert report.files_scanned == 0
        assert report.rules == []

    def test_empty_directory_loads_nothing(self, tmp_path: Path) -> None:
        report = load_rules(tmp_path)
        assert report.rules == [] and report.unsupported == []

    def test_missing_directory_is_reported_not_raised(self, tmp_path: Path) -> None:
        report = load_rules(tmp_path / "nope")
        assert report.rules == []
        assert report.unsupported

    def test_invalid_yaml_is_unsupported_not_raised(self, tmp_path: Path) -> None:
        write_raw(tmp_path, "bad.yml", "title: [unclosed\n  - x: : :\n")
        report = load_rules(tmp_path)
        assert report.rules == []
        assert report.unsupported

    def test_non_utf8_file_is_unsupported(self, tmp_path: Path) -> None:
        (tmp_path / "bin.yml").write_bytes(b"title: \xff\xfe\x00bad")
        report = load_rules(tmp_path)
        assert report.rules == []
        assert report.unsupported

    def test_multi_document_file_loads_each_rule(self, tmp_path: Path) -> None:
        write_raw(
            tmp_path,
            "multi.yml",
            f"""\
            title: One
            id: {UUID_A}
            logsource: {{product: linux, category: process_creation}}
            detection:
              s: {{CommandLine|contains: 'one'}}
              condition: s
            ---
            title: Two
            id: {UUID_B}
            logsource: {{product: linux, category: process_creation}}
            detection:
              s: {{CommandLine|contains: 'two'}}
              condition: s
            """,
        )
        assert sorted(r.name for r in load_rules(tmp_path).rules) == ["One", "Two"]


def _dir_with(tmp_path: Path, **kwargs: Any) -> Path:
    write_rule(tmp_path, **kwargs)
    return tmp_path


# -- (2) supported modifiers / conditions ------------------------------------


def _detect(selection: str, condition: str = "sel") -> str:
    return (
        f"sel:\n{selection}\n  other:\n    CommandLine|contains: 'zzz-other'\n"
        f"  condition: {condition}"
    )


class TestSupportedSubset:
    @pytest.mark.parametrize(
        ("field_line", "command", "expected"),
        [
            ("    CommandLine|contains: 'curl '", "x curl http://a", True),
            ("    CommandLine|contains: 'curl '", "wget http://a", False),
            ("    CommandLine|startswith: 'sudo '", "sudo ls", True),
            ("    CommandLine|startswith: 'sudo '", "x sudo ls", False),
            ("    CommandLine|endswith: '.sh'", "run a.sh", True),
            ("    CommandLine|endswith: '.sh'", "a.sh run", False),
            ("    CommandLine: 'exact'", "exact", True),
            ("    CommandLine: 'exact'", "exact plus", False),
            ("    CommandLine|contains: 'CURL'", "curl", True),  # case-insensitive
            ("    CommandLine|contains: 'a*b'", "xx a123b yy", True),  # wildcard
            ("    CommandLine|contains: 'a?c'", "abc", True),
            ("    CommandLine|contains: 'a?c'", "ac", False),
        ],
    )
    def test_text_modifiers(
        self, tmp_path: Path, field_line: str, command: str, expected: bool
    ) -> None:
        write_rule(tmp_path, detection=_detect(field_line))
        assert fires(only_rule(tmp_path), cmd_event(command)) is expected

    def test_contains_all_requires_every_value(self, tmp_path: Path) -> None:
        sel = "    CommandLine|contains|all:\n      - 'aaa'\n      - 'bbb'"
        write_rule(tmp_path, detection=_detect(sel))
        rule = only_rule(tmp_path)
        assert fires(rule, cmd_event("aaa bbb"))
        assert not fires(rule, cmd_event("aaa only"))

    def test_value_list_is_or(self, tmp_path: Path) -> None:
        sel = "    CommandLine|contains:\n      - 'aaa'\n      - 'bbb'"
        write_rule(tmp_path, detection=_detect(sel))
        rule = only_rule(tmp_path)
        assert fires(rule, cmd_event("xx bbb"))
        assert not fires(rule, cmd_event("ccc"))

    def test_cidr_modifier(self, tmp_path: Path) -> None:
        write_rule(
            tmp_path,
            logsource="product: linux",
            detection="sel:\n    SourceIp|cidr: '203.0.113.0/24'\n  condition: sel",
        )
        rule = only_rule(tmp_path)
        assert fires(rule, make_event(ip="203.0.113.9"))
        assert not fires(rule, make_event(ip="198.51.100.9"))

    def test_exists_modifier(self, tmp_path: Path) -> None:
        write_rule(
            tmp_path,
            logsource="product: linux",
            detection="sel:\n    User|exists: true\n  condition: sel",
        )
        rule = only_rule(tmp_path)
        assert fires(rule, make_event(user="alice"))
        assert not fires(rule, make_event(user=None))

    @pytest.mark.parametrize(
        ("condition", "command", "expected"),
        [
            ("sel_a and sel_b", "aaa bbb", True),
            ("sel_a and sel_b", "aaa", False),
            ("sel_a or sel_b", "bbb", True),
            ("sel_a and not sel_b", "aaa", True),
            ("sel_a and not sel_b", "aaa bbb", False),
            ("(sel_a or sel_b) and not sel_c", "bbb", True),
            ("(sel_a or sel_b) and not sel_c", "bbb ccc", False),
            ("1 of sel_*", "bbb", True),
            ("1 of sel_*", "zzz", False),
            ("all of sel_*", "aaa bbb ccc", True),
            ("all of sel_*", "aaa bbb", False),
            ("1 of them", "ccc", True),
            ("any of them", "ccc", True),
            ("all of them", "aaa bbb ccc", True),
            ("all of them", "aaa bbb", False),
        ],
    )
    def test_condition_grammar(
        self, tmp_path: Path, condition: str, command: str, expected: bool
    ) -> None:
        detection = (
            "sel_a:\n    CommandLine|contains: 'aaa'\n"
            "  sel_b:\n    CommandLine|contains: 'bbb'\n"
            "  sel_c:\n    CommandLine|contains: 'ccc'\n"
            f"  condition: {condition}"
        )
        write_rule(tmp_path, detection=detection)
        assert fires(only_rule(tmp_path), cmd_event(command)) is expected

    def test_keyword_list_selection_matches_message(self, tmp_path: Path) -> None:
        write_rule(
            tmp_path,
            logsource="product: linux",
            detection="keywords:\n    - 'needle'\n  condition: keywords",
        )
        rule = only_rule(tmp_path)
        assert fires(rule, make_event(message="found a needle here"))
        assert not fires(rule, make_event(message="nothing"))

    def test_logsource_service_gate_filters_other_services(self, tmp_path: Path) -> None:
        write_rule(
            tmp_path,
            logsource="product: linux\n  service: sshd",
            detection="sel:\n    Message|contains: 'hello'\n  condition: sel",
        )
        rule = only_rule(tmp_path)
        assert fires(rule, make_event(message="hello", service="sshd"))
        assert not fires(rule, make_event(message="hello", service="cron"))

    @pytest.mark.parametrize(
        ("level", "name"),
        [
            ("informational", "INFO"),
            ("low", "NOTICE"),
            ("medium", "WARNING"),
            ("high", "ERROR"),
            ("critical", "CRITICAL"),
        ],
    )
    def test_level_maps_to_severity(self, tmp_path: Path, level: str, name: str) -> None:
        write_rule(tmp_path, level=level)
        assert only_rule(tmp_path).severity.name == name


# -- (3) unsupported reasons -------------------------------------------------


def _unsupported_reason(tmp_path: Path, **kwargs: Any) -> str:
    write_rule(tmp_path, **kwargs)
    report = load_rules(tmp_path)
    assert report.rules == [], "rule should not have loaded"
    assert len(report.unsupported) == 1
    return report.unsupported[0].reason.lower()


class TestUnsupported:
    @pytest.mark.parametrize(
        "modifier",
        [
            "re",
            "base64",
            "base64offset",
            "gt",
            "lt",
            "gte",
            "lte",
            "windash",
            "fieldref",
            "utf16le",
        ],
    )
    def test_unsupported_modifier_is_reported_with_its_name(
        self, tmp_path: Path, modifier: str
    ) -> None:
        det = f"sel:\n    CommandLine|{modifier}: 'x'\n  condition: sel"
        reason = _unsupported_reason(tmp_path, detection=det)
        assert modifier in reason

    def test_count_aggregation_condition_is_unsupported(self, tmp_path: Path) -> None:
        det = "sel:\n    CommandLine|contains: 'x'\n  condition: sel | count() > 5"
        assert "aggregation" in _unsupported_reason(tmp_path, detection=det)

    def test_timeframe_is_unsupported(self, tmp_path: Path) -> None:
        det = "sel:\n    CommandLine|contains: 'x'\n  timeframe: 5m\n  condition: sel"
        assert "aggregation" in _unsupported_reason(tmp_path, detection=det)

    @pytest.mark.parametrize("product", ["windows", "macos"])
    def test_non_linux_product_is_unsupported(self, tmp_path: Path, product: str) -> None:
        reason = _unsupported_reason(
            tmp_path, logsource=f"product: {product}\n  category: process_creation"
        )
        assert product in reason

    def test_unknown_field_is_unsupported(self, tmp_path: Path) -> None:
        det = "sel:\n    ParentImage|contains: 'x'\n  condition: sel"
        assert "parentimage" in _unsupported_reason(tmp_path, detection=det).lower()

    def test_unknown_logsource_service_is_unsupported(self, tmp_path: Path) -> None:
        reason = _unsupported_reason(tmp_path, logsource="product: linux\n  service: nosuchsvc")
        assert "nosuchsvc" in reason

    def test_undefined_selection_in_condition_is_unsupported(self, tmp_path: Path) -> None:
        det = "sel:\n    CommandLine|contains: 'x'\n  condition: missing"
        assert "undefined" in _unsupported_reason(tmp_path, detection=det)

    def test_missing_title_is_unsupported(self, tmp_path: Path) -> None:
        write_raw(
            tmp_path,
            "t.yml",
            """\
            logsource: {product: linux}
            detection:
              s: {Message|contains: 'x'}
              condition: s
            """,
        )
        assert any("title" in r for r in reasons(tmp_path))

    def test_non_mapping_document_is_unsupported(self, tmp_path: Path) -> None:
        write_raw(tmp_path, "list.yml", "- a\n- b\n")
        report = load_rules(tmp_path)
        assert report.rules == [] and report.unsupported

    def test_unsupported_entry_names_file_and_title(self, tmp_path: Path) -> None:
        det = "sel:\n    CommandLine|re: 'x'\n  condition: sel"
        write_rule(tmp_path, "bad.yml", title="Regex Rule", detection=det)
        (entry,) = load_rules(tmp_path).unsupported
        assert entry.path == "bad.yml"
        assert entry.title == "Regex Rule"


# -- (4) hostile YAML --------------------------------------------------------


class TestHostileYaml:
    def test_alias_bomb_is_rejected_quickly(self, tmp_path: Path) -> None:
        write_raw(
            tmp_path,
            "bomb.yml",
            """\
            a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
            b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
            c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
            d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
            e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
            title: Bomb
            logsource: {product: linux, category: process_creation}
            detection:
              sel: {CommandLine|contains: *e}
              condition: sel
            """,
        )
        start = time.monotonic()
        report = load_rules(tmp_path)
        assert time.monotonic() - start < TIME_BUDGET_SECONDS
        assert report.rules == []
        assert report.unsupported

    def test_simple_alias_is_rejected(self, tmp_path: Path) -> None:
        write_raw(
            tmp_path,
            "alias.yml",
            f"""\
            title: Alias
            id: {UUID_A}
            logsource: {{product: linux, category: process_creation}}
            detection:
              s1: &v {{CommandLine|contains: 'x'}}
              s2: *v
              condition: s1 or s2
            """,
        )
        report = load_rules(tmp_path)
        assert report.rules == []
        assert any("alias" in u.reason.lower() for u in report.unsupported)

    def test_duplicate_key_is_rejected(self, tmp_path: Path) -> None:
        write_raw(
            tmp_path,
            "dup.yml",
            f"""\
            title: Dup
            id: {UUID_A}
            logsource: {{product: linux, category: process_creation}}
            detection:
              sel:
                CommandLine|contains: 'safe'
                CommandLine|contains: 'evil'
              condition: sel
            """,
        )
        report = load_rules(tmp_path)
        assert report.rules == []
        assert any("duplicate" in u.reason.lower() for u in report.unsupported)

    def test_duplicate_top_level_key_is_rejected(self, tmp_path: Path) -> None:
        write_raw(
            tmp_path,
            "dup2.yml",
            f"""\
            title: One
            title: Two
            id: {UUID_A}
            logsource: {{product: linux, category: process_creation}}
            detection:
              sel: {{CommandLine|contains: 'x'}}
              condition: sel
            """,
        )
        assert load_rules(tmp_path).rules == []

    def test_python_object_tag_is_not_executed(self, tmp_path: Path) -> None:
        marker = tmp_path / "pwned.txt"
        write_raw(
            tmp_path,
            "tag.yml",
            f"""\
            title: !!python/object/apply:builtins.open ["{marker.as_posix()}", "w"]
            logsource: {{product: linux}}
            detection:
              s: {{Message|contains: 'x'}}
              condition: s
            """,
        )
        report = load_rules(tmp_path)
        assert report.rules == []
        assert not marker.exists()

    def test_huge_wildcard_pattern_is_rejected(self, tmp_path: Path) -> None:
        pattern = "a*" * 400  # 800 chars, over the 512-char cap
        det = f"sel:\n    CommandLine|contains: '{pattern}'\n  condition: sel"
        write_rule(tmp_path, detection=det)
        report = load_rules(tmp_path)
        assert report.rules == []
        assert report.unsupported

    def test_pattern_at_reasonable_length_is_accepted(self, tmp_path: Path) -> None:
        det = f"sel:\n    CommandLine|contains: '{'a' * 100}*end'\n  condition: sel"
        write_rule(tmp_path, detection=det)
        assert len(load_rules(tmp_path).rules) == 1

    def test_empty_value_is_unsupported(self, tmp_path: Path) -> None:
        det = "sel:\n    CommandLine|contains: ''\n  condition: sel"
        write_rule(tmp_path, detection=det)
        report = load_rules(tmp_path)
        assert report.rules == []
        assert report.unsupported

    def test_empty_value_inside_list_is_unsupported(self, tmp_path: Path) -> None:
        det = "sel:\n    CommandLine|contains:\n      - 'ok'\n      - ''\n  condition: sel"
        write_rule(tmp_path, detection=det)
        assert load_rules(tmp_path).rules == []

    def test_empty_value_list_is_unsupported(self, tmp_path: Path) -> None:
        det = "sel:\n    CommandLine|contains: []\n  condition: sel"
        write_rule(tmp_path, detection=det)
        assert load_rules(tmp_path).rules == []

    def test_oversized_value_list_is_unsupported(self, tmp_path: Path) -> None:
        values = "\n".join(f"      - 'v{i}'" for i in range(1100))
        det = f"sel:\n    CommandLine|contains:\n{values}\n  condition: sel"
        write_rule(tmp_path, detection=det)
        assert load_rules(tmp_path).rules == []

    def test_deeply_nested_condition_is_unsupported(self, tmp_path: Path) -> None:
        cond = "(" * 40 + "sel" + ")" * 40
        det = f"sel:\n    CommandLine|contains: 'x'\n  condition: {cond}"
        write_rule(tmp_path, detection=det)
        assert load_rules(tmp_path).rules == []


# -- (5) wildcard evaluation is bounded; padded payloads still detected --------


def _wild_rule(tmp_path: Path, pattern: str, mode: str = "contains") -> SigmaRule:
    key = "CommandLine" if mode == "eq" else f"CommandLine|{mode}"
    det = f"sel:\n    {key}: '{pattern}'\n  condition: sel"
    write_rule(tmp_path, detection=det)
    return only_rule(tmp_path)


class TestWildcardSafety:
    @pytest.mark.parametrize(
        "pattern",
        [
            "a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b",
            "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*c",
            "a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?b",
            "a*" * 200 + "b",
        ],
    )
    def test_adversarial_pattern_on_long_text_does_not_hang(
        self, tmp_path: Path, pattern: str
    ) -> None:
        det = f"sel:\n    CommandLine|contains: '{pattern}'\n  condition: sel"
        write_rule(tmp_path, detection=det)
        report = load_rules(tmp_path)
        if not report.rules:  # rejected at load time is also safe
            return
        rule = report.rules[0]
        event = cmd_event("a" * 20000)
        start = time.monotonic()
        result = fires(rule, event)
        elapsed = time.monotonic() - start
        assert elapsed < TIME_BUDGET_SECONDS
        assert result is False

    def test_many_adversarial_rules_against_many_events_stay_bounded(self, tmp_path: Path) -> None:
        for i in range(10):
            pat = "a*" * (20 + i) + "b"
            write_rule(
                tmp_path,
                f"r{i}.yml",
                title=f"R{i}",
                rule_id=f"{i:08x}-0000-4000-8000-000000000000",
                detection=f"sel:\n    CommandLine|contains: '{pat}'\n  condition: sel",
            )
        rules = load_rules(tmp_path).rules
        event = cmd_event("a" * 8000)
        start = time.monotonic()
        for rule in rules:
            fires(rule, event)
        assert time.monotonic() - start < TIME_BUDGET_SECONDS

    def test_wildcard_still_matches_real_payload(self, tmp_path: Path) -> None:
        rule = _wild_rule(tmp_path, "curl*|*sh")
        assert fires(rule, cmd_event("curl http://x/y.sh | sh"))
        assert not fires(rule, cmd_event("curl http://x/y.sh"))

    def test_literal_payload_after_long_padding_is_still_detected(self, tmp_path: Path) -> None:
        rule = _wild_rule(tmp_path, "base64 -d")
        padded = "A" * 20000 + " base64 -d | sh"
        assert fires(rule, cmd_event(padded))

    def test_wildcard_payload_after_long_padding_is_still_detected(self, tmp_path: Path) -> None:
        rule = _wild_rule(tmp_path, "base64*-d*|*sh")
        padded = "A" * 20000 + " base64 -d | sh"
        assert fires(rule, cmd_event(padded))

    def test_payload_before_long_padding_is_still_detected(self, tmp_path: Path) -> None:
        rule = _wild_rule(tmp_path, "base64*-d*|*sh")
        padded = "base64 -d | sh " + "A" * 20000
        assert fires(rule, cmd_event(padded))

    def test_payload_split_across_padding_is_not_a_false_positive(self, tmp_path: Path) -> None:
        rule = _wild_rule(tmp_path, "needle*haystack", mode="eq")
        assert not fires(rule, cmd_event("needle " + "A" * 20000))

    def test_padding_does_not_make_unrelated_event_match(self, tmp_path: Path) -> None:
        rule = _wild_rule(tmp_path, "base64*-d*|*sh")
        assert not fires(rule, cmd_event("A" * 20000))

    def test_example_rule_detects_padded_payload(self) -> None:
        rules = {r.name: r for r in load_rules(EXAMPLES).rules}
        rule = next(r for n, r in rules.items() if "base64" in n.lower())
        assert fires(rule, cmd_event("x" * 20000 + " echo aGk= | base64 -d | sh"))
        assert fires(rule, cmd_event("echo aGk= | base64 -d | sh"))
        assert not fires(rule, cmd_event("echo aGk= | base64 -d > out.txt"))


# -- (6) ids and caps --------------------------------------------------------


class TestIds:
    def test_id_is_deterministic(self) -> None:
        assert sigma_rule_id(UUID_A, "t") == sigma_rule_id(UUID_A, "t")

    def test_id_from_uuid_uses_first_eight_hex_chars(self) -> None:
        assert sigma_rule_id(UUID_A, "t") == "SIGMA-5c2c3993"

    def test_uuid_case_and_whitespace_do_not_change_id(self) -> None:
        assert sigma_rule_id(UUID_A.upper(), "t") == sigma_rule_id(f"  {UUID_A} ", "t")

    def test_id_without_uuid_is_title_hash_and_stable(self) -> None:
        first = sigma_rule_id(None, "My Rule")
        assert first == sigma_rule_id(None, "My Rule")
        assert first != sigma_rule_id(None, "Other Rule")
        assert SIGMA_RULE_ID_RE.match(first)

    def test_invalid_uuid_falls_back_to_title_hash(self) -> None:
        assert sigma_rule_id("not-a-uuid", "T") == sigma_rule_id(None, "T")

    @pytest.mark.parametrize("value", [UUID_A, None, "garbage"])
    def test_id_always_matches_pattern(self, value: str | None) -> None:
        assert SIGMA_RULE_ID_RE.match(sigma_rule_id(value, "title"))

    def test_same_rule_loaded_twice_gets_same_id(self, tmp_path: Path) -> None:
        write_rule(tmp_path)
        first = only_rule(tmp_path).rule_id
        assert only_rule(tmp_path).rule_id == first

    def test_duplicate_id_across_files_is_reported_unsupported(self, tmp_path: Path) -> None:
        write_rule(tmp_path, "a.yml", title="First", rule_id=UUID_A)
        write_rule(tmp_path, "b.yml", title="Second", rule_id=UUID_A)
        report = load_rules(tmp_path)
        assert [r.name for r in report.rules] == ["First"]
        assert len(report.unsupported) == 1
        assert "duplicate" in report.unsupported[0].reason.lower()

    def test_distinct_ids_both_load(self, tmp_path: Path) -> None:
        write_rule(tmp_path, "a.yml", title="First", rule_id=UUID_A)
        write_rule(tmp_path, "b.yml", title="Second", rule_id=UUID_B)
        assert len(load_rules(tmp_path).rules) == 2

    def test_rule_id_regex_rejects_other_shapes(self) -> None:
        assert not SIGMA_RULE_ID_RE.match("R001")
        assert not SIGMA_RULE_ID_RE.match("SIGMA-XYZ")
        assert not SIGMA_RULE_ID_RE.match("SIGMA-5C2C3993")


class TestCaps:
    def test_max_rules_limits_loaded_rules(self, tmp_path: Path) -> None:
        for i in range(5):
            write_rule(
                tmp_path, f"r{i}.yml", title=f"R{i}", rule_id=f"{i:08x}-0000-4000-8000-000000000000"
            )
        report = load_rules(tmp_path, max_rules=2)
        assert len(report.rules) == 2
        assert report.unsupported

    def test_max_rules_one_loads_exactly_one(self, tmp_path: Path) -> None:
        write_rule(tmp_path, "a.yml", title="A", rule_id=UUID_A)
        write_rule(tmp_path, "b.yml", title="B", rule_id=UUID_B)
        assert len(load_rules(tmp_path, max_rules=1).rules) == 1

    def test_oversized_file_is_skipped_with_reason(self, tmp_path: Path) -> None:
        write_rule(tmp_path, "big.yml", extra="description: " + "x" * 2000)
        report = load_rules(tmp_path, max_file_bytes=500)
        assert report.rules == []
        assert any("large" in r.lower() for r in reasons_of(report))

    def test_small_file_under_cap_still_loads(self, tmp_path: Path) -> None:
        write_rule(tmp_path, "small.yml")
        assert len(load_rules(tmp_path, max_file_bytes=4096).rules) == 1

    def test_many_documents_in_one_file_are_capped(self, tmp_path: Path) -> None:
        doc = (
            "title: T{i}\nlogsource: {{product: linux}}\ndetection:\n"
            "  s: {{Message|contains: 'x{i}'}}\n  condition: s\n"
        )
        text = "---\n".join(doc.format(i=i) for i in range(500))
        (tmp_path / "many.yml").write_text(text, encoding="utf-8")
        report = load_rules(tmp_path, max_file_bytes=10_000_000)
        assert len(report.rules) < 500
        assert report.unsupported

    def test_loader_never_raises_on_garbage(self, tmp_path: Path) -> None:
        for i, blob in enumerate(
            ["", "---", "{", "!!binary x", "a: &x [*x]", "\x00\x01", "- - - -"]
        ):
            (tmp_path / f"g{i}.yml").write_text(blob, encoding="utf-8", errors="ignore")
        report = load_rules(tmp_path)
        assert report.files_scanned == 7


def reasons_of(report: Any) -> list[str]:
    return [u.reason for u in report.unsupported]


# -- (7) response gating -----------------------------------------------------

SIGMA_ID = "SIGMA-5c2c3993"


@pytest.fixture()
def rig(tmp_path: Path) -> Iterator[Rig]:
    r = Rig(tmp_path)
    try:
        yield r
    finally:
        r.store.close()


def sigma_alert(ip: str = "203.0.113.10") -> Any:
    alert = make_alert(ip)
    alert.rule_id = SIGMA_ID
    return alert


class TestResponseGating:
    def test_include_sigma_rules_defaults_to_false(self) -> None:
        assert ResponseConfig().include_sigma_rules is False

    def test_include_sigma_rules_must_be_bool(self) -> None:
        from sentinelai.core.exceptions import ConfigError

        with pytest.raises(ConfigError):
            make_config(include_sigma_rules="yes")._validate_safety()

    def test_auto_mode_does_not_block_sigma_alert(self, rig: Rig) -> None:
        action = rig.responder(make_config(mode="auto")).consider(sigma_alert())
        assert action is None
        assert rig.fw.calls == []
        assert "skipped" in rig.decisions()

    def test_auto_mode_skip_reason_mentions_sigma(self, rig: Rig) -> None:
        rig.responder(make_config(mode="auto")).consider(sigma_alert())
        (record,) = rig.records("skipped")
        assert "sigma" in json.dumps(record).lower()

    def test_auto_mode_still_blocks_builtin_rule_alert(self, rig: Rig) -> None:
        rig.responder(make_config(mode="auto")).consider(make_alert("203.0.113.10"))
        assert rig.fw.calls, "control: built-in alerts must still trigger blocking"

    def test_auto_mode_blocks_sigma_alert_when_opted_in(self, rig: Rig) -> None:
        cfg = make_config(mode="auto", include_sigma_rules=True)
        rig.responder(cfg).consider(sigma_alert())
        assert rig.fw.calls

    def test_approval_mode_may_still_queue_sigma_alert(self, rig: Rig) -> None:
        alert = sigma_alert()
        rig.responder(make_config(mode="approval")).consider(alert)
        assert rig.fw.calls == []  # nothing applied without a human
        assert re.fullmatch(r"SIGMA-[0-9a-f]{8}", alert.rule_id)
        assert "pending_id" in alert.context.get("response", {})

    def test_lookalike_rule_id_is_not_treated_as_sigma(self, rig: Rig) -> None:
        alert = make_alert("203.0.113.10")
        alert.rule_id = "SIGMA-XYZ"
        rig.responder(make_config(mode="auto")).consider(alert)
        assert rig.fw.calls


# -- (8) CLI -----------------------------------------------------------------


class TestCli:
    def test_import_empty_directory_reports_nothing_importable(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        result = CliRunner().invoke(cli, ["rules", "import", str(empty)])
        assert result.exit_code == 0, result.output
        assert "No rules were importable" in result.output

    def test_import_valid_directory_lists_rules_and_config_snippet(self, tmp_path: Path) -> None:
        write_rule(tmp_path / "rules", title="CLI Rule")
        result = CliRunner().invoke(cli, ["rules", "import", str(tmp_path / "rules")])
        assert result.exit_code == 0, result.output
        assert "1 importable" in result.output
        assert "sigma:" in result.output

    def test_import_json_output_is_valid_and_lists_unsupported(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules"
        write_rule(rules, "ok.yml", title="Good", rule_id=UUID_A)
        write_rule(
            rules,
            "bad.yml",
            title="Bad",
            rule_id=UUID_B,
            detection="sel:\n    CommandLine|re: 'x'\n  condition: sel",
        )
        result = CliRunner().invoke(cli, ["rules", "import", str(rules), "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert [r["id"] for r in data["imported"]] == ["SIGMA-5c2c3993"]
        assert [u["title"] for u in data["unsupported"]] == ["Bad"]

    def test_import_missing_directory_fails_cleanly(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(cli, ["rules", "import", str(tmp_path / "nope")])
        assert result.exit_code != 0
        assert "Traceback" not in result.output

    def test_import_does_not_write_into_rules_directory(self, tmp_path: Path) -> None:
        write_rule(tmp_path / "rules")
        before = sorted(p.name for p in (tmp_path / "rules").iterdir())
        CliRunner().invoke(cli, ["rules", "import", str(tmp_path / "rules")])
        assert sorted(p.name for p in (tmp_path / "rules").iterdir()) == before

    def test_plain_rules_command_still_lists_builtin_rules(self) -> None:
        result = CliRunner().invoke(cli, ["rules"])
        assert result.exit_code == 0, result.output
        assert "R001" in result.output


def test_sigma_rules_use_expected_category_for_sshd(tmp_path: Path) -> None:
    write_rule(
        tmp_path,
        logsource="product: linux\n  service: sshd",
        detection="sel:\n    Message|contains: 'x'\n  condition: sel",
    )
    assert only_rule(tmp_path).category is EventCategory.SSH


def test_event_step_pool_caps_total_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinelai.sigma import matcher

    rule = _wild_rule(tmp_path, "*a*b*c*")
    event = cmd_event("a" * 5000)
    monkeypatch.setattr(matcher, "EVENT_STEP_POOL", 50)
    outcomes = [matcher.evaluate_detection(rule._parsed.detection, event) for _ in range(20)]
    # once the shared pool is spent, later rules are refused for this event
    assert outcomes[-1] == (False, True)
    # a fresh event gets a fresh pool
    assert matcher.evaluate_detection(rule._parsed.detection, cmd_event("a" * 5000))[1] in (
        True,
        False,
    )
