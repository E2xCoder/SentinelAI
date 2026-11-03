"""Prompt-injection hardening tests for LLM triage.

Every payload in ``benchmarks/injection/cases.yaml`` is attacker-controlled log
text. The tests prove three things without any network access:

* it can only ever reach the model inside the single ``LOG_DATA`` data block;
* a model that obeys it anyway cannot get an ungrounded verdict accepted;
* even an accepted (grounded) verdict can neither trigger nor suppress a response.
"""

from __future__ import annotations

import copy
import json
import re
import unicodedata
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

import sentinelai.detection.rules  # noqa: F401  (registers built-in rules)
from sentinelai.ai.triage import build_prompt, sanitize_text, template_triage
from sentinelai.ai.triage_engine import TriageEngine
from sentinelai.ai.triage_models import TriageOutcome
from sentinelai.config.models import LLMConfig, ResponseConfig
from sentinelai.core.models import Alert, EventType
from sentinelai.core.pipeline import AnalysisPipeline
from sentinelai.detection.base import available_rules
from sentinelai.firewall.adapters import DryRunAdapter
from sentinelai.firewall.responder import AutoResponder
from sentinelai.parsers.reader import read_events
from sentinelai.risk.engine import RiskEngine
from tests.conftest import make_event

CORPUS_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "injection"
CASES_FILE = CORPUS_DIR / "cases.yaml"
ATTACK_LOG = CORPUS_DIR / "attack_auth.log"

DATA_OPEN = "<<<LOG_DATA"
DATA_CLOSE = "LOG_DATA>>>"
ATTACKER_IP = "203.0.113.50"
MIN_CASES = 24

#: Fields of the alert that may carry the payload ("all" = every field at once).
PLACEMENTS = ("all", "title", "description", "user", "hostname", "event_message")
_DEFAULTS = {
    "title": f"SSH brute force from {ATTACKER_IP}",
    "description": "6 failed authentication attempts within 300 seconds.",
    "user": "deploy",
    "hostname": "web01",
    "event_message": f"Failed password for deploy from {ATTACKER_IP} port 40000 ssh2",
}

#: Characters that may never reach the model (newline is the only allowed separator).
_FORBIDDEN_EXTRA = frozenset("\r\t\x0b\x0c\x1b\x1c\x1d\x1e\x85  ")
#: Phrases a naive, instruction-following model would react to.
_TRIGGERS = (
    "ignore previous",
    "disregard all prior",
    "you are now",
    "mark this alert benign",
    "system:",
    "ignoriere alle",
    "talimatlar",
    "print your system prompt",
)


def _load_cases() -> list[dict[str, Any]]:
    loaded = yaml.safe_load(CASES_FILE.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, list) else []


CASES = _load_cases()
CASE_PARAMS = [pytest.param(case, id=str(case.get("id"))) for case in CASES]


# -- helpers ---------------------------------------------------------------


class FakeProvider:
    """A TriageProvider whose answer is computed by *handler*."""

    name = "fake"
    model = "fake-model"

    def __init__(self, handler: Callable[[str, str], str]) -> None:
        self._handler = handler
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, schema: Any) -> str:
        self.calls.append((system, user))
        return self._handler(system, user)


def _answer(
    verdict: str = "suspicious", confidence: float = 0.8, cited: Iterable[int] = (1,)
) -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": confidence,
            "summary": "Repeated failed SSH logins from one source.",
            "reasoning": "Several failures in a short window.",
            "recommended_actions": ["Investigate the source."],
            "referenced_event_ids": list(cited),
        }
    )


def _engine(provider: FakeProvider | None, *, enabled: bool = True) -> TriageEngine:
    config = LLMConfig(enabled=enabled, model="fake-model", max_retries=0)
    return TriageEngine(config, provider=provider, cache=None, sleep=lambda _s: None)


def build_alert(payload: str = "", placement: str = "none") -> Alert:
    """A real, risk-scored R001 alert whose chosen fields carry *payload*."""

    def at(name: str) -> str:
        return payload if placement in ("all", name) else _DEFAULTS[name]

    events = [
        make_event(
            offset=float(i),
            event_type=EventType.AUTH_FAILURE,
            ip=ATTACKER_IP,
            user=at("user"),
            hostname=at("hostname"),
            port=40000 + i,
            message=at("event_message"),
        )
        for i in range(3)
    ]
    rule = available_rules()["R001"]()
    alert = rule.make_alert(
        events[-1],
        at("title"),
        at("description"),
        events=events,
        attempts=3,
        window_seconds=300,
    )
    RiskEngine().score(alert)
    return alert


def probe_of(payload: str) -> str:
    """The first characters of the payload that survive sanitising."""
    return sanitize_text(payload, 300)[:25].strip()


def split_data_block(user: str) -> tuple[str, str, str]:
    """Return (before, block, after) around the single data block."""
    start = user.index(DATA_OPEN)
    end = user.index(DATA_CLOSE) + len(DATA_CLOSE)
    return user[:start], user[start:end], user[end:]


def outside_block(system: str, user: str) -> str:
    before, _block, after = split_data_block(user)
    return f"{system}\n{before}\n{after}"


def occurrences(text: str, needle: str) -> list[int]:
    found, start = [], text.find(needle)
    while start != -1:
        found.append(start)
        start = text.find(needle, start + 1)
    return found


def _snapshot(alert: Alert) -> dict[str, Any]:
    context = copy.deepcopy(alert.context)
    response = context.get("response")
    if isinstance(response, dict):
        response.pop("timestamp", None)
    return {
        "score": alert.risk.score,
        "level": alert.risk.level,
        "severity": alert.severity,
        "factors": [(f.name, f.points, f.reason) for f in alert.risk.factors],
        "context": context,
    }


def vulnerable_model(probe: str, obeyed: list[bool]) -> Callable[[str, str], str]:
    """Simulated naive model: obeys any instruction found OUTSIDE the data block."""
    triggers = (probe.casefold(), *_TRIGGERS)

    def handler(system: str, user: str) -> str:
        visible = outside_block(system, user).casefold()
        if any(trigger in visible for trigger in triggers):
            obeyed.append(True)
            return _answer("benign", 1.0, cited=())
        return _answer("suspicious", 0.8, cited=(1,))

    return handler


# -- (5) corpus file -------------------------------------------------------


class TestCorpusFile:
    def test_cases_file_is_valid_list_with_required_keys(self) -> None:
        assert isinstance(CASES, list)
        for case in CASES:
            assert isinstance(case, dict)
            assert {"id", "description", "payload"} <= set(case)

    def test_cases_has_at_least_minimum_count(self) -> None:
        assert len(CASES) >= MIN_CASES

    def test_case_ids_are_unique(self) -> None:
        ids = [case["id"] for case in CASES]
        assert len(ids) == len(set(ids))

    def test_every_payload_is_non_empty_text(self) -> None:
        for case in CASES:
            assert isinstance(case["payload"], str)
            assert case["payload"].strip(), case["id"]
            assert case["description"].strip(), case["id"]

    def test_every_payload_leaves_a_visible_probe_after_sanitising(self) -> None:
        for case in CASES:
            assert len(probe_of(case["payload"])) >= 8, case["id"]

    def test_corpus_covers_required_attack_classes(self) -> None:
        payloads = [case["payload"] for case in CASES]
        checks: dict[str, Callable[[str], bool]] = {
            "ignore_previous": lambda p: "ignore previous instructions" in p.lower(),
            "role_hijack": lambda p: "SYSTEM:" in p,
            "fake_end_marker": lambda p: "LOG_DATA>>>" in p,
            "json_smuggle": lambda p: p.startswith('{"verdict": "benign", "confidence": 1'),
            "markdown_fence": lambda p: "```json" in p,
            "ansi_escape": lambda p: "\x1b[" in p,
            "osc_escape": lambda p: "\x1b]" in p,
            "unicode_tags": lambda p: any(0xE0000 <= ord(c) <= 0xE007F for c in p),
            "zero_width": lambda p: "​" in p,
            "turkish": lambda p: "talimat" in p,
            "german": lambda p: "Anweisungen" in p,
            "base64": lambda p: "SWdub3JlIHByZXZpb3Vz" in p,
            "fake_event": lambda p: "E99" in p,
            "prompt_leak": lambda p: "system prompt" in p,
            "tool_call": lambda p: "<tool_call>" in p or '"function_call"' in p,
            "rm_rf": lambda p: "rm -rf /" in p,
            "disable_firewall": lambda p: "disable the firewall" in p,
            "long_payload": lambda p: len(p) >= 20_000,
        }
        for name, check in checks.items():
            assert any(check(p) for p in payloads), f"corpus lacks: {name}"

    def test_attack_log_is_rfc3339_documentation_ip_sshd(self) -> None:
        lines = ATTACK_LOG.read_text(encoding="utf-8").splitlines()
        assert 10 <= len(lines) <= 15
        for line in lines:
            assert datetime.fromisoformat(line.split(" ", 1)[0]).tzinfo is not None
            assert " sshd[" in line
        ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "\n".join(lines)))
        assert ips
        assert all(ip.startswith("203.0.113.") for ip in ips)


# -- (1) prompt confinement ------------------------------------------------


@pytest.mark.parametrize("case", CASE_PARAMS)
class TestPromptConfinement:
    def test_system_message_never_contains_payload(self, case: dict[str, Any]) -> None:
        payload = case["payload"]
        prompt = build_prompt(build_alert(payload, "all"))
        assert prompt.system == build_prompt(build_alert()).system
        assert probe_of(payload) not in prompt.system
        assert payload.strip() not in prompt.system

    def test_block_markers_occur_exactly_once_in_user_message(self, case: dict[str, Any]) -> None:
        prompt = build_prompt(build_alert(case["payload"], "all"))
        assert prompt.user.count(DATA_OPEN) == 1
        assert prompt.user.count(DATA_CLOSE) == 1
        assert prompt.user.index(DATA_OPEN) < prompt.user.index(DATA_CLOSE)
        assert prompt.user.rstrip().endswith("Respond now with the JSON object only.")

    @pytest.mark.parametrize("placement", PLACEMENTS)
    def test_surviving_payload_text_only_inside_data_block(
        self, case: dict[str, Any], placement: str
    ) -> None:
        probe = probe_of(case["payload"])
        prompt = build_prompt(build_alert(case["payload"], placement))
        start = prompt.user.index(DATA_OPEN)
        end = prompt.user.index(DATA_CLOSE)
        hits = occurrences(prompt.user, probe)
        assert hits, "payload vanished entirely; the check would be vacuous"
        assert all(start < pos < end for pos in hits)
        assert probe not in prompt.system

    def test_text_outside_data_block_is_independent_of_payload(
        self, case: dict[str, Any]
    ) -> None:
        attacked = build_prompt(build_alert(case["payload"], "all"))
        clean = build_prompt(build_alert())
        assert outside_block(attacked.system, attacked.user) == outside_block(
            clean.system, clean.user
        )

    @pytest.mark.parametrize("placement", PLACEMENTS)
    def test_no_control_escape_or_invisible_character_survives(
        self, case: dict[str, Any], placement: str
    ) -> None:
        prompt = build_prompt(build_alert(case["payload"], placement))
        for message in (prompt.system, prompt.user):
            for ch in message:
                if ch == "\n":
                    continue
                assert unicodedata.category(ch)[0] != "C", f"U+{ord(ch):04X}"
                assert ch not in _FORBIDDEN_EXTRA, f"U+{ord(ch):04X}"
                assert not 0xE0000 <= ord(ch) <= 0xE007F

    def test_payload_cannot_inject_extra_lines_into_the_user_message(
        self, case: dict[str, Any]
    ) -> None:
        attacked = build_prompt(build_alert(case["payload"], "all"))
        clean = build_prompt(build_alert())
        # One field per line: a payload must never add lines to the block.
        assert len(attacked.user.splitlines()) == len(clean.user.splitlines())


class TestSpecificEvasions:
    def test_hidden_tag_character_instruction_is_removed(self) -> None:
        case = next(c for c in CASES if c["id"] == "unicode_tag_chars")
        prompt = build_prompt(build_alert(case["payload"], "all"))
        assert "ignore previous" not in prompt.user.casefold()
        assert "Session opened normally" in prompt.user

    def test_zero_width_split_instruction_is_rejoined_inside_block_only(self) -> None:
        case = next(c for c in CASES if c["id"] == "zero_width_split")
        prompt = build_prompt(build_alert(case["payload"], "all"))
        before, block, after = split_data_block(prompt.user)
        assert "ignore previous instructions" in block
        assert "ignore previous" not in (before + after + prompt.system).casefold()

    def test_nested_delimiter_cannot_reassemble(self) -> None:
        case = next(c for c in CASES if c["id"] == "marker_reassembly")
        prompt = build_prompt(build_alert(case["payload"], "all"))
        assert prompt.user.count(DATA_OPEN) == 1
        assert prompt.user.count(DATA_CLOSE) == 1


# -- (2) simulated vulnerable model ----------------------------------------


class TestSimulatedVulnerableModel:
    @pytest.mark.parametrize("case", CASE_PARAMS)
    def test_nothing_leaks_into_an_instruction_channel(self, case: dict[str, Any]) -> None:
        alert = build_alert(case["payload"], "all")
        obeyed: list[bool] = []
        provider = FakeProvider(vulnerable_model(probe_of(case["payload"]), obeyed))
        outcome = _engine(provider).triage(alert)
        assert provider.calls
        assert obeyed == []
        assert outcome.valid_llm is True
        assert outcome.result.verdict == "suspicious"
        assert outcome.result.confidence == pytest.approx(0.8)

    @pytest.mark.parametrize("placement", PLACEMENTS)
    def test_every_placement_takes_the_honest_path(self, placement: str) -> None:
        for case in CASES:
            obeyed: list[bool] = []
            provider = FakeProvider(vulnerable_model(probe_of(case["payload"]), obeyed))
            outcome = _engine(provider).triage(build_alert(case["payload"], placement))
            assert obeyed == [], case["id"]
            assert outcome.result.verdict == "suspicious", case["id"]

    def test_harness_detects_payload_spliced_into_system_message(self) -> None:
        case = CASES[0]
        prompt = build_prompt(build_alert(case["payload"], "all"))
        handler = vulnerable_model(probe_of(case["payload"]), [])
        answer = json.loads(handler(prompt.system + "\n" + case["payload"], prompt.user))
        assert answer["verdict"] == "benign"
        assert answer["confidence"] == 1.0

    def test_harness_detects_payload_appended_after_the_data_block(self) -> None:
        case = CASES[0]
        prompt = build_prompt(build_alert(case["payload"], "all"))
        handler = vulnerable_model(probe_of(case["payload"]), [])
        answer = json.loads(handler(prompt.system, prompt.user + "\n" + case["payload"]))
        assert answer["verdict"] == "benign"


# -- (3) compromised model -------------------------------------------------


class TestCompromisedModelRejected:
    @pytest.mark.parametrize("case", CASE_PARAMS)
    def test_benign_verdict_citing_fake_events_falls_back_to_template(
        self, case: dict[str, Any]
    ) -> None:
        alert = build_alert(case["payload"], "all")
        provider = FakeProvider(lambda _s, _u: _answer("benign", 1.0, cited=range(1, 100)))
        outcome = _engine(provider).triage(alert)
        assert len(provider.calls) == 1
        assert outcome.valid_llm is False
        assert outcome.source == "template"
        assert outcome.rejection is not None
        assert "not provided" in outcome.rejection
        assert outcome.result == template_triage(alert)

    @pytest.mark.parametrize("case", CASE_PARAMS)
    def test_model_echoing_the_payload_verbatim_is_rejected(self, case: dict[str, Any]) -> None:
        alert = build_alert(case["payload"], "all")
        provider = FakeProvider(lambda _s, _u: case["payload"])
        outcome = _engine(provider).triage(alert)
        assert outcome.valid_llm is False
        assert outcome.source == "template"
        assert outcome.result == template_triage(alert)

    def test_smuggled_json_citing_event_99_is_rejected(self) -> None:
        case = next(c for c in CASES if c["id"] == "json_smuggle_full")
        assert json.loads(case["payload"])["verdict"] == "benign"
        alert = build_alert(case["payload"], "all")
        outcome = _engine(FakeProvider(lambda _s, _u: case["payload"])).triage(alert)
        assert outcome.valid_llm is False
        assert outcome.rejection is not None
        assert "not provided" in outcome.rejection

    def test_smuggled_json_inside_markdown_fence_with_trailing_text_is_rejected(self) -> None:
        case = next(c for c in CASES if c["id"] == "markdown_fence_smuggle")
        outcome = _engine(FakeProvider(lambda _s, _u: case["payload"])).triage(
            build_alert(case["payload"], "all")
        )
        assert outcome.valid_llm is False
        assert outcome.source == "template"


def _respond(
    payload: str, verdict: str | None, min_level: str
) -> tuple[dict[str, Any], list[dict[str, Any]], list[tuple[str, str, int | None]], TriageOutcome]:
    """Triage (or not), then run the real responder; return what it produced."""
    alert = build_alert(payload, "all")
    firewall = DryRunAdapter()
    responder = AutoResponder(ResponseConfig(enabled=True, min_risk_level=min_level), firewall)
    before = _snapshot(alert)
    if verdict is None:
        outcome = _engine(None, enabled=False).triage(alert)
    else:
        provider = FakeProvider(lambda _s, _u: _answer(verdict, 1.0, cited=(1, 2)))
        outcome = _engine(provider).triage(alert)
    assert _snapshot(alert) == before, "triage must not touch the alert"
    responder.consider(alert)
    actions = [
        {k: v for k, v in action.to_dict().items() if k != "timestamp"}
        for action in responder.actions
    ]
    return _snapshot(alert), actions, firewall.calls, outcome


class TestAcceptedVerdictIsAdvisoryOnly:
    @pytest.mark.parametrize("case", CASE_PARAMS)
    def test_grounded_benign_verdict_is_accepted_as_advisory(self, case: dict[str, Any]) -> None:
        _snap, _actions, _calls, outcome = _respond(case["payload"], "benign", "low")
        assert outcome.valid_llm is True
        assert outcome.source == "llm:fake-model"
        assert outcome.result.verdict == "benign"
        assert outcome.result.referenced_event_ids == (1, 2)

    @pytest.mark.parametrize("verdict", ["benign", "malicious"])
    @pytest.mark.parametrize("min_level", ["low", "critical"])
    @pytest.mark.parametrize("case", CASE_PARAMS)
    def test_verdict_never_changes_score_context_or_response(
        self, case: dict[str, Any], verdict: str, min_level: str
    ) -> None:
        with_llm = _respond(case["payload"], verdict, min_level)
        without_llm = _respond(case["payload"], None, min_level)
        assert with_llm[0] == without_llm[0]  # score, level, severity, factors, context
        assert with_llm[1] == without_llm[1]  # responder actions
        assert with_llm[2] == without_llm[2]  # firewall calls
        assert without_llm[3].valid_llm is False

    def test_benign_verdict_does_not_suppress_a_block(self) -> None:
        snap, actions, calls, _outcome = _respond(CASES[0]["payload"], "benign", "low")
        assert len(actions) == 1
        assert actions[0]["ip"] == ATTACKER_IP
        assert calls
        assert snap["context"]["response"]["ip"] == ATTACKER_IP

    def test_malicious_verdict_does_not_trigger_a_block_below_threshold(self) -> None:
        snap, actions, calls, _outcome = _respond(CASES[0]["payload"], "malicious", "critical")
        assert snap["level"].value != "critical"
        assert actions == []
        assert calls == []
        assert "response" not in snap["context"]


# -- (4) end to end --------------------------------------------------------


def _strip_payloads(text: str) -> str:
    cleaned = []
    for line in text.splitlines():
        line = re.sub(r"(ssh2) .*$", r"\1", line)
        line = re.sub(r"for inj_\S+ from", "for deploy from", line)
        cleaned.append(line)
    return "\n".join(cleaned) + "\n"


class TestEndToEndDetectionIgnoresPayloads:
    def test_attack_log_contains_payloads_and_stripped_copy_does_not(
        self, tmp_path: Path
    ) -> None:
        original = ATTACK_LOG.read_text(encoding="utf-8")
        stripped = _strip_payloads(original)
        for needle in ("Ignore previous instructions", "SYSTEM:", "LOG_DATA>>>", "inj_"):
            assert needle in original
            assert needle not in stripped

    def test_r001_fires_identically_with_and_without_payloads(
        self, test_config, tmp_path: Path
    ) -> None:
        clean_log = tmp_path / "clean_auth.log"
        clean_log.write_text(
            _strip_payloads(ATTACK_LOG.read_text(encoding="utf-8")), encoding="utf-8", newline="\n"
        )
        clean_config = copy.deepcopy(test_config)
        clean_config.state_dir = str(tmp_path / "state_clean")
        clean_config.report.output_dir = str(tmp_path / "reports_clean")
        clean_config.validate()

        results = {}
        for label, config, path in (
            ("attack", test_config, ATTACK_LOG),
            ("clean", clean_config, clean_log),
        ):
            pipeline = AnalysisPipeline(config)
            try:
                results[label] = pipeline.run_scan(read_events(path), use_ai=False)
            finally:
                pipeline.close()

        def r001(label: str) -> list[tuple[int, float, str]]:
            return [
                (a.event_count, a.risk.score, a.risk.level.value)
                for a in results[label].alerts
                if a.rule_id == "R001"
            ]

        assert r001("attack")
        assert r001("attack") == r001("clean")
        assert results["attack"].statistics.total_events == results["clean"].statistics.total_events

    def test_prompts_for_scanned_attack_alerts_keep_payloads_inside_data_block(
        self, test_config
    ) -> None:
        pipeline = AnalysisPipeline(test_config)
        try:
            result = pipeline.run_scan(read_events(ATTACK_LOG), use_ai=False)
        finally:
            pipeline.close()
        r001 = [a for a in result.alerts if a.rule_id == "R001"]
        assert r001
        baseline_system = build_prompt(build_alert()).system
        for alert in r001:
            prompt = build_prompt(alert)
            assert prompt.system == baseline_system
            assert prompt.user.count(DATA_OPEN) == 1
            assert prompt.user.count(DATA_CLOSE) == 1
            before, block, after = split_data_block(prompt.user)
            assert "ignore previous instructions" in block.casefold()
            assert "ignore previous" not in (before + after).casefold()
