"""End-to-end integration tests over the bundled example logs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinelai.core.pipeline import AnalysisPipeline
from sentinelai.parsers.reader import read_events
from sentinelai.reporting.renderers import render_csv, render_html, render_json
from sentinelai.reporting.report import build_report

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
AUTH_LOG = EXAMPLES / "auth.log"


@pytest.fixture()
def pipeline(test_config):
    pipe = AnalysisPipeline(test_config)
    yield pipe
    pipe.close()


class TestAuthLogScan:
    def test_expected_rules_fire(self, pipeline) -> None:
        result = pipeline.run_scan(read_events(AUTH_LOG), use_ai=False)
        fired = {a.rule_id for a in result.alerts}
        # The scenario embeds a full attack chain; assert its signature rules.
        assert "R001" in fired  # SSH brute force
        assert "R005" in fired  # root login
        assert "R020" in fired  # UID-0 backdoor account
        assert "R031" in fired  # reverse shell
        assert "R040" in fired  # suspicious cron
        assert "R050" in fired  # security service (ufw) stopped

    def test_alert_count_reasonable(self, pipeline) -> None:
        result = pipeline.run_scan(read_events(AUTH_LOG), use_ai=False)
        assert 6 <= len(result.alerts) <= 20

    def test_critical_reverse_shell(self, pipeline) -> None:
        result = pipeline.run_scan(read_events(AUTH_LOG), use_ai=False)
        rev = next(a for a in result.alerts if a.rule_id == "R031")
        assert rev.risk.level.value == "critical"
        assert rev.risk.score >= 80

    def test_attack_pattern_recognized(self, pipeline) -> None:
        result = pipeline.run_scan(read_events(AUTH_LOG), use_ai=False)
        assert result.patterns
        assert any("brute force" in p.name.lower() for p in result.patterns)

    def test_every_alert_scored_and_explained(self, pipeline) -> None:
        result = pipeline.run_scan(read_events(AUTH_LOG), use_ai=False)
        for alert in result.alerts:
            assert alert.risk.score > 0
            assert alert.risk.factors
            assert alert.id is not None  # persisted

    def test_alerts_persisted_and_retrievable(self, pipeline) -> None:
        result = pipeline.run_scan(read_events(AUTH_LOG), use_ai=False)
        first = result.alerts[0]
        loaded = pipeline.store.get(first.id)
        assert loaded is not None
        assert loaded.rule_id == first.rule_id


class TestReporting:
    def test_all_three_formats_render(self, pipeline) -> None:
        result = pipeline.run_scan(read_events(AUTH_LOG), use_ai=False)
        report = build_report(result, title="Test", source=str(AUTH_LOG))

        as_json = render_json(report)
        parsed = json.loads(as_json)
        assert parsed["summary"]["alerts_total"] == len(result.alerts)
        assert "behavior_analysis" in parsed["summary"]

        as_csv = render_csv(report)
        assert "rule_id" in as_csv.splitlines()[0]
        assert len(as_csv.splitlines()) == len(result.alerts) + 1

        as_html = render_html(report)
        assert as_html.startswith("<!DOCTYPE html>")
        assert "Behavior analysis" in as_html

    def test_report_has_recommendations(self, pipeline) -> None:
        result = pipeline.run_scan(read_events(AUTH_LOG), use_ai=False)
        report = build_report(result, title="Test", source=str(AUTH_LOG))
        assert report.recommendations


class TestNginxLog:
    def test_web_scan_parses(self, pipeline) -> None:
        nginx_log = EXAMPLES / "nginx_access.log"
        result = pipeline.run_scan(read_events(nginx_log), use_ai=False)
        assert result.statistics.total_events >= 5


class TestDryRunFirewall:
    def test_no_response_when_disabled(self, pipeline) -> None:
        # test_config has response disabled by default.
        result = pipeline.run_scan(read_events(AUTH_LOG), use_ai=False)
        assert pipeline.responder.actions == []
        assert result is not None
