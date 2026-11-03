"""Tests for the tuning foundations: store schema v2, suppression/risk config, overlay loader."""

from __future__ import annotations

import json
import math
import sqlite3
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from sentinelai.config.loader import load_config, overlay_path
from sentinelai.config.models import (
    DetectionConfig,
    RiskConfig,
    SentinelConfig,
    parse_suppressions,
)
from sentinelai.core.exceptions import ConfigError, StorageError
from sentinelai.core.models import Alert, EventCategory, Severity
from sentinelai.core.store import SCHEMA_VERSION, AlertStore
from sentinelai.risk.engine import RiskEngine
from tests.conftest import BASE_TS

_LEGACY_SCHEMA = """
CREATE TABLE alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    risk_level  TEXT NOT NULL,
    risk_score  REAL NOT NULL,
    ip          TEXT,
    user        TEXT,
    hostname    TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    payload     TEXT NOT NULL
);
"""


def make_alert(rule_id: str = "R001", ip: str = "203.0.113.5") -> Alert:
    alert = Alert(
        rule_id=rule_id,
        rule_name="Test Rule",
        title=f"{rule_id} fired",
        description="synthetic alert",
        category=EventCategory.AUTHENTICATION,
        severity=Severity.WARNING,
        first_seen=BASE_TS,
        last_seen=BASE_TS + timedelta(seconds=30),
        ip=ip,
        user="alice",
        hostname="web01",
        event_count=6,
    )
    alert.risk = RiskEngine().score(alert)
    return alert


def _table_names(path: Path) -> set[str]:
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    finally:
        conn.close()
    return {row[0] for row in rows}


@pytest.fixture()
def store(tmp_path: Path):
    db = AlertStore(tmp_path / "alerts.db")
    yield db
    db.close()


# -- store: schema migration ---------------------------------------------------------------


class TestStoreMigration:
    def test_fresh_database_is_current_schema_version(self, tmp_path: Path) -> None:
        db = AlertStore(tmp_path / "fresh.db")
        try:
            assert db.schema_version == SCHEMA_VERSION
        finally:
            db.close()
        assert {"alerts", "feedback", "config_history"} <= _table_names(tmp_path / "fresh.db")

    def test_legacy_v1_database_migrates_with_data_intact(self, tmp_path: Path) -> None:
        path = tmp_path / "legacy.db"
        alert = make_alert()
        conn = sqlite3.connect(str(path))
        conn.executescript(_LEGACY_SCHEMA)
        conn.execute(
            "INSERT INTO alerts (rule_id, title, category, severity, risk_level, risk_score, "
            "ip, user, hostname, first_seen, last_seen, created_at, fingerprint, payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.rule_id,
                alert.title,
                alert.category.value,
                alert.severity.value,
                alert.risk.level.value,
                alert.risk.score,
                alert.ip,
                alert.user,
                alert.hostname,
                alert.first_seen.isoformat(),
                alert.last_seen.isoformat(),
                alert.created_at.isoformat(),
                alert.fingerprint,
                json.dumps(alert.to_dict(include_events=True)),
            ),
        )
        conn.commit()
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        conn.close()

        db = AlertStore(path)
        try:
            assert db.schema_version == SCHEMA_VERSION
            loaded = db.get(1)
            assert loaded is not None
            assert loaded.rule_id == "R001"
            assert loaded.ip == "203.0.113.5"
            assert loaded.user == "alice"
            assert len(db.recent()) == 1
            # The migrated tables are usable immediately.
            assert db.add_feedback(1, "tp") > 0
        finally:
            db.close()
        assert {"alerts", "feedback", "config_history"} <= _table_names(path)

    def test_reopening_migrated_database_is_idempotent(self, tmp_path: Path) -> None:
        path = tmp_path / "again.db"
        first = AlertStore(path)
        first.save(make_alert())
        first.close()
        second = AlertStore(path)
        try:
            assert second.schema_version == SCHEMA_VERSION
            assert len(second.recent()) == 1
        finally:
            second.close()

    def test_newer_database_version_raises_storage_error(self, tmp_path: Path) -> None:
        path = tmp_path / "future.db"
        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA user_version = 99")
        conn.commit()
        conn.close()
        with pytest.raises(StorageError, match="newer"):
            AlertStore(path)


# -- store: feedback -----------------------------------------------------------------------


class TestStoreFeedback:
    def test_add_feedback_snapshots_stored_alert(self, store: AlertStore) -> None:
        alert_id = store.save(make_alert())
        feedback_id = store.add_feedback(alert_id, "fp", note="known scanner")
        (entry,) = store.list_feedback()
        assert entry.id == feedback_id
        assert entry.alert_id == alert_id
        assert entry.label == "fp"
        assert entry.note == "known scanner"
        assert entry.rule_id == "R001"
        assert entry.snapshot["rule_id"] == "R001"
        assert entry.snapshot["ip"] == "203.0.113.5"
        assert entry.ts.tzinfo is not None

    def test_snapshot_survives_later_alert_update(self, store: AlertStore) -> None:
        alert = make_alert()
        alert_id = store.save(alert)
        store.add_feedback(alert_id, "tp")
        alert.title = "changed after labelling"
        store.update(alert)
        (entry,) = store.list_feedback()
        assert entry.snapshot["title"] == "R001 fired"

    def test_relabelling_replaces_with_same_row_id(self, store: AlertStore) -> None:
        alert_id = store.save(make_alert())
        first = store.add_feedback(alert_id, "tp", note="first")
        second = store.add_feedback(alert_id, "fp", note="second")
        assert first == second
        (entry,) = store.list_feedback()
        assert entry.label == "fp"
        assert entry.note == "second"

    def test_invalid_label_raises_storage_error(self, store: AlertStore) -> None:
        alert_id = store.save(make_alert())
        with pytest.raises(StorageError, match="label"):
            store.add_feedback(alert_id, "maybe")
        assert store.list_feedback() == []

    def test_unknown_alert_id_raises_storage_error(self, store: AlertStore) -> None:
        with pytest.raises(StorageError, match="does not exist"):
            store.add_feedback(4242, "tp")
        assert store.list_feedback() == []

    def test_note_is_truncated_to_500_characters(self, store: AlertStore) -> None:
        alert_id = store.save(make_alert())
        store.add_feedback(alert_id, "tp", note="x" * 900)
        (entry,) = store.list_feedback()
        assert len(entry.note) == 500

    def test_explicit_naive_timestamp_is_treated_as_utc(self, store: AlertStore) -> None:
        alert_id = store.save(make_alert())
        store.add_feedback(alert_id, "tp", ts=datetime(2026, 1, 7, 12, 0, 0))
        (entry,) = store.list_feedback()
        assert entry.ts == datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)

    def test_list_feedback_filters_by_label(self, store: AlertStore) -> None:
        a = store.save(make_alert("R001"))
        b = store.save(make_alert("R002"))
        store.add_feedback(a, "tp")
        store.add_feedback(b, "fp")
        assert [e.alert_id for e in store.list_feedback(label="fp")] == [b]
        assert [e.alert_id for e in store.list_feedback(label="tp")] == [a]

    def test_list_feedback_filters_by_rule(self, store: AlertStore) -> None:
        a = store.save(make_alert("R001"))
        b = store.save(make_alert("R002"))
        store.add_feedback(a, "fp")
        store.add_feedback(b, "fp")
        assert [e.alert_id for e in store.list_feedback(rule_id="R002")] == [b]
        assert store.list_feedback(rule_id="R999") == []

    def test_list_feedback_combines_label_and_rule_filters(self, store: AlertStore) -> None:
        a = store.save(make_alert("R001"))
        b = store.save(make_alert("R001", ip="203.0.113.9"))
        store.add_feedback(a, "tp")
        store.add_feedback(b, "fp")
        result = store.list_feedback(label="fp", rule_id="R001")
        assert [e.alert_id for e in result] == [b]

    def test_list_feedback_empty_store_returns_empty_list(self, store: AlertStore) -> None:
        assert store.list_feedback() == []

    def test_delete_feedback_removes_entry_and_returns_true(self, store: AlertStore) -> None:
        alert_id = store.save(make_alert())
        store.add_feedback(alert_id, "tp")
        assert store.delete_feedback(alert_id) is True
        assert store.list_feedback() == []

    def test_delete_feedback_without_entry_returns_false(self, store: AlertStore) -> None:
        alert_id = store.save(make_alert())
        assert store.delete_feedback(alert_id) is False
        assert store.delete_feedback(4242) is False


# -- store: config history -----------------------------------------------------------------


class TestStoreConfigHistory:
    def test_add_and_list_config_history_roundtrip(self, store: AlertStore) -> None:
        history_id = store.add_config_history(
            "apply", ["p1", "p2"], "old: 1\n", "new: 2\n", note="tuning run"
        )
        (entry,) = store.list_config_history()
        assert entry.id == history_id
        assert entry.action == "apply"
        assert entry.proposal_ids == ["p1", "p2"]
        assert entry.previous_text == "old: 1\n"
        assert entry.new_text == "new: 2\n"
        assert entry.note == "tuning run"
        assert entry.rolled_back is False
        assert entry.ts.tzinfo is not None

    def test_list_config_history_is_ordered_oldest_first(self, store: AlertStore) -> None:
        first = store.add_config_history("apply", [], "", "a")
        second = store.add_config_history("rollback", [], "a", "")
        assert [e.id for e in store.list_config_history()] == [first, second]

    def test_mark_rolled_back_sets_flag(self, store: AlertStore) -> None:
        history_id = store.add_config_history("apply", ["p1"], "", "x")
        store.mark_rolled_back(history_id)
        (entry,) = store.list_config_history()
        assert entry.rolled_back is True

    def test_mark_rolled_back_unknown_id_raises_storage_error(self, store: AlertStore) -> None:
        with pytest.raises(StorageError, match="does not exist"):
            store.mark_rolled_back(4242)

    def test_invalid_action_raises_storage_error(self, store: AlertStore) -> None:
        with pytest.raises(StorageError, match="action"):
            store.add_config_history("delete", [], "", "")
        assert store.list_config_history() == []


# -- config: suppressions ------------------------------------------------------------------


class TestParseSuppressions:
    def test_bare_ip_becomes_slash_32(self) -> None:
        (sup,) = parse_suppressions(
            [{"rule": "R001", "ip": "203.0.113.5", "expires": "2099-01-01"}]
        )
        assert sup.ip == "203.0.113.5/32"
        assert sup.user is None
        assert sup.rule == "R001"

    def test_cidr_is_normalized_non_strict(self) -> None:
        (sup,) = parse_suppressions(
            [{"rule": "R001", "ip": "10.1.2.3/24", "expires": "2099-01-01"}]
        )
        assert sup.ip == "10.1.2.0/24"

    def test_date_string_expires_at_end_of_day_utc(self) -> None:
        (sup,) = parse_suppressions([{"rule": "R001", "user": "bob", "expires": "2099-03-04"}])
        assert sup.expires == datetime(2099, 3, 4, 23, 59, 59, 999999, tzinfo=timezone.utc)

    def test_date_object_expires_at_end_of_day_utc(self) -> None:
        (sup,) = parse_suppressions([{"rule": "R001", "user": "bob", "expires": date(2099, 3, 4)}])
        assert sup.expires == datetime(2099, 3, 4, 23, 59, 59, 999999, tzinfo=timezone.utc)

    def test_iso_datetime_string_with_z_suffix(self) -> None:
        (sup,) = parse_suppressions(
            [{"rule": "R001", "user": "bob", "expires": "2099-03-04T10:00:00Z"}]
        )
        assert sup.expires == datetime(2099, 3, 4, 10, 0, 0, tzinfo=timezone.utc)

    def test_iso_datetime_string_with_offset_converted_to_utc(self) -> None:
        (sup,) = parse_suppressions(
            [{"rule": "R001", "user": "bob", "expires": "2099-03-04T10:00:00+02:00"}]
        )
        assert sup.expires == datetime(2099, 3, 4, 8, 0, 0, tzinfo=timezone.utc)

    def test_naive_datetime_is_assumed_utc(self) -> None:
        (sup,) = parse_suppressions(
            [{"rule": "R001", "user": "bob", "expires": datetime(2099, 3, 4, 10, 0, 0)}]
        )
        assert sup.expires == datetime(2099, 3, 4, 10, 0, 0, tzinfo=timezone.utc)

    def test_user_and_ip_and_note_are_kept(self) -> None:
        (sup,) = parse_suppressions(
            [
                {
                    "rule": "R010",
                    "user": "svc.backup@corp",
                    "ip": "198.51.100.0/24",
                    "expires": "2099-01-01",
                    "note": "backup job",
                }
            ]
        )
        assert sup.user == "svc.backup@corp"
        assert sup.note == "backup job"

    def test_empty_list_returns_empty_list(self) -> None:
        assert parse_suppressions([]) == []

    @pytest.mark.parametrize(
        ("entry", "fragment"),
        [
            ({"rule": "R001", "user": "a", "expires": "2099-01-01", "color": "red"}, "unknown"),
            ({"user": "a", "expires": "2099-01-01"}, "rule"),
            ({"rule": "R001", "expires": "2099-01-01"}, "user"),
            ({"rule": "R001", "user": "*", "expires": "2099-01-01"}, "user"),
            ({"rule": "R001", "user": "a b", "expires": "2099-01-01"}, "user"),
            ({"rule": "R001", "user": "a" * 65, "expires": "2099-01-01"}, "user"),
            ({"rule": "R001", "ip": "999.1.1.1", "expires": "2099-01-01"}, "ip"),
            ({"rule": "R001", "ip": "10.0.0.0/33", "expires": "2099-01-01"}, "ip"),
            ({"rule": "R001", "ip": 12345, "expires": "2099-01-01"}, "ip"),
            ({"rule": "r001", "user": "a", "expires": "2099-01-01"}, "rule"),
            ({"rule": "RULE1", "user": "a", "expires": "2099-01-01"}, "rule"),
            ({"rule": "R001", "user": "a"}, "expires"),
            ({"rule": "R001", "user": "a", "expires": "next week"}, "expires"),
            ({"rule": "R001", "user": "a", "expires": "2099-13-45"}, "expires"),
            ({"rule": "R001", "user": "a", "expires": 12345}, "expires"),
            ({"rule": "R001", "user": "a", "expires": "2099-01-01", "note": "n" * 201}, "note"),
            ({"rule": "R001", "user": "a", "expires": "2099-01-01", "note": 5}, "note"),
        ],
    )
    def test_invalid_entry_raises_config_error(self, entry: dict[str, Any], fragment: str) -> None:
        with pytest.raises(ConfigError, match=fragment):
            parse_suppressions([entry])

    def test_non_mapping_entry_raises_config_error(self) -> None:
        with pytest.raises(ConfigError, match="mapping"):
            parse_suppressions(["R001"])  # type: ignore[list-item]

    def test_non_list_raises_config_error(self) -> None:
        with pytest.raises(ConfigError, match="list"):
            parse_suppressions({"rule": "R001"})  # type: ignore[arg-type]

    def test_note_of_exactly_200_chars_is_accepted(self) -> None:
        (sup,) = parse_suppressions(
            [{"rule": "R001", "user": "a", "expires": "2099-01-01", "note": "n" * 200}]
        )
        assert len(sup.note) == 200

    def test_error_message_names_offending_index(self) -> None:
        good = {"rule": "R001", "user": "a", "expires": "2099-01-01"}
        with pytest.raises(ConfigError, match=r"suppressions\[1\]"):
            parse_suppressions([good, {"rule": "R001"}])


class TestDetectionConfigSuppressionValidation:
    def test_validate_accepts_valid_suppressions(self) -> None:
        cfg = DetectionConfig(
            suppressions=[{"rule": "R001", "ip": "203.0.113.5", "expires": "2099-01-01"}]
        )
        cfg.validate()
        assert cfg.parsed_suppressions()[0].ip == "203.0.113.5/32"

    def test_validate_rejects_bad_suppressions(self) -> None:
        cfg = DetectionConfig(suppressions=[{"rule": "R001", "user": "*", "expires": "2099-01-01"}])
        with pytest.raises(ConfigError, match="user"):
            cfg.validate()

    def test_validate_rejects_non_mapping_suppression(self) -> None:
        cfg = DetectionConfig(suppressions=["nope"])  # type: ignore[list-item]
        with pytest.raises(ConfigError):
            cfg.validate()


class TestRiskConfigValidation:
    def test_empty_weights_are_valid(self) -> None:
        RiskConfig().validate()

    @pytest.mark.parametrize("weight", [0.5, 1.0, 1.5, 1])
    def test_weights_within_bounds_are_accepted(self, weight: float) -> None:
        RiskConfig(rule_weights={"R001": weight}).validate()

    @pytest.mark.parametrize("weight", [0.49, 1.51, 0, -1, 100])
    def test_weights_out_of_bounds_are_rejected(self, weight: float) -> None:
        with pytest.raises(ConfigError, match="R001"):
            RiskConfig(rule_weights={"R001": weight}).validate()

    @pytest.mark.parametrize("weight", [math.nan, math.inf, -math.inf])
    def test_non_finite_weights_are_rejected(self, weight: float) -> None:
        with pytest.raises(ConfigError):
            RiskConfig(rule_weights={"R001": weight}).validate()

    @pytest.mark.parametrize("weight", [True, False, "1.0", None])
    def test_non_numeric_or_bool_weights_are_rejected(self, weight: Any) -> None:
        with pytest.raises(ConfigError):
            RiskConfig(rule_weights={"R001": weight}).validate()

    @pytest.mark.parametrize("rule", ["r001", "RULE", "R1", "R0001", ""])
    def test_bad_rule_id_is_rejected(self, rule: str) -> None:
        with pytest.raises(ConfigError, match="rule id"):
            RiskConfig(rule_weights={rule: 1.0}).validate()

    def test_non_mapping_weights_are_rejected(self) -> None:
        with pytest.raises(ConfigError, match="mapping"):
            RiskConfig(rule_weights=[("R001", 1.0)]).validate()  # type: ignore[arg-type]


# -- loader: tuning overlay ----------------------------------------------------------------


@pytest.fixture()
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate HOME/cwd/env so no real config.yaml or SENTINELAI_* variable leaks in."""
    import os

    for name in list(os.environ):
        if name.startswith("SENTINELAI_"):
            monkeypatch.delenv(name)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _state_with_overlay(root: Path, overlay: str) -> Path:
    state = root / "state"
    _write(state / "tuning.yaml", overlay)
    return state


def _config_file(root: Path, state: Path, extra: str = "") -> Path:
    return _write(root / "main.yaml", f"state_dir: {state.as_posix()}\n{extra}")


class TestLoaderOverlay:
    def test_overlay_applies_detection_thresholds(self, isolated: Path) -> None:
        state = _state_with_overlay(
            isolated, "detection:\n  brute_force_attempts: 9\n  port_scan_ports: 25\n"
        )
        config = load_config(_config_file(isolated, state))
        assert config.detection.brute_force_attempts == 9
        assert config.detection.port_scan_ports == 25
        assert config.tuning_overlay == str(state / "tuning.yaml")

    def test_overlay_beats_main_config_file_values(self, isolated: Path) -> None:
        state = _state_with_overlay(isolated, "detection:\n  brute_force_attempts: 9\n")
        cfg_file = _config_file(isolated, state, "detection:\n  brute_force_attempts: 3\n")
        assert load_config(cfg_file).detection.brute_force_attempts == 9

    def test_overlay_suppressions_are_added_to_main_config_ones(self, isolated: Path) -> None:
        state = _state_with_overlay(
            isolated,
            "detection:\n"
            "  suppressions:\n"
            "    - {rule: R002, ip: 198.51.100.7, expires: '2099-01-01'}\n",
        )
        cfg_file = _config_file(
            isolated,
            state,
            "detection:\n"
            "  suppressions:\n"
            "    - {rule: R001, user: admin, expires: '2099-01-01'}\n",
        )
        config = load_config(cfg_file)
        rules = [s["rule"] for s in config.detection.suppressions]
        assert rules == ["R001", "R002"]
        assert [s.rule for s in config.detection.parsed_suppressions()] == ["R001", "R002"]

    def test_overlay_suppressions_work_without_main_suppressions(self, isolated: Path) -> None:
        state = _state_with_overlay(
            isolated,
            "detection:\n"
            "  suppressions:\n"
            "    - {rule: R002, ip: 198.51.100.7, expires: '2099-01-01'}\n",
        )
        config = load_config(_config_file(isolated, state))
        assert len(config.detection.suppressions) == 1

    def test_overlay_rule_weights_replace_main_ones(self, isolated: Path) -> None:
        state = _state_with_overlay(isolated, "risk:\n  rule_weights:\n    R002: 0.8\n")
        cfg_file = _config_file(isolated, state, "risk:\n  rule_weights:\n    R001: 1.2\n")
        config = load_config(cfg_file)
        assert config.risk.rule_weights == {"R002": 0.8}

    def test_missing_overlay_is_not_an_error(self, isolated: Path) -> None:
        state = isolated / "state"
        state.mkdir()
        config = load_config(_config_file(isolated, state))
        assert config.tuning_overlay == ""

    def test_empty_overlay_file_is_accepted(self, isolated: Path) -> None:
        state = _state_with_overlay(isolated, "")
        config = load_config(_config_file(isolated, state))
        assert config.detection.brute_force_attempts == DetectionConfig().brute_force_attempts

    @pytest.mark.parametrize(
        "overlay",
        [
            "firewall:\n  adapter: command\n",
            "detection:\n  disabled_rules: [R001]\n",
            "detection:\n  enabled_rules: [R001]\n",
            "detection:\n  suspicious_hours_start: 3\n",
            "risk:\n  other: 1\n",
            "state_dir: /elsewhere\n",
            "intel:\n  enabled: false\n",
        ],
    )
    def test_disallowed_overlay_key_raises_config_error(
        self, isolated: Path, overlay: str
    ) -> None:
        state = _state_with_overlay(isolated, overlay)
        with pytest.raises(ConfigError, match="tuning overlay"):
            load_config(_config_file(isolated, state))

    def test_overlay_section_must_be_a_mapping(self, isolated: Path) -> None:
        state = _state_with_overlay(isolated, "detection: [1, 2]\n")
        with pytest.raises(ConfigError, match="mapping"):
            load_config(_config_file(isolated, state))

    def test_overlay_boolean_threshold_is_rejected(self, isolated: Path) -> None:
        state = _state_with_overlay(isolated, "detection:\n  brute_force_attempts: true\n")
        with pytest.raises(ConfigError, match="number"):
            load_config(_config_file(isolated, state))

    def test_overlay_non_list_suppressions_rejected(self, isolated: Path) -> None:
        state = _state_with_overlay(isolated, "detection:\n  suppressions: nope\n")
        with pytest.raises(ConfigError, match="list"):
            load_config(_config_file(isolated, state))

    def test_overlay_invalid_suppression_fails_validation(self, isolated: Path) -> None:
        state = _state_with_overlay(
            isolated,
            "detection:\n  suppressions:\n    - {rule: R001, user: '*', expires: '2099-01-01'}\n",
        )
        with pytest.raises(ConfigError, match="user"):
            load_config(_config_file(isolated, state))

    def test_overlay_out_of_range_weight_fails_validation(self, isolated: Path) -> None:
        state = _state_with_overlay(isolated, "risk:\n  rule_weights:\n    R001: 9.0\n")
        with pytest.raises(ConfigError, match="R001"):
            load_config(_config_file(isolated, state))

    def test_overlay_non_mapping_rule_weights_rejected(self, isolated: Path) -> None:
        state = _state_with_overlay(isolated, "risk:\n  rule_weights: [1, 2]\n")
        with pytest.raises(ConfigError, match="rule_weights"):
            load_config(_config_file(isolated, state))

    def test_invalid_yaml_overlay_raises_config_error(self, isolated: Path) -> None:
        state = _state_with_overlay(isolated, "detection: [unclosed\n  - : :\n")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            load_config(_config_file(isolated, state))

    def test_non_mapping_top_level_overlay_raises_config_error(self, isolated: Path) -> None:
        state = _state_with_overlay(isolated, "- a\n- b\n")
        with pytest.raises(ConfigError, match="mapping"):
            load_config(_config_file(isolated, state))


class TestLoaderPrecedence:
    def test_env_override_beats_overlay(
        self, isolated: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = _state_with_overlay(isolated, "detection:\n  brute_force_attempts: 9\n")
        monkeypatch.setenv("SENTINELAI_DETECTION_BRUTE_FORCE_ATTEMPTS", "14")
        config = load_config(_config_file(isolated, state))
        assert config.detection.brute_force_attempts == 14

    def test_state_dir_env_decides_where_overlay_is_found(
        self, isolated: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = _state_with_overlay(isolated, "detection:\n  port_scan_ports: 33\n")
        monkeypatch.setenv("SENTINELAI_STATE_DIR", str(state))
        # No main config file, so the state dir comes from the environment only.
        config = load_config()
        assert config.state_dir == str(state)
        assert config.detection.port_scan_ports == 33
        assert overlay_path(config) == state / "tuning.yaml"

    def test_state_dir_env_beats_config_file_state_dir(
        self, isolated: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_state = _state_with_overlay(isolated / "env", "detection:\n  port_scan_ports: 41\n")
        file_state = _state_with_overlay(isolated / "file", "detection:\n  port_scan_ports: 17\n")
        monkeypatch.setenv("SENTINELAI_STATE_DIR", str(env_state))
        config = load_config(_config_file(isolated, file_state))
        assert config.detection.port_scan_ports == 41

    def test_no_overlay_and_no_config_yields_defaults(
        self, isolated: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINELAI_STATE_DIR", str(isolated / "empty-state"))
        config = load_config()
        assert isinstance(config, SentinelConfig)
        assert config.tuning_overlay == ""
        assert config.detection.suppressions == []
        assert config.risk.rule_weights == {}
