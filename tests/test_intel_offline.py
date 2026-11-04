"""Tests for the cache-only (offline) threat-intelligence mode.

No network is ever touched: provider ``lookup`` methods are replaced by fakes,
and cache rows are seeded directly. Addresses are well-known public resolvers
used only as opaque, globally-routable inputs (documentation ranges are not
"public" for the aggregator).
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sentinelai.config.loader import load_config
from sentinelai.config.models import IntelConfig
from sentinelai.core.exceptions import ConfigError
from sentinelai.intel.aggregator import ThreatIntelAggregator
from sentinelai.intel.base import ProviderResult
from sentinelai.intel.cache import IntelCache
from sentinelai.intel.providers import AbuseIPDBProvider, OTXProvider

PUBLIC_IP = "8.8.8.8"
OTHER_IP = "1.1.1.1"
UNKNOWN_IP = "9.9.9.9"
PRIVATE_IP = "10.0.0.5"
TTL = 3600

PAYLOAD: dict[str, Any] = {
    "score": 85.0,
    "malicious": True,
    "country": "ZZ",
    "isp": "Example ISP",
    "tags": ["scanner", "ssh-bruteforce"],
}


# -- helpers ---------------------------------------------------------------


def make_intel(*, offline: bool, **overrides: Any) -> IntelConfig:
    config = IntelConfig(offline=offline, cache_ttl_seconds=TTL, **overrides)
    config.abuseipdb.enabled = True
    config.abuseipdb.api_key = "fake-key-for-tests"
    return config


class CallRecorder:
    """Stand-in for ``ThreatIntelProvider.lookup`` (set on the class, so no ``self``)."""

    def __init__(self, result: dict[str, Any] | None = None, *, explode: bool = False) -> None:
        self.calls: list[str] = []
        self._result = result
        self._explode = explode

    def __call__(self, ip: str) -> ProviderResult | None:
        self.calls.append(ip)
        if self._explode:
            raise AssertionError(f"provider.lookup must not be called in offline mode ({ip})")
        return None if self._result is None else ProviderResult(self._result)


def install(monkeypatch: pytest.MonkeyPatch, recorder: CallRecorder) -> CallRecorder:
    monkeypatch.setattr(AbuseIPDBProvider, "lookup", recorder)
    monkeypatch.setattr(OTXProvider, "lookup", recorder)
    return recorder


def seed(
    state_dir: Path,
    ip: str,
    payload: dict[str, Any] | None = None,
    *,
    provider: str = "abuseipdb",
    age_seconds: float = 0.0,
) -> None:
    """Insert a cache row created ``age_seconds`` ago."""
    cache = IntelCache(state_dir / "intel_cache.db", TTL)
    cache.put(provider, ip, dict(PAYLOAD if payload is None else payload))
    cache.close()
    if age_seconds:
        conn = sqlite3.connect(str(state_dir / "intel_cache.db"))
        conn.execute(
            "UPDATE intel_cache SET created_at = ? WHERE provider = ? AND ip = ?",
            (time.time() - age_seconds, provider, ip),
        )
        conn.commit()
        conn.close()


def row_count(state_dir: Path) -> int:
    conn = sqlite3.connect(str(state_dir / "intel_cache.db"))
    try:
        return int(conn.execute("SELECT COUNT(*) FROM intel_cache").fetchone()[0])
    finally:
        conn.close()


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    path = tmp_path / "state"
    path.mkdir()
    return path


@pytest.fixture
def offline_agg(state_dir: Path) -> Iterator[ThreatIntelAggregator]:
    # IntelCache creates the schema, so the offline reader finds the table even on a
    # brand-new state directory.
    agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)
    yield agg
    agg.close()


# -- offline mode ----------------------------------------------------------


class TestOfflineLookups:
    def test_provider_is_never_called(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        recorder = install(monkeypatch, CallRecorder(explode=True))
        agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)

        try:
            for ip in (PUBLIC_IP, OTHER_IP, UNKNOWN_IP, PRIVATE_IP):
                agg.lookup(ip)
        finally:
            agg.close()

        assert recorder.calls == []

    def test_fresh_cache_entry_is_served_without_stale_tag(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        install(monkeypatch, CallRecorder(explode=True))
        seed(state_dir, PUBLIC_IP)
        agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)

        try:
            rep = agg.lookup(PUBLIC_IP)
        finally:
            agg.close()

        assert rep.sources == {"abuseipdb": PAYLOAD}
        assert rep.score == 85.0
        assert rep.malicious is True
        assert rep.country == "ZZ"
        assert rep.isp == "Example ISP"
        assert rep.tags == ["scanner", "ssh-bruteforce"]
        assert "stale-cache" not in rep.tags

    def test_expired_cache_entry_is_served_and_tagged_stale(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        install(monkeypatch, CallRecorder(explode=True))
        seed(state_dir, PUBLIC_IP, age_seconds=TTL * 10)
        agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)

        try:
            rep = agg.lookup(PUBLIC_IP)
        finally:
            agg.close()

        assert rep.score == 85.0 / 2  # only-expired data is discounted
        assert rep.malicious is True
        assert "stale-cache" in rep.tags
        assert rep.tags.count("stale-cache") == 1

    def test_expired_entry_is_not_deleted_from_the_cache(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        install(monkeypatch, CallRecorder(explode=True))
        seed(state_dir, PUBLIC_IP, age_seconds=TTL * 10)
        agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)

        try:
            agg.lookup(PUBLIC_IP)
        finally:
            agg.close()

        assert row_count(state_dir) == 1

    def test_unknown_ip_gets_a_bare_reputation(
        self, monkeypatch: pytest.MonkeyPatch, offline_agg: ThreatIntelAggregator
    ) -> None:
        install(monkeypatch, CallRecorder(explode=True))

        rep = offline_agg.lookup(UNKNOWN_IP)

        assert rep.ip == UNKNOWN_IP
        assert rep.sources == {}
        assert rep.score == 0.0
        assert rep.malicious is False
        assert rep.tags == []
        assert rep.errors == []

    def test_unknown_ip_does_not_get_stale_tag_or_error(
        self, offline_agg: ThreatIntelAggregator
    ) -> None:
        rep = offline_agg.lookup(UNKNOWN_IP)

        assert "stale-cache" not in rep.tags
        assert not any("budget" in e or "failed" in e for e in rep.errors)

    def test_lookup_budget_is_untouched(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        install(monkeypatch, CallRecorder(explode=True))
        seed(state_dir, PUBLIC_IP)
        agg = ThreatIntelAggregator(make_intel(offline=True, max_lookups_per_run=0), state_dir)

        try:
            known = agg.lookup(PUBLIC_IP)
            unknown = agg.lookup(UNKNOWN_IP)
            used = agg._lookups_done  # noqa: SLF001 - verifying the budget counter
        finally:
            agg.close()

        assert used == 0
        assert known.score == 85.0  # a zero budget does not block cache answers
        assert known.errors == [] and unknown.errors == []

    def test_private_address_is_unchanged(self, offline_agg: ThreatIntelAggregator) -> None:
        rep = offline_agg.lookup(PRIVATE_IP)

        assert rep.tags == ["private-address"]
        assert rep.sources == {}
        assert rep.score == 0.0

    def test_private_address_is_not_answered_from_cache(
        self, state_dir: Path
    ) -> None:
        seed(state_dir, PRIVATE_IP)
        agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)

        try:
            rep = agg.lookup(PRIVATE_IP)
        finally:
            agg.close()

        assert rep.tags == ["private-address"]
        assert rep.sources == {}

    def test_result_is_memoised(self, state_dir: Path) -> None:
        seed(state_dir, PUBLIC_IP)
        agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)

        try:
            first = agg.lookup(PUBLIC_IP)
            second = agg.lookup(PUBLIC_IP)
        finally:
            agg.close()

        assert first is second

    def test_partial_cache_across_providers_merges_and_flags_stale(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        install(monkeypatch, CallRecorder(explode=True))
        seed(state_dir, PUBLIC_IP, {"score": 20.0, "tags": ["a"]}, provider="abuseipdb")
        seed(
            state_dir,
            PUBLIC_IP,
            {"score": 70.0, "malicious": True, "tags": ["b"]},
            provider="otx",
            age_seconds=TTL * 5,
        )
        config = make_intel(offline=True)
        config.otx.enabled = True
        config.otx.api_key = "fake-key-for-tests"
        agg = ThreatIntelAggregator(config, state_dir)

        try:
            rep = agg.lookup(PUBLIC_IP)
        finally:
            agg.close()

        assert set(rep.sources) == {"abuseipdb", "otx"}
        assert rep.score == 70.0  # a fresh entry is present: no discount
        assert rep.malicious is True
        assert rep.tags == ["a", "b", "stale-cache"]

    def test_zero_ttl_never_marks_entries_stale(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        seed(state_dir, PUBLIC_IP, age_seconds=10**7)
        config = make_intel(offline=True)
        config.cache_ttl_seconds = 0
        agg = ThreatIntelAggregator(config, state_dir)

        try:
            rep = agg.lookup(PUBLIC_IP)
        finally:
            agg.close()

        assert rep.score == 85.0
        assert "stale-cache" not in rep.tags

    @pytest.mark.parametrize("raw", ["{not json", "[1, 2, 3]", '"just a string"', ""])
    def test_corrupt_cache_payload_is_treated_as_unknown(
        self, state_dir: Path, raw: str
    ) -> None:
        seed(state_dir, PUBLIC_IP)
        conn = sqlite3.connect(str(state_dir / "intel_cache.db"))
        conn.execute("UPDATE intel_cache SET payload = ?", (raw,))
        conn.commit()
        conn.close()
        agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)

        try:
            rep = agg.lookup(PUBLIC_IP)
        finally:
            agg.close()

        assert rep.sources == {}
        assert rep.score == 0.0

    def test_close_is_idempotent(self, state_dir: Path) -> None:
        agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)

        agg.close()
        agg.close()


# -- offline hardening -------------------------------------------------------


def set_payload(state_dir: Path, raw: str) -> None:
    conn = sqlite3.connect(str(state_dir / "intel_cache.db"))
    conn.execute("UPDATE intel_cache SET payload = ?", (raw,))
    conn.commit()
    conn.close()


def offline_lookup(state_dir: Path, raw: str, ip: str = PUBLIC_IP) -> Any:
    seed(state_dir, ip)
    set_payload(state_dir, raw)
    agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)
    try:
        return agg.lookup(ip)
    finally:
        agg.close()


class TestOfflineHardening:
    def test_cache_connection_is_read_only(self, state_dir: Path) -> None:
        seed(state_dir, PUBLIC_IP, age_seconds=TTL * 10)
        agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)
        conn = agg._offline_conn  # noqa: SLF001 - verifying the connection mode
        assert conn is not None

        try:
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                conn.execute("DELETE FROM intel_cache")
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                conn.execute(
                    "INSERT INTO intel_cache (provider, ip, payload, created_at) "
                    "VALUES ('x', 'y', '{}', 0)"
                )
        finally:
            agg.close()

        assert row_count(state_dir) == 1

    def test_lookups_do_not_modify_the_cache_file(self, state_dir: Path) -> None:
        seed(state_dir, PUBLIC_IP, age_seconds=TTL * 10)
        db = state_dir / "intel_cache.db"
        agg = ThreatIntelAggregator(make_intel(offline=True), state_dir)
        before = db.stat().st_mtime_ns
        content = db.read_bytes()

        try:
            agg.lookup(PUBLIC_IP)
            agg.lookup(UNKNOWN_IP)
        finally:
            agg.close()

        assert db.stat().st_mtime_ns == before
        assert db.read_bytes() == content

    @pytest.mark.parametrize(
        "raw",
        [
            '{"score": NaN}',
            '{"score": Infinity}',
            '{"score": -Infinity}',
            '{"score": 1e999}',
            '{"score": "99"}',
            '{"score": null}',
            '{"score": true}',
            '{"score": [1]}',
            '{"score": {"a": 1}}',
        ],
    )
    def test_non_finite_or_non_numeric_score_cannot_raise_and_becomes_zero(
        self, state_dir: Path, raw: str
    ) -> None:
        rep = offline_lookup(state_dir, raw)

        assert rep.score == 0.0
        assert rep.sources["abuseipdb"]["score"] == 0.0
        assert "stale-cache" in rep.tags  # an unreliable payload is flagged

    @pytest.mark.parametrize(
        ("raw", "expected"), [('{"score": 1000}', 100.0), ('{"score": -5}', 0.0)]
    )
    def test_out_of_range_score_is_clamped(
        self, state_dir: Path, raw: str, expected: float
    ) -> None:
        rep = offline_lookup(state_dir, raw)

        assert rep.score == expected
        assert "stale-cache" not in rep.tags

    def test_over_long_strings_and_lists_are_clamped(self, state_dir: Path) -> None:
        payload = {
            "score": 50,
            "isp": "i" * 10_000,
            "country": "c" * 10_000,
            "tags": ["t" * 500] + [f"tag{n}" for n in range(1000)],
        }

        rep = offline_lookup(state_dir, json.dumps(payload))

        assert len(rep.isp or "") == 100
        assert len(rep.country or "") == 100
        assert len(rep.tags) == 32
        assert max(len(tag) for tag in rep.tags) <= 100

    def test_wrong_typed_fields_are_dropped(self, state_dir: Path) -> None:
        raw = json.dumps(
            {
                "score": 40,
                "malicious": "yes",
                "country": 123,
                "isp": ["x"],
                "tags": [1, None, {}, "ok"],
            }
        )

        rep = offline_lookup(state_dir, raw)

        assert rep.malicious is False
        assert rep.country is None
        assert rep.isp is None
        assert rep.tags == ["ok", "stale-cache"]

    def test_non_list_tags_are_dropped(self, state_dir: Path) -> None:
        rep = offline_lookup(state_dir, '{"score": 40, "tags": "scanner"}')

        assert rep.tags == ["stale-cache"]

    def test_deeply_nested_payload_cannot_raise(self, state_dir: Path) -> None:
        rep = offline_lookup(state_dir, "[" * 200_000)

        assert rep.sources == {}
        assert rep.score == 0.0


# -- online control --------------------------------------------------------


class TestOnlineModeUnchanged:
    def test_online_mode_calls_provider_and_fills_cache(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        recorder = install(monkeypatch, CallRecorder(PAYLOAD))
        agg = ThreatIntelAggregator(make_intel(offline=False), state_dir)

        try:
            rep = agg.lookup(PUBLIC_IP)
        finally:
            agg.close()

        assert recorder.calls == [PUBLIC_IP]
        assert rep.score == 85.0
        assert rep.malicious is True
        assert row_count(state_dir) == 1

    def test_online_mode_uses_fresh_cache_without_calling_provider(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        recorder = install(monkeypatch, CallRecorder(explode=True))
        seed(state_dir, PUBLIC_IP)
        agg = ThreatIntelAggregator(make_intel(offline=False), state_dir)

        try:
            rep = agg.lookup(PUBLIC_IP)
        finally:
            agg.close()

        assert recorder.calls == []
        assert rep.score == 85.0

    def test_online_mode_refetches_expired_entry_without_stale_tag(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        fresh = {"score": 5.0, "malicious": False}
        recorder = install(monkeypatch, CallRecorder(fresh))
        seed(state_dir, PUBLIC_IP, age_seconds=TTL * 10)
        agg = ThreatIntelAggregator(make_intel(offline=False), state_dir)

        try:
            rep = agg.lookup(PUBLIC_IP)
        finally:
            agg.close()

        assert recorder.calls == [PUBLIC_IP]
        assert rep.score == 5.0
        assert "stale-cache" not in rep.tags

    def test_online_mode_enforces_the_lookup_budget(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        recorder = install(monkeypatch, CallRecorder(PAYLOAD))
        agg = ThreatIntelAggregator(make_intel(offline=False, max_lookups_per_run=1), state_dir)

        try:
            first = agg.lookup(PUBLIC_IP)
            second = agg.lookup(OTHER_IP)
        finally:
            agg.close()

        assert recorder.calls == [PUBLIC_IP]
        assert first.errors == []
        assert any("budget exhausted" in e for e in second.errors)

    def test_online_unknown_ip_with_failing_provider_records_error(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        install(monkeypatch, CallRecorder(None))
        agg = ThreatIntelAggregator(make_intel(offline=False), state_dir)

        try:
            rep = agg.lookup(UNKNOWN_IP)
        finally:
            agg.close()

        assert rep.errors == ["abuseipdb: lookup failed"]

    def test_online_private_address_is_never_sent_out(
        self, monkeypatch: pytest.MonkeyPatch, state_dir: Path
    ) -> None:
        recorder = install(monkeypatch, CallRecorder(explode=True))
        agg = ThreatIntelAggregator(make_intel(offline=False), state_dir)

        try:
            rep = agg.lookup(PRIVATE_IP)
        finally:
            agg.close()

        assert recorder.calls == []
        assert rep.tags == ["private-address"]


# -- configuration ---------------------------------------------------------


class TestOfflineConfig:
    def test_offline_defaults_to_false(self) -> None:
        assert IntelConfig().offline is False

    def test_env_override_true_sets_the_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "config.yaml"
        cfg.write_text(f'state_dir: "{(tmp_path / "s").as_posix()}"\n', encoding="utf-8")
        monkeypatch.setenv("SENTINELAI_INTEL_OFFLINE", "true")

        assert load_config(cfg).intel.offline is True

    def test_env_override_beats_the_config_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            f'state_dir: "{(tmp_path / "s").as_posix()}"\nintel:\n  offline: false\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("SENTINELAI_INTEL_OFFLINE", "1")

        assert load_config(cfg).intel.offline is True

    def test_env_override_false_beats_file_true(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            f'state_dir: "{(tmp_path / "s").as_posix()}"\nintel:\n  offline: true\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("SENTINELAI_INTEL_OFFLINE", "false")

        assert load_config(cfg).intel.offline is False

    def test_yaml_flag_sets_offline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SENTINELAI_INTEL_OFFLINE", raising=False)
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            f'state_dir: "{(tmp_path / "s").as_posix()}"\nintel:\n  offline: true\n',
            encoding="utf-8",
        )

        assert load_config(cfg).intel.offline is True

    def test_non_boolean_offline_is_rejected_by_validation(self) -> None:
        config = IntelConfig()
        config.offline = "yes"  # type: ignore[assignment]

        with pytest.raises(ConfigError, match="intel.offline"):
            config.validate()
