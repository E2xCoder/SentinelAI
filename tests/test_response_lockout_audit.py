"""Tests for the self-lockout guard and the append-only response audit log."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinelai.config.models import ResponseConfig
from sentinelai.firewall import lockout
from sentinelai.firewall.audit import ResponseAudit
from sentinelai.firewall.lockout import LockoutGuard

_NO_ENV: dict[str, str] = {}


def _cfg(**overrides: object) -> ResponseConfig:
    """A config with every optional protection off unless overridden."""
    values: dict[str, object] = {
        "admin_ranges": [],
        "protect_ssh_peer": False,
        "protect_gateway": False,
        "protect_own_addresses": False,
    }
    values.update(overrides)
    return ResponseConfig(**values)  # type: ignore[arg-type]


def _guard(config: ResponseConfig, **kwargs: object) -> LockoutGuard:
    kwargs.setdefault("env", _NO_ENV)
    kwargs.setdefault("gateways", lambda: set())
    kwargs.setdefault("own_addresses", lambda: set())
    return LockoutGuard(config, **kwargs)  # type: ignore[arg-type]


# -- lockout: admin ranges -----------------------------------------------------------------


class TestAdminRanges:
    def test_ip_inside_ipv4_cidr_is_protected_and_reason_names_range(self) -> None:
        guard = _guard(_cfg(admin_ranges=["203.0.113.0/24"]))
        reason = guard.protected_reason("203.0.113.77")
        assert reason is not None
        assert "203.0.113.0/24" in reason

    def test_ip_outside_cidr_is_not_protected(self) -> None:
        guard = _guard(_cfg(admin_ranges=["203.0.113.0/24"]))
        assert guard.protected_reason("203.0.114.1") is None

    def test_bare_ipv4_entry_matches_only_that_address(self) -> None:
        guard = _guard(_cfg(admin_ranges=["198.51.100.7"]))
        reason = guard.protected_reason("198.51.100.7")
        assert reason is not None
        assert "198.51.100.7" in reason
        assert guard.protected_reason("198.51.100.8") is None

    def test_ipv6_cidr_matches_inside_address(self) -> None:
        guard = _guard(_cfg(admin_ranges=["2001:db8::/32"]))
        reason = guard.protected_reason("2001:db8::1234")
        assert reason is not None
        assert "2001:db8::/32" in reason
        assert guard.protected_reason("2001:db9::1") is None

    def test_bare_ipv6_entry_matches(self) -> None:
        guard = _guard(_cfg(admin_ranges=["2001:db8::5"]))
        assert guard.protected_reason("2001:db8::5") is not None
        assert guard.protected_reason("2001:db8::6") is None

    def test_ipv4_address_never_matches_ipv6_range(self) -> None:
        guard = _guard(_cfg(admin_ranges=["::/0"]))
        assert guard.protected_reason("203.0.113.5") is None

    def test_host_bits_in_cidr_are_tolerated(self) -> None:
        guard = _guard(_cfg(admin_ranges=["203.0.113.9/24"]))
        reason = guard.protected_reason("203.0.113.200")
        assert reason is not None
        assert "203.0.113.0/24" in reason

    def test_invalid_admin_entries_are_ignored(self) -> None:
        guard = _guard(_cfg(admin_ranges=["not-an-ip", "", "300.1.1.1/8", "203.0.113.0/24"]))
        assert guard.protected_reason("203.0.113.1") is not None
        assert guard.protected_reason("8.8.8.8") is None

    def test_ipv4_mapped_ipv6_matches_ipv4_range(self) -> None:
        guard = _guard(_cfg(admin_ranges=["192.0.2.0/24"]))
        assert guard.protected_reason("::ffff:192.0.2.1") is not None

    def test_zone_id_suffix_is_stripped(self) -> None:
        guard = _guard(_cfg(admin_ranges=["fe80::/10"]))
        assert guard.protected_reason("fe80::1%eth0") is not None


# -- lockout: SSH peer ---------------------------------------------------------------------


class TestSshPeer:
    def test_ssh_connection_peer_is_protected(self) -> None:
        env = {"SSH_CONNECTION": "203.0.113.50 51234 198.51.100.1 22"}
        guard = _guard(_cfg(protect_ssh_peer=True), env=env)
        reason = guard.protected_reason("203.0.113.50")
        assert reason is not None
        assert "SSH" in reason

    def test_ssh_client_peer_is_protected(self) -> None:
        env = {"SSH_CLIENT": "203.0.113.51 51234 22"}
        guard = _guard(_cfg(protect_ssh_peer=True), env=env)
        assert guard.protected_reason("203.0.113.51") is not None

    def test_only_the_peer_is_blocked_not_the_server_address(self) -> None:
        env = {"SSH_CONNECTION": "203.0.113.50 51234 198.51.100.1 22"}
        guard = _guard(_cfg(protect_ssh_peer=True), env=env)
        assert guard.protected_reason("198.51.100.1") is None
        assert guard.protected_reason("203.0.113.51") is None

    def test_ipv6_ssh_peer_is_protected(self) -> None:
        env = {"SSH_CONNECTION": "2001:db8::7 51234 2001:db8::1 22"}
        guard = _guard(_cfg(protect_ssh_peer=True), env=env)
        assert guard.protected_reason("2001:db8::7") is not None

    def test_flag_off_disables_ssh_check(self) -> None:
        env = {"SSH_CONNECTION": "203.0.113.50 51234 198.51.100.1 22"}
        guard = _guard(_cfg(protect_ssh_peer=False), env=env)
        assert guard.protected_reason("203.0.113.50") is None

    @pytest.mark.parametrize("value", ["", "garbage", "999.9.9.9 1 2 3", "   ", "; rm -rf /"])
    def test_malformed_ssh_value_is_ignored(self, value: str) -> None:
        env = {"SSH_CONNECTION": value, "SSH_CLIENT": value}
        guard = _guard(_cfg(protect_ssh_peer=True), env=env)
        assert guard.protected_reason("203.0.113.50") is None

    def test_missing_ssh_env_protects_nothing(self) -> None:
        guard = _guard(_cfg(protect_ssh_peer=True), env={})
        assert guard.protected_reason("203.0.113.50") is None

    def test_both_variables_are_honoured(self) -> None:
        env = {
            "SSH_CONNECTION": "203.0.113.50 1 198.51.100.1 22",
            "SSH_CLIENT": "203.0.113.51 1 22",
        }
        guard = _guard(_cfg(protect_ssh_peer=True), env=env)
        assert guard.protected_reason("203.0.113.50") is not None
        assert guard.protected_reason("203.0.113.51") is not None


# -- lockout: gateway and own addresses ----------------------------------------------------


class TestGatewayAndOwnAddresses:
    def test_injected_gateway_is_protected(self) -> None:
        guard = _guard(_cfg(protect_gateway=True), gateways=lambda: {"192.0.2.1"})
        reason = guard.protected_reason("192.0.2.1")
        assert reason is not None
        assert "gateway" in reason

    def test_gateway_flag_off_disables_check(self) -> None:
        guard = _guard(_cfg(protect_gateway=False), gateways=lambda: {"192.0.2.1"})
        assert guard.protected_reason("192.0.2.1") is None

    def test_injected_own_address_is_protected(self) -> None:
        guard = _guard(_cfg(protect_own_addresses=True), own_addresses=lambda: {"198.51.100.9"})
        reason = guard.protected_reason("198.51.100.9")
        assert reason is not None
        assert "host" in reason

    def test_own_address_flag_off_disables_check(self) -> None:
        guard = _guard(_cfg(protect_own_addresses=False), own_addresses=lambda: {"198.51.100.9"})
        assert guard.protected_reason("198.51.100.9") is None

    def test_unrelated_ip_is_not_protected_with_every_flag_on(self) -> None:
        guard = _guard(
            _cfg(
                admin_ranges=["203.0.113.0/24"],
                protect_ssh_peer=True,
                protect_gateway=True,
                protect_own_addresses=True,
            ),
            env={"SSH_CONNECTION": "203.0.113.50 1 198.51.100.1 22"},
            gateways=lambda: {"192.0.2.1"},
            own_addresses=lambda: {"198.51.100.9"},
        )
        assert guard.protected_reason("8.8.8.8") is None

    def test_ipv4_mapped_ipv6_matches_ipv4_gateway(self) -> None:
        guard = _guard(_cfg(protect_gateway=True), gateways=lambda: {"192.0.2.1"})
        assert guard.protected_reason("::ffff:192.0.2.1") is not None

    def test_ipv4_mapped_ipv6_in_provider_matches_plain_ipv4(self) -> None:
        guard = _guard(_cfg(protect_gateway=True), gateways=lambda: {"::ffff:192.0.2.1"})
        assert guard.protected_reason("192.0.2.1") is not None

    def test_invalid_entries_from_providers_are_skipped(self) -> None:
        guard = _guard(
            _cfg(protect_gateway=True),
            gateways=lambda: {"junk", "", "192.0.2.1"},
        )
        assert guard.protected_reason("192.0.2.1") is not None

    def test_raising_provider_fails_closed_without_raising(self) -> None:
        def boom() -> set[str]:
            raise RuntimeError("no network")

        guard = _guard(
            _cfg(protect_gateway=True, protect_own_addresses=True),
            gateways=boom,
            own_addresses=boom,
        )
        assert guard.protected_reason("192.0.2.1") == "could not evaluate lockout protection"

    def test_order_admin_range_reported_before_gateway(self) -> None:
        guard = _guard(
            _cfg(admin_ranges=["192.0.2.0/24"], protect_gateway=True),
            gateways=lambda: {"192.0.2.1"},
        )
        reason = guard.protected_reason("192.0.2.1")
        assert reason is not None
        assert "admin range" in reason


# -- lockout: input handling and caching ---------------------------------------------------


class TestInputsAndCaching:
    @pytest.mark.parametrize("value", ["", "not-an-ip", "999.1.1.1", "1.2.3", "1.2.3.4/24"])
    def test_invalid_ip_string_returns_none(self, value: str) -> None:
        guard = _guard(_cfg(admin_ranges=["0.0.0.0/0"]))
        assert guard.protected_reason(value) is None

    def test_non_string_ip_returns_none(self) -> None:
        guard = _guard(_cfg(admin_ranges=["0.0.0.0/0"]))
        assert guard.protected_reason(None) is None  # type: ignore[arg-type]
        assert guard.protected_reason(12345) is None  # type: ignore[arg-type]

    def test_gateway_provider_is_called_once_until_refresh(self) -> None:
        calls: list[int] = []

        def provider() -> set[str]:
            calls.append(1)
            return {"192.0.2.1"}

        guard = _guard(_cfg(protect_gateway=True), gateways=provider)
        for _ in range(3):
            assert guard.protected_reason("192.0.2.1") is not None
            assert guard.protected_reason("8.8.8.8") is None
        assert len(calls) == 1
        guard.refresh()
        guard.protected_reason("192.0.2.1")
        assert len(calls) == 2

    def test_own_address_provider_is_called_once_until_refresh(self) -> None:
        calls: list[int] = []

        def provider() -> set[str]:
            calls.append(1)
            return {"198.51.100.9"}

        guard = _guard(_cfg(protect_own_addresses=True), own_addresses=provider)
        for _ in range(3):
            guard.protected_reason("198.51.100.9")
        assert len(calls) == 1
        guard.refresh()
        guard.protected_reason("198.51.100.9")
        assert len(calls) == 2

    def test_refresh_picks_up_changed_provider_result(self) -> None:
        state = {"gw": {"192.0.2.1"}}
        guard = _guard(_cfg(protect_gateway=True), gateways=lambda: state["gw"])
        assert guard.protected_reason("192.0.2.2") is None
        state["gw"] = {"192.0.2.2"}
        assert guard.protected_reason("192.0.2.2") is None  # still cached
        guard.refresh()
        assert guard.protected_reason("192.0.2.2") is not None

    def test_refresh_rereads_ssh_environment(self) -> None:
        env: dict[str, str] = {}
        guard = _guard(_cfg(protect_ssh_peer=True), env=env)
        assert guard.protected_reason("203.0.113.50") is None
        env["SSH_CONNECTION"] = "203.0.113.50 1 198.51.100.1 22"
        guard.refresh()
        assert guard.protected_reason("203.0.113.50") is not None

    def test_providers_not_called_when_flags_are_off(self) -> None:
        def fail() -> set[str]:
            raise AssertionError("must not be called")

        guard = _guard(_cfg(), gateways=fail, own_addresses=fail)
        assert guard.protected_reason("192.0.2.1") is None


# -- lockout: default implementations ------------------------------------------------------


class TestDefaults:
    def test_default_own_addresses_never_raises_and_includes_loopback(self) -> None:
        addresses = lockout.default_own_addresses()
        assert "127.0.0.1" in addresses
        assert "::1" in addresses

    def test_default_own_addresses_survives_total_socket_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_args: object, **_kwargs: object) -> None:
            raise OSError("sockets disabled")

        monkeypatch.setattr(lockout.socket, "gethostname", boom)
        monkeypatch.setattr(lockout.socket, "socket", boom)
        assert lockout.default_own_addresses() >= {"127.0.0.1", "::1"}

    def test_default_gateways_never_raises(self) -> None:
        assert isinstance(lockout.default_gateways(), set)

    def test_default_gateways_is_empty_off_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(lockout.sys, "platform", "win32")
        assert lockout.default_gateways() == set()

    def test_default_gateways_parses_proc_net_route(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        route = tmp_path / "route"
        route.write_text(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\n"  # 192.168.2.1
            "eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"  # not a default route
            "eth1\t00000000\t00000000\t0001\t0\t0\t200\t00000000\n"  # gateway 0.0.0.0
            "eth2\t00000000\tZZZZZZZZ\t0003\t0\t0\t300\t00000000\n"  # bad hex
            "short\n",
            encoding="ascii",
        )
        monkeypatch.setattr(lockout.sys, "platform", "linux")
        monkeypatch.setattr(lockout, "_ROUTE_FILE", str(route))
        assert lockout.default_gateways() == {"192.168.2.1"}

    def test_default_gateways_missing_route_file_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(lockout.sys, "platform", "linux")
        monkeypatch.setattr(lockout, "_ROUTE_FILE", str(tmp_path / "missing"))
        assert lockout.default_gateways() == set()

    def test_guard_with_default_providers_never_raises(self) -> None:
        guard = LockoutGuard(_cfg(protect_gateway=True, protect_own_addresses=True), env={})
        assert guard.protected_reason("127.0.0.1") is not None
        assert guard.protected_reason("not-an-ip") is None


# -- audit ---------------------------------------------------------------------------------


_FIXED_NOW = datetime(2026, 1, 7, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def audit(tmp_path: Path) -> ResponseAudit:
    return ResponseAudit(tmp_path / "audit" / "response.jsonl", now=lambda: _FIXED_NOW)


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


class TestAuditRecord:
    def test_record_appends_valid_json_line_with_core_fields(self, audit: ResponseAudit) -> None:
        audit.record("blocked", ip="203.0.113.5", reason="brute force", alert_id=7)
        (line,) = _lines(audit.path)
        obj = json.loads(line)
        assert obj["event"] == "response"
        assert obj["decision"] == "blocked"
        assert obj["ip"] == "203.0.113.5"
        assert obj["reason"] == "brute force"
        assert obj["alert_id"] == 7
        assert obj["ts"] == _FIXED_NOW.isoformat()

    def test_none_fields_are_omitted(self, audit: ResponseAudit) -> None:
        audit.record("skipped")
        obj = json.loads(_lines(audit.path)[0])
        for key in ("ip", "alert_id", "rule_id", "risk_level", "mode", "run_id"):
            assert key not in obj
        assert obj["decision"] == "skipped"

    def test_extra_fields_are_recorded(self, audit: ResponseAudit) -> None:
        audit.record("failed", ip="203.0.113.5", error="adapter exploded", attempt=2)
        obj = json.loads(_lines(audit.path)[0])
        assert obj["error"] == "adapter exploded"
        assert obj["attempt"] == 2

    def test_keys_are_sorted(self, audit: ResponseAudit) -> None:
        audit.record("blocked", ip="203.0.113.5", rule_id="R001", run_id="r1", mode="auto")
        obj = json.loads(_lines(audit.path)[0])
        assert list(obj) == sorted(obj)

    def test_naive_clock_is_treated_as_utc(self, tmp_path: Path) -> None:
        log = ResponseAudit(tmp_path / "a.jsonl", now=lambda: datetime(2026, 1, 7, 12, 0, 0))
        log.record("queued")
        obj = json.loads(_lines(log.path)[0])
        assert obj["ts"] == "2026-01-07T12:00:00+00:00"

    def test_default_clock_yields_utc_timestamp(self, tmp_path: Path) -> None:
        log = ResponseAudit(tmp_path / "a.jsonl")
        log.record("queued")
        ts = json.loads(_lines(log.path)[0])["ts"]
        assert datetime.fromisoformat(ts).utcoffset() == timezone.utc.utcoffset(None)

    def test_parent_directory_is_created(self, tmp_path: Path) -> None:
        log = ResponseAudit(tmp_path / "deep" / "er" / "audit.jsonl")
        log.record("blocked", ip="203.0.113.5")
        assert log.path.is_file()

    def test_path_accepts_string(self, tmp_path: Path) -> None:
        log = ResponseAudit(str(tmp_path / "s.jsonl"))
        log.record("blocked")
        assert isinstance(log.path, Path)
        assert log.path.is_file()


class TestAuditInjectionResistance:
    def test_newline_in_reason_cannot_forge_extra_line(self, audit: ResponseAudit) -> None:
        audit.record("skipped", ip="203.0.113.5", reason='x\n{"decision":"blocked"}')
        lines = _lines(audit.path)
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj["decision"] == "skipped"

    def test_crlf_and_unicode_line_separators_stay_one_line(self, audit: ResponseAudit) -> None:
        audit.record("skipped", reason="a\r\nb c d\x85e\x0bf\x0cg")
        raw = audit.path.read_text(encoding="utf-8")
        assert len(raw.splitlines()) == 1
        assert raw.count("\n") == 1

    def test_control_characters_are_removed(self, audit: ResponseAudit) -> None:
        audit.record("skipped", reason="a\x00b\x1b[31mc\x07d\x7fe")
        obj = json.loads(_lines(audit.path)[0])
        assert all(ch.isprintable() for ch in obj["reason"])
        assert obj["reason"].startswith("ab")

    def test_forged_value_in_ip_field_is_flattened(self, audit: ResponseAudit) -> None:
        audit.record("blocked", ip='1.1.1.1"\n{"decision":"blocked","ip":"2.2.2.2"}')
        lines = _lines(audit.path)
        assert len(lines) == 1
        assert json.loads(lines[0])["decision"] == "blocked"

    def test_nested_values_in_extra_are_sanitised(self, audit: ResponseAudit) -> None:
        audit.record("failed", detail={"k\ney": ["a\nb", ("c\r\nd",)]})
        raw = audit.path.read_text(encoding="utf-8")
        assert raw.count("\n") == 1
        obj = json.loads(raw)
        assert obj["detail"] == {"k ey": ["a b", ["c  d"]]}

    def test_long_values_are_capped_at_500_characters(self, audit: ResponseAudit) -> None:
        audit.record("skipped", reason="y" * 5000)
        obj = json.loads(_lines(audit.path)[0])
        assert len(obj["reason"]) == 500

    def test_value_of_exactly_500_characters_is_kept(self, audit: ResponseAudit) -> None:
        audit.record("skipped", reason="z" * 500)
        assert len(json.loads(_lines(audit.path)[0])["reason"]) == 500

    def test_non_ascii_text_is_preserved(self, audit: ResponseAudit) -> None:
        audit.record("skipped", reason="yasakli adres şğü")
        assert json.loads(_lines(audit.path)[0])["reason"] == "yasakli adres şğü"

    def test_unserialisable_extra_is_stringified_not_raised(self, audit: ResponseAudit) -> None:
        audit.record("failed", payload=object())
        obj = json.loads(_lines(audit.path)[0])
        assert isinstance(obj["payload"], str)


class TestAuditAppendOnly:
    def test_file_only_grows_across_many_writes(self, audit: ResponseAudit) -> None:
        sizes: list[int] = []
        for i in range(25):
            audit.record("blocked", ip=f"203.0.113.{i}", alert_id=i)
            sizes.append(audit.path.stat().st_size)
        assert sizes == sorted(set(sizes))
        assert len(_lines(audit.path)) == 25

    def test_earlier_lines_are_never_rewritten(self, audit: ResponseAudit) -> None:
        audit.record("blocked", ip="203.0.113.1")
        first = _lines(audit.path)[0]
        audit.record("denied", ip="203.0.113.2")
        lines = _lines(audit.path)
        assert lines[0] == first
        assert len(lines) == 2

    def test_new_instance_appends_to_existing_file(self, audit: ResponseAudit) -> None:
        audit.record("blocked", ip="203.0.113.1")
        other = ResponseAudit(audit.path)
        other.record("denied", ip="203.0.113.2")
        assert [r["decision"] for r in other.read()] == ["blocked", "denied"]

    def test_write_failure_is_swallowed(self, tmp_path: Path) -> None:
        directory = tmp_path / "is_a_dir"
        directory.mkdir()
        log = ResponseAudit(directory)
        log.record("blocked", ip="203.0.113.5")  # must not raise
        assert directory.is_dir()

    def test_unwritable_parent_is_swallowed(self, tmp_path: Path) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        log = ResponseAudit(blocker / "child" / "audit.jsonl")
        log.record("blocked")  # parent "directory" is a regular file; must not raise
        assert log.read() == []


class TestAuditRead:
    def test_read_returns_last_n_in_order(self, audit: ResponseAudit) -> None:
        for i in range(10):
            audit.record("blocked", alert_id=i)
        assert [r["alert_id"] for r in audit.read(3)] == [7, 8, 9]

    def test_read_default_limit_returns_everything_when_small(self, audit: ResponseAudit) -> None:
        for i in range(5):
            audit.record("blocked", alert_id=i)
        assert len(audit.read()) == 5

    def test_read_limit_larger_than_file_returns_all(self, audit: ResponseAudit) -> None:
        audit.record("blocked")
        assert len(audit.read(1000)) == 1

    def test_read_missing_file_returns_empty_list(self, tmp_path: Path) -> None:
        assert ResponseAudit(tmp_path / "nope.jsonl").read() == []

    @pytest.mark.parametrize("limit", [0, -1, -100])
    def test_read_non_positive_limit_returns_empty_list(
        self, audit: ResponseAudit, limit: int
    ) -> None:
        audit.record("blocked")
        assert audit.read(limit) == []

    def test_read_skips_malformed_blank_and_non_object_lines(self, audit: ResponseAudit) -> None:
        audit.record("blocked", alert_id=1)
        with audit.path.open("a", encoding="utf-8") as handle:
            handle.write("this is not json\n\n   \n[1, 2, 3]\n\"str\"\n{\"truncated\": \n")
        audit.record("denied", alert_id=2)
        assert [r["alert_id"] for r in audit.read()] == [1, 2]

    def test_read_tolerates_invalid_utf8(self, audit: ResponseAudit) -> None:
        audit.record("blocked", alert_id=1)
        with audit.path.open("ab") as handle:
            handle.write(b"\xff\xfe\xfa garbage\n")
        audit.record("denied", alert_id=2)
        assert [r["alert_id"] for r in audit.read()] == [1, 2]

    def test_read_on_directory_path_returns_empty_list(self, tmp_path: Path) -> None:
        assert ResponseAudit(tmp_path).read() == []
