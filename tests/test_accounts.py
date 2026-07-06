"""Tests for the account classification module."""

from __future__ import annotations

import pytest

from sentinelai.detection.accounts import (
    AccountKind,
    _BUILTIN_SERVICE_ACCOUNTS,
    classify_account,
    read_uid_min,
)


class TestClassifyAccount:
    def test_uid_zero_is_privileged(self) -> None:
        assert classify_account("backdoor", "0") is AccountKind.PRIVILEGED

    def test_uid_zero_overrides_service_name(self) -> None:
        assert classify_account("sshd", "0") is AccountKind.PRIVILEGED
        assert classify_account("nobody", "0") is AccountKind.PRIVILEGED

    def test_low_uid_is_system(self) -> None:
        assert classify_account("unknownsvc", "65") is AccountKind.SYSTEM
        assert classify_account("foo", "999") is AccountKind.SYSTEM

    def test_uid_at_boundary_is_human(self) -> None:
        assert classify_account("alice", "1000") is AccountKind.HUMAN

    def test_high_uid_is_human(self) -> None:
        assert classify_account("bob", "1001") is AccountKind.HUMAN

    def test_known_service_name_without_uid(self) -> None:
        for name in ("sshd", "www-data", "mysql", "nobody", "daemon"):
            assert classify_account(name, None) is AccountKind.SERVICE, name

    def test_systemd_wildcard(self) -> None:
        for name in ("systemd-resolve", "systemd-network", "systemd-timesync"):
            assert classify_account(name, None) is AccountKind.SERVICE, name

    def test_underscore_prefix_wildcard(self) -> None:
        assert classify_account("_chrony", None) is AccountKind.SERVICE
        assert classify_account("_apt", None) is AccountKind.SERVICE

    def test_unknown_name_no_uid_is_human(self) -> None:
        assert classify_account("attacker", None) is AccountKind.HUMAN

    def test_custom_allowlist(self) -> None:
        assert classify_account(
            "myapp-worker", "2001",
            service_allowlist=["myapp-*"],
        ) is AccountKind.SERVICE

    def test_custom_allowlist_exact(self) -> None:
        assert classify_account(
            "deploy", "2002",
            service_allowlist=["deploy"],
        ) is AccountKind.SERVICE

    def test_custom_allowlist_does_not_suppress_unknown(self) -> None:
        assert classify_account(
            "hacker", "2003",
            service_allowlist=["deploy"],
        ) is AccountKind.HUMAN

    def test_custom_uid_min(self) -> None:
        assert classify_account("x", "499", uid_min=500) is AccountKind.SYSTEM
        assert classify_account("x", "500", uid_min=500) is AccountKind.HUMAN

    def test_empty_uid_string_treated_as_absent(self) -> None:
        assert classify_account("alice", "") is AccountKind.HUMAN

    def test_none_username(self) -> None:
        assert classify_account(None, "1001") is AccountKind.HUMAN

    def test_known_service_with_high_uid_still_service(self) -> None:
        assert classify_account("postgres", "5432") is AccountKind.SERVICE


class TestReadUidMin:
    def test_missing_file_returns_default(self, tmp_path) -> None:
        assert read_uid_min(str(tmp_path / "nonexistent")) == 1000

    def test_parses_login_defs(self, tmp_path) -> None:
        defs = tmp_path / "login.defs"
        defs.write_text("# comment\nUID_MIN\t\t500\nUID_MAX\t\t60000\n")
        assert read_uid_min(str(defs)) == 500

    def test_malformed_value_returns_default(self, tmp_path) -> None:
        defs = tmp_path / "login.defs"
        defs.write_text("UID_MIN  abc\n")
        assert read_uid_min(str(defs)) == 1000


class TestBuiltinAllowlist:
    def test_contains_essential_accounts(self) -> None:
        for name in ("nobody", "sshd", "www-data", "mysql", "postgres",
                      "redis", "mongodb", "daemon", "messagebus", "tcpdump"):
            assert name in _BUILTIN_SERVICE_ACCOUNTS, f"{name} missing from builtin list"

    def test_contains_wildcards(self) -> None:
        wildcards = [p for p in _BUILTIN_SERVICE_ACCOUNTS if "*" in p]
        assert "systemd-*" in wildcards
        assert "_*" in wildcards
