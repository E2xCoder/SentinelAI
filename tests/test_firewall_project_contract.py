"""Contract between SentinelAI and the external Firewall Automation project.

The project lives in a git-ignored folder, so these tests only run on a
machine that has it; elsewhere (CI) they are skipped. Only ``dry_run`` and an
injected runner are used: no real ufw/sudo command is ever executed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from sentinelai.config.models import FirewallConfig
from sentinelai.firewall.adapters import PythonModuleAdapter

_PROJECT = Path(__file__).resolve().parents[1] / "linux-firewall-automation-main"

pytestmark = pytest.mark.skipif(
    not (_PROJECT / "firewall_manager.py").is_file(),
    reason="Firewall Automation project not present (git-ignored folder)",
)

_IP = "203.0.113.5"


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(_PROJECT))
    monkeypatch.delitem(sys.modules, "firewall_manager", raising=False)
    monkeypatch.chdir(tmp_path)  # firewall.log lands here, not in the repo
    cfg = FirewallConfig(
        adapter="python",
        module="firewall_manager",
        attribute="FirewallManager",
        init_kwargs={"state_file": str(tmp_path / "state.json"), "dry_run": True},
    )
    return PythonModuleAdapter(cfg)


def test_block_list_unblock_roundtrip(adapter) -> None:
    assert adapter.block_ip(_IP) is True
    assert adapter.is_blocked(_IP) is True
    assert adapter.list_blocked() == [_IP]
    assert adapter.unblock_ip(_IP) is True
    assert adapter.is_blocked(_IP) is False
    assert adapter.list_blocked() == []


def test_temporary_block_is_listed(adapter) -> None:
    assert adapter.temporary_block(_IP, 60) is True
    assert adapter.list_blocked() == [_IP]


def test_bad_input_returns_false_never_raises(adapter) -> None:
    assert adapter.block_ip("not-an-ip") is False
    assert adapter.unblock_ip("not-an-ip") is False
    assert adapter.temporary_block(_IP, 0) is False
    assert adapter.unblock_ip(_IP) is False  # never blocked


def test_failed_ufw_command_returns_false(tmp_path, monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(_PROJECT))
    monkeypatch.delitem(sys.modules, "firewall_manager", raising=False)
    monkeypatch.chdir(tmp_path)
    import firewall_manager

    manager = firewall_manager.FirewallManager(
        state_file=str(tmp_path / "s.json"), runner=lambda command: False
    )
    assert manager.block_ip(_IP) is False
    assert manager.list_blocked() == []


def test_import_does_not_start_the_menu() -> None:
    # A module-level input() loop would hang or fail here instead of returning.
    result = subprocess.run(
        [sys.executable, "-c", "import firewall_manager"],
        cwd=_PROJECT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
