"""Desktop interface: loopback server, access checks and a scan end to end.

The server binds to 127.0.0.1 on a free port; nothing leaves this machine.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sentinelai.config.models import SentinelConfig
from sentinelai.gui import launcher
from sentinelai.gui.server import GuiServer, gui_config, sample_log_path

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "auth.log"


@pytest.fixture
def server(tmp_path: Path) -> Iterator[GuiServer]:
    config = SentinelConfig()
    config.state_dir = str(tmp_path / "state")
    config.intel.enabled = False
    gui = GuiServer(config=config)
    gui.start()
    yield gui
    gui.stop()


def call(
    server: GuiServer,
    path: str,
    *,
    data: bytes | None = None,
    token: str | None = "",
    host: str | None = None,
) -> tuple[int, Any]:
    headers = {}
    if token is not None:
        headers["X-Sentinel-Token"] = token or server.token
    if host:
        headers["Host"] = host
    request = urllib.request.Request(  # noqa: S310
        f"http://127.0.0.1:{server.port}{path}", data=data, headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            body = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read()
        status = exc.code
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


def wait_done(server: GuiServer, job_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        _, state = call(server, f"/api/job/{job_id}")
        if state["status"] != "running":
            return state  # type: ignore[no-any-return]
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_page_is_served_with_a_strict_csp(server: GuiServer) -> None:
    request = urllib.request.Request(f"http://127.0.0.1:{server.port}/")  # noqa: S310
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        page = response.read().decode("utf-8")
        csp = response.headers["Content-Security-Policy"]
    assert "SentinelAI" in page and "E2xCoder" in page
    assert "default-src 'none'" in csp
    assert server.token not in page


def test_api_needs_the_token(server: GuiServer) -> None:
    assert call(server, "/api/info", token=None)[0] == 401
    assert call(server, "/api/info", token="wrong")[0] == 401
    assert call(server, "/api/quit", data=b"{}", token=None)[0] == 401
    assert not server.quit_requested.is_set()
    status, info = call(server, "/api/info")
    assert status == 200 and info["version"]


def test_foreign_host_header_is_rejected(server: GuiServer) -> None:
    """DNS rebinding: a page on evil.example resolving to 127.0.0.1."""
    assert call(server, "/api/info", host=f"evil.example:{server.port}")[0] == 403
    assert call(server, "/", token=None, host="evil.example")[0] == 403


def test_token_is_only_in_the_url_fragment(server: GuiServer) -> None:
    assert server.url == f"http://127.0.0.1:{server.port}/#t={server.token}"


def test_scan_by_path_end_to_end(server: GuiServer) -> None:
    body = json.dumps({"path": str(EXAMPLE), "ai": False}).encode()
    status, job = call(server, "/api/scan", data=body)
    assert status == 202
    state = wait_done(server, job["id"])
    assert state["status"] == "done", state
    assert state["events"] > 0
    _, result = call(server, f"/api/job/{job['id']}/result")
    assert result["alerts_total"] == len(result["alerts"]) > 0
    scores = [a["risk"]["score"] for a in result["alerts"]]
    assert scores == sorted(scores, reverse=True)
    assert "sample_events" not in result["alerts"][0]
    assert result["report"]["summary"]["events_analyzed"] == state["events"]
    status, alert = call(server, f"/api/job/{job['id']}/alert?i=0")
    assert status == 200 and "sample_events" in alert
    assert call(server, f"/api/job/{job['id']}/alert?i=9999")[0] == 404
    status, html = call(server, f"/api/job/{job['id']}/report.html")
    assert status == 200 and b"<html" in html.lower()
    _, history = call(server, "/api/history")
    assert len(history["alerts"]) == result["alerts_total"]


def test_upload_scans_and_removes_the_temp_file(server: GuiServer) -> None:
    status, job = call(
        server, "/api/upload?name=..%2F..%2Fauth.log&ai=0", data=EXAMPLE.read_bytes()
    )
    assert status == 202
    assert job["source"] == "auth.log"
    assert wait_done(server, job["id"])["status"] == "done"
    assert not [p for p in server._upload_dir.rglob("*") if p.is_file()]


def test_sample_scan(server: GuiServer) -> None:
    assert sample_log_path() is not None
    status, job = call(server, "/api/scan-sample", data=b"{}")
    assert status == 202
    assert wait_done(server, job["id"])["status"] == "done"


def test_bad_requests_are_clean_errors(server: GuiServer) -> None:
    missing = json.dumps({"path": "/no/such/file.log"}).encode()
    status, body = call(server, "/api/scan", data=missing)
    assert status == 400 and "error" in body
    assert call(server, "/api/scan", data=b"{}")[0] == 400
    assert call(server, "/api/scan", data=b"not json")[0] == 400
    assert call(server, "/api/job/0000000000000000")[0] == 404
    assert call(server, "/api/job/..%2F..")[0] == 404
    assert call(server, "/api/nope")[0] == 404
    assert call(server, "/etc/passwd", token=None)[0] == 404


def test_rules_listing(server: GuiServer) -> None:
    status, rules = call(server, "/api/rules")
    assert status == 200
    assert {"R001", "R007"} <= {r["id"] for r in rules}


def test_quit_sets_the_flag(server: GuiServer) -> None:
    assert call(server, "/api/quit", data=b"{}")[0] == 200
    assert server.quit_requested.is_set()


def test_gui_config_never_enables_response(monkeypatch: pytest.MonkeyPatch) -> None:
    def loaded() -> SentinelConfig:
        config = SentinelConfig()
        config.response.enabled = True
        config.firewall.adapter = "python"
        return config

    monkeypatch.setattr("sentinelai.gui.server.load_config", loaded)
    config = gui_config()
    assert config.response.enabled is False
    assert config.firewall.adapter == "dry_run"


def test_self_test_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELAI_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "selftest.txt"
    assert launcher.self_test(str(out)) == 0
    assert "SELFTEST OK" in out.read_text(encoding="utf-8")


def test_browser_lookup_returns_a_file_or_none() -> None:
    found = launcher.find_app_browser()
    assert found is None or Path(found).is_file()
