"""Open the desktop interface in its own window.

A Chromium-family browser started with ``--app=URL`` shows a page in a plain
window without tabs or an address bar, which is what users expect from a
desktop application. Microsoft Edge ships with Windows, so that path needs no
extra download there. When no such browser is found, the page opens in the
default browser instead.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

from sentinelai.gui.server import GuiServer
from sentinelai.utils.logging import get_logger
from sentinelai.utils.paths import default_state_dir

_LOGGER = get_logger("gui.launcher")

#: Stop a browser-tab session this long after the page stops pinging.
#: Browsers throttle timers in hidden tabs to about one per minute.
_IDLE_SECONDS = 180.0
#: An app window that exits faster than this handed off to another process.
_HANDOFF_SECONDS = 4.0


def find_app_browser() -> str | None:
    """Path of a Chromium-family browser that supports ``--app``, if any."""
    candidates: list[str] = []
    if sys.platform == "win32":
        for root in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA"):
            base = os.environ.get(root)
            if base:
                candidates += [
                    rf"{base}\Microsoft\Edge\Application\msedge.exe",
                    rf"{base}\Google\Chrome\Application\chrome.exe",
                    rf"{base}\BraveSoftware\Brave-Browser\Application\brave.exe",
                ]
    elif sys.platform == "darwin":
        candidates += [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    else:
        for name in (
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "microsoft-edge",
            "brave-browser",
        ):
            found = shutil.which(name)
            if found:
                candidates.append(found)
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    return None


def _open_app_window(browser: str, url: str) -> subprocess.Popen[bytes] | None:
    # A private profile makes the browser start a new process that lives as
    # long as the window, instead of handing the URL to a running browser.
    profile = default_state_dir() / "gui-profile"
    try:
        return subprocess.Popen(  # noqa: S603 - fixed argument list, no shell
            [
                browser,
                f"--app={url}",
                f"--user-data-dir={profile}",
                "--no-first-run",
                "--no-default-browser-check",
                "--window-size=1320,880",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        _LOGGER.warning("Could not start %s: %s", browser, exc)
        return None


def _wait_for_tab(server: GuiServer) -> None:
    while not server.quit_requested.wait(2.0):
        if time.monotonic() - server.last_ping > _IDLE_SECONDS:
            return


def run_gui(port: int = 0, open_window: bool = True) -> None:
    """Start the interface and block until its window is closed."""
    server = GuiServer(port=port)
    server.start()
    print(f"SentinelAI interface: {server.url}", flush=True)  # noqa: T201
    try:
        if not open_window:
            server.quit_requested.wait()
            return
        browser = find_app_browser()
        process = _open_app_window(browser, server.url) if browser else None
        if process is not None:
            started = time.monotonic()
            while process.poll() is None and not server.quit_requested.wait(0.5):
                pass
            if server.quit_requested.is_set() or time.monotonic() - started > _HANDOFF_SECONDS:
                if process.poll() is None:
                    process.terminate()
                return
            # The process handed off to an existing browser: the window is
            # open, but only the page's pings tell us when it closes.
            server.last_ping = time.monotonic()
        else:
            webbrowser.open(server.url)
        _wait_for_tab(server)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


def self_test(output: str | None = None) -> int:
    """Start the server, scan the bundled sample over HTTP and report.

    Used by the release build to prove that a packaged program can serve the
    interface and run a scan. Opens no window.
    """
    lines: list[str] = []
    code = 1
    server = GuiServer()
    server.start()
    try:
        base = f"http://127.0.0.1:{server.port}"
        headers = {"X-Sentinel-Token": server.token, "Content-Type": "application/json"}

        def call(path: str, data: bytes | None = None) -> dict[str, object]:
            request = urllib.request.Request(base + path, data=data, headers=headers)  # noqa: S310
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                parsed: dict[str, object] = json.loads(response.read())
                return parsed

        with urllib.request.urlopen(base + "/", timeout=30) as response:  # noqa: S310
            page = response.read().decode("utf-8")
        lines.append(f"page bytes: {len(page)}")
        job = call("/api/scan-sample", b"{}")
        deadline = time.monotonic() + 120
        state = job
        while state.get("status") == "running" and time.monotonic() < deadline:
            time.sleep(0.2)
            state = call(f"/api/job/{job['id']}")
        lines.append(f"scan status: {state.get('status')} events: {state.get('events')}")
        if state.get("status") == "done":
            result = call(f"/api/job/{job['id']}/result")
            total = result.get("alerts_total")
            lines.append(f"alerts: {total}")
            if isinstance(total, int) and total > 0 and "SentinelAI" in page:
                code = 0
        else:
            lines.append(f"error: {state.get('error')}")
    except Exception as exc:  # noqa: BLE001 - a self-test reports every failure
        lines.append(f"self-test failed: {exc!r}")
    finally:
        server.stop()
    lines.append("SELFTEST OK" if code == 0 else "SELFTEST FAILED")
    text = "\n".join(lines) + "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")  # noqa: T201
    return code
