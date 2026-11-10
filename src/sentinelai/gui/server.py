"""Loopback HTTP server behind the desktop interface.

Security model
--------------
The server is reachable only from this machine, but other local programs and
web pages open in the user's browser can still send requests to a loopback
port. Three checks keep them out:

* It binds to ``127.0.0.1`` only.
* Every ``/api/`` request must carry a random per-run token in the
  ``X-Sentinel-Token`` header. A web page from another origin cannot set a
  custom header without a CORS preflight, and no CORS headers are ever sent.
* The ``Host`` header must name the loopback address and this port, which
  blocks DNS-rebinding.

Log content is untrusted. The server returns it only as JSON; the page inserts
it with ``textContent``, never as HTML.
"""

from __future__ import annotations

import hmac
import json
import platform
import re
import secrets
import shutil
import tempfile
import threading
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from sentinelai import __version__
from sentinelai.config.loader import load_config
from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import SentinelError
from sentinelai.core.models import LogEvent
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("gui.server")

#: Largest upload accepted from the page (bytes).
MAX_UPLOAD_BYTES = 4 * 1024 * 1024 * 1024
#: Largest JSON request body accepted (bytes).
_MAX_JSON_BYTES = 64 * 1024
#: Alerts returned in one result page; the page asks for more as needed.
_MAX_ALERT_ROWS = 2000
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_JOB_ID = re.compile(r"^[a-f0-9]{16}$")


def gui_config() -> SentinelConfig:
    """Load the user's configuration with every response feature forced off."""
    config = load_config()
    config.response.enabled = False
    config.firewall.adapter = "dry_run"
    return config


def _static_text(name: str) -> str:
    static = resources.files("sentinelai.gui").joinpath("static")
    return static.joinpath(name).read_text(encoding="utf-8")


def sample_log_path() -> Path | None:
    """Path of the bundled sample log, or ``None`` when it is not on disk."""
    candidate = resources.files("sentinelai.gui").joinpath("static").joinpath("sample_auth.log")
    path = Path(str(candidate))
    return path if path.is_file() else None


@dataclass
class ScanJob:
    """State of one scan started from the interface."""

    id: str
    source: str
    started: float = field(default_factory=time.monotonic)
    finished: float | None = None
    events: int = 0
    status: str = "running"
    error: str = ""
    report: dict[str, Any] | None = None
    alerts: list[dict[str, Any]] = field(default_factory=list)
    html_report: str = ""

    @property
    def elapsed(self) -> float:
        end = self.finished if self.finished is not None else time.monotonic()
        return max(end - self.started, 0.0)

    def progress(self) -> dict[str, Any]:
        elapsed = self.elapsed
        return {
            "id": self.id,
            "status": self.status,
            "source": self.source,
            "events": self.events,
            "elapsed": round(elapsed, 2),
            "rate": round(self.events / elapsed) if elapsed > 0.001 else 0,
            "error": self.error,
        }


class GuiServer:
    """Owns the HTTP server, the access token and the scan jobs."""

    def __init__(self, port: int = 0, config: SentinelConfig | None = None) -> None:
        self.token = secrets.token_urlsafe(32)
        self._config = config
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._scan_lock = threading.Lock()
        self.last_ping = time.monotonic()
        self.quit_requested = threading.Event()
        self._upload_dir = Path(tempfile.mkdtemp(prefix="sentinelai-gui-"))
        self._httpd = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(self))
        self._httpd.daemon_threads = True
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    @property
    def url(self) -> str:
        """Address to open. The token travels in the fragment, so it is never
        sent to the server in a request line or stored in a server log."""
        return f"http://127.0.0.1:{self.port}/#t={self.token}"

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="sentinelai-gui", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        shutil.rmtree(self._upload_dir, ignore_errors=True)

    # -- configuration -----------------------------------------------------

    def config(self) -> SentinelConfig:
        if self._config is None:
            self._config = gui_config()
        return self._config

    # -- jobs --------------------------------------------------------------

    def job(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def start_scan(
        self, path: Path, *, display_name: str, use_ai: bool, delete_after: bool = False
    ) -> ScanJob | None:
        """Start a scan in the background; ``None`` when one is already running."""
        if not self._scan_lock.acquire(blocking=False):
            return None
        job = ScanJob(id=secrets.token_hex(8), source=display_name)
        with self._lock:
            self._jobs = {job.id: job}  # keep only the latest result in memory
        thread = threading.Thread(
            target=self._run_scan,
            args=(job, path, use_ai, delete_after),
            name="sentinelai-scan",
            daemon=True,
        )
        thread.start()
        return job

    def _run_scan(self, job: ScanJob, path: Path, use_ai: bool, delete_after: bool) -> None:
        from sentinelai.core.pipeline import AnalysisPipeline
        from sentinelai.parsers.reader import ReaderLimits, read_events
        from sentinelai.reporting.report import build_report
        from sentinelai.reporting.writer import render_report

        try:
            config = self.config()
            limits = ReaderLimits(
                max_line_chars=config.limits.max_line_chars,
                max_decompressed_bytes=config.limits.max_decompressed_mb * 1024 * 1024,
            )
            pipeline = AnalysisPipeline(config)
            try:
                result = pipeline.run_scan(
                    _counted(read_events(path, limits=limits), job), use_ai=use_ai
                )
                report = build_report(
                    result,
                    title=config.report.title,
                    source=job.source,
                    max_events_per_alert=config.report.max_events_per_alert,
                )
            finally:
                pipeline.close()
            full = report.to_dict(include_events=True)
            job.alerts = full.pop("alerts")
            job.report = full
            job.html_report = render_report(report, "html")
            job.status = "done"
        except SentinelError as exc:
            job.status = "error"
            job.error = str(exc)
        except Exception as exc:  # noqa: BLE001 - shown to the user, never a crash
            _LOGGER.exception("Scan failed")
            job.status = "error"
            job.error = f"Unexpected error: {exc}"
        finally:
            job.finished = time.monotonic()
            if delete_after:
                shutil.rmtree(path.parent, ignore_errors=True)
            self._scan_lock.release()

    def new_upload_path(self, name: str) -> Path:
        """Private temp location that keeps the file name (parsers use it as a hint)."""
        safe = _SAFE_NAME.sub("_", Path(name).name).strip("._") or "upload.log"
        folder = Path(tempfile.mkdtemp(dir=self._upload_dir))
        return folder / safe[:120]

    # -- read-only data ----------------------------------------------------

    def info(self) -> dict[str, Any]:
        config = self.config()
        try:
            import sklearn  # noqa: F401

            ai = True
        except ImportError:
            ai = False
        return {
            "version": __version__,
            "platform": platform.system() or "unknown",
            "state_dir": str(config.resolve_state_dir()),
            "ai_available": ai and config.ai.enabled,
            "sample_available": sample_log_path() is not None,
        }

    def history(self) -> dict[str, Any]:
        from sentinelai.core.store import AlertStore

        store = AlertStore(self.config().resolve_state_dir() / "alerts.db")
        try:
            since = datetime.now(timezone.utc) - timedelta(days=30)
            return {
                "alerts": [a.to_dict(include_events=False) for a in store.recent(300)],
                "incidents": [i.to_dict() for i in store.list_incidents(limit=100)],
                "by_level_30d": store.count_alerts_by_level_since(since),
            }
        finally:
            store.close()

    def rules(self) -> list[dict[str, Any]]:
        from sentinelai.detection.base import available_rules

        return [
            {
                "id": rule_id,
                "name": cls.name,
                "category": cls.category.value,
                "severity": cls.severity.value,
                "mitre": list(cls.mitre_techniques),
                "description": (cls.__doc__ or "").strip().split("\n\n")[0],
            }
            for rule_id, cls in sorted(available_rules().items())
        ]


def _counted(events: Iterable[LogEvent], job: ScanJob) -> Iterator[LogEvent]:
    for event in events:
        job.events += 1
        yield event


def _make_handler(app: GuiServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "SentinelAI"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            _LOGGER.debug("gui %s", format % args)

        # -- plumbing ------------------------------------------------------

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str,
            extra: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload: Any, status: int = HTTPStatus.OK) -> None:
            body = json.dumps(payload, default=str).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def _error(self, status: int, message: str) -> None:
            self.close_connection = True
            self._json({"error": message}, status)

        def _host_ok(self) -> bool:
            host = self.headers.get("Host", "")
            return host in (f"127.0.0.1:{app.port}", f"localhost:{app.port}")

        def _authorised(self) -> bool:
            supplied = self.headers.get("X-Sentinel-Token", "")
            return hmac.compare_digest(supplied.encode(), app.token.encode())

        def _guard(self) -> bool:
            """Reject requests that fail the Host or token check."""
            if not self._host_ok():
                self._error(HTTPStatus.FORBIDDEN, "Bad Host header")
                return False
            if not self._authorised():
                self._error(HTTPStatus.UNAUTHORIZED, "Missing or wrong token")
                return False
            return True

        def _read_json(self) -> dict[str, Any] | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > _MAX_JSON_BYTES:
                self._error(HTTPStatus.BAD_REQUEST, "Bad request body")
                return None
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                self._error(HTTPStatus.BAD_REQUEST, "Body is not valid JSON")
                return None
            if not isinstance(data, dict):
                self._error(HTTPStatus.BAD_REQUEST, "Body must be a JSON object")
                return None
            return data

        # -- GET -----------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802
            url = urlsplit(self.path)
            if url.path in ("/", "/index.html"):
                if not self._host_ok():
                    self._error(HTTPStatus.FORBIDDEN, "Bad Host header")
                    return
                self._send(
                    HTTPStatus.OK,
                    _static_text("index.html").encode("utf-8"),
                    "text/html; charset=utf-8",
                    {
                        "Content-Security-Policy": (
                            "default-src 'none'; script-src 'unsafe-inline'; "
                            "style-src 'unsafe-inline'; img-src data:; "
                            "connect-src 'self'; base-uri 'none'; form-action 'none'"
                        )
                    },
                )
                return
            if not url.path.startswith("/api/"):
                self._error(HTTPStatus.NOT_FOUND, "Not found")
                return
            if not self._guard():
                return
            try:
                self._get_api(url.path, parse_qs(url.query))
            except SentinelError as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except Exception as exc:  # noqa: BLE001 - report, keep serving
                _LOGGER.exception("GUI request failed")
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Unexpected error: {exc}")

        def _get_api(self, path: str, query: dict[str, list[str]]) -> None:
            if path == "/api/ping":
                app.last_ping = time.monotonic()
                self._json({"ok": True})
            elif path == "/api/info":
                self._json(app.info())
            elif path == "/api/history":
                self._json(app.history())
            elif path == "/api/rules":
                self._json(app.rules())
            elif path.startswith("/api/job/"):
                self._get_job(path.split("/")[3:], query)
            else:
                self._error(HTTPStatus.NOT_FOUND, "Not found")

        def _get_job(self, parts: list[str], query: dict[str, list[str]]) -> None:
            job = app.job(parts[0]) if parts and _JOB_ID.match(parts[0]) else None
            if job is None:
                self._error(HTTPStatus.NOT_FOUND, "Unknown scan")
                return
            tail = parts[1] if len(parts) > 1 else ""
            if tail == "":
                self._json(job.progress())
            elif job.status != "done" or job.report is None:
                self._error(HTTPStatus.CONFLICT, "Scan has not finished")
            elif tail == "result":
                rows = [
                    {k: v for k, v in alert.items() if k != "sample_events"} | {"index": i}
                    for i, alert in enumerate(job.alerts[:_MAX_ALERT_ROWS])
                ]
                self._json(
                    {
                        **job.progress(),
                        "report": job.report,
                        "alerts": rows,
                        "alerts_total": len(job.alerts),
                    }
                )
            elif tail == "alert":
                try:
                    index = int(query.get("i", [""])[0])
                    alert = job.alerts[index] if index >= 0 else None
                except (ValueError, IndexError):
                    alert = None
                if alert is None:
                    self._error(HTTPStatus.NOT_FOUND, "Unknown alert")
                else:
                    self._json(alert)
            elif tail == "report.html":
                self._send(
                    HTTPStatus.OK,
                    job.html_report.encode("utf-8"),
                    "application/octet-stream",
                    {"Content-Disposition": 'attachment; filename="sentinelai-report.html"'},
                )
            else:
                self._error(HTTPStatus.NOT_FOUND, "Not found")

        # -- POST ----------------------------------------------------------

        def do_POST(self) -> None:  # noqa: N802
            url = urlsplit(self.path)
            if not self._guard():
                return
            try:
                self._post_api(url.path, parse_qs(url.query))
            except SentinelError as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except Exception as exc:  # noqa: BLE001 - report, keep serving
                _LOGGER.exception("GUI request failed")
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Unexpected error: {exc}")

        def _started(self, job: ScanJob | None) -> None:
            if job is None:
                self._error(HTTPStatus.CONFLICT, "A scan is already running")
            else:
                self._json(job.progress(), HTTPStatus.ACCEPTED)

        def _post_api(self, path: str, query: dict[str, list[str]]) -> None:
            use_ai = query.get("ai", ["1"])[0] != "0"
            if path == "/api/upload":
                self._upload(query, use_ai)
                return
            data = self._read_json()
            if data is None:
                return
            if path == "/api/scan":
                from sentinelai.utils.paths import resolve_input_file

                raw = str(data.get("path", "")).strip().strip('"')
                if not raw:
                    self._error(HTTPStatus.BAD_REQUEST, "Enter the path of a log file")
                    return
                resolved = resolve_input_file(raw)
                self._started(
                    app.start_scan(
                        resolved, display_name=str(resolved), use_ai=bool(data.get("ai", True))
                    )
                )
            elif path == "/api/scan-sample":
                sample = sample_log_path()
                if sample is None:
                    self._error(HTTPStatus.NOT_FOUND, "The sample log is not available")
                    return
                self._started(
                    app.start_scan(sample, display_name="Sample: auth.log", use_ai=False)
                )
            elif path == "/api/quit":
                self._json({"ok": True})
                app.quit_requested.set()
            else:
                self._error(HTTPStatus.NOT_FOUND, "Not found")

        def _upload(self, query: dict[str, list[str]], use_ai: bool) -> None:
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._error(HTTPStatus.LENGTH_REQUIRED, "Content-Length is required")
                return
            if length <= 0 or length > MAX_UPLOAD_BYTES:
                self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "File is empty or too large")
                return
            name = query.get("name", ["upload.log"])[0]
            target = app.new_upload_path(name)
            remaining = length
            with target.open("wb") as handle:
                while remaining > 0:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    handle.write(chunk)
                    remaining -= len(chunk)
            if remaining:
                shutil.rmtree(target.parent, ignore_errors=True)
                self._error(HTTPStatus.BAD_REQUEST, "Upload was interrupted")
                return
            job = app.start_scan(
                target, display_name=Path(name).name[:200], use_ai=use_ai, delete_after=True
            )
            if job is None:
                shutil.rmtree(target.parent, ignore_errors=True)
            self._started(job)

    return Handler
