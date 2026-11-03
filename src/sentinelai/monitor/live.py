"""Live monitoring: continuous tailing of multiple logs with instant detection."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path

from sentinelai.config.models import LiveConfig
from sentinelai.core.models import Alert, LogEvent
from sentinelai.core.pipeline import AnalysisPipeline
from sentinelai.monitor.tailer import LogTailer
from sentinelai.parsers.base import LogParser, detect_parser
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("monitor.live")

AlertCallback = Callable[[Alert], None]
EventCallback = Callable[[LogEvent], None]


class _Source:
    """A tailed file plus its lazily detected parser."""

    def __init__(self, path: Path, from_beginning: bool) -> None:
        self.tailer = LogTailer(path, from_beginning=from_beginning)
        self.parser: LogParser | None = None
        self.pending_sample: list[str] = []

    def parse(self, lines: list[str]) -> list[LogEvent]:
        """Parse new lines, detecting the format from the first batch."""
        if self.parser is None:
            self.pending_sample.extend(lines)
            try:
                self.parser = detect_parser(self.tailer.path.name, self.pending_sample)
            except Exception:  # noqa: BLE001 - keep sampling until detectable
                if len(self.pending_sample) > 500:
                    self.pending_sample = self.pending_sample[-200:]
                return []
            lines, self.pending_sample = self.pending_sample, []
        return list(self.parser.parse_lines(lines, source=str(self.tailer.path)))


class LiveMonitor:
    """Watches configured log files and pushes events through the pipeline.

    Alert de-duplication happens inside the rule engine (fingerprint +
    cooldown); the monitor guarantees each appended line is parsed once.
    """

    def __init__(
        self,
        config: LiveConfig,
        pipeline: AnalysisPipeline,
        on_alert: AlertCallback | None = None,
        on_event: EventCallback | None = None,
    ) -> None:
        self._config = config
        self._pipeline = pipeline
        self._on_alert = on_alert
        self._on_event = on_event
        self._stop = threading.Event()
        self._sources = [
            _Source(Path(p).expanduser(), config.from_beginning) for p in config.paths
        ]
        self.events_seen = 0
        self.alerts_raised = 0
        self._last_reap = time.monotonic()

    def _maybe_reap(self) -> None:
        """Expire timed-out firewall blocks at most once per reap interval."""
        response = self._pipeline.response_config
        if not response.enabled:
            return
        now = time.monotonic()
        if now - self._last_reap < response.reap_interval_seconds:
            return
        self._last_reap = now
        try:
            self._pipeline.operator.reap()
        except Exception:  # noqa: BLE001 - housekeeping must not stop the loop
            _LOGGER.exception("Response reap failed")

    def stop(self) -> None:
        """Request the monitoring loop to exit."""
        self._stop.set()

    def run(self, max_iterations: int | None = None) -> None:
        """Run the polling loop until :meth:`stop` (or *max_iterations*).

        *max_iterations* exists for tests and bounded runs.
        """
        _LOGGER.info(
            "Live monitoring started on %d source(s)", len(self._sources)
        )
        iterations = 0
        try:
            while not self._stop.is_set():
                self._poll_once()
                self._maybe_reap()
                iterations += 1
                if max_iterations is not None and iterations >= max_iterations:
                    break
                self._stop.wait(self._config.poll_interval_seconds)
        finally:
            for source in self._sources:
                source.tailer.close()
            _LOGGER.info(
                "Live monitoring stopped (%d events, %d alerts)",
                self.events_seen,
                self.alerts_raised,
            )

    def _poll_once(self) -> None:
        for source in self._sources:
            try:
                lines = source.tailer.poll()
            except Exception:  # noqa: BLE001 - a bad source must not stop the loop
                _LOGGER.exception("Tailer failed for %s", source.tailer.path)
                continue
            if not lines:
                continue
            for event in source.parse(lines):
                self.events_seen += 1
                if self._on_event is not None:
                    self._on_event(event)
                for alert in self._pipeline.process_event(event):
                    self.alerts_raised += 1
                    if self._on_alert is not None:
                        self._on_alert(alert)
