"""Log replay: re-experience a historical log as if it were live.

Events are emitted with inter-event delays derived from their original
timestamps divided by a speed factor — ideal for testing detections and
demos without waiting for a real attack.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable

from sentinelai.core.models import Alert, LogEvent
from sentinelai.core.pipeline import AnalysisPipeline
from sentinelai.utils.logging import get_logger

_LOGGER = get_logger("monitor.replay")

#: Never sleep longer than this between events, whatever the log says.
_MAX_GAP_SECONDS = 5.0


class LogReplayer:
    """Replays parsed events through the pipeline at a configurable speed."""

    def __init__(
        self,
        pipeline: AnalysisPipeline,
        speed: float = 10.0,
        on_alert: Callable[[Alert], None] | None = None,
        on_event: Callable[[LogEvent], None] | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if speed <= 0:
            raise ValueError("Replay speed must be positive")
        self._pipeline = pipeline
        self._speed = speed
        self._on_alert = on_alert
        self._on_event = on_event
        self._sleep = sleeper
        self.events_replayed = 0
        self.alerts_raised = 0

    def replay(self, events: Iterable[LogEvent]) -> None:
        """Replay *events* in order with proportional delays."""
        previous = None
        for event in events:
            if previous is not None:
                gap = (event.timestamp - previous).total_seconds() / self._speed
                if gap > 0:
                    self._sleep(min(gap, _MAX_GAP_SECONDS))
            previous = event.timestamp
            self.events_replayed += 1
            if self._on_event is not None:
                self._on_event(event)
            for alert in self._pipeline.process_event(event):
                self.alerts_raised += 1
                if self._on_alert is not None:
                    self._on_alert(alert)
        _LOGGER.info(
            "Replay finished: %d events, %d alerts",
            self.events_replayed,
            self.alerts_raised,
        )
