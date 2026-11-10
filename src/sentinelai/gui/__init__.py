"""Desktop interface for SentinelAI.

A small HTTP server bound to the loopback interface serves a single-page
interface; the launcher opens it in a chromeless browser window so it looks
and behaves like a desktop application on Linux, Windows and macOS.

The interface only analyses logs and shows results. It never enables
automated response: scans started here always run with response disabled
and the ``dry_run`` firewall adapter.
"""

from __future__ import annotations

from sentinelai.gui.launcher import run_gui
from sentinelai.gui.server import GuiServer

__all__ = ["GuiServer", "run_gui"]
