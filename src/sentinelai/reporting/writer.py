"""Writes rendered reports to disk with path-traversal protection."""

from __future__ import annotations

from pathlib import Path

from sentinelai.reporting.renderers import available_formats, get_renderer
from sentinelai.reporting.report import Report
from sentinelai.utils.logging import get_logger
from sentinelai.utils.paths import resolve_output_file

_LOGGER = get_logger("reporting.writer")

_EXTENSIONS = {"json": ".json", "csv": ".csv", "html": ".html"}


def render_report(report: Report, fmt: str) -> str:
    """Render *report* to a string in the requested format."""
    return get_renderer(fmt)(report)


def write_reports(
    report: Report,
    formats: list[str],
    output_dir: str | Path,
    basename: str = "sentinelai-report",
) -> dict[str, Path]:
    """Render and write *report* in each format; return format→path.

    Output is confined to *output_dir* to prevent path traversal from a
    templated basename.
    """
    base = Path(output_dir).expanduser().resolve()
    written: dict[str, Path] = {}
    for fmt in formats:
        if fmt not in available_formats():
            _LOGGER.warning("Skipping unknown report format %r", fmt)
            continue
        safe_name = Path(basename).name  # strip any directory components
        target = resolve_output_file(
            base / f"{safe_name}{_EXTENSIONS.get(fmt, '.' + fmt)}", base_dir=base
        )
        target.write_text(render_report(report, fmt), encoding="utf-8")
        written[fmt] = target
        _LOGGER.info("Wrote %s report to %s", fmt, target)
    return written
