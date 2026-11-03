"""Integrity manifest for the frozen benchmark scenarios.

``MANIFEST.sha256`` pins the SHA-256 of every file under ``scenarios/`` so a
benchmark cannot be silently edited to make a regression disappear. Line
endings are normalized (``\\r\\n`` -> ``\\n``) before hashing so Windows
checkouts produce the same digests as Linux ones.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from sentinelai.core.exceptions import EvaluationError

MANIFEST_NAME = "MANIFEST.sha256"
SCENARIOS_DIR = "scenarios"

_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _hash_file(path: Path) -> str:
    """Return the SHA-256 hex digest of ``path`` with CRLF normalized to LF."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise EvaluationError(f"Cannot read benchmark file {path}: {exc}") from exc
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _iter_files(scenarios: Path) -> list[Path]:
    """Return all regular files below ``scenarios``; reject any symlink."""
    if scenarios.is_symlink():
        raise EvaluationError(f"Symlinks are not allowed in benchmarks: {scenarios}")
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(scenarios, followlinks=False):
        base = Path(dirpath)
        for name in (*dirnames, *filenames):
            if (base / name).is_symlink():
                raise EvaluationError(f"Symlinks are not allowed in benchmarks: {base / name}")
        files.extend(base / name for name in filenames if (base / name).is_file())
    return files


def compute_manifest(root: Path) -> dict[str, str]:
    """Hash every file under ``root/scenarios``; keys are POSIX paths relative to ``root``."""
    scenarios = root / SCENARIOS_DIR
    if not scenarios.is_dir():
        raise EvaluationError(f"Benchmark scenarios directory not found: {scenarios}")
    entries: dict[str, str] = {}
    for path in _iter_files(scenarios):
        rel = path.relative_to(root).as_posix()
        if "\n" in rel or "\r" in rel:
            raise EvaluationError(f"Unsupported file name in benchmarks: {rel!r}")
        entries[rel] = _hash_file(path)
    return dict(sorted(entries.items()))


def write_manifest(root: Path) -> Path:
    """Write ``root/MANIFEST.sha256`` and return its path."""
    entries = compute_manifest(root)
    text = "".join(f"{digest}  {rel}\n" for rel, digest in entries.items())
    target = root / MANIFEST_NAME
    try:
        # write_bytes avoids platform newline translation (always LF).
        target.write_bytes(text.encode("utf-8"))
    except OSError as exc:
        raise EvaluationError(f"Cannot write manifest {target}: {exc}") from exc
    return target


def read_manifest(root: Path) -> dict[str, str]:
    """Parse ``root/MANIFEST.sha256`` into ``{relative_path: sha256_hex}``."""
    target = root / MANIFEST_NAME
    try:
        text = target.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise EvaluationError(f"Benchmark manifest not found: {target}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise EvaluationError(f"Cannot read manifest {target}: {exc}") from exc

    entries: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        digest, sep, rel = line.partition("  ")
        if not sep or not _HEX_RE.match(digest) or not rel or rel != rel.strip():
            raise EvaluationError(f"Malformed manifest line {lineno} in {target}")
        if rel in entries:
            raise EvaluationError(f"Duplicate manifest entry on line {lineno}: {rel}")
        entries[rel] = digest
    return entries


def verify_manifest(root: Path) -> list[str]:
    """Return sorted problems (modified/added/removed); empty means intact."""
    expected = read_manifest(root)
    actual = compute_manifest(root)
    problems: list[str] = []
    for rel in expected.keys() | actual.keys():
        if rel not in actual:
            problems.append(f"removed: {rel}")
        elif rel not in expected:
            problems.append(f"added: {rel}")
        elif expected[rel] != actual[rel]:
            problems.append(f"modified: {rel}")
    return sorted(problems)
