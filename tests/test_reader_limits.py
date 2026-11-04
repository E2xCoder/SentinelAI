"""Resource-limit tests for the streaming reader and the live tailer.

Logs are attacker controlled, so a single huge line or a gzip bomb must never
exhaust memory. All content here is synthetic.
"""

from __future__ import annotations

import gzip
import os
import random
import time
import tracemalloc
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sentinelai.cli.commands.analysis import limits_from_config
from sentinelai.config.models import SentinelConfig
from sentinelai.core.exceptions import LogSourceError
from sentinelai.monitor import tailer as tailer_module
from sentinelai.monitor.tailer import LogTailer
from sentinelai.parsers import reader
from sentinelai.parsers.reader import ReaderLimits, sample_lines, stream_lines

POSIX = os.name == "posix"


# -- helpers ---------------------------------------------------------------


class WarningSpy:
    """Collects ``_LOGGER.warning`` calls made by a module logger."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, message: str, *args: Any, **_kwargs: Any) -> None:
        self.calls.append(message % args if args else message)


@pytest.fixture
def reader_warnings(monkeypatch: pytest.MonkeyPatch) -> WarningSpy:
    spy = WarningSpy()
    monkeypatch.setattr(reader._LOGGER, "warning", spy)
    return spy


@pytest.fixture
def tailer_warnings(monkeypatch: pytest.MonkeyPatch) -> WarningSpy:
    spy = WarningSpy()
    monkeypatch.setattr(tailer_module._LOGGER, "warning", spy)
    return spy


def write_bytes(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def append(path: Path, data: bytes) -> None:
    with path.open("ab") as handle:
        handle.write(data)


def random_lines(count: int, seed: int = 7) -> bytes:
    rng = random.Random(seed)
    rows = [f"row {i} {rng.getrandbits(64):016x}\n" for i in range(count)]
    return "".join(rows).encode("ascii")


@pytest.fixture
def tailers() -> Iterator[list[LogTailer]]:
    opened: list[LogTailer] = []
    yield opened
    for item in opened:
        item.close()


def open_tailer(
    tailers: list[LogTailer], path: Path, *, max_line_chars: int = 100, from_beginning: bool = True
) -> LogTailer:
    item = LogTailer(path, from_beginning=from_beginning, max_line_chars=max_line_chars)
    tailers.append(item)
    return item


def drain(item: LogTailer, polls: int = 12) -> list[str]:
    """Poll a fixed number of times (a poll may be empty while a line is pending)."""
    collected: list[str] = []
    for _ in range(polls):
        collected.extend(item.poll())
    return collected


# -- ReaderLimits ----------------------------------------------------------


class TestReaderLimits:
    @pytest.mark.parametrize("value", [0, -1, -65536])
    def test_non_positive_max_line_chars_is_rejected(self, value: int) -> None:
        with pytest.raises(ValueError, match="positive"):
            ReaderLimits(max_line_chars=value)

    @pytest.mark.parametrize("value", [0, -1])
    def test_non_positive_max_decompressed_bytes_is_rejected(self, value: int) -> None:
        with pytest.raises(ValueError, match="positive"):
            ReaderLimits(max_decompressed_bytes=value)

    def test_positive_values_are_accepted(self) -> None:
        limits = ReaderLimits(max_line_chars=1, max_decompressed_bytes=1)

        assert (limits.max_line_chars, limits.max_decompressed_bytes) == (1, 1)

    def test_limits_from_config_converts_megabytes_to_bytes(self) -> None:
        config = SentinelConfig()
        config.limits.max_line_chars = 2048
        config.limits.max_decompressed_mb = 3

        limits = limits_from_config(config)

        assert limits.max_line_chars == 2048
        assert limits.max_decompressed_bytes == 3 * 1024 * 1024

    def test_limits_from_default_config_matches_reader_defaults(self) -> None:
        limits = limits_from_config(SentinelConfig())

        assert limits.max_line_chars == 65_536
        assert limits.max_decompressed_bytes == 2_048 * 1024 * 1024


# -- stream_lines: oversized lines -----------------------------------------


class TestOversizedLines:
    def test_oversized_line_is_skipped_and_neighbours_survive(
        self, tmp_path: Path, reader_warnings: WarningSpy
    ) -> None:
        path = write_bytes(tmp_path / "a.log", b"before\n" + b"x" * 5000 + b"\nafter\n")

        lines = list(stream_lines(path, ReaderLimits(max_line_chars=100)))

        assert lines == ["before\n", "after\n"]

    def test_oversized_line_at_eof_without_newline_is_skipped(self, tmp_path: Path) -> None:
        path = write_bytes(tmp_path / "a.log", b"before\n" + b"x" * 5000)

        lines = list(stream_lines(path, ReaderLimits(max_line_chars=100)))

        assert lines == ["before\n"]

    def test_line_exactly_at_the_limit_is_kept(self, tmp_path: Path) -> None:
        body = "y" * 100
        path = write_bytes(tmp_path / "a.log", f"{body}\nnext\n".encode())

        lines = list(stream_lines(path, ReaderLimits(max_line_chars=100)))

        assert lines == [body + "\n", "next\n"]

    def test_unterminated_last_line_exactly_at_limit_is_kept(self, tmp_path: Path) -> None:
        body = "y" * 100
        path = write_bytes(tmp_path / "a.log", body.encode())

        assert list(stream_lines(path, ReaderLimits(max_line_chars=100))) == [body]

    def test_line_one_char_over_the_limit_is_dropped(self, tmp_path: Path) -> None:
        path = write_bytes(tmp_path / "a.log", b"z" * 101 + b"\nkeep\n")

        lines = list(stream_lines(path, ReaderLimits(max_line_chars=100)))

        assert lines == ["keep\n"]

    def test_several_oversized_lines_in_a_row_are_all_skipped(self, tmp_path: Path) -> None:
        data = b"".join(b"x" * 500 + b"\n" for _ in range(5)) + b"tail\n"
        path = write_bytes(tmp_path / "a.log", data)

        assert list(stream_lines(path, ReaderLimits(max_line_chars=100))) == ["tail\n"]

    def test_exactly_one_warning_per_file_with_the_count(
        self, tmp_path: Path, reader_warnings: WarningSpy
    ) -> None:
        data = b"".join(b"x" * 500 + b"\nok\n" for _ in range(3))
        path = write_bytes(tmp_path / "a.log", data)

        list(stream_lines(path, ReaderLimits(max_line_chars=100)))

        assert len(reader_warnings.calls) == 1
        assert "3 oversized" in reader_warnings.calls[0]

    def test_no_warning_when_nothing_is_oversized(
        self, tmp_path: Path, reader_warnings: WarningSpy
    ) -> None:
        path = write_bytes(tmp_path / "a.log", b"a\nb\n")

        list(stream_lines(path, ReaderLimits(max_line_chars=100)))

        assert reader_warnings.calls == []

    def test_empty_file_yields_nothing(self, tmp_path: Path) -> None:
        path = write_bytes(tmp_path / "empty.log", b"")

        assert list(stream_lines(path)) == []

    def test_sample_lines_honours_the_limit(self, tmp_path: Path) -> None:
        path = write_bytes(tmp_path / "a.log", b"x" * 400 + b"\nfirst\nsecond\n")

        sample = sample_lines(path, limits=ReaderLimits(max_line_chars=100))

        assert sample == ["first", "second"]

    def test_five_megabyte_line_is_fast_and_memory_bounded(self, tmp_path: Path) -> None:
        path = tmp_path / "huge.log"
        with path.open("wb") as handle:
            handle.write(b"head\n")
            handle.write(b"A" * (5 * 1024 * 1024))
            handle.write(b"\ntail\n")
        limits = ReaderLimits(max_line_chars=1024)

        tracemalloc.start()
        started = time.perf_counter()
        try:
            lines = list(stream_lines(path, limits))
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        elapsed = time.perf_counter() - started

        assert lines == ["head\n", "tail\n"]
        assert peak < 4 * 1024 * 1024
        assert elapsed < 5.0

    def test_five_megabyte_unterminated_line_is_memory_bounded(self, tmp_path: Path) -> None:
        path = write_bytes(tmp_path / "huge.log", b"A" * (5 * 1024 * 1024))

        tracemalloc.start()
        try:
            lines = list(stream_lines(path, ReaderLimits(max_line_chars=1024)))
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

        assert lines == []
        assert peak < 4 * 1024 * 1024


# -- stream_lines: gzip ----------------------------------------------------


class TestGzipLimits:
    def test_normal_gzip_file_is_read(self, tmp_path: Path) -> None:
        path = tmp_path / "auth.log.1.gz"
        with gzip.open(path, "wb") as handle:
            handle.write(b"one\ntwo\nthree\n")

        assert list(stream_lines(path)) == ["one\n", "two\n", "three\n"]

    def test_gzip_within_the_limit_is_read_completely(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log.gz"
        payload = random_lines(200)
        with gzip.open(path, "wb") as handle:
            handle.write(payload)

        lines = list(stream_lines(path, ReaderLimits(max_decompressed_bytes=len(payload) + 10)))

        assert "".join(lines).encode("ascii") == payload

    def test_gzip_bomb_of_zeros_raises_log_source_error(self, tmp_path: Path) -> None:
        path = tmp_path / "bomb.log.gz"
        with gzip.open(path, "wb", compresslevel=9) as handle:
            block = b"\x00" * (1024 * 1024)
            for _ in range(50):
                handle.write(block)
        assert path.stat().st_size < 1024 * 1024  # really is a bomb
        limits = ReaderLimits(max_decompressed_bytes=1_000_000)

        with pytest.raises(LogSourceError, match="decompression limit"):
            list(stream_lines(path, limits))

    def test_gzip_bomb_of_short_lines_raises_log_source_error(self, tmp_path: Path) -> None:
        path = tmp_path / "bomb2.log.gz"
        with gzip.open(path, "wb", compresslevel=9) as handle:
            handle.write(b"a\n" * 1_500_000)
        limits = ReaderLimits(max_decompressed_bytes=1_000_000)

        with pytest.raises(LogSourceError, match="decompression limit"):
            list(stream_lines(path, limits))

    def test_gzip_bomb_is_stopped_early(self, tmp_path: Path) -> None:
        path = tmp_path / "bomb.log.gz"
        with gzip.open(path, "wb", compresslevel=9) as handle:
            block = b"\x00" * (1024 * 1024)
            for _ in range(50):
                handle.write(block)
        seen = 0

        with pytest.raises(LogSourceError):
            for _ in stream_lines(path, ReaderLimits(max_decompressed_bytes=1_000_000)):
                seen += 1

        assert seen == 0  # a stream of zeros has no newline, so no line is ever yielded

    def test_plain_file_is_not_subject_to_the_decompression_limit(self, tmp_path: Path) -> None:
        path = write_bytes(tmp_path / "plain.log", random_lines(200))

        lines = list(stream_lines(path, ReaderLimits(max_decompressed_bytes=10)))

        assert len(lines) == 200

    def test_truncated_gzip_raises_log_source_error(self, tmp_path: Path) -> None:
        full = gzip.compress(random_lines(2000))
        path = write_bytes(tmp_path / "cut.log.gz", full[: len(full) // 2])

        with pytest.raises(LogSourceError, match="Failed reading"):
            list(stream_lines(path))

    def test_garbage_with_gz_suffix_raises_log_source_error(self, tmp_path: Path) -> None:
        path = write_bytes(tmp_path / "junk.log.gz", b"this is definitely not gzip data")

        with pytest.raises(LogSourceError):
            list(stream_lines(path))

    def test_corrupted_gzip_body_raises_log_source_error(self, tmp_path: Path) -> None:
        data = bytearray(gzip.compress(random_lines(2000)))
        for index in range(len(data) // 3, len(data) // 3 + 40):
            data[index] ^= 0xFF
        path = write_bytes(tmp_path / "flip.log.gz", bytes(data))

        with pytest.raises(LogSourceError):
            list(stream_lines(path))

    def test_empty_gzip_file_raises_or_yields_nothing(self, tmp_path: Path) -> None:
        path = write_bytes(tmp_path / "empty.log.gz", b"")

        try:
            lines = list(stream_lines(path))
        except LogSourceError:
            return
        assert lines == []

    def test_missing_file_raises_log_source_error(self, tmp_path: Path) -> None:
        with pytest.raises(LogSourceError):
            list(stream_lines(tmp_path / "nope.log"))


# -- LogTailer -------------------------------------------------------------


class TestTailerLimits:
    def test_non_positive_max_line_chars_is_rejected(self, tmp_path: Path) -> None:
        path = write_bytes(tmp_path / "t.log", b"")

        with pytest.raises(ValueError, match="positive"):
            LogTailer(path, max_line_chars=0)

    def test_complete_oversized_line_is_dropped_neighbours_kept(
        self, tmp_path: Path, tailers: list[LogTailer], tailer_warnings: WarningSpy
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"ok1\n" + b"x" * 500 + b"\nok2\n")
        item = open_tailer(tailers, path)

        assert item.poll() == ["ok1", "ok2"]
        assert len(tailer_warnings.calls) == 1

    def test_line_exactly_at_limit_is_kept(self, tmp_path: Path, tailers: list[LogTailer]) -> None:
        body = "k" * 100
        path = write_bytes(tmp_path / "t.log", f"{body}\n{'k' * 101}\n".encode())
        item = open_tailer(tailers, path)

        assert item.poll() == [body]

    def test_huge_unterminated_chunk_is_dropped_and_later_lines_delivered(
        self, tmp_path: Path, tailers: list[LogTailer], tailer_warnings: WarningSpy
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"")
        item = open_tailer(tailers, path)

        append(path, b"ok\n" + b"x" * 5000)
        assert item.poll() == ["ok"]
        assert len(tailer_warnings.calls) == 1

        append(path, b"y" * 3000)  # still the same unterminated line
        assert item.poll() == []

        append(path, b"zzz\nlater\n")
        assert item.poll() == ["later"]
        assert len(tailer_warnings.calls) == 1  # one oversized line, one warning

    def test_oversized_line_spanning_many_polls_does_not_grow_memory(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"")
        item = open_tailer(tailers, path)

        for _ in range(20):
            append(path, b"x" * 1000)
            item.poll()

        assert len(item._partial) <= 100

    def test_line_growing_past_limit_across_polls_is_dropped(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"")
        item = open_tailer(tailers, path)

        append(path, b"a" * 60)
        assert item.poll() == []  # still a plausible partial line
        append(path, b"b" * 60 + b"\nnext\n")

        assert item.poll() == ["next"]

    def test_normal_lines_are_delivered_incrementally(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"")
        item = open_tailer(tailers, path)

        append(path, b"par")
        assert item.poll() == []
        append(path, b"tial\nsecond\n")

        assert item.poll() == ["partial", "second"]

    def test_crlf_and_blank_lines_are_normalised(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"one\r\n\r\n   \ntwo\r\n")
        item = open_tailer(tailers, path)

        assert item.poll() == ["one", "two"]

    def test_truncation_is_detected_and_new_content_read(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"first line here\nsecond line here\n")
        item = open_tailer(tailers, path)
        assert item.poll() == ["first line here", "second line here"]

        write_bytes(path, b"new\n")  # shorter than the previous position

        assert item.poll() == ["new"]

    def test_truncation_discards_a_pending_oversized_line(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"")
        item = open_tailer(tailers, path)
        append(path, b"x" * 5000)
        item.poll()  # now discarding an oversized line

        write_bytes(path, b"fresh\n")

        assert item.poll() == ["fresh"]

    @pytest.mark.skipif(not POSIX, reason="renaming an open file is not allowed on Windows")
    def test_rotation_is_detected_and_new_file_followed(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"old1\n")
        item = open_tailer(tailers, path)
        assert item.poll() == ["old1"]

        path.rename(tmp_path / "t.log.1")
        write_bytes(path, b"rotated1\nrotated2\n")

        assert item.poll() == ["rotated1", "rotated2"]

    def test_missing_file_is_tolerated_then_picked_up(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        path = tmp_path / "later.log"
        item = open_tailer(tailers, path)
        assert item.poll() == []

        write_bytes(path, b"hello\n")

        assert item.poll() == ["hello"]

    def test_read_cap_spreads_a_backlog_over_several_polls(
        self, tmp_path: Path, tailers: list[LogTailer], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tailer_module, "_MAX_READ_CHARS", 6)
        path = write_bytes(tmp_path / "t.log", b"l1\nl2\nl3\nl4\nl5\n")
        item = open_tailer(tailers, path)

        first = item.poll()
        rest = drain(item)

        assert first == ["l1", "l2"]
        assert first + rest == ["l1", "l2", "l3", "l4", "l5"]

    def test_read_cap_splitting_a_line_still_reassembles_it(
        self, tmp_path: Path, tailers: list[LogTailer], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tailer_module, "_MAX_READ_CHARS", 4)
        path = write_bytes(tmp_path / "t.log", b"abcdefgh\nij\n")
        item = open_tailer(tailers, path)

        collected = drain(item)

        assert collected == ["abcdefgh", "ij"]

    def test_read_cap_with_oversized_line_across_polls_recovers(
        self, tmp_path: Path, tailers: list[LogTailer], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tailer_module, "_MAX_READ_CHARS", 4)
        path = write_bytes(tmp_path / "t.log", b"abcdefghij\n")
        item = open_tailer(tailers, path, max_line_chars=6)
        for _ in range(10):
            item.poll()

        append(path, b"ok\n")

        assert drain(item) == ["ok"]

    def test_from_beginning_false_skips_existing_content(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"old\n")
        item = open_tailer(tailers, path, from_beginning=False)
        assert item.poll() == []

        append(path, b"new\n")

        assert item.poll() == ["new"]

# -- LogTailer review fixes ------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class TestTailerReviewFixes:
    def test_trailing_carriage_return_without_newline_causes_no_duplicates(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"")
        item = open_tailer(tailers, path)

        append(path, b"abc\r")
        assert item.poll() == []
        assert item._position <= path.stat().st_size

        append(path, b"\ndef\nghi\n")
        lines = item.poll()

        assert lines == ["abc", "def", "ghi"]
        assert item._position <= path.stat().st_size
        assert item.poll() == []

    def test_position_is_a_real_byte_offset_for_crlf_files(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"")
        item = open_tailer(tailers, path)

        append(path, b"one\r\ntwo\r\n")

        assert item.poll() == ["one", "two"]
        assert item._position == path.stat().st_size
        assert item.poll() == []

    def test_multibyte_character_split_across_writes_is_decoded_once(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        euro = "€".encode()  # three bytes
        assert len(euro) == 3
        path = write_bytes(tmp_path / "t.log", b"")
        item = open_tailer(tailers, path)

        append(path, b"cost " + euro[:2])
        first = item.poll()
        append(path, euro[2:] + b"\nnext\n")
        second = item.poll()

        assert first == []
        assert second == ["cost €", "next"]
        assert "�" not in "".join(first + second)

    def test_multibyte_split_after_a_complete_line_keeps_both_lines(
        self, tmp_path: Path, tailers: list[LogTailer]
    ) -> None:
        euro = "€".encode()
        path = write_bytes(tmp_path / "t.log", b"")
        item = open_tailer(tailers, path)

        append(path, b"first\ncost " + euro[:2])
        assert item.poll() == ["first"]
        append(path, euro[2:] + b"\n")

        assert item.poll() == ["cost €"]

    def test_oversized_line_warnings_are_rate_limited(
        self, tmp_path: Path, tailers: list[LogTailer], tailer_warnings: WarningSpy
    ) -> None:
        clock = _Clock()
        path = write_bytes(tmp_path / "t.log", b"")
        item = LogTailer(path, from_beginning=True, max_line_chars=100, clock=clock)
        tailers.append(item)

        append(path, (b"x" * 500 + b"\n") * 5)
        assert item.poll() == []
        assert len(tailer_warnings.calls) == 1  # first drop warns, the other four are summarised

        clock.now += 10
        append(path, b"y" * 500 + b"\n")
        item.poll()
        assert len(tailer_warnings.calls) == 1  # still inside the quiet interval

        clock.now += 61
        append(path, b"z" * 500 + b"\nok\n")
        assert item.poll() == ["ok"]

        assert len(tailer_warnings.calls) == 2
        assert "oversized lines dropped" in tailer_warnings.calls[1]
        assert "7 total" in tailer_warnings.calls[1]

    @pytest.mark.parametrize("error", [OSError("boom"), RuntimeError("boom")])
    def test_open_closes_the_handle_when_seek_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
    ) -> None:
        path = write_bytes(tmp_path / "t.log", b"data\n")
        handles: list[Any] = []
        real_open = Path.open

        class _BadSeek:
            def __init__(self, real: Any) -> None:
                self._real = real

            @property
            def closed(self) -> bool:
                return bool(self._real.closed)

            def fileno(self) -> int:
                return int(self._real.fileno())

            def seek(self, *_args: Any) -> int:
                raise error

            def close(self) -> None:
                self._real.close()

        def fake_open(self: Path, *args: Any, **kwargs: Any) -> Any:
            real = real_open(self, *args, **kwargs)
            if self == path and args[:1] == ("rb",):
                handles.append(_BadSeek(real))
                return handles[-1]
            return real

        monkeypatch.setattr(Path, "open", fake_open)

        if isinstance(error, OSError):
            item = LogTailer(path)
            assert item._handle is None
        else:
            with pytest.raises(RuntimeError):
                LogTailer(path)

        assert len(handles) == 1
        assert handles[0].closed
