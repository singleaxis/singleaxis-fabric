# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""P1 seal-thread failure paths (spec 050 §3.7, 049 §7.1), from Sol's 97fdb9b review: the
reclaim backlog is bounded even while a (stalled) reclaimer is alive; dropped state is never
released under the seal or allocator lock, and a segment's retained state is bounded by the
forced seal; a seal thread that cannot even be constructed never escapes into the caller and
fails ``close()``."""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric._loss
import fabric._sequence
from fabric import _seal, wire
from fabric._capture_types import COUNTERS, STRICT_ENV

SOURCE = "s-" + "b" * 32
DIGEST = bytes.fromhex("c" * 64)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    for name in ("FABRIC_RUN_ID", "FABRIC_RUN_RESUME_TOKEN", "FABRIC_WIRE_ID_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    COUNTERS.reset()
    emitter = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)
    COUNTERS.reset()


def _request(seals: _seal.SegmentSeals, index: int, last: int = -1) -> None:
    seals.request_seal(f"seg-{index:032x}", last_sequence=last, manifest_digest=None,
                       terminal=True, resumable=False, source_id=SOURCE, epoch=7)  # fmt: skip


def _put(
    seals: _seal.SegmentSeals, index: int, positions: int, cls: type[dict[int, Any]] = dict
) -> None:
    """The settled state note_allocated/settle produce, set directly (fast fault tests)."""
    with seals._lock:
        seals._segments[f"seg-{index:032x}"] = _seal._Segment(
            entries=cls.fromkeys(range(positions), DIGEST), source=(SOURCE, 7))  # fmt: skip
    _request(seals, index, positions - 1)


def _refuse_seal_threads(monkeypatch: pytest.MonkeyPatch) -> None:
    original = threading.Thread.start

    def start(self: threading.Thread) -> None:
        if self.name.startswith("fabric-seal"):
            raise RuntimeError("thread start refused")
        original(self)

    monkeypatch.setattr(threading.Thread, "start", start)


def _refuse_seal_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    original = threading.Thread

    def construct(*args: Any, **kwargs: Any) -> threading.Thread:
        if str(kwargs.get("name", "")).startswith("fabric-seal"):
            raise RuntimeError("thread construction refused")
        return original(*args, **kwargs)

    monkeypatch.setattr(threading, "Thread", construct)


def _install(tmp_path: Path) -> wire.WireHandle:
    return wire.install(spool_dir=str(tmp_path / "spool"), span_exporter=InMemorySpanExporter(),
                        patch_httpx=False, patch_aiohttp=False, id_key=b"k" * 32)  # fmt: skip


# --- 1: the reclaim backlog is bounded while a reclaimer is alive ----------------------------


def test_a_stalled_live_reclaimer_keeps_its_backlog_within_the_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_seal, "MAX_PENDING_SEALS", 1)
    building, release_build = threading.Event(), threading.Event()
    reclaiming, release_reclaim = threading.Event(), threading.Event()
    original = _seal.seal_digest

    def blocked(entries: Any) -> str:
        building.set()
        release_build.wait(10)
        return original(entries)

    class SlowEntries(dict[int, Any]):
        def popitem(self) -> tuple[int, Any]:
            reclaiming.set()
            release_reclaim.wait(10)
            return super().popitem()

    monkeypatch.setattr(_seal, "seal_digest", blocked)
    seals = _seal.SegmentSeals(lambda marker: True)
    try:
        _request(seals, 0)
        assert building.wait(2)
        _request(seals, 1)
        _put(seals, 2, 2048, SlowEntries)  # the reclaimer takes it and stalls on it
        assert reclaiming.wait(2)
        for index in range(3, 603):  # 1,228,800 more positions dropped meanwhile
            _put(seals, index, 2048)
        reclaimer = seals._reclaimer
        assert reclaimer is not None and reclaimer.is_alive()  # alive, but stalled
        assert seals._reclaim_positions <= _seal.MAX_RECLAIM_POSITIONS
        assert seals.stats()["seal_state_freed_inline"] > 0
    finally:
        release_reclaim.set()
        release_build.set()
        seals.drain(5)
        if (worker := seals._reclaimer) is not None:
            worker.join(5)


# --- 2: dropped state is never released under the seal or allocator lock ---------------------


def test_the_forced_seal_bounds_what_one_segment_retains() -> None:
    assert _seal.FORCED_SEAL_ENTRIES == 65_536  # 050 §3.7 / K5 (P1 review)
    seals = _seal.SegmentSeals(lambda marker: True)
    forced: list[str] = []
    seals.on_forced = forced.append
    segment = "seg-" + "f" * 32
    for sequence in range(_seal.FORCED_SEAL_ENTRIES):
        seals.note_allocated(segment, sequence)
    assert forced == [segment]  # the run table seals it and continues in a new segment


def test_a_dropped_segment_is_never_released_under_the_seal_lock_or_a_hold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_seal, "MAX_PENDING_SEALS", 1)
    _refuse_seal_threads(monkeypatch)
    seals = _seal.SegmentSeals(lambda marker: True)
    held = threading.Lock()  # stands for the allocator lock
    seen: list[tuple[int, int, bool, bool]] = []

    class TrackedEntries(dict[int, Any]):
        def __del__(self) -> None:
            seen.append((threading.get_ident(), len(self), seals._lock.locked(), held.locked()))

    _request(seals, 0)
    _put(seals, 1, 1_000_000)  # retained for a reclaimer that cannot start: the bound
    _seal.hold()  # as the allocator and the run table do around the allocator lock
    held.acquire()
    try:
        _put(seals, 2, _seal.FORCED_SEAL_ENTRIES, TrackedEntries)  # past the bound
        assert seen == []  # never released inside the lock
    finally:
        held.release()
        _seal.unhold()
    try:
        assert len(seen) == 1  # released at unhold, outside both locks
        _, size, seal_locked, allocator_locked = seen[0]
        assert size == _seal.FORCED_SEAL_ENTRIES and not seal_locked and not allocator_locked
        assert seals.stats()["seal_state_freed_inline"] == 1
    finally:
        seals._reclaim.clear()


def test_a_run_exit_releases_dropped_state_only_after_the_allocator_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _install(tmp_path)
    seals = handle._tee.pipeline.seals
    assert isinstance(seals, _seal.SegmentSeals)
    monkeypatch.setattr(_seal, "MAX_PENDING_SEALS", 1)
    _refuse_seal_threads(monkeypatch)
    seen: list[tuple[int, int, bool, bool]] = []
    lock, seal_lock = handle.allocator._lock, seals._lock

    class TrackedEntries(dict[int, Any]):
        def __del__(self) -> None:
            seen.append((threading.get_ident(), len(self), seal_lock.locked(), lock.locked()))

    _request(seals, 0)
    _put(seals, 1, 1_000_000)  # the reclaim backlog at its bound
    try:
        with wire.run("big-run"):
            table = handle.allocator.segments
            run = next(r for r in table._runs.values() if r.depth > 0)  # type: ignore[attr-defined]
            with seals._lock:
                seals._segments[run.open_segment] = _seal._Segment(
                    entries=TrackedEntries.fromkeys(range(_seal.FORCED_SEAL_ENTRIES), DIGEST),
                    source=(handle.allocator.source_id, handle.allocator.epoch),
                )  # fmt: skip
        assert seen and all(not seal_locked and not allocator_locked
                            for _, _, seal_locked, allocator_locked in seen)  # fmt: skip
    finally:
        seals._reclaim.clear()
        handle.close(2)


# --- 3: a seal thread that cannot be constructed --------------------------------------------


def test_a_drain_whose_worker_cannot_be_constructed_fails_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _refuse_seal_threads(monkeypatch)
    seals = _seal.SegmentSeals(lambda marker: True)
    _request(seals, 0)
    _refuse_seal_construction(monkeypatch)
    assert seals.drain(0.01) is False  # never raises (strict mode unset)
    assert seals.stats()["seals_pending"] == 1
    assert seals.stats()["seal_worker_failures"] >= 2


def test_final_fails_when_its_worker_cannot_be_constructed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _install(tmp_path)
    with wire.run("open-run"):
        assert handle._tee.flush(2)
        _refuse_seal_construction(monkeypatch)
        result = handle.close(2)
    assert result is False


@pytest.mark.skipif(not hasattr(threading, "_daemon_threads_allowed"), reason="CPython 3.12+")
def test_the_real_daemon_thread_refusal_never_escapes_flush(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _install(tmp_path)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(threading, "_daemon_threads_allowed", lambda: False)
            with wire.run("run-constructor-refused"):
                pass
            assert handle.flush(0.05) is False
    finally:
        handle.close(2)


@pytest.mark.skipif(not hasattr(threading, "_daemon_threads_allowed"), reason="CPython 3.12+")
def test_the_real_daemon_thread_refusal_fails_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _install(tmp_path)
    with wire.run("open-run"):
        assert handle._tee.flush(2)
        with monkeypatch.context() as patch:
            patch.setattr(threading, "_daemon_threads_allowed", lambda: False)
            result = handle.close(2)
    assert result is False


def test_an_exception_in_final_fails_close(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    handle = _install(tmp_path)
    table = handle.allocator.segments

    def broken() -> None:
        raise RuntimeError("on_final failed")

    monkeypatch.setattr(table, "on_final", broken)
    assert handle.close(2) is False


# --- the final-phase drop accounting, isolated from a pending seal ---------------------------


def test_final_phase_drops_fail_close_with_nothing_left_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_seal, "MAX_PENDING_SEALS", 1)
    release = threading.Event()
    original = _seal.seal_digest

    def held(entries: Any) -> str:
        release.wait(10)
        return original(entries)

    monkeypatch.setattr(_seal, "seal_digest", held)
    handle = _install(tmp_path)
    seals = handle._tee.pipeline.seals
    assert isinstance(seals, _seal.SegmentSeals)
    timer = threading.Timer(0.3, release.set)  # the builder catches up during close
    with contextlib.ExitStack() as blocks:
        for index in range(4):
            blocks.enter_context(wire.run(f"run-{index}", resumable=True))
        timer.start()
        result = handle.close(5.0)
    timer.join()
    stats = seals.stats()
    assert stats["seals_pending"] == 0  # every admitted seal was built: nothing pending
    assert stats["seals_dropped"] >= 2  # only the drops can fail close
    assert result is False
