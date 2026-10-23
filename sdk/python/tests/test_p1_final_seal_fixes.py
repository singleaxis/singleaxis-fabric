# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""P1 final-review regressions (spec 050 §3.7, 049 §7.1): a bounded ``drain`` never hashes
on its caller; seals dropped while finalizing fail ``close()`` (sticky, whatever drained
before); a dropped segment's state is never freed on the caller."""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric._loss
import fabric._sequence
from fabric import _seal, wire
from fabric._capture_types import COUNTERS, STRICT_ENV, Marker

SOURCE = "s-" + "b" * 32
DIGEST = "sha256:" + "c" * 64


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


def _refuse_seal_threads(monkeypatch: pytest.MonkeyPatch) -> None:
    """No seal thread can start (late interpreter shutdown); other threads still can."""
    original = threading.Thread.start

    def start(self: threading.Thread) -> None:
        if self.name.startswith("fabric-seal"):
            raise RuntimeError("can't create new thread at interpreter shutdown")
        original(self)

    monkeypatch.setattr(threading.Thread, "start", start)


# --- 3: a positive drain deadline holds without a worker -------------------------------------


@pytest.mark.parametrize("timeout", [0.005, 0.05])
def test_a_bounded_drain_never_hashes_on_its_caller(
    monkeypatch: pytest.MonkeyPatch, timeout: float
) -> None:
    calls: list[int] = []
    original = _seal.seal_digest

    def slow(entries: Any) -> str:
        calls.append(threading.get_ident())
        time.sleep(0.2)
        return original(entries)

    _refuse_seal_threads(monkeypatch)
    monkeypatch.setattr(_seal, "seal_digest", slow)
    markers: list[Marker] = []
    seals = _seal.SegmentSeals(markers.append)
    _request(seals, 1)
    begun = time.monotonic()
    assert seals.drain(timeout) is False
    assert time.monotonic() - begun < timeout + 0.05
    assert calls == [] and markers == []  # left pending, never hashed here
    assert seals.stats()["seals_pending"] == 1
    assert seals.drain(None) is True  # only an unbounded drain builds on its caller
    assert [m.kind for m in markers] == ["segment_seal"]


def test_a_bounded_drain_restarts_a_missing_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    original = threading.Thread.start
    refused = [True]

    def start(self: threading.Thread) -> None:
        if self.name == "fabric-seal" and refused[0]:
            raise RuntimeError("thread start refused")
        original(self)

    monkeypatch.setattr(threading.Thread, "start", start)
    markers: list[Marker] = []
    seals = _seal.SegmentSeals(markers.append)
    _request(seals, 1)
    assert seals.stats()["seal_worker_failures"] == 1
    refused[0] = False  # threads can start again: the drain starts the worker
    assert seals.drain(5.0) is True
    assert [m.kind for m in markers] == ["segment_seal"]


# --- 1: seals dropped while finalizing fail close() ------------------------------------------


def test_seals_dropped_in_the_final_phase_fail_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_seal, "MAX_PENDING_SEALS", 1)
    _refuse_seal_threads(monkeypatch)
    exporter = InMemorySpanExporter()
    handle = wire.install(spool_dir=str(tmp_path / "spool"), span_exporter=exporter,
                          patch_httpx=False, patch_aiohttp=False, id_key=b"k" * 32)  # fmt: skip
    with contextlib.ExitStack() as blocks:
        for index in range(4):
            blocks.enter_context(wire.run(f"run-{index}"))
        assert handle._tee.flush(5.0)
        result = handle.close(5.0)
    seals = handle._tee.pipeline.seals
    assert isinstance(seals, _seal.SegmentSeals)
    assert seals.stats()["seals_dropped"] == 3
    assert result is False, "close reported success despite seals lost in final"
    registration = handle.registration
    assert registration is not None and registration._final  # the final marker is durable


def test_a_drop_before_close_is_not_consumed_by_an_intermediate_drain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = wire.install(spool_dir=str(tmp_path / "spool"), span_exporter=InMemorySpanExporter(),
                          patch_httpx=False, patch_aiohttp=False, id_key=b"k" * 32)  # fmt: skip
    seals = handle._tee.pipeline.seals
    assert isinstance(seals, _seal.SegmentSeals)
    monkeypatch.setattr(_seal, "MAX_PENDING_SEALS", 1)
    started, release = threading.Event(), threading.Event()
    original = _seal.seal_digest

    def blocked(entries: Any) -> str:
        started.set()
        release.wait(10)
        return original(entries)

    monkeypatch.setattr(_seal, "seal_digest", blocked)
    for index in range(3):  # each outermost exit hands its seal off
        with wire.run(f"run-{index}"):
            pass
        if index == 0:
            assert started.wait(5)  # the first is building (stalled), the second waits
    assert seals.stats()["seals_dropped"] == 1  # the third
    release.set()
    assert handle.flush(5.0) is False  # this flush reports the drop ...
    assert handle.flush(5.0) is True  # ... and the next one has nothing new
    monkeypatch.setattr(_seal, "seal_digest", original)
    assert handle.close(5.0) is False  # but the epoch's close still does (sticky)


def test_a_close_without_drops_succeeds(tmp_path: Path) -> None:
    handle = wire.install(spool_dir=str(tmp_path / "spool"), span_exporter=InMemorySpanExporter(),
                          patch_httpx=False, patch_aiohttp=False, id_key=b"k" * 32)  # fmt: skip
    with wire.run("run-ok", resumable=True):  # left open: sealed by final()
        assert handle.close(5.0) is True


# --- 2: a dropped segment's state is never freed on the caller -------------------------------


def test_a_dropped_large_segment_is_freed_off_the_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    started, release = threading.Event(), threading.Event()
    original = _seal.seal_digest

    def blocked(entries: Any) -> str:
        started.set()
        release.wait(30)
        return original(entries)

    monkeypatch.setattr(_seal, "seal_digest", blocked)
    seals = _seal.SegmentSeals(lambda marker: True)
    reclaimed: list[tuple[int, int]] = []

    class TrackedEntries(dict[int, Any]):
        """Its release is observable and slow (a large dict's free, made unmistakable)."""

        size = 0

        def __setitem__(self, key: int, value: Any) -> None:
            super().__setitem__(key, value)
            TrackedEntries.size = max(TrackedEntries.size, len(self))

        def __del__(self) -> None:
            reclaimed.append((threading.get_ident(), TrackedEntries.size))
            time.sleep(0.2)

    try:
        _request(seals, 0)
        assert started.wait(2)
        _request(seals, 1)  # a waiting seal: the position bound applies
        segment = f"seg-{2:032x}"
        seals.note_allocated(segment, 0)
        seals._segments[segment].entries = TrackedEntries()
        for sequence in range(1_000_000):
            if sequence:
                seals.note_allocated(segment, sequence)
            seals.settle(segment, sequence, DIGEST)
        caller = threading.get_ident()
        begun = time.perf_counter()
        _request(seals, 2, 999_999)
        elapsed = time.perf_counter() - begun
        assert seals.stats()["seals_dropped"] == 1
        assert (caller, 1_000_000) not in reclaimed, "the caller freed the whole segment"
        assert elapsed < 0.1, elapsed  # the 0.2 s release never runs on the caller
        deadline = time.monotonic() + 10
        while not reclaimed and time.monotonic() < deadline:
            time.sleep(0.01)
        assert reclaimed and reclaimed[0][0] != caller and reclaimed[0][1] == 1_000_000
        while getattr(seals, "_reclaim_positions", 0) and time.monotonic() < deadline:
            time.sleep(0.01)  # counted until its release has finished
        assert getattr(seals, "_reclaim_positions", 0) == 0
    finally:
        release.set()
        seals.drain(30.0)


def test_dropped_state_counts_against_the_bound_and_stays_bounded_without_a_reclaimer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_seal, "MAX_PENDING_SEALS", 1)
    monkeypatch.setattr(_seal, "MAX_RECLAIM_POSITIONS", 8192, raising=False)
    monkeypatch.setattr(_seal, "RECLAIM_INLINE_POSITIONS", 16, raising=False)
    started, release = threading.Event(), threading.Event()
    original_digest = _seal.seal_digest

    def blocked(entries: Any) -> str:
        started.set()
        release.wait(30)
        return original_digest(entries)

    monkeypatch.setattr(_seal, "seal_digest", blocked)
    original_start = threading.Thread.start

    def start(self: threading.Thread) -> None:
        if self.name == "fabric-seal-reclaim":
            raise RuntimeError("thread start refused")
        original_start(self)

    monkeypatch.setattr(threading.Thread, "start", start)
    seals = _seal.SegmentSeals(lambda marker: True)

    def complete(index: int, positions: int) -> None:
        segment = f"seg-{index:032x}"
        for sequence in range(positions):
            seals.note_allocated(segment, sequence)
            seals.settle(segment, sequence, DIGEST)
        _request(seals, index, positions - 1)

    try:
        complete(0, 1)
        assert started.wait(5)
        complete(1, 1)  # waiting: the bounds apply
        for index in range(2, 202):  # 200 dropped segments of 512 positions
            complete(index, 512)
        stats = seals.stats()
        assert stats["seals_dropped"] == 200
        assert getattr(seals, "_reclaim_positions", 0) <= 8192  # bounded, no reclaimer
        assert stats.get("seal_state_freed_inline") == 200 - 8192 // 512
    finally:
        release.set()
        seals.drain(30.0)
