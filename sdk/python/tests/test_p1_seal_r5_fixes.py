# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""P1 seal review r5 (spec 050 §3.7, 049 §7.1): the reclaim backlog is bounded in segments
as well as positions, so empty dropped segments cannot pile up while the seal worker and the
reclaimer are stalled or cannot start (Sol: 14,096 empty ``wire.run()`` blocks)."""

from __future__ import annotations

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

BOUND = getattr(_seal, "MAX_RECLAIM_SEGMENTS", _seal.MAX_PENDING_SEALS)
RUNS = _seal.MAX_PENDING_SEALS + 10_000  # 14,096


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


def _install(tmp_path: Path) -> tuple[wire.WireHandle, _seal.SegmentSeals]:
    handle = wire.install(spool_dir=str(tmp_path / "spool"), span_exporter=InMemorySpanExporter(),
                          patch_httpx=False, patch_aiohttp=False, id_key=b"k" * 32)  # fmt: skip
    seals = handle._tee.pipeline.seals
    assert isinstance(seals, _seal.SegmentSeals)
    return handle, seals


def _assert_bounded(seals: _seal.SegmentSeals) -> None:
    stats = seals.stats()
    assert len(seals._reclaim) <= BOUND, len(seals._reclaim)
    assert getattr(seals, "_reclaim_segments", 0) <= BOUND
    assert stats["seals_pending"] <= _seal.MAX_PENDING_SEALS + 1  # + the one building
    assert stats["seals_dropped"] >= RUNS - _seal.MAX_PENDING_SEALS - 1
    assert stats["seal_state_freed_inline"] > 0  # past the bound: released after unlock


def test_empty_runs_keep_the_reclaim_backlog_bounded_with_stalled_live_threads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    building, release_build = threading.Event(), threading.Event()
    reclaiming, release_reclaim = threading.Event(), threading.Event()
    original_digest = _seal.seal_digest
    original_reclaim = _seal.SegmentSeals._reclaim_work

    def blocked_digest(entries: Any) -> str:
        building.set()
        release_build.wait(30)
        return original_digest(entries)

    def blocked_reclaim(self: _seal.SegmentSeals) -> None:
        reclaiming.set()
        release_reclaim.wait(30)
        original_reclaim(self)

    monkeypatch.setattr(_seal, "seal_digest", blocked_digest)
    monkeypatch.setattr(_seal.SegmentSeals, "_reclaim_work", blocked_reclaim)
    handle, seals = _install(tmp_path)
    try:
        with wire.run("building"):
            pass
        assert building.wait(5)
        for index in range(RUNS):
            with wire.run(f"empty-{index}"):
                pass
        assert reclaiming.wait(5)
        worker, reclaimer = seals._worker, seals._reclaimer
        assert worker is not None and worker.is_alive()  # both alive, both stalled
        assert reclaimer is not None and reclaimer.is_alive()
        _assert_bounded(seals)
    finally:
        release_reclaim.set()
        release_build.set()
        seals.drain(30)
        handle.close(5)


def test_empty_runs_keep_the_reclaim_backlog_bounded_when_no_thread_can_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle, seals = _install(tmp_path)
    original = threading.Thread.start

    def start(self: threading.Thread) -> None:
        if self.name.startswith("fabric-seal"):
            raise RuntimeError("thread start refused")
        original(self)

    monkeypatch.setattr(threading.Thread, "start", start)
    try:
        for index in range(RUNS):
            with wire.run(f"public-empty-{index}"):
                pass
        _assert_bounded(seals)
    finally:
        assert handle.close(2) is False  # seals were dropped and left pending
        seals._reclaim.clear()
        seals._ready.clear()
