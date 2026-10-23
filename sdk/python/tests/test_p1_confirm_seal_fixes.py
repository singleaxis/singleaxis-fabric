# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""P1 confirmation-review regressions (spec 050): resume-token acceptance follows the
effective identity mode (049 §2.9 rules 5 and 7); seals waiting for the seal worker are
bounded, failing open with a counted missing seal (049 §7.1); a bounded ``drain`` never
starts a digest it has no time for."""

from __future__ import annotations

import threading
import time
import tracemalloc
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric._loss
import fabric._sequence
from fabric import _seal, _segments, wire
from fabric._capture_types import COUNTERS, STRICT_ENV, Marker
from fabric._segments import format_entry, format_token

from ._records_harness import RecordingContent

SOURCE = "s-" + "b" * 32
BOUND = getattr(_seal, "MAX_PENDING_SEALS", 4096)  # the documented bound
CLEAR = "customer-patient-42"


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


def _segment(index: int) -> str:
    return f"seg-{index:032x}"


def _stalled(monkeypatch: pytest.MonkeyPatch) -> tuple[threading.Event, threading.Event]:
    """Hold the seal worker inside its first digest until ``release`` is set."""
    started, release = threading.Event(), threading.Event()
    original = _seal.seal_digest

    def blocked(entries: object) -> str:
        started.set()
        release.wait(30)
        return original(entries)  # type: ignore[arg-type]

    monkeypatch.setattr(_seal, "seal_digest", blocked)
    return started, release


# --- 1: token acceptance follows the effective identity mode ---------------------------------


def test_production_without_a_key_refuses_a_clear_token_even_in_clear_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "clear")  # requested, but no key: pseudonymous
    exporter = InMemorySpanExporter()
    handle = wire.install(
        content_endpoint="http://127.0.0.1:4318/content", tenant_id="tenant-a",
        spool_dir=str(tmp_path / "spool"), spool_max_bytes=128 << 20, span_exporter=exporter,
        content_client=cast("Any", RecordingContent()), patch_httpx=False,
        patch_aiohttp=False,
    )  # fmt: skip
    assert handle.gate is not None and handle.gate.profile == "production"
    assert handle.config.id_key is None
    entry = format_entry("seg-" + "c" * 32, "s-" + "e" * 32, 5, 3, "sha256:" + "d" * 64)
    token = format_token(CLEAR, entry)
    assert token is not None
    records = handle.records
    assert records is not None
    with wire.run(resume=token, resumable=True):
        attempt = records.begin("tool_call", "sdk.records")
        assert attempt is not None
        assert attempt.emit("end", name_hint="fabric.tool_call", attributes={}, start_ns=1,
                            end_ns=2)  # fmt: skip
    assert handle.flush(10.0)
    rows = [dict(span.attributes or {}) for span in exporter.get_finished_spans()]
    markers = {r.get("fabric.run.id") for r in rows if r.get("fabric.heartbeat.kind")
               in ("run_start", "run_end", "segment_seal")}  # fmt: skip
    record_ids = {r.get("fabric.run.id") for r in rows
                  if r.get("fabric.capture.input") == "records"}  # fmt: skip
    assert CLEAR not in str(rows)
    assert markers == record_ids and len(markers) == 1 and None not in markers
    table = handle.allocator.segments
    assert isinstance(table, _segments.SegmentTable)
    assert table.stats()["tokens_rejected"] == 1
    assert table.rule.effective_mode == "pseudonymous"


# --- 2: the seals waiting for the worker are bounded -----------------------------------------


def test_pending_seals_are_bounded_while_the_builder_is_stalled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started, release = _stalled(monkeypatch)
    markers: list[Marker] = []
    seals = _seal.SegmentSeals(markers.append)
    try:
        seals.request_seal(_segment(0), last_sequence=-1, manifest_digest=None, terminal=True,
                           resumable=False, source_id=SOURCE, epoch=7)  # fmt: skip
        assert started.wait(5)
        begun = time.perf_counter()
        for index in range(1, 20_001):
            seals.request_seal(_segment(index), last_sequence=-1, manifest_digest=None,
                               terminal=True, resumable=False, source_id=SOURCE,
                               epoch=7)  # fmt: skip
        assert time.perf_counter() - begun < 5.0  # never blocked on the stalled builder
        stats = seals.stats()
        assert stats["seals_pending"] <= BOUND + 1  # + the one building
        assert stats.get("seals_dropped") == 20_000 - BOUND
    finally:
        release.set()
    assert seals.drain(30.0) is False  # seals were dropped: the record is incomplete
    assert seals.drain(1.0) is True  # reported once
    assert len(markers) == BOUND + 1
    assert seals.stats()["seals_pending"] == 0


def test_pending_seal_memory_is_bounded_by_retained_positions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_seal, "MAX_PENDING_SEAL_POSITIONS", 4096, raising=False)
    started, release = _stalled(monkeypatch)
    markers: list[Marker] = []
    seals = _seal.SegmentSeals(markers.append)
    digest = "sha256:" + "c" * 64

    def complete(index: int, positions: int) -> None:
        segment = _segment(index)
        for sequence in range(positions):
            seals.note_allocated(segment, sequence)
            seals.settle(segment, sequence, digest)
        seals.request_seal(segment, last_sequence=positions - 1, manifest_digest=None,
                           terminal=True, resumable=False, source_id=SOURCE,
                           epoch=7)  # fmt: skip

    try:
        complete(0, 1)
        assert started.wait(5)
        tracemalloc.start()
        before = tracemalloc.get_traced_memory()[0]
        for index in range(1, 2_001):  # 2,000 segments of 64 positions: 128,000 positions
            complete(index, 64)
        grown = tracemalloc.get_traced_memory()[0] - before
        tracemalloc.stop()
        stats = seals.stats()
        assert stats["seals_pending"] <= 1 + 4096 // 64
        assert getattr(seals, "_ready_positions", 0) <= 4096
        assert stats.get("seals_dropped") == 2_000 - 4096 // 64
        assert stats["open_segments"] == 0  # dropped state is released, not kept
        assert grown < 4 << 20, grown  # unbounded, 128,000 retained positions is ~20 MB
    finally:
        release.set()
    assert seals.drain(30.0) is False
    assert len(markers) == 1 + 4096 // 64


def test_one_seal_is_always_admitted_whatever_its_size(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_seal, "MAX_PENDING_SEAL_POSITIONS", 8, raising=False)
    markers: list[Marker] = []
    seals = _seal.SegmentSeals(markers.append)
    for sequence in range(100):  # larger than the position bound, nothing else waiting
        seals.note_allocated(_segment(1), sequence)
        seals.settle(_segment(1), sequence, "loss:queue_full")
    seals.request_seal(_segment(1), last_sequence=99, manifest_digest=None, terminal=True,
                       resumable=False, source_id=SOURCE, epoch=7)  # fmt: skip
    assert seals.drain(10.0)
    assert [m.segment_id for m in markers] == [_segment(1)]
    assert seals.stats()["seals_dropped"] == 0


# --- 3: a bounded drain never starts a digest it has no time for ------------------------------


def test_drain_without_a_worker_honours_its_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    original = _seal.seal_digest

    def slow(entries: object) -> str:
        time.sleep(0.2)
        return original(entries)  # type: ignore[arg-type]

    def refuse(self: threading.Thread) -> None:
        raise RuntimeError("can't create new thread at interpreter shutdown")

    monkeypatch.setattr(_seal, "seal_digest", slow)
    monkeypatch.setattr(threading.Thread, "start", refuse)
    markers: list[Marker] = []
    seals = _seal.SegmentSeals(markers.append)
    seals.request_seal(_segment(1), last_sequence=-1, manifest_digest=None, terminal=True,
                       resumable=False, source_id=SOURCE, epoch=7)  # fmt: skip
    begun = time.monotonic()
    assert seals.drain(0) is False
    assert time.monotonic() - begun < 0.1
    assert seals.stats()["seals_pending"] == 1 and markers == []  # still pending, counted
    assert seals.drain(5.0) is False  # bounded: never hashed on the caller (050 final review)
    assert seals.drain(None) is True  # an unbounded drain builds on its caller
    assert [m.kind for m in markers] == ["segment_seal"]


def test_drain_without_a_worker_skips_a_digest_longer_than_the_time_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(self: threading.Thread) -> None:
        raise RuntimeError("can't create new thread at interpreter shutdown")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    seals = _seal.SegmentSeals(lambda marker: True)
    for sequence in range(100_000):  # an estimated 0.2 s digest
        seals.note_allocated(_segment(1), sequence)
        seals.settle(_segment(1), sequence, "loss:queue_full")
    seals.request_seal(_segment(1), last_sequence=99_999, manifest_digest=None, terminal=True,
                       resumable=False, source_id=SOURCE, epoch=7)  # fmt: skip
    begun = time.monotonic()
    assert seals.drain(0.05) is False
    assert time.monotonic() - begun < 0.1
    assert seals.stats()["seals_pending"] == 1
