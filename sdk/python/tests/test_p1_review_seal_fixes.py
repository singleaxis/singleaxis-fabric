# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""P1 review regressions (spec 050): the seal digest never runs on the application thread
or under the allocator lock (C, 049 §7.1 / §3.16); an epoch registration is finalized only
once its ``final`` marker is durably spooled (D, §3.2 rule 3); the run table forgets ended
runs (bounded memory); a pseudonymous consumer never takes a clear correlation id from a
resume token (R8, 049 §2.9 rule 7)."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

import fabric._loss
import fabric._sequence
from fabric import _seal, _segments, wire
from fabric._capture_types import COUNTERS, STRICT_ENV, Marker
from fabric._segments import format_entry, format_token
from fabric._sequence import SourceAllocator
from fabric.wire import _registration as reg
from fabric.wire._spool import Spool, unframe_all

KEY = b"fabric-test-id-key-not-a-secret"
SEG = "seg-" + "a" * 32
SOURCE = "s-" + "b" * 32
SLOW_S = 0.4  # how long the instrumented seal digest takes
FAST_S = 0.2  # the application-side bound: well under the digest's own time


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    for name in ("FABRIC_RUN_ID", "FABRIC_RUN_RESUME_TOKEN", "FABRIC_WIRE_ID_KEY"):
        monkeypatch.delenv(name, raising=False)
    COUNTERS.reset()
    emitter = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)
    COUNTERS.reset()


class _Null(SpanExporter):
    def export(self, spans: Any) -> SpanExportResult:
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def _install(tmp_path: Path, **overrides: Any) -> wire.WireHandle:
    return wire.install(spool_dir=str(tmp_path / "spool"), span_exporter=_Null(),
                        patch_httpx=False, patch_aiohttp=False, source_id="host-p1",
                        **overrides)  # fmt: skip


def _record(handle: wire.WireHandle) -> None:
    records = handle.records
    assert records is not None
    attempt = records.begin("tool_call", "sdk.records")
    assert attempt is not None
    now = time.time_ns()
    assert attempt.emit("end", name_hint="tool", attributes={}, start_ns=now, end_ns=now)


def _slow_digest(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Make the seal digest slow and record the threads it runs on."""
    threads: list[int] = []
    original = _seal.seal_digest

    def digest(entries: Any) -> str:
        threads.append(threading.get_ident())
        time.sleep(SLOW_S)
        return original(entries)

    monkeypatch.setattr(_seal, "seal_digest", digest)
    return threads


def _hold(handle: wire.WireHandle) -> None:
    """Stop the spool's drainer, so what is spooled stays readable (pumped by the test)."""
    sender = handle._tee.sender
    assert sender is not None
    sender._stop.set()
    sender._wake.set()
    deadline = time.monotonic() + 5
    while sender._thread is not None and sender._thread.is_alive():
        assert time.monotonic() < deadline
        time.sleep(0.01)


def _spooled(handle: wire.WireHandle) -> list[dict[str, Any]]:
    sender = handle._tee.sender
    assert sender is not None
    assert handle._tee.flush(10.0)
    sender.pump()
    return [doc for name in sender.spool.names()
            for doc, _ in unframe_all(sender.spool.read(name))]  # fmt: skip


# --- C: the seal is built on the seal worker -------------------------------------------------


def test_request_seal_is_o1_on_the_caller_and_hashes_on_the_seal_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    markers: list[Marker] = []
    seals = _seal.SegmentSeals(markers.append)
    for sequence in range(20_000):
        seals.note_allocated(SEG, sequence)
        seals.settle(SEG, sequence, "sha256:" + "c" * 64)
    threads = _slow_digest(monkeypatch)
    started = time.perf_counter()
    seals.request_seal(SEG, last_sequence=19_999, manifest_digest=None, terminal=True,
                       resumable=False, source_id=SOURCE, epoch=7)  # fmt: skip
    elapsed = time.perf_counter() - started
    assert elapsed < FAST_S, elapsed  # the caller never waits for the digest
    assert seals.stats()["seals_pending"] == 1  # accounted until its marker is queued
    assert seals.drain(10.0)
    assert threads and threading.get_ident() not in threads
    [marker] = markers
    assert marker.kind == "segment_seal" and marker.seal is not None
    assert seals.stats()["seals_pending"] == 0 and seals.stats()["sealed"] == 1


def test_settle_hands_off_too_and_markers_keep_hand_off_order() -> None:
    markers: list[Marker] = []
    seals = _seal.SegmentSeals(markers.append)
    seals.bind_source(lambda: (SOURCE, 7))
    segments = [f"seg-{index:032x}" for index in range(50)]
    for segment in segments:
        seals.note_allocated(segment, 0)
        seals.request_seal(segment, last_sequence=0, manifest_digest=None, terminal=False,
                           resumable=True)  # fmt: skip
    for segment in segments:  # the settle (a worker or a loss path) completes each seal
        seals.settle(segment, 0, "loss:queue_full")
    assert seals.drain(10.0)
    assert [m.segment_id for m in markers] == segments


def test_drain_builds_on_the_caller_when_no_worker_can_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    markers: list[Marker] = []
    seals = _seal.SegmentSeals(markers.append)

    def refuse(self: threading.Thread) -> None:
        raise RuntimeError("can't create new thread at interpreter shutdown")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    seals.request_seal(SEG, last_sequence=-1, manifest_digest=None, terminal=True,
                       resumable=False, source_id=SOURCE, epoch=7)  # fmt: skip
    assert markers == [] and seals.stats()["seal_worker_failures"] == 1
    assert seals.drain(1.0)
    assert [m.kind for m in markers] == ["segment_seal"]


def test_run_exit_never_hashes_on_the_app_thread_or_under_the_allocator_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _install(tmp_path, id_key=KEY)
    _hold(handle)
    threads = _slow_digest(monkeypatch)
    with wire.run("job-c"):
        _record(handle)
        assert handle._tee.flush(5.0)  # the position settled: the exit's seal is ready
        threads.clear()
        started = time.perf_counter()
    exit_s = time.perf_counter() - started
    waited: list[float] = []

    def allocate() -> None:  # another application thread, during the seal
        begun = time.perf_counter()
        handle.allocator.allocate()
        waited.append(time.perf_counter() - begun)

    other = threading.Thread(target=allocate)
    other.start()
    other.join(5.0)
    assert exit_s < FAST_S, exit_s
    assert waited and waited[0] < FAST_S, waited  # the allocator lock is not held for it
    assert handle._tee.flush(10.0)
    assert threads and threading.get_ident() not in threads
    kinds = [d["marker"]["kind"] for d in _spooled(handle) if d["record_kind"] == "marker"]
    assert "segment_seal" in kinds


def test_close_queues_every_seal_before_the_final_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _install(tmp_path, id_key=KEY)
    _slow_digest(monkeypatch)
    queued: list[str] = []
    loss = handle._tee.loss
    original = loss._queue

    def spy(marker: Marker) -> bool:
        queued.append(marker.kind)
        return original(marker)

    monkeypatch.setattr(loss, "_queue", spy)
    with wire.run("job-order", resumable=True):  # left open: final() seals it
        _record(handle)
        assert handle.close(10.0)
    assert queued.index("segment_seal") < queued.index("final"), queued


# --- D: finalize the registration only after a durable final --------------------------------


def test_final_trigger_leaves_the_epoch_declarable_until_final_is_durable(
    tmp_path: Path,
) -> None:
    """The review repro: ``_p1_final`` runs before ``loss.final()``; a writer that dies
    right after it must still be declared an orphan at its high-water mark."""
    spool = Spool(str(tmp_path / "spool"), 64 << 20)
    allocator = SourceAllocator(SOURCE)
    registration = reg.register(spool, allocator.source_id, allocator.epoch,
                                allocator=allocator)  # fmt: skip
    try:
        allocator.allocate()
        handle: Any = SimpleNamespace(
            allocator=SimpleNamespace(segments=SimpleNamespace(on_final=lambda: None)),
            registration=registration,
        )  # fmt: skip
        wire._p1_final(handle)
        registration._release()  # the writer dies: no orderly close
        orphans = reg.scan_orphans(spool)
        assert len(orphans) == 1 and orphans[0].next_sequence == 1
    finally:
        registration.close()
        spool.release()


def test_a_close_that_could_not_spool_final_keeps_the_registration(tmp_path: Path) -> None:
    handle = _install(tmp_path)
    registration = handle.registration
    assert registration is not None and registration.status == "registered"
    path = Path(str(registration.path))
    with wire.run("job-d"):
        _record(handle)
    assert handle.flush(5.0)
    sender = handle._tee.sender
    assert sender is not None

    def stalled_close(timeout_s: float, *, exiting: bool = False) -> bool:
        sender.loss.attach(None)  # a pump that never got to spool the final marker
        sender._stop.set()
        sender._wake.set()
        return False

    sender.close = stalled_close  # type: ignore[method-assign]
    epoch, last = handle.allocator.last_sequence()
    assert handle.close(1.0) is False
    assert path.exists()  # kept, unflagged
    data = path.read_bytes()
    fields = reg.decode(data)
    assert fields is not None and not fields["final"]
    scanner = Spool(str(tmp_path / "spool"), 64 << 20)
    try:
        orphans = reg.scan_orphans(scanner)
    finally:
        scanner.release()
    assert epoch == registration.epoch
    assert [(o.epoch, o.next_sequence) for o in orphans] == [(epoch, last + 1)]


def test_an_orderly_close_finalizes_and_removes_the_registration(tmp_path: Path) -> None:
    handle = _install(tmp_path)
    registration = handle.registration
    assert registration is not None
    path = Path(str(registration.path))
    with wire.run("job-ok"):
        _record(handle)
    assert handle.close(10.0)
    assert not path.exists()
    scanner = Spool(str(tmp_path / "spool"), 64 << 20)
    try:
        assert reg.scan_orphans(scanner) == []
    finally:
        scanner.release()


# --- the run table forgets ended runs ------------------------------------------------------


def test_ended_runs_leave_the_run_table_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_segments, "MAX_RETIRED_RUNS", 16, raising=False)
    handle = _install(tmp_path, id_key=KEY)
    table = handle.allocator.segments
    assert isinstance(table, _segments.SegmentTable)
    for _ in range(200):
        with wire.run():  # one minted run per request
            pass
    assert len(table._runs) == 0
    assert len(table._retired) == 16
    assert table.stats()["open_runs"] == 0 and table.stats()["segments_sealed"] == 200


def test_a_retired_run_still_continues_locally_and_counts_post_terminal_use(
    tmp_path: Path,
) -> None:
    handle = _install(tmp_path, id_key=KEY)
    _hold(handle)
    table = handle.allocator.segments
    assert isinstance(table, _segments.SegmentTable)
    with wire.run("job-again"):  # outermost exit: a terminal seal, then retired
        _record(handle)
    emitted = fabric._sequence.run_pseudonym("job-again", KEY)
    first = table.get(emitted)
    assert (
        isinstance(first, _segments._Run) and emitted not in table._runs
    )  # retired, still readable
    entry = first.last_entry
    with wire.run("job-again"):  # re-entered: post-terminal (K2), continued locally
        _record(handle)
    assert table.stats()["post_terminal_allocations"] >= 1
    starts = [d["marker"] for d in _spooled(handle)
              if d["record_kind"] == "marker" and d["marker"]["kind"] == "run_start"]  # fmt: skip
    assert [m["predecessors"] for m in starts] == [["none"], [entry]]


# --- a pseudonymous consumer never takes a clear correlation id ----------------------------


def _clear_token(source: str = "host-x") -> str:
    entry = format_entry("seg-" + "c" * 32, source, 5, 3, "sha256:" + "d" * 64)
    token = format_token("customer-run-42", entry)
    assert token is not None
    return token


def test_a_pseudonymous_consumer_rejects_a_clear_correlation_id(tmp_path: Path) -> None:
    handle = _install(tmp_path, id_key=KEY)
    _hold(handle)
    with wire.run(resume=_clear_token(), resumable=True):
        _record(handle)
    docs = _spooled(handle)
    records = {d["span"]["attributes"].get("fabric.run.id")
               for d in docs if d["record_kind"] == "record"}  # fmt: skip
    markers = {d["marker"].get("run_id") for d in docs
               if d["record_kind"] == "marker" and d["marker"].get("run_id")}  # fmt: skip
    assert records == markers and len(records) == 1  # records and markers agree
    (run_id,) = records
    assert run_id is not None and run_id.startswith("r-")
    assert all("customer-run-42" not in str(d) for d in docs)
    table = handle.allocator.segments
    assert isinstance(table, _segments.SegmentTable)
    assert table.stats()["tokens_rejected"] == 1


def test_a_clear_mode_consumer_keeps_the_token_correlation_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "clear")
    handle = _install(tmp_path)
    table = handle.allocator.segments
    assert isinstance(table, _segments.SegmentTable)
    plan = table.prepare(resume=_clear_token())
    assert (plan.run_id, plan.identity.id_basis) == ("customer-run-42", "token")
    assert os.environ["FABRIC_IDENTITY_MODE"] == "clear"
