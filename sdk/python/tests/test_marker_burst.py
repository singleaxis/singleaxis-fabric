# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run markers under bursts (P1 review P2-4).

Before: the marker queue held 1,024 markers and the spool sender fsync'd one marker per
file, so 2,000 plain ``wire.run()`` blocks dropped 4,900 of 6,000 markers and fully
recorded runs verified as ``unverified``/``partial``. Now the sender spools markers 64 to a
batch file (D4), the queue is bounded at 16,384 markers and 16 MiB (``_loss``), queuing
stays O(1) on the app thread, and a marker that is still dropped is counted and leaves its
scope or segment reported as a gap, never complete. Markers the spool cannot take are held
and mirrored to the loss ledger (D1); a drainer replays them after the process dies."""

from __future__ import annotations

import errno
import json
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
import uuid
from collections import Counter
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

import fabric._loss
import fabric._sequence
from fabric import _loss, wire
from fabric._capture_types import COUNTERS, STRICT_ENV, Marker, SealInfo
from fabric.reconstruct import reconstruct
from fabric.wire import _ledger, _sender
from fabric.wire._spool import Spool, marker_doc, unframe_all

from .test_segments_run import EXPORTER, KEY, SRC, JsonlExporter
from .test_wire_spool import wait_for

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX spool")

RUN_KINDS = ("run_start", "run_end", "segment_seal")
QUEUED_KINDS = (*RUN_KINDS, "final", "manifest")  # every kind that goes through the queue
COMPLETE = ("complete_for_observed_scopes", "complete_for_declared_scope")


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    monkeypatch.setenv("FABRIC_CLOCK_UNCERTAINTY_MS", "0")
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


def _install(host: Path, source: str) -> wire.WireHandle:
    host.mkdir(parents=True, exist_ok=True)
    return wire.install(
        spool_dir=str(host / "spool"), span_exporter=JsonlExporter(host / "spans.jsonl"),
        patch_httpx=False, patch_aiohttp=False, source_id=source, id_key=KEY.encode(),
    )  # fmt: skip


def _blocks(handle: wire.WireHandle, count: int) -> None:
    """``count`` plain run blocks with one record each, back to back on this thread."""
    records = handle.records
    assert records is not None
    for _ in range(count):
        with wire.run():
            attempt = records.begin("tool_call", "sdk.records")
            assert attempt is not None
            now = time.time_ns()
            assert attempt.emit("end", name_hint="tool", attributes={}, start_ns=now, end_ns=now)


def _spans(host: Path) -> list[dict[str, Any]]:
    path = host / "spans.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _markers(spans: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Delivered queued markers (no periodic heartbeat) by event id: one per marker."""
    found: dict[str, dict[str, Any]] = {}
    for span in spans:
        attrs = span["attributes"]
        kind = "manifest" if span["name"] == _loss.SPAN_MANIFEST else attrs.get(
            "fabric.heartbeat.kind")  # fmt: skip
        if kind in QUEUED_KINDS and isinstance(event := attrs.get("fabric.event_id"), str):
            found[event] = {"kind": kind, **attrs}
    return found


def _report(host: Path) -> dict[str, Any]:
    return reconstruct([host / "spans.jsonl"], evaluated_at=datetime.now(UTC))


def _seal_marker(index: int, source: str = "src-burst", epoch: int = 7) -> Marker:
    return Marker(
        "segment_seal", source, epoch, index, run_id=f"r-{uuid.uuid4().hex}",
        scope_id=str(uuid.uuid4()), segment_id=f"seg-{uuid.uuid4().hex}", terminal=True,
        resumable=False, seal=SealInfo(index, "sha256:" + "0" * 64, "sha256:" + "1" * 64, ()),
        manifest_seq=0,
    )  # fmt: skip


class _Recording(SpanExporter):
    def __init__(self) -> None:
        self.spans: list[ReadableSpan] = []

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self.spans += spans
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


@pytest.fixture
def recording() -> _Recording:
    return _Recording()


@pytest.fixture
def sender(tmp_path: Path, recording: _Recording) -> Iterator[_sender.Sender]:
    """A sender on its own spool whose loss emitter never drains by itself (``attach``):
    only an explicit pump spools."""
    loss = _loss.LossEmitter()
    spool = Spool(str(tmp_path / "spool"), 256 * 1024 * 1024, 4096)
    built = _sender.Sender(spool, recording, loss, content=None, service_name="burst")
    loss.attach(lambda: None)
    yield built
    loss.attach(None)
    loss._stop.set()
    spool.release()


def _spooled_events(spool: Spool) -> list[str]:
    """Marker event ids in the spool, in drain (file name, then frame) order."""
    docs = [doc for name in spool.names() for doc, _ in unframe_all(spool.read(name))]
    return [doc["marker"]["event_id"] for doc in docs if doc["record_kind"] == "marker"]


# --- the burst repro -------------------------------------------------------------------------


def test_a_burst_of_run_blocks_drops_no_marker_and_every_run_verifies(tmp_path: Path) -> None:
    """The review's repro: 2,000 run blocks back to back on the spool path. No marker is
    dropped or left held, flush acknowledges, and every fully recorded run verifies."""
    host = tmp_path / "a"
    handle = _install(host, "host-burst")
    _blocks(handle, 2000)
    assert handle.flush(60.0)
    stats = handle.stats()
    assert (stats.markers_dropped, stats.markers_held) == (0, 0)
    assert handle.close(60.0)
    markers = _markers(_spans(host))
    kinds = Counter(m["kind"] for m in markers.values())
    assert {kind: kinds[kind] for kind in RUN_KINDS} == dict.fromkeys(RUN_KINDS, 2000)
    report = _report(host)
    assert len(report["runs"]) == 2000
    assert Counter(r["verdict"] for r in report["runs"]) == Counter({COMPLETE[0]: 2000})
    assert all(run["gaps"] == [] for run in report["runs"])


def test_every_forced_drop_is_counted_and_reported_as_a_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the queue bound at 10 and the sender stalled (its pump lock held) while 20 run
    blocks queue 40 run markers, at least 30 are dropped. Every queued marker is then
    either delivered or counted, flush and close report the drop, and every run missing a
    marker is reported with a gap, never complete; the others still verify."""
    monkeypatch.setattr(_loss, "MAX_QUEUED_MARKERS", 10)
    attempted: list[str] = []
    queue = _loss.LossEmitter._queue

    def counting(self: _loss.LossEmitter, marker: Marker) -> bool:
        attempted.append(marker.event_id)
        return queue(self, marker)

    monkeypatch.setattr(_loss.LossEmitter, "_queue", counting)
    host = tmp_path / "a"
    handle = _install(host, "host-drops")
    sender = handle._tee.sender
    assert sender is not None
    assert handle.flush(30.0)  # the install's manifest is delivered before the stall
    with sender._pump_lock:  # a sender stalled in disk I/O: nothing leaves the queue
        _blocks(handle, 20)
    assert not handle.flush(60.0)  # a marker was dropped since the last flush
    dropped = handle.stats().markers_dropped
    assert dropped >= 30
    assert not handle.close(60.0)
    delivered = _markers(_spans(host))
    assert set(delivered) <= set(attempted)
    assert len(attempted) == len(delivered) + dropped  # every marker delivered or counted

    report = _report(host)
    assert len(report["runs"]) == 20
    have: dict[str, set[str]] = {}
    for marker in delivered.values():
        if marker["kind"] in RUN_KINDS:
            have.setdefault(marker["fabric.run.id"], set()).add(marker["kind"])
    degraded = 0
    for run in report["runs"]:
        if have.get(run["run_id"], set()) == set(RUN_KINDS):
            assert run["verdict"] in COMPLETE and run["gaps"] == [], run
            continue
        degraded += 1
        assert run["verdict"] not in COMPLETE, run
        assert run["gaps"], run  # an explicit gap, never a silent verdict
        assert {g["gap_type"] for g in run["gaps"]} & {
            "tail_unverified", "unsealed_segment", "segment_missing"}, run["gaps"]  # fmt: skip
    assert 1 <= degraded <= dropped


# --- passivity -------------------------------------------------------------------------------


def test_queuing_a_marker_is_o1_and_never_waits_for_a_stalled_spool(
    sender: _sender.Sender, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pump stalled inside a spool write (holding the pump lock) never slows the app
    thread: 20,000 markers queue in well under a second, nothing is written on the calling
    thread, the queue keeps exactly its bound and every marker past it is counted."""
    stalled, release = threading.Event(), threading.Event()
    writers: list[str] = []
    write_batch = sender.spool.write_batch

    def stalling(*args: Any, **kwargs: Any) -> Any:
        writers.append(threading.current_thread().name)
        stalled.set()
        release.wait(30.0)
        return write_batch(*args, **kwargs)

    monkeypatch.setattr(sender.spool, "write_batch", stalling)
    loss = sender.loss
    loss.queue_marker(_seal_marker(0))
    pump = threading.Thread(target=sender.pump, name="stalled-pump", daemon=True)
    pump.start()
    assert stalled.wait(10.0)
    markers = [_seal_marker(index) for index in range(1, 20001)]
    started = time.perf_counter()
    results = [loss.queue_marker(marker) for marker in markers]
    elapsed = time.perf_counter() - started
    release.set()
    pump.join(30.0)
    assert elapsed < 1.0, elapsed  # ~20 ms in practice; generous for a loaded CI host
    assert set(writers) == {"stalled-pump"}  # no spool I/O on the queuing thread
    assert sum(results) == _loss.MAX_QUEUED_MARKERS
    assert loss.markers_dropped == len(markers) - _loss.MAX_QUEUED_MARKERS


def test_the_queue_is_also_bounded_in_bytes(
    sender: _sender.Sender, monkeypatch: pytest.MonkeyPatch
) -> None:
    size = _loss.marker_bytes(_seal_marker(0))
    assert size >= 700  # a seal marker's measured footprint is ~700 bytes
    monkeypatch.setattr(_loss, "MAX_QUEUED_MARKER_BYTES", 3 * size)
    loss = sender.loss
    assert [loss.queue_marker(_seal_marker(i)) for i in range(5)] == [True] * 3 + [False] * 2
    assert loss.markers_dropped == 2
    sender.pump()  # the queue empties, so its byte charge does too
    assert loss.queue_marker(_seal_marker(5))


# --- batching (D4) ---------------------------------------------------------------------------


def test_markers_are_spooled_64_to_a_batch_file_in_order(
    sender: _sender.Sender, recording: _Recording
) -> None:
    markers = [_seal_marker(index) for index in range(130)]
    for marker in markers:
        assert sender.loss.queue_marker(marker)
    assert sender.pump()
    assert len(sender.spool.names()) == 3  # 64 + 64 + 2: three fsync'd files, not 130
    assert _spooled_events(sender.spool) == [m.event_id for m in markers]
    assert sender.stats()["spooled"] == 130
    assert sender.spool.try_lock()
    assert sender._drain() == "more"
    events = [(s.attributes or {})["fabric.event_id"] for s in recording.spans]
    assert events == [m.event_id for m in markers]  # exported in queue order


def test_a_batch_over_the_bound_is_written_one_record_per_file(
    sender: _sender.Sender, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_batch = sender.spool.write_batch

    def no_room_for_one_file(records: Any, **kwargs: Any) -> Any:
        if kwargs.get("group"):
            return [None]
        return write_batch(records, **kwargs)

    monkeypatch.setattr(sender.spool, "write_batch", no_room_for_one_file)
    markers = [_seal_marker(index) for index in range(5)]
    for marker in markers:
        sender.loss.queue_marker(marker)
    sender.pump()
    assert len(sender.spool.names()) == 5
    assert _spooled_events(sender.spool) == [m.event_id for m in markers]
    assert sender._held == []


def test_a_failed_batch_holds_it_and_everything_after_in_order(
    sender: _sender.Sender, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second batch fails (ENOSPC): the first stays spooled, the rest is held in queue
    order, mirrored to the ledger, and spooled in that order by the next pump."""
    write_batch, calls = sender.spool.write_batch, [0]

    def second_fails(records: Any, **kwargs: Any) -> Any:
        calls[0] += 1
        if calls[0] == 2:
            raise OSError(errno.ENOSPC, "No space left on device")
        return write_batch(records, **kwargs)

    monkeypatch.setattr(sender.spool, "write_batch", second_fails)
    markers = [_seal_marker(index) for index in range(150)]
    for marker in markers:
        sender.loss.queue_marker(marker)
    sender.pump()
    assert calls[0] == 2  # nothing after the failed batch was tried
    assert _spooled_events(sender.spool) == [m.event_id for m in markers[:64]]
    assert [m.event_id for m in sender._held] == [m.event_id for m in markers[64:]]
    ledger = sender.spool.ledger
    assert ledger is not None and ledger.used() >= 1
    sender.pump()
    assert sender._held == [] and ledger.used() == 0
    assert _spooled_events(sender.spool) == [m.event_id for m in markers]
    assert sender.stats()["markers_dropped"] == 0


def test_held_markers_past_the_bound_are_dropped_and_counted(
    sender: _sender.Sender, monkeypatch: pytest.MonkeyPatch
) -> None:
    def full(*args: Any, **kwargs: Any) -> Any:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(sender.spool, "write_batch", full)
    monkeypatch.setattr(_sender, "_MAX_HELD_MARKERS", 5)
    markers = [_seal_marker(index) for index in range(8)]
    for marker in markers:
        sender.loss.queue_marker(marker)
    sender.pump()
    assert [m.event_id for m in sender._held] == [m.event_id for m in markers[:5]]
    assert sender.stats()["markers_dropped"] == 3
    assert sender.stats()["markers_held"] == 5


def test_the_ledger_encodes_no_more_than_its_slots_can_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A long held list (a full disk under a burst) mirrors its oldest markers into this
    process's 16 slots and stops there: the cost of a pump's mirror stays bounded."""
    (tmp_path / "spool").mkdir(mode=0o700)
    ledger = _ledger.LossLedger(str(tmp_path / "spool"))
    encodes = [0]
    encode = _ledger._encode

    def counting(owner: str, records: Any) -> bytes | None:
        encodes[0] += 1
        return encode(owner, records)

    monkeypatch.setattr(_ledger, "_encode", counting)
    docs = [{**marker_doc(_seal_marker(i)), "schema_version": "x", "order": i,
             "written_at_unix_nano": 1} for i in range(5000)]  # fmt: skip
    assert not ledger.store(docs)
    assert ledger.used() == _ledger.MAX_OWN_SLOTS
    assert ledger.overflows == 1
    assert encodes[0] < 1000
    assert ledger.store([])
    assert ledger.used() == 0


# --- crash: held markers survive through the ledger --------------------------------------------

AGENT = EXPORTER + textwrap.dedent(
    """
    import errno
    host, blocks = Path(sys.argv[1]), int(sys.argv[2])
    handle = install(host, "host-crash")
    def full(fd, buffers):  # every spool record write: the volume is full
        raise OSError(errno.ENOSPC, "No space left on device")
    os.writev = full
    for _ in range(blocks):
        with wire.run():
            record(handle)
    handle._tee.flush(30.0)  # every record has its outcome (a disk_full loss)
    deadline = time.monotonic() + 30
    while handle.status()["seals"]["sealed"] < blocks and time.monotonic() < deadline:
        time.sleep(0.02)
    sender = handle._tee.sender
    sender.pump()  # what it cannot spool is held and mirrored to the ledger
    print("READY " + json.dumps({"held": [m.event_id for m in sender._held],
                                 **sender.stats()}), flush=True)
    time.sleep(600)  # SIGKILLed here: nothing runs at exit
    """
)


def test_held_run_markers_survive_a_crash_through_the_ledger(tmp_path: Path) -> None:
    """A full disk holds every run marker of 12 run blocks (two batch attempts' worth with
    their loss ranges); the process is SIGKILLed. The next drainer exports them from the
    ledger with their persisted event ids, and every scope closes and every segment seals."""
    host, blocks = tmp_path / "a", 12
    env = {**os.environ, "TEST_ID_KEY": KEY, "FABRIC_IDENTITY_MODE": "pseudonymous",
           "FABRIC_CLOCK_UNCERTAINTY_MS": "0", "PYTHONPATH": str(SRC)}  # fmt: skip
    agent = subprocess.Popen(  # noqa: S603 - this interpreter and a fixed test script
        [sys.executable, "-c", AGENT, str(host), str(blocks)], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    try:
        assert agent.stdout is not None
        line = agent.stdout.readline()
        assert line.startswith("READY "), (line, agent.stderr.read() if agent.stderr else "")
        state = json.loads(line[len("READY ") :])
    finally:
        os.kill(agent.pid, signal.SIGKILL)
        agent.wait(30)
    held = set(state["held"])
    assert len(held) >= 3 * blocks  # the run markers of every block (and a manifest)
    assert state["markers_dropped"] == 0 and state["ledger_overflows"] == 0
    assert state["ledger_slots"] >= 2

    drainer = _install(host, "host-drainer")
    assert wait_for(lambda: drainer.stats().ledger_recovered >= len(held), 30.0)
    drainer.close(30.0)
    markers = _markers(_spans(host))
    assert held <= set(markers)
    held_kinds = Counter(m["kind"] for e, m in markers.items() if e in held)
    assert {kind: held_kinds[kind] for kind in RUN_KINDS} == dict.fromkeys(RUN_KINDS, blocks)
    runs = {m["fabric.run.id"] for e, m in markers.items() if e in held and m["kind"] in RUN_KINDS}
    report = _report(host)
    crashed = [run for run in report["runs"] if run["run_id"] in runs]
    assert len(crashed) == blocks
    for run in crashed:
        assert all(scope["state"] == "closed" for scope in run["scopes"]), run["scopes"]
        assert all(s["state"] == "sealed" for s in run["segments"]), run["segments"]
        assert run["verdict"] not in COMPLETE  # its record was lost to the full disk
