# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 050 WP-11b: the ``record`` spool kind, the writer-side 260/8 bound (R6), typed
markers with a persisted uuid4 ``event_id`` (R2), segment-attributed losses (R3), marker
spans, orphan-epoch heartbeats, and the capture/v1 1.3.0 spool fixtures."""

from __future__ import annotations

import errno
import json
import os
import random
import sys
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from fabric._capture_types import Marker, SealInfo
from fabric._loss import (
    SPAN_HEARTBEAT,
    SPAN_MANIFEST,
    LossEmitter,
    loss_attributes,
    marker_fields,
    marker_from_fields,
    marker_span,
)
from fabric.wire import _registration
from fabric.wire._ledger import LossLedger, decode_slot
from fabric.wire._pipeline import CapturePipeline
from fabric.wire._registration import Orphan
from fabric.wire._sender import Sender
from fabric.wire._spool import (
    MAX_BODIES,
    SCHEMA,
    CorruptRecordError,
    OverBoundError,
    Spool,
    exchange_doc,
    frame,
    loss_doc,
    loss_range,
    marker_doc,
    record_doc,
    unframe,
    unframe_all,
    valid_header,
)

from .test_wire_helpers import CAPTURE, load_validator

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX spool")
# Seeded pseudo-random inputs (property tests), never secrets.
# ruff: noqa: S311

SEG_A, SEG_B = "seg-" + "a" * 32, "seg-" + "b" * 32
RUN = "r-93347307304ecb0a9bb1b51ae90ac326"
DIGEST = "sha256:" + "c9" * 32
VALIDATOR = load_validator()
SCHEMAS = {
    rel: json.loads((CAPTURE / rel).read_text("utf-8")) for rel in VALIDATOR.SCHEMAS.values()
}
FIXTURES = CAPTURE / "fixtures"


class _Exporter(SpanExporter):
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.spans: list[Any] = []

    def export(self, spans: Any) -> SpanExportResult:
        if not self.ok:
            return SpanExportResult.FAILURE
        self.spans += list(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


class _Content:
    def __init__(self) -> None:
        self.sent: list[tuple[dict[str, Any], bytes]] = []

    def send(self, descriptor: dict[str, Any], data: Any) -> str:
        self.sent.append((descriptor, bytes(data)))
        return "accepted"


def _sender(
    spool: Spool, exporter: SpanExporter, loss: LossEmitter, *, content: Any, service_name: str
) -> Sender:
    """A sender the test drives by hand: no background drain thread, and losses and
    markers left for :meth:`Sender.pump` (never taken by the emitter's own thread)."""
    sender = Sender(spool, exporter, loss, content=content, service_name=service_name)
    sender._stop.set()  # wake() starts no thread
    loss.attach(lambda: None)
    return sender


def _full(doc: dict[str, Any], order: int = 0) -> dict[str, Any]:
    return {**doc, "schema_version": SCHEMA, "order": order, "written_at_unix_nano": 1000 + order}


def _uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _hex(rng: random.Random, n: int) -> str:
    return f"{rng.getrandbits(4 * n) | 1:0{n}x}"


# --- generators --------------------------------------------------------------------------


def _descriptor(
    rng: random.Random, sequence: int, data: bytes, *, attempt: str | None = None,
    only: bool = False,
) -> dict[str, Any]:  # fmt: skip
    base: dict[str, Any] = {
        "schema_version": "fabric.content-object/v2", "object_id": _uuid(rng),
        "tenant_id": "tenant-a", "role": "tool.call.arguments",
        "media_type": "application/json", "content_encoding": "identity",
        "provenance": "caller_reported", "boundary": "caller", "source_id": "s-a",
        "source_epoch": 7, "source_sequence": sequence, "run_id": RUN,
        "operation_id": attempt or _uuid(rng), "captured_at": "2026-10-19T09:00:02Z",
    }  # fmt: skip
    if attempt is not None:
        base["attempt_id"] = attempt
    if only:  # R5: a descriptor-only body
        return {**base, "representation": "unavailable", "transformations": [],
                "status": "not_captured", "status_reason": "payload_too_large"}  # fmt: skip
    return {**base, "representation": "exact", "transformations": [], "status": "stored",
            "stored_byte_length": len(data), "stored_sha256": "sha256:" + "0" * 64,
            "source_byte_length": len(data), "source_sha256": "sha256:" + "0" * 64}  # fmt: skip


def _span(rng: random.Random, sequence: int, attrs: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"trace_id": _hex(rng, 32), "span_id": _hex(rng, 16), "trace_flags": 1,
            "start_time_unix_nano": 10, "end_time_unix_nano": 20,
            "attributes": {"fabric.source_id": "s-a", "fabric.source.epoch": 7,
                           "fabric.source.sequence": sequence, **attrs}, **extra}  # fmt: skip


def _record(
    rng: random.Random, sequence: int, bodies: int, *, only: int = 0
) -> tuple[dict[str, Any], list[bytes]]:
    """A records-input entry with ``bodies`` bodies, ``only`` of them descriptor-only."""
    attempt = _uuid(rng)
    staged = []
    for index in range(bodies):
        descriptor_only = index < only
        data = b"" if descriptor_only else rng.randbytes(rng.randint(0, 40))
        staged.append((_descriptor(rng, sequence, data, attempt=attempt, only=descriptor_only),
                       data))  # fmt: skip
    attrs: dict[str, Any] = {
        "fabric.capture.input": "records", "fabric.event_id": _uuid(rng),
        "fabric.attempt.uid": attempt, "fabric.step.kind": "tool_call",
        "fabric.run.segment_id": SEG_A, "fabric.run.id": RUN,
    }  # fmt: skip
    if staged:
        attrs["fabric.content.object_ids"] = [d["object_id"] for d, _ in staged]
    span = _span(rng, sequence, attrs, name="fabric.tool_call", kind="internal",
                 status=rng.choice(["unset", "ok", "error"]))  # fmt: skip
    return record_doc("s-a", 7, "svc", span, staged), [data for _, data in staged]


def _exchange(rng: random.Random, sequence: int, bodies: int) -> tuple[dict[str, Any], list[bytes]]:
    staged = []
    for _ in range(bodies):
        data = rng.randbytes(rng.randint(0, 8))
        staged.append((_descriptor(rng, sequence, data), data))
    span = _span(rng, sequence, {"fabric.wire.exchange_id": _uuid(rng), "fabric.run.id": RUN},
                 name="fabric.model_call", kind="client", status="unset")  # fmt: skip
    return exchange_doc("s-a", 7, "svc", span, staged), [data for _, data in staged]


def _markers(rng: random.Random) -> list[Marker]:
    """One marker of every spooled kind, with random ids."""
    scope, seg = _uuid(rng), "seg-" + _hex(rng, 32)
    predecessor = f"seg-{_hex(rng, 32)}/s-a/7/{rng.randint(-1, 40)}/{DIGEST}"
    manifest = json.loads((FIXTURES / "valid" / "spool-record-manifest.json").read_text())
    attrs = manifest["marker"]["manifest"]
    return [
        Marker("run_start", "s-a", 7, rng.randint(-1, 99), RUN, scope, seg, ("none",),
               resumable=True, open_deadline_s=3600, manifest_id=_uuid(rng),
               manifest_digest=DIGEST, manifest_seq=0, session_id="sess-" + _hex(rng, 32),
               user_id="usr-" + _hex(rng, 32), links=(RUN,), id_basis="caller",
               identity={"agent_id": "billing-agent"}),
        Marker("run_start", "s-a", 7, 5, RUN, scope, seg, (predecessor,),
               declared_branches=("seg-" + _hex(rng, 32), "seg-" + _hex(rng, 32)),
               branch_ids=("br-" + _hex(rng, 32),), id_basis="token"),
        Marker("run_end", "s-a", 7, 9, RUN, scope, seg, scope_status="ok",
               outcome="completed", stop_reason="goal_reached", manifest_seq=0),
        Marker("segment_seal", "s-a", 7, 9, RUN, scope, seg, terminal=False, resumable=True,
               seal=SealInfo(9, DIGEST, "sha256:" + "5e" * 32, ("br-" + _hex(rng, 32),))),
        Marker("final", "s-a", 7, rng.randint(-1, 99)),
        Marker("manifest", attrs["fabric.source_id"], attrs["fabric.source.epoch"], -1,
               manifest=attrs, event_id=attrs["fabric.event_id"]),
    ]  # fmt: skip


# --- spool header properties ----------------------------------------------------------------


def _entry(rng: random.Random, kind: str) -> tuple[dict[str, Any], list[bytes]]:
    if kind == "exchange":
        return _exchange(rng, rng.randint(0, 99), rng.randint(0, 6))
    if kind == "record":
        bodies = rng.randint(0, 8)
        return _record(rng, rng.randint(0, 99), bodies, only=rng.randint(0, bodies))
    if kind == "marker":
        return marker_doc(rng.choice(_markers(rng))), []
    segment = rng.choice([None, SEG_A])
    first = rng.randint(0, 50)
    last = first + rng.randint(0, 5)
    count = last - first + 1 if segment else rng.randint(1, last - first + 1)
    return loss_doc((("s-a", 7, "queue_full", segment), (first, last, count))), []


@pytest.mark.parametrize("kind", ["exchange", "record", "marker", "loss"])
def test_every_kind_round_trips_through_its_frame(kind: str) -> None:
    for seed in range(150):
        rng = random.Random(f"{kind}-{seed}")
        doc, bodies = _entry(rng, kind)
        full = _full(doc, seed)
        assert valid_header(full, sum(map(len, bodies))), (kind, seed)
        if kind != "exchange":  # the normative schema agrees (exchanges: fixture tests)
            VALIDATOR.validate_document(full, SCHEMAS)
        header, blob = unframe(b"".join(frame(full, bodies)))
        assert header == full and bytes(blob) == b"".join(bodies)


def test_typed_markers_and_losses_round_trip() -> None:
    for seed in range(50):
        rng = random.Random(seed)
        for marker in _markers(rng):
            fields = marker_doc(marker)["marker"]
            again = marker_from_fields(marker.source_id, marker.epoch, fields)
            assert again.event_id == marker.event_id
            assert marker_fields(again) == fields
        loss = (("s-a", 7, "disk_full", rng.choice([None, SEG_B])), (3, 5, 3))
        assert loss_range(_full(loss_doc(loss))) == loss


@pytest.mark.parametrize("kind", ["exchange", "record", "marker", "loss"])
def test_a_corrupt_frame_is_refused(kind: str) -> None:
    for seed in range(60):
        rng = random.Random(f"corrupt-{kind}-{seed}")
        doc, bodies = _entry(rng, kind)
        data = bytearray(b"".join(frame(_full(doc), bodies)))
        position = rng.randrange(len(data))
        data[position] ^= 1 << rng.randrange(8)
        with pytest.raises(CorruptRecordError):
            unframe_all(bytes(data))
        with pytest.raises(CorruptRecordError):
            unframe_all(bytes(data[: rng.randrange(len(data))]))  # torn


_BAD_HEADERS: dict[str, tuple[str, Callable[[dict[str, Any]], Any]]] = {
    "marker event id not uuid4": ("marker", lambda d: d["marker"].update(event_id="x")),
    "periodic is never spooled": ("marker", lambda d: d["marker"].update(kind="periodic")),
    "outcome on run_start": ("marker", lambda d: d["marker"].update(outcome="completed")),
    "unknown marker field": ("marker", lambda d: d["marker"].update(colour="red")),
    "loss segment id": ("loss", lambda d: d["loss"].update(segment_id="seg-1")),
    "record with an exchange id": (
        "record", lambda d: d["span"]["attributes"].update({"fabric.wire.exchange_id": "x"})),
    "record of the wire input": (
        "record", lambda d: d["span"]["attributes"].update({"fabric.capture.input": "wire"})),
    "record without attempt": (
        "record", lambda d: d["span"]["attributes"].pop("fabric.attempt.uid")),
    "record with a structured value": (
        "record", lambda d: d["span"]["attributes"].update({"fabric.tool.name": {"a": 1}})),
    "exchange of the records input": (
        "exchange", lambda d: d["span"]["attributes"].update({"fabric.capture.input": "records"})),
}  # fmt: skip


@pytest.mark.parametrize("case", sorted(_BAD_HEADERS))
def test_a_header_outside_the_contract_is_corrupt(case: str) -> None:
    kind, mutate = _BAD_HEADERS[case]
    rng = random.Random(case)
    bodies: list[bytes]
    if kind == "marker":
        doc, bodies = marker_doc(_markers(rng)[0]), []
    elif kind == "loss":
        doc, bodies = _entry(rng, "loss")
    elif kind == "record":
        doc, bodies = _record(rng, 1, 2)
    else:
        doc, bodies = _exchange(rng, 1, 2)
    full = _full(doc)
    mutate(full)
    with pytest.raises(CorruptRecordError):
        unframe(b"".join(frame(full, bodies)))  # a valid digest, an invalid header


def _files(directory: Path) -> set[str]:
    return {p.name for p in directory.iterdir() if p.name.endswith(".rec") or "tmp" in p.name}


def test_260_bodies_are_accepted_and_261_refused_before_the_write(tmp_path: Path) -> None:
    rng = random.Random(260)
    spool = Spool(str(tmp_path / "spool"), 64 << 20)
    doc, bodies = _exchange(rng, 1, MAX_BODIES)
    assert isinstance(spool.write(doc, bodies), str)
    before, charged = _files(tmp_path / "spool"), spool.bytes
    doc, bodies = _exchange(rng, 2, MAX_BODIES + 1)
    with pytest.raises(OverBoundError):
        spool.write(doc, bodies)
    assert _files(tmp_path / "spool") == before and spool.bytes == charged  # nothing written
    record, record_bodies = _record(rng, 3, 8, only=3)
    assert isinstance(spool.write(record, record_bodies), str)
    nine, nine_bodies = _record(rng, 4, 8)
    nine["bodies"].append(dict(nine["bodies"][0], offset=sum(map(len, nine_bodies))))
    with pytest.raises(OverBoundError):
        spool.write(nine, [*nine_bodies, nine_bodies[0]])
    assert len(_files(tmp_path / "spool")) == len(before) + 1


def test_a_batch_refuses_only_its_over_bound_entries(tmp_path: Path) -> None:
    rng = random.Random(7)
    spool = Spool(str(tmp_path / "spool"), 64 << 20)
    entries = [_exchange(rng, 0, 1), _exchange(rng, 1, MAX_BODIES + 1), _record(rng, 2, 2)]
    results = spool.write_group(entries)
    assert isinstance(results[1], OverBoundError)
    assert isinstance(results[0], str) and results[0] == results[2]  # one batch file
    records = unframe_all(spool.read(results[0]))
    assert [doc["record_kind"] for doc, _ in records] == ["exchange", "record"]


def test_the_sender_spools_records_and_refuses_over_bound_entries(tmp_path: Path) -> None:
    rng = random.Random(11)
    spool = Spool(str(tmp_path / "spool"), 64 << 20)
    content, exporter = _Content(), _Exporter()
    sender = _sender(spool, exporter, LossEmitter(), content=content, service_name="svc")
    record, _ = _record(rng, 0, 3, only=1)
    big, _ = _exchange(rng, 1, MAX_BODIES + 1)
    staged = [[(b["descriptor"], bytes(b["length"])) for b in d["bodies"]] for d in (record, big)]
    outcomes = sender.spool_exchanges([("s-a", 7, record["span"], staged[0]),
                                       ("s-a", 7, big["span"], staged[1])])  # fmt: skip
    assert outcomes == ["spooled", "internal_error"]
    assert sender.stats()["over_bound_refused"] == 1
    assert spool.try_lock()
    assert sender._drain() == "more"
    assert [d["object_id"] for d, _ in content.sent] == record["span"]["attributes"][
        "fabric.content.object_ids"
    ]  # the descriptor-only body travels too
    (span,) = exporter.spans
    assert span.name == "fabric.tool_call" and span.attributes["fabric.capture.input"] == "records"
    assert span.instrumentation_scope.name == "fabric.records"
    assert tuple(span.attributes["fabric.content.object_ids"]) == tuple(
        record["span"]["attributes"]["fabric.content.object_ids"]
    )
    spool.release()


# --- markers: persisted event ids and spans --------------------------------------------------


def _heartbeat_document(name: str, attrs: dict[str, Any]) -> dict[str, Any]:
    """The loss-record-v1 form of a heartbeat span (every run-marker key)."""
    back = {"fabric.run.id": "run_id", "fabric.run.scope_id": "scope_id",
            "fabric.run.segment_id": "segment_id", "fabric.run.predecessors": "predecessors",
            "fabric.run.resumable": "resumable", "fabric.run.open_deadline_s": "open_deadline_s",
            "fabric.run.declared_branches": "declared_branches",
            "fabric.run.branch_ids": "branch_ids", "fabric.run.terminal": "terminal",
            "fabric.capture.manifest_id": "manifest_id",
            "fabric.capture.manifest_digest": "manifest_digest",
            "fabric.capture.manifest_seq": "manifest_seq",
            "fabric.run.scope_status": "scope_status", "fabric.run.outcome": "outcome",
            "fabric.run.stop_reason": "stop_reason", "fabric.session_id": "session_id",
            "fabric.user_id": "user_id", "fabric.run.parent_id": "parent_run_id",
            "fabric.run.resumed_from": "resumed_from", "fabric.run.links": "links",
            "fabric.run.id_basis": "id_basis", "fabric.event_id": "event_id"}  # fmt: skip
    seal = {"fabric.segment.last_sequence": "last_sequence",
            "fabric.segment.manifest_digest": "manifest_digest",
            "fabric.segment.seal_digest": "seal_digest",
            "fabric.segment.branch_ids": "branch_ids"}  # fmt: skip
    identity = {f"fabric.{n}": n for n in ("agent_id", "system_id", "deployment_id",
                                           "release_id", "environment")}  # fmt: skip
    assert name == SPAN_HEARTBEAT
    document: dict[str, Any] = {
        "schema_version": "fabric.loss-record/v1", "kind": "heartbeat",
        "source": {"source_id": attrs["fabric.source_id"],
                   "source_epoch": attrs["fabric.source.epoch"]},
        "emitted_at": "2026-10-19T09:00:00Z", "heartbeat_kind": attrs["fabric.heartbeat.kind"],
        "last_sequence": attrs["fabric.heartbeat.last_sequence"],
    }  # fmt: skip
    for key, raw in attrs.items():
        value = list(raw) if isinstance(raw, tuple) else raw
        if key in back:
            document[back[key]] = value
        elif key in seal:
            document.setdefault("seal", {})[seal[key]] = value
        elif key in identity:
            document.setdefault("identity", {})[identity[key]] = value
        else:
            assert key in ("fabric.source_id", "fabric.source.epoch", "fabric.heartbeat.kind",
                           "fabric.heartbeat.last_sequence"), key  # fmt: skip
    return document


def test_marker_spans_carry_the_persisted_event_id_and_validate() -> None:
    rng = random.Random(3)
    for marker in [*_markers(rng), Marker("periodic", "s-a", 7, 4)]:
        name, attrs = marker_span(marker.source_id, marker.epoch, marker_fields(marker))
        assert attrs["fabric.event_id"] == marker.event_id
        if marker.kind == "manifest":
            assert name == SPAN_MANIFEST and attrs == {
                k: tuple(v) if isinstance(v, list) else v
                for k, v in (marker.manifest or {}).items()
            }
            continue
        VALIDATOR.validate_document(_heartbeat_document(name, attrs), SCHEMAS)


def test_a_replayed_or_retried_marker_keeps_its_event_id(tmp_path: Path) -> None:
    spool = Spool(str(tmp_path / "spool"), 1 << 20)
    exporter, loss = _Exporter(ok=False), LossEmitter()
    sender = _sender(spool, exporter, loss, content=None, service_name="svc")
    marker = _markers(random.Random(5))[3]  # a segment_seal
    assert loss.queue_marker(marker)
    sender.pump()
    assert spool.try_lock()
    assert sender._drain() == "retry"  # the export failed: the record stays
    exporter.ok = True
    assert sender._drain() == "more"  # the replay
    (span,) = exporter.spans
    assert span.attributes["fabric.event_id"] == marker.event_id
    assert span.attributes["fabric.segment.seal_digest"] == marker.seal.seal_digest  # type: ignore[union-attr]
    spool.release()


def test_a_ledger_replay_keeps_the_marker_event_id(tmp_path: Path) -> None:
    """A process whose disk is full holds its marker in the ledger and dies; the drainer
    exports it from the ledger with the event id minted in the dead process."""
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            os.close(read)
            spool = Spool(str(tmp_path / "spool"), 1 << 20)

            def full(*_: Any, **__: Any) -> Any:
                raise OSError(errno.ENOSPC, "full")

            spool.write = spool.write_batch = full  # type: ignore[method-assign]
            loss = LossEmitter()
            sender = _sender(spool, _Exporter(), loss, content=None, service_name="svc")
            marker = _markers(random.Random(9))[2]  # a run_end
            loss.queue_marker(marker)
            loss.record("s-a", 7, "disk_full", 12, segment_id=SEG_B)
            sender.pump()
            sender.pump()  # still held: the ledger copy is unchanged
            os.write(write, marker.event_id.encode())
            code = 0
        finally:
            os._exit(code)
    os.close(write)
    event_id = os.read(read, 64).decode()
    os.waitpid(pid, 0)
    spool = Spool(str(tmp_path / "spool"), 1 << 20)
    assert spool.try_lock()
    exporter = _Exporter()
    sender = _sender(spool, exporter, LossEmitter(), content=None, service_name="svc")
    sender._recover_orphans()
    spans = {span.name: span for span in exporter.spans}
    assert spans[SPAN_HEARTBEAT].attributes["fabric.event_id"] == event_id
    assert spans["fabric.capture_loss"].attributes["fabric.run.segment_id"] == SEG_B
    assert sender.stats()["ledger_recovered"] == 2
    spool.release()


def test_a_manifest_too_large_for_a_slot_is_not_mirrored(tmp_path: Path) -> None:
    ledger = LossLedger(str(tmp_path))
    event_id = str(uuid.uuid4())
    attrs: dict[str, Any] = {"fabric.event_id": event_id,
             "fabric.manifest.after_source_sequence": -1,
             "fabric.manifest.capture_points": ["x" * 120] * 64}  # fmt: skip
    big = Marker("manifest", "s-a", 7, -1, manifest=attrs, event_id=event_id)
    run_end = _markers(random.Random(1))[2]
    records = [_full(marker_doc(big)), _full(marker_doc(run_end), 1)]
    assert ledger.store(records) and ledger.store(records)
    assert ledger.manifests_unledgered == 1 and ledger.overflows == 0
    assert ledger.used() == 1


def test_an_invalid_marker_is_dropped_never_spooled(tmp_path: Path) -> None:
    spool = Spool(str(tmp_path / "spool"), 1 << 20)
    loss = LossEmitter()
    sender = _sender(spool, _Exporter(), loss, content=None, service_name="svc")
    seal = SealInfo(3, DIGEST, DIGEST)
    loss.queue_marker(Marker("segment_seal", "s-a", 7, 3, RUN, segment_id=SEG_A, seal=seal))
    # ... without ``terminal``, which a spooled seal must carry
    sender.pump()
    assert spool.names() == [] and sender.stats()["markers_invalid"] == 1


# --- losses: segment attribution (R3) -----------------------------------------------------


def test_losses_of_two_segments_never_coalesce() -> None:
    emitter = LossEmitter()
    for sequence in range(12):  # two runs interleaving positions on one source
        emitter.record("s-a", 7, "queue_full", sequence,
                       segment_id=SEG_A if sequence % 2 else SEG_B)  # fmt: skip
    emitter.record("s-a", 7, "queue_full", 13, segment_id=SEG_A)
    emitter.record("s-a", 7, "queue_full", 14, segment_id=SEG_A)  # adjacent: merged
    emitter.record("s-a", 7, "queue_full", 20)  # outside any run
    emitter.record("s-a", 7, "queue_full", 25)  # segment-less ranges coalesce as before
    losses, _ = emitter.take(periodic=False)
    by_segment: dict[Any, list[tuple[int, int, int]]] = {}
    for (_, _, _, segment), rng in losses:
        by_segment.setdefault(segment, []).append(rng)
    assert sorted(by_segment[SEG_B]) == [(s, s, 1) for s in range(0, 12, 2)]
    assert sorted(by_segment[SEG_A]) == [*((s, s, 1) for s in range(1, 12, 2)), (13, 14, 2)]
    assert by_segment[None] == [(20, 25, 2)]
    for loss in losses:  # each segment range is exact, and every doc validates
        doc = _full(loss_doc(loss))
        VALIDATOR.validate_document(doc, SCHEMAS)
        attrs = loss_attributes(loss)
        assert attrs.get("fabric.run.segment_id") == loss[0][3]
    emitter.close(1.0)


def test_spooled_losses_name_one_segment_each(tmp_path: Path) -> None:
    spool = Spool(str(tmp_path / "spool"), 1 << 20)
    loss = LossEmitter()
    sender = _sender(spool, _Exporter(), loss, content=None, service_name="svc")
    for sequence in (1, 2, 3, 4):
        loss.record("s-a", 7, "queue_full", sequence, segment_id=(SEG_A, SEG_B)[sequence % 2])
    sender.pump()
    docs = [doc for name in spool.names() for doc, _ in unframe_all(spool.read(name))]
    segments = sorted((d["loss"]["segment_id"], d["loss"]["first_sequence"]) for d in docs)
    assert segments == [(SEG_A, 2), (SEG_A, 4), (SEG_B, 1), (SEG_B, 3)]
    assert spool.try_lock()
    exporter = _Exporter()
    sender._exporter = exporter
    sender._drain()
    assert {s.attributes["fabric.run.segment_id"] for s in exporter.spans} == {SEG_A, SEG_B}
    spool.release()


def test_the_pending_table_is_bounded_per_range(monkeypatch: pytest.MonkeyPatch) -> None:
    import fabric._loss as loss_module  # noqa: PLC0415

    monkeypatch.setattr(loss_module, "_MAX_PENDING_RANGES", 3)
    emitter = LossEmitter()
    for sequence in (0, 2, 4, 6):  # four disjoint ranges of one segment: the fourth is a gap
        emitter.record("s-a", 7, "shutdown", sequence, segment_id=SEG_A)
    emitter.record("s-a", 7, "shutdown", 1, segment_id=SEG_A)  # merges 0..2: room again
    emitter.record("s-a", 7, "shutdown", 8, segment_id=SEG_A)
    losses, _ = emitter.take(periodic=False)
    assert sorted(rng for _, rng in losses) == [(0, 2, 3), (4, 4, 1), (8, 8, 1)]
    emitter.close(1.0)


# --- disk-full losses settle ---------------------------------------------------------------


def test_disk_full_losses_settle_and_survive_in_the_ledger(tmp_path: Path) -> None:
    import dataclasses  # noqa: PLC0415

    from fabric._sequence import SourceAllocator  # noqa: PLC0415

    from .test_capture_hooks import _capture_job  # noqa: PLC0415

    spool = Spool(str(tmp_path / "spool"), 1 << 20)
    loss = LossEmitter()
    sender = _sender(spool, _Exporter(), loss, content=None, service_name="svc")
    settled: list[tuple[str | None, int, str]] = []
    loss.set_settle(lambda segment, sequence, entry: settled.append((segment, sequence, entry)))

    def full(*_: Any, **__: Any) -> list[Any]:
        raise OSError(errno.ENOSPC, "full")

    def full_group(records: Sequence[Any]) -> list[Any]:
        return [OSError(errno.ENOSPC, "full") for _ in records]

    spool.write_group = full_group  # type: ignore[method-assign]
    spool.write = spool.write_batch = full  # type: ignore[method-assign,assignment]
    pipeline = CapturePipeline(store=None, tracer_provider=None, loss=loss, sender=sender)
    allocator = SourceAllocator("node-1", "wire")
    jobs = [_capture_job(allocator, SEG_A), _capture_job(allocator, SEG_B)]
    for job in jobs:
        assert pipeline.submit(dataclasses.replace(job))
    assert pipeline.flush(5.0)
    assert sorted(settled) == sorted(
        (job.segment_id, job.source_sequence, "loss:disk_full") for job in jobs
    )
    assert sender.stats()["disk_full_drops"] == 2
    sender.pump()  # the loss records cannot be spooled either: mirrored to the ledger
    assert spool.ledger is not None and spool.ledger.used() == 1
    fd = os.open(spool.ledger.path, os.O_RDONLY)
    try:
        slot = os.pread(fd, 4096, 4096 + 4096 * spool.ledger._own[0])
    finally:
        os.close(fd)
    records = decode_slot(slot)
    assert records is not None
    assert sorted(r["loss"]["segment_id"] for r in records) == [SEG_A, SEG_B]
    assert all(r["loss"]["reason"] == "disk_full" for r in records)
    pipeline.close(1.0)


# --- orphaned epochs (§3.2 rule 5) -------------------------------------------------------


def test_orphaned_epochs_are_declared_by_a_heartbeat_until_delivered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    found = [Orphan("s-a", 7, 5), Orphan("s-a", 8, 0)]  # the second never allocated
    monkeypatch.setattr(_registration, "scan_orphans", lambda spool: found)
    spool = Spool(str(tmp_path / "spool"), 1 << 20)
    exporter = _Exporter(ok=False)
    sender = _sender(spool, exporter, LossEmitter(), content=None, service_name="svc")
    assert sender.scan_epochs() == 0  # not the drainer
    assert spool.try_lock()
    assert sender.scan_epochs() == 1
    found.clear()
    assert not sender.pump()  # not exported: kept
    exporter.ok = True
    assert sender.pump()
    assert sender.pump() and len(exporter.spans) == 1  # delivered once
    (span,) = exporter.spans
    assert span.name == SPAN_HEARTBEAT
    assert span.attributes["fabric.heartbeat.kind"] == "periodic"
    assert span.attributes["fabric.heartbeat.last_sequence"] == 4
    assert span.attributes["fabric.source.epoch"] == 7
    assert sender.stats()["orphan_heartbeats"] == 1
    spool.release()


def test_a_failing_orphan_scan_never_stops_the_drainer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(spool: Spool) -> list[Orphan]:
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(_registration, "scan_orphans", broken)
    spool = Spool(str(tmp_path / "spool"), 1 << 20)
    sender = _sender(spool, _Exporter(), LossEmitter(), content=None, service_name="svc")
    assert spool.try_lock() and sender.scan_epochs() == 0
    spool.release()


# --- the registration directory (WP-10) ------------------------------------------------------


def test_a_spool_with_epoch_registrations_opens(tmp_path: Path) -> None:
    directory = tmp_path / "spool"
    Spool(str(directory), 1 << 20)
    (directory / _registration.EPOCHS_DIR).mkdir(mode=0o700)
    (directory / _registration.EPOCHS_DIR / f"{7:020d}.reg").write_bytes(b"\0" * 4096)
    spool = Spool(str(directory), 1 << 20)  # a second install or a spawned worker
    spool.rescan()
    assert spool.names() == [] and spool.bytes == 0  # never a record, never charged


# --- capture/v1 1.3.0 fixtures ------------------------------------------------------------------


def _fixtures(kind: str) -> list[Path]:
    return sorted((FIXTURES / kind).glob("spool-record-*.json"))


@pytest.mark.parametrize("path", _fixtures("valid"), ids=lambda p: p.stem)
def test_valid_spool_fixtures_round_trip(path: Path, tmp_path: Path) -> None:
    doc = json.loads(path.read_text("utf-8"))
    blob = sum(body["length"] for body in doc.get("bodies", []))
    assert valid_header(doc, blob)
    bodies = [bytes(body["length"]) for body in doc.get("bodies", [])]
    header, _ = unframe(b"".join(frame(doc, bodies)))
    assert header == doc
    source = doc["source"]
    common = {k: doc[k] for k in ("schema_version", "order", "written_at_unix_nano")}
    if doc["record_kind"] == "marker" and "event_id" in doc["marker"]:
        marker = marker_from_fields(source["source_id"], source["source_epoch"], doc["marker"])
        assert {**marker_doc(marker), **common} == doc
    elif doc["record_kind"] == "loss":
        assert {**loss_doc(loss_range(doc)), **common} == doc
    elif doc["record_kind"] in ("exchange", "record") and "service_name" in doc:
        build = record_doc if doc["record_kind"] == "record" else exchange_doc
        pairs = zip(doc["bodies"], bodies, strict=True)
        staged = [(body["descriptor"], data) for body, data in pairs]
        again = build(source["source_id"], source["source_epoch"], doc["service_name"],
                      doc["span"], staged)  # fmt: skip
        assert {**again, **common} == doc
    spool = Spool(str(tmp_path / "spool"), 1 << 20)
    span = _sender(spool, _Exporter(), LossEmitter(), content=None, service_name="svc")._span(doc)
    if doc["record_kind"] == "marker":
        assert span.attributes is not None
        assert span.attributes.get("fabric.event_id") == doc["marker"].get("event_id")
    elif doc["record_kind"] == "record":
        assert span.name == doc["span"]["name"] and span.attributes == {
            k: tuple(v) if isinstance(v, list) else v for k, v in doc["span"]["attributes"].items()
        }


_STRUCTURAL = (
    "spool-record-body-gap", "spool-record-exchange-261", "spool-record-exchange-records-input",
    "spool-record-manifest-event-id-mismatch", "spool-record-manifest-position-mismatch",
    "spool-record-manifest-with-run", "spool-record-marker-bad-event-id",
    "spool-record-marker-outcome-on-run-start", "spool-record-marker-session-on-run-end",
    "spool-record-marker-without-scope", "spool-record-record-agent-authenticated",
    "spool-record-record-bodies-out-of-order", "spool-record-record-nine-bodies",
    "spool-record-record-source-mismatch", "spool-record-record-structured-value",
    "spool-record-record-wrong-input", "spool-record-segment-seal-without-run",
)  # fmt: skip


@pytest.mark.parametrize("name", _STRUCTURAL)
def test_structurally_invalid_spool_fixtures_are_refused_on_read(name: str) -> None:
    doc = json.loads((FIXTURES / "invalid" / f"{name}.json").read_text("utf-8"))
    blob = sum(body.get("length", 0) for body in doc.get("bodies", []))
    assert not valid_header(doc, blob)
