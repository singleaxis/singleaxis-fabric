# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 050 WP-01 call sites and stubs: the allocator's segment and seal hooks, loss
settlement, the pipeline's record-job dispatch, the ``p1_attributes`` merge and settle
calls, the install/close/run hooks, and the typed no-op stubs other work packages fill.
Every hook is a no-op by default, so capture output is unchanged."""

from __future__ import annotations

import dataclasses
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric._loss
import fabric._sequence
from fabric import _capture_types as ct
from fabric import _manifest, _records, _seal, _segments, wire
from fabric._capture_types import (
    COUNTERS,
    Allocation,
    Marker,
    NullRunTable,
    NullSealAccumulator,
    RecordJob,
    RecordsMisuseError,
    SealInfo,
)
from fabric._loss import LossEmitter
from fabric._sequence import RunScope, SourceAllocator
from fabric.reconstruct import _evidence as reconstruct_evidence
from fabric.reconstruct import _fields_model, _graph, _project
from fabric.wire import _attrs, _pipeline, _registration
from fabric.wire._model import CapturedBody, CaptureJob

SEG = "seg-" + "c" * 32


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(ct.STRICT_ENV, raising=False)
    COUNTERS.reset()
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)
    COUNTERS.reset()


class _Table(NullRunTable):
    """A run table that puts every allocation in one segment and records the hooks."""

    def __init__(self, segment: str | None = SEG, *, fail: bool = False) -> None:
        self.segment, self.fail = segment, fail
        self.calls: list[tuple[str, Any]] = []

    def on_allocate(self, allocation: Allocation) -> str | None:
        self.calls.append(("allocate", allocation))
        if self.fail:
            raise RuntimeError("segment bug")
        return self.segment

    def on_block_enter(self, scope: RunScope) -> None:
        self.calls.append(("enter", scope.scope_id))

    def on_block_exit(self, scope: RunScope) -> None:
        self.calls.append(("exit", scope.scope_id))

    def on_final(self) -> None:
        self.calls.append(("final", None))


class _Seals(NullSealAccumulator):
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.allocated: list[tuple[str, int]] = []
        self.settled: list[tuple[str, int, str]] = []

    def note_allocated(self, segment_id: str, sequence: int) -> None:
        if self.fail:
            raise RuntimeError("seal bug")
        self.allocated.append((segment_id, sequence))

    def settle(self, segment_id: str, sequence: int, entry: str) -> None:
        if self.fail:
            raise RuntimeError("seal bug")
        self.settled.append((segment_id, sequence, entry))


# --- the allocator (§3.3) ----------------------------------------------------------------


def test_allocation_without_segments_keeps_the_legacy_tuple() -> None:
    allocator = SourceAllocator("node-1", "wire")
    assert isinstance(allocator.segments, NullRunTable)
    assert isinstance(allocator.seals, NullSealAccumulator)
    first = allocator.allocate()
    assert first == Allocation(allocator.epoch, 0, None, None, None)
    assert allocator.next_sequence() == (allocator.epoch, 1, None)
    assert allocator.next_sequence_for(None) == (allocator.epoch, 2, None)
    assert allocator.allocate_for(None).sequence == 3


def test_allocation_takes_the_open_segment_and_counts_it_outstanding() -> None:
    allocator = SourceAllocator("node-1", "wire")
    table, seals = _Table(), _Seals()
    allocator.attach(segments=table, seals=seals)
    scope = RunScope("r-1", str(uuid.uuid4()), None)
    got = allocator.allocate_for(scope)
    assert got == Allocation(allocator.epoch, 0, scope, SEG, None)
    assert table.calls == [("allocate", Allocation(allocator.epoch, 0, scope))]
    assert seals.allocated == [(SEG, 0)]
    allocator.settle(SEG, 0, "sha256:" + "0" * 64)
    allocator.settle(None, 1, "loss:queue_full")  # segment-less: nothing to settle
    assert seals.settled == [(SEG, 0, "sha256:" + "0" * 64)]
    allocator.attach()
    assert isinstance(allocator.segments, NullRunTable)
    assert allocator.allocate().segment_id is None


def test_a_failing_hook_never_fails_the_allocation() -> None:
    allocator = SourceAllocator("node-1", "wire")
    allocator.attach(segments=_Table(fail=True), seals=_Seals())
    assert allocator.next_sequence() == (allocator.epoch, 0, None)
    allocator.attach(segments=_Table(), seals=_Seals(fail=True))
    assert allocator.allocate().segment_id == SEG
    allocator.settle(SEG, 1, "loss:shutdown")  # swallowed


# --- the loss funnel (§3.3, R3) -------------------------------------------------------------


def test_every_loss_settles_its_segment() -> None:
    emitter = LossEmitter()
    settled: list[tuple[str | None, int, str]] = []
    emitter.set_settle(lambda segment, sequence, entry: settled.append((segment, sequence, entry)))
    emitter.record("s-a", 5, "queue_full", 3, segment_id=SEG)
    emitter.record("s-a", 5, "shutdown", 4)
    assert settled == [(SEG, 3, "loss:queue_full"), (None, 4, "loss:shutdown")]
    assert emitter.recorded == 2
    losses, _ = emitter.take(periodic=False)
    assert sorted(losses, key=str) == [(("s-a", 5, "queue_full", SEG), (3, 3, 1)),
                                       (("s-a", 5, "shutdown", None), (4, 4, 1))]  # fmt: skip
    emitter.close(1.0)


def test_a_failing_settle_never_loses_the_loss() -> None:
    emitter = LossEmitter()

    def broken(segment: str | None, sequence: int, entry: str) -> None:
        raise RuntimeError("seal bug")

    emitter.set_settle(broken)
    emitter.record("s-a", 5, "internal_error", 9, segment_id=SEG)
    assert emitter.has_pending_losses()
    emitter.set_settle(None)
    emitter.record("s-a", 5, "internal_error", 10, segment_id=SEG)  # the no-op again
    emitter.close(1.0)


def test_queue_marker_takes_every_kind() -> None:
    """WP-11b: the typed marker queue replaced the legacy beat queue (050 §3.5)."""
    emitter = LossEmitter()
    start = Marker("run_start", "s-a", 5, 2, "r-1", "scope-1")
    seal = SealInfo(2, None, "sha256:" + "0" * 64)
    sealed = Marker("segment_seal", "s-a", 5, 2, segment_id=SEG, seal=seal)
    assert emitter.queue_marker(start) and emitter.queue_marker(sealed)
    _, beats = emitter.take(periodic=False)
    assert beats == [start, sealed]  # the same markers: event ids minted once
    emitter.close(1.0)


# --- the pipeline (§3.5, §3.7, §3.9) ---------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class _SegmentJob(CaptureJob):
    """An exchange job carrying a segment, as WP-12/WP-14 will make them."""

    segment_id: str | None = None


def _capture_job(allocator: SourceAllocator, segment: str | None = None) -> _SegmentJob:
    epoch, sequence, _ = allocator.next_sequence()
    now = time.time_ns()
    body = CapturedBody([b"{}"], 2, truncated=False, media_type="application/json")
    return _SegmentJob(
        exchange_id=str(uuid.uuid4()), api="openai.chat_completions", provider_name="openai",
        source_id=allocator.source_id, source_epoch=epoch, source_sequence=sequence,
        run_id="r-" + "1" * 32, parent_context=None, started_ns=now, ended_ns=now + 1,
        request=body, response=body, response_state="complete", http_status_code=200,
        segment_id=segment,
    )  # fmt: skip


def _record_job(allocator: SourceAllocator) -> RecordJob:
    epoch, sequence, _ = allocator.next_sequence()
    return RecordJob(
        source_id=allocator.source_id, source_epoch=epoch, source_sequence=sequence,
        segment_id=SEG, run_id=None, scope_id=None, event_id=str(uuid.uuid4()),
        attempt_uid=str(uuid.uuid4()), name="tool_call", start_ns=1, end_ns=2,
        otlp_status="unset", attributes={},
    )  # fmt: skip


def _provider() -> tuple[TracerProvider, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


def test_p1_attributes_merge_into_the_exchange_span(monkeypatch: pytest.MonkeyPatch) -> None:
    allocator = SourceAllocator("node-1", "wire")
    job = _capture_job(allocator)
    plain = _pipeline.exchange_attributes(
        job, request_sha256=None, response_sha256=None, request_ref=None, response_ref=None,
        store_status="disabled", truncated=False, metadata={},
    )  # fmt: skip
    assert _attrs.p1_attributes(job) == {}
    monkeypatch.setattr(_pipeline, "p1_attributes", lambda job: {"fabric.capture.input": "wire"})
    merged = _pipeline.exchange_attributes(
        job, request_sha256=None, response_sha256=None, request_ref=None, response_ref=None,
        store_status="disabled", truncated=False, metadata={},
    )  # fmt: skip
    assert merged == {**plain, "fabric.capture.input": "wire"}

    def broken(job: Any) -> dict[str, Any]:
        raise RuntimeError("enrichment bug")

    monkeypatch.setattr(_pipeline, "p1_attributes", broken)
    assert _pipeline.exchange_attributes(
        job, request_sha256=None, response_sha256=None, request_ref=None, response_ref=None,
        store_status="disabled", truncated=False, metadata={},
    ) == plain  # fmt: skip


def test_a_written_exchange_settles_its_segment(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, exporter = _provider()
    loss = LossEmitter()
    pipeline = _pipeline.CapturePipeline(store=None, tracer_provider=provider, loss=loss)
    assert isinstance(pipeline.seals, _seal.SegmentSeals)
    allocator = SourceAllocator("node-1", "wire")
    settled: list[tuple[str | None, int, str]] = []
    pipeline.set_settle(lambda segment, sequence, entry: settled.append((segment, sequence, entry)))
    seen: list[dict[str, Any]] = []

    def digest(**span: Any) -> str:
        seen.append(span)
        return "sha256:" + "d" * 64

    monkeypatch.setattr(_pipeline, "record_digest", digest)
    plain, segmented = _capture_job(allocator), _capture_job(allocator, SEG)
    assert pipeline.submit(plain)
    assert pipeline.submit(segmented)
    assert pipeline.flush(5.0)
    assert len(exporter.get_finished_spans()) == 2
    assert settled == [(SEG, segmented.source_sequence, "sha256:" + "d" * 64)]
    assert seen[0]["name"] == "fabric.model_call"
    assert seen[0]["status"] == "unset"
    assert seen[0]["content"] == []  # metadata-only pipeline: nothing stored
    pipeline.set_settle(None)
    pipeline.close(1.0)
    loss.close(1.0)


def test_record_entry_lists_stored_digests_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_pipeline, "record_digest", lambda **span: "|".join(span["content"]))
    span = {
        "name": "fabric.model_call", "start_time_unix_nano": 1, "end_time_unix_nano": 2,
        "status": "unset", "attributes": {"fabric.wire.response_sha256": "b" * 64,
                                          "fabric.wire.request_sha256": "a" * 64},
    }  # fmt: skip
    assert _pipeline._record_entry(span) == "sha256:" + "a" * 64 + "|sha256:" + "b" * 64


def test_a_failing_record_job_is_an_internal_error_loss(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, _ = _provider()
    loss = LossEmitter()
    pipeline = _pipeline.CapturePipeline(store=None, tracer_provider=provider, loss=loss)

    def broken(job: Any) -> Any:
        raise RuntimeError("protect bug")

    monkeypatch.setattr(pipeline, "_prepare_record", broken)
    allocator = SourceAllocator("node-1", "wire")
    settled: list[tuple[str | None, int, str]] = []
    loss.set_settle(lambda segment, sequence, entry: settled.append((segment, sequence, entry)))
    job = _record_job(allocator)
    assert _pipeline._job_bytes(job) == 0
    assert pipeline.submit(job)
    assert pipeline.flush(5.0)
    assert pipeline.stats()["internal_errors"] == 1
    assert settled == [(SEG, job.source_sequence, "loss:internal_error")]
    pipeline.close(1.0)
    loss.close(1.0)


# --- install, close and run hooks (§3.1, §3.2, §3.6) ----------------------------------------


def test_install_attaches_and_close_detaches_the_p1_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, _ = _provider()
    table = _Table(segment=None)
    monkeypatch.setattr(_segments, "new_run_table", lambda: table)
    handle = wire.install(tracer_provider=provider, patch_httpx=False, patch_aiohttp=False)
    allocator = handle.allocator
    assert handle.registration is not None  # direct mode: no spool to register on
    assert handle.registration.status == "unregistered_direct"
    assert isinstance(handle.records, _records.RecordsInput)
    assert _records.records_input(handle) is handle.records
    assert allocator.segments is table
    assert allocator.seals is handle._tee.pipeline.seals
    with wire.run("run-1"):
        allocator.next_sequence()
    kinds = [kind for kind, _ in table.calls]
    assert kinds == ["enter", "allocate", "exit"]
    assert table.calls[0][1] == table.calls[2][1]
    handle.close(2.0)
    assert ("final", None) in table.calls
    assert isinstance(allocator.segments, NullRunTable)
    assert handle.records is None
    assert _records.records_input(handle) is None
    assert _records.records_input(None) is None


class _BrokenRegistration(_registration.Registration):
    def final(self) -> None:
        raise RuntimeError("registration bug")

    def close(self) -> None:
        raise RuntimeError("registration bug")


def test_the_p1_hooks_fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, _ = _provider()

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("hook bug")

    monkeypatch.setattr(_registration, "register", broken)
    monkeypatch.setattr(_segments, "new_run_table", broken)
    monkeypatch.setattr(_manifest, "emit_initial", broken)
    handle = wire.install(tracer_provider=provider, patch_httpx=False, patch_aiohttp=False)
    assert handle.capturing
    handle.registration = _BrokenRegistration("failed", 1, "s-a")
    handle.allocator.attach(segments=_Table(fail=True))
    monkeypatch.setattr(handle.allocator.segments, "on_block_enter", broken)
    monkeypatch.setattr(handle.allocator.segments, "on_final", broken)
    with wire.run("run-2"):
        pass
    assert handle.close(2.0)


# --- stubs: typed, fail-open, today's behaviour ----------------------------------------------


def test_records_input_without_a_handle_emits_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    records = _records.RecordsInput()
    assert records.begin("tool_call", "sdk.records") is None
    assert records.begin("not_a_kind", "sdk.records") is None  # type: ignore[arg-type]
    assert records.begin("tool_call", "sdk.records", provenance="sniffed") is None  # type: ignore[arg-type]
    assert COUNTERS.api_misuse == 2
    assert records.mode_of("tool.input") == "omit"  # fail closed
    assert records.v2("sess", "session-1") is None
    assert records.v2("nope", "x") is None
    assert COUNTERS.api_misuse == 3
    issuer = fabric._sequence.GeneratedIds()
    attempt = _records.Attempt(records, issuer.mint(str(uuid.uuid4())), "tool_call", "sdk.records")
    assert attempt.emit("start", name_hint="t", attributes={}, start_ns=1, end_ns=1) is False
    monkeypatch.setenv(ct.STRICT_ENV, "1")
    with pytest.raises(RecordsMisuseError):
        records.begin("not_a_kind", "sdk.records")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="v2 prefix"):
        records.v2("nope", "x")


def test_segments_stubs_return_their_not_capturing_values(monkeypatch: pytest.MonkeyPatch) -> None:
    assert isinstance(_segments.new_run_table(), NullRunTable)
    assert _segments.resume_token() is None
    assert _segments.resume_tokens(2) == ()
    assert _segments.resume_tokens(65) == ()
    assert _segments.end_run(None, "completed", resume=("fr3/x",)) == "not_capturing"
    assert _segments.end_run(None, "won", resume=()) == "failed"  # type: ignore[arg-type]
    assert _segments.set_run_outcome("failed", "error") is False
    assert _segments.set_run_outcome("completed", "bored") is False  # type: ignore[arg-type]
    assert COUNTERS.api_misuse == 3
    monkeypatch.setenv(ct.STRICT_ENV, "1")
    with pytest.raises(RecordsMisuseError):
        _segments.resume_tokens(0)


def test_seal_manifest_and_registration_stubs() -> None:
    assert _seal.loss_entry("queue_full") == "loss:queue_full"
    assert isinstance(_seal.new_accumulator(), _seal.SegmentSeals)
    handle: Any = object()
    assert _manifest.build_manifest(handle, 1, seq=0, after=-1, previous_digest=None) is None
    _manifest.emit_initial(handle)
    _manifest.capture_point_changed(handle, "wire.py.aiohttp", "failed")
    assert _manifest.manifest_digest({}).startswith("sha256:")  # built by WP-13
    assert _registration.register(None, "s-a", 1).status == "unregistered_direct"
    assert _registration.scan_orphans(handle) == []  # not a spool: fails open
    registration = _registration.Registration("registered", 1, "s-a")
    registration.mirror(5)
    registration.final()
    registration.close()
    assert _registration.Orphan("s-a", 1, 5).next_sequence == 5
    assert _registration.REG_SIZE == 4096
    assert _registration.OFF_HEADER_SHA256 + 32 == _registration.REG_SIZE


def test_reconstruct_stubs() -> None:
    now = datetime.now(UTC)
    node = _graph.SegmentNode(SEG, "r-1", "s-a", 1, ("none",))
    (graph,) = _graph.build_run_graphs([node], evaluated_at=now)  # WP-31: built
    assert (graph.run_id, graph.run_state) == ("r-1", "not_resumable_unclosed")
    assert _graph.RunGraph("r-1", (node,), None).run_aliases == ()
    assert len(_graph.P1_GAP_TYPES) == 10
    assert (
        _project.build_projection({}, graphs=[], reconstruction_sha256="0", evaluated_at=now)
        is None
    )
    fields = _fields_model.extract_model_fields(
        "openai.chat_completions", request=b"{}", response=None
    )
    assert fields.parse_status == "not_parsed"
    assert dict(fields.fields) == {}
    assert _fields_model.FieldValue("C36", "captured").locators == ()
    decoded = reconstruct_evidence.decode_evidence(
        b"{}", evidence_types={}, provenance="reported", capture_point="sdk.records@1"
    )
    assert (decoded.status, dict(decoded.fields)) == ("not_decoded", {})


def test_inferred_step_id_is_a_reproducible_uuid4_format_id() -> None:
    first = _project.inferred_step_id("fabric-obj://a/b#/messages/3")
    assert ct.UUID4_RE.fullmatch(first)
    assert uuid.UUID(first).version == 4
    assert first == _project.inferred_step_id("fabric-obj://a/b#/messages/3")
    assert first != _project.inferred_step_id("fabric-obj://a/b#/messages/4")
    assert first != str(uuid.uuid5(uuid.NAMESPACE_URL, "fabric-obj://a/b#/messages/3"))
