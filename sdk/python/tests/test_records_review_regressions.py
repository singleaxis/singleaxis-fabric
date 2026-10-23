# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Regressions from the P1 review (records input, evidence carrier, explicit producers).

A: structured evidence, built (``EvidenceDoc``) or raw (``RecordBody(role="record.evidence")``),
   is held to its type's closed item schema and the identity rule before it is persisted:
   a clear caller id or a field outside the schema never reaches the spool, the store or
   the Node (spec 050 §3.4a item 2, §3.17 canaries, R8). Plus the total-work bound of
   ``EvidenceDoc.build`` (R9).
F: a retained evidence document is charged to the in-flight byte budget before admission;
   refused, its reference is dropped and the record carries a descriptor-only evidence
   object (``inflight_budget``).
G: the production profile without ``FABRIC_WIRE_ID_KEY`` emits no clear caller id, in
   either identity mode (049 §2.9 rule 5), as the run identity rule does.
H: rule A refuses an unknown key before touching its value.
J: records-mode ``CallRecorder`` maps any caller id (R8) and never stops the delegate.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import fabric._loss
import fabric._sequence
from fabric import _capture_types as ct
from fabric import wire
from fabric._capture_types import (
    COUNTERS,
    DescriptorOnlyBody,
    EvidenceDoc,
    RecordBody,
    RecordJob,
    RecordsMisuseError,
)
from fabric._evidence import EVIDENCE_MAX_VALUES
from fabric._records import MAX_ATTRIBUTE_ITEMS, RecordsInput
from fabric._sequence import EmittedId, pseudonym_v2
from fabric.wire._policy import CapturePolicy, ContentGate
from fabric.wire._protect import Protector

from ._records_harness import Handle, RecordingContent

KEY = b"k" * 32
TYPE = "fabric.test.items/v1"
EVIDENCE_MEDIA = "application/vnd.fabric.record-evidence+json"
CLEAR_ID, SECRET = "customer-alice", "SECRET_MEDICAL_NOTE"


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(ct.STRICT_ENV, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    COUNTERS.reset()
    yield
    COUNTERS.reset()


def _emit(attempt: Any, **kw: Any) -> bool:
    assert attempt is not None
    result: bool = attempt.emit("end", name_hint="fabric.tool_call", attributes={},
                                start_ns=1, end_ns=2, **kw)  # fmt: skip
    return result


def _raw(items: list[dict[str, Any]]) -> RecordBody:
    data = json.dumps({"schema_version": "fabric.record-evidence/v1", "evidence_type": TYPE,
                       "items": items}, sort_keys=True, separators=(",", ":")).encode()  # fmt: skip
    return RecordBody("record.evidence", data, EVIDENCE_MEDIA, "caller")


def _spooled(handle: Handle) -> tuple[bytes, list[dict[str, Any]], list[bytes]]:
    """Everything spooled for the records (spans and bodies), its descriptors and bytes."""
    sender = handle.sender
    assert sender is not None
    raw = b"".join(sender.spool.read(name) for name in sender.spool.names())
    staged = [body for *_, bodies in sender.items for body in bodies]
    return raw, [d for d, _ in staged], [data for _, data in staged]


# --- A: the evidence carrier (both forms) -------------------------------------------------------


@pytest.mark.parametrize("carrier", ["doc", "raw"])
def test_a_evidence_never_spools_or_delivers_a_clear_id_or_content(carrier: str) -> None:
    handle = Handle(id_key=KEY)
    try:
        canary = {"name": "test", "count": 1, "actor": CLEAR_ID, "body": SECRET}
        mapped = {"name": "test", "count": 1, "actor": CLEAR_ID}
        for item in (canary, mapped):
            if carrier == "raw":
                kwargs: dict[str, Any] = {"bodies": [_raw([item])]}
            else:
                doc = EvidenceDoc.build(TYPE, [item])
                kwargs = {"evidence": doc} if isinstance(doc, EvidenceDoc) else {"bodies": [doc]}
            assert _emit(handle.input.begin("tool_call", "sdk.records"), **kwargs)
        handle.flush()
        raw, descriptors, datas = _spooled(handle)
        sender = handle.sender
        assert sender is not None
        assert sender.deliver()
        delivered = b"".join(data for _, data in sender.content_log.bodies)
        for blob in (raw, b"".join(datas), delivered):
            assert CLEAR_ID.encode() not in blob
            assert SECRET.encode() not in blob
        refused, kept = descriptors
        assert (refused["role"], refused["status"]) == ("record.evidence", "not_captured")
        assert refused["status_reason"] == "parse_failed"
        assert kept["status"] == "stored"
        [item] = json.loads(datas[-1])["items"]
        assert item["actor"] == pseudonym_v2("act", CLEAR_ID, KEY)  # mapped, never clear
    finally:
        handle.close()


@pytest.mark.parametrize("mode", ["pseudonymous", "clear"])
def test_a_evidence_ids_without_a_key_are_omitted_or_clear_only_by_opt_in(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", mode)
    handle = Handle()
    try:
        item = {"name": "test", "count": 1, "actor": CLEAR_ID}
        doc = EvidenceDoc.build(TYPE, [item])
        assert isinstance(doc, EvidenceDoc)
        assert _emit(handle.input.begin("tool_call", "sdk.records"), evidence=doc)
        assert _emit(handle.input.begin("tool_call", "sdk.records"), bodies=[_raw([item])])
        handle.flush()
        _, descriptors, datas = _spooled(handle)
        for descriptor, data in zip(descriptors, datas, strict=True):
            assert descriptor["status"] == "stored"
            [written] = json.loads(data)["items"]
            if mode == "clear":  # the explicit opt-in: the opaque clear form (R8)
                assert written["actor"] == CLEAR_ID
            else:  # no key: nothing derived from the id is written
                assert "actor" not in written
    finally:
        handle.close()


def test_a_evidence_changed_after_emit_is_validated_again_on_the_worker() -> None:
    handle = Handle(id_key=KEY)
    try:
        item: dict[str, Any] = {"name": "test", "count": 1}
        doc = EvidenceDoc.build(TYPE, [item])
        assert isinstance(doc, EvidenceDoc)
        held = threading_gate(handle)
        assert _emit(handle.input.begin("tool_call", "sdk.records"), evidence=doc)
        item["body"] = SECRET  # the application mutates its object while the job is queued
        item["actor"] = CLEAR_ID
        held.set()
        handle.flush()
        raw, descriptors, datas = _spooled(handle)
        assert SECRET.encode() not in raw
        assert CLEAR_ID.encode() not in raw
        [descriptor] = descriptors
        assert (descriptor["status"], descriptor["status_reason"]) == (
            "not_captured", "encoding_failed")  # fmt: skip
        assert datas == [b""]
    finally:
        handle.close()


def threading_gate(handle: Handle) -> Any:
    """Hold the capture worker before it encodes the next record job."""
    import threading  # noqa: PLC0415

    gate = threading.Event()
    pipeline = handle.pipeline
    original = pipeline._record_evidence

    def held(job: RecordJob) -> Any:
        gate.wait(5)
        return original(job)

    pipeline._record_evidence = held  # type: ignore[method-assign]
    return gate


def test_a_raw_evidence_that_is_not_an_envelope_is_never_written() -> None:
    handle = Handle(id_key=KEY)
    try:
        for data in (SECRET.encode(), b'{"schema_version":"fabric.record-evidence/v1"}',
                     b'{"schema_version":"fabric.record-evidence/v1","evidence_type":'
                     b'"fabric.test.items/v1","items":[{"name":"x","count":1.5}]}'):  # fmt: skip
            body = RecordBody("record.evidence", data, EVIDENCE_MEDIA, "caller")
            assert _emit(handle.input.begin("tool_call", "sdk.records"), bodies=[body])
        handle.flush()
        raw, descriptors, _ = _spooled(handle)
        assert SECRET.encode() not in raw
        assert [d["status_reason"] for d in descriptors] == ["parse_failed"] * 3
    finally:
        handle.close()


def test_a_the_store_path_never_writes_a_clear_id_or_content(actual: Any) -> None:
    handle, _, _, root = actual
    item = {"name": "test", "count": 1, "actor": CLEAR_ID, "body": SECRET}
    doc = EvidenceDoc.build(TYPE, [item])
    assert isinstance(doc, DescriptorOnlyBody)
    assert _emit(handle.records.begin("tool_call", "sdk.records"), bodies=[doc])
    assert _emit(handle.records.begin("tool_call", "sdk.records"), bodies=[_raw([item])])
    clean = EvidenceDoc.build(TYPE, [{"name": "test", "count": 1, "actor": CLEAR_ID}])
    assert _emit(handle.records.begin("tool_call", "sdk.records"), evidence=clean)
    assert handle.flush(5)
    written = b"".join(p.read_bytes() for p in Path(root).rglob("*") if p.is_file())
    assert written  # the clean document was stored
    assert CLEAR_ID.encode() not in written
    assert SECRET.encode() not in written


def test_a_build_has_a_total_work_bound() -> None:
    """Fable P3-1: 4096 items of 4096-element lists are inside the per-container bounds;
    the walk stops at :data:`EVIDENCE_MAX_VALUES` instead of visiting all 16M values."""
    seen = [0]

    class Counted(list[int]):
        def __iter__(self) -> Iterator[int]:
            for value in super().__iter__():
                seen[0] += 1
                yield value

    tags = Counted(range(ct.EVIDENCE_MAX_ITEMS))
    items = [{"name": "x", "count": 1, "tags": tags}] * ct.EVIDENCE_MAX_ITEMS
    started = time.perf_counter()
    got = EvidenceDoc.build(TYPE, items)
    elapsed = time.perf_counter() - started
    assert isinstance(got, DescriptorOnlyBody)
    assert got.reason == "payload_too_large"
    assert seen[0] <= EVIDENCE_MAX_VALUES
    assert elapsed < 0.5  # generous on a loaded machine; 800 ms before the bound


# --- F: the in-flight charge ----------------------------------------------------------------------


def test_f_evidence_is_charged_and_refused_by_the_inflight_budget() -> None:
    handle = Handle(budget=1)
    try:
        doc = EvidenceDoc.build(TYPE, [{"name": "test", "count": 1}] * 4096)
        assert isinstance(doc, EvidenceDoc)
        assert doc.charge > 1
        submitted: list[Any] = []
        original = handle.pipeline.submit

        def submit(job: Any) -> bool:
            submitted.append(job)
            return original(job)

        handle.pipeline.submit = submit  # type: ignore[method-assign]
        assert _emit(handle.input.begin("tool_call", "sdk.records"), evidence=doc)
        [job] = submitted
        assert job.evidence is None  # the reference to the application's objects is dropped
        assert handle.input.stats.snapshot()["records_budget_refused"] == 1
        handle.flush()
        _, descriptors, _ = _spooled(handle)
        [descriptor] = descriptors
        assert (descriptor["role"], descriptor["status"], descriptor["status_reason"]) == (
            "record.evidence", "not_captured", "inflight_budget")  # fmt: skip
    finally:
        handle.close()


def test_f_an_unmeasured_document_is_charged_the_cap() -> None:
    job = RecordJob("s-" + "0" * 32, 1, 0, None, None, None, "e", "a", "fabric.activity", 0, 0,
                    "unset", {}, evidence=EvidenceDoc(TYPE, ()))  # fmt: skip
    assert job.inflight_charge == ct.EVIDENCE_MAX_BYTES
    handle = Handle()
    try:
        doc = EvidenceDoc.build(TYPE, [{"name": "test", "count": 1}])
        assert isinstance(doc, EvidenceDoc)
        assert _emit(handle.input.begin("tool_call", "sdk.records"), evidence=doc)
        handle.flush()
        assert handle.budget.used == 0  # released when the job is done
    finally:
        handle.close()


# --- G: production without a key ------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["clear", "pseudonymous"])
def test_g_production_without_a_key_emits_no_clear_caller_id(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", mode)
    policy = CapturePolicy("acme", 3, "sha256:" + "3" * 64, {"tool.call.result": "retain_original"})
    gate = ContentGate("production", "enabled", None, policy)
    handle = Handle(gate=gate, protector=Protector(policy, max_body_bytes=1 << 20))
    try:
        handle.gate = gate  # type: ignore[attr-defined]
        handle.records = records = RecordsInput(handle)  # type: ignore[arg-type]
        assert records.identity_mode == "pseudonymous"
        attempt = records.begin("tool_call", "sdk.records", step_id="patient-123",
                                parent_attempt="patient-parent")  # fmt: skip
        stream = RecordBody("tool.call.result", b"{}", "application/json", "caller",
                            stream_id="patient-stream")  # fmt: skip
        assert _emit(attempt, bodies=[stream])
        again = records.begin("tool_call", "sdk.records", step_id="patient-123")
        assert _emit(again)
        handle.flush()
        raw, descriptors, _ = _spooled(handle)
        assert b"patient-" not in raw
        sender = handle.sender
        assert sender is not None
        first, second = (span["attributes"] for _, _, span, _ in sender.items)
        assert first["fabric.step.id"].startswith("g-")
        assert first["fabric.step.parent_id"].startswith("g-")
        assert first["fabric.step.id"] == second["fabric.step.id"]  # one join id per value
        assert descriptors[0]["stream_id"].startswith("g-")
        assert records.v2("usr", "patient-123") is None  # omitted, as the run's user_id
        assert records.map_id("patient-123") == first["fabric.step.id"]
    finally:
        handle.close()


def test_g_real_production_install_without_a_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: PLC0415
        InMemorySpanExporter,
    )

    loss = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", loss)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "clear")
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    exporter = InMemorySpanExporter()
    handle = wire.install(content_endpoint="http://127.0.0.1:4318/content", tenant_id="tenant-a",
                          spool_dir=str(tmp_path / "node-spool"), spool_max_bytes=128 << 20,
                          span_exporter=exporter, content_client=RecordingContent(),  # type: ignore[arg-type]
                          patch_httpx=False, patch_aiohttp=False)  # fmt: skip
    try:
        assert handle.gate is not None
        assert handle.gate.profile == "production"
        assert handle.config.id_key is None
        records = handle.records
        assert records is not None
        assert _emit(records.begin("tool_call", "sdk.records", step_id="patient-123"))
        assert handle.flush(5)
        spans = [s for s in exporter.get_finished_spans()
                 if (s.attributes or {}).get("fabric.capture.input") == "records"]  # fmt: skip
        [span] = spans
        step = (span.attributes or {})["fabric.step.id"]
        assert isinstance(step, str)
        assert step.startswith("g-")
    finally:
        handle.close(5)
        loss.close(1)


# --- H: rule A before any value is touched -----------------------------------------------------


def test_h_an_unknown_key_is_dropped_without_traversing_its_value() -> None:
    class DoNotTraverse(list[int]):
        def __iter__(self) -> Iterator[int]:
            raise AssertionError("unknown attribute value traversed")

        def __len__(self) -> int:
            raise AssertionError("unknown attribute value measured")

    cyclic: list[Any] = []
    cyclic.append(cyclic)
    handle = Handle()
    try:
        for value in (DoNotTraverse([1, 2, 3]), cyclic):
            attempt = handle.input.begin("tool_call", "sdk.records")
            assert attempt is not None
            attributes = {"unknown.content": value, "fabric.error.domain": "tool"}
            assert attempt.emit("end", name_hint="fabric.tool_call", attributes=attributes,
                                start_ns=1, end_ns=2)  # fmt: skip
        handle.flush()
        sender = handle.sender
        assert sender is not None
        for *_, span, _ in sender.items:
            assert "unknown.content" not in span["attributes"]
            assert span["attributes"]["fabric.error.domain"] == "tool"
        assert handle.input.stats.snapshot()["records_keys_dropped"] == 2
    finally:
        handle.close()


def test_h_an_admitted_key_refuses_a_long_or_nested_value_by_its_shape() -> None:
    class NoIteration(list[str]):
        def __iter__(self) -> Iterator[str]:
            raise AssertionError("a value longer than any admitted array was traversed")

    cyclic: list[Any] = []
    cyclic.append(cyclic)
    long = NoIteration(["x"] * (MAX_ATTRIBUTE_ITEMS + 1))
    handle = Handle()
    try:
        for value in (long, cyclic, [["nested"]]):
            assert _emit_attrs(handle, {"fabric.error.domain": value})
        assert handle.input.stats.snapshot()["records_keys_dropped"] == 3
    finally:
        handle.close()


def _emit_attrs(handle: Handle, attributes: dict[str, Any]) -> bool:
    attempt = handle.input.begin("tool_call", "sdk.records")
    assert attempt is not None
    return attempt.emit("end", name_hint="fabric.tool_call", attributes=attributes,
                        start_ns=1, end_ns=2)  # fmt: skip


# --- J: records-mode CallRecorder ids -------------------------------------------------------------


@pytest.fixture
def actual(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: PLC0415

    from fabric.content_store import LocalFilesystemContentStore  # noqa: PLC0415

    from .test_capture_integration import JsonlSpanExporter  # noqa: PLC0415

    loss = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", loss)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    monkeypatch.setenv("FABRIC_CLOCK_UNCERTAINTY_MS", "0")
    provider = TracerProvider()
    spans = tmp_path / "actual.jsonl"
    provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(spans)))
    root = tmp_path / "actual-store"
    store = LocalFilesystemContentStore(root=str(root), tenant_id="tenant-a")
    handle = wire.install(store=store, tracer_provider=provider, patch_httpx=False,
                          patch_aiohttp=False, id_key=KEY)  # fmt: skip
    yield handle, store, spans, root
    handle.close(5)
    loss.close(1)
    provider.shutdown()


@pytest.mark.parametrize("option", [
    {"operation_id": "tenant/patient-123"}, {"attempt_id": "tenant/patient 1"},
    {"parent_call_id": "tenant/patient-123"}, {"agent_id": "agent with spaces"},
    {"kind": "not-a-kind"}, {"operation_id": 7},
])  # fmt: skip
def test_j_records_mode_never_stops_the_delegate(
    actual: Any, tmp_path: Path, option: dict[str, Any]
) -> None:
    from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, CallRecorder  # noqa: PLC0415
    from fabric.content_store import LocalFilesystemContentStore  # noqa: PLC0415

    handle = actual[0]
    writer = ByteEvidenceRecorder(ByteEvidenceConfig(
        store=LocalFilesystemContentStore(root=str(tmp_path / "explicit"), tenant_id="tenant-a"),
        roles=frozenset({"tool.call.arguments", "tool.call.result"}),
    ))  # fmt: skip
    called: list[bool] = []
    try:
        recorder = CallRecorder(writer, run_id="r", agent_id="a", source_id="s", mode="records")

        def delegate_ok(data: bytes) -> bytes:
            called.append(True)
            return b"ok"

        result = recorder.call(b"{}", delegate_ok, **option)
        assert result == b"ok"
        assert called == [True]
        with pytest.raises(KeyError, match="delegate"):  # the delegate's own error, unchanged
            recorder.call(b"{}", _raise_key_error, **option)

        async def delegate(data: bytes) -> bytes:
            return b"async"

        import asyncio  # noqa: PLC0415

        assert asyncio.run(recorder.acall(b"{}", delegate, **option)) == b"async"
        with recorder.stream(b"{}", lambda data: iter([b"a", b"b"]), **option) as chunks:
            assert list(chunks) == [b"a", b"b"]
        assert handle.flush(5)
        snapshot = recorder.snapshot(settle_timeout_s=5)
        text = json.dumps(snapshot)
        assert "patient" not in text
        assert "agent with spaces" not in text
        if option.get("operation_id") == "tenant/patient-123":
            [first, *_] = snapshot["calls"]
            assert first["operation_id"].startswith("lbl-")  # mapped (R8), not refused
    finally:
        writer.close()


def _raise_key_error(data: bytes) -> bytes:
    raise KeyError("delegate")


def test_j_strict_mode_still_raises_on_misuse(actual: Any, tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, CallRecorder  # noqa: PLC0415
    from fabric.content_store import LocalFilesystemContentStore  # noqa: PLC0415

    writer = ByteEvidenceRecorder(ByteEvidenceConfig(
        store=LocalFilesystemContentStore(root=str(tmp_path / "explicit"), tenant_id="tenant-a"),
        roles=frozenset({"tool.call.arguments", "tool.call.result"}),
    ))  # fmt: skip
    try:
        recorder = CallRecorder(writer, run_id="r", agent_id="a", source_id="s", mode="records")
        monkeypatch.setenv(ct.STRICT_ENV, "1")
        with pytest.raises(ValueError, match="kind"):
            recorder.call(b"{}", lambda data: b"ok", kind="not-a-kind")
        assert recorder.call(b"{}", lambda data: b"ok", operation_id="tenant/patient-1") == b"ok"
    finally:
        writer.close()


# --- WP-16 note: a mapped id passed back is not mapped again ------------------------------------


def test_map_id_returns_an_emitted_id_that_passes_through() -> None:
    handle = Handle(id_key=KEY)
    try:
        records = handle.input
        mapped = records.map_id("patient-123")
        assert isinstance(mapped, EmittedId)
        assert records.map_id(mapped) == mapped
        assert type(records.map_id(mapped)) is EmittedId
    finally:
        handle.close()


def test_strict_mode_raises_a_schema_refusal_at_build(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ct.STRICT_ENV, "1")
    with pytest.raises(RecordsMisuseError):
        EvidenceDoc.build(TYPE, [{"name": "x", "count": 1, "body": SECRET}])
