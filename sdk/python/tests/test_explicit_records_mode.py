# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 050 §3.10 (WP-16): the explicit producers on the records input.

The three-way mode (records, journal, legacy); in records mode one record per journal
event with the §3.10 ids and R4 status inputs, bodies protected by the install's capture
policy before they reach the spool, the 16 MiB + 1 outcome and ``not_exact_bytes`` as
descriptor-only bodies, the snapshot view, the ``records_mode`` seal refusal, the
byte-config conflict check, the manifest's capture-point state, and the session-based
adapters (``ByteBoundaryAdapter``, the terminal and artifact adapters, ``FinalHTTPAdapter``).

Records-mode cases that read the spool run on the WP-11a harness (a real capture pipeline,
allocator, sender and spool) installed in place of the wire handle's records input; the
manifest, conflict and HTTP cases run on a real ``fabric.wire`` install.
"""

from __future__ import annotations

import asyncio
import contextvars
import gc
import json
import sys
import uuid
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric._loss
import fabric._sequence
from fabric import (
    ByteEvidenceConfig,
    ByteEvidenceRecorder,
    BytePrivacyPolicy,
    CallRecorder,
    LocalFilesystemContentStore,
    _manifest,
    call_recorder,
    wire,
)
from fabric import _capture_types as ct
from fabric._capture_types import COUNTERS
from fabric._loss import LossEmitter
from fabric._sequence import label_pseudonym
from fabric.adapters.byte_boundary import ByteBoundaryAdapter
from fabric.adapters.synthetic_evidence import (
    AllowlistedArtifactObserver,
    BoundedTerminalAdapter,
    SyntheticCaptureSession,
)
from fabric.http_dispatch import FinalHTTPAdapter, IndependentHTTPWitness
from fabric.source_spool import SyntheticSourceSpool
from fabric.wire import WireConfig
from fabric.wire._policy import CapturePolicy, ContentGate
from fabric.wire._protect import Protector

from ._records_harness import Handle

KEY = b"k" * 32
ROLES = frozenset({
    "model.request.messages", "model.output.messages", "tool.call.arguments",
    "tool.call.result", "interaction.payload", "database.query", "database.rows",
    "terminal.argv", "terminal.stdin", "terminal.stdout", "terminal.stderr",
    "artifact.before", "artifact.after",
})  # fmt: skip
SECRET = b'{"secret":"do-not-spool-me"}'


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    monkeypatch.setenv(ct.STRICT_ENV, "1")
    COUNTERS.reset()
    yield
    COUNTERS.reset()


class Harness(Handle):
    """The WP-11a harness as the installed records input (``flush(timeout)`` as a
    ``WireHandle`` has it)."""

    def flush(self, timeout_s: float = 5.0) -> bool:  # type: ignore[override]
        return bool(self.pipeline.flush(timeout_s))

    def spooled(self) -> list[dict[str, Any]]:
        """``(span, staged)`` of every spooled record, in position order."""
        assert self.flush()
        assert self.sender is not None
        found = [{"span": span, "staged": staged} for _, _, span, staged in self.sender.items]
        return sorted(found, key=lambda r: r["span"]["attributes"]["fabric.source.sequence"])

    def spool_bytes(self) -> bytes:
        assert self.sender is not None
        root = Path(self.sender.directory)
        return b"".join(p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file())


def _policy(**modes: str) -> tuple[ContentGate, Protector]:
    policy = CapturePolicy("acme", 1, "sha256:" + "1" * 64, modes)
    return ContentGate("production", "enabled", None, policy), Protector(
        policy, max_body_bytes=1 << 20
    )


def _harness(monkeypatch: pytest.MonkeyPatch, **modes: str) -> Harness:
    modes = modes or dict.fromkeys(ROLES, "retain_original")
    gate, protector = _policy(**modes)
    handle = Harness(gate=gate, protector=protector, id_key=KEY)
    monkeypatch.setattr(call_recorder, "installed_records", lambda: handle.input)
    return handle


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> Iterator[Harness]:
    handle = _harness(monkeypatch)
    yield handle
    handle.close()


@pytest.fixture
def writer(tmp_path: Path) -> Iterator[ByteEvidenceRecorder]:
    store = LocalFilesystemContentStore(str(tmp_path / "explicit"), tenant_id="tenant")
    made = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=ROLES))
    yield made
    made.close()


def _spool(tmp_path: Path) -> SyntheticSourceSpool:
    root = tmp_path / "journal"
    root.mkdir(mode=0o700)
    return SyntheticSourceSpool(str(root), tenant_id="tenant", run_id="run")


def _recorder(writer: ByteEvidenceRecorder, **kwargs: Any) -> CallRecorder:
    return CallRecorder(writer, run_id="run", agent_id="agent", source_id="source", **kwargs)


def _attrs(record: dict[str, Any]) -> dict[str, Any]:
    return dict(record["span"]["attributes"])


# --- the three-way mode ----------------------------------------------------------------------


def test_auto_mode_follows_the_spec_table(
    harness: Harness, writer: ByteEvidenceRecorder, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    assert _recorder(writer).mode == "records"
    spool = _spool(tmp_path)
    try:
        assert _recorder(writer, source_spool=spool).mode == "journal"
    finally:
        spool.close()
    monkeypatch.setattr(call_recorder, "installed_records", lambda: None)
    monkeypatch.setattr(call_recorder, "_LEGACY_WARNED", [])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert _recorder(writer).mode == "legacy"
        assert _recorder(writer, mode="legacy").mode == "legacy"
        session = SyntheticCaptureSession(writer, tenant_id="tenant", run_id="run")
        assert session.mode == "legacy"
    deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert len(deprecations) == 1  # one per process
    assert deprecations[0].filename == __file__  # attributed to the caller


def test_a_mode_contradicting_the_arguments_is_configuration(
    writer: ByteEvidenceRecorder, tmp_path: Path, harness: Harness
) -> None:
    with pytest.raises(ValueError, match="journal mode requires a source_spool"):
        _recorder(writer, mode="journal")
    spool = _spool(tmp_path)
    try:
        with pytest.raises(ValueError, match="only in journal mode"):
            _recorder(writer, source_spool=spool, mode="records")
        with pytest.raises(ValueError, match="only in journal mode"):
            SyntheticCaptureSession(writer, tenant_id="tenant", run_id="run",
                                    source_spool=spool, mode="legacy")  # fmt: skip
    finally:
        spool.close()
    with pytest.raises(ValueError, match="mode must be"):
        _recorder(writer, mode="sequenced")


# --- records mode: one record per journal event, ids, statuses ------------------------------


def test_one_record_per_journal_event_with_the_spec_ids(
    harness: Harness, writer: ByteEvidenceRecorder
) -> None:
    recorder = _recorder(writer)
    assert recorder.source_id == harness.allocator.source_id  # the process source
    result = recorder.call(b'{"q":1}', lambda data: b'{"a":2}', kind="tool",
                           operation_id="op-1", attempt_id="try-1", context=b"ctx")  # fmt: skip
    assert result == b'{"a":2}'
    records = harness.spooled()
    snapshot = recorder.snapshot()
    (call,) = snapshot["calls"]
    # operation.start (+ input body), the context, the result, operation.outcome
    rows = [*snapshot["starts"], *snapshot["events"][1:], *snapshot["operations"]]
    assert len(records) == len(rows) == 4
    assert [r["span"]["attributes"]["fabric.source.sequence"] for r in records] == [0, 1, 2, 3]
    for record, row in zip(records, rows, strict=True):
        found = _attrs(record)
        assert found["fabric.event_id"] == str(uuid.UUID(hex=row["record_id"]))
        assert found["fabric.attempt.uid"] == call["call_id"]
        assert found["fabric.step.id"] == label_pseudonym("lbl-", "op-1", KEY)
        assert found["fabric.step.attempt_id"] == label_pseudonym("lbl-", "try-1", KEY)
        assert found["fabric.step.kind"] == "tool_call"
        assert found["fabric.capture.input"] == "records"
        assert found["fabric.capture.point"].startswith("explicit.call_recorder@")
        assert "fabric.step.parent_id" not in found
        assert record["span"]["name"] == "fabric.tool_call"
    assert str(uuid.UUID(call["call_id"])) == call["call_id"]  # dashed uuid4
    assert (call["operation_id"], call["attempt_id"]) == (
        label_pseudonym("lbl-", "op-1", KEY), label_pseudonym("lbl-", "try-1", KEY))  # fmt: skip
    lifecycles = [_attrs(r).get("fabric.step.lifecycle_state") for r in records]
    assert lifecycles == ["running", "running", "running", "completed"]
    assert _attrs(records[3])["fabric.step.status"] == "ok"
    staged = [[(d["role"], d["boundary"], bytes(b)) for d, b in r["staged"]] for r in records]
    assert staged == [
        [("tool.call.arguments", "tool", b'{"q":1}')],
        [("interaction.payload", "caller", b"ctx")],  # placed at its admitted boundary
        [("tool.call.result", "tool", b'{"a":2}')],
        [],
    ]
    assert recorder.seal_source() == {"status": "refused", "reason": "records_mode"}


def test_step_kinds_parents_and_unnamed_ids(harness: Harness, writer: ByteEvidenceRecorder) -> None:
    recorder = _recorder(writer)

    def inner(data: bytes) -> bytes:
        return recorder.call(data, lambda d: d, kind="database")

    recorder.call(b"{}", inner, kind="agent")
    recorder.call(b"{}", lambda d: d, kind="model", parent_call_id="caller-parent")
    records = harness.spooled()
    calls = recorder.snapshot()["calls"]
    by_uid = {c["call_id"]: c for c in calls}
    kinds = {_attrs(r)["fabric.attempt.uid"]: _attrs(r)["fabric.step.kind"] for r in records}
    assert sorted(kinds.values()) == ["database", "delegation", "model_call"]
    agent, database, model = calls
    for record in records:
        found = _attrs(record)
        call = by_uid[found["fabric.attempt.uid"]]
        # no operation/attempt id given: both are the attempt's own uid
        assert found["fabric.step.id"] == found["fabric.step.attempt_id"] == call["call_id"]
    nested = [_attrs(r) for r in records if _attrs(r)["fabric.attempt.uid"] == database["call_id"]]
    assert {r["fabric.step.parent_id"] for r in nested} == {agent["call_id"]}
    explicit = [_attrs(r) for r in records if _attrs(r)["fabric.attempt.uid"] == model["call_id"]]
    assert {r["fabric.step.parent_id"] for r in explicit} == {
        label_pseudonym("lbl-", "caller-parent", KEY)}  # fmt: skip
    assert model["parent_call_id"] == label_pseudonym("lbl-", "caller-parent", KEY)


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        ("ok", ("completed", "ok", "unset")),
        ("error", ("completed", "error", "error")),
        ("cancelled", ("cancelled", "cancelled", "unset")),
        ("deferred", ("deferred", "unknown", "unset")),
    ],
)
def test_end_record_carries_the_three_status_inputs(
    harness: Harness, writer: ByteEvidenceRecorder, outcome: str,
    expected: tuple[str, str, str],
) -> None:  # fmt: skip
    recorder = _recorder(writer)
    failure = ValueError("delegate failure")

    def delegate(data: bytes) -> Any:
        if outcome == "error":
            raise failure
        if outcome == "cancelled":
            raise asyncio.CancelledError
        return iter(()) if outcome == "deferred" else b"{}"

    if outcome in ("error", "cancelled"):
        with pytest.raises((ValueError, asyncio.CancelledError)) as caught:
            recorder.call(b"{}", delegate, kind="tool")
        assert outcome != "error" or caught.value is failure
    else:
        recorder.call(b"{}", delegate, kind="tool")
    end = harness.spooled()[-1]
    found = _attrs(end)
    assert (found["fabric.step.lifecycle_state"], found["fabric.step.status"],
            end["span"]["status"]) == expected  # fmt: skip


def test_streams_are_one_data_record_per_chunk(
    harness: Harness, writer: ByteEvidenceRecorder
) -> None:
    recorder = _recorder(writer)
    assert list(recorder.stream(b"{}", lambda d: iter((b"a", b"bc")), kind="tool")) == [
        b"a", b"bc"]  # fmt: skip

    async def chunks(data: bytes) -> Any:
        for part in (b"x",):
            yield part

    async def drain() -> list[bytes]:
        return [c async for c in recorder.astream(b"{}", chunks, kind="tool")]

    assert asyncio.run(drain()) == [b"x"]
    records = harness.spooled()
    data = [d for r in records for d, _ in r["staged"] if d["role"] == "tool.call.result"]
    assert [(d.get("chunk_index"), d["stream_id"]) for d in data][:2] == [
        (0, data[0]["stream_id"]), (1, data[0]["stream_id"])]  # fmt: skip
    call_ids = [c["call_id"] for c in recorder.snapshot()["calls"]]
    assert data[0]["stream_id"] == call_ids[0]  # the call id is the stream id
    assert len(records) == 4 + 3


def test_a_capture_after_the_end_is_an_update(
    harness: Harness, writer: ByteEvidenceRecorder
) -> None:
    """A context copied inside the call still names it after it ended: data recorded
    there is an ``update`` (no lifecycle, no status) of the ended attempt."""
    recorder = _recorder(writer)
    copied: list[contextvars.Context] = []

    def delegate(data: bytes) -> bytes:
        copied.append(contextvars.copy_context())
        return b"{}"

    recorder.call(b"{}", delegate, kind="tool")
    copied[0].run(recorder.record_data, b"late", role="tool.call.result")
    records = harness.spooled()
    assert len(records) == 4
    last = _attrs(records[-1])
    assert "fabric.step.lifecycle_state" not in last
    assert "fabric.step.status" not in last
    assert last["fabric.attempt.uid"] == _attrs(records[0])["fabric.attempt.uid"]
    assert [bytes(b) for _, b in records[-1]["staged"]] == [b"late"]


def test_an_abandoned_stream_emits_no_end_from_its_finalizer(
    harness: Harness, writer: ByteEvidenceRecorder
) -> None:
    recorder = _recorder(writer)
    stream = recorder.stream(b"{}", lambda d: iter((b"a", b"b")), kind="tool")
    assert next(stream) == b"a"
    del stream
    gc.collect()
    records = harness.spooled()
    assert [_attrs(r).get("fabric.step.lifecycle_state") for r in records] == [
        "running", "running"]  # fmt: skip
    (outcome,) = recorder.snapshot()["operations"]
    assert (outcome["status"], outcome["status_reason"]) == ("failed", "abandoned_unclosed")
    assert recorder.snapshot()["calls"][0]["status"] == "partial"


# --- records mode: bodies ---------------------------------------------------------------------


def test_bodies_are_protected_before_the_spool(
    monkeypatch: pytest.MonkeyPatch, writer: ByteEvidenceRecorder
) -> None:
    handle = _harness(monkeypatch, **{"tool.call.arguments": "metadata_only",
                                      "tool.call.result": "retain_original"})  # fmt: skip
    try:
        recorder = _recorder(writer)
        recorder.call(SECRET, lambda d: b'{"kept":1}', kind="tool")
        records = handle.spooled()
        start_bodies = records[0]["staged"]
        [(descriptor, data)] = start_bodies
        assert (descriptor["status"], descriptor["status_reason"], data) == (
            "not_captured", "privacy_policy", b"")  # fmt: skip
        assert descriptor["source_byte_length"] == len(SECRET)
        spooled = handle.spool_bytes()
        assert SECRET not in spooled  # never written to disk
        assert b'{"kept":1}' in spooled  # the retained role is
        # interaction.payload is not named by the configured policy: omit, no body built
        recorder.call(b"{}", lambda d: b"{}", kind="tool", context=b"ctx")
        context = [r for r in handle.spooled() if not r["staged"]]
        assert context  # the context record carries no body at all
        events = recorder.snapshot()["events"]
        assert ("not_captured", "privacy_policy") in [
            (e["status"], e.get("status_reason")) for e in events
            if e["role"] == "interaction.payload"]  # fmt: skip
    finally:
        handle.close()


def test_over_the_cap_and_not_exact_bytes_are_descriptor_only(
    harness: Harness, writer: ByteEvidenceRecorder
) -> None:
    recorder = _recorder(writer)
    big = b"x" * (16 * 1024 * 1024 + 1)
    marker = object()
    assert recorder.call(big, lambda d: marker, kind="tool") is marker
    records = harness.spooled()
    [(over, over_data)] = records[0]["staged"]
    assert (over["status"], over["status_reason"], over_data) == (
        "not_captured", "payload_too_large", b"")  # fmt: skip
    assert over["source_byte_length"] == len(big)
    assert over["representation"] == "unavailable"
    [(inexact, inexact_data)] = records[1]["staged"]
    assert (inexact["status"], inexact["status_reason"], inexact_data) == (
        "unsupported", "not_exact_bytes", b"")  # fmt: skip
    events = recorder.snapshot()["events"]
    assert [(e["status"], e.get("status_reason")) for e in events] == [
        ("not_captured", "payload_too_large"), ("unsupported", "not_exact_bytes")]  # fmt: skip
    del big


def test_the_byte_writer_is_not_called(
    harness: Harness, writer: ByteEvidenceRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("ByteEvidenceRecorder.capture called in records mode")

    monkeypatch.setattr(writer, "capture", refuse)
    recorder = _recorder(writer)
    recorder.call(b"{}", lambda d: b"{}", kind="model")
    session = SyntheticCaptureSession(writer, tenant_id="tenant", run_id="run")
    session.capture(b"{}", source_id="s", boundary="tool", role="tool.call.result",
                    operation_id="op", attempt_id="1")  # fmt: skip
    assert len(harness.spooled()) == 4


def test_snapshot_statuses_settle_with_the_handle(
    monkeypatch: pytest.MonkeyPatch, writer: ByteEvidenceRecorder
) -> None:
    handle = _harness(monkeypatch)
    settled = {"value": False}
    monkeypatch.setattr(handle, "flush", lambda timeout_s=5.0: settled["value"])
    try:
        recorder = _recorder(writer)
        recorder.call(b"{}", lambda d: b"{}", kind="tool")
        view = recorder.snapshot()
        assert view["capture_mode"] == "records"
        assert view["writer_settled"] is False
        assert [e["status"] for e in view["events"]] == ["pending", "pending"]
        assert view["source_high_water"] == {}
        assert [e["source_sequence"] for e in view["events"]] == [None, None]
        settled["value"] = True
        view = recorder.snapshot()
        assert view["writer_settled"] is True
        assert [e["status"] for e in view["events"]] == ["settled", "settled"]
        assert view["all_observed_calls_finished"] is True
    finally:
        handle.close()


def test_an_inactive_input_is_a_counted_gap_and_never_changes_the_call(
    harness: Harness, writer: ByteEvidenceRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = _recorder(writer)
    monkeypatch.setattr(call_recorder, "installed_records", lambda: None)
    assert recorder.call(b"{}", lambda d: b"{}", kind="tool") == b"{}"
    view = recorder.snapshot()
    assert view["recording_gaps"] == 3  # start, result, end were not emitted
    assert view["writer_settled"] is False
    assert {e["status"] for e in view["events"]} == {"failed"}
    assert view["operations"][0]["status_reason"] == "record_not_emitted"


def test_a_refused_submit_is_a_wire_loss_and_a_view_gap(
    monkeypatch: pytest.MonkeyPatch, writer: ByteEvidenceRecorder
) -> None:
    monkeypatch.delenv(ct.STRICT_ENV)
    gate, protector = _policy(**dict.fromkeys(ROLES, "retain_original"))
    handle = Harness(gate=gate, protector=protector, id_key=KEY, queue_max_items=1)
    monkeypatch.setattr(call_recorder, "installed_records", lambda: handle.input)
    try:
        recorder = _recorder(writer)
        handle.pipeline.close(2.0)  # closed: every submit is a shutdown loss
        assert recorder.call(b"{}", lambda d: b"{}", kind="tool") == b"{}"
        assert recorder.snapshot(settle_timeout_s=0.1)["recording_gaps"] == 3
    finally:
        handle.close()


# --- configuration conflict and manifest state (real install) ---------------------------------


@pytest.fixture
def installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(WireConfig(store=store, tracer_provider=provider, patch_httpx=False,
                                     patch_aiohttp=False))  # fmt: skip
    try:
        yield handle, exporter, store
    finally:
        wire.uninstall()
        emitter.close(1.0)


def _states(handle: Any) -> dict[str, str]:
    document = _manifest.current_document(handle.allocator)
    assert document is not None
    return {p["id"]: p["state"] for p in document["capture_points"]}


def test_a_byte_config_disagreeing_with_the_capture_policy_raises(
    installed: Any, tmp_path: Path
) -> None:
    store = LocalFilesystemContentStore(str(tmp_path / "explicit"), tenant_id="tenant")
    disagree = ByteEvidenceRecorder(ByteEvidenceConfig(
        store=store, roles=ROLES,
        role_policies={"model.request.messages": BytePrivacyPolicy(mode="omit")},
    ))  # fmt: skip
    agree = ByteEvidenceRecorder(ByteEvidenceConfig(
        store=store, roles=ROLES,
        role_policies={"model.request.messages": BytePrivacyPolicy(mode="original")},
    ))  # fmt: skip
    try:
        with pytest.raises(ValueError, match=r"capture policy for: model\.request\.messages"):
            _recorder(disagree)
        with pytest.raises(ValueError, match="disagree"):
            SyntheticCaptureSession(disagree, tenant_id="tenant", run_id="run")
        assert _recorder(agree).mode == "records"  # local default: retain_original
        assert _recorder(disagree, mode="legacy").mode == "legacy"  # not checked there
        assert disagree.capture_policy_conflicts(lambda role: "omit") == []
    finally:
        disagree.close()
        agree.close()


def test_explicit_producers_mark_their_capture_points_active(
    installed: Any, writer: ByteEvidenceRecorder, tmp_path: Path
) -> None:
    handle, exporter, _ = installed
    before = _states(handle)
    assert before["explicit.call_recorder"] == "installed_inactive"
    assert before["explicit.final_http"] == "installed_inactive"
    recorder = _recorder(writer)
    recorder.call(b"{}", lambda d: b"{}", kind="tool")
    recorder.call(b"{}", lambda d: b"{}", kind="tool")  # no second change
    assert _states(handle)["explicit.call_recorder"] == "active"
    with IndependentHTTPWitness(tmp_path / "witness") as witness:
        adapter = FinalHTTPAdapter(declared_url=witness.url, recorder=recorder)
        result = adapter.request("POST", witness.url, b"{}", operation_id="op",
                                 attempt_id="1")  # fmt: skip
        assert result.body == b"ok"
    session = SyntheticCaptureSession(writer, tenant_id="tenant", run_id="run")
    ByteBoundaryAdapter(session, kind="tool", source_id="tool-1").call(
        b"{}", lambda d: b"{}", operation_id="t", attempt_id="1")  # fmt: skip
    states = _states(handle)
    assert states["explicit.final_http"] == "active"
    assert states["explicit.byte_boundary"] == "active"
    assert states["explicit.subprocess_artifact"] == "installed_inactive"
    assert handle.flush(10.0)
    manifests = [s for s in exporter.get_finished_spans() if s.name == "fabric.capture_manifest"]
    assert len(manifests) == 4  # manifest 0 and one per state change
    records = [s for s in exporter.get_finished_spans()
               if dict(s.attributes or {}).get("fabric.capture.input") == "records"]  # fmt: skip
    points = {str(dict(s.attributes or {})["fabric.capture.point"]).split("@")[0]
              for s in records}  # fmt: skip
    assert points == {"explicit.call_recorder", "explicit.final_http", "explicit.byte_boundary"}


# --- the session-based adapters ---------------------------------------------------------------


def test_byte_boundary_adapter_in_records_mode(
    harness: Harness, writer: ByteEvidenceRecorder
) -> None:
    session = SyntheticCaptureSession(writer, tenant_id="tenant", run_id="run")
    assert session.mode == "records"
    model = ByteBoundaryAdapter(session, kind="model", source_id="model-1")
    marker = object()
    assert model.call(b'{"m":1}', lambda d: marker, operation_id="m", attempt_id="1",
                      context=b"ctx") is marker  # fmt: skip
    records = harness.spooled()
    found = [_attrs(r) for r in records]
    assert [f.get("fabric.step.lifecycle_state") for f in found] == [
        "running", "running", "running", "completed"]  # fmt: skip
    assert {f["fabric.step.kind"] for f in found} == {"model_call"}
    assert {f["fabric.capture.point"].split("@")[0] for f in found} == {"explicit.byte_boundary"}
    assert len({f["fabric.attempt.uid"] for f in found}) == 1
    assert {f["fabric.step.id"] for f in found} == {label_pseudonym("lbl-", "m", KEY)}
    assert {f["fabric.step.attempt_id"] for f in found} == {label_pseudonym("lbl-", "1", KEY)}
    assert found[-1]["fabric.step.status"] == "ok"
    staged = [[(d["role"], d["status"], d.get("status_reason")) for d, _ in r["staged"]]
              for r in records]  # fmt: skip
    assert staged == [
        [("interaction.payload", "stored", None)],
        [("model.request.messages", "stored", None)],
        [("model.output.messages", "unsupported", "not_exact_bytes")],
        [],
    ]
    view = session.snapshot()
    assert view["capture_mode"] == "records"
    assert [e["status"] for e in view["events"]] == ["settled", "settled", "unsupported"]


def test_terminal_and_artifact_adapters_in_records_mode(
    harness: Harness, writer: ByteEvidenceRecorder, tmp_path: Path
) -> None:
    session = SyntheticCaptureSession(writer, tenant_id="tenant", run_id="run")
    root = tmp_path / "work"
    root.mkdir()
    observer = AllowlistedArtifactObserver(session, root=str(root), relative_paths=["out.txt"])
    observer.observe(phase="before", operation_id="job", attempt_id="1")
    terminal = BoundedTerminalAdapter(session, allowed_cwd_root=str(root))
    result = terminal.run(
        [sys.executable, "-c", "open('out.txt','w').write('hi'); print('done')"],
        cwd=str(root), stdin=b"", operation_id="job", attempt_id="1",
    )  # fmt: skip
    assert result.returncode == 0
    assert observer.observe(phase="after", operation_id="job", attempt_id="1") == {
        "out.txt": True}  # fmt: skip
    records = harness.spooled()
    found = [_attrs(r) for r in records]
    assert {f["fabric.step.kind"] for f in found} == {"terminal"}
    assert {f["fabric.capture.point"].split("@")[0] for f in found} == {
        "explicit.subprocess_artifact"}  # fmt: skip
    # one attempt per adapter source (terminal-1, artifact-1) of the (operation, attempt)
    assert len({f["fabric.attempt.uid"] for f in found}) == 2
    bodies = {d["role"]: (d, bytes(b)) for r in records for d, b in r["staged"]}
    argv, argv_bytes = bodies["terminal.argv"]
    assert argv["media_type"] == "application/json"
    assert json.loads(argv_bytes)[0] == sys.executable
    assert bodies["terminal.stdout"][1] == b"done\n"
    after, after_bytes = bodies["artifact.after"]
    assert (after["boundary"], after_bytes) == ("host", b"hi")
    ends = [f for f in found if f.get("fabric.step.lifecycle_state") == "completed"]
    assert len(ends) == 1 and ends[0]["fabric.step.status"] == "unknown"  # never inferred ok
    view = session.snapshot()
    outcomes = view["operations"]
    assert [o["outcome"].get("artifact_present") for o in outcomes] == [False, None, True]
    assert all("object_id" not in o["outcome"] for o in outcomes)
    assert all(o["status"] == "recorded" for o in outcomes)


def test_session_gaps_are_records_with_descriptor_only_bodies(
    harness: Harness, writer: ByteEvidenceRecorder
) -> None:
    session = SyntheticCaptureSession(writer, tenant_id="tenant", run_id="run")
    gaps = (("unsupported", "not_exact_bytes"), ("truncated", "output_capture_limit"),
            ("failed", "stream_drain_timeout"))  # fmt: skip
    for status, reason in gaps:
        session.gap(source_id="terminal-1", boundary="terminal", role="terminal.stdout",
                    operation_id="op", attempt_id="1", status=status, reason=reason)  # fmt: skip
    session.outcome(source_id="terminal-1", operation_id="op", attempt_id="1",
                    boundary="terminal", returncode=0, timed_out=True)  # fmt: skip
    session.outcome(source_id="terminal-1", operation_id="op", attempt_id="1",
                    boundary="terminal", result_status="ok")  # fmt: skip
    records = harness.spooled()
    staged = [[(d["status"], d.get("status_reason")) for d, _ in r["staged"]] for r in records]
    assert staged == [[("unsupported", "not_exact_bytes")],
                      [("not_captured", "payload_too_large")], [], [], []]  # fmt: skip
    found = [_attrs(r) for r in records]
    assert [f.get("fabric.step.lifecycle_state") for f in found] == [
        "running", "running", "running", "cancelled", None]  # fmt: skip
    assert found[3]["fabric.step.status"] == "timeout"
    assert "fabric.step.status" not in found[4]  # an outcome after the end: update
    with pytest.raises(ValueError, match="incomplete evidence state"):
        session.gap(source_id="t", boundary="terminal", role="terminal.stdout",
                    operation_id="op", attempt_id="1", status="stored", reason="x")  # fmt: skip


def test_journal_mode_session_is_unchanged(writer: ByteEvidenceRecorder, tmp_path: Path,
                                           harness: Harness) -> None:  # fmt: skip
    spool = _spool(tmp_path)
    try:
        session = SyntheticCaptureSession(writer, tenant_id="tenant", run_id="run",
                                          source_spool=spool)  # fmt: skip
        assert session.mode == "journal"
        descriptor = session.capture(b"{}", source_id="s", boundary="tool",
                                     role="tool.call.result", operation_id="op",
                                     attempt_id="1")  # fmt: skip
        assert descriptor["object_id"]
        assert "capture_mode" not in session.snapshot()
    finally:
        spool.close()
    assert harness.spooled() == []  # nothing on the records input
