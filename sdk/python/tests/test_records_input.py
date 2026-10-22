# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 050 §3.4 (WP-11a): the records input. Rule A and rule N against the WP-00 vectors,
the R4 phase table, R9 strict versus fail-open, the identity rule (R8), descriptor-only
and string bodies, the in-flight charge, PROTECT on the spool path (the real WP-11b sender
and spool), delivery from that spool, content provenance end to end, the provider path
(sampled out, D3 refusal) and the passivity of ``emit``."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_OFF
from opentelemetry.trace import StatusCode

import fabric._loss
from fabric import _capture_types as ct
from fabric._capture_types import (
    COUNTERS,
    DescriptorOnlyBody,
    EvidenceDoc,
    RecordBody,
    RecordJob,
    RecordsMisuseError,
    SpanIds,
)
from fabric._records import (
    RecordsInput,
    category,
    compile_check,
    compile_checks,
    project_attributes,
    records_max_object_bytes,
)
from fabric._records_keys_generated import RECORD_KEY_CHECKS
from fabric._seal import record_digest
from fabric._sequence import V2_TYPES, EmittedId, pseudonym_v2
from fabric._version import __version__
from fabric.wire._policy import CapturePolicy, ContentGate
from fabric.wire._protect import Protector

from ._records_harness import (
    SEG_A,
    SOURCE,
    Handle,
    alternating,
    coverage_validator,
    reference,
    vector,
)

KEY = b"k" * 32
JSON = "application/json"


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    monkeypatch.setenv(ct.STRICT_ENV, "1")
    COUNTERS.reset()
    yield
    COUNTERS.reset()


@pytest.fixture()
def handle() -> Iterator[Handle]:
    made = Handle(segments=alternating(SEG_A))
    yield made
    made.close()


def _provider(sampler: Any = None) -> tuple[TracerProvider, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(sampler=sampler) if sampler is not None else TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


def _emit(attempt: Any, phase: str = "end", **kwargs: Any) -> bool:
    fields: dict[str, Any] = {"name_hint": "fabric.tool_call", "attributes": {},
                              "start_ns": 10, "end_ns": 20}  # fmt: skip
    return bool(attempt.emit(phase, **(fields | kwargs)))


def _items(handle: Handle) -> list[tuple[dict[str, Any], list[tuple[dict[str, Any], bytes]]]]:
    handle.flush()
    return [(span, staged) for _, _, span, staged in handle.sender.items]  # type: ignore[union-attr]


# --- rule A, rule N (vectors) -----------------------------------------------------------------


@pytest.mark.parametrize("case", vector("records-span-v1.json")["cases"], ids=lambda c: c["name"])
def test_rule_a_matches_the_records_span_vectors(case: dict[str, Any]) -> None:
    checks = compile_checks(labels=case["capture_labels"], identity=case["identity_mode"])
    kept, dropped = project_attributes(case["attributes"], checks)
    assert kept == case["admitted"]
    assert dropped == sorted(case["dropped"])


def test_rule_a_table_is_the_vector_table() -> None:
    assert sorted(RECORD_KEY_CHECKS) == vector("records-span-v1.json")["keys"]


@pytest.mark.parametrize("labels", ["pseudonymous", "clear"])
@pytest.mark.parametrize("identity", ["pseudonymous", "clear"])
def test_rule_a_checks_equal_the_registry_check_function(labels: str, identity: str) -> None:
    check_value = coverage_validator().check_value
    samples: list[Any] = [None, True, 0, -1, 1 << 63, 3, 2.5, "", "x", "agent", "records",
                          "observed", "r-" + "1" * 32, "s-" + "2" * 32, "billing.prod",
                          "seg-" + "3" * 32, str(uuid.uuid4()), "sdk.records@0.9.0",
                          "source:s-" + "4" * 32 + ":12", "source:clear:12", "h-" + "5" * 40,
                          [str(uuid.uuid4())], [str(uuid.uuid4())] * 2, [], ["x"]]  # fmt: skip
    for key, check in RECORD_KEY_CHECKS.items():
        predicate = compile_check(check, labels=labels, identity=identity)  # type: ignore[arg-type]
        for sample in [*samples, *check.get("examples", ())]:
            value = list(sample) if isinstance(sample, tuple) else sample
            expected = check_value(check, value, labels=labels, identity=identity)
            assert predicate(value) == expected, (key, value)


@pytest.mark.parametrize("case", vector("span-category-v1.json")["cases"], ids=lambda c: c["name"])
def test_rule_n_matches_the_span_category_vectors(case: dict[str, Any]) -> None:
    assert category(case["name_hint"], case["attribute_keys"]) == case["category"]
    assert reference().span_category(case["name_hint"], case["attribute_keys"]) == case["category"]


# --- the phase table (R4) ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("phase", "inputs", "lifecycle", "result", "otlp", "misused"),
    [
        ("start", {}, "running", None, "unset", 0),
        ("start", {"lifecycle": "queued"}, "queued", None, "unset", 0),
        ("start", {"lifecycle": "completed"}, "running", None, "unset", 1),
        ("start", {"result_status": "ok"}, "running", None, "unset", 1),
        ("data", {"lifecycle": "suspended", "otlp_status": "ok"}, "suspended", None, "ok", 0),
        ("update", {}, None, None, "unset", 0),
        ("update", {"lifecycle": "running", "otlp_status": "error"}, None, None, "unset", 2),
        ("end", {}, "completed", "unknown", "unset", 0),
        ("end", {"result_status": "error"}, "completed", "error", "unset", 0),
        ("end", {"lifecycle": "cancelled", "result_status": "cancelled", "otlp_status": "error"},
         "cancelled", "cancelled", "error", 0),
        ("end", {"lifecycle": "running"}, "completed", "unknown", "unset", 1),
    ],
)  # fmt: skip
def test_the_phase_table(
    monkeypatch: pytest.MonkeyPatch, handle: Handle, phase: str, inputs: dict[str, Any],
    lifecycle: str | None, result: str | None, otlp: str, misused: int,
) -> None:  # fmt: skip
    monkeypatch.delenv(ct.STRICT_ENV)
    attempt = handle.input.begin("tool_call", "sdk.records")
    assert _emit(attempt, phase, **inputs)
    [(span, _)] = _items(handle)
    attrs = span["attributes"]
    assert attrs.get("fabric.step.lifecycle_state") == lifecycle
    assert attrs.get("fabric.step.status") == result
    assert span["status"] == otlp
    assert COUNTERS.api_misuse == misused


def test_an_update_after_end_is_emitted(handle: Handle) -> None:
    attempt = handle.input.begin("tool_call", "sdk.records")
    assert _emit(attempt, "end")
    assert _emit(attempt, "update", attributes={"fabric.error.domain": "tool"})
    first, second = _items(handle)
    assert first[0]["attributes"]["fabric.attempt.uid"] == second[0]["attributes"][
        "fabric.attempt.uid"]  # fmt: skip
    assert "fabric.step.lifecycle_state" not in second[0]["attributes"]
    assert second[0]["attributes"]["fabric.error.domain"] == "tool"


# --- the record and its keys ------------------------------------------------------------------


def test_every_record_carries_the_fabric_keys(handle: Handle) -> None:
    attempt = handle.input.begin("tool_call", "sdk.records", step_id="order-42",
                                 parent_attempt=str(uuid.uuid4()))  # fmt: skip
    assert attempt is not None
    assert ct.UUID4_RE.fullmatch(attempt.uid)
    event = str(uuid.uuid4()).upper()
    assert _emit(attempt, attributes={
        "fabric.source.sequence": 99, "fabric.tool.name": "search", "fabric.actor.type": "user",
        "fabric.step.attempt_id": "Jane's attempt", "fabric.score": 0.5,
    }, event_id=event)  # fmt: skip
    [(span, staged)] = _items(handle)
    attrs = span["attributes"]
    assert attrs["fabric.capture.input"] == "records"
    assert attrs["fabric.capture.source"] == "reported"
    assert attrs["fabric.capture.point"] == f"sdk.records@{__version__}"
    assert (attrs["fabric.source_id"], attrs["fabric.source.sequence"]) == (SOURCE, 0)
    assert attrs["fabric.source.epoch"] == handle.allocator.epoch
    assert attrs["fabric.event_id"] == event.lower()
    assert attrs["fabric.attempt.uid"] == attempt.uid
    assert attrs["fabric.run.segment_id"] == SEG_A
    assert attrs["fabric.step.kind"] == "tool_call"
    assert attrs["fabric.actor.type"] == "user"
    assert attrs["fabric.step.id"].startswith("g-")  # mapped without a key, never clear
    assert attrs["fabric.step.attempt_id"].startswith("g-")
    assert "Jane" not in str(span)
    assert "fabric.tool.name" not in attrs  # not a records key
    assert "fabric.run.id" not in attrs  # outside a run
    assert span["name"] == "fabric.tool_call"
    assert staged == []
    assert handle.input.stats.snapshot()["records_keys_dropped"] == 3


def test_a_record_reuses_host_span_ids(handle: Handle) -> None:
    attempt = handle.input.begin("tool_call", "sdk.records")
    ids = SpanIds(trace_id=0xABC, span_id=0xDEF, parent_span_id=0x123, parent_is_remote=True)
    assert _emit(attempt, span_ids=ids)
    [(span, _)] = _items(handle)
    assert (span["trace_id"], span["span_id"]) == (f"{0xABC:032x}", f"{0xDEF:016x}")
    assert (span["parent_span_id"], span["parent_is_remote"]) == (f"{0x123:016x}", True)


# --- identity (R8) ----------------------------------------------------------------------------


def test_v2_and_the_identity_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    keyed = Handle(id_key=KEY)
    records = keyed.input
    mapped = records.v2("sess", "session-1")
    assert mapped == pseudonym_v2("sess", "session-1", KEY)
    assert isinstance(mapped, EmittedId)
    assert records.v2("usr", mapped) is mapped  # an EmittedId of this issuer passes
    assert records.v2("usr", "sess-" + "0" * 32) == pseudonym_v2("usr", "sess-" + "0" * 32, KEY)
    assert records.map_id("op-1").startswith("lbl-")
    keyed.close()
    unkeyed = Handle()
    assert unkeyed.input.v2("act", "a") is None  # no key: omitted
    unkeyed.close()
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "clear")
    clear = Handle(id_key=KEY)
    assert clear.input.v2("sess", "session-1") == "session-1"
    assert clear.input.map_id("op 1").startswith("h-")
    assert clear.input.map_id("op-1") == "op-1"
    clear.close()
    with pytest.raises(RecordsMisuseError):
        RecordsInput().v2("nope", "x")
    assert set(V2_TYPES) >= {"sess", "usr"}


# --- bodies, PROTECT and provenance on the spool path ---------------------------------------


def test_bodies_are_protected_and_named_in_order(handle: Handle) -> None:
    attempt = handle.input.begin("tool_call", "sdk.records")
    evidence = EvidenceDoc.build("fabric.test.items/v1", [{"name": "orders.lookup", "count": 1}],
                                 boundary="tool")  # fmt: skip
    assert isinstance(evidence, EvidenceDoc)
    bodies = [
        RecordBody("tool.call.arguments", '{"q":"é"}', JSON, "tool"),
        RecordBody("tool.call.result", b"", JSON, "tool"),
        DescriptorOnlyBody.for_reason("step.error", "text/plain", "caller", "not_exact_bytes",
                                      observed_byte_length=7),
        RecordBody("tool.call.result", "\ud800", JSON, "tool"),
    ]  # fmt: skip
    assert _emit(attempt, bodies=bodies, evidence=evidence)
    [(span, staged)] = _items(handle)
    descriptors = [d for d, _ in staged]
    assert span["attributes"]["fabric.content.object_ids"] == [d["object_id"] for d in descriptors]
    assert attempt is not None
    args, empty, failed, surrogate, ev = descriptors
    assert (args["status"], args["provenance"], args["boundary"]) == ("stored", "caller_reported",
                                                                       "tool")  # fmt: skip
    assert staged[0][1] == '{"q":"é"}'.encode()
    assert args["attempt_id"] == args["operation_id"] == attempt.uid
    assert (empty["status"], empty["stored_byte_length"]) == ("stored", 0)  # 049 §2.6
    assert (failed["status"], failed["status_reason"]) == ("unsupported", "not_exact_bytes")
    assert failed["representation"] == "unavailable"
    assert "stored_sha256" not in failed
    assert (surrogate["status"], surrogate["status_reason"]) == ("not_captured", "parse_failed")
    assert (ev["role"], ev["status"], ev["boundary"]) == ("record.evidence", "stored", "tool")
    assert reference().evidence_envelope_refusal(staged[4][1], ["fabric.test.items/v1"]) is None
    content = [d.get("stored_sha256") for d in descriptors]
    assert content[2] is None
    entry = record_digest(name=span["name"], start_ns=span["start_time_unix_nano"],
                          end_ns=span["end_time_unix_nano"], status=span["status"],
                          attributes=span["attributes"], content=content)  # fmt: skip
    expected = reference().record_digest(
        name=span["name"], start_ns=span["start_time_unix_nano"],
        end_ns=span["end_time_unix_nano"], status=span["status"],
        attributes=span["attributes"],
        content=reference().record_content("record", descriptors,
                                           span["attributes"]["fabric.content.object_ids"]),
    )  # fmt: skip
    assert entry == expected
    assert handle.budget.used == 0  # the charge is released when the job is done


def test_observed_records_keep_protocol_provenance_end_to_end(handle: Handle) -> None:
    """Astra confirmation fix: the body's own validated ``content_provenance`` is kept
    through PROTECT into the spool record; ``protocol`` survives on observed records (the
    P4/P5 protocol-only roles depend on it), and so does the evidence object's."""
    attempt = handle.input.begin("mcp_call", "sdk.records", provenance="observed")
    evidence = EvidenceDoc.build("fabric.test.items/v1", [{"name": "x", "count": 1}])
    assert isinstance(evidence, EvidenceDoc)
    bodies = [RecordBody("mcp.notification", b'{"jsonrpc":"2.0"}', JSON, "tool", "protocol"),
              RecordBody("mcp.request", b"{}", JSON, "tool", "caller_reported")]  # fmt: skip
    assert _emit(attempt, bodies=bodies, evidence=evidence)
    [(span, staged)] = _items(handle)
    assert span["attributes"]["fabric.capture.source"] == "observed"
    provenance = [(d["role"], d["provenance"], d["status"]) for d, _ in staged]
    assert provenance == [("mcp.notification", "protocol", "stored"),
                          ("mcp.request", "caller_reported", "stored"),
                          ("record.evidence", "protocol", "stored")]  # fmt: skip


def test_a_record_is_delivered_from_the_real_spool_bodies_first(handle: Handle) -> None:
    """050 §3.5 end to end on the WP-11b sender: the record entry passes the spool's header
    check (span status ``ok`` included), its bodies reach the Node in reference order (a
    descriptor-only body as its descriptor with no bytes), then its span is exported as the
    record itself (name, kind, status, ids and attributes as spooled) and the spool empties."""
    attempt = handle.input.begin("tool_call", "sdk.records")
    bodies = [
        RecordBody("tool.call.arguments", b'{"q":1}', JSON, "tool"),
        DescriptorOnlyBody.for_reason("step.error", "text/plain", "caller", "not_exact_bytes",
                                      observed_byte_length=7),
        RecordBody("tool.call.result", b'{"ok":true}', JSON, "tool"),
    ]  # fmt: skip
    assert _emit(attempt, bodies=bodies, otlp_status="ok")
    [(span, staged)] = _items(handle)
    assert span["status"] == "ok"
    sender = handle.sender
    assert sender is not None
    assert sender.deliver()
    assert sender.spool.names() == []
    assert sender.content_log.bodies == staged
    assert [len(data) for _, data in staged] == [7, 0, 11]
    [exported] = [s for s in sender.exported.get_finished_spans() if s.name == span["name"]]
    assert exported.status.status_code is StatusCode.OK
    assert exported.instrumentation_scope is not None
    assert exported.instrumentation_scope.name == "fabric.records"
    assert (f"{exported.context.trace_id:032x}", f"{exported.context.span_id:016x}") == (
        span["trace_id"], span["span_id"])  # fmt: skip
    assert (exported.start_time, exported.end_time) == (
        span["start_time_unix_nano"], span["end_time_unix_nano"])  # fmt: skip
    attributes = dict(exported.attributes or {})
    plain = {k: list(v) if isinstance(v, tuple) else v for k, v in attributes.items()}
    assert plain == span["attributes"]


def test_reported_records_cannot_claim_protocol_provenance(
    monkeypatch: pytest.MonkeyPatch, handle: Handle
) -> None:
    protocol = RecordBody("mcp.notification", b"{}", JSON, "tool", "protocol")
    with pytest.raises(RecordsMisuseError):  # the WP-01 RecordJob check
        RecordJob(SOURCE, 1, 0, None, None, None, str(uuid.uuid4()), str(uuid.uuid4()),
                  "fabric.activity", 0, 0, "unset", {}, bodies=(protocol,))  # fmt: skip
    attempt = handle.input.begin("mcp_call", "sdk.records")
    with pytest.raises(RecordsMisuseError, match="protocol content"):
        _emit(attempt, bodies=[protocol])
    monkeypatch.delenv(ct.STRICT_ENV)
    COUNTERS.reset()
    assert _emit(attempt, bodies=[protocol, RecordBody("mcp.request", b"{}", JSON, "tool")])
    [(span, staged)] = _items(handle)
    assert [(d["role"], d["provenance"]) for d, _ in staged] == [("mcp.request",
                                                                   "caller_reported")]  # fmt: skip
    assert span["attributes"]["fabric.capture.source"] == "reported"
    assert COUNTERS.api_misuse == 1


def test_object_cap_and_privacy_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FABRIC_RECORDS_MAX_OBJECT_BYTES", "4")
    policy = CapturePolicy("acme", 3, "sha256:" + "3" * 64,
                           {"tool.call.arguments": "metadata_only",
                            "tool.call.result": "retain_original",
                            "record.evidence": "metadata_only"})  # fmt: skip
    gate = ContentGate("production", "enabled", None, policy)
    handle = Handle(gate=gate, protector=Protector(policy, max_body_bytes=1 << 20))
    records = handle.input
    assert records.mode_of("tool.call.arguments") == "metadata_only"
    assert records.mode_of("tool.call.result") == "retain_original"
    assert records.mode_of("record.evidence") == "metadata_only"
    assert records.mode_of("step.error") == "omit"  # not named by a configured policy
    assert records.mode_of("no.such.role") == "omit"
    attempt = records.begin("tool_call", "sdk.records")
    evidence = EvidenceDoc.build("fabric.test.items/v1", [{"name": "x", "count": 1}])
    assert _emit(attempt, evidence=evidence, bodies=[
        RecordBody("tool.call.arguments", b"{}", JSON, "caller"),
        RecordBody("tool.call.result", b"12345", JSON, "caller"),
        RecordBody("step.error", b"boom", "text/plain", "caller"),
    ])  # fmt: skip
    [(_, staged)] = _items(handle)
    summary = [(d["role"], d["status"], d.get("status_reason"), d["privacy_mode"])
               for d, _ in staged]  # fmt: skip
    assert summary == [
        ("tool.call.arguments", "not_captured", "privacy_policy", "metadata_only"),
        ("tool.call.result", "not_captured", "payload_too_large", "retain_original"),
        ("record.evidence", "not_captured", "payload_too_large", "metadata_only"),
    ]
    handle.close()
    with pytest.raises(ValueError, match="between 1 and 16777216"):
        records_max_object_bytes({"FABRIC_RECORDS_MAX_OBJECT_BYTES": "x"})


def test_no_destination_writes_no_objects() -> None:
    provider, exporter = _provider()
    handle = Handle(node=False, provider=provider)
    assert handle.input.mode_of("tool.call.result") == "omit"
    attempt = handle.input.begin("tool_call", "sdk.records")
    evidence = EvidenceDoc.build("fabric.test.items/v1", [])
    assert _emit(attempt, bodies=[RecordBody("tool.call.result", b"{}", JSON, "caller")],
                 evidence=evidence)  # fmt: skip
    handle.flush()
    [span] = exporter.get_finished_spans()
    assert "fabric.content.object_ids" not in (span.attributes or {})
    handle.close()


# --- the in-flight charge ---------------------------------------------------------------------


def test_bodies_over_the_inflight_budget_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    handle = Handle(budget=10)
    release, original = threading.Event(), handle.pipeline._prepare_record

    def held(job: Any) -> Any:
        release.wait(5.0)
        return original(job)

    handle.pipeline._prepare_record = held  # type: ignore[method-assign]
    attempt = handle.input.begin("tool_call", "sdk.records")
    assert _emit(attempt, bodies=[RecordBody("tool.call.result", "ab", JSON, "caller")])
    assert handle.budget.used == 8  # str: len * 4 until the worker encodes it
    assert _emit(attempt, bodies=[RecordBody("tool.call.result", b"abcd", JSON, "caller")])
    assert handle.budget.used == 8  # over the budget: refused, nothing charged
    release.set()
    items = _items(handle)
    assert handle.budget.used == 0
    assert items[1][1][0][0]["status_reason"] == "inflight_budget"
    assert items[1][1][0][1] == b""
    assert handle.input.stats.snapshot()["records_budget_refused"] == 1
    handle.close()


# --- fail-open and strict (R9) ----------------------------------------------------------------


def test_misuse_fails_open_and_raises_under_strict(
    monkeypatch: pytest.MonkeyPatch, handle: Handle
) -> None:
    records = handle.input
    with pytest.raises(RecordsMisuseError):
        records.begin("nope", "sdk.records")  # type: ignore[arg-type]
    attempt = records.begin("tool_call", "sdk.records")
    with pytest.raises(RecordsMisuseError):
        _emit(attempt, "finish")
    with pytest.raises(RecordsMisuseError):
        _emit(attempt, start_ns=-1)
    monkeypatch.delenv(ct.STRICT_ENV)
    assert records.begin("tool_call", "Not A Point") is None
    assert records.begin("tool_call", "sdk.records", aliases={"bad": "x"}) is None
    assert records.mode_of(None) == "omit"  # type: ignore[arg-type]
    assert records.v2("sess", "") is None
    assert not _emit(attempt, "finish")
    assert not _emit(attempt, name_hint=None)
    assert not _emit(attempt, attributes=[])
    assert _emit(attempt, start_ns=5, end_ns=1, event_id="not-a-uuid",
                 bodies=[object(), *[RecordBody("tool.call.result", b"{}", JSON, "caller")] * 10],
                 span_ids="x")  # fmt: skip
    assert COUNTERS.api_misuse >= 10
    [(span, staged)] = _items(handle)
    assert span["end_time_unix_nano"] == span["start_time_unix_nano"] == 5
    assert len(staged) == 8
    assert handle.allocator.last_sequence()[1] == 0  # misuse before allocation: no position


def test_an_internal_failure_after_allocation_is_an_internal_error_loss(
    monkeypatch: pytest.MonkeyPatch, handle: Handle
) -> None:
    attempt = handle.input.begin("tool_call", "sdk.records")
    settled: list[tuple[str | None, int, str]] = []
    handle.loss.set_settle(lambda segment, sequence, entry: settled.append(
        (segment, sequence, entry)))  # fmt: skip

    def broken(job: Any) -> bool:
        raise RuntimeError("pipeline bug")

    monkeypatch.setattr(handle.pipeline, "submit", broken)
    with pytest.raises(RuntimeError):
        _emit(attempt)
    monkeypatch.delenv(ct.STRICT_ENV)
    assert not _emit(attempt)
    assert settled == [(SEG_A, 0, "loss:internal_error"), (SEG_A, 1, "loss:internal_error")]
    assert COUNTERS.internal_errors == 2


def test_an_inactive_input_emits_nothing(handle: Handle) -> None:
    attempt = handle.input.begin("tool_call", "sdk.records")
    handle.records = None  # close() detaches the input
    assert not _emit(attempt)
    assert RecordsInput(None).begin("tool_call", "sdk.records") is None
    assert handle.allocator.last_sequence()[1] == -1


# --- the provider path ------------------------------------------------------------------------


def test_provider_path_emits_and_settles_the_record() -> None:
    provider, exporter = _provider()
    handle = Handle(node=False, provider=provider, segments=alternating(SEG_A))
    attempt = handle.input.begin("tool_call", "sdk.records")
    ids = SpanIds(trace_id=0xABC, span_id=0xDEF, parent_span_id=0x123)
    assert _emit(attempt, otlp_status="error", span_ids=ids)
    assert _emit(attempt, otlp_status="ok")
    handle.flush()
    first, second = exporter.get_finished_spans()
    assert (first.context.trace_id, first.context.span_id) == (0xABC, 0xDEF)
    assert first.parent is not None
    assert first.parent.span_id == 0x123
    assert first.status.status_code is StatusCode.ERROR
    assert second.status.status_code is StatusCode.OK
    assert second.context.span_id != 0xDEF  # the override held for one start_span only
    handle.pipeline.seals.request_seal(SEG_A, last_sequence=1, manifest_digest=None,
                                       terminal=True, resumable=False)  # fmt: skip
    [marker] = handle.markers
    entries = []
    for span in (first, second):
        attrs = dict(span.attributes or {})
        status: ct.OtlpStatus = "error" if span.status.status_code is StatusCode.ERROR else "ok"
        assert span.start_time is not None
        assert span.end_time is not None
        digest = record_digest(name=span.name, start_ns=span.start_time, end_ns=span.end_time,
                               status=status, attributes=attrs, content=[])  # fmt: skip
        entries.append((attrs["fabric.source.sequence"], digest))
    assert marker.seal is not None
    assert marker.seal.seal_digest == reference().seal_digest(entries)
    handle.close()


def test_a_sampled_out_record_is_a_span_dropped_loss() -> None:
    provider, exporter = _provider(ALWAYS_OFF)
    handle = Handle(node=False, provider=provider, segments=alternating(SEG_A))
    settled: list[tuple[str | None, int, str]] = []
    handle.loss.set_settle(lambda segment, sequence, entry: settled.append(
        (segment, sequence, entry)))  # fmt: skip
    attempt = handle.input.begin("tool_call", "sdk.records")
    assert _emit(attempt)
    handle.flush()
    assert exporter.get_finished_spans() == ()
    assert settled == [(SEG_A, 0, "loss:span_dropped")]
    handle.close()


def test_a_protected_provider_never_carries_a_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """D3: a provider with a Fabric-protected route (no private fallback) refuses the
    record: a ``span_dropped`` loss, never a projected span."""
    provider, exporter = _provider()
    monkeypatch.setattr(fabric._loss, "has_protected_route", lambda candidate: True)
    handle = Handle(node=False, provider=provider)
    attempt = handle.input.begin("tool_call", "sdk.records")
    assert _emit(attempt)
    handle.flush()
    assert exporter.get_finished_spans() == ()
    assert handle.pipeline.stats()["spans_refused"] == 1
    losses, _ = handle.loss.take(periodic=False)
    assert [key[2] for key, _ in losses] == ["span_dropped"]
    handle.close()


# --- passivity --------------------------------------------------------------------------------


def test_emit_is_passive(monkeypatch: pytest.MonkeyPatch) -> None:
    """``emit`` never waits for the worker or the queue, never encodes a body on the app
    thread, never raises in fail-open mode, and leaves the caller's objects untouched."""
    monkeypatch.delenv(ct.STRICT_ENV)
    handle = Handle(queue_max_items=1)
    release, original = threading.Event(), handle.pipeline._prepare_record
    encoded_on: list[str] = []

    def held(job: Any) -> Any:
        encoded_on.append(threading.current_thread().name)
        release.wait(5.0)
        return original(job)

    handle.pipeline._prepare_record = held  # type: ignore[method-assign]
    attempt = handle.input.begin("tool_call", "sdk.records")
    attributes = {"fabric.actor.type": "agent"}
    body = RecordBody("tool.call.result", "x" * 1000, JSON, "caller")
    started = time.perf_counter()
    outcomes = [_emit(attempt, attributes=attributes, bodies=[body]) for _ in range(50)]
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0  # a blocked worker and a full queue never block the caller
    assert outcomes.count(True) <= 2
    assert attributes == {"fabric.actor.type": "agent"}
    monkeypatch.setattr(handle.pipeline, "charge_record", lambda job: 1 / 0)
    assert not _emit(attempt)  # an internal failure: counted, a loss, never raised
    release.set()
    handle.flush()
    assert set(encoded_on) == {"fabric-wire-capture"}
    assert handle.budget.used == 0
    handle.close()
