# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 050 §3 shared types (WP-01): the fail-open/strict rule (R9), the phase table and
three status inputs (R4), body and record bounds (R5, R6), the evidence carrier (R7) and
typed markers (R2), plus the vocabularies pinned to the coverage registry."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, get_args

import pytest

from fabric import _capture_types as ct
from fabric._capture_types import (
    COUNTERS,
    EVIDENCE_MAX_DEPTH,
    EVIDENCE_MAX_ITEMS,
    EVIDENCE_MAX_STRING,
    MAX_RECORD_BODIES,
    DescriptorOnlyBody,
    EvidenceContinuation,
    EvidenceDoc,
    EvidenceRef,
    Marker,
    RecordBody,
    RecordJob,
    RecordsMisuseError,
    SealInfo,
    fail_open,
    misuse,
    resolve_status_inputs,
)

REGISTRY = Path(__file__).resolve().parents[3] / "contracts/coverage/v1/registry"
CAPTURE_SCHEMAS = Path(__file__).resolve().parents[3] / "contracts/capture/v1/schema"
SEG = "seg-" + "a" * 32
BR = "br-" + "b" * 32
TEST_TYPE = "fabric.test.items/v1"


@pytest.fixture(autouse=True)
def _counters(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(ct.STRICT_ENV, raising=False)
    COUNTERS.reset()
    yield
    COUNTERS.reset()


# --- fail-open / strict (R9) ---------------------------------------------------------------


@fail_open(None)
def _api(behaviour: str) -> str | None:
    if behaviour == "misuse":
        raise RecordsMisuseError("records API misuse: test")
    if behaviour == "bug":
        raise KeyError("internal")
    if behaviour == "interrupt":
        raise KeyboardInterrupt
    if behaviour == "cancel":
        raise asyncio.CancelledError
    return "ok"


def test_fail_open_returns_the_value_on_success() -> None:
    assert _api("fine") == "ok"
    assert COUNTERS.snapshot() == {"api_misuse": 0, "internal_errors": 0}
    assert _api.__name__ == "_api"  # functools.wraps


def test_fail_open_never_raises_into_the_app_and_counts() -> None:
    assert _api("misuse") is None
    assert _api("bug") is None
    assert _api("bug") is None
    assert COUNTERS.snapshot() == {"api_misuse": 1, "internal_errors": 2}


@pytest.mark.parametrize("value", ["0", "", "true", "yes", " 1"])
def test_only_exactly_one_is_strict(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(ct.STRICT_ENV, value)
    assert not ct.strict()
    assert _api("misuse") is None


def test_strict_mode_raises_misuse_as_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ct.STRICT_ENV, "1")
    with pytest.raises(ValueError, match="records API misuse"):
        _api("misuse")
    with pytest.raises(KeyError):
        _api("bug")
    assert COUNTERS.snapshot() == {"api_misuse": 1, "internal_errors": 1}


@pytest.mark.parametrize("strict", [False, True])
def test_base_exceptions_always_propagate(monkeypatch: pytest.MonkeyPatch, strict: bool) -> None:
    if strict:
        monkeypatch.setenv(ct.STRICT_ENV, "1")
    with pytest.raises(KeyboardInterrupt):
        _api("interrupt")
    with pytest.raises(asyncio.CancelledError):
        _api("cancel")
    assert COUNTERS.snapshot() == {"api_misuse": 0, "internal_errors": 0}


def test_fail_open_keeps_a_typed_default_on_methods() -> None:
    class Api:
        @fail_open(())
        def tokens(self, n: int) -> tuple[str, ...]:
            if n < 1:
                raise RecordsMisuseError("records API misuse: n")
            return ("t",) * n

    assert Api().tokens(2) == ("t", "t")
    assert Api().tokens(0) == ()


def test_misuse_counts_and_raises_only_in_strict(monkeypatch: pytest.MonkeyPatch) -> None:
    misuse("lifecycle on update")
    assert COUNTERS.api_misuse == 1
    monkeypatch.setenv(ct.STRICT_ENV, "1")
    with pytest.raises(RecordsMisuseError):
        misuse("lifecycle on update")
    assert COUNTERS.api_misuse == 2


# --- the phase table and the three status inputs (R4) --------------------------------------


def test_phase_table_covers_every_phase_including_update() -> None:
    assert set(ct.PHASE_TABLE) == set(get_args(ct.Phase)) == {"start", "data", "update", "end"}
    update = ct.PHASE_TABLE["update"]
    assert update.lifecycles == frozenset()
    assert update.default_lifecycle is None
    assert not update.result_allowed
    assert update.otlp_must_be_unset


@pytest.mark.parametrize(
    ("phase", "expected"),
    [
        ("start", ("running", None, "unset")),
        ("data", ("running", None, "unset")),
        ("update", (None, None, "unset")),
        ("end", ("completed", "unknown", "unset")),
    ],
)
def test_phase_defaults(phase: Any, expected: tuple[Any, ...]) -> None:
    got = resolve_status_inputs(phase)
    assert (got.lifecycle, got.result_status, got.otlp_status) == expected
    assert got.dropped == ()


def test_end_never_infers_ok_and_the_three_inputs_stay_independent() -> None:
    got = resolve_status_inputs("end", result_status="error")
    assert (got.lifecycle, got.result_status, got.otlp_status) == ("completed", "error", "unset")
    got = resolve_status_inputs("end", "cancelled", "cancelled", "error")
    assert (got.lifecycle, got.result_status, got.otlp_status) == (
        "cancelled",
        "cancelled",
        "error",
    )
    got = resolve_status_inputs("end", "deferred")
    assert (got.lifecycle, got.result_status) == ("deferred", "unknown")


@pytest.mark.parametrize(
    ("phase", "kwargs", "dropped", "kept"),
    [
        ("start", {"lifecycle": "queued"}, (), ("queued", None, "unset")),
        ("start", {"lifecycle": "completed"}, ("lifecycle",), ("running", None, "unset")),
        ("start", {"result_status": "ok"}, ("result_status",), ("running", None, "unset")),
        ("data", {"lifecycle": "queued"}, ("lifecycle",), ("running", None, "unset")),
        ("data", {"lifecycle": "suspended", "otlp_status": "ok"}, (), ("suspended", None, "ok")),
        ("update", {"lifecycle": "running"}, ("lifecycle",), (None, None, "unset")),
        ("update", {"result_status": "ok"}, ("result_status",), (None, None, "unset")),
        ("update", {"otlp_status": "error"}, ("otlp_status",), (None, None, "unset")),
        ("end", {"lifecycle": "running"}, ("lifecycle",), ("completed", "unknown", "unset")),
        ("end", {"result_status": "maybe"}, ("result_status",), ("completed", "unknown", "unset")),
        ("end", {"otlp_status": "fine"}, ("otlp_status",), ("completed", "unknown", "unset")),
    ],
)
def test_values_outside_the_table_are_dropped_not_fatal(
    phase: Any, kwargs: dict[str, Any], dropped: tuple[str, ...], kept: tuple[Any, ...]
) -> None:
    got = resolve_status_inputs(phase, **kwargs)
    assert got.dropped == dropped
    assert (got.lifecycle, got.result_status, got.otlp_status) == kept


@pytest.mark.parametrize("phase", ["stop", None, 3])
def test_an_unknown_phase_is_misuse(phase: Any) -> None:
    with pytest.raises(RecordsMisuseError):
        resolve_status_inputs(phase)


# --- bodies (R5, R9) -----------------------------------------------------------------------


def _body(**overrides: Any) -> RecordBody:
    fields: dict[str, Any] = {
        "role": "tool.input", "data": b"{}", "media_type": "application/json",
        "boundary": "caller",
    }  # fmt: skip
    return RecordBody(**(fields | overrides))


def test_record_body_takes_bytes_or_str_by_reference() -> None:
    data = "héllo"
    body = _body(data=data)
    assert body.data is data
    assert body.inflight_charge == len(data) * 4  # UTF-8 upper bound until encoded
    assert _body(data=b"abc").inflight_charge == 3
    assert _body(data=b"").data == b""  # a zero-byte object, never a failure marker


@pytest.mark.parametrize("data", [bytearray(b"x"), memoryview(b"x"), 3, None, ["x"]])
def test_mutable_or_non_bytes_body_data_is_misuse(data: Any) -> None:
    with pytest.raises(RecordsMisuseError):
        _body(data=data)


@pytest.mark.parametrize(
    "overrides",
    [
        {"role": ""}, {"media_type": None}, {"boundary": 1}, {"content_provenance": "bytes"},
        {"stream_id": ""}, {"chunk_index": -1}, {"chunk_index": True}, {"chunk_index": 1.0},
    ],
)  # fmt: skip
def test_record_body_field_misuse(overrides: dict[str, Any]) -> None:
    with pytest.raises(RecordsMisuseError):
        _body(**overrides)


def test_record_body_is_frozen() -> None:
    body = _body(stream_id="s1", chunk_index=0)
    with pytest.raises(AttributeError):
        body.data = b"changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("reason", "status", "projected"),
    [
        ("payload_too_large", "not_captured", ("not_captured", "body_cap")),
        ("parse_failed", "not_captured", ("not_captured", "parse_failed")),
        ("encoding_failed", "not_captured", ("not_captured", "parse_failed")),
        ("not_exact_bytes", "unsupported", ("unsupported", "unsupported_api")),
    ],
)
def test_descriptor_only_reasons(reason: Any, status: Any, projected: tuple[str, str]) -> None:
    body = DescriptorOnlyBody("tool.input", "application/json", "caller", status, reason, 12)
    assert body.projected == projected
    assert body.inflight_charge == 0
    made = DescriptorOnlyBody.for_reason("tool.input", "application/json", "caller", reason)
    assert (made.status, made.reason, made.observed_byte_length) == (status, reason, None)
    assert (
        set(ct.DESCRIPTOR_PROJECTION) == ct.DESCRIPTOR_REASONS == set(get_args(ct.DescriptorReason))
    )


@pytest.mark.parametrize(
    ("status", "reason", "length"),
    [
        ("unsupported", "payload_too_large", None),  # status contradicts the reason
        ("not_captured", "not_exact_bytes", None),
        ("not_captured", "too_big", None),  # unknown reason
        ("dropped", "parse_failed", None),  # unknown status
        ("not_captured", "parse_failed", -1),
        ("not_captured", "parse_failed", True),
    ],
)
def test_descriptor_only_misuse(status: Any, reason: Any, length: Any) -> None:
    with pytest.raises(RecordsMisuseError):
        DescriptorOnlyBody("tool.input", "application/json", "caller", status, reason, length)
    with pytest.raises(RecordsMisuseError):
        DescriptorOnlyBody.for_reason("tool.input", "a/b", "caller", "too_big")  # type: ignore[arg-type]


# --- record jobs: MAX_RECORD_BODIES (R6) ----------------------------------------------------


def _job(
    bodies: tuple[Any, ...] = (), evidence: EvidenceDoc | None = None, **overrides: Any
) -> RecordJob:
    fields: dict[str, Any] = {
        "source_id": "s-" + "0" * 32, "source_epoch": 7, "source_sequence": 3,
        "segment_id": SEG, "run_id": "r-" + "1" * 32, "scope_id": str(uuid.uuid4()),
        "event_id": str(uuid.uuid4()), "attempt_uid": str(uuid.uuid4()), "name": "tool_call",
        "start_ns": 1, "end_ns": 2, "otlp_status": "unset", "attributes": {},
        "bodies": bodies, "evidence": evidence,
    }  # fmt: skip
    return RecordJob(**(fields | overrides))


def _evidence() -> EvidenceDoc:
    built = EvidenceDoc.build(TEST_TYPE, [{"n": 1}])
    assert isinstance(built, EvidenceDoc)
    return built


def test_max_record_bodies_is_eight_including_the_evidence_object() -> None:
    assert MAX_RECORD_BODIES == 8
    _job(tuple(_body() for _ in range(8)))
    _job(tuple(_body() for _ in range(7)), _evidence())
    with pytest.raises(RecordsMisuseError):
        _job(tuple(_body() for _ in range(9)))
    with pytest.raises(RecordsMisuseError):
        _job(tuple(_body() for _ in range(8)), _evidence())


def test_descriptor_only_bodies_count_toward_the_bound() -> None:
    gone = DescriptorOnlyBody.for_reason("tool.input", "application/json", "caller", "parse_failed")
    job = _job((_body(data="abc"), gone))
    assert job.inflight_charge == 12
    with pytest.raises(RecordsMisuseError):
        _job(tuple(gone for _ in range(9)))


def test_one_evidence_object_per_record() -> None:
    over = DescriptorOnlyBody.for_reason(
        ct.EVIDENCE_ROLE, ct.EVIDENCE_MEDIA_TYPE, "caller", "payload_too_large"
    )
    _job((over,))
    with pytest.raises(RecordsMisuseError):
        _job((over,), _evidence())
    with pytest.raises(RecordsMisuseError):
        _job((over, over))


def test_record_job_provenance_and_status() -> None:
    protocol = _body(content_provenance="protocol")
    _job((protocol,), provenance="observed")
    with pytest.raises(RecordsMisuseError):
        _job((protocol,))  # protocol content on a reported attempt
    with pytest.raises(RecordsMisuseError):
        _job(otlp_status="failed")
    with pytest.raises(RecordsMisuseError):
        _job(provenance="hooked")


# --- the evidence carrier (§3.4a) -----------------------------------------------------------


def _nested(depth: int) -> dict[str, Any]:
    item: dict[str, Any] = {"leaf": 1}
    for _ in range(depth - 1):
        item = {"child": item}
    return item


def test_evidence_within_bounds_is_built() -> None:
    ref = EvidenceRef(str(uuid.uuid4()), "tool.input", "/0", (0, 4))
    doc = EvidenceDoc.build(
        TEST_TYPE, [{"a": 1, "b": True, "c": None, "d": "x" * EVIDENCE_MAX_STRING,
                     "e": [1, 2], "f": _nested(EVIDENCE_MAX_DEPTH - 1)}],
        refs=[ref], continuation=EvidenceContinuation(0, final=True),
    )  # fmt: skip
    assert isinstance(doc, EvidenceDoc)
    assert doc.refs == (ref,)
    assert EvidenceDoc.build(TEST_TYPE, []) == EvidenceDoc(TEST_TYPE, ())


@pytest.mark.parametrize(
    "items",
    [
        [{"n": i} for i in range(EVIDENCE_MAX_ITEMS + 1)],
        [_nested(EVIDENCE_MAX_DEPTH + 1)],
        [{"list": [[[[1]]]]}],
        [{"s": "x" * (EVIDENCE_MAX_STRING + 1)}],
        [{"k" * (EVIDENCE_MAX_STRING + 1): 1}],
        [{"many": list(range(EVIDENCE_MAX_ITEMS + 1))}],
        [{"wide": {f"k{i}": i for i in range(EVIDENCE_MAX_ITEMS + 1)}}],
    ],
)
def test_evidence_over_a_bound_becomes_a_descriptor_only_body(items: list[Any]) -> None:
    got = EvidenceDoc.build(TEST_TYPE, items, boundary="tool_bound")
    assert isinstance(got, DescriptorOnlyBody)
    assert (got.role, got.media_type, got.boundary) == (
        ct.EVIDENCE_ROLE, ct.EVIDENCE_MEDIA_TYPE, "tool_bound")  # fmt: skip
    assert (got.status, got.reason) == ("not_captured", "payload_too_large")


@pytest.mark.parametrize(
    ("evidence_type", "items", "kwargs"),
    [
        ("fabric.unknown/v1", [{}], {}),  # not registered
        ("Fabric Test", [{}], {}),  # not a type id
        (TEST_TYPE, [{"f": 1.5}], {}),  # no floats
        (TEST_TYPE, [{"b": b"x"}], {}),  # no bytes
        (TEST_TYPE, [{"o": object()}], {}),
        (TEST_TYPE, [{1: "x"}], {}),  # string keys only
        (TEST_TYPE, [{"": "x"}], {}),
        (TEST_TYPE, [{"i": 1 << 63}], {}),
        (TEST_TYPE, ["not an object"], {}),
        (TEST_TYPE, [{}], {"refs": [EvidenceRef("not-a-uuid", "tool.input")]}),
        (TEST_TYPE, [{}], {"refs": [EvidenceRef(str(uuid.uuid4()), "r", byte_range=(5, 1))]}),
        (TEST_TYPE, [{}], {"refs": ["x"]}),
        (TEST_TYPE, [{}], {"continuation": EvidenceContinuation(-1, final=False)}),
        (TEST_TYPE, [{}], {"continuation": EvidenceContinuation(0, final=1)}),  # type: ignore[arg-type]
    ],
)
def test_malformed_evidence_is_misuse(
    evidence_type: str, items: list[Any], kwargs: dict[str, Any]
) -> None:
    with pytest.raises(RecordsMisuseError):
        EvidenceDoc.build(evidence_type, items, **kwargs)


# --- typed markers (§3.5, R2) ---------------------------------------------------------------


def _marker(kind: Any = "periodic", **fields: Any) -> Marker:
    return Marker(kind, "s-" + "0" * 32, 5, 9, **fields)


def test_marker_event_id_is_a_uuid4_minted_once() -> None:
    first, second = _marker(), _marker()
    assert ct.UUID4_RE.fullmatch(first.event_id)
    assert first.event_id != second.event_id
    pinned = _marker(event_id=first.event_id)
    assert pinned.event_id == first.event_id  # read back from the spool or ledger
    with pytest.raises(ValueError, match="uuid4"):
        _marker(event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, "x")))


def test_marker_placement_rules() -> None:
    seal = SealInfo(9, None, "sha256:" + "0" * 64, (BR,))
    _marker("segment_seal", segment_id=SEG, seal=seal, terminal=True)
    _marker("manifest", manifest={"fabric.capture.manifest_seq": 0}, manifest_seq=0)
    _marker("run_end", run_id="r-x", scope_id="s", outcome="completed", stop_reason="goal_reached")
    _marker("run_start", predecessors=("none",), session_id="sess-1", user_id="usr-1",
            parent_run_id="r-p", resumed_from="r-q", links=("r-l",), id_basis="minted",
            identity={"fabric.agent_id": "agt-1"}, declared_branches=(SEG,),
            branch_ids=(BR,))  # fmt: skip
    bad: list[tuple[Any, dict[str, Any]]] = [
        ("final", {"seal": seal}),
        ("segment_seal", {}),
        ("periodic", {"manifest": {}}),
        ("manifest", {}),
        ("run_start", {"outcome": "completed"}),
        ("run_end", {"outcome": "won"}),
        ("run_end", {"stop_reason": "bored"}),
        ("run_start", {"predecessors": ("seg-x",), "session_id": "sess-1"}),
        ("run_end", {"links": ("r-l",)}),
        ("run_start", {"predecessors": ("none",), "links": tuple(f"r-{i}" for i in range(17))}),
        ("run_end", {"id_basis": "minted"}),
        ("run_start", {"id_basis": "guess"}),
        ("run_end", {"scope_status": "fine"}),
        ("run_start", {"segment_id": "seg-short"}),
        ("run_start", {"branch_ids": ("br-x",)}),
        ("run_start", {"branch_ids": (SEG,)}),  # branch ids are br- ids
        ("run_start", {"declared_branches": (BR,)}),  # fork children are seg- ids
        ("heartbeat", {}),
    ]
    for kind, fields in bad:
        with pytest.raises(ValueError):
            _marker(kind, **fields)


def test_marker_branch_lists_follow_the_contract_patterns_and_bounds() -> None:
    """X46 (loss-record-v1, spool-record-v1): ``declared_branches`` names fork children by
    segment id and ``branch_ids`` names token branches; each holds at most 64."""
    schema = json.loads((CAPTURE_SCHEMAS / "loss-record-v1.schema.json").read_text("utf-8"))
    (props,) = [b["properties"] for b in schema["oneOf"] if "heartbeat_kind" in b["properties"]]
    for name, pattern in (("declared_branches", ct.SEGMENT_ID_RE),
                          ("branch_ids", ct.BRANCH_ID_RE)):  # fmt: skip
        items = props[name]["items"]
        assert (items["pattern"], props[name]["maxItems"]) == (pattern.pattern, ct.MAX_BRANCHES)
    full = tuple(f"seg-{i:032x}" for i in range(64))
    branches = tuple(f"br-{i:032x}" for i in range(64))
    marker = _marker("run_start", predecessors=("none",), declared_branches=full,
                     branch_ids=branches)  # fmt: skip
    assert (marker.declared_branches, marker.branch_ids) == (full, branches)
    with pytest.raises(ValueError, match="declared_branches"):
        _marker("run_start", predecessors=("none",), declared_branches=(*full, "seg-" + "f" * 32))
    with pytest.raises(ValueError, match="branch_ids"):
        _marker("run_start", predecessors=("none",), branch_ids=(*branches, "br-" + "f" * 32))


def test_marker_bridges_the_legacy_beat() -> None:
    for beat in [
        ("s-a", 5, 9, None, None, "periodic"),
        ("s-a", 5, 9, "r-1", "scope-1", "run_start"),
        ("s-a", 5, 9, "r-1", "scope-1", "run_end"),
        ("s-a", 5, -1, None, None, "final"),
    ]:
        assert Marker.from_beat(beat).to_beat() == beat
    assert Marker.from_beat(("s-a", 5, 9, "r-1", "scope-1", "periodic")).run_id is None
    seal = SealInfo(9, None, "sha256:" + "0" * 64)
    assert _marker("segment_seal", segment_id=SEG, seal=seal).to_beat() is None
    with pytest.raises(ValueError, match="legacy"):
        Marker.from_beat(("s-a", 5, 9, None, None, "segment_seal"))


# --- the allocation, run-table and accumulator no-ops ----------------------------------------


def test_null_run_table_and_accumulator_do_nothing() -> None:
    table, seals = ct.NullRunTable(), ct.NullSealAccumulator()
    allocation = ct.Allocation(5, 0, None)
    assert (allocation.segment_id, allocation.manifest_seq) == (None, None)
    assert table.on_allocate(allocation) is None
    assert table.get("r-1") is None
    table.on_block_enter(None)  # type: ignore[arg-type]
    table.on_block_exit(None)  # type: ignore[arg-type]
    table.on_final()
    seals.note_allocated(SEG, 0)
    seals.settle(SEG, 0, "loss:queue_full")
    seals.request_seal(SEG, last_sequence=0, manifest_digest=None, terminal=True, resumable=False)
    assert seals.outstanding(SEG) == 0
    ct.settle_noop(None, 0, "loss:shutdown")
    entry = ct.RunEntry("r-1", "r-1", "minted")
    assert (entry.open_segment, entry.sealed, entry.depth) == (None, [], 0)
    sealed = ct.SealedSegment(SEG, 9, None, terminal=False, resumable=True)
    assert sealed.branch_ids == ()


# --- vocabularies pinned to the coverage registry (placeholders WP-00 replaces) ---------------


def _vocabulary(name: str) -> set[str]:
    doc = json.loads((REGISTRY / "vocabularies-v1.json").read_text(encoding="utf-8"))
    return {row["value"] for row in doc[name]}


def _key_enum(key: str) -> set[str]:
    doc = json.loads((REGISTRY / "telemetry-keys-v1.json").read_text(encoding="utf-8"))
    return {set_ for row in doc["keys"] if row["key"] == key for set_ in row["check"]["values"]}


def test_vocabularies_match_the_registry() -> None:
    assert _vocabulary("step_kind") | {"agent_turn"} == ct.STEP_KINDS  # agent_turn: §4.1
    assert _vocabulary("lifecycle_state") == ct.LIFECYCLES
    assert _vocabulary("result_status") == ct.RESULT_STATUSES
    assert _key_enum("fabric.run.outcome") == ct.RUN_OUTCOMES
    assert _key_enum("fabric.run.stop_reason") == ct.STOP_REASONS
    assert _key_enum("fabric.run.scope_status") == ct.SCOPE_STATUSES
    assert set(get_args(ct.CaptureInput)) == _key_enum("fabric.capture.input")
    legacy_kinds = _key_enum("fabric.heartbeat.kind")
    assert legacy_kinds <= ct.MARKER_KINDS
    assert ct.MARKER_KINDS - legacy_kinds == {"manifest"}
