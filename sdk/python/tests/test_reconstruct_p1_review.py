# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""P1 review regressions for the verifier (spec 050 §3.12; spec 049 §2.10, §2.12).

- B1: an unsealed segment in the terminal's predecessor closure never lets a run terminate,
  and a segment without a seal is reported whether or not any of its records survived.
- B2: every consumed ``br-`` id is bound to the seal of a predecessor the consumer names
  (049 X46); an id no present, sealed issuer minted is a conflict, a lost or unsealed issuer
  keeps the run from completing.
- E: a records-input object is read and verified (bytes, length, digest, record contract,
  binding to the record) before its seal contribution is accepted or it is projected as
  captured; a deleted or altered body is a gap and the run is never complete.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._capture_types import RecordBody
from fabric.content_store import LocalFilesystemContentStore
from fabric.reconstruct import reconstruct
from fabric.reconstruct._objects import STATUS_REASONS, record_descriptor_ok
from tests.test_capture_integration import JsonlSpanExporter
from tests.test_reconstruct_graph import br, entry, node, one, seal, seg, start, why
from tests.test_reconstruct_project import PCapture, project, status, steps_of
from tests.test_reconstruct_project import field as projected_field
from tests.test_reconstruct_verifier import CAPTURE_ROOT, RUN, Capture, only_run


@pytest.fixture
def capture(tmp_path: Path) -> Capture:
    capture = Capture(tmp_path)
    capture.manifest()
    return capture


def gaps(run: dict[str, Any]) -> list[tuple[str, str | None]]:
    return sorted((g["gap_type"], g.get("reason")) for g in run["gaps"])


# --------------------------------------------------------------------------
# B1: unsealed ancestors
# --------------------------------------------------------------------------


def test_b1_graph_unsealed_empty_ancestor_is_not_terminated() -> None:
    graph = one(
        node(1, last_sequence=None, manifest_digest=None, sealed_ns=None, state="unsealed"),
        node(2, 1, terminal=True),
    )
    assert (graph.rule, graph.run_state) == ("G7", "conflicted")
    assert why(graph) == [("segment_missing", "predecessor_unsealed", seg(1))]


def test_b1_graph_every_ancestor_of_the_closure_is_sealed() -> None:
    """A sealed root, an unsealed middle, a terminal: the middle fails G5."""
    graph = one(
        node(1, resumable=True),
        node(2, 1, last_sequence=None, manifest_digest=None, sealed_ns=None),
        node(3, entry(2, last=41), terminal=True),
    )
    assert graph.run_state == "conflicted"
    assert why(graph) == [("segment_missing", "predecessor_unsealed", seg(2))]


def test_b1_verifier_empty_ancestor_without_its_seal(capture: Capture) -> None:
    """Review repro B1: an empty ancestor whose seal never arrived."""
    first, last = capture.new_segment(), capture.new_segment()
    capture.run_start(RUN, segment_id=first)
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=first, terminal=False)
    predecessor = f"{first}/{capture.source_id}/{capture.epoch}/-1/{capture.manifest_digest}"
    capture.run_start(RUN, segment_id=last, predecessors=(predecessor,), id_basis="token")
    capture.record()
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=last)
    capture.heartbeat()
    capture.rows = [
        row for row in capture.rows
        if not (row["attributes"].get("fabric.heartbeat.kind") == "segment_seal"
                and row["attributes"].get("fabric.run.segment_id") == first)
    ]  # fmt: skip
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert run["run_state"] == "conflicted"
    assert ("unsealed_segment", "source_lost") in gaps(run)
    assert ("segment_missing", "predecessor_unsealed") in gaps(run)
    assert {s["segment_id"]: s["state"] for s in run["segments"]}[first] == "unsealed"


def test_b1_an_empty_segment_without_a_seal_is_reported(capture: Capture) -> None:
    """049 §2.12 rule 3 / X44: a segment is unsealed whether or not any record survived; an
    open run whose empty continuation lost its seal is never complete."""
    first, empty = capture.new_segment(), capture.new_segment()
    start(capture, RUN, first)
    a = seal(capture, RUN, first, extra={"fabric.run.resumable": True})
    start(capture, RUN, empty, a, id_basis="token")
    capture.run_end(RUN)
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["run_state"] == "open"
    assert ("unsealed_segment", "source_lost") in gaps(run)
    assert run["verdict"] == "partial"


# --------------------------------------------------------------------------
# B2: consumed branch ids and their issuers
# --------------------------------------------------------------------------


def test_b2_consumed_branch_needs_an_issuing_predecessor() -> None:
    """Review repro B2: the predecessor issued no branch at all."""
    graph = one(node(1), node(2, 1, branch_ids=(br(99),), terminal=True))
    assert (graph.rule, graph.run_state) == ("G1", "conflicted")
    assert why(graph) == [("segment_conflict", "branch_not_issued", seg(2))]


def test_b2_a_forged_id_beside_the_issued_one_is_a_conflict() -> None:
    graph = one(
        node(1, resumable=True, issued_branch_ids=(br(1),)),
        node(2, 1, branch_ids=(br(1), br(99)), terminal=True),
    )
    assert graph.run_state == "conflicted"
    assert why(graph) == [("segment_conflict", "branch_not_issued", seg(2))]


def test_b2_an_id_issued_by_a_segment_the_consumer_does_not_name() -> None:
    """The id is bound to its issuing seal: another segment of the run does not count."""
    graph = one(
        node(1, resumable=True, issued_branch_ids=(br(1),)),
        node(2, 1, resumable=True),
        node(3, 2, branch_ids=(br(1),), terminal=True),
    )
    assert ("segment_conflict", "branch_not_issued", seg(3)) in why(graph)
    assert graph.run_state == "conflicted"


def test_b2_a_root_never_consumes_a_branch() -> None:
    assert why(one(node(1, branch_ids=(br(1),), terminal=True))) == [
        ("segment_conflict", "branch_not_issued", seg(1))
    ]


def test_b2_a_lost_or_unsealed_issuer_prevents_completeness() -> None:
    lost = one(node(2, 1, branch_ids=(br(1),), terminal=True))
    assert (lost.rule, lost.run_state) == ("G2", "conflicted")
    unsealed = one(
        node(1, last_sequence=None, manifest_digest=None, sealed_ns=None),
        node(2, 1, branch_ids=(br(1),), terminal=True),
    )
    assert unsealed.run_state == "conflicted"
    assert why(unsealed) == [("segment_missing", "predecessor_unsealed", seg(1))]


def test_b2_issued_branches_still_terminate() -> None:
    graph = one(
        node(1, resumable=True, issued_branch_ids=(br(1), br(2))),
        node(2, 1, branch_ids=(br(1),)),
        node(3, 1, branch_ids=(br(2),)),
        node(4, 2, 3, terminal=True),
    )
    assert (graph.rule, graph.run_state, graph.gaps) == ("G5", "terminated", ())


@pytest.mark.parametrize("consumed", [[br(99)], [br(1), br(99)]], ids=["unissued", "forged"])
def test_b2_verifier_reports_an_unissued_branch(capture: Capture, consumed: list[str]) -> None:
    first, consumer = capture.new_segment(), capture.new_segment()
    start(capture, RUN, first)
    issued = {"fabric.segment.branch_ids": [br(1)]} if br(1) in consumed else {}
    a = seal(capture, RUN, first, extra={"fabric.run.resumable": True, **issued})
    start(capture, RUN, consumer, a, id_basis="token", extra={"fabric.run.branch_ids": consumed})
    seal(capture, RUN, consumer, terminal=True)
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["run_state"] == "conflicted" and run["verdict"] == "partial"
    assert ("segment_conflict", "branch_not_issued") in gaps(run)


# --------------------------------------------------------------------------
# E: records-input bodies
# --------------------------------------------------------------------------


def sealed_record(capture: Capture, *objects: bytes | None) -> dict[str, Any]:
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    row = capture.record(objects=objects)
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    return row


def test_e_intact_record_body_is_complete(capture: Capture) -> None:
    sealed_record(capture, b'{"secret":"correct"}', None)
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_observed_scopes"
    assert run["run_state"] == "terminated"


@pytest.mark.parametrize(
    ("damage", "expected"),
    [("delete", ("missing_object", "absent")), ("corrupt", ("digest_mismatch", "content_digest"))],
)
def test_e_records_content_bytes_are_verified(
    capture: Capture, damage: str, expected: tuple[str, str]
) -> None:
    """Review repro E: a deleted or altered body is a gap of the record, never complete."""
    row = sealed_record(capture, b'{"secret":"correct"}')
    path = capture.object_path(row["attributes"]["fabric.content.object_ids"][0])
    assert path.exists()
    if damage == "delete":
        path.unlink()
    else:
        path.write_bytes(b"CORRUPTED")
    document = capture.reconstruct()
    run = only_run(document)
    assert run["verdict"] == "partial"
    assert expected in gaps(run)
    (gap,) = [g for g in run["gaps"] if g["gap_type"] == expected[0]]
    sequence = row["attributes"]["fabric.source.sequence"]
    assert (gap["first_sequence"], gap["last_sequence"]) == (sequence, sequence)
    assert gap["segment_id"] == row["attributes"]["fabric.run.segment_id"]
    # The body's seal contribution is refused: the seal cannot be recomputed.
    assert ("seal_mismatch", "content_unavailable") in gaps(run)
    assert run["checks"]["bytes"] == "failed"
    assert document["scopes"][0]["verdict"] == "partial"


def _rewrite_descriptor(capture: Capture, object_id: str, **changes: Any) -> None:
    meta = capture.root / "store" / "tenant-a" / "evidence" / "meta" / f"{object_id}.json"
    descriptor = json.loads(meta.read_text())
    descriptor.update(changes)
    for key in [key for key, value in changes.items() if value is None]:
        del descriptor[key]
    meta.write_text(json.dumps(descriptor))


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"attempt_id": "a-other", "operation_id": "a-other"}, "binding_mismatch"),
        ({"source_sequence": 99}, "binding_mismatch"),
        ({"role": "tool.result"}, "sidecar_mismatch"),  # not a role of the table
        ({"boundary": "terminal"}, "sidecar_mismatch"),  # the role's row refuses it
        ({"source_sha256": None}, "sidecar_mismatch"),  # stored exact without its source
        ({"unknown": 1}, "sidecar_mismatch"),  # outside the closed key set
        ({"stored_byte_length": 3}, "sidecar_mismatch"),
    ],
)
def test_e_descriptor_contract_and_binding(
    capture: Capture, changes: dict[str, Any], reason: str
) -> None:
    row = sealed_record(capture, b'{"secret":"correct"}')
    _rewrite_descriptor(capture, row["attributes"]["fabric.content.object_ids"][0], **changes)
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert ("digest_mismatch", reason) in gaps(run)


def test_e_descriptor_only_object_is_bound_too(capture: Capture) -> None:
    row = sealed_record(capture, None)
    object_id = row["attributes"]["fabric.content.object_ids"][0]
    assert only_run(capture.reconstruct())["verdict"] == "complete_for_observed_scopes"
    _rewrite_descriptor(capture, object_id, attempt_id="a-other")
    run = only_run(capture.reconstruct())
    assert ("digest_mismatch", "binding_mismatch") in gaps(run)
    meta = capture.root / "store" / "tenant-a" / "evidence" / "meta" / f"{object_id}.json"
    meta.unlink()
    run = only_run(capture.reconstruct())
    assert ("missing_object", "absent") in gaps(run)


def test_e_unsealed_record_body_is_verified_too(capture: Capture) -> None:
    """Body verification does not depend on the seal check."""
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    row = capture.record(objects=(b'{"a":1}',))
    capture.run_end(RUN)
    capture.heartbeat()
    capture.object_path(row["attributes"]["fabric.content.object_ids"][0]).unlink()
    assert ("missing_object", "absent") in gaps(only_run(capture.reconstruct()))


def test_e_projection_never_reports_a_damaged_body_captured(tmp_path: Path) -> None:
    capture = PCapture(tmp_path)
    capture.manifest()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    capture.object_roles.append(("tool.call.arguments", "application/json"))
    row = capture.record(objects=(b'{"city":"Paris"}',))
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    (tool,) = steps_of(projection, "tool_call")
    assert projected_field(tool, "tool.execution.arguments")["status"] == "captured"
    capture.object_path(row["attributes"]["fabric.content.object_ids"][0]).write_bytes(b"X")
    _, projection = project(capture)
    (tool,) = steps_of(projection, "tool_call")
    assert status(tool, "tool.execution.arguments") == "not_captured(store_failed)"


def test_e_status_reasons_match_the_descriptor_schema() -> None:
    schema = json.loads((CAPTURE_ROOT / "schema" / "content-log-record-v1.schema.json").read_text())
    enum = schema["$defs"]["descriptor"]["properties"]["status_reason"]["enum"]
    assert frozenset(enum) == STATUS_REASONS


def test_e_record_contract_accepts_the_capture_fixture() -> None:
    """The valid spool-record fixture's record bodies satisfy the record contract once
    persisted (the writer adds encoding and ref to an object with bytes)."""
    document = json.loads(
        (CAPTURE_ROOT / "fixtures" / "valid" / "spool-record-record-bodies.json").read_text()
    )
    descriptors = [body["descriptor"] for body in document["bodies"]]
    assert descriptors
    for descriptor in descriptors:
        persisted = dict(descriptor)
        if persisted["status"] != "not_captured":
            persisted.update(encoding="binary", ref="file:///store/" + persisted["object_id"])
        assert record_descriptor_ok(persisted), descriptor
    assert not record_descriptor_ok({**descriptors[0], "role": "tool.result"})


# --------------------------------------------------------------------------
# E (confirmation review, item 4): production object authentication of record objects
# --------------------------------------------------------------------------


def stamped_record(capture: Capture, *objects: bytes | None) -> tuple[dict[str, Any], list[str]]:
    """A sealed record whose telemetry all carries the Node's stamp (049 §7.9) and whose
    objects' persisted descriptors carry it too; returns the record row and its object ids."""
    row = sealed_record(capture, *objects)
    for each in capture.rows:
        each["attributes"]["fabric.source.authenticated"] = True
    object_ids = list(row["attributes"]["fabric.content.object_ids"])
    for object_id in object_ids:
        _rewrite_descriptor(capture, object_id, source_authenticated=True)
    return row, object_ids


def production(capture: Capture, **kwargs: Any) -> dict[str, Any]:
    return only_run(capture.reconstruct(profile="production", trusted_source=True, **kwargs))


def auth_gaps(run: dict[str, Any]) -> list[tuple[str | None, int | None]]:
    return sorted((g.get("reason"), g.get("first_sequence"))
                  for g in run["gaps"] if g["gap_type"] == "source_unauthenticated")  # fmt: skip


def test_e_stamped_record_objects_authenticate_in_production(capture: Capture) -> None:
    stamped_record(capture, b'{"a":1}', None)
    run = production(capture)
    assert auth_gaps(run) == []
    assert run["verdict"] == "complete_for_observed_scopes"


@pytest.mark.parametrize("unstamped", [0, 1], ids=["stored_body", "descriptor_only"])
def test_e_an_unstamped_record_object_is_unauthenticated(capture: Capture, unstamped: int) -> None:
    row, object_ids = stamped_record(capture, b'{"a":1}', None)
    _rewrite_descriptor(capture, object_ids[unstamped], source_authenticated=None)
    run = production(capture)
    sequence = row["attributes"]["fabric.source.sequence"]
    assert auth_gaps(run) == [("unstamped_object", sequence)]
    (gap,) = [g for g in run["gaps"] if g["gap_type"] == "source_unauthenticated"]
    assert gap["effect"] == "unverified"
    assert gap["segment_id"] == row["attributes"]["fabric.run.segment_id"]
    assert run["verdict"] == "unverified"


def test_e_record_object_stamps_are_not_required_outside_production(capture: Capture) -> None:
    _, object_ids = stamped_record(capture, b'{"a":1}', None)
    for object_id in object_ids:
        _rewrite_descriptor(capture, object_id, source_authenticated=None)
    run = only_run(capture.reconstruct(profile="local", trusted_source=True))
    assert auth_gaps(run) == []
    assert run["verdict"] == "complete_for_observed_scopes"


# --------------------------------------------------------------------------
# E against real SDK output
# --------------------------------------------------------------------------


@pytest.fixture
def installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Any, Any, Path]]:
    loss = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", loss)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    monkeypatch.setenv("FABRIC_CLOCK_UNCERTAINTY_MS", "0")
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    monkeypatch.delenv("FABRIC_RECORDS_STRICT", raising=False)
    provider = TracerProvider()
    spans = tmp_path / "actual.jsonl"
    provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(spans)))
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(
        store=store, tracer_provider=provider, patch_httpx=False, patch_aiohttp=False,
        id_key=b"k" * 32,
    )  # fmt: skip
    yield handle, store, spans
    handle.close(5)
    loss.close(1)
    provider.shutdown()


@pytest.mark.parametrize("damage", ["delete", "corrupt"])
def test_e_real_sdk_record_body_is_verified(installed: tuple[Any, Any, Path], damage: str) -> None:
    handle, store, spans = installed
    with wire.run("body-verification"):
        attempt = handle.records.begin("tool_call", "sdk.records")
        assert attempt.emit(
            "end", name_hint="fabric.tool_call", attributes={}, start_ns=1, end_ns=2,
            bodies=[RecordBody("tool.call.result", b'{"answer":42}', "application/json",
                               "caller")],
        )  # fmt: skip
    assert handle.close(5)
    baseline = only_run(reconstruct([spans], store=store))
    assert baseline["verdict"] == "complete_for_observed_scopes"
    rows = [json.loads(line) for line in spans.read_text().splitlines()]
    row = next(r for r in rows if r["attributes"].get("fabric.capture.input") == "records")
    object_id = row["attributes"]["fabric.content.object_ids"][0]
    ref = store.evidence_ref_for(object_id)
    assert store.read_descriptor(ref)["role"] == "tool.call.result"
    path = Path(ref.removeprefix("file://"))
    if damage == "delete":
        path.unlink()
    else:
        path.write_bytes(b"CORRUPTED")
    run = only_run(reconstruct([spans], store=store))
    assert run["verdict"] == "partial"
    assert {g["gap_type"] for g in run["gaps"]} & {"missing_object", "digest_mismatch"}
