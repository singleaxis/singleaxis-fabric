# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Verifier inputs and integrity for run structure (spec 050 §3.12, WP-30).

The ``Capture`` builder of ``test_reconstruct_verifier`` plays the P1 capture worker:
records-input records, segment-tagged exchanges, segment-attributed losses, segment seals
computed by the WP-00 reference rule (``scripts/contracts/p1_reference.py``) and capture
manifests written through the WP-00 manifest-span mapping. The verifier recomputes seals
through the SDK's own rule, ``fabric._seal`` (WP-11a), never the reference: a seal the
capture side computed by the reference verifies only because the two agree byte for byte.
Every report is validated against the run-reconstruction schema and its semantic rules.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from fabric import _seal
from fabric.reconstruct import SpanRecord, read_span_file
from fabric.reconstruct.__main__ import _duration_ns, main
from fabric.reconstruct._inputs import (
    MANIFEST_SPAN_KEYS,
    HeartbeatObs,
    ManifestObs,
    RecordObs,
    SegmentSealObs,
    manifest_document,
    observe,
)
from fabric.reconstruct._report import Gap
from tests.test_reconstruct_inputs import to_otlp
from tests.test_reconstruct_verifier import (
    COVERAGE,
    COVERAGE_REGISTRY,
    EPOCH,
    MANIFEST_VECTOR,
    P1_REFERENCE,
    RUN,
    Capture,
    only_run,
    react_turns,
    validate,
)

RUN_B = "r-" + "b" * 32


def test_the_verifier_recomputes_seals_with_the_sdk_rule() -> None:
    """The WP-30 fallback to the reference rule is gone: ``fabric._seal`` is WP-11a's own
    implementation, which the verifier calls, and not the reference module's functions."""
    assert _seal.seal_digest is not P1_REFERENCE.seal_digest
    assert _seal.record_digest is not P1_REFERENCE.record_digest
    assert _seal.seal_digest([]) == P1_REFERENCE.seal_digest([])


@pytest.fixture
def capture(tmp_path: Path) -> Capture:
    return Capture(tmp_path)


def gaps(run: Mapping[str, Any], gap_type: str | None = None) -> list[dict[str, Any]]:
    return [g for g in run["gaps"] if gap_type is None or g["gap_type"] == gap_type]


def sealed_run(capture: Capture, *, final: bool = True) -> tuple[str, str]:
    """A P1 run: manifest 0, one scope and segment holding three exchanges and three
    records interleaved (one record with a stored and a descriptor-only object), a terminal
    seal, and the epoch's final heartbeat. Returns ``(scope id, segment id)``."""
    capture.manifest()
    segment = capture.new_segment()
    scope = capture.run_start(RUN, segment_id=segment)
    for index, (request, response) in enumerate(react_turns()):
        capture.exchange(request, response)
        objects: tuple[bytes | None, ...] = (b'{"city":"Paris"}', None) if index == 0 else ()
        capture.record(objects=objects)
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, scope_id=scope)
    if final:
        capture.heartbeat()
    return scope, segment


# --------------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------------


def test_manifest_span_mapping_is_the_registry_mapping() -> None:
    assert dict(MANIFEST_SPAN_KEYS) == COVERAGE._manifest_key_rows(COVERAGE_REGISTRY)


@pytest.mark.parametrize("case", MANIFEST_VECTOR["cases"], ids=lambda c: c["name"])
def test_manifest_span_rebuilds_the_vector_document(case: Mapping[str, Any]) -> None:
    assert manifest_document(case["attributes"]) == case["manifest"]


def test_manifest_observation_carries_the_canonical_digest() -> None:
    case = MANIFEST_VECTOR["cases"][0]
    span = SpanRecord("a" * 32, "b" * 16, None, "fabric.capture_manifest", 1, 1,
                      case["attributes"], {})  # fmt: skip
    observed = observe(span)
    assert isinstance(observed, ManifestObs)
    assert observed.sha256 == COVERAGE.manifest_digest(case["manifest"])
    assert observed.manifest_seq == case["manifest"]["manifest_seq"]


def test_otlp_status_and_kind_are_read(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    row = capture.record(run_id=None, status="error")
    export = to_otlp([row])
    span = export["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["status"] = {"code": "STATUS_CODE_ERROR"}
    span["kind"] = "SPAN_KIND_INTERNAL"
    path = tmp_path / "spans.json"
    path.write_text(json.dumps(export), encoding="utf-8")
    _, (record,) = read_span_file(path)
    assert (record.status, record.kind) == ("error", "internal")
    observed = observe(record)
    assert isinstance(observed, RecordObs)
    assert observed.source_sequence == 0


def test_records_and_seals_are_observed(capture: Capture) -> None:
    sealed_run(capture)
    rows = capture.rows
    kinds = []
    for row in rows:
        record = SpanRecord(row["trace_id"], row["span_id"], None, row["name"], row["start_ns"],
                            row["end_ns"], row["attributes"], {})  # fmt: skip
        kinds.append(type(observe(record)).__name__)
    assert kinds.count("RecordObs") == 3
    assert kinds.count("SegmentSealObs") == 1
    assert kinds.count("ManifestObs") == 1


def test_a_malformed_seal_still_reveals_its_sequence(capture: Capture) -> None:
    attributes = {
        "fabric.source_id": "wire-1", "fabric.source.epoch": 7,
        "fabric.heartbeat.last_sequence": 3, "fabric.heartbeat.kind": "segment_seal",
        "fabric.run.segment_id": "seg-not-hex",
    }  # fmt: skip
    record = SpanRecord("a" * 32, "b" * 16, None, "fabric.capture_heartbeat", 1, 1,
                        attributes, {})  # fmt: skip
    assert observe(record) == HeartbeatObs("wire-1", 7, None, None, 3)
    attributes["fabric.run.segment_id"] = "seg-" + "0" * 32
    attributes["fabric.segment.last_sequence"] = 3
    attributes["fabric.segment.seal_digest"] = "sha256:" + "0" * 64
    assert isinstance(observe(record), SegmentSealObs)


# --------------------------------------------------------------------------
# Records interleaved with exchanges
# --------------------------------------------------------------------------


def test_records_interleaved_with_exchanges_verify(capture: Capture) -> None:
    _, segment = sealed_run(capture)
    document = capture.reconstruct()
    run = only_run(document)
    assert run["verdict"] == "complete_for_observed_scopes"
    assert gaps(run) == []
    assert run["counts"]["exchanges"] == 3
    assert [entry["state"] for entry in document["scopes"]] == ["closed"]
    (source,) = document["sources"]
    assert source["missing_sequences"] == []
    assert source["manifests"] == [
        {"manifest_id": capture.manifest_id, "sha256": capture.manifest_digest, "manifest_seq": 0}
    ]
    assert source["unsealed_epochs"] == []
    (entry,) = run["segments"]
    assert entry["segment_id"] == segment
    assert entry["state"] == "sealed"
    assert entry["predecessors"] == ["none"]
    assert entry["terminal"] is True
    assert entry["seal_digest"] == capture.seal_digest(segment)
    assert entry["manifest_digest"] == capture.manifest_digest
    assert run["run_aliases"] == []
    assert run["evaluated_at"] == document["inputs"]["evaluated_at"]
    assert run["run_state"] == "terminated"  # the segment graph (WP-31) states it
    # Each record here is its own attempt; its membership is its one position.
    assert [a["records"] for a in run["attempts"]] == [1, 1, 1]
    assert main(["--spans", str(capture.write()), "--store-root", str(capture.root / "store"),
                 "--tenant", "tenant-a", "--out", str(capture.root / "r.json")]) == 0  # fmt: skip


def test_records_fill_sequences_without_seals(capture: Capture) -> None:
    """Pre-seal accounting: a records span's sequence is never a sequence gap (it was
    counted missing before spec 050, because only exchanges filled the source)."""
    capture.exchange(*react_turns()[0], scope_id=None)
    capture.record(scope_id=None)
    capture.exchange(*react_turns()[1], scope_id=None)
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    assert "segments" not in run


def test_host_duplicates_are_ignored(capture: Capture) -> None:
    sealed_run(capture)
    record = next(r for r in capture.rows if r["name"] == "fabric.tool_call")
    duplicate = json.loads(json.dumps(record))
    duplicate["span_id"] = "d" * 16
    for key in ("fabric.source.sequence", "fabric.source_id", "fabric.source.epoch"):
        duplicate["attributes"].pop(key)
    duplicate["attributes"]["fabric.step.status"] = "error"  # anything: it is not accounted
    capture.rows.append(duplicate)
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_observed_scopes"
    assert gaps(run) == []


def test_a_retried_record_is_one_record(capture: Capture) -> None:
    sealed_run(capture)
    record = next(r for r in capture.rows if r["name"] == "fabric.tool_call")
    retry = json.loads(json.dumps(record))
    retry["attributes"]["fabric.source.authenticated"] = True  # receiver-owned: excluded
    capture.rows.append(retry)
    run = only_run(capture.reconstruct(profile="local"))
    assert gaps(run) == []


def test_a_differing_record_at_one_position_is_a_conflicting_claim(capture: Capture) -> None:
    sealed_run(capture)
    record = next(r for r in capture.rows if r["name"] == "fabric.tool_call")
    other = json.loads(json.dumps(record))
    other["attributes"]["fabric.event_id"] = capture.new_id()
    capture.rows.append(other)
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert ("digest_mismatch", "conflicting_claim") in {
        (g["gap_type"], g.get("reason")) for g in gaps(run)
    }
    assert ("seal_mismatch", "conflicting_member") in {
        (g["gap_type"], g.get("reason")) for g in gaps(run)
    }


# --------------------------------------------------------------------------
# Seal recomputation
# --------------------------------------------------------------------------


def _seal_gaps(run: Mapping[str, Any]) -> list[tuple[str, str | None, str | None]]:
    return [(g["gap_type"], g.get("segment_id"), g.get("reason"))
            for g in run["gaps"] if g["gap_type"] == "seal_mismatch"]  # fmt: skip


def test_seal_mismatch_for_a_deleted_tail(capture: Capture) -> None:
    _, segment = sealed_run(capture)
    tail = [r for r in capture.rows if r["name"] == "fabric.tool_call"][-1]
    capture.rows.remove(tail)
    document = capture.reconstruct()
    run = only_run(document)
    assert run["verdict"] == "partial"
    assert _seal_gaps(run) == [("seal_mismatch", segment, "digest_differs")]
    assert run["segments"][0]["state"] == "conflict"
    # Scope verdicts count the seal gap too.
    assert document["scopes"][0]["verdict"] == "partial"


def test_seal_mismatch_for_an_edited_record(capture: Capture) -> None:
    _, segment = sealed_run(capture)
    record = [r for r in capture.rows if r["name"] == "fabric.tool_call"][1]
    record["attributes"]["fabric.step.status"] = "error"
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert [g["gap_type"] for g in gaps(run)] == ["seal_mismatch"]
    assert _seal_gaps(run) == [("seal_mismatch", segment, "digest_differs")]


def test_seal_mismatch_for_an_edited_exchange(capture: Capture) -> None:
    _, segment = sealed_run(capture)
    exchange = next(r for r in capture.rows if r["name"] == "fabric.model_call")
    exchange["attributes"]["gen_ai.operation.name"] = "completion"
    run = only_run(capture.reconstruct())
    assert _seal_gaps(run) == [("seal_mismatch", segment, "digest_differs")]


def test_seal_mismatch_for_an_edited_object_descriptor(capture: Capture) -> None:
    _, segment = sealed_run(capture)
    record = next(r for r in capture.rows if "fabric.content.object_ids" in r["attributes"])
    object_id = record["attributes"]["fabric.content.object_ids"][0]
    meta = capture.root / "store" / "tenant-a" / "evidence" / "meta" / f"{object_id}.json"
    descriptor = json.loads(meta.read_text())
    descriptor["stored_sha256"] = "sha256:" + "0" * 64
    meta.write_text(json.dumps(descriptor))
    run = only_run(capture.reconstruct())
    assert _seal_gaps(run) == [("seal_mismatch", segment, "digest_differs")]


def test_seal_mismatch_for_a_record_moved_between_segments(capture: Capture) -> None:
    capture.manifest()
    first, second = capture.new_segment(), capture.new_segment()
    capture.run_start(RUN, segment_id=first)
    capture.record()
    moved = capture.record()
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=first, terminal=False)
    # WP-31: the second segment continues the first (a second root is G1).
    entry = f"{first}/{capture.source_id}/{EPOCH}/{capture.sequence - 1}/{capture.manifest_digest}"
    capture.run_start(RUN, segment_id=second, predecessors=(entry,))
    capture.record()
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=second)
    capture.heartbeat()
    assert not gaps(only_run(capture.reconstruct()))
    moved["attributes"]["fabric.run.segment_id"] = second
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert sorted(_seal_gaps(run)) == sorted(
        [("seal_mismatch", first, "digest_differs"), ("seal_mismatch", second, "digest_differs")]
    )
    assert {s["segment_id"]: s["state"] for s in run["segments"]} == {
        first: "conflict", second: "conflict",
    }  # fmt: skip


def test_a_record_after_its_seal_is_a_segment_conflict(capture: Capture) -> None:
    _, segment = sealed_run(capture, final=False)
    capture.run_start(RUN)
    late = capture.record(segment_id=segment)
    capture.run_end(RUN)
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    sequence = late["attributes"]["fabric.source.sequence"]
    assert {
        "gap_type": "segment_conflict", "effect": "partial", "source_id": capture.source_id,
        "source_epoch": EPOCH, "first_sequence": sequence, "last_sequence": sequence,
        "segment_id": segment, "reason": "record_after_seal",
    } in gaps(run)  # fmt: skip
    assert _seal_gaps(run) == []  # the sealed members still verify


def test_an_unsealed_segment_is_partial_source_lost(capture: Capture) -> None:
    capture.manifest()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    capture.exchange(*react_turns()[0])
    capture.record()
    capture.run_end(RUN)
    capture.heartbeat()  # the process crashed before the seal settled
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    unsealed = gaps(run, "unsealed_segment")
    assert [(g["effect"], g.get("reason"), g.get("segment_id")) for g in unsealed] == [
        ("partial", "source_lost", segment)
    ]
    assert run["segments"][0]["state"] == "unsealed"
    assert "seal_digest" not in run["segments"][0]


def test_a_seal_without_the_store_is_unverified(capture: Capture) -> None:
    sealed_run(capture)
    run = only_run(capture.reconstruct(store=None))
    assert ("seal_mismatch", "unverified", "no_store") in {
        (g["gap_type"], g["effect"], g.get("reason")) for g in gaps(run)
    }
    assert run["verdict"] == "unverified"


def test_a_seal_with_the_rule_unavailable_is_unverified(
    capture: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def stub(*args: Any, **kwargs: Any) -> str:
        raise NotImplementedError

    sealed_run(capture)
    monkeypatch.setattr(_seal, "seal_digest", stub)
    run = only_run(capture.reconstruct())
    assert {(g["gap_type"], g.get("reason")) for g in gaps(run)} == {
        ("seal_mismatch", "seal_rule_unavailable")
    }


def test_interleaved_segments_with_losses_each_verify(capture: Capture) -> None:
    """T8: two runs interleave positions on one source with queue_full losses in both;
    each seal verifies with only its own segment's losses, and an unattributed loss is
    never a seal member."""
    capture.manifest()
    seg_a, seg_b = capture.new_segment(), capture.new_segment()
    capture.run_start(RUN, segment_id=seg_a)
    capture.run_start(RUN_B, segment_id=seg_b)
    for turn in range(3):
        capture.record(run_id=RUN)
        capture.record(run_id=RUN_B)
        lost_a, lost_b = capture.skip(), capture.skip()
        capture.loss("queue_full", lost_a, segment_id=seg_a)
        capture.loss("queue_full", lost_b, segment_id=seg_b)
        if turn == 1:
            capture.loss("shutdown", capture.skip())  # outside every segment
    capture.run_end(RUN_B)
    capture.segment_seal(RUN_B, segment_id=seg_b)
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=seg_a)
    capture.heartbeat()
    document = capture.reconstruct()
    for run_id, segment in ((RUN, seg_a), (RUN_B, seg_b)):
        run = next(r for r in document["runs"] if r["run_id"] == run_id)
        assert _seal_gaps(run) == []
        assert [(s["segment_id"], s["state"]) for s in run["segments"]] == [(segment, "sealed")]
        assert {g["gap_type"] for g in gaps(run)} == {"loss"}  # the lost positions: partial
    losses = document["sources"][0]["loss_ranges"]
    assert {loss.get("segment_id") for loss in losses} == {seg_a, seg_b, None}


def test_a_loss_attributed_to_another_segment_breaks_the_seal(capture: Capture) -> None:
    capture.manifest()
    seg_a, seg_b = capture.new_segment(), capture.new_segment()
    capture.run_start(RUN, segment_id=seg_a)
    capture.record()
    lost = capture.skip()
    capture.loss("queue_full", lost, segment_id=seg_a)
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=seg_a)
    capture.heartbeat()
    loss_row = next(r for r in capture.rows if r["name"] == "fabric.capture_loss")
    loss_row["attributes"]["fabric.run.segment_id"] = seg_b
    run = only_run(capture.reconstruct())
    assert _seal_gaps(run) == [("seal_mismatch", seg_a, "digest_differs")]


# --------------------------------------------------------------------------
# Scope pairing with continuation run_start markers (spec 050 §9 delta 1)
# --------------------------------------------------------------------------


def test_a_continuation_run_start_keeps_the_scope_closed(capture: Capture) -> None:
    capture.manifest()
    first, second = capture.new_segment(), capture.new_segment()
    scope = capture.run_start(RUN, segment_id=first)
    capture.record()
    capture.segment_seal(RUN, segment_id=first, terminal=False)  # resume_token() inside
    entry = (f"{first}/{capture.source_id}/{EPOCH}/{capture.sequence - 1}/"
             f"{capture.manifest_digest}")  # fmt: skip
    capture.open_scopes.remove((RUN, scope))
    capture.run_start(RUN, scope, segment_id=second, predecessors=(entry,), id_basis="token")
    capture.record()
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=second)
    capture.heartbeat()
    document = capture.reconstruct()
    run = only_run(document)
    assert run["verdict"] == "complete_for_observed_scopes", gaps(run)
    (listing,) = run["scopes"]
    assert (listing["state"], listing["start_sequence"]) == ("closed", -1)
    second_entry = next(s for s in run["segments"] if s["segment_id"] == second)
    assert second_entry["predecessors"] == [entry]


def test_two_unsegmented_starts_of_one_scope_still_conflict(capture: Capture) -> None:
    scope = capture.run_start(RUN)
    capture.exchange(*react_turns()[0])
    capture.heartbeat(run_id=RUN, kind="run_start", scope_id=scope)
    capture.run_end(RUN)
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["scopes"][0]["state"] == "conflict"


# --------------------------------------------------------------------------
# Manifests
# --------------------------------------------------------------------------


def _manifest_gaps(run: Mapping[str, Any]) -> list[tuple[str, int | None, int | None, str]]:
    return [(g["effect"], g.get("first_sequence"), g.get("last_sequence"), g["reason"])
            for g in gaps(run, "manifest_gap")]  # fmt: skip


def test_a_lost_trailing_manifest_is_detected_from_the_heartbeat(capture: Capture) -> None:
    sealed_run(capture, final=False)
    capture.manifest(emit=False)  # manifest 1 (a capture-point state change) is lost
    capture.record()
    capture.heartbeat(extra={"fabric.capture.manifest_seq": 1})
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"  # what ran under manifest 1 is unknown
    top = capture.sequence - 1
    window = [g for g in _manifest_gaps(run) if g[3] == "manifest_missing"]
    assert window and all(g[0] == "unverified" for g in window)
    assert window[0][2] is not None and window[0][2] <= top


def test_a_missing_middle_manifest_is_a_manifest_gap(capture: Capture) -> None:
    capture.manifest()
    segment = capture.new_segment()
    scope = capture.run_start(RUN, segment_id=segment)
    capture.record()
    capture.manifest(emit=False)  # manifest 1: lost
    capture.record()
    capture.manifest()  # manifest 2 names manifest 1's digest
    capture.record()
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, scope_id=scope)
    capture.heartbeat()
    document = capture.reconstruct()
    run = only_run(document)
    assert run["verdict"] == "unverified"
    assert _manifest_gaps(run) and {g[3] for g in _manifest_gaps(run)} >= {"manifest_missing"}
    assert [m["manifest_seq"] for m in document["sources"][0]["manifests"]] == [0, 2]


def test_a_broken_manifest_chain_is_a_manifest_gap(capture: Capture) -> None:
    capture.manifest()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    capture.record()
    capture.manifest(previous="sha256:" + "1" * 64)
    capture.record()
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert "chain_mismatch" in {g[3] for g in _manifest_gaps(run)}


def test_an_edited_manifest_is_unknown_to_the_markers(capture: Capture) -> None:
    sealed_run(capture)
    manifest = next(r for r in capture.rows if r["name"] == "fabric.capture_manifest")
    manifest["attributes"]["fabric.manifest.content_capture"] = "disabled"
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert {g[3] for g in _manifest_gaps(run)} == {"unknown_manifest"}


def test_two_different_manifest_zero_documents_conflict(capture: Capture) -> None:
    sealed_run(capture)
    capture.manifest(0, profile="production")
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert ("segment_conflict", "manifest_conflict") in {
        (g["gap_type"], g.get("reason")) for g in gaps(run)
    }
    assert run["segments"][0]["state"] == "conflict"


def test_an_unsealed_prior_epoch_is_partial_for_its_runs(tmp_path: Path) -> None:
    prior = Capture(tmp_path, epoch=EPOCH + 1)
    prior.manifest()
    segment = prior.new_segment()
    prior.run_start(RUN, segment_id=segment)
    prior.record()
    prior.run_end(RUN)
    prior.segment_seal(RUN, segment_id=segment)  # sealed, but the epoch never wrote final
    current = Capture(tmp_path, epoch=EPOCH + 2)
    current.manifest(unsealed_prior=(EPOCH + 1,))
    current.rows[:0] = prior.rows
    current.record_content.update(prior.record_content)
    document = current.reconstruct()
    run = only_run(document)
    assert ("unsealed_epoch", "unsealed_prior_epoch") in {
        (g["gap_type"], g.get("reason")) for g in gaps(run)
    }
    assert run["verdict"] == "partial"
    declaring = next(s for s in document["sources"] if s["source_epoch"] == EPOCH + 2)
    assert declaring["unsealed_epochs"] == [EPOCH + 1]


def test_an_orphan_epoch_is_listed_unsealed(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    sealed_run(capture)
    orphan = Capture(tmp_path, epoch=EPOCH + 7)
    orphan.skip()
    orphan.periodic(0)  # the drainer's heartbeat for a killed spawned worker
    capture.rows.extend(orphan.rows)
    document = capture.reconstruct()
    source = next(s for s in document["sources"] if s["source_epoch"] == EPOCH + 7)
    assert source["unsealed_epochs"] == [EPOCH + 7]
    assert source["missing_sequences"] == [[0, 0]]


def test_a_pre_p1_capture_has_no_run_structure_fields(capture: Capture) -> None:
    for request, response in react_turns():
        capture.exchange(request, response)
    capture.heartbeat()
    document = capture.reconstruct()
    run = only_run(document)
    assert not {"segments", "run_aliases", "run_state", "evaluated_at", "attempts"} & set(run)
    assert not {"manifests", "unsealed_epochs"} & set(document["sources"][0])


# --------------------------------------------------------------------------
# Attempt membership beyond the projection's 64 event ids
# --------------------------------------------------------------------------


def test_two_interleaved_attempts_keep_their_full_membership(capture: Capture) -> None:
    capture.manifest()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    attempt_a, attempt_b = capture.new_id(), capture.new_id()
    first = capture.sequence
    for _ in range(70):
        capture.record(attempt_uid=attempt_a, step_id="stp-" + "1a" * 16)
        capture.record(attempt_uid=attempt_b)
    tail = capture.sequence
    for _ in range(3):  # attempt b's last three records are consecutive
        capture.record(attempt_uid=attempt_b)
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert gaps(run) == []
    attempts = {entry["attempt_uid"]: entry for entry in run["attempts"]}
    a, b = attempts[attempt_a], attempts[attempt_b]
    assert (a["records"], b["records"]) == (70, 73)
    assert a["step_id"] == "stp-" + "1a" * 16 and "step_id" not in b
    (a_positions,) = a["sequences"]
    (b_positions,) = b["sequences"]
    assert (a_positions["source_id"], a_positions["source_epoch"]) == (capture.source_id, EPOCH)
    assert a_positions["ranges"] == [[first + 2 * i, first + 2 * i] for i in range(70)]
    assert b_positions["ranges"] == [
        *([first + 1 + 2 * i, first + 1 + 2 * i] for i in range(69)),
        [first + 139, tail + 2],
    ]
    validate_attempts = [len(r) for r in (a_positions["ranges"], b_positions["ranges"])]
    assert validate_attempts == [70, 70]


def test_an_inconsistent_attempt_listing_is_refused(capture: Capture) -> None:
    sealed_run(capture)
    document = capture.reconstruct()
    document["runs"][0]["attempts"][0]["records"] = 2
    with pytest.raises(Exception, match="attempt"):
        validate(document)


# --------------------------------------------------------------------------
# Graph hand-off and CLI
# --------------------------------------------------------------------------


def test_segment_graph_results_are_merged(
    capture: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The run fields WP-31's graph decides (run state, missing segments, aliases, gaps)
    reach the report; ``run_open`` is info and an open run exits 1."""
    from datetime import UTC, datetime  # noqa: PLC0415

    from fabric.reconstruct import _verify  # noqa: PLC0415
    from fabric.reconstruct._graph import RunGraph, SegmentNode  # noqa: PLC0415

    missing = "seg-" + "e" * 32
    seen: list[SegmentNode] = []

    def graphs(segments: Any, **kwargs: Any) -> list[RunGraph]:
        seen.extend(segments)
        node = SegmentNode(missing, RUN, "s-x", 1, ("none",))
        return [
            RunGraph(RUN, (*segments, node), "open", run_aliases=("r-" + "c" * 32,),
                     gaps=(Gap("run_open", "info", segment_id=missing),),
                     deadline_at=datetime(2026, 11, 1, tzinfo=UTC))
        ]  # fmt: skip

    monkeypatch.setattr(_verify, "build_run_graphs", graphs)
    _, segment = sealed_run(capture)
    document = capture.reconstruct()
    run = only_run(document)
    assert [node.segment_id for node in seen] == [segment]
    assert seen[0].predecessors == ("none",) and seen[0].terminal is True
    assert seen[0].clock_uncertainty_ns == 0
    assert run["run_state"] == "open"
    assert run["verdict"] == "complete_for_observed_scopes"  # run_open is info
    assert {s["segment_id"]: s["state"] for s in run["segments"]} == {
        segment: "sealed", missing: "missing",
    }  # fmt: skip
    assert run["run_aliases"] == ["r-" + "c" * 32]
    assert run["deadline_at"] == "2026-11-01T00:00:00Z"
    args = ["--spans", str(capture.write()), "--store-root", str(capture.root / "store"),
            "--tenant", "tenant-a", "--out", str(capture.root / "r.json")]  # fmt: skip
    assert main(args) == 1


@pytest.fixture
def cli_capture(capture: Capture) -> Iterator[list[str]]:
    sealed_run(capture)
    yield ["--spans", str(capture.write()), "--store-root", str(capture.root / "store"),
           "--tenant", "tenant-a", "--out", str(capture.root / "r.json")]  # fmt: skip


def test_cli_run_structure_flags(cli_capture: list[str], tmp_path: Path) -> None:
    out = Path(cli_capture[-1])
    args = [*cli_capture, "--evaluated-at", "2026-10-19T10:00:00Z", "--clock-uncertainty",
            "250ms", "--max-clock-uncertainty", "5m"]  # fmt: skip
    assert main(args) == 0
    report = json.loads(out.read_text())
    assert report["inputs"]["evaluated_at"] == "2026-10-19T10:00:00Z"
    assert report["runs"][0]["evaluated_at"] == "2026-10-19T10:00:00Z"


def test_cli_projection_before_wp32_writes_nothing(
    cli_capture: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "projection.json"
    assert main([*cli_capture, "--projection", str(target)]) == 0
    assert not target.exists()
    assert "no step projection was built" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--evaluated-at", "yesterday"),
        ("--evaluated-at", "2026-10-19T10:00:00"),  # no offset
        ("--clock-uncertainty", "-1s"),
        ("--clock-uncertainty", "2 days"),
        ("--max-clock-uncertainty", "400d"),
        ("--coverage-profile", "model-calls"),
    ],
)
def test_cli_refuses_bad_run_structure_flags(
    cli_capture: list[str], flag: str, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([*cli_capture, f"{flag}={value}"]) == 2
    assert value not in capsys.readouterr().err


@pytest.mark.parametrize(
    ("text", "nanos"),
    [("0", 0), ("2", 2_000_000_000), ("250ms", 250_000_000), ("1.5s", 1_500_000_000),
     ("5m", 300_000_000_000), ("1h", 3_600_000_000_000), ("7ns", 7), ("3us", 3_000)],
)  # fmt: skip
def test_durations(text: str, nanos: int) -> None:
    assert _duration_ns(text, "--clock-uncertainty") == nanos


def test_the_sdk_seal_rule_reproduces_the_seal_vectors() -> None:
    """The verifier's seal rule (``fabric._seal``) reproduces the WP-00 vectors."""
    vectors = json.loads(
        (Path(__file__).resolve().parents[3]
         / "contracts/coverage/v1/fixtures/vectors/seal-digest-v1.json").read_text()
    )  # fmt: skip
    for record in vectors["records"]:
        span = record["span"]
        digest = _seal.record_digest(
            name=span["name"], start_ns=span["start_ns"], end_ns=span["end_ns"],
            status=span["status"], attributes=span["attributes"], content=record["content"],
        )  # fmt: skip
        assert digest == record["digest"], record["name"]
    for segment in vectors["segments"]:
        pairs = [(sequence, entry) for sequence, entry in segment["entries"]]
        assert _seal.seal_digest(pairs) == segment["seal_digest"], segment["name"]
