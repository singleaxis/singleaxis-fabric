# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 050 §3.7 (WP-11a): record and seal digests against the WP-00 vectors, the
``SegmentSeals`` accumulator, and segment-attributed settlement (R3, T8): queue-full losses
settle only their own segment's seal."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest

from fabric import _capture_types as ct
from fabric._capture_types import COUNTERS, RecordBody
from fabric._seal import (
    SegmentSeals,
    canonical_bytes,
    loss_entry,
    record_digest,
    seal_digest,
)
from fabric.wire import _pipeline

from ._records_harness import SEG_A, SEG_B, SOURCE, Handle, alternating, reference, vector

DIGEST = "sha256:" + "d" * 64


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    monkeypatch.setenv(ct.STRICT_ENV, "1")
    COUNTERS.reset()
    yield
    COUNTERS.reset()


# --- the digests (seal-digest-v1, seal-parity-v1) -------------------------------------------


def _span_digest(span: dict[str, Any], content: list[str | None]) -> str:
    return record_digest(name=span["name"], start_ns=span["start_ns"], end_ns=span["end_ns"],
                         status=span["status"], attributes=span["attributes"],
                         content=content)  # fmt: skip


def _content(record: dict[str, Any]) -> list[str | None]:
    """The content list the agent derives: for a record, each object id's stored digest."""
    if record["kind"] == "exchange":
        return list(record["content"])
    by_id = {d["object_id"]: d for d in record["descriptors"]}
    ids = record["span"]["attributes"].get("fabric.content.object_ids", [])
    return [by_id[oid].get("stored_sha256") for oid in ids]


@pytest.mark.parametrize("record", vector("seal-digest-v1.json")["records"],
                         ids=lambda r: r["name"])  # fmt: skip
def test_record_digest_vectors(record: dict[str, Any]) -> None:
    ref = reference()
    content = _content(record)
    assert content == ref.record_content(record["kind"], record["descriptors"],
                                         record["span"]["attributes"].get(
                                             "fabric.content.object_ids", []))  # fmt: skip
    assert _span_digest(record["span"], content) == record["digest"]


def test_exchange_seal_entry_matches_the_vector() -> None:
    record = vector("seal-digest-v1.json")["records"][0]
    span = record["span"]
    spool_span = {"name": span["name"], "start_time_unix_nano": span["start_ns"],
                  "end_time_unix_nano": span["end_ns"], "status": span["status"],
                  "attributes": span["attributes"]}  # fmt: skip
    assert _pipeline._record_entry(spool_span) == record["digest"]


@pytest.mark.parametrize("segment", vector("seal-digest-v1.json")["segments"],
                         ids=lambda s: s["name"])  # fmt: skip
def test_seal_digest_vectors(segment: dict[str, Any]) -> None:
    doc = vector("seal-digest-v1.json")
    digests = {r["name"]: r["digest"] for r in doc["records"]}
    records = [(seq, digests[name]) for seq, name in segment["records"]]
    entries = reference().seal_entries(records, segment["losses"], segment["segment_id"])
    assert sorted(map(tuple, entries)) == sorted(map(tuple, segment["entries"]))
    assert seal_digest(segment["entries"]) == segment["seal_digest"]
    # the accumulator, fed the same positions, seals to the same digest
    seals = SegmentSeals()
    markers: list[ct.Marker] = []
    seals.set_sink(markers.append)
    seg = segment["segment_id"]
    for seq, _ in segment["entries"]:
        seals.note_allocated(seg, seq)
    for seq, entry in reversed(segment["entries"]):  # settlement order never matters
        seals.settle(seg, seq, entry)
    last = max((seq for seq, _ in segment["entries"]), default=-1)
    seals.request_seal(seg, last_sequence=last, manifest_digest=None, terminal=True,
                       resumable=False, run_id="r-" + "1" * 32, source_id=SOURCE,
                       epoch=7)  # fmt: skip
    assert [m.seal.seal_digest for m in markers if m.seal] == [segment["seal_digest"]]


@pytest.mark.parametrize("case", vector("seal-parity-v1.json")["cases"], ids=lambda c: c["name"])
def test_seal_parity_vectors(case: dict[str, Any]) -> None:
    """T3, the Python half: the digest of what the agent emitted equals the digest of the
    Node's export (the receiver-owned stamp excluded)."""
    emitted = case["emitted"]
    if "digest" not in case:
        return  # a loss: its entries are checked by the seal vectors
    content = case.get("content", [])
    assert _span_digest(emitted, content) == case["digest"]
    export = {**emitted, **case["expected_export"]}
    assert _span_digest(export, content) == case["digest"]


def test_digest_rules() -> None:
    with pytest.raises(ValueError, match="status"):
        record_digest(name="n", start_ns=0, end_ns=0, status="failed",  # type: ignore[arg-type]
                      attributes={}, content=[])  # fmt: skip
    with pytest.raises(ValueError, match="floats"):
        canonical_bytes({"a": 1.5})
    with pytest.raises(ValueError, match="one entry"):
        seal_digest([(1, DIGEST), (1, "loss:shutdown")])
    tupled = record_digest(name="n", start_ns=1, end_ns=2, status="ok",
                           attributes={"k": ("a", "b")}, content=[None])  # fmt: skip
    listed = record_digest(name="n", start_ns=1, end_ns=2, status="ok",
                           attributes={"k": ["a", "b"]}, content=[None])  # fmt: skip
    assert tupled == listed
    assert seal_digest([]) == reference().seal_digest([])


# --- the accumulator -------------------------------------------------------------------------


def _seals() -> tuple[SegmentSeals, list[ct.Marker]]:
    seals = SegmentSeals()
    markers: list[ct.Marker] = []
    seals.set_sink(markers.append)
    seals.bind_source(lambda: (SOURCE, 7))
    return seals, markers


def test_a_seal_waits_for_every_outstanding_position() -> None:
    seals, markers = _seals()
    for seq in (3, 4, 5):
        seals.note_allocated(SEG_A, seq)
    seals.settle(SEG_A, 3, DIGEST)
    seals.request_seal(SEG_A, last_sequence=5, manifest_digest="sha256:" + "e" * 64,
                       terminal=False, resumable=True, run_id="r-" + "1" * 32)  # fmt: skip
    assert seals.outstanding(SEG_A) == 2
    assert markers == []
    seals.settle(SEG_A, 4, loss_entry("queue_full"))
    seals.settle(SEG_A, 4, DIGEST)  # one outcome per position: ignored
    assert seals.entries(SEG_A) == [(3, DIGEST), (4, "loss:queue_full")]
    seals.settle(SEG_A, 5, DIGEST)
    [marker] = markers
    assert (marker.kind, marker.source_id, marker.epoch, marker.segment_id) == (
        "segment_seal", SOURCE, 7, SEG_A)  # fmt: skip
    assert (marker.terminal, marker.resumable, marker.run_id) == (False, True, "r-" + "1" * 32)
    assert marker.seal is not None
    assert marker.seal.seal_digest == seal_digest(
        [(3, DIGEST), (4, "loss:queue_full"), (5, DIGEST)])  # fmt: skip
    assert ct.UUID4_RE.fullmatch(marker.event_id)
    seals.settle(SEG_A, 6, DIGEST)  # after the seal: counted, never a second marker
    assert seals.stats()["late_settles"] == 1
    assert seals.stats()["open_segments"] == 0


def test_an_empty_segment_seals_at_once_and_failures_are_counted() -> None:
    seals, markers = _seals()
    seals.request_seal(SEG_B, last_sequence=-1, manifest_digest=None, terminal=True,
                       resumable=False)  # fmt: skip
    assert markers[0].seal is not None
    assert markers[0].seal.seal_digest == seal_digest([])
    seals.settle(SEG_A, 0, "not an entry")
    assert seals.stats()["internal_errors"] == 1
    orphan = SegmentSeals()  # no source bound, no sink: sealed but never queued
    orphan.request_seal(SEG_A, last_sequence=-1, manifest_digest=None, terminal=True,
                        resumable=False)  # fmt: skip
    orphan.note_allocated(SEG_B, 0)
    orphan.settle(SEG_B, 0, DIGEST)
    orphan.request_seal(SEG_B, last_sequence=0, manifest_digest=None, terminal=True,
                        resumable=False, source_id=SOURCE, epoch=3)  # fmt: skip
    assert orphan.stats()["seal_markers_unqueued"] == 2
    assert orphan.stats()["sealed"] == 1


def test_a_long_segment_is_forced_to_seal_once() -> None:
    seals, _ = _seals()
    seals = SegmentSeals(forced_at=3)
    forced: list[str] = []
    seals.on_forced = forced.append
    for seq in range(5):
        seals.note_allocated(SEG_A, seq)
    assert forced == [SEG_A]
    assert seals.stats()["segment_forced_seal"] == 1


# --- segment-attributed settlement through the pipeline (R3, T8) ------------------------------


def _blocked(handle: Handle) -> threading.Event:
    """Hold the capture worker on its first record until the returned event is set."""
    release, original = threading.Event(), handle.pipeline._prepare_record

    def held(job: Any) -> Any:
        release.wait(5.0)
        return original(job)

    handle.pipeline._prepare_record = held  # type: ignore[method-assign]
    return release


def test_queue_full_losses_settle_their_own_segment_only() -> None:
    """Two runs interleave positions on one source with ``queue_full`` losses in both: each
    seal holds only its own segment's records and losses (T8)."""
    handle = Handle(queue_max_items=1, segments=alternating(SEG_A, SEG_B))
    release = _blocked(handle)
    attempt = handle.input.begin("tool_call", "sdk.records")
    assert attempt is not None
    results = []
    for i in range(6):
        results.append(
            attempt.emit(
                "end",
                name_hint="fabric.tool_call",
                attributes={},
                start_ns=i,
                end_ns=i + 1,
                bodies=[RecordBody("tool.call.result", b"{}", "application/json", "caller")],
            )
        )
        if i == 0:  # the worker holds the first; the queue takes one more
            deadline = time.monotonic() + 5
            while handle.pipeline.stats()["queue_depth"] and time.monotonic() < deadline:
                time.sleep(0.001)
    assert results[:2] == [True, True]
    assert results.count(False) == 4
    release.set()
    handle.flush()
    for segment, last in ((SEG_A, 4), (SEG_B, 5)):
        handle.pipeline.seals.request_seal(segment, last_sequence=last, manifest_digest=None,
                                           terminal=True, resumable=False)  # fmt: skip
    by_segment = {m.segment_id: m for m in handle.markers}
    assert handle.sender is not None
    spans = {item[2]["attributes"]["fabric.source.sequence"]: item for item in handle.sender.items}
    for segment, own in ((SEG_A, (0, 2, 4)), (SEG_B, (1, 3, 5))):
        entries = []
        for seq in own:
            if seq in spans:
                _, _, span, staged = spans[seq]
                content = [d.get("stored_sha256") for d, _ in staged]
                entries.append((seq, record_digest(
                    name=span["name"], start_ns=span["start_time_unix_nano"],
                    end_ns=span["end_time_unix_nano"], status=span["status"],
                    attributes=span["attributes"], content=content)))  # fmt: skip
            else:
                entries.append((seq, "loss:queue_full"))
        marker = by_segment[segment]
        assert marker.seal is not None
        assert marker.seal.seal_digest == reference().seal_digest(entries)
        assert marker.epoch == handle.allocator.epoch
    losses, _ = handle.loss.take(periodic=False)
    assert sum(count for _, (_, _, count) in losses) == 4
    handle.close()
