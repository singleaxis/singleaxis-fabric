# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Sol P0-A round 6 #1: emitted identity provenance never depends on a bounded cache. A
recorder pins the run and source ids it emits for its lifetime; minted ids are returned as
:class:`fabric._sequence.EmittedId` values, recognised by type, so no amount of other
traffic changes an identity a live caller holds; a plain string is always mapped."""

from __future__ import annotations

import copy
import json
import pickle
import threading
from pathlib import Path

import pytest

from fabric._sequence import EmittedId, GeneratedIds, KeyedIds, label_pseudonym
from fabric.byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder
from fabric.call_recorder import CallRecorder
from fabric.content_store.local import LocalFilesystemContentStore

KEY = b"fabric-test-id-key-not-a-secret"
# Sol's reproduction values: run-a / source-a under KEY ...
RUN_A = "r-f6668a736cbbf1357f1265491572327c"
SOURCE_A = "s-a6a49abac37a97419e0e8051ecd05c87"
# ... and the drifted pair it observed after eviction (the mapping of the first pair).
DRIFTED = ("r-5db5dbd499e68e17a827718072afb4aa", "s-e2445b5fb99e683cd81e270ba4bc32a6")
ROLE = "tool.call.result"
CAPACITY = 131_072  # the old registry's capacity (2 x 65536)


def _recorder(tmp_path: Path, key: bytes = KEY) -> ByteEvidenceRecorder:
    store = LocalFilesystemContentStore(str(tmp_path / key.hex()[:8]), tenant_id="tenant-a")
    return ByteEvidenceRecorder(ByteEvidenceConfig(
        store=store, roles=frozenset({ROLE, "tool.call.arguments"}), id_key=key,
        identity_mode="pseudonymous", max_records=1_000_000, queue_max_items=65536,
    ))  # fmt: skip


def _ids(recorder: ByteEvidenceRecorder) -> KeyedIds:
    ids = recorder.emitted_ids
    assert isinstance(ids, KeyedIds)
    return ids


def test_identities_never_change_for_a_live_recorder_after_131073_registrations(
    tmp_path: Path,
) -> None:
    """The review's reproduction at the old registry's real capacity: a CallRecorder for
    run-a / source-a captures, 131,073 other ids go through the shared recorder, and the
    original CallRecorder captures again: its events and its content descriptors carry
    the same run and source ids before and after."""
    recorder = _recorder(tmp_path)
    try:
        calls = CallRecorder(recorder, run_id="run-a", agent_id="agent-a", source_id="source-a")
        assert (calls.run_id, calls.source_id) == (RUN_A, SOURCE_A)
        assert calls.call(b"before", lambda _: b"result") == b"result"
        ids = _ids(recorder)
        for n in range(CAPACITY + 1):  # every one of them was registered before the fix
            if n % 3 == 0:
                ids.run(f"other-{n}", 0)
            elif n % 3 == 1:
                ids.source(f"other-{n}")
            else:
                ids.other(f"other-{n}")
        recorder.capture(b"x", role=ROLE, boundary="tool", source_id="source-b",
                         source_epoch=0, source_sequence=1, run_id="run-b")  # fmt: skip
        assert calls.call(b"after", lambda _: b"result") == b"result"
        snapshot = calls.snapshot()
        events = snapshot["calls"] + snapshot["events"]
        assert len(snapshot["events"]) == 4  # input and output of both calls
        for item in events:
            if "run_id" in item:
                assert item["run_id"] == RUN_A
            if "source_id" in item:
                assert item["source_id"] == SOURCE_A
        settled = [d for d in recorder.drain_settled() if d.get("run_id") == RUN_A]
        assert len(settled) == 4
        assert {(d["run_id"], d["source_id"]) for d in settled} == {(RUN_A, SOURCE_A)}
        assert DRIFTED[0] not in json.dumps(snapshot) and DRIFTED[1] not in json.dumps(snapshot)
    finally:
        assert recorder.close()


def test_a_minted_parent_call_id_joins_from_another_thread(tmp_path: Path) -> None:
    """A minted call id returned to the caller joins as ``parent_call_id`` across threads
    (an explicit parent), however much traffic came in between; its plain-string copy is
    caller input and maps to an ``lbl-`` label."""
    recorder = _recorder(tmp_path)
    try:
        calls = CallRecorder(recorder, run_id="run-a", agent_id="agent-a", source_id="source-a")
        seen: list[str | None] = []

        def parent_call(_: bytes) -> bytes:
            seen.append(calls.current_call_id)
            return b"ok"

        calls.call(b"parent", parent_call)
        (parent,) = seen
        assert isinstance(parent, EmittedId)
        ids = _ids(recorder)
        for n in range(CAPACITY + 1):
            ids.other(f"noise-{n}")
        done: list[bytes] = []
        worker = threading.Thread(target=lambda: done.append(
            calls.call(b"child", lambda _: b"ok", parent_call_id=parent)))  # fmt: skip
        worker.start()
        worker.join(10.0)
        assert done == [b"ok"]
        calls.call(b"plain", lambda _: b"ok", parent_call_id=str(parent))
        parents = [c["parent_call_id"] for c in calls.snapshot()["calls"]]
        assert parents == [None, parent, label_pseudonym("lbl-", str(parent), KEY)]
    finally:
        assert recorder.close()


def test_provenance_is_by_type_and_issuer_never_by_shape(tmp_path: Path) -> None:
    ids, other = KeyedIds(KEY), KeyedIds(b"another-test-id-key-not-secret")
    run = ids.run("run-a", 0)
    assert isinstance(run, EmittedId) and run == RUN_A
    assert ids.run(run, 5) is run  # typed: kept, in any epoch
    assert KeyedIds(KEY).run(run, 0) is run  # any recorder holding the key
    assert ids.run(RUN_A, 0) == DRIFTED[0]  # a plain string is caller input
    assert other.run(run, 0) != run  # another key never emitted it
    for value in (ids.source("source-a"), ids.other("op"), ids.agent("agent"),
                  ids.mint("0f4c2a7e9b1d4e3f")):  # fmt: skip
        assert isinstance(value, EmittedId)
        assert (ids.source(value), ids.other(value), ids.agent(value)) == (value,) * 3
    with pytest.raises(TypeError, match="minted by Fabric"):
        EmittedId(RUN_A, "kid-00000000")
    for clone in (copy.copy(run), copy.deepcopy(run), pickle.loads(pickle.dumps(run))):  # noqa: S301
        assert isinstance(clone, EmittedId) and ids.run(clone, 0) == RUN_A
    assert json.dumps({"run_id": run}) == json.dumps({"run_id": RUN_A})


def test_generated_ids_keep_their_type_and_never_drift() -> None:
    ids = GeneratedIds()
    first = ids.other("op-private")
    assert first.startswith("g-") and isinstance(first, EmittedId)
    for n in range(70_000):  # beyond the remembered values
        ids.other(f"noise-{n}")
    assert ids.other(first) is first
    assert ids.other("op-private") == first  # remembered before the bound was reached
    assert GeneratedIds().other(first) != first  # another instance never generated it
    run = ids.run("run-a", 0)
    assert ids.run(run, 3) is run


@pytest.mark.parametrize("mode", ["pseudonymous", "clear"])
def test_emitted_run_and_source_ids_round_trip_in_both_modes(tmp_path: Path, mode: str) -> None:
    store = LocalFilesystemContentStore(str(tmp_path / mode), tenant_id="tenant-a")
    recorder = ByteEvidenceRecorder(ByteEvidenceConfig(
        store=store, roles=frozenset({ROLE}), id_key=KEY, identity_mode=mode,  # type: ignore[arg-type]
    ))  # fmt: skip
    try:
        run, source = recorder.emitted_run_id("run-a"), recorder.emitted_source_id("source-a")
        expected = (RUN_A, SOURCE_A) if mode == "pseudonymous" else ("run-a", "source-a")
        assert (run, source) == expected
        descriptor = recorder.capture(b"x", role=ROLE, boundary="tool", source_id=source,
                                      source_epoch=0, source_sequence=1, run_id=run)  # fmt: skip
        assert (descriptor["run_id"], descriptor["source_id"]) == expected
    finally:
        assert recorder.close()
