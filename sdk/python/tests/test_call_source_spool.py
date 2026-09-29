# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Custom call journal restart/readback distinguishes metadata and bytes."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fabric import (
    ByteEvidenceConfig,
    ByteEvidenceRecorder,
    CallRecorder,
    LocalFilesystemContentStore,
)
from fabric.byte_resolver import ByteEvidenceResolver
from fabric.source_spool import SyntheticSourceSpool


@pytest.fixture
def recording(tmp_path: Path) -> Iterator[tuple[ByteEvidenceRecorder, LocalFilesystemContentStore]]:
    store = LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant")
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store,
            roles=frozenset(
                {
                    "model.request.messages",
                    "model.output.messages",
                    "tool.call.arguments",
                    "tool.call.result",
                }
            ),
        )
    )
    yield writer, store
    writer.close()


def _spool(tmp_path: Path, **options: Any) -> SyntheticSourceSpool:
    root = tmp_path / "spool"
    root.mkdir(mode=0o700, exist_ok=True)
    return SyntheticSourceSpool(str(root), tenant_id="tenant", run_id="run", **options)


def _recorder(
    writer: ByteEvidenceRecorder, spool: SyntheticSourceSpool, **options: Any
) -> CallRecorder:
    return CallRecorder(
        writer, run_id="run", agent_id="agent", source_id="source", source_spool=spool, **options
    )


def test_source_journal_restart_exact_content_readback(recording: Any, tmp_path: Path) -> None:
    writer, store = recording
    spool = _spool(tmp_path)
    first = _recorder(writer, spool)
    first.call(b"PRIVATE input", lambda _: b"PRIVATE output", operation_id="op", attempt_id="one")
    first_snapshot = first.snapshot()
    assert first_snapshot["source_epoch_persisted"]
    assert first_snapshot["source_spool_settled"]
    assert first_snapshot["source_spool_health"]["spooled"] == 4
    assert first_snapshot["source_identity_authenticated"] is False
    assert first_snapshot["pre_spool_crash_window_unverified"]
    on_disk = b"".join(path.read_bytes() for path in spool.root.glob("event-*.json"))
    assert b"PRIVATE" not in on_disk
    assert b"file://" not in on_disk
    assert b'"status":"pending"' in on_disk
    spool.close()

    restarted = _spool(tmp_path)
    try:
        second = _recorder(writer, restarted)
        unresolved = second.snapshot()
        assert unresolved["source_epoch"] == 1
        assert {
            event["status"] for event in unresolved["recovered_records"] if "object_id" in event
        } == {"pending"}
        second = _recorder(
            writer, restarted, recovery_resolver=ByteEvidenceResolver(store, tenant_id="tenant")
        )
        recovered = second.recovered_snapshots()
        assert len(recovered) == 1
        assert recovered[0]["source_epoch"] == 0
        assert recovered[0]["calls"][0]["status"] == "ok"
        assert {event["status"] for event in recovered[0]["events"]} == {"stored"}
        assert [event["record_id"] for event in recovered[0]["events"]] == [
            event["record_id"] for event in first_snapshot["events"]
        ]
        value = second.call(b"again", lambda value: value)
        assert value == b"again"
        current = second.snapshot()
        assert current["starts"][0]["source_epoch"] == 1
        assert current["starts"][0]["source_sequence"] == 0
        assert current["recovery_history_unverified"]
    finally:
        restarted.close()


def test_pending_bytes_and_incomplete_stream_survive_restart(
    recording: Any,
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    writer, store = recording
    spool = _spool(tmp_path)
    gate, entered = threading.Event(), threading.Event()
    real_put = type(store).put_bytes_object

    def blocked(self: LocalFilesystemContentStore, descriptor: Any, content: bytes) -> Any:
        entered.set()
        gate.wait(timeout=3)
        return real_put(self, descriptor, content)

    monkeypatch.setattr(type(store), "put_bytes_object", blocked)
    recorder = _recorder(writer, spool)
    stream = recorder.stream(b"request", lambda _: iter((b"first", b"second")), kind="model")
    value = next(stream)
    assert value == b"first"
    entered_signal = entered.wait(timeout=1)
    assert entered_signal
    spool.flush()
    pending = recorder.snapshot(settle_timeout_s=0)
    assert pending["writer_settled"] is False
    assert pending["source_spool_settled"]
    assert {event["status"] for event in pending["events"]} == {"pending"}
    spool.close()
    restarted = _spool(tmp_path)
    try:
        recovered = _recorder(
            writer, restarted, recovery_resolver=ByteEvidenceResolver(store, tenant_id="tenant")
        )
        incomplete = recovered.recovered_snapshots()[0]
        assert incomplete["calls"][0]["status"] == "running"
        assert incomplete["operations"] == []
        assert {event["status"] for event in incomplete["events"]} == {"failed"}
        gate.set()
        writer.flush()
        settled = recovered.recovered_snapshots()[0]
        assert {event["status"] for event in settled["events"]} == {"stored"}
        assert settled["calls"][0]["status"] == "running"
    finally:
        gate.set()
        restarted.close()
        stream.close()


@pytest.mark.parametrize("failure", ["quota", "write", "closed"])
def test_source_journal_failure_preserves_delegate(
    recording: Any,
    tmp_path: Path,
    monkeypatch: Any,
    failure: str,
) -> None:
    writer, _store = recording
    spool = _spool(tmp_path, max_bytes=1 if failure == "quota" else 65536)
    if failure == "write":

        def fail(_: Any) -> int:
            raise OSError("PRIVATE disk failure")

        monkeypatch.setattr(spool, "_write_event", fail)
    elif failure == "closed":
        spool.close()
    recorder = _recorder(writer, spool)
    called = []
    response = b"result"

    def delegate(payload: bytes) -> bytes:
        called.append(payload)
        return response

    actual = recorder.call(b"input", delegate)
    assert actual is response
    assert called == [b"input"]
    snapshot = recorder.snapshot()
    assert snapshot["calls"][0]["status"] == "ok"
    health = snapshot["source_spool_health"]
    assert health["failed"] + health["dropped"] == 4
    assert "PRIVATE" not in json.dumps(snapshot)
    if failure != "closed":
        spool.close()


def test_source_identity_and_corrupt_content_recovery(recording: Any, tmp_path: Path) -> None:
    writer, store = recording
    spool = _spool(tmp_path)
    with pytest.raises(ValueError, match="tenant/run"):
        CallRecorder(
            writer, run_id="other", agent_id="agent", source_id="source", source_spool=spool
        )
    recorder = _recorder(writer, spool)
    recorder.call(b"input", lambda _: b"output")
    snapshot = recorder.snapshot()
    Path(snapshot["events"][0]["descriptor"]["ref"].removeprefix("file://")).write_bytes(b"corrupt")
    spool.close()
    restarted = _spool(tmp_path)
    try:
        recovered = _recorder(
            writer, restarted, recovery_resolver=ByteEvidenceResolver(store, tenant_id="tenant")
        )
        snapshot = recovered.recovered_snapshots()[0]
        assert snapshot["events"][0]["status"] == "failed"
        assert snapshot["events"][1]["status"] == "stored"
    finally:
        restarted.close()


def test_source_queue_overflow_does_not_wait_for_disk(
    recording: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    writer, _store = recording
    spool = _spool(tmp_path, queue_max_items=1)
    gate, entered = threading.Event(), threading.Event()
    write = spool._write_event

    def blocked(event: Any) -> int:
        entered.set()
        gate.wait(timeout=3)
        return write(event)

    monkeypatch.setattr(spool, "_write_event", blocked)
    recorder = _recorder(writer, spool)
    try:
        result = recorder.call(b"q", lambda _: b"answer")
        assert result == b"answer"
        assert not gate.is_set()
        entered_signal = entered.wait(timeout=1)
        assert entered_signal
        pending = recorder.snapshot(settle_timeout_s=0)
        assert pending["source_spool_settled"] is False
        assert pending["source_spool_health"]["dropped"] > 0
        assert pending["recording_gaps"] > 0
    finally:
        gate.set()
        spool.close()
