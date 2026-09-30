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


def test_explicit_metadata_seal_survives_restart_without_promoting_trust(
    recording: Any, tmp_path: Path
) -> None:
    writer, store = recording
    spool = _spool(tmp_path)
    first = _recorder(writer, spool)
    first.call(b"PRIVATE input", lambda _: b"PRIVATE output")
    sealed = first.seal_source()
    assert sealed["status"] == "sealed"
    current = first.snapshot()
    assert current["source_metadata_seal"]["source_high_water"] == {"source": 3}
    assert current["source_identity_authenticated"] is False
    assert current["pre_spool_crash_window_unverified"]
    spool.close()
    restarted = _spool(tmp_path)
    try:
        second = _recorder(
            writer, restarted, recovery_resolver=ByteEvidenceResolver(store, tenant_id="tenant")
        )
        recovered = second.recovered_snapshots()[0]
        assert recovered["source_high_water"] == {"source": 3}
        assert recovered["source_observed_high_water"] == {"source": 3}
        assert recovered["source_high_water_basis"] == "sealed_terminal"
        assert recovered["source_unsealed_epoch_ranges"] == []
        assert recovered["recovery_history_unverified"]
        assert recovered["source_identity_authenticated"] is False
        assert "PRIVATE" not in json.dumps(sealed)
    finally:
        restarted.close()


def test_unsealed_empty_epoch_remains_visible(recording: Any, tmp_path: Path) -> None:
    writer, _store = recording
    spool = _spool(tmp_path)
    spool.close()
    restarted = _spool(tmp_path)
    try:
        snapshot = _recorder(writer, restarted).snapshot()
        assert snapshot["recovered_records"] == []
        assert snapshot["source_unsealed_epoch_ranges"] == [{"start": 0, "end": 0}]
        assert snapshot["recovery_history_unverified"]
    finally:
        restarted.close()


def test_sealed_empty_epoch_remains_visible(recording: Any, tmp_path: Path) -> None:
    writer, _store = recording
    spool = _spool(tmp_path)
    assert _recorder(writer, spool).seal_source()["status"] == "sealed"
    spool.close()
    restarted = _spool(tmp_path)
    try:
        recovered = _recorder(writer, restarted).recovered_snapshots()
        assert len(recovered) == 1
        assert recovered[0]["source_high_water"] == {"source": -1}
        assert recovered[0]["source_observed_high_water"] == {}
        assert recovered[0]["events"] == []
        assert recovered[0]["source_high_water_basis"] == "sealed_terminal"
        assert recovered[0]["pre_spool_crash_window_unverified"]
    finally:
        restarted.close()


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -1, True, "bad", 3601])
def test_seal_timeout_is_bounded(recording: Any, tmp_path: Path, timeout: Any) -> None:
    writer, _store = recording
    spool = _spool(tmp_path)
    try:
        assert _recorder(writer, spool).seal_source(timeout_s=timeout) == {
            "status": "refused",
            "reason": "invalid_timeout",
        }
    finally:
        spool.close()


def test_seal_writer_failure_does_not_expose_exception(
    recording: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    writer, _store = recording
    spool = _spool(tmp_path)
    recorder = _recorder(writer, spool)

    def fail(_timeout: float) -> bool:
        raise OSError("PRIVATE credential in underlying storage error")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(writer, "flush", fail)
            result = recorder.seal_source()
        assert result == {"status": "refused", "reason": "source_seal_failed"}
        assert "PRIVATE" not in json.dumps(result)
        assert spool.current_seal() is None
    finally:
        spool.close()


def test_seal_pending_writer_is_not_completed(
    recording: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    writer, _store = recording
    spool = _spool(tmp_path)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(writer, "flush", lambda _timeout: False)
            result = _recorder(writer, spool).seal_source(timeout_s=0)
        assert result == {"status": "refused", "reason": "writers_unsettled"}
        assert spool.current_seal() is None
    finally:
        spool.close()


def test_late_action_after_seal_executes_but_is_a_recording_gap(
    recording: Any, tmp_path: Path
) -> None:
    writer, _store = recording
    spool = _spool(tmp_path)
    recorder = _recorder(writer, spool)
    try:
        recorder.call(b"input", lambda value: value)
        assert recorder.seal_source()["status"] == "sealed"
        result = b"unchanged"
        actual = recorder.call(b"later", lambda _: result)
        assert actual is result
        snapshot = recorder.snapshot()
        assert snapshot["recording_gaps"] > 0
        assert any(event["source_spool_status"] != "spooled" for event in snapshot["starts"])
        assert recorder.seal_source()["status"] == "refused"
    finally:
        spool.close()


def test_seal_refuses_incomplete_stream_and_missing_spool(recording: Any, tmp_path: Path) -> None:
    writer, _store = recording
    without = CallRecorder(writer, run_id="run", agent_id="agent", source_id="source")
    assert without.seal_source() == {"status": "refused", "reason": "source_spool_unavailable"}
    spool = _spool(tmp_path)
    recorder = _recorder(writer, spool)
    stream = recorder.stream(b"request", lambda _: iter((b"one", b"two")))
    try:
        assert next(stream) == b"one"
        assert recorder.seal_source() == {"status": "refused", "reason": "call_incomplete"}
        stream.close()
        assert recorder.seal_source() == {"status": "refused", "reason": "call_incomplete"}
        assert spool.current_seal() is None
    finally:
        stream.close()
        spool.close()


def test_seal_cannot_overtake_inflight_outcome(
    recording: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    writer, _store = recording
    spool = _spool(tmp_path)
    recorder = _recorder(writer, spool)
    reached, release = threading.Event(), threading.Event()
    original = recorder._base
    result: list[bytes] = []

    def paused(call: Any) -> dict[str, Any]:
        if call.ended:
            reached.set()
            if not release.wait(timeout=3):
                raise TimeoutError("test outcome barrier expired")
        return original(call)

    monkeypatch.setattr(recorder, "_base", paused)
    thread = threading.Thread(target=lambda: result.append(recorder.call(b"input", lambda v: v)))
    thread.start()
    try:
        assert reached.wait(timeout=1)
        assert recorder.seal_source() == {"status": "refused", "reason": "call_incomplete"}
        assert spool.current_seal() is None
        release.set()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert result == [b"input"]
        assert recorder.seal_source()["status"] == "sealed"
    finally:
        release.set()
        thread.join(timeout=2)
        spool.close()


def test_seal_refuses_withheld_content_and_known_loss(recording: Any, tmp_path: Path) -> None:
    writer, _store = recording
    spool = _spool(tmp_path)
    recorder = _recorder(writer, spool)
    try:
        recorder.call(b"input", lambda value: value, context=b"withheld context")
        assert recorder.seal_source() == {"status": "refused", "reason": "content_not_stored"}
        recorder._fault()
        assert recorder.seal_source() == {"status": "refused", "reason": "recording_loss"}
        assert spool.current_seal() is None
    finally:
        spool.close()
