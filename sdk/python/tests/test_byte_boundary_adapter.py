# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 042: a byte-call tap preserves the caller's action and marks gaps."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, LocalFilesystemContentStore
from fabric.adapters.byte_boundary import ByteBoundaryAdapter
from fabric.adapters.synthetic_evidence import SyntheticCaptureSession
from fabric.synthetic_reconcile import (
    ExpectedByteObject,
    ExpectedOperation,
    SyntheticByteResolver,
    reconcile_synthetic_run,
)

ROLES = frozenset(
    {
        "interaction.payload",
        "model.request.messages",
        "model.output.messages",
        "tool.call.arguments",
        "tool.call.result",
    }
)


def _session(tmp_path: Path) -> tuple[SyntheticCaptureSession, LocalFilesystemContentStore]:
    store = LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="test-tenant")
    recorder = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=ROLES))
    return SyntheticCaptureSession(recorder, tenant_id="test-tenant", run_id="run-1"), store


def _stored(store: LocalFilesystemContentStore, snapshot: dict[str, Any], role: str) -> list[bytes]:
    return [
        store.read(event["descriptor"]["ref"])
        for event in snapshot["events"]
        if event["role"] == role and event["status"] == "stored"
    ]


def test_exact_model_and_tool_bytes_retries_and_empty_context(tmp_path: Path) -> None:
    session, store = _session(tmp_path)
    model = ByteBoundaryAdapter(session, kind="model", source_id="model-1")
    tool = ByteBoundaryAdapter(session, kind="tool", source_id="tool-1")
    truth: list[bytes] = []

    def model_send(payload: bytes) -> bytes:
        truth.append(payload)
        return b"\x00response\xff" if len(truth) == 1 else b""

    request = b"\x00request\xff"
    first = model.call(
        request,
        model_send,
        operation_id="model-op",
        attempt_id="try-1",
        context=b"",
    )
    second = model.call(
        b"retry",
        model_send,
        operation_id="model-op",
        attempt_id="try-2",
    )
    tool_result = tool.call(
        b"\xffargs\x00",
        lambda data: b"result:" + data,
        operation_id="tool-op",
        attempt_id="try-1",
    )
    assert (first, second, tool_result) == (
        b"\x00response\xff",
        b"",
        b"result:\xffargs\x00",
    )
    assert truth == [request, b"retry"]
    snapshot = session.snapshot()
    assert snapshot["writer_settled"]
    assert _stored(store, snapshot, "interaction.payload") == [b""]
    assert _stored(store, snapshot, "model.request.messages") == truth
    assert _stored(store, snapshot, "model.output.messages") == [first, second]
    assert _stored(store, snapshot, "tool.call.arguments") == [b"\xffargs\x00"]
    assert _stored(store, snapshot, "tool.call.result") == [tool_result]
    assert [item["result_status"] for item in snapshot["operations"]] == ["ok"] * 3
    assert [
        event["attempt_id"]
        for event in snapshot["events"]
        if event["role"] == "model.request.messages"
    ] == ["try-1", "try-2"]
    closed = session.recorder.close()
    assert closed


def test_delegate_exception_and_unsupported_result_preserve_caller_semantics(
    tmp_path: Path,
) -> None:
    session, _store = _session(tmp_path)
    adapter = ByteBoundaryAdapter(session, kind="model", source_id="model-1")
    failure = RuntimeError("original failure")

    def fail(_payload: bytes) -> bytes:
        raise failure

    with pytest.raises(RuntimeError) as caught:
        adapter.call(b"request", fail, operation_id="op-1", attempt_id="try-1")
    assert caught.value is failure
    result = object()
    assert (
        adapter.call(b"request-2", lambda _payload: result, operation_id="op-2", attempt_id="try-1")
        is result
    )
    snapshot = session.snapshot()
    assert [
        (event["role"], event["status"])
        for event in snapshot["events"]
        if event["role"] == "model.output.messages"
    ] == [
        ("model.output.messages", "failed"),
        ("model.output.messages", "unsupported"),
    ]
    assert [item["result_status"] for item in snapshot["operations"]] == ["error", "ok"]
    closed = session.recorder.close()
    assert closed


def test_deferred_result_is_not_mislabeled_as_completed(tmp_path: Path) -> None:
    session, _store = _session(tmp_path)
    adapter = ByteBoundaryAdapter(session, kind="model", source_id="model-1")

    def stream(_payload: bytes) -> Any:
        return iter((b"later",))

    iterator = adapter.call(b"request", stream, operation_id="stream-op", attempt_id="try-1")
    assert next(iterator) == b"later"
    snapshot = session.snapshot()
    assert [operation["result_status"] for operation in snapshot["operations"]] == ["deferred"]
    assert {(event["role"], event["status"]) for event in snapshot["events"]} >= {
        ("model.output.messages", "unsupported"),
    }
    report = reconcile_synthetic_run(
        snapshot,
        [
            ExpectedByteObject(
                "model-1",
                "provider_bound",
                "stream-op",
                "try-1",
                "model.request.messages",
                b"request",
            )
        ],
        SyntheticByteResolver(_store, tenant_id="test-tenant"),
    )
    assert report["verdict"] == "partial"
    assert any(item["kind"] == "incomplete_operation_outcome" for item in report["discrepancies"])
    closed = session.recorder.close()
    assert closed


def test_recorder_failure_does_not_change_delegate_and_bypass_is_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session, store = _session(tmp_path)
    adapter = ByteBoundaryAdapter(session, kind="model", source_id="model-1")
    independent_truth: list[tuple[bytes, bytes]] = []

    def send(payload: bytes) -> bytes:
        reply = b"reply:" + payload
        independent_truth.append((payload, reply))
        return reply

    assert adapter.call(b"seen", send, operation_id="op-1", attempt_id="try-1") == b"reply:seen"
    # Direct call is a route bypass: the independent witness sees it; Fabric
    # does not, and the reconciler must lower the verdict.
    assert send(b"bypass") == b"reply:bypass"
    expected = [
        ExpectedByteObject("model-1", "provider_bound", f"op-{index}", "try-1", role, data)
        for index, (request, response) in enumerate(independent_truth, start=1)
        for role, data in (("model.request.messages", request), ("model.output.messages", response))
    ]
    report = reconcile_synthetic_run(
        session.snapshot(),
        expected,
        SyntheticByteResolver(store, tenant_id="test-tenant"),
        expected_operations=[
            ExpectedOperation("provider_bound", "op-1", "try-1", {"result_status": "ok"})
        ],
    )
    assert report["verdict"] == "partial"
    assert {
        item["role"]
        for item in report["discrepancies"]
        if item["kind"] == "missing_required_object"
    } == {"model.request.messages", "model.output.messages"}

    def broken_capture(*_args: object, **_kwargs: object) -> None:
        raise OSError("content store unavailable")

    monkeypatch.setattr(session.recorder, "capture", broken_capture)
    previous_event_count = len(session.snapshot()["events"])
    assert adapter.call(b"fault", send, operation_id="op-3", attempt_id="try-1") == b"reply:fault"
    failed_events = cast(list[dict[str, Any]], session.snapshot()["events"])
    assert len(failed_events) == previous_event_count + 2
    assert [(event["role"], event["status"]) for event in failed_events[-2:]] == [
        ("model.request.messages", "failed"),
        ("model.output.messages", "failed"),
    ]
    closed = session.recorder.close()
    assert closed


def test_session_capture_exception_falls_back_to_explicit_gaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session, _store = _session(tmp_path)
    adapter = ByteBoundaryAdapter(session, kind="model", source_id="model-1")

    def failed_capture(*_args: object, **_kwargs: object) -> None:
        raise OSError("recording handler failed")

    monkeypatch.setattr(session, "capture", failed_capture)
    assert (
        adapter.call(
            b"input", lambda data: b"output:" + data, operation_id="op-1", attempt_id="try-1"
        )
        == b"output:input"
    )
    snapshot = session.snapshot()
    assert [(item["role"], item["status"]) for item in snapshot["events"]] == [
        ("model.request.messages", "failed"),
        ("model.output.messages", "failed"),
    ]
    assert [operation["result_status"] for operation in snapshot["operations"]] == ["ok"]
    closed = session.recorder.close()
    assert closed
