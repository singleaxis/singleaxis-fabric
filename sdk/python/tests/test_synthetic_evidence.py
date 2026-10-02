# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Bounded synthetic adapters: compare observations with independent truth."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import pytest

from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, LocalFilesystemContentStore
from fabric.adapters.synthetic_evidence import (
    AllowlistedArtifactObserver,
    BoundedTerminalAdapter,
    ControlledHTTPModelAdapter,
    SyntheticCaptureSession,
)
from fabric.source_spool import SyntheticSourceSpool
from fabric.synthetic_otlp import project_synthetic_snapshot
from fabric.synthetic_reconcile import (
    ExpectedByteObject,
    ExpectedOperation,
    SyntheticByteResolver,
    reconcile_synthetic_run,
)

ROLES = frozenset(
    {
        "model.request.messages",
        "model.output.messages",
        "terminal.argv",
        "terminal.stdin",
        "terminal.stdout",
        "terminal.stderr",
        "interaction.payload",
        "artifact.before",
        "artifact.after",
    }
)


def _session(
    tmp_path: Path,
    *,
    payload_max_bytes: int = 1024 * 1024,
    source_spool: SyntheticSourceSpool | None = None,
) -> tuple[SyntheticCaptureSession, LocalFilesystemContentStore]:
    store = LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="synthetic-tenant")
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(store=store, roles=ROLES, payload_max_bytes=payload_max_bytes)
    )
    return SyntheticCaptureSession(
        recorder, tenant_id="synthetic-tenant", run_id="run-1", source_spool=source_spool
    ), store


def _events(session: SyntheticCaptureSession) -> list[dict[str, Any]]:
    snapshot = session.snapshot()
    assert snapshot["writer_settled"]
    return cast(list[dict[str, Any]], snapshot["events"])


def _close_recorder(session: SyntheticCaptureSession) -> None:
    closed = session.recorder.close()
    assert closed


def _close_spool(spool: SyntheticSourceSpool) -> None:
    closed = spool.close()
    assert closed


def _bytes_for(
    store: LocalFilesystemContentStore, events: list[dict[str, Any]], role: str
) -> list[bytes]:
    return [
        store.read(item["descriptor"]["ref"])
        for item in events
        if item["role"] == role and item["status"] == "stored"
    ]


def _provider_context(port: int, body: bytes) -> bytes:
    return json.dumps(
        {
            "method": "POST",
            "scheme": "http",
            "host": "127.0.0.1",
            "port": port,
            "path": "/model",
            "content_type": "application/octet-stream",
            "content_length": len(body),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_controlled_provider_records_exact_wire_body_and_direct_bypass_is_not_claimed(
    tmp_path: Path,
) -> None:
    session, store = _session(tmp_path)
    truth: list[bytes] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            truth.append(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"\x00reply\xff")

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/model"
        adapter = ControlledHTTPModelAdapter(session, endpoint)
        status, response = adapter.post(
            b"\x00request\xff", operation_id="model-1", attempt_id="try-1"
        )
        assert (status, response) == (200, b"\x00reply\xff")
        retry_status, retry_response = adapter.post(
            b"retry", operation_id="model-1", attempt_id="try-2"
        )
        assert (retry_status, retry_response) == (200, response)
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
        connection.request("POST", "/model", body=b"bypass")
        assert connection.getresponse().status == 200
        connection.close()
        events = _events(session)
        assert truth == [b"\x00request\xff", b"retry", b"bypass"]
        assert _bytes_for(store, events, "model.request.messages") == truth[:2]
        assert _bytes_for(store, events, "model.output.messages") == [response, retry_response]
        assert _bytes_for(store, events, "interaction.payload") == [
            _provider_context(server.server_port, truth[0]),
            _provider_context(server.server_port, truth[1]),
        ]
        snapshot = session.snapshot()
        assert sorted(
            item["source_sequence"] for item in [*snapshot["events"], *snapshot["operations"]]
        ) == list(range(8))
        assert [event["attempt_id"] for event in events] == ["try-1"] * 3 + ["try-2"] * 3
        assert session.snapshot()["source_identity_authenticated"] is False
    finally:
        server.shutdown()
        server.server_close()
        session.recorder.close()


def test_recorder_write_failure_does_not_change_provider_or_terminal_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session, _store = _session(tmp_path)
    truth: list[bytes] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            truth.append(body)
            self.send_response(201)
            self.end_headers()
            self.wfile.write(b"provider-result\x00")

        def log_message(self, *_args: object) -> None:
            pass

    def failed_capture(*_args: object, **_kwargs: object) -> None:
        raise OSError("synthetic content-store failure")

    monkeypatch.setattr(session.recorder, "capture", failed_capture)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        provider = ControlledHTTPModelAdapter(
            session, f"http://127.0.0.1:{server.server_port}/model"
        )
        assert provider.post(
            b"request\xff", operation_id="model-fault", attempt_id="attempt-1"
        ) == (201, b"provider-result\x00")
        assert truth == [b"request\xff"]

        root = tmp_path / "work"
        root.mkdir()
        terminal = BoundedTerminalAdapter(session, allowed_cwd_root=str(root))
        program = "\n".join(
            (
                "import sys",
                "sys.stdout.buffer.write(b'output\\x00')",
                "sys.stderr.buffer.write(b'error\\xff')",
            )
        )
        result = terminal.run(
            [sys.executable, "-c", program],
            cwd=str(root),
            stdin=b"input\x00",
            operation_id="terminal-fault",
            attempt_id="attempt-1",
        )
        assert (result.returncode, result.stdout, result.stderr) == (
            0,
            b"output\x00",
            b"error\xff",
        )
        snapshot = session.snapshot()
        assert snapshot["events"]
        assert all(event["status"] == "failed" for event in snapshot["events"])
    finally:
        server.shutdown()
        server.server_close()
        session.recorder.close()


def test_terminal_and_artifact_exact_binary_bytes_and_empty_stream(tmp_path: Path) -> None:
    session, store = _session(tmp_path)
    root = tmp_path / "work"
    root.mkdir()
    artifact = root / "out.bin"
    observer = AllowlistedArtifactObserver(session, root=str(root), relative_paths=["out.bin"])
    assert observer.observe(phase="before", operation_id="tool-1", attempt_id="try-1") == {
        "out.bin": False
    }
    script = (
        "import pathlib,sys; data=sys.stdin.buffer.read(); "
        "pathlib.Path('out.bin').write_bytes(data+b'\\x00artifact'); "
        "sys.stdout.buffer.write(b'\\xffout'); "
        "sys.stderr.buffer.write(b'\\x00err')"
    )
    adapter = BoundedTerminalAdapter(session, allowed_cwd_root=str(root), chunk_bytes=2)
    result = adapter.run(
        [sys.executable, "-c", script],
        cwd=str(root),
        stdin=b"\x00\xff",
        operation_id="tool-1",
        attempt_id="try-1",
    )
    assert result.returncode == 0
    assert result.stdout == b"\xffout" and result.stderr == b"\x00err"
    assert artifact.read_bytes() == b"\x00\xff\x00artifact"
    assert observer.observe(phase="after", operation_id="tool-1", attempt_id="try-1") == {
        "out.bin": True
    }
    events = _events(session)
    assert b"".join(_bytes_for(store, events, "terminal.stdin")) == b"\x00\xff"
    assert b"".join(_bytes_for(store, events, "terminal.stdout")) == result.stdout
    assert b"".join(_bytes_for(store, events, "terminal.stderr")) == result.stderr
    assert _bytes_for(store, events, "artifact.after") == [artifact.read_bytes()]
    assert not any(
        event["role"] == "artifact.before" and event["status"] == "stored" for event in events
    )
    assert all(
        item["descriptor"]["stored_sha256"]
        == "sha256:" + hashlib.sha256(store.read(item["descriptor"]["ref"])).hexdigest()
        for item in events
        if item["status"] == "stored"
    )
    assert [
        item["source_sequence"] for item in events if item["source_id"] == "terminal-1"
    ] == list(range(sum(item["source_id"] == "terminal-1" for item in events)))
    assert result.observed_stream_order
    _close_recorder(session)


def test_terminal_overflow_and_cancel_are_explicit_and_do_not_change_action(tmp_path: Path) -> None:
    session, store = _session(tmp_path)
    root = tmp_path / "work"
    root.mkdir()
    adapter = BoundedTerminalAdapter(
        session, allowed_cwd_root=str(root), chunk_bytes=4, max_capture_output_bytes=4
    )
    result = adapter.run(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'123456789')"],
        cwd=str(root),
        stdin=b"",
        operation_id="tool-2",
        attempt_id="try-2",
    )
    assert result.returncode == 0 and result.stdout == b"123456789"
    events = _events(session)
    assert any(
        item["role"] == "terminal.stdout" and item["status"] == "truncated" for item in events
    )
    assert _bytes_for(store, events, "terminal.stdin") == [b""]
    cancel = threading.Event()
    cancel.set()
    cancelled = adapter.run(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        cwd=str(root),
        stdin=b"",
        operation_id="tool-3",
        attempt_id="try-3",
        timeout_s=10,
        cancel=cancel,
    )
    assert cancelled.timed_out and cancelled.returncode != 0
    _close_recorder(session)


def test_artifact_symlink_and_oversize_are_gaps(tmp_path: Path) -> None:
    session, _store = _session(tmp_path)
    root = tmp_path / "work"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"secret")
    observer = AllowlistedArtifactObserver(
        session, root=str(root), relative_paths=["out.bin"], max_bytes=3
    )
    (root / "out.bin").symlink_to(outside)
    assert observer.observe(phase="after", operation_id="tool-4", attempt_id="try-4") == {
        "out.bin": False
    }
    (root / "out.bin").unlink()
    (root / "out.bin").write_bytes(b"four")
    assert observer.observe(phase="after", operation_id="tool-4", attempt_id="try-4") == {
        "out.bin": True
    }
    statuses = [item["status"] for item in _events(session)]
    assert statuses == ["unsupported", "truncated"]
    _close_recorder(session)


def test_artifact_modification_and_privacy_canary_stay_in_content_store(tmp_path: Path) -> None:
    session, store = _session(tmp_path)
    root = tmp_path / "work"
    root.mkdir()
    canary = b"synthetic-secret-canary-\x00\xff"
    artifact = root / "out.bin"
    artifact.write_bytes(b"old")
    observer = AllowlistedArtifactObserver(session, root=str(root), relative_paths=["out.bin"])
    observer.observe(phase="before", operation_id="tool-5", attempt_id="try-5")
    artifact.write_bytes(canary)
    observer.observe(phase="after", operation_id="tool-5", attempt_id="try-5")
    snapshot = session.snapshot()
    assert _bytes_for(store, snapshot["events"], "artifact.before") == [b"old"]
    assert _bytes_for(store, snapshot["events"], "artifact.after") == [canary]
    assert canary not in json.dumps(snapshot).encode()
    _close_recorder(session)


def test_rejects_remote_endpoint_and_cwd_escape(tmp_path: Path) -> None:
    session, _store = _session(tmp_path)
    with pytest.raises(ValueError, match="loopback"):
        ControlledHTTPModelAdapter(session, "https://example.com/model")
    root = tmp_path / "work"
    root.mkdir()
    adapter = BoundedTerminalAdapter(session, allowed_cwd_root=str(root))
    with pytest.raises(ValueError, match="approved root"):
        adapter.run(
            [sys.executable, "-c", "pass"],
            cwd=str(tmp_path),
            stdin=b"",
            operation_id="x",
            attempt_id="x",
        )
    _close_recorder(session)


def test_authorized_resolution_and_reconciliation_never_false_complete(tmp_path: Path) -> None:
    session, store = _session(tmp_path)
    session.capture(
        b"\x00exact\xff",
        source_id="provider-http-1",
        boundary="provider_bound",
        role="model.request.messages",
        operation_id="model-1",
        attempt_id="try-1",
    )
    snapshot = session.snapshot()
    descriptor = snapshot["events"][0]["descriptor"]
    resolver = SyntheticByteResolver(store, tenant_id="synthetic-tenant")
    assert resolver.resolve(descriptor).data == b"\x00exact\xff"
    assert resolver.resolve({**descriptor, "tenant_id": "other"}).status == "denied"
    assert resolver.resolve({**descriptor, "ref": descriptor["ref"] + "?x=1"}).status == "denied"
    expected = [
        ExpectedByteObject(
            "provider-http-1",
            "provider_bound",
            "model-1",
            "try-1",
            "model.request.messages",
            b"\x00exact\xff",
        )
    ]
    report = reconcile_synthetic_run(snapshot, expected, resolver)
    assert report["verdict"] == "unverified"
    assert report["discrepancies"] == []
    assert not report["complete_verdict_available"]
    bypass = ExpectedByteObject(
        "provider-http-1",
        "provider_bound",
        "model-2",
        "try-2",
        "model.request.messages",
        b"bypass",
    )
    report = reconcile_synthetic_run(snapshot, [*expected, bypass], resolver)
    assert report["verdict"] == "partial"
    assert any(row["kind"] == "missing_required_object" for row in report["discrepancies"])
    uri = descriptor["ref"]
    Path(urlsplit(uri).path).write_bytes(b"tampered")
    assert resolver.resolve(descriptor).status == "corrupted"
    assert reconcile_synthetic_run(snapshot, expected, resolver)["verdict"] == "partial"
    _close_recorder(session)


def test_source_spool_stage_recovery_and_quota_loss_lower_verdict(tmp_path: Path) -> None:
    root = tmp_path / "source-spool"
    root.mkdir(mode=0o700)
    spool = SyntheticSourceSpool(str(root), tenant_id="synthetic-tenant", run_id="run-1")
    session, _store = _session(tmp_path, source_spool=spool)
    session.capture(
        b"source-byte",
        source_id="provider-http-1",
        boundary="provider_bound",
        role="model.request.messages",
        operation_id="model-1",
        attempt_id="try-1",
    )
    session.outcome(
        source_id="provider-http-1",
        boundary="provider_bound",
        operation_id="model-1",
        attempt_id="try-1",
        http_status=200,
    )
    snapshot = session.snapshot()
    assert snapshot["source_epoch_persisted"]
    assert snapshot["source_spool_settled"]
    assert [
        item["source_spool_status"] for item in [*snapshot["events"], *snapshot["operations"]]
    ] == ["spooled", "spooled"]
    assert snapshot["pre_spool_crash_window_unverified"]
    _close_recorder(session)
    _close_spool(spool)
    recovered = SyntheticSourceSpool(str(root), tenant_id="synthetic-tenant", run_id="run-1")
    assert recovered.epoch == 1
    assert [item["role"] for item in recovered.recovered()] == [
        "model.request.messages",
        "operation.outcome",
    ]
    _close_spool(recovered)
    quota_root = tmp_path / "quota-spool"
    quota_root.mkdir(mode=0o700)
    quota = SyntheticSourceSpool(
        str(quota_root), tenant_id="synthetic-tenant", run_id="run-1", max_bytes=1
    )
    second, second_store = _session(tmp_path / "second", source_spool=quota)
    second.capture(
        b"source-byte",
        source_id="provider-http-1",
        boundary="provider_bound",
        role="model.request.messages",
        operation_id="model-1",
        attempt_id="try-1",
    )
    limited = second.snapshot()
    assert limited["events"][0]["source_spool_status"] == "dropped"
    report = reconcile_synthetic_run(
        limited,
        [
            ExpectedByteObject(
                "provider-http-1",
                "provider_bound",
                "model-1",
                "try-1",
                "model.request.messages",
                b"source-byte",
            )
        ],
        SyntheticByteResolver(second_store, tenant_id="synthetic-tenant"),
    )
    assert report["verdict"] == "partial"
    assert any(row["kind"] == "source_spool_gap" for row in report["discrepancies"])
    _close_recorder(second)
    _close_spool(quota)


def test_unapproved_outcome_field_is_a_gap_not_a_metadata_secret(tmp_path: Path) -> None:
    root = tmp_path / "source-spool"
    root.mkdir(mode=0o700)
    spool = SyntheticSourceSpool(str(root), tenant_id="synthetic-tenant", run_id="run-1")
    session, _store = _session(tmp_path, source_spool=spool)
    session.outcome(
        source_id="provider-http-1",
        boundary="provider_bound",
        operation_id="model-1",
        attempt_id="try-1",
        unapproved_field="secret-canary",
    )
    snapshot = session.snapshot()
    assert snapshot["operations"] == []
    assert snapshot["events"][0]["status"] == "unsupported"
    assert b"secret-canary" not in json.dumps(snapshot).encode()
    assert b"secret-canary" not in b"".join(
        path.read_bytes() for path in root.iterdir() if path.is_file()
    )
    _close_recorder(session)
    _close_spool(spool)


def test_local_shadow_pilot_reconciles_two_models_terminal_and_artifact(tmp_path: Path) -> None:
    session, store = _session(tmp_path)
    endpoint_truth: list[bytes] = []
    reply = b"\x00model-reply\xff"

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            endpoint_truth.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    root = tmp_path / "work"
    root.mkdir()
    try:
        model = ControlledHTTPModelAdapter(session, f"http://127.0.0.1:{server.server_port}/model")
        assert model.post(b"start\x00", operation_id="model-1", attempt_id="try-1") == (200, reply)
        observer = AllowlistedArtifactObserver(session, root=str(root), relative_paths=["out.bin"])
        assert observer.observe(phase="before", operation_id="tool-1", attempt_id="try-1") == {
            "out.bin": False
        }
        script = (
            "import pathlib,sys; data=sys.stdin.buffer.read(); "
            "pathlib.Path('out.bin').write_bytes(data+b'\\xff'); "
            "sys.stdout.buffer.write(b'done\\x00')"
        )
        argv = [sys.executable, "-c", script]
        stdin = b"artifact\x00"
        terminal = BoundedTerminalAdapter(session, allowed_cwd_root=str(root))
        result = terminal.run(
            argv,
            cwd=str(root),
            stdin=stdin,
            operation_id="tool-1",
            attempt_id="try-1",
        )
        assert result.returncode == 0
        assert result.stdout == b"done\x00" and result.stderr == b""
        assert observer.observe(phase="after", operation_id="tool-1", attempt_id="try-1") == {
            "out.bin": True
        }
        artifact_truth = (root / "out.bin").read_bytes()
        assert artifact_truth == stdin + b"\xff"
        assert model.post(artifact_truth, operation_id="model-2", attempt_id="try-1") == (
            200,
            reply,
        )
        assert endpoint_truth == [b"start\x00", artifact_truth]
        expected = [
            ExpectedByteObject(
                "provider-http-1",
                "provider_bound",
                "model-1",
                "try-1",
                "interaction.payload",
                _provider_context(server.server_port, endpoint_truth[0]),
            ),
            ExpectedByteObject(
                "provider-http-1",
                "provider_bound",
                "model-1",
                "try-1",
                "model.request.messages",
                endpoint_truth[0],
            ),
            ExpectedByteObject(
                "provider-http-1",
                "provider_bound",
                "model-1",
                "try-1",
                "model.output.messages",
                reply,
            ),
            ExpectedByteObject(
                "terminal-1",
                "terminal",
                "tool-1",
                "try-1",
                "terminal.argv",
                b"\x00".join(os.fsencode(item) for item in argv) + b"\x00",
            ),
            ExpectedByteObject(
                "terminal-1",
                "terminal",
                "tool-1",
                "try-1",
                "interaction.payload",
                json.dumps(
                    {"cwd": str(root.resolve()), "approved_env": {}},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode(),
            ),
            ExpectedByteObject(
                "terminal-1", "terminal", "tool-1", "try-1", "terminal.stdin", stdin
            ),
            ExpectedByteObject(
                "terminal-1", "terminal", "tool-1", "try-1", "terminal.stdout", result.stdout
            ),
            ExpectedByteObject("terminal-1", "terminal", "tool-1", "try-1", "terminal.stderr", b""),
            ExpectedByteObject(
                "artifact-1", "tool", "tool-1", "try-1", "artifact.after", artifact_truth
            ),
            ExpectedByteObject(
                "provider-http-1",
                "provider_bound",
                "model-2",
                "try-1",
                "interaction.payload",
                _provider_context(server.server_port, endpoint_truth[1]),
            ),
            ExpectedByteObject(
                "provider-http-1",
                "provider_bound",
                "model-2",
                "try-1",
                "model.request.messages",
                endpoint_truth[1],
            ),
            ExpectedByteObject(
                "provider-http-1",
                "provider_bound",
                "model-2",
                "try-1",
                "model.output.messages",
                reply,
            ),
        ]
        expected_operations = [
            ExpectedOperation("provider_bound", "model-1", "try-1", {"http_status": 200}),
            ExpectedOperation(
                "tool",
                "tool-1",
                "try-1",
                {"artifact_phase": "before", "artifact_present": False},
            ),
            ExpectedOperation("terminal", "tool-1", "try-1", {"returncode": 0, "timed_out": False}),
            ExpectedOperation(
                "tool",
                "tool-1",
                "try-1",
                {
                    "artifact_size": len(artifact_truth),
                    "artifact_phase": "after",
                    "artifact_present": True,
                },
            ),
            ExpectedOperation("provider_bound", "model-2", "try-1", {"http_status": 200}),
        ]
        snapshot = session.snapshot()
        report = reconcile_synthetic_run(
            snapshot,
            expected,
            SyntheticByteResolver(store, tenant_id="synthetic-tenant"),
            expected_operations=expected_operations,
        )
        assert report["discrepancies"] == []
        assert report["verdict"] == "unverified"
        payload, projected_ids = project_synthetic_snapshot(snapshot)
        assert len(projected_ids) == len(expected) == 12
        assert set(projected_ids) == {event["record_id"] for event in snapshot["events"]}
        projected = json.loads(payload)["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        assert len(projected) == 12
        for record, event in zip(projected, snapshot["events"], strict=True):
            attrs = {item["key"]: item["value"] for item in record["attributes"]}
            descriptor = event["descriptor"]
            assert attrs["role"]["stringValue"] == event["role"]
            assert attrs["status"]["stringValue"] == "stored"
            assert attrs["content_object_id"]["stringValue"] == descriptor["object_id"]
            assert attrs["content_sha256"]["stringValue"] == descriptor["stored_sha256"]
            assert record["eventName"] == (
                "agent.evidence.artifact"
                if event["role"].startswith("artifact.")
                else "agent.evidence.content"
            )
        for forbidden in (
            b"start\x00",
            b"artifact\x00",
            str(root).encode(),
            os.fsencode(sys.executable),
        ):
            assert forbidden not in payload
    finally:
        server.shutdown()
        server.server_close()
        session.recorder.close()


@pytest.mark.parametrize("cancel_requested", [False, True])
def test_terminal_deadline_after_child_closes_pipes(tmp_path: Path, cancel_requested: bool) -> None:
    session, _ = _session(tmp_path)
    adapter = BoundedTerminalAdapter(session, allowed_cwd_root=str(tmp_path))
    cancel = threading.Event()
    timer = threading.Timer(0.1, cancel.set)
    if cancel_requested:
        timer.start()
    try:
        result = adapter.run(
            [
                sys.executable,
                "-c",
                "import os,time; os.close(0); os.close(1); os.close(2); time.sleep(0.7)",
            ],
            cwd=str(tmp_path),
            stdin=b"",
            operation_id="closed-pipes",
            attempt_id="attempt-1",
            timeout_s=10 if cancel_requested else 0.1,
            cancel=cancel,
        )
        assert result.timed_out
        assert result.returncode < 0
    finally:
        timer.cancel()
        if cancel_requested:
            timer.join()
        _close_recorder(session)
