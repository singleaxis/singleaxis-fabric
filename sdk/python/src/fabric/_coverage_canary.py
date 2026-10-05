# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Real loopback routing, with fixture-only receiving-side observations.

This deliberately does not issue production receipts. The receiving witness
shares this process and is not an independent production trust authority.
"""

from __future__ import annotations

import hashlib
import http.client
import tempfile
import threading
from collections.abc import Iterator
from contextlib import ExitStack
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from opentelemetry import trace

from ._version import __version__
from .byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder
from .call_otlp import project_call_snapshot
from .call_recorder import CallRecorder
from .content_store.local import LocalFilesystemContentStore
from .source_spool import SyntheticSourceSpool

_CHUNKS = (b"first\x00\n", b"second\xff\n", b"last\n")
_REQUEST = b"fixture-request\x00\xff"
_RESPONSE = b"fixture-response\xff"


class _RetryableFixtureError(Exception):
    pass


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _handler(observations: list[dict[str, Any]]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            attempt = self.headers.get("X-Fabric-Canary-Attempt", "unknown")
            status = (
                HTTPStatus.SERVICE_UNAVAILABLE
                if attempt in {"retry-1", "hidden-1"}
                else HTTPStatus.OK
            )
            chunks = _CHUNKS if self.path == "/stream" else (_RESPONSE,)
            observations.append(
                {
                    "attempt_id": attempt,
                    "request_sha256": _sha(body),
                    "response_sha256": [_sha(chunk) for chunk in chunks]
                    if status == HTTPStatus.OK
                    else [],
                    "status": status,
                }
            )
            self.send_response(status)
            self.send_header("Content-Length", str(sum(map(len, chunks))))
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(chunk)
                self.wfile.flush()

        def log_message(self, _format: str, *args: Any) -> None:
            # The fixture never emits request paths, headers or bodies to logs.
            return

    return Handler


def _request(port: int, attempt: str, body: bytes, *, stream: bool = False) -> Iterator[bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            "/stream" if stream else "/call",
            body,
            {"X-Fabric-Canary-Attempt": attempt},
        )
        response = connection.getresponse()
        if response.status != HTTPStatus.OK:
            response.read()
            raise _RetryableFixtureError
        if stream:
            while chunk := response.readline():
                yield chunk
        else:
            yield response.read()
    finally:
        connection.close()


def _execute(
    recorder: CallRecorder,
    port: int,
) -> dict[str, bool]:
    def call(attempt: str, body: bytes) -> bytes:
        return b"".join(_request(port, attempt, body))

    result = recorder.call(
        _REQUEST,
        lambda body: call("call-1", body),
        operation_id="call",
        attempt_id="call-1",
    )
    stream = recorder.stream(
        _REQUEST,
        lambda body: _request(port, "stream-1", body, stream=True),
        operation_id="stream",
        attempt_id="stream-1",
    )
    chunks = list(stream)
    failed = False
    try:
        recorder.call(
            _REQUEST,
            lambda body: call("retry-1", body),
            operation_id="retry",
            attempt_id="retry-1",
        )
    except _RetryableFixtureError:
        failed = True
    retry = recorder.call(
        _REQUEST,
        lambda body: call("retry-2", body),
        operation_id="retry",
        attempt_id="retry-2",
    )
    # Negative controls execute real requests. They cannot be made complete by
    # the fact that the well-instrumented calls above succeeded.
    bypass = call("bypass-1", _REQUEST)

    def hidden_retry(body: bytes) -> bytes:
        try:
            call("hidden-1", body)
        except _RetryableFixtureError:
            return call("hidden-2", body)
        raise RuntimeError("fixture retry did not occur")

    hidden = recorder.call(
        _REQUEST,
        hidden_retry,
        operation_id="hidden",
        attempt_id="hidden-wrapper",
    )
    return {
        "call_result_preserved": result == _RESPONSE,
        "stream_chunks_preserved": chunks == list(_CHUNKS),
        "retry_failure_preserved": failed,
        "retry_result_preserved": retry == _RESPONSE,
        "bypass_result_preserved": bypass == _RESPONSE,
        "hidden_retry_result_preserved": hidden == _RESPONSE,
    }


def _evaluate(
    snapshot: dict[str, Any],
    observations: list[dict[str, Any]],
    store: LocalFilesystemContentStore,
    seal: dict[str, Any],
    spool: SyntheticSourceSpool,
    action_checks: dict[str, bool],
) -> dict[str, Any]:
    calls = {call["attempt_id"]: call for call in snapshot["calls"]}
    native = {row["attempt_id"]: row for row in observations}
    positives = {"call-1", "stream-1", "retry-1", "retry-2"}
    missing = sorted(set(native) - set(calls))
    unexpected = sorted(set(calls) - set(native))
    exact = True
    for attempt in positives:
        events = [row for row in snapshot["events"] if row["attempt_id"] == attempt]
        inputs = [row for row in events if row["role"] == "tool.call.arguments"]
        outputs = [row for row in events if row["role"] == "tool.call.result"]
        exact &= len(inputs) == 1 and store.read(inputs[0]["descriptor"]["ref"]) == _REQUEST
        expected = (
            [] if attempt == "retry-1" else list(_CHUNKS) if attempt == "stream-1" else [_RESPONSE]
        )
        exact &= [store.read(row["descriptor"]["ref"]) for row in outputs] == expected
        exact &= native[attempt]["request_sha256"] == _sha(_REQUEST)
        exact &= native[attempt]["response_sha256"] == [_sha(item) for item in expected]
        exact &= calls[attempt]["status"] == ("error" if attempt == "retry-1" else "ok")
    records = [*snapshot["starts"], *snapshot["events"], *snapshot["operations"]]
    _, projected_ids = project_call_snapshot(snapshot)
    readback = spool.readback_sealed_epoch(0) if seal["status"] == "sealed" else {}
    readback_events = readback.get("records", [])
    checks = {
        **action_checks,
        "routed_calls_reconciled": positives <= set(native) and positives <= set(calls),
        "exact_original_fixture_bytes": exact,
        "deliberate_bypass_detected": "bypass-1" in missing,
        "hidden_physical_retry_detected": {"hidden-1", "hidden-2"} <= set(missing),
        "false_complete_refused": bool(missing or unexpected),
        "recording_loss_absent": snapshot["recording_gaps"] == 0
        and snapshot["unretained_drops"] == 0,
        "writers_settled": snapshot["writer_settled"] and snapshot["source_spool_settled"],
        "source_metadata_fsync_readback": {row["record_id"] for row in readback_events}
        == {row["record_id"] for row in records}
        and seal["status"] == "sealed",
        "bounded_projection_exact_ids": set(projected_ids) == {row["record_id"] for row in records},
    }
    return {
        "schema_version": "fabric.routed-fixture-canary/v1",
        "status": "PASS" if all(checks.values()) else "FAIL",
        "integration": "fabric.call_recorder",
        "fabric_version": __version__,
        "boundary": "stdlib_loopback_http_fixture/v1",
        "checks": checks,
        "native_physical_attempts": len(observations),
        "recorded_logical_attempts": len(calls),
        "missing_physical_attempts": missing,
        "unmatched_wrapper_attempts": unexpected,
        "projected_records": len(records),
        "full_route_coverage_complete": False,
        "production_qualified": False,
        "witness_independence": "same_process_fixture_only",
        "source_scope": {"source_count": 1, "source_epoch": 0},
        "privacy_profile": "synthetic_fixture_original_bytes_only",
        "deployment_privacy_policy_exercised": False,
        "limits": [
            "Only explicit dispatcher boundaries are observed",
            "Line-delimited fixture chunks are not arbitrary provider protocol chunks",
            "The fixture witness is not an independent production authority",
            "No TLS, cloud encryption, destination receipts or crash qualification",
        ],
    }


def run_fixture_canary(*, root: str | None = None) -> dict[str, Any]:
    """Exercise calls, streams, physical retries and bypasses over actual localhost HTTP."""
    observations: list[dict[str, Any]] = []
    with (
        tempfile.TemporaryDirectory(prefix="fabric-canary-", dir=root) as temporary,
        ExitStack() as cleanup,
    ):
        work = Path(temporary)
        spool_root = work / "spool"
        spool_root.mkdir(mode=0o700)
        store = LocalFilesystemContentStore(str(work / "bytes"), tenant_id="fixture")
        writer = ByteEvidenceRecorder(
            ByteEvidenceConfig(
                store=store,
                roles=frozenset({"tool.call.arguments", "tool.call.result"}),
            )
        )
        cleanup.callback(writer.close)
        spool = SyntheticSourceSpool(str(spool_root), tenant_id="fixture", run_id="canary")
        cleanup.callback(spool.close)
        server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(observations))
        cleanup.callback(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        cleanup.callback(thread.join, timeout=5)
        cleanup.callback(server.shutdown)
        recorder = CallRecorder(
            writer,
            run_id="canary",
            agent_id="fixture",
            source_id="fixture-source",
            source_spool=spool,
            tracer=trace.NoOpTracerProvider().get_tracer("fixture"),
        )
        checks = _execute(recorder, server.server_port)
        snapshot = recorder.snapshot()
        seal = recorder.seal_source()
        return _evaluate(snapshot, observations, store, seal, spool, checks)
