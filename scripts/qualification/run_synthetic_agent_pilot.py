#!/usr/bin/env python3
"""Installed-wheel, independent-truth pilot for the spec-040 synthetic slice.

The fixture is intentionally not an evaluation service or a production agent.
It runs only against a local controlled provider and no-shell local tools.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

import fabric
from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, LocalFilesystemContentStore
from fabric.adapters.synthetic_evidence import (
    AllowlistedArtifactObserver,
    BoundedTerminalAdapter,
    ControlledHTTPModelAdapter,
    SyntheticCaptureSession,
)
from fabric.source_spool import SyntheticSourceSpool
from fabric.synthetic_otlp import export_synthetic_snapshot, project_synthetic_snapshot
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
        "interaction.payload",
        "terminal.argv",
        "terminal.stdin",
        "terminal.stdout",
        "terminal.stderr",
        "artifact.before",
        "artifact.after",
    }
)
CANARY = "PILOT_SECRET_CANARY_do_not_export"
TOOL = Path(__file__).with_name("synthetic_agent_tool.py").resolve()


@dataclass(frozen=True)
class PilotTLS:
    node_ca: str | None = None
    node_cert: str | None = None
    node_key: str | None = None
    sink_ca: str | None = None
    node_token_file: str | None = None


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode()


def _decode(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _append_truth(path: Path, record: dict[str, object]) -> None:
    with path.open("ab") as stream:
        stream.write(_json_bytes(record) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def _read_truth(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_bytes().splitlines()]


class ProviderFixture:
    def __init__(self, journal: Path) -> None:
        self.journal = journal
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> "ProviderFixture":
        journal = self.journal

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers["Content-Length"]))
                request = json.loads(body)
                stage = request["stage"]
                attempt = request["attempt"]
                if stage == 1 and attempt == 1:
                    status, response = 503, b"retry-this-attempt"
                elif stage == 1 and attempt == 2:
                    status, response = (
                        200,
                        _json_bytes(
                            {"tool": "create", "stdin_b64": _b64(b"\x00seed\xff")}
                        ),
                    )
                elif stage == 2 and attempt == 1:
                    status, response = (
                        200,
                        _json_bytes(
                            {
                                "tool": "modify",
                                "stdin_b64": _b64(b"PILOT_SECRET_CANARY_\x00"),
                            }
                        ),
                    )
                elif stage == 3 and attempt == 1:
                    status, response = 200, b"synthetic-final-answer\x00"
                else:
                    status, response = 400, b"unexpected-step"
                _append_truth(
                    journal,
                    {
                        "request_b64": _b64(body),
                        "response_b64": _b64(response),
                        "status": status,
                        "stage": stage,
                        "attempt": attempt,
                    },
                )
                self.send_response(status)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *_args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        assert self.server is not None
        self.server.shutdown()
        self.server.server_close()
        assert self.thread is not None
        self.thread.join(timeout=5)

    @property
    def port(self) -> int:
        assert self.server is not None
        return self.server.server_port


def _provider_context(port: int, body: bytes) -> bytes:
    return _json_bytes(
        {
            "method": "POST",
            "scheme": "http",
            "host": "127.0.0.1",
            "port": port,
            "path": "/model",
            "content_type": "application/octet-stream",
            "content_length": len(body),
        }
    )


def _terminal_context(work: Path) -> bytes:
    return _json_bytes({"cwd": str(work.resolve()), "approved_env": {}})


def _direct_bypass(port: int) -> None:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST", "/model", body=_json_bytes({"stage": 4, "attempt": 1})
        )
        response = connection.getresponse()
        response.read()
        assert response.status == 400
    finally:
        connection.close()


def _sink_get(
    endpoint: str, path: str, *, ca_cert_path: str | None = None
) -> dict[str, object]:
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
        "127.0.0.1",
        "localhost",
    }:
        raise ValueError("controlled sink URL must be local HTTP(S)")
    if parsed.scheme == "https":
        if not ca_cert_path:
            raise ValueError("controlled HTTPS sink requires a CA certificate")
        context = ssl.create_default_context(cafile=ca_cert_path)
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            parsed.hostname, parsed.port or 443, timeout=5, context=context
        )
    else:
        if ca_cert_path is not None:
            raise ValueError("controlled HTTP sink cannot accept a CA certificate")
        connection = http.client.HTTPConnection(
            parsed.hostname, parsed.port or 80, timeout=5
        )
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read(65536)
        if response.status != 200:
            raise RuntimeError(f"controlled sink returned {response.status}")
        return json.loads(body)
    finally:
        connection.close()


def _check_sink(
    endpoint: str,
    ids: list[str],
    digests: list[str],
    *,
    ca_cert_path: str | None = None,
) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        missing = [
            value
            for value in [*ids, *digests]
            if not _sink_get(
                endpoint, "/contains?needle=" + quote(value), ca_cert_path=ca_cert_path
            )["found"]
        ]
        if not missing:
            break
        time.sleep(1)
    else:
        raise AssertionError(
            f"controlled sink lacks {len(missing)} required IDs/digests"
        )
    if _sink_get(
        endpoint, "/contains?needle=" + quote(CANARY), ca_cert_path=ca_cert_path
    )["found"]:
        raise AssertionError("privacy canary escaped to controlled sink")


def _run_case(
    root: Path, fault: str, node_url: str | None, sink_url: str | None, tls: PilotTLS
) -> dict[str, object]:
    root.mkdir(mode=0o700)
    work = root / "work"
    work.mkdir(mode=0o700)
    spool_dir = root / "source-spool"
    spool_dir.mkdir(mode=0o700)
    endpoint_journal = root / "provider-truth.jsonl"
    tool_journal = work / "tool-truth.jsonl"
    store = LocalFilesystemContentStore(
        str(root / "store"), tenant_id="synthetic-tenant"
    )
    recorder = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=ROLES))
    spool = SyntheticSourceSpool(
        str(spool_dir), tenant_id="synthetic-tenant", run_id=f"agent-{fault}"
    )
    session = SyntheticCaptureSession(
        recorder,
        tenant_id="synthetic-tenant",
        run_id=f"agent-{fault}",
        source_spool=spool,
    )
    tool = BoundedTerminalAdapter(session, allowed_cwd_root=str(work), chunk_bytes=3)
    artifact = AllowlistedArtifactObserver(
        session, root=str(work), relative_paths=["result.bin"]
    )
    run_order: list[str] = []
    artifact_truth: list[bytes] = []
    tool_argv: list[list[str]] = []
    try:
        with ProviderFixture(endpoint_journal) as provider:
            model = ControlledHTTPModelAdapter(
                session, f"http://127.0.0.1:{provider.port}/model"
            )
            request_1 = _json_bytes({"stage": 1, "attempt": 1, "canary": CANARY})
            assert (
                model.post(request_1, operation_id="model-1", attempt_id="try-1")[0]
                == 503
            )
            run_order.append("model-1/try-1")
            request_retry = _json_bytes({"stage": 1, "attempt": 2, "canary": CANARY})
            status, response = model.post(
                request_retry, operation_id="model-1", attempt_id="try-2"
            )
            assert status == 200
            run_order.append("model-1/try-2")
            for tool_number in (1, 2):
                command = json.loads(response)
                mode = "create" if tool_number == 1 else "modify"
                assert command["tool"] == mode
                operation = f"tool-{tool_number}"
                attempt = "try-1"
                artifact.observe(
                    phase="before", operation_id=operation, attempt_id=attempt
                )
                argv = [sys.executable, str(TOOL), mode, str(tool_journal)]
                tool_argv.append(argv)
                result = tool.run(
                    argv,
                    cwd=str(work),
                    stdin=_decode(command["stdin_b64"]),
                    operation_id=operation,
                    attempt_id=attempt,
                )
                assert result.returncode == 0 and not result.timed_out
                artifact.observe(
                    phase="after", operation_id=operation, attempt_id=attempt
                )
                artifact_bytes = (work / "result.bin").read_bytes()
                artifact_truth.append(artifact_bytes)
                run_order.append(operation)
                request = _json_bytes(
                    {
                        "stage": tool_number + 1,
                        "attempt": 1,
                        "parent_operation_id": operation,
                        "previous_model_response_b64": _b64(response),
                        "terminal_stdout_b64": _b64(result.stdout),
                        "terminal_stderr_b64": _b64(result.stderr),
                        "artifact_b64": _b64(artifact_bytes),
                    }
                )
                status, response = model.post(
                    request, operation_id=f"model-{tool_number + 1}", attempt_id="try-1"
                )
                assert status == 200
                run_order.append(f"model-{tool_number + 1}/try-1")
            assert response == b"synthetic-final-answer\x00"
            if fault == "bypass":
                _direct_bypass(provider.port)
        snapshot = session.snapshot()
        assert snapshot["writer_settled"] and snapshot["source_spool_settled"]
        assert not snapshot["source_spool_recovered_gaps"]
        assert CANARY.encode() not in _json_bytes(snapshot)
        assert all(
            CANARY.encode() not in path.read_bytes()
            for path in spool_dir.iterdir()
            if path.is_file()
        )
        endpoint = _read_truth(endpoint_journal)
        tools = _read_truth(tool_journal)
        assert len(endpoint) == (5 if fault == "bypass" else 4)
        assert len(tools) == 2
        assert [entry["mode"] for entry in tools] == ["create", "modify"]
        assert run_order == [
            "model-1/try-1",
            "model-1/try-2",
            "tool-1",
            "model-2/try-1",
            "tool-2",
            "model-3/try-1",
        ]
        for index, truth in enumerate(tools):
            assert _decode(str(truth["after_b64"])) == artifact_truth[index]
            if index:
                assert _decode(str(truth["before_b64"])) == artifact_truth[index - 1]
        for index, entry in enumerate(endpoint[1:4], start=1):
            if index < 2:
                continue
            request = json.loads(_decode(str(entry["request_b64"])))
            assert _decode(request["artifact_b64"]) == artifact_truth[index - 2]
            assert request["parent_operation_id"] == f"tool-{index - 1}"
        expected: list[ExpectedByteObject] = []
        expected_operations: list[ExpectedOperation] = []
        for entry in endpoint:
            stage = int(entry["stage"])
            attempt = int(entry["attempt"])
            request = _decode(str(entry["request_b64"]))
            response = _decode(str(entry["response_b64"]))
            operation = f"model-{stage}"
            attempt_id = f"try-{attempt}"
            for role, data in (
                ("interaction.payload", _provider_context(provider.port, request)),
                ("model.request.messages", request),
                ("model.output.messages", response),
            ):
                expected.append(
                    ExpectedByteObject(
                        "provider-http-1",
                        "provider_bound",
                        operation,
                        attempt_id,
                        role,
                        data,
                    )
                )
            expected_operations.append(
                ExpectedOperation(
                    "provider_bound",
                    operation,
                    attempt_id,
                    {"http_status": int(entry["status"])},
                )
            )
        for index, truth in enumerate(tools, start=1):
            operation = f"tool-{index}"
            argv = tool_argv[index - 1]
            before = (
                _decode(str(truth["before_b64"])) if truth["before_present"] else None
            )
            after = _decode(str(truth["after_b64"]))
            for role, data in (
                (
                    "terminal.argv",
                    b"\x00".join(os.fsencode(item) for item in argv) + b"\x00",
                ),
                ("interaction.payload", _terminal_context(work)),
                ("terminal.stdin", _decode(str(truth["stdin_b64"]))),
                ("terminal.stdout", _decode(str(truth["stdout_b64"]))),
                ("terminal.stderr", _decode(str(truth["stderr_b64"]))),
            ):
                expected.append(
                    ExpectedByteObject(
                        "terminal-1", "terminal", operation, "try-1", role, data
                    )
                )
            if before is not None:
                expected.append(
                    ExpectedByteObject(
                        "artifact-1",
                        "tool",
                        operation,
                        "try-1",
                        "artifact.before",
                        before,
                    )
                )
            expected.append(
                ExpectedByteObject(
                    "artifact-1", "tool", operation, "try-1", "artifact.after", after
                )
            )
            expected_operations.extend(
                [
                    ExpectedOperation(
                        "tool",
                        operation,
                        "try-1",
                        {
                            "artifact_phase": "before",
                            "artifact_present": before is not None,
                        },
                    ),
                    ExpectedOperation(
                        "terminal",
                        operation,
                        "try-1",
                        {
                            "returncode": int(truth["returncode"]),
                            "timed_out": False,
                        },
                    ),
                    ExpectedOperation(
                        "tool",
                        operation,
                        "try-1",
                        {
                            "artifact_phase": "after",
                            "artifact_present": True,
                            "artifact_size": len(after),
                        },
                    ),
                ]
            )
        if fault == "missing-object":
            first = next(
                event for event in snapshot["events"] if event["status"] == "stored"
            )
            first_ref = first["descriptor"]["ref"]
            Path(urlsplit(first_ref).path).unlink()
        resolver = SyntheticByteResolver(store, tenant_id="synthetic-tenant")
        report = reconcile_synthetic_run(
            snapshot, expected, resolver, expected_operations=expected_operations
        )
        expected_verdict = "unverified" if fault == "clean" else "partial"
        assert report["verdict"] == expected_verdict, report
        assert (not report["discrepancies"]) == (fault == "clean"), report
        assert not report["complete_verdict_available"]
        receipt: dict[str, object] | None = None
        expected_sink_records: list[dict[str, object]] = []
        if fault == "clean" and node_url is not None:
            assert sink_url is not None
            projected, projected_ids = project_synthetic_snapshot(snapshot)
            assert CANARY.encode() not in projected
            assert str(root).encode() not in projected
            projected_records = json.loads(projected)["resourceLogs"][0]["scopeLogs"][
                0
            ]["logRecords"]
            assert projected_ids == [event["record_id"] for event in snapshot["events"]]
            for projected_record, event in zip(
                projected_records, snapshot["events"], strict=True
            ):
                attrs = {
                    attr["key"]: next(iter(attr["value"].values()))
                    for attr in projected_record["attributes"]
                }
                assert attrs["record_id"] == event["record_id"]
                assert attrs["role"] == event["role"]
                assert attrs["status"] == event["status"]
                if event["status"] == "stored":
                    assert (
                        attrs["content_sha256"] == event["descriptor"]["stored_sha256"]
                    )
                expected_sink_records.append(
                    {
                        "event_name": projected_record["eventName"],
                        "attributes": {
                            key: attrs[key]
                            for key in (
                                "record_id",
                                "role",
                                "status",
                                "content_object_id",
                                "content_sha256",
                                "source_id",
                                "source_epoch",
                                "source_sequence",
                                "operation_id",
                                "attempt_id",
                                "tenant_id",
                                "run_id",
                            )
                            if key in attrs
                        },
                    }
                )
            receipt = export_synthetic_snapshot(
                snapshot,
                node_url,
                ca_cert_path=tls.node_ca,
                client_cert_path=tls.node_cert,
                client_key_path=tls.node_key,
                bearer_token_path=tls.node_token_file,
            )
            assert receipt["receipt_stage"] == "node_accepted"
            assert receipt["rejected_count"] == 0
            ids = [event["record_id"] for event in snapshot["events"]]
            digests = [
                event["descriptor"]["stored_sha256"]
                for event in snapshot["events"]
                if event["status"] == "stored"
            ]
            _check_sink(sink_url, ids, digests, ca_cert_path=tls.sink_ca)
        return {
            "fault": fault,
            "verdict": report["verdict"],
            "discrepancies": report["discrepancies"],
            "expected_operations": len(expected_operations),
            "expected_byte_objects": len(expected),
            "captured_byte_events": len(snapshot["events"]),
            "source_high_water": snapshot["source_high_water"],
            "byte_digests": sorted(
                {"sha256:" + hashlib.sha256(item.data).hexdigest() for item in expected}
            ),
            "node_receipt_stage": receipt["receipt_stage"] if receipt else None,
            "sink_byte_presence_checked": len(snapshot["events"]) if receipt else 0,
            "expected_sink_records": expected_sink_records,
        }
    finally:
        recorder.close()
        spool.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", help="loopback Fabric Node /v1/logs URL")
    parser.add_argument("--sink-url", help="loopback controlled sink base URL")
    parser.add_argument("--node-ca", help="trusted test CA for HTTPS Node")
    parser.add_argument("--node-cert", help="test client certificate for HTTPS Node")
    parser.add_argument("--node-key", help="test client key for HTTPS Node")
    parser.add_argument("--sink-ca", help="trusted test CA for HTTPS sink")
    parser.add_argument("--node-token-file", help="workload token file for HTTPS Node")
    parser.add_argument("--work-dir", type=Path, help="dedicated output directory")
    parser.add_argument(
        "--report-path", type=Path, help="write full digest/discrepancy report"
    )
    args = parser.parse_args()
    if bool(args.node_url) != bool(args.sink_url):
        parser.error("--node-url and --sink-url must be supplied together")
    module_path = Path(fabric.__file__).resolve()
    checkout_src = Path(__file__).resolve().parents[2] / "sdk" / "python" / "src"
    if module_path.is_relative_to(checkout_src):
        parser.error("pilot must import an installed wheel, not repository source")
    if not TOOL.is_file():
        parser.error("synthetic tool fixture missing")
    tls = PilotTLS(args.node_ca, args.node_cert, args.node_key, args.sink_ca, args.node_token_file)
    if args.work_dir is None:
        with tempfile.TemporaryDirectory(prefix="fabric-agent-pilot-") as directory:
            cases = [
                _run_case(
                    Path(directory) / fault, fault, args.node_url, args.sink_url, tls
                )
                for fault in ("clean", "bypass", "missing-object")
            ]
    else:
        args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        cases = [
            _run_case(args.work_dir / fault, fault, args.node_url, args.sink_url, tls)
            for fault in ("clean", "bypass", "missing-object")
        ]
    report = {
        "schema_version": "fabric.synthetic-agent-pilot/v1",
        "installed_fabric_module": str(module_path),
        "cases": cases,
        "qualification": "NO_GO",
        "reason": "source auth, passive non-interference and durable destination proof unverified",
    }
    if args.report_path is not None:
        args.report_path.parent.mkdir(parents=True, exist_ok=True)
        args.report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "schema_version": report["schema_version"],
                "qualification": report["qualification"],
                "cases": [
                    {
                        "fault": case["fault"],
                        "verdict": case["verdict"],
                        "expected_byte_objects": case["expected_byte_objects"],
                        "discrepancy_count": len(case["discrepancies"]),
                        "node_receipt_stage": case["node_receipt_stage"],
                        "sink_byte_presence_checked": case[
                            "sink_byte_presence_checked"
                        ],
                    }
                    for case in cases
                ],
                "report_path": str(args.report_path) if args.report_path else None,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
