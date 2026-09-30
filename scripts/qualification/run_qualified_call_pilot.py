#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Installed-wheel, synthetic-only qualified evidence pilot (spec 046).

Runs a real loopback model endpoint and a no-shell subprocess. Their native
ledgers are populated outside the recorder. Signing keys exist only in memory.
Stage signatures are fixture assertions, NOT live Node or customer storage
proofs. A complete bounded fixture verdict is never a production GO.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from contextlib import ExitStack
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, LocalFilesystemContentStore
from fabric import __file__ as fabric_package_file
from fabric.byte_resolver import ByteEvidenceResolver
from fabric.call_otlp import project_call_snapshot
from fabric.call_reconcile import RouteDeclaration
from fabric.call_recorder import CallRecorder
from fabric.evidence_attestation import EvidenceTrustKey, attestation_signing_bytes
from fabric.independent_feed import (
    ExpectedAttempt,
    ExpectedRole,
    IndependentFeedExpectation,
)
from fabric.independent_store import LocalIndependentFeedResolver
from fabric.qualified_run import (
    QualifiedFeedInput,
    QualifiedRunExpectation,
    qualified_receipt_expectations,
    route_closure_subject_bytes,
    source_binding_subject_bytes,
    verify_qualified_call_run,
)
from fabric.receipt_sets import receipt_set_bytes
from fabric.source_spool import SyntheticSourceSpool

TENANT = "synthetic-qualified"
SOURCE = "reference-dispatcher"
CANARY = b"QUALIFIED_SYNTHETIC_PRIVATE_CANARY_046"
STAGES = (
    "source_spooled",
    "node_accepted",
    "destination_accepted",
    "destination_durable",
)
ROLES = frozenset(
    {
        "tool.call.arguments",
        "tool.call.result",
        "model.request.messages",
        "model.output.messages",
        "terminal.argv",
        "terminal.stdin",
        "terminal.stdout",
        "terminal.stderr",
        "context.file",
        "artifact.after",
    }
)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write_private(path: Path, data: bytes) -> None:
    """Only create new owned fixture files; never overwrite previous evidence."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


class NativeByteResolver:
    """Fixture-only, separate tenant/issuer-bound local native byte store."""

    def __init__(self, root: Path, issuer_id: str) -> None:
        self.tenant_id = TENANT
        self.issuer_id = issuer_id
        self.root = root / TENANT / issuer_id
        self.root.mkdir(mode=0o700)
        self.reader = LocalIndependentFeedResolver(
            root.resolve(), tenant_id=TENANT, issuer_id=issuer_id
        )

    def put(self, object_id: str, data: bytes) -> None:
        if not _ID.fullmatch(object_id):
            raise ValueError("invalid fixture byte identifier")
        write_private(self.root / object_id, data)

    def resolve(self, byte_object_id: str, max_bytes: int) -> bytes:
        return self.reader.resolve(byte_object_id, max_bytes)


class NativeLedger:
    """Observations from delegates/services, never from Fabric's snapshot."""

    def __init__(self, root: Path, issuer: str, boundary: str) -> None:
        self.issuer = issuer
        self.boundary = boundary
        self.resolver = NativeByteResolver(root, issuer)
        self.records: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def byte(
        self, operation: str, role: str, data: bytes, chunk: int | None = None
    ) -> None:
        with self.lock:
            object_id = "native-" + uuid.uuid4().hex
            self.resolver.put(object_id, data)
            self.records.append(
                {
                    "cursor": len(self.records),
                    "kind": "byte",
                    "operation_id": operation,
                    "attempt_id": "try-1",
                    "role": role,
                    "chunk_index": chunk,
                    "byte_length": len(data),
                    "sha256": sha(data),
                    "byte_object_id": object_id,
                }
            )

    def end(self, operation: str) -> None:
        with self.lock:
            self.records.append(
                {
                    "cursor": len(self.records),
                    "kind": "operation",
                    "operation_id": operation,
                    "attempt_id": "try-1",
                    "outcome": {"result_status": "ok"},
                }
            )

    def document(self, expected: IndependentFeedExpectation) -> bytes:
        return canonical(
            {
                "schema_version": "fabric.independent-feed/v1",
                "feed_id": expected.feed_id,
                "tenant_id": TENANT,
                "run_id": expected.run_id,
                "scope_sha256": expected.scope_sha256,
                "route_id": expected.route_id,
                "route_version": expected.route_version,
                "source_id": SOURCE,
                "source_epoch": 0,
                "boundary": self.boundary,
                "cursor_domain": expected.cursor_domain,
                "cursor_start": expected.cursor_start,
                "cursor_end": expected.cursor_end,
                "records": self.records,
            }
        )


class FixtureSigner:
    """Explicit fixture apparatus, not a recorder runtime signing service."""

    def __init__(self, now: int) -> None:
        self.now = now
        self.private: dict[str, Ed25519PrivateKey] = {}
        self.trusted: dict[str, EvidenceTrustKey] = {}

    def register(self, issuer: str, purpose: str) -> None:
        private = Ed25519PrivateKey.generate()
        self.private[issuer] = private
        self.trusted[issuer + "-key"] = EvidenceTrustKey(
            issuer,
            TENANT,
            private.public_key().public_bytes_raw(),
            frozenset({purpose}),
            self.now - 1,
            self.now + 300,
        )

    def sign(
        self,
        run: str,
        scope: str,
        issuer: str,
        purpose: str,
        subject_kind: str,
        subject_id: str,
        subject: bytes,
    ) -> bytes:
        key_id = issuer + "-key"
        payload = {
            "statement_type": purpose,
            "issuer_id": issuer,
            "tenant_id": TENANT,
            "run_id": run,
            "scope_sha256": scope,
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "subject_sha256": sha(subject),
            "issued_at": self.now,
            "expires_at": self.now + 300,
        }
        signature = self.private[issuer].sign(
            attestation_signing_bytes(payload, key_id=key_id)
        )
        return canonical(
            {
                "schema_version": "fabric.evidence-attestation/v1",
                "algorithm": "Ed25519",
                "key_id": key_id,
                "payload": payload,
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )


def run_pilot(output: Path) -> dict[str, Any]:
    with ExitStack() as resources:
        return _run_pilot(output, resources)


def _run_pilot(output: Path, resources: ExitStack) -> dict[str, Any]:  # noqa: PLR0915
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    run = "qualified-" + uuid.uuid4().hex
    native_root = output / "approved-native-originals"
    native_root.mkdir(mode=0o700)
    (native_root / TENANT).mkdir(mode=0o700)
    agent_ledger = NativeLedger(native_root, "fixture-orchestrator", "caller")
    provider_ledger = NativeLedger(native_root, "fixture-provider", "provider_bound")
    terminal_ledger = NativeLedger(native_root, "fixture-terminal", "tool")
    workspace = output / "agent-workspace"
    workspace.mkdir(mode=0o700)
    artifact = workspace / "result.bin"
    artifact_bytes = b"\x00\xffrecorded-artifact\n"
    chunks = (b"create:", artifact_bytes)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass  # Never send provider request bytes to collector logs.

        def do_POST(self) -> None:
            size = int(self.headers["Content-Length"])
            if size > 65536 or self.path not in {"/plan", "/answer"}:
                self.send_error(400)
                return
            request = self.rfile.read(size)
            operation = "model-plan" if self.path == "/plan" else "model-answer"
            provider_ledger.byte(operation, "model.request.messages", request)
            pieces = chunks if self.path == "/plan" else (b"completed",)
            response = b"".join(
                len(piece).to_bytes(4, "big") + piece for piece in pieces
            )
            self.send_response(200)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            for index, piece in enumerate(pieces):
                provider_ledger.byte(
                    operation,
                    "model.output.messages",
                    piece,
                    index if self.path == "/plan" else None,
                )
            provider_ledger.end(operation)
            self.wfile.write(response)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()

    def stop_server() -> None:
        if serving.is_alive():
            server.shutdown()
        server.server_close()
        serving.join(timeout=5)

    resources.callback(stop_server)
    endpoint = f"http://127.0.0.1:{server.server_port}"
    journal = output / "source-journal"
    journal.mkdir(mode=0o700)
    spool = SyntheticSourceSpool(str(journal), tenant_id=TENANT, run_id=run)
    resources.callback(spool.close)
    store = LocalFilesystemContentStore(
        str(output / "approved-captured-originals"), tenant_id=TENANT
    )
    writer = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=ROLES))
    resources.callback(writer.close)
    recorder = CallRecorder(
        writer, run_id=run, agent_id="coordinator", source_id=SOURCE, source_spool=spool
    )

    def request(route: str, payload: bytes) -> list[bytes]:
        # Explicit empty proxy configuration prevents inherited HTTP proxy routes.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(
            urllib.request.Request(endpoint + route, data=payload, method="POST"),
            timeout=10,
        ) as response:
            wire = response.read(65537)
        if len(wire) > 65536:
            raise AssertionError("controlled provider response exceeded fixture bound")
        pieces: list[bytes] = []
        while wire:
            if len(wire) < 4:
                raise AssertionError("controlled provider framing incomplete")
            length = int.from_bytes(wire[:4], "big")
            if len(wire) < length + 4:
                raise AssertionError("controlled provider framing incomplete")
            pieces.append(wire[4 : length + 4])
            wire = wire[length + 4 :]
        return pieces

    program = (
        "import pathlib,sys; data=sys.stdin.buffer.read(); "
        "pathlib.Path(sys.argv[1]).write_bytes(data); sys.stdout.buffer.write(data)"
    )
    argv = [sys.executable, "-I", "-S", "-c", program, str(artifact)]
    approved_context = canonical({"cwd": str(workspace), "environment": {}})
    tool_arguments = canonical({"argv": argv, "cwd": str(workspace), "environment": {}})

    def tool(payload: bytes) -> bytes:
        terminal_ledger.byte("terminal-write", "tool.call.arguments", payload)
        for role, value in (
            ("terminal.argv", canonical(argv)),
            ("context.file", approved_context),
            ("terminal.stdin", artifact_bytes),
        ):
            terminal_ledger.byte("terminal-write", role, value)
            recorder.record_data(value, role=role)
        process = subprocess.run(
            argv,
            input=artifact_bytes,
            capture_output=True,
            cwd=workspace,
            env={},
            shell=False,
            timeout=10,
            check=False,
        )
        if process.returncode != 0:
            raise AssertionError("synthetic terminal process failed")
        for role, value in (
            ("terminal.stdout", process.stdout),
            ("terminal.stderr", process.stderr),
        ):
            terminal_ledger.byte("terminal-write", role, value)
            recorder.record_data(value, role=role)
        # Filesystem inventory reads the created file independently of stdout.
        file_bytes = artifact.read_bytes()
        terminal_ledger.byte("terminal-write", "artifact.after", file_bytes)
        recorder.record_data(file_bytes, role="artifact.after")
        result = canonical(
            {
                "returncode": process.returncode,
                "signal": None,
                "artifact_sha256": sha(file_bytes),
            }
        )
        terminal_ledger.byte("terminal-write", "tool.call.result", result)
        terminal_ledger.end("terminal-write")
        return result

    def agent(payload: bytes) -> bytes:
        agent_ledger.byte("agent", "tool.call.arguments", payload)
        observed_chunks = list(
            recorder.stream(
                CANARY,
                lambda data: iter(request("/plan", data)),
                kind="model",
                operation_id="model-plan",
                attempt_id="try-1",
            )
        )
        if tuple(observed_chunks) != chunks:
            raise AssertionError("model stream bytes changed")
        terminal_result = recorder.call(
            tool_arguments,
            tool,
            kind="tool",
            operation_id="terminal-write",
            attempt_id="try-1",
        )
        final_request = terminal_result + b"\n" + artifact.read_bytes()
        result = recorder.call(
            final_request,
            lambda data: request("/answer", data)[0],
            kind="model",
            operation_id="model-answer",
            attempt_id="try-1",
        )
        agent_ledger.byte("agent", "tool.call.result", result)
        agent_ledger.end("agent")
        return result

    try:
        if (
            recorder.call(
                b"synthetic-task",
                agent,
                kind="agent",
                operation_id="agent",
                attempt_id="try-1",
            )
            != b"completed"
        ):
            raise AssertionError("recording changed the synthetic agent result")
        if recorder.seal_source()["status"] != "sealed":
            raise AssertionError("synthetic source did not seal")
        snapshot = recorder.snapshot()
    finally:
        stop_server()

    routes = tuple(
        RouteDeclaration("route-" + boundary, "1", boundary)
        for boundary in ("caller", "provider_bound", "tool")
    )
    scope_document = canonical(
        {
            "schema_version": "fabric.fixture-scope/v1",
            "tenant_id": TENANT,
            "run_id": run,
            "agent": "qualified-call-pilot-v1",
            "model_endpoint": endpoint,
            "terminal_argv": argv,
            "cwd": str(workspace),
            "approved_environment": {},
            "required_roles": sorted(ROLES),
            "max_operations": 4,
            "max_object_bytes": 65536,
            "privacy": "synthetic_only_exact_originals_in_owned_0700_storage",
            "retention": "fixture_directory_owner_controls_removal",
            "excluded_routes": [
                "SSH",
                "database",
                "browser",
                "cloud",
                "sandbox",
                "messaging",
            ],
            "closure": "fixture_assertion_only_not_platform_network_or_process_enforcement",
            "outage_limit": "qualification_fails_on_any_missing_evidence",
        }
    )
    scope = sha(scope_document)
    # Expectations are fixed from the test workload, NOT from snapshot/events.
    attempts = {
        "caller": (
            ExpectedAttempt(
                "agent",
                "try-1",
                {"result_status": "ok"},
                (ExpectedRole("tool.call.arguments"), ExpectedRole("tool.call.result")),
            ),
        ),
        "provider_bound": (
            ExpectedAttempt(
                "model-plan",
                "try-1",
                {"result_status": "ok"},
                (
                    ExpectedRole("model.request.messages"),
                    ExpectedRole("model.output.messages", 2),
                ),
            ),
            ExpectedAttempt(
                "model-answer",
                "try-1",
                {"result_status": "ok"},
                (
                    ExpectedRole("model.request.messages"),
                    ExpectedRole("model.output.messages"),
                ),
            ),
        ),
        "tool": (
            ExpectedAttempt(
                "terminal-write",
                "try-1",
                {"result_status": "ok"},
                tuple(
                    ExpectedRole(role)
                    for role in (
                        "tool.call.arguments",
                        "terminal.argv",
                        "context.file",
                        "terminal.stdin",
                        "terminal.stdout",
                        "terminal.stderr",
                        "artifact.after",
                        "tool.call.result",
                    )
                ),
            ),
        ),
    }
    cursor_ends = {"caller": 2, "provider_bound": 6, "tool": 8}
    ledgers = (agent_ledger, provider_ledger, terminal_ledger)
    feed_expectations = tuple(
        IndependentFeedExpectation(
            "feed-" + ledger.boundary,
            TENANT,
            run,
            scope,
            "route-" + ledger.boundary,
            "1",
            SOURCE,
            0,
            ledger.boundary,
            "native-" + ledger.boundary,
            0,
            cursor_ends[ledger.boundary],
            ledger.issuer,
            attempts[ledger.boundary],
        )
        for ledger in ledgers
    )
    expectation = QualifiedRunExpectation(
        TENANT,
        run,
        scope,
        SOURCE,
        0,
        routes,
        feed_expectations,
        "fixture-source",
        "fixture-closure",
        "fixture-route-closure",
        tuple((stage, "fixture-" + stage) for stage in STAGES),
        tuple((stage, "set-" + stage) for stage in STAGES),
    )
    now = int(time.time())
    signer = FixtureSigner(now)
    for ledger in ledgers:
        signer.register(ledger.issuer, "independent_witness")
    signer.register("fixture-source", "source_binding")
    signer.register("fixture-closure", "route_closure")
    for stage in STAGES:
        signer.register("fixture-" + stage, stage)
    feeds = tuple(
        QualifiedFeedInput(
            ledger.document(feed_expected),
            signer.sign(
                run,
                scope,
                ledger.issuer,
                "independent_witness",
                "evidence_set",
                feed_expected.feed_id,
                ledger.document(feed_expected),
            ),
            feed_expected,
            ledger.resolver,
        )
        for ledger, feed_expected in zip(ledgers, feed_expectations, strict=True)
    )
    resolver = ByteEvidenceResolver(store, tenant_id=TENANT)
    source_binding = signer.sign(
        run,
        scope,
        "fixture-source",
        "source_binding",
        "source",
        SOURCE,
        source_binding_subject_bytes(expectation),
    )
    route_closure = signer.sign(
        run,
        scope,
        "fixture-closure",
        "route_closure",
        "evidence_set",
        expectation.closure_set_id,
        route_closure_subject_bytes(expectation),
    )
    receipt_expectations = qualified_receipt_expectations(
        snapshot, expectation=expectation, resolver=resolver, source_spool=spool
    )
    receipts = {}
    for stage, receipt_expected in receipt_expectations.items():
        manifest = receipt_set_bytes(receipt_expected)
        receipts[stage] = (
            manifest,
            signer.sign(
                run,
                scope,
                receipt_expected.issuer_id,
                stage,
                "evidence_set",
                receipt_expected.set_id,
                manifest,
            ),
        )

    def verify(**changes: Any) -> dict[str, Any]:
        inputs = dict(
            expectation=expectation,
            feeds=feeds,
            resolver=resolver,
            source_spool=spool,
            source_binding_attestation=source_binding,
            route_closure_attestation=route_closure,
            receipts=receipts,
            trusted_keys=signer.trusted,
            verification_time=now,
        )
        changed_snapshot = changes.pop("snapshot", snapshot)
        inputs.update(changes)
        return verify_qualified_call_run(changed_snapshot, **inputs)

    positive = verify()
    if positive["verdict"] != "verified_complete_for_declared_scope":
        raise AssertionError("bounded fixture failed: " + json.dumps(positive))
    negatives: dict[str, dict[str, Any]] = {}

    def negative(name: str, **changes: Any) -> None:
        result = verify(**changes)
        if result["verdict"] == "verified_complete_for_declared_scope":
            raise AssertionError(
                "injected evidence loss retained completeness: " + name
            )
        negatives[name] = result

    for index, feed in enumerate(feeds):
        negative(
            "missing-feed-" + feed.expectation.feed_id,
            feeds=tuple(value for offset, value in enumerate(feeds) if offset != index),
        )
    for stage in STAGES:
        negative(
            "missing-receipt-" + stage,
            receipts={
                name: receipt for name, receipt in receipts.items() if name != stage
            },
        )
    negative("missing-source-binding", source_binding_attestation=None)
    negative("missing-route-closure", route_closure_attestation=None)
    negative("missing-source-readback", source_spool=None)
    negative("bad-source-signature", source_binding_attestation=b"{}")
    negative(
        "bad-feed-signature",
        feeds=(replace(feeds[0], attestation_bytes=b"{}"), *feeds[1:]),
    )
    unreachable = (
        *routes,
        RouteDeclaration("unwrapped-ssh", "1", "remote", observed=False),
    )
    negative(
        "reachable-unobserved-route",
        expectation=replace(expectation, routes=unreachable),
    )
    changed = copy.deepcopy(snapshot)
    changed["events"].pop()
    negative("missing-captured-byte", snapshot=changed)
    changed = copy.deepcopy(snapshot)
    changed["operations"].pop()
    negative("missing-captured-operation", snapshot=changed)
    negative(
        "accepted-without-durable-readback",
        receipts={**receipts, "destination_durable": receipts["destination_accepted"]},
    )
    # Mutate one independently stored object, preserving length. Restore only
    # this fixture-owned object after recording its expected failure verdict.
    first_native = agent_ledger.records[0]["byte_object_id"]
    native_path = agent_ledger.resolver.root / first_native
    original = native_path.read_bytes()
    native_path.write_bytes(b"X" * len(original))
    negative("native-byte-corruption")
    native_path.write_bytes(original)
    native_path.rename(native_path.with_suffix(".withheld"))
    negative("missing-native-byte-object")
    native_path.with_suffix(".withheld").rename(native_path)

    captured_path = Path(
        snapshot["events"][0]["descriptor"]["ref"].removeprefix("file://")
    )
    if not captured_path.resolve().is_relative_to(output.resolve()):
        raise AssertionError("captured object is outside the owned fixture directory")
    saved_original = captured_path.read_bytes()
    captured_path.write_bytes(b"X" * len(saved_original))
    negative("captured-original-corruption")
    captured_path.write_bytes(saved_original)
    captured_path.rename(captured_path.with_suffix(".withheld"))
    negative("missing-captured-original-object")
    captured_path.with_suffix(".withheld").rename(captured_path)

    for name, path in (
        ("missing-source-record", next(journal.glob("event-*.json"))),
        ("missing-source-seal", journal / "seal-0.json"),
    ):
        withheld = path.with_suffix(".withheld")
        path.rename(withheld)
        negative(name)
        withheld.rename(path)

    changed = copy.deepcopy(snapshot)
    changed["recording_gaps"] = 1
    negative("missing-feed-with-known-loss", snapshot=changed, feeds=())

    # An issuer cannot cover a partly accepted batch by signing only the
    # accepted subset and omitting its rejected record from the expected set.
    subset = json.loads(receipts["destination_accepted"][0])
    subset["entries"].pop()
    subset_bytes = canonical(subset)
    partial_receipt = signer.sign(
        run,
        scope,
        "fixture-destination_accepted",
        "destination_accepted",
        "evidence_set",
        "set-destination_accepted",
        subset_bytes,
    )
    negative(
        "partial-acceptance-missing-record",
        receipts={
            **receipts,
            "destination_accepted": (subset_bytes, partial_receipt),
        },
    )

    projection, record_ids = project_call_snapshot(snapshot)
    public_outputs = [
        canonical(snapshot),
        canonical(positive),
        canonical(negatives),
        projection,
    ]
    public_outputs.extend(manifest for manifest, _ in receipts.values())
    public_outputs.extend(feed.manifest_bytes for feed in feeds)
    public_outputs.extend(
        path.read_bytes() for path in journal.rglob("*") if path.is_file()
    )
    if any(CANARY in data for data in public_outputs):
        raise AssertionError("private canary escaped approved original-byte storage")
    summary = {
        "schema_version": "fabric.qualified-pilot/v1",
        "fixture_only": True,
        "production_status": "NO_GO",
        "verdict": positive["verdict"],
        "scope_sha256": scope,
        "run_id": run,
        "operations": 4,
        "byte_objects": 15,
        "metadata_records": len(record_ids),
        "negative_tests": len(negatives),
        "zero_unexplained_discrepancies": True,
        "canary_metadata_check": "passed",
        "receipt_authority": "fixture_only_not_live_node_or_storage_issuance",
        "missing_live_gates": [
            "authorized_issuer_deployment_qualification",
            "platform_route_closure",
            "real_node_and_destination_receipt_issuance",
            "customer_storage_encryption_retention_restore_rotation",
            "independent_owner_signoff",
        ],
        "artifact_sha256": sha(artifact.read_bytes()),
        "installed_sdk_file_sha256": sha(Path(fabric_package_file).read_bytes()),
    }
    write_private(output / "scope.json", scope_document)
    write_private(output / "snapshot.json", canonical(snapshot))
    write_private(output / "projection.json", projection)
    write_private(output / "positive.json", canonical(positive))
    write_private(output / "negative-tests.json", canonical(negatives))
    write_private(output / "summary.json", canonical(summary))
    write_private(output / "source-binding.json", source_binding)
    write_private(output / "route-closure.json", route_closure)
    for feed in feeds:
        write_private(
            output / (feed.expectation.feed_id + ".json"), feed.manifest_bytes
        )
        write_private(
            output / (feed.expectation.feed_id + "-attestation.json"),
            feed.attestation_bytes,
        )
    for stage, (manifest, attestation) in receipts.items():
        write_private(output / (stage + ".json"), manifest)
        write_private(output / (stage + "-attestation.json"), attestation)
    write_private(
        output / "trust-keys.json",
        canonical(
            {
                key_id: {
                    "issuer_id": key.issuer_id,
                    "tenant_id": key.tenant_id,
                    "public_key": base64.b64encode(key.public_key).decode("ascii"),
                    "statement_types": sorted(key.statement_types),
                    "valid_from": key.valid_from,
                    "valid_until": key.valid_until,
                    "fixture_only": True,
                }
                for key_id, key in signer.trusted.items()
            }
        ),
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        "--evidence-dir",
        dest="output",
        type=Path,
        required=True,
        help="New evidence directory; its parent must already exist",
    )
    parser.add_argument(
        "--fixture-only",
        action="store_true",
        help="Acknowledge that fixture signatures are not production proofs",
    )
    args = parser.parse_args()
    if not args.fixture_only:
        parser.error(
            "requires --fixture-only; fixture receipts cannot establish production GO"
        )
    installed = Path(fabric_package_file).resolve()
    if (
        not installed.is_relative_to(Path(sys.prefix).resolve())
        or sys.prefix == sys.base_prefix
    ):
        parser.error("requires the SDK wheel installed in a virtual environment")
    output = args.output.absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        parser.error(
            "output must be a new directory inside an existing approved parent"
        )
    try:
        summary = run_pilot(output)
    except Exception:
        # No raw errors/arguments can escape into terminal or collector logs.
        print(
            "Qualified fixture failed; preserve its owned evidence directory for review.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
