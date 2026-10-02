#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline multi-agent orchestration with real effects and configured Fabric capture.

The model is a deterministic local HTTP fixture, not an LLM. It returns a plan
consumed by a coordinator and three concurrent workers. No external services,
credentials, shell commands, model bill, or production qualification.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import secrets
import sqlite3
import sys
import threading
import urllib.error
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from opentelemetry.sdk.trace import TracerProvider
from fabric import ByteEvidenceConfig, ByteEvidenceRecorder
from fabric.call_recorder import CallRecorder
from fabric.deployment_policy import DeploymentPolicy
from fabric.deployment_state import CapturePolicyRegistry
from fabric.enterprise import PolicyCaptureSession
from fabric.governed_store import GovernedLocalContentStore, LocalCapabilityAuthority
from fabric.source_spool import SyntheticSourceSpool

if not __debug__:
    raise RuntimeError(
        "qualification example requires assertions; optimized Python is unsupported"
    )

CANARY = b"SYNTHETIC_ORCHESTRATION_SECRET"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def validated_plan(payload: bytes) -> list[str]:
    """Only this inert fixture's closed plan can select local workers."""
    if len(payload) > 65536:
        raise ValueError("fixture plan exceeds its size limit")
    plan = json.loads(payload, object_pairs_hook=_unique_object)
    if (
        not isinstance(plan, dict)
        or set(plan) != {"workers", "join_background"}
        or plan["workers"] != ["file", "database", "process"]
        or plan["join_background"] is not True
    ):
        raise ValueError("fixture returned an unexpected plan")
    return plan["workers"]


def reconcile_http_attempts(
    ledger: list[dict[str, Any]], calls: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compare independently observed HTTP attempts against explicit boundaries.

    Route mapping is a closed fixture contract, not automatic discovery of an
    application's routes or independent production authority.
    """
    routes = {"model-plan": "/model", "http-retry": "/retry"}
    physical = Counter(
        (
            row["route"],
            f"try-{row['attempt']}",
            "ok" if row["status"] == 200 else "error",
        )
        for row in ledger
    )
    captured = Counter(
        (routes[row["operation_id"]], row["attempt_id"], row["status"])
        for row in calls
        if row["operation_id"] in routes
    )

    def rows(attempts: Counter[tuple[str, str, str]]) -> list[dict[str, str]]:
        return [
            {"route": route, "attempt_id": attempt, "outcome": outcome}
            for route, attempt, outcome in sorted(attempts.elements())
        ]

    missing = rows(physical - captured)
    unmatched = rows(captured - physical)
    return {
        "basis": "same_process_server_ledger_and_closed_fixture_route_map",
        "physical_attempts": sum(physical.values()),
        "captured_attempts": sum(captured.values()),
        "missing_physical_attempts": missing,
        "unmatched_captured_attempts": unmatched,
        "fixture_http_routes_reconciled": not missing and not unmatched,
    }


class FixtureService:
    def __init__(self) -> None:
        self.ledger: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                payload = self.rfile.read(min(length, 65536))
                with fixture.lock:
                    attempt = (
                        sum(row["route"] == self.path for row in fixture.ledger) + 1
                    )
                    status = 503 if self.path == "/retry" and attempt == 1 else 200
                    result = (
                        json.dumps(
                            {
                                "workers": ["file", "database", "process"],
                                "join_background": True,
                            }
                        ).encode()
                        if self.path == "/model"
                        else b"ok"
                    )
                    fixture.ledger.append(
                        {
                            "route": self.path,
                            "attempt": attempt,
                            "request_sha256": hashlib.sha256(payload).hexdigest(),
                            "status": status,
                        }
                    )
                self.send_response(status)
                self.send_header("Content-Length", str(len(result)))
                self.end_headers()
                self.wfile.write(result)

            def log_message(self, *_args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def request(self, route: str, payload: bytes) -> bytes:
        url = f"http://127.0.0.1:{self.server.server_port}{route}"
        request = urllib.request.Request(url, data=payload, method="POST")
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - fixed loopback
            return response.read(65536)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def configure(
    output: Path, provider: TracerProvider, policy_path: Path | None = None
) -> tuple[
    PolicyCaptureSession,
    SyntheticSourceSpool,
    GovernedLocalContentStore,
    GovernedLocalContentStore,
    CapturePolicyRegistry,
    str,
    LocalCapabilityAuthority,
    bytes,
]:
    root = output / "governed"
    privacy = {
        role: "retain_original"
        for role in (
            "tool.call.result",
            "model.output.messages",
            "artifact.after",
            "database.rows",
        )
    }
    privacy.update(
        {
            "tool.call.arguments": "redact",
            "model.request.messages": "metadata_only",
            "memory.write.content": "tokenize",
            "memory.read.content": "tokenize",
            "terminal.stdout": "omit",
            "terminal.stderr": "omit",
        }
    )
    policy = DeploymentPolicy.from_dict(
        {
            "schema_version": "fabric.deployment-policy/v1",
            "policy_id": "orchestration",
            "policy_version": 1,
            "tenant_id": "fixture-tenant",
            "workload_id": "coordinator",
            "privacy": privacy,
            "storage": {
                "backend": "local",
                "region": "local",
                "key_id": "ephemeral-fixture",
                "root": str(root.absolute()),
            },
            "retention": {"days": 1},
            "required_integrations": [],
            "deployment": {
                "profile": "local",
                "image_digest": "local",
                "tls_required": False,
                "encrypted_store_required": True,
            },
        }
    )
    if policy_path is not None:
        policy_bytes = policy_path.read_bytes()
        if len(policy_bytes) > 1024 * 1024:
            raise ValueError("sample policy exceeds its size limit")
        supplied = json.loads(policy_bytes, object_pairs_hook=_unique_object)
        if not isinstance(supplied, dict) or not isinstance(
            supplied.get("storage"), dict
        ):
            raise ValueError("sample policy must contain a storage object")
        if "root" in supplied.get("storage", {}):
            raise ValueError(
                "sample policy must omit storage.root; output owns isolated fixture storage"
            )
        supplied["storage"]["root"] = str(root.absolute())
        policy = DeploymentPolicy.from_dict(supplied)
    authority = LocalCapabilityAuthority(secrets.token_bytes(32))
    key = secrets.token_bytes(32)
    token = authority.issue(
        policy=policy,
        subject_id="fixture-admin",
        permissions={
            "write_original",
            "write_derivative",
            "read_original",
            "read_derivative",
            "policy_admin",
            "policy_read",
            "lifecycle",
            "audit",
        },
    )
    original = GovernedLocalContentStore(
        root, policy=policy, authority=authority, capability=token, encryption_key=key
    )
    derivative = GovernedLocalContentStore(
        root,
        policy=policy,
        authority=authority,
        capability=token,
        encryption_key=key,
        plane="derivative",
    )
    registry = CapturePolicyRegistry(
        output / "config", authority=authority, initial_policy=policy, capability=token
    )
    revision = registry.approve(expected_revision=0, capability=token)
    registry.observe_applied(
        policy_digest=policy.digest,
        expected_revision=revision,
        capabilities=[
            "python-dispatch",
            "local-http",
            "local-file",
            "local-sqlite",
            "local-process",
        ],
        capability=token,
    )
    journal = output / "journal"
    journal.mkdir(mode=0o700)
    spool = SyntheticSourceSpool(
        str(journal.absolute()), tenant_id=policy.tenant_id, run_id="orchestration-run"
    )
    session = PolicyCaptureSession(
        policy=policy,
        store=original,
        derivative_store=derivative,
        source_spool=spool,
        run_id="orchestration-run",
        source_id="coordinator-source",
        agent_id="coordinator",
        queue_max_items=256,
        redactors={
            role: lambda value: value.replace(CANARY, b"[REDACTED]")
            for role, mode in policy.privacy.items()
            if mode == "redact"
        },
        tokenization_key=secrets.token_bytes(32),
        tracer=provider.get_tracer("enterprise-orchestration"),
    )
    return session, spool, original, derivative, registry, token, authority, key


async def orchestrate(
    session: PolicyCaptureSession,
    service: FixtureService,
    output: Path,
    *,
    inject_gaps: bool = True,
) -> dict[str, Any]:
    recorder = session.calls
    memory: dict[str, bytes] = {}
    side_effects = output / "effects"
    side_effects.mkdir(mode=0o700)
    database = side_effects / "state.sqlite"
    ready_workers: set[str] = set()
    workers_ready = asyncio.Event()

    async def join_workers(name: str) -> None:
        ready_workers.add(name)
        if len(ready_workers) == 3:
            workers_ready.set()
        await asyncio.wait_for(workers_ready.wait(), timeout=5)

    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE results (worker TEXT PRIMARY KEY, value INTEGER)"
        )

    async def file_worker(payload: bytes) -> bytes:
        await join_workers("file")
        (side_effects / "result.bin").write_bytes(payload)
        recorder.record_data(payload, role="artifact.after")
        return b"file-written"

    async def database_worker(_payload: bytes) -> bytes:
        await join_workers("database")
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO results VALUES (?, ?)", ("database-worker", 42)
            )
        recorder.record_data(b"42", role="database.rows", boundary="service")
        return b"database-committed"

    async def process_worker(payload: bytes) -> bytes:
        await join_workers("process")
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data.upper())",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate(payload)
        recorder.record_data(stdout, role="terminal.stdout", boundary="terminal")
        recorder.record_data(stderr, role="terminal.stderr", boundary="terminal")
        if process.returncode:
            raise RuntimeError("fixture subprocess failed")
        return b"process-ok"

    async def background(payload: bytes) -> bytes:
        await asyncio.sleep(0.01)
        (side_effects / "background.done").write_bytes(payload)
        return b"background-joined"

    async def cancelled(_payload: bytes) -> bytes:
        await asyncio.sleep(60)
        return b"unreachable"

    async def coordinator(payload: bytes) -> bytes:
        memory["task"] = payload
        recorder.record_data(payload, role="memory.write.content")
        recorder.record_data(memory["task"], role="memory.read.content")
        plan = await recorder.acall(
            b"plan-three-workers",
            lambda data: asyncio.to_thread(service.request, "/model", data),
            kind="model",
            operation_id="model-plan",
            attempt_id="try-1",
        )
        selected = validated_plan(plan)
        workers = {
            "file": file_worker,
            "database": database_worker,
            "process": process_worker,
        }
        task = asyncio.create_task(
            recorder.acall(
                b"done",
                background,
                agent_id="background-worker",
                operation_id="background",
                attempt_id="try-1",
            )
        )
        results = await asyncio.gather(
            *(
                recorder.acall(
                    payload,
                    workers[name],
                    agent_id=name + "-worker",
                    operation_id=name + "-operation",
                    attempt_id="try-1",
                )
                for name in selected
            )
        )
        await task
        for attempt in (1, 2):
            try:
                await recorder.acall(
                    b"retry",
                    lambda data: asyncio.to_thread(service.request, "/retry", data),
                    operation_id="http-retry",
                    attempt_id=f"try-{attempt}",
                )
                break
            except urllib.error.HTTPError:
                if attempt == 2:
                    raise
        cancel_task = asyncio.create_task(
            recorder.acall(
                b"cancel",
                cancelled,
                agent_id="cancel-worker",
                operation_id="cancel-test",
                attempt_id="try-1",
            )
        )
        await asyncio.sleep(0)
        cancel_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await cancel_task
        stream = recorder.stream(
            b"partial",
            lambda _: iter((b"first", b"unconsumed")),
            operation_id="partial-stream" if inject_gaps else "complete-stream",
            attempt_id="try-1",
        )
        if inject_gaps:
            first = next(stream)
            assert first == b"first"
            stream.close()
        else:
            chunks = list(stream)
            assert chunks == [b"first", b"unconsumed"]
        return b"|".join(results)

    result = await recorder.acall(
        CANARY,
        coordinator,
        kind="agent",
        operation_id="orchestrator",
        attempt_id="try-1",
    )
    if inject_gaps:
        # Deliberate uninstrumented operation tests honest coverage failure.
        await asyncio.to_thread(service.request, "/bypass", b"intentional-bypass")
    with sqlite3.connect(database) as independent_connection:
        rows = independent_connection.execute(
            "SELECT worker, value FROM results"
        ).fetchall()
    assert rows == [("database-worker", 42)]
    assert (side_effects / "result.bin").read_bytes() == CANARY
    assert (side_effects / "background.done").read_bytes() == b"done"
    assert result == b"file-written|database-committed|process-ok"
    return {
        "file_readback": True,
        "database_readback": True,
        "background_joined": True,
        "subprocess_completed": True,
        "memory_roundtrip": memory["task"] == CANARY,
        "concurrent_workers_ready": ready_workers == {"file", "database", "process"},
    }


def run(
    output: Path, policy_path: Path | None = None, *, scenario: str = "gaps"
) -> dict[str, Any]:
    if scenario not in {"clean", "gaps"}:
        raise ValueError("scenario must be clean or gaps")
    inject_gaps = scenario == "gaps"
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    provider = TracerProvider()
    session, spool, original, derivative, registry, token, authority, key = configure(
        output, provider, policy_path
    )
    spool_closed = False
    service = FixtureService()
    try:
        effects = asyncio.run(
            orchestrate(session, service, output, inject_gaps=inject_gaps)
        )
        report = session.report()
        snapshot = report["source_snapshot"]
        calls = snapshot["calls"]
        states = {row["operation_id"]: row["status"] for row in calls}
        assert states["cancel-test"] == "cancelled"
        assert states["partial-stream" if inject_gaps else "complete-stream"] == (
            "partial" if inject_gaps else "ok"
        )
        retries = [
            row["status"] for row in calls if row["operation_id"] == "http-retry"
        ]
        assert retries == ["error", "ok"]
        assert any(row["parent_call_id"] is not None for row in calls)
        assert snapshot["recording_gaps"] == 0 and snapshot["unretained_drops"] == 0
        batches = session.metadata_batches(batch_size=8)
        assert all(CANARY not in payload for payload, _ in batches)
        ledger = list(service.ledger)
        http_reconciliation = reconcile_http_attempts(ledger, calls)
        assert http_reconciliation["unmatched_captured_attempts"] == []
        assert http_reconciliation["missing_physical_attempts"] == (
            [{"route": "/bypass", "attempt_id": "try-1", "outcome": "ok"}]
            if inject_gaps
            else []
        )
        # Real authorization denial exercises passive capture loss, not a fake store.
        read_token = authority.issue(
            policy=session.policy,
            subject_id="restricted-writer",
            permissions={"read_original"},
        )
        denied_store = GovernedLocalContentStore(
            original.root,
            policy=session.policy,
            authority=authority,
            capability=read_token,
            encryption_key=key,
        )
        denied_writer = ByteEvidenceRecorder(
            ByteEvidenceConfig(
                store=denied_store,
                roles=frozenset({"tool.call.arguments", "tool.call.result"}),
            )
        )
        denied_recorder = CallRecorder(
            denied_writer,
            run_id="denied-run",
            source_id="denied-source",
            agent_id="agent",
            tracer=provider.get_tracer("denied-store"),
        )
        denied_result = denied_recorder.call(
            b"input", lambda _: b"application-still-works"
        )
        assert denied_result == b"application-still-works"
        denied_snapshot = denied_recorder.snapshot()
        assert all(row["status"] == "failed" for row in denied_snapshot["events"])
        denied_writer.close()
        denied_store.close()
        seal = session.calls.seal_source()
        # A complete metadata seal still does not prove independent route or
        # destination closure. Withheld bytes and partial streams refuse it.
        expected_seal = (
            "refused"
            if inject_gaps
            or any(row["status"] != "stored" for row in snapshot["events"])
            else "sealed"
        )
        assert seal["status"] == expected_seal
        report = session.report()
        session.close()
        spool.close()
        spool_closed = True
        recovery: dict[str, Any] = {"status": "not_run", "source_epoch": 0}
        if inject_gaps:
            recovered = SyntheticSourceSpool(
                str((output / "journal").absolute()),
                tenant_id=session.policy.tenant_id,
                run_id="orchestration-run",
            )
            try:
                recovered_count = len(recovered.recovered())
                assert recovered.epoch == 1 and recovered_count > 0
                recovery = {
                    "status": "recovered_unqualified",
                    "new_epoch": recovered.epoch,
                    "recovered_records": recovered_count,
                    "original_history_verified": False,
                    "qualification": "unsupported_multi_epoch",
                }
            finally:
                recovered.close()
        report.update(
            {
                "fixture_kind": "deterministic_http_plan_not_llm",
                "scenario": scenario,
                "effect_readback": effects,
                "independent_http_ledger": ledger,
                "captured_http_attempts": http_reconciliation["captured_attempts"],
                "http_reconciliation": http_reconciliation,
                "deliberate_bypass_detected": bool(
                    http_reconciliation["missing_physical_attempts"]
                ),
                "full_route_coverage_complete": False,
                "retry_outcomes": retries,
                "cancellation_preserved": True,
                "partial_stream_detected": "partial" in states.values(),
                "source_seal": seal,
                "source_recovery": recovery,
                "passive_denied_storage": {
                    "application_result_preserved": True,
                    "event_statuses": [
                        row["status"] for row in denied_snapshot["events"]
                    ],
                },
                "deployment": registry.read(token),
                "storage": original.attestation(),
                "production_verdict": "NO_GO",
                "fixture_keys": "ephemeral_not_saved",
                "external_model_provider": "not_invoked",
                "cross_process_capture": "unsupported",
                "node_and_destination_receipts": "not_run",
            }
        )
        encoded = json.dumps(report, indent=2).encode()
        assert CANARY not in encoded
        (output / "report.json").write_bytes(encoded)
        (output / "policy.json").write_text(
            json.dumps(session.policy.to_dict(), indent=2)
        )
        return report
    finally:
        service.close()
        session.close()
        if not spool_closed:
            spool.close()
        original.close()
        derivative.close()
        provider.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--policy", type=Path, help="validated full policy JSON without storage.root"
    )
    parser.add_argument(
        "--scenario",
        choices=("clean", "gaps"),
        default="gaps",
        help="clean fixture or deliberate bypass/partial-stream/restart (default: gaps)",
    )
    args = parser.parse_args()
    report = run(args.output, args.policy, scenario=args.scenario)
    print(
        json.dumps(
            {
                "result": "LOCAL_CHECKS_PASS",
                "production_verdict": "NO_GO",
                "scenario": report["scenario"],
                "deliberate_bypass_detected": report["deliberate_bypass_detected"],
                "report": str(args.output / "report.json"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
