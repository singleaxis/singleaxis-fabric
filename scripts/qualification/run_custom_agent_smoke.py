#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Installed-wheel custom dispatcher, exact-data and independent-state smoke.

Synthetic data only. Provider witnesses are collected inside delegates outside
the recorder; file/SQLite readback uses separate reads/connections. These
fixture records are not authenticated production audit feeds.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import sqlite3
import sys
import tempfile
import uuid
from contextlib import nullcontext
from pathlib import Path

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    ByteEvidenceConfig,
    ByteEvidenceRecorder,
    BytePrivacyPolicy,
    LocalFilesystemContentStore,
)
from fabric import __file__ as fabric_package_file
from fabric.call_recorder import CallRecorder
from fabric.call_reconcile import (
    CallByteWitness,
    CallOperationWitness,
    RouteDeclaration,
    reconcile_call_run,
)
from fabric.synthetic_reconcile import SyntheticByteResolver
from fabric.source_spool import SyntheticSourceSpool

SOURCE = "dispatcher"
CANARY = b"CUSTOM_AGENT_PRIVATE_CANARY"
ROLES = frozenset(
    {
        "tool.call.arguments",
        "tool.call.result",
        "model.request.messages",
        "model.output.messages",
        "database.query",
        "database.rows",
        "artifact.after",
    }
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--otlp-endpoint")
    parser.add_argument("--ca-cert")
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")
    parser.add_argument("--bearer-token-file")
    args = parser.parse_args()
    run_id = "custom-agent-" + uuid.uuid4().hex
    installed = Path(fabric_package_file).resolve()
    if not installed.is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError("smoke requires a wheel installed in a virtual environment")
    expected: list[CallByteWitness] = []
    outcomes: list[CallOperationWitness] = []

    def witnessed(
        op: str,
        boundary: str,
        role: str,
        data: bytes,
        chunk: int | None = None,
        source: str = "fixture",
    ) -> None:
        expected.append(
            CallByteWitness(
                run_id,
                SOURCE,
                boundary,
                op,
                "try-1",
                role,
                data,
                chunk_index=chunk,
                witness_source=source,
            )
        )

    def ended(op: str, boundary: str, source: str = "fixture") -> None:
        outcomes.append(
            CallOperationWitness(
                run_id,
                SOURCE,
                boundary,
                op,
                "try-1",
                {"result_status": "ok"},
                witness_source=source,
            )
        )

    if args.evidence_dir is not None:
        args.evidence_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    workspace = (
        nullcontext(str(args.evidence_dir))
        if args.evidence_dir is not None
        else tempfile.TemporaryDirectory(prefix="fabric-custom-agent-")
    )
    with workspace as directory:
        root = Path(directory)
        journal_path = root / "source-journal"
        journal_path.mkdir(mode=0o700)
        spool = SyntheticSourceSpool(
            str(journal_path.resolve()), tenant_id="synthetic", run_id=run_id
        )
        store = LocalFilesystemContentStore(
            str(root / "protected"), tenant_id="synthetic"
        )
        writer = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=ROLES))
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        recorder = CallRecorder(
            writer,
            run_id=run_id,
            agent_id="coordinator",
            source_id=SOURCE,
            tracer=provider.get_tracer("custom-agent-smoke"),
            source_spool=spool,
        )
        database = root / "fixture.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE evidence (value INTEGER)")
        artifact = root / "result.bin"

        def provider_stream(payload: bytes):
            witnessed(
                "model-plan",
                "provider_bound",
                "model.request.messages",
                payload,
                source="provider",
            )
            for index, chunk in enumerate((b"write:", b"42")):
                witnessed(
                    "model-plan",
                    "provider_bound",
                    "model.output.messages",
                    chunk,
                    index,
                    "provider",
                )
                yield chunk
            ended("model-plan", "provider_bound", "provider")

        async def file_tool(payload: bytes) -> bytes:
            witnessed("file-write", "tool", "tool.call.arguments", payload)
            await asyncio.sleep(0)
            artifact.write_bytes(payload)
            recorder.record_data(artifact.read_bytes(), role="artifact.after")
            # A separate filesystem observation supplies expected effect bytes.
            witnessed(
                "file-write",
                "tool",
                "artifact.after",
                artifact.read_bytes(),
                source="filesystem",
            )
            result = b"file-written"
            witnessed("file-write", "tool", "tool.call.result", result)
            ended("file-write", "tool")
            return result

        async def database_tool(payload: bytes) -> bytes:
            witnessed("db-write", "service", "database.query", payload, source="sqlite")
            await asyncio.sleep(0)
            with sqlite3.connect(database) as connection:
                connection.execute(payload.decode("ascii"))
                connection.commit()
            # Read through an independent read-only connection after commit.
            with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as observer:
                rows = observer.execute(
                    "SELECT value FROM evidence ORDER BY value"
                ).fetchall()
            result = json.dumps(rows, separators=(",", ":")).encode("ascii")
            witnessed("db-write", "service", "database.rows", result, source="sqlite")
            ended("db-write", "service", "sqlite")
            return result

        def provider_finish(payload: bytes) -> bytes:
            witnessed(
                "model-answer",
                "provider_bound",
                "model.request.messages",
                payload,
                source="provider",
            )
            result = b"completed"
            witnessed(
                "model-answer",
                "provider_bound",
                "model.output.messages",
                result,
                source="provider",
            )
            ended("model-answer", "provider_bound", "provider")
            return result

        async def agent(payload: bytes) -> bytes:
            witnessed("agent", "caller", "tool.call.arguments", payload)
            stream = recorder.stream(
                CANARY,
                provider_stream,
                kind="model",
                operation_id="model-plan",
                attempt_id="try-1",
            )
            chunks = list(stream)
            if chunks != [b"write:", b"42"]:
                raise AssertionError("model stream behavior changed")
            file_result, database_result = await asyncio.gather(
                recorder.acall(
                    b"\x00\xff" + CANARY,
                    file_tool,
                    kind="tool",
                    operation_id="file-write",
                    attempt_id="try-1",
                    agent_id="file-agent",
                ),
                recorder.acall(
                    b"INSERT INTO evidence VALUES (42)",
                    database_tool,
                    kind="database",
                    operation_id="db-write",
                    attempt_id="try-1",
                    agent_id="db-agent",
                ),
            )
            result = recorder.call(
                file_result + database_result,
                provider_finish,
                kind="model",
                operation_id="model-answer",
                attempt_id="try-1",
            )
            witnessed("agent", "caller", "tool.call.result", result)
            ended("agent", "caller")
            return result

        async def run() -> bytes:
            return await recorder.acall(
                b"synthetic-task",
                agent,
                kind="agent",
                operation_id="agent",
                attempt_id="try-1",
            )

        result = asyncio.run(run())
        if result != b"completed":
            raise AssertionError("agent result changed")
        snapshot = recorder.snapshot()
        spans = exporter.get_finished_spans()
        if len(spans) != 5 or len({span.context.trace_id for span in spans}) != 1:
            raise AssertionError(
                "custom-agent timeline did not preserve trace relationships"
            )
        if any(
            CANARY in str(span.attributes).encode() or span.events for span in spans
        ):
            raise AssertionError("private data escaped into call spans")
        resolver = SyntheticByteResolver(store, tenant_id="synthetic")
        routes = [
            RouteDeclaration("dispatcher-" + boundary, "1", boundary)
            for boundary in ("caller", "provider_bound", "tool", "service")
        ]
        clean = reconcile_call_run(
            snapshot, expected, resolver, expected_operations=outcomes, routes=routes
        )
        if clean["discrepancies"] or clean["verdict"] != "unverified":
            raise AssertionError(
                "clean custom-agent records did not reconcile: " + json.dumps(clean)
            )
        if (
            CANARY in json.dumps(snapshot).encode()
            or CANARY in json.dumps(clean).encode()
        ):
            raise AssertionError("private content escaped protected storage")

        # Independent expectation reveals a call outside the wrapped dispatcher.
        bypass_query = b"INSERT INTO evidence VALUES (99)"
        with sqlite3.connect(database) as connection:
            connection.execute(bypass_query.decode("ascii"))
            connection.commit()
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as observer:
            if observer.execute(
                "SELECT COUNT(*) FROM evidence WHERE value=99"
            ).fetchone() != (1,):
                raise AssertionError("direct database bypass did not execute")
        bypass = CallByteWitness(
            run_id,
            SOURCE,
            "service",
            "direct-call",
            "try-1",
            "database.query",
            bypass_query,
            witness_source="sqlite",
        )
        missing = reconcile_call_run(
            snapshot,
            [*expected, bypass],
            resolver,
            expected_operations=outcomes,
            routes=routes,
        )
        tampered = copy.deepcopy(snapshot)
        first = next(event for event in tampered["events"] if "descriptor" in event)
        first["descriptor"]["stored_sha256"] = "sha256:" + "0" * 64
        corrupted = reconcile_call_run(
            tampered, expected, resolver, expected_operations=outcomes, routes=routes
        )
        if missing["verdict"] != "partial" or corrupted["verdict"] != "partial":
            raise AssertionError("missing or corrupted evidence did not lower verdict")

        def failed_mask(_data: bytes) -> bytes:
            raise RuntimeError(CANARY.decode())

        privacy_store = LocalFilesystemContentStore(
            str(root / "privacy-protected"), tenant_id="synthetic"
        )
        privacy_roles = frozenset({"tool.call.arguments", "tool.call.result"})
        privacy_writer = ByteEvidenceRecorder(
            ByteEvidenceConfig(
                store=privacy_store,
                roles=privacy_roles,
                role_policies={
                    role: BytePrivacyPolicy(
                        mode="masked_only",
                        transform=failed_mask,
                        transformation_id="fixture-mask",
                        transformation_version="1",
                    )
                    for role in privacy_roles
                },
            )
        )
        privacy_run = run_id + "-privacy"
        privacy_calls = CallRecorder(
            privacy_writer,
            run_id=privacy_run,
            agent_id="privacy-agent",
            source_id=SOURCE,
            tracer=provider.get_tracer("privacy-smoke"),
        )
        privacy_result = privacy_calls.call(
            CANARY, lambda value: value, operation_id="privacy-op", attempt_id="try-1"
        )
        if privacy_result is not CANARY:
            raise AssertionError("privacy transformation failure changed agent result")
        privacy_snapshot = privacy_calls.snapshot()
        privacy_report = reconcile_call_run(
            privacy_snapshot,
            [
                CallByteWitness(
                    privacy_run, SOURCE, "tool", "privacy-op", "try-1", role, CANARY
                )
                for role in sorted(privacy_roles)
            ],
            SyntheticByteResolver(privacy_store, tenant_id="synthetic"),
            expected_operations=[
                CallOperationWitness(
                    privacy_run,
                    SOURCE,
                    "tool",
                    "privacy-op",
                    "try-1",
                    {"result_status": "ok"},
                )
            ],
            routes=[RouteDeclaration("privacy-tool", "1", "tool")],
        )
        if (
            privacy_report["verdict"] != "partial"
            or CANARY in json.dumps(privacy_snapshot).encode()
        ):
            raise AssertionError("privacy failure was not safely reported")
        if not privacy_writer.close():
            raise AssertionError("privacy writer did not settle")
        if not writer.close():
            raise AssertionError("content writer did not settle")
        if not spool.close():
            raise AssertionError("source journal did not settle")
        provider.shutdown()
        summary = {
            "schema_version": "fabric.custom-agent-smoke/v1",
            "installed_wheel": True,
            "run_id": run_id,
            "calls": len(snapshot["calls"]),
            "byte_objects": len(expected),
            "independent_discrepancies": len(clean["discrepancies"]),
            "clean_verdict": clean["verdict"],
            "bypass_verdict": missing["verdict"],
            "corruption_verdict": corrupted["verdict"],
            "qualification": "NO_GO",
            "privacy_failure_verdict": privacy_report["verdict"],
        }
        if args.otlp_endpoint:
            from fabric.call_otlp import export_call_snapshot, project_call_snapshot

            projected, record_ids = project_call_snapshot(snapshot)
            if CANARY in projected or b"file://" in projected:
                raise AssertionError(
                    "private content or local refs escaped metadata projection"
                )
            receipt = export_call_snapshot(
                snapshot,
                args.otlp_endpoint,
                ca_cert_path=args.ca_cert,
                client_cert_path=args.client_cert,
                client_key_path=args.client_key,
                bearer_token_path=args.bearer_token_file,
            )
            if receipt.get("receipt_stage") != "node_accepted":
                raise AssertionError(
                    "Node did not fully accept the custom-call metadata"
                )
            summary["node_export"] = receipt
            summary["projected_records"] = len(record_ids)
            if args.evidence_dir is not None:
                (root / "projected.json").write_bytes(projected)
            privacy_projected, privacy_ids = project_call_snapshot(privacy_snapshot)
            if CANARY in privacy_projected:
                raise AssertionError(
                    "failed masking canary escaped metadata projection"
                )
            privacy_receipt = export_call_snapshot(
                privacy_snapshot,
                args.otlp_endpoint,
                ca_cert_path=args.ca_cert,
                client_cert_path=args.client_cert,
                client_key_path=args.client_key,
                bearer_token_path=args.bearer_token_file,
            )
            if privacy_receipt.get("receipt_stage") != "node_accepted":
                raise AssertionError("Node did not accept privacy-failure metadata")
            summary["privacy_projected_records"] = len(privacy_ids)
            if args.evidence_dir is not None:
                (root / "privacy-projected.json").write_bytes(privacy_projected)
        if args.evidence_dir is not None:
            for filename, document in (
                ("snapshot.json", snapshot),
                ("report.json", clean),
                ("summary.json", summary),
                ("privacy-report.json", privacy_report),
            ):
                target = root / filename
                target.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
                os.chmod(target, 0o600)
        print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
