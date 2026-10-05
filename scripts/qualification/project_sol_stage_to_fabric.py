#!/usr/bin/env python3
"""Post-run, test-only Fabric projection of one synthetic Sol CLI evidence set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, LocalFilesystemContentStore
from fabric.adapters.synthetic_evidence import SyntheticCaptureSession
from fabric.source_spool import SyntheticSourceSpool
from fabric.synthetic_otlp import project_synthetic_snapshot
from fabric.synthetic_reconcile import SyntheticByteResolver

ROLES = frozenset(
    {
        "interaction.payload",
        "model.request.messages",
        "model.output.messages",
        "tool.call.arguments",
        "tool.call.result",
        "network.request",
        "network.response",
        "artifact.after",
    }
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.evidence_dir.resolve(strict=True)
    source_report = json.loads((root / "reconciliation.json").read_text())
    if source_report.get("production_go") is not False:
        raise ValueError("stage report must not claim production GO")
    projection = Path(tempfile.mkdtemp(prefix="fabric-projection-", dir=root))
    (projection / "source-spool").mkdir(mode=0o700)
    tenant = "synthetic-sol-stage"
    run_id = root.name
    store = LocalFilesystemContentStore(str(projection / "content"), tenant_id=tenant)
    recorder = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=ROLES))
    spool = SyntheticSourceSpool(
        str(projection / "source-spool"), tenant_id=tenant, run_id=run_id
    )
    session = SyntheticCaptureSession(
        recorder, tenant_id=tenant, run_id=run_id, source_spool=spool
    )
    truth: dict[tuple[str, str, str, str], bytes] = {}

    def capture(
        path_or_bytes: Path | bytes,
        source: str,
        boundary: str,
        role: str,
        operation: str,
    ) -> None:
        data = (
            path_or_bytes.read_bytes()
            if isinstance(path_or_bytes, Path)
            else path_or_bytes
        )
        session.capture(
            data,
            source_id=source,
            boundary=boundary,
            role=role,
            operation_id=operation,
            attempt_id="attempt-1",
        )
        truth[(source, boundary, role, operation)] = data

    try:
        capture(
            root / "prompt.txt",
            "codex-cli",
            "caller",
            "model.request.messages",
            "prompt",
        )
        capture(
            root / "codex.jsonl",
            "codex-cli",
            "caller",
            "interaction.payload",
            "cli-jsonl",
        )
        events = [
            json.loads(line)
            for line in (root / "codex.jsonl").read_bytes().splitlines()
        ]
        for index, event in enumerate(events):
            if event.get("type") != "item.completed":
                continue
            item = event.get("item") or {}
            if item.get("type") == "agent_message":
                capture(
                    item.get("text", "").encode(),
                    "codex-cli",
                    "caller",
                    "model.output.messages",
                    f"message-{index:04d}",
                )
            elif item.get("type") == "command_execution":
                operation = f"command-{index:04d}"
                capture(
                    item.get("command", "").encode(),
                    "codex-cli",
                    "tool",
                    "tool.call.arguments",
                    operation,
                )
                capture(
                    item.get("aggregated_output", "").encode(),
                    "codex-cli",
                    "tool",
                    "tool.call.result",
                    operation,
                )
                for role in (
                    "terminal.argv",
                    "terminal.stdin",
                    "terminal.stdout",
                    "terminal.stderr",
                ):
                    session.gap(
                        source_id="codex-cli",
                        boundary="terminal",
                        role=role,
                        operation_id=operation,
                        attempt_id="attempt-1",
                        status="unsupported",
                        reason="cli_jsonl_does_not_expose_raw_terminal_role",
                    )
        for role in ("model.request.messages", "model.output.messages"):
            session.gap(
                source_id="codex-cli",
                boundary="provider_bound",
                role=role,
                operation_id="model-boundary",
                attempt_id="attempt-1",
                status="unsupported",
                reason="subscription_cli_does_not_expose_final_provider_bound_bytes",
            )
        journal = [
            json.loads(line)
            for line in (root / "service-journal.jsonl").read_text().splitlines()
        ]
        for entry in journal:
            operation = f"service-{entry['sequence']:04d}"
            capture(
                root / entry["request"]["path"],
                "fixture-service",
                "service",
                "network.request",
                operation,
            )
            capture(
                root / entry["response"]["path"],
                "fixture-service",
                "service",
                "network.response",
                operation,
            )
        for name in ("report.json", "artifact.bin"):
            path = root / "agent-workspace" / name
            if path.is_file():
                capture(
                    path, "fixture-fs", "host", "artifact.after", f"artifact-{name}"
                )
        snapshot = session.snapshot()
        resolver = SyntheticByteResolver(store, tenant_id=tenant)
        mismatches = []
        checked = 0
        for event in snapshot["events"]:
            if event["status"] == "unsupported":
                continue
            key = (
                event["source_id"],
                event["boundary"],
                event["role"],
                event["operation_id"],
            )
            expected = truth.get(key)
            descriptor = event.get("descriptor")
            if expected is None or descriptor is None:
                mismatches.append(
                    {
                        "record_id": event["record_id"],
                        "error": "missing_expected_or_descriptor",
                    }
                )
                continue
            result = resolver.resolve(descriptor)
            if result.status != "available" or result.data != expected:
                mismatches.append(
                    {
                        "record_id": event["record_id"],
                        "role": event["role"],
                        "resolution": result.status,
                    }
                )
            else:
                checked += 1
        payload, record_ids = project_synthetic_snapshot(snapshot)
        if b"FABRIC_SYNTHETIC_SECRET_DO_NOT_EXPORT" in payload:
            mismatches.append({"error": "canary_in_otlp_metadata"})
        write_private(
            projection / "snapshot.json", json.dumps(snapshot, sort_keys=True).encode()
        )
        write_private(projection / "otlp-metadata.json", payload)
        result = {
            "verdict": "partial"
            if mismatches
            or any(e["status"] == "unsupported" for e in snapshot["events"])
            else "unverified",
            "production_go": False,
            "stored_objects_resolved": checked,
            "captured_event_count": len(snapshot["events"]),
            "unsupported_event_count": sum(
                e["status"] == "unsupported" for e in snapshot["events"]
            ),
            "metadata_record_count": len(record_ids),
            "source_spool_settled": snapshot["source_spool_settled"],
            "writer_settled": snapshot["writer_settled"],
            "source_identity_authenticated": snapshot["source_identity_authenticated"],
            "pre_spool_crash_window_unverified": snapshot[
                "pre_spool_crash_window_unverified"
            ],
            "otlp_metadata_sha256": sha256(payload),
            "mismatches": mismatches,
            "excluded": [
                "node_acceptance",
                "destination_durable_receipt",
                "provider_bound_bytes",
                "raw_terminal_streams",
            ],
        }
        write_private(
            projection / "resolution-report.json",
            (json.dumps(result, indent=2, sort_keys=True) + "\n").encode(),
        )
        print(
            json.dumps(
                {
                    "projection_dir": str(projection),
                    "verdict": result["verdict"],
                    "stored_objects_resolved": checked,
                    "mismatches": len(mismatches),
                },
                sort_keys=True,
            )
        )
        return 0 if not mismatches and checked else 2
    finally:
        spool.close()
        recorder.close()


if __name__ == "__main__":
    raise SystemExit(main())
