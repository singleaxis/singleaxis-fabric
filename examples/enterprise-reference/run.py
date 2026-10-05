#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run a finite derivative-only reference deployment with actual service crashes.

The ingress and destination are separate local processes, not production OTel
Collector or cloud attestations. The orchestrator owns ephemeral test keys.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import secrets
import resource
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

from fabric.byte_evidence import (
    ByteEvidenceConfig,
    ByteEvidenceRecorder,
    BytePrivacyPolicy,
)
from fabric.byte_spool import DurableByteSpool
from fabric.call_otlp import project_call_snapshot_batches
from fabric.call_recorder import CallRecorder
from fabric.evidence_attestation import EvidenceTrustKey
from fabric.metadata_delivery import JournalMetadataSender
from fabric.http_dispatch import FinalHTTPAdapter, IndependentHTTPWitness
from fabric.receipt_sets import (
    EvidenceSetEntry,
    ReceiptSetExpectation,
    metadata_entries,
    verify_receipt_set,
)
from fabric.reference_receipts import ReferenceReceiptClient

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from processes import ReferenceProcess  # noqa: E402

CANARY = b"REFERENCE_PRIVATE_CANARY_NEVER_PERSIST"
TENANT = "reference-tenant"
RUN = "reference-run"
SCOPE = "sha256:" + hashlib.sha256(b"python-reference-derivative-only-v1").hexdigest()


def _module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _private(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode("ascii")


def _service_configuration(
    output: Path, role: str, key: Ed25519PrivateKey
) -> dict[str, Any]:
    return {
        "root": str(output / role),
        "tenant_id": TENANT,
        "run_id": RUN,
        "scope_sha256": SCOPE,
        "role": role,
        "issuer_id": role + "-issuer",
        "key_id": role + "-key",
        "signing_key_base64": _private(key),
        "bearer_token": secrets.token_hex(32),
        "port": 0,
    }


def _client(configuration: dict[str, Any], endpoint: str) -> ReferenceReceiptClient:
    return ReferenceReceiptClient(
        endpoint,
        tenant_id=TENANT,
        run_id=RUN,
        scope_sha256=SCOPE,
        bearer_token=configuration["bearer_token"],
        timeout_s=0.5,
    )


def _snapshot(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "fabric.call-recording/v1",
        "tenant_id": TENANT,
        "run_id": RUN,
        "starts": [row for row in records if row["role"] == "operation.start"],
        "operations": [row for row in records if row["role"] == "operation.outcome"],
        "events": [
            row
            for row in records
            if row["role"] not in {"operation.start", "operation.outcome"}
        ],
    }


def _expected_metadata(records: list[dict[str, Any]]) -> tuple[EvidenceSetEntry, ...]:
    return tuple(
        entry
        for payload, _ids in project_call_snapshot_batches(
            _snapshot(records), batch_size=128
        )
        for entry in metadata_entries(payload)
    )


def _same_entries(
    actual: list[dict[str, Any]], expected: tuple[EvidenceSetEntry, ...]
) -> bool:
    def key(value: dict[str, Any]) -> tuple[str, str]:
        return value["kind"], value["identifier"]

    return sorted(actual, key=key) == sorted(
        [asdict(value) for value in expected], key=key
    )


def _wait_inventory(
    client: ReferenceReceiptClient,
    expected: tuple[EvidenceSetEntry, ...],
    *,
    timeout_s: float = 15,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inventory = client.inventory()
        if _same_entries(inventory["entries"], expected):
            return inventory
        time.sleep(0.05)
    raise RuntimeError("reference exact destination inventory did not converge")


def run(output: Path, *, iterations: int = 20) -> dict[str, Any]:  # noqa: PLR0915
    from fabric.reference_receipts import ReferenceByteStore
    from fabric.source_spool import SyntheticSourceSpool

    if type(iterations) is not int or not 1 <= iterations <= 100:
        raise ValueError("reference iterations must be between 1 and 100")
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    destination_key, node_key = (
        Ed25519PrivateKey.generate(),
        Ed25519PrivateKey.generate(),
    )
    destination_config = _service_configuration(output, "destination", destination_key)
    node_config = _service_configuration(output, "node", node_key)
    destination = ReferenceProcess(destination_config)
    node: ReferenceProcess | None = None
    writer: ByteEvidenceRecorder | None = None
    journal: SyntheticSourceSpool | None = None
    sender: JournalMetadataSender | None = None
    byte_spool: DurableByteSpool | None = None
    provider = TracerProvider(sampler=ALWAYS_ON)
    baseline_witness = IndependentHTTPWitness(
        output / "baseline-http", responses=((200, CANARY),)
    )
    capture_witness = IndependentHTTPWitness(
        output / "captured-http", responses=((200, CANARY),)
    )
    encryption_key = secrets.token_bytes(32)
    try:
        destination_ready = destination.start()
        destination_client = _client(destination_config, destination_ready["endpoint"])
        node_config["destination"] = {
            "endpoint": destination_ready["endpoint"],
            "tenant_id": TENANT,
            "run_id": RUN,
            "scope_sha256": SCOPE,
            "bearer_token": destination_config["bearer_token"],
            "timeout_s": 0.5,
        }
        node = ReferenceProcess(node_config)
        node_ready = node.start()
        node_client = _client(node_config, node_ready["endpoint"])
        destination.stop(kill=True)
        outage_started = time.monotonic()
        for directory in ("journal", "outbox"):
            (output / directory).mkdir(mode=0o700)

        def make_writer() -> tuple[ByteEvidenceRecorder, DurableByteSpool]:
            spool = DurableByteSpool(
                output / "byte-spool",
                tenant_id=TENANT,
                encryption_key=encryption_key,
                max_records=1024,
                max_attempts=1000,
                retry_initial_s=0.05,
                retry_max_s=0.2,
            )
            policy = BytePrivacyPolicy(
                mode="masked_only",
                transform=lambda data: data.replace(CANARY, b"[REDACTED]"),
                transformation_id="reference-redactor",
                transformation_version="1",
            )
            store = ReferenceByteStore(destination_client)
            recorder = ByteEvidenceRecorder(
                ByteEvidenceConfig(
                    store=store,
                    roles=frozenset(
                        {"model.request.messages", "model.output.messages"}
                    ),
                    role_policies={
                        "model.request.messages": policy,
                        "model.output.messages": policy,
                    },
                    durable_spool=spool,
                    queue_max_items=1024,
                    max_records=1024,
                )
            )
            return recorder, spool

        writer, byte_spool = make_writer()
        journal = SyntheticSourceSpool(
            str(output / "journal"),
            tenant_id=TENANT,
            run_id=RUN,
            max_records=2048,
            queue_max_items=2048,
        )
        calls = CallRecorder(
            writer,
            run_id=RUN,
            source_id="python-reference",
            agent_id="reference-agent",
            source_spool=journal,
            max_events=2048,
            tracer=provider.get_tracer("reference"),
        )
        measurements = _module(
            "reference_measurements",
            HERE.parents[1] / "scripts/qualification/capture_measurements.py",
        )
        baseline_witness.start()
        capture_witness.start()
        baseline_http = FinalHTTPAdapter(declared_url=baseline_witness.url)
        captured_http = FinalHTTPAdapter(
            declared_url=capture_witness.url, recorder=calls
        )
        attempts = {"baseline": 0, "capture": 0}

        def dispatch(
            adapter: FinalHTTPAdapter, url: str, value: bytes, phase: str
        ) -> bytes:
            attempts[phase] += 1
            return adapter.request(
                "POST",
                url,
                value,
                operation_id="measured-http",
                attempt_id=f"{phase}-{attempts[phase]}",
            ).body

        measurement = measurements.measure_passive_calls(
            lambda value: dispatch(
                baseline_http, baseline_witness.url, value, "baseline"
            ),
            lambda value: dispatch(
                captured_http, capture_witness.url, value, "capture"
            ),
            payload=CANARY,
            iterations=iterations,
        )
        boundary_clean = captured_http.reconcile(capture_witness.inventory())
        FinalHTTPAdapter(declared_url=capture_witness.url).request(
            "POST",
            capture_witness.url,
            CANARY,
            operation_id="deliberate-bypass",
            attempt_id="bypass-1",
        )
        boundary_bypass = captured_http.reconcile(capture_witness.inventory())
        if not writer.wait_durable(10) or not journal.flush(10):
            raise RuntimeError("reference durable admission failed")
        outage_health = byte_spool.health()
        if outage_health["durable"] != 2 * iterations or outage_health["delivered"]:
            raise RuntimeError("outage was not retained as pending durable evidence")
        # Freeze acknowledged identities BEFORE any restart. Recovered inventory
        # is evidence to compare, never the authority for what should exist.
        original_records = journal.durable_records()
        expected_metadata = _expected_metadata(original_records)
        original_descriptors = [
            byte_spool.descriptor(identity) for identity in byte_spool.object_ids()
        ]
        expected_content = tuple(
            EvidenceSetEntry(
                "content_object",
                row["object_id"],
                row["stored_sha256"],
                row["stored_byte_length"],
            )
            for row in original_descriptors
            if row is not None
        )
        content_ids = {row.identifier for row in expected_content}
        referenced_ids = {
            row["object_id"] for row in original_records if "object_id" in row
        }
        if len(expected_content) != 2 * iterations or content_ids != referenced_ids:
            raise RuntimeError("pre-restart source/content identity mismatch")
        (output / "source-expectations.json").write_text(
            json.dumps(
                {
                    "basis": "orchestrator frozen durable acknowledgement before crash",
                    "metadata": [asdict(row) for row in expected_metadata],
                    "content": [asdict(row) for row in expected_content],
                },
                sort_keys=True,
            )
            + "\n"
        )
        sender = JournalMetadataSender(
            str(output / "outbox"),
            journal=journal,
            transport=node_client,
            batch_size=32,
            retry_initial_s=0.05,
            retry_max_s=0.2,
        )
        if not sender.drain(10):
            raise RuntimeError("reference node metadata acceptance failed")
        before_ids = [row["batch_id"] for row in sender.manifest()["batches"]]
        accepted_before_restart = sender.health()
        node.stop(kill=True)
        sender.close()
        sender = None
        writer.close(0.2)
        writer = None
        byte_spool.close(2)
        byte_spool = None
        journal.close()
        journal = None
        destination.restart()
        outage_ms = (time.monotonic() - outage_started) * 1000
        node.restart()
        recovery_started = time.monotonic()
        writer, byte_spool = make_writer()
        journal = SyntheticSourceSpool(
            str(output / "journal"),
            tenant_id=TENANT,
            run_id=RUN,
            max_records=2048,
            queue_max_items=2048,
        )
        sender = JournalMetadataSender(
            str(output / "outbox"),
            journal=journal,
            transport=node_client,
            batch_size=32,
            retry_initial_s=0.05,
            retry_max_s=0.2,
        )
        if not sender.drain(10) or not writer.flush(10):
            raise RuntimeError("reference recovery did not settle")
        descriptors = [writer.get(identity) for identity in byte_spool.object_ids()]
        if any(
            row is None or row["status"] not in {"stored", "redacted"}
            for row in descriptors
        ):
            raise RuntimeError(
                "recovered byte objects did not all settle: "
                + json.dumps(byte_spool.health())
            )
        recovered_content = tuple(
            EvidenceSetEntry(
                "content_object",
                row["object_id"],
                row["stored_sha256"],
                row["stored_byte_length"],
            )
            for row in descriptors
            if row is not None
        )
        recovered_metadata = _expected_metadata(journal.durable_records())
        if set(recovered_content) != set(expected_content) or set(
            recovered_metadata
        ) != set(expected_metadata):
            raise RuntimeError(
                "acknowledged durable inventory missing or changed after restart"
            )
        recovered_health = byte_spool.health()
        if any(
            recovered_health.get(name, 0)
            for name in (
                "lost",
                "corrupt_entries",
                "admission_rejections",
                "orphaned_temporary_files",
                "unpersisted_fault",
                "persistence_faults",
                "missing_durable_entries",
                "recovery_inventory_unverified",
            )
        ):
            raise RuntimeError("byte spool recovery contains loss or uncertainty")
        expected = expected_metadata + expected_content
        inventory = _wait_inventory(destination_client, expected)
        recovery_ms = (time.monotonic() - recovery_started) * 1000
        after_ids = [row["batch_id"] for row in sender.manifest()["batches"]]
        challenge = "readback-" + secrets.token_hex(12)
        proof = destination_client.receipt(
            stage="destination_durable", set_id=challenge
        )
        expected_receipt = ReceiptSetExpectation(
            "destination_durable",
            TENANT,
            RUN,
            SCOPE,
            challenge,
            "destination-issuer",
            expected,
        )
        now = int(time.time())
        trusted = EvidenceTrustKey(
            "destination-issuer",
            TENANT,
            destination_key.public_key().public_bytes_raw(),
            frozenset({"destination_accepted", "destination_durable"}),
            now - 60,
            now + 3600,
        )
        verification = verify_receipt_set(
            proof.manifest,
            proof.attestation,
            expectation=expected_receipt,
            trusted_keys={"destination-key": trusted},
            verification_time=now,
        )
        revoked = verify_receipt_set(
            proof.manifest,
            proof.attestation,
            expectation=expected_receipt,
            trusted_keys={"destination-key": replace(trusted, revoked=True)},
            verification_time=now,
        )
        substituted = verify_receipt_set(
            proof.manifest,
            proof.attestation,
            expectation=replace(expected_receipt, stage="node_accepted"),
            trusted_keys={"destination-key": trusted},
            verification_time=now,
        )
        for row in expected_content:
            content = destination_client.read_object(row.identifier)
            if content != b"[REDACTED]" or CANARY in content:
                raise RuntimeError("reference permitted-byte readback mismatch")
        destination.restart()
        inventory_after_restart = _wait_inventory(destination_client, expected)
        canary_absent = not any(
            CANARY in path.read_bytes() for path in output.rglob("*") if path.is_file()
        )
        checks = {
            "passive_return_values": measurement["application_results_equal"],
            "declared_final_http_boundary": boundary_clean["status"] == "complete",
            "direct_bypass_detected": boundary_bypass["status"] == "unverified",
            "outage_durable_retention": outage_health["durable"] == 2 * iterations,
            "metadata_identity_after_restart": before_ids == after_ids,
            "destination_exact_set": _same_entries(inventory["entries"], expected),
            "destination_restart_readback": _same_entries(
                inventory_after_restart["entries"], expected
            ),
            "fresh_destination_receipt": verification.status == "verified",
            "revoked_key_refused": revoked.status != "verified",
            "stage_substitution_refused": substituted.status != "verified",
            "privacy_canary_absent_on_disk": canary_absent,
            "recovered_epoch_explicit": journal.epoch == 1,
        }
        if not all(checks.values()):
            raise RuntimeError("reference qualification check failed")
        report = {
            "schema_version": "fabric.enterprise-reference-report/v1",
            "verdict": "LOCAL_REFERENCE_CHECKS_PASS",
            "production_verdict": "NO_GO",
            "checks": checks,
            "expected_metadata_records": len(expected_metadata),
            "expected_content_objects": len(expected_content),
            "process_topology": "application plus separate ingress and destination processes",
            "faults_exercised": [
                "destination_outage",
                "node_sigkill_restart",
                "destination_sigkill_restart",
                "source_journal_reopen",
                "byte_spool_reopen",
                "metadata_sender_reopen",
            ],
            "outage_health": outage_health,
            "byte_delivery": byte_spool.health(),
            "metadata_before_restart": accepted_before_restart,
            "metadata_after_restart": sender.health(),
            "final_boundary": {
                "clean": boundary_clean,
                "after_deliberate_bypass": boundary_bypass,
            },
            "node": node_ready["facts"],
            "destination": inventory["facts"],
            "measurements": {
                "admission": measurement,
                "recovery_ms": recovery_ms,
                "destination_outage_ms": outage_ms,
                "application_peak_rss_kib": resource.getrusage(
                    resource.RUSAGE_SELF
                ).ru_maxrss,
                "peak_rss_scope": "Linux process high-water including prior imports; not isolated allocation delta",
                "protected_backlog_objects": outage_health["durable"],
                "protected_backlog_committed_bytes": outage_health["bytes"],
                "capacity_qualification": "configured finite bounds and fault tests; no production workload budget",
            },
            "privacy": "derivative_only; original canary not permitted on disk",
            "trace_sampling": "explicit_always_on_for_reproducible_reference",
            "source_completeness": "pre_admission_unknown_without_independent_source_truth",
            "excluded_target_gates": [
                "real_otel_node",
                "cloud_iam_kms_tls",
                "native_bpf",
                "production_slo",
                "unbounded_sdk_route_coverage",
                "typescript_durable_parity",
            ],
        }
        closure_path = HERE / "closure_campaign.py"
        if not closure_path.is_file():
            raise RuntimeError("required distributed closure campaign unavailable")
        closure = _module("reference_closure_campaign", closure_path)
        closure_report = closure.run_closure_campaign(output / "closure")
        if (
            closure_report.get("status") != "passed"
            or closure_report.get("clean", {}).get("complete") is not True
            or any(
                value.get("complete") is not False
                for value in closure_report.get("negative_cases", {}).values()
            )
            or set(closure_report.get("negative_cases", {}))
            != {"late_child", "unjoined_child", "dead_child"}
        ):
            raise RuntimeError("required distributed closure campaign failed")
        report["distributed_closure"] = closure_report
        report = json.loads(json.dumps(report))
        (output / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n"
        )
        return report
    finally:
        if sender is not None:
            sender.close(2)
        if writer is not None:
            writer.close(2)
        if byte_spool is not None:
            byte_spool.close(2)
        if journal is not None:
            journal.close(2)
        if node is not None:
            node.stop()
        destination.stop()
        baseline_witness.close()
        capture_witness.close()
        provider.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=20)
    args = parser.parse_args()
    report = run(args.output, iterations=args.iterations)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
