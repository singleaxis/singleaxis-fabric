#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Actual configured local SDK/storage exercise using only synthetic content.

Uses ephemeral in-memory local authority/encryption keys, never cloud credentials.
Produced metadata is reviewable; encrypted fixture objects cannot be reopened
once this process exits because fixture keys are deliberately not saved.
"""

from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path
from typing import Any

from opentelemetry.sdk.trace import TracerProvider

from fabric.control_evidence import ControlObservation
from fabric.deployment_policy import DeploymentPolicy
from fabric.deployment_state import CapturePolicyRegistry, RevisionConflictError
from fabric.enterprise import PolicyCaptureSession
from fabric.governed_store import GovernedLocalContentStore, LocalCapabilityAuthority
from fabric.source_spool import SyntheticSourceSpool

SECRET = b"SYNTHETIC_PRIVATE_CANARY"


def run(output: Path) -> dict[str, Any]:
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = output / "content"
    policy = DeploymentPolicy.from_dict(
        {
            "schema_version": "fabric.deployment-policy/v1",
            "policy_id": "local-exercise",
            "policy_version": 1,
            "tenant_id": "fixture-tenant",
            "workload_id": "fixture-agent",
            "privacy": {
                "tool.call.arguments": "redact",
                "tool.call.result": "retain_original",
                "artifact.after": "tokenize",
                "terminal.stderr": "omit",
                "model.request.messages": "metadata_only",
                "model.output.messages": "metadata_only",
            },
            "storage": {
                "backend": "local",
                "region": "local",
                "key_id": "ephemeral-fixture-key",
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
    authority = LocalCapabilityAuthority(secrets.token_bytes(32))
    encryption_key = secrets.token_bytes(32)
    permissions = {
        "write_original",
        "write_derivative",
        "read_original",
        "read_derivative",
        "audit",
        "lifecycle",
        "policy_admin",
        "policy_read",
    }
    token = authority.issue(
        policy=policy, subject_id="local-fixture-admin", permissions=permissions
    )
    common = {
        "policy": policy,
        "authority": authority,
        "capability": token,
        "encryption_key": encryption_key,
    }
    original = GovernedLocalContentStore(root, plane="original", **common)
    derivative = GovernedLocalContentStore(root, plane="derivative", **common)
    registry = CapturePolicyRegistry(
        output / "configuration",
        authority=authority,
        initial_policy=policy,
        capability=token,
    )
    revision = registry.approve(expected_revision=0, capability=token)
    registry.observe_applied(
        policy_digest=policy.digest,
        capabilities=["python-dispatch", "local-aes-gcm"],
        expected_revision=revision,
        capability=token,
    )
    journal = output / "journal"
    journal.mkdir(mode=0o700)
    spool = SyntheticSourceSpool(
        str(journal.absolute()), tenant_id=policy.tenant_id, run_id="local-run"
    )
    provider = TracerProvider()
    session = PolicyCaptureSession(
        policy=policy,
        store=original,
        derivative_store=derivative,
        run_id="local-run",
        source_id="python-dispatch",
        agent_id="fixture-agent",
        source_spool=spool,
        redactors={
            "tool.call.arguments": lambda data: data.replace(SECRET, b"[REDACTED]")
        },
        tokenization_key=secrets.token_bytes(32),
        tracer=provider.get_tracer("enterprise-local-fixture"),
    )
    witnesses: list[str] = []

    def tool(data: bytes) -> bytes:
        witnesses.append("tool-called")
        session.calls.record_data(SECRET, role="artifact.after")
        session.calls.record_data(SECRET, role="terminal.stderr")
        return b"result:" + data

    try:
        assert (
            session.calls.call(SECRET, tool, operation_id="op-1", attempt_id="try-1")
            == b"result:" + SECRET
        )
        assert list(
            session.calls.stream(
                b"model",
                lambda _: iter((b"one", b"two")),
                kind="model",
                operation_id="model-1",
                attempt_id="try-1",
            )
        ) == [b"one", b"two"]
        session.observe_external_control(
            ControlObservation(
                control_id="fixture-sandbox",
                action_id="op-1",
                external_policy_id="external-sandbox",
                external_policy_version=1,
                external_policy_digest="sha256:" + "a" * 64,
                reviewed_artifact_digest="sha256:" + "b" * 64,
                decision="unknown",
                issuer_id="fixture",
            )
        )
        report = session.report()
        payloads = session.metadata_batches(batch_size=3)
        assert all(SECRET not in payload for payload, _ in payloads)
        original_uris = original.list_object_uris()
        derivative_uris = derivative.list_object_uris()
        assert len(original_uris) == 1 and len(derivative_uris) == 2
        assert original.read(original_uris[0]) == b"result:" + SECRET
        assert all(SECRET not in derivative.read(uri) for uri in derivative_uris)
        assert all(SECRET not in path.read_bytes() for path in root.rglob("*.json"))
        readonly = authority.issue(
            policy=policy, subject_id="reader", permissions={"read_original"}
        )
        denied = GovernedLocalContentStore(
            root,
            policy=policy,
            authority=authority,
            capability=readonly,
            encryption_key=encryption_key,
        )
        try:
            denied.delete(original_uris[0])
            raise AssertionError("unauthorized deletion succeeded")
        except PermissionError:
            pass
        original.set_hold(
            original_uris[0], hold_id="hold-1", reason_code="fixture-test"
        )
        try:
            original.delete(original_uris[0])
            raise AssertionError("held object deletion succeeded")
        except PermissionError:
            pass
        original.release_hold(
            original_uris[0], hold_id="hold-1", reason_code="fixture-release"
        )
        deletion = original.delete(original_uris[0])
        assert not original.exists(original_uris[0])
        try:
            registry.approve(expected_revision=0, capability=token)
            raise AssertionError("stale revision succeeded")
        except RevisionConflictError:
            pass
        assert len(witnesses) == 1
        # Readable report contains only closed metadata, no payloads, keys or capabilities.
        report.update(
            local_checks={
                "capture_path": "PASS",
                "privacy_before_queue": "PASS",
                "encrypted_readback": "PASS",
                "separate_derivatives": "PASS",
                "least_privilege": "PASS",
                "hold_delete": "PASS",
                "optimistic_revision": "PASS",
                "metadata_projection": "PASS",
            },
            storage=original.attestation(),
            deletion=deletion,
            deployment=registry.read(token),
            witness_basis="local_fixture_delegate",
            production_verdict="NO_GO",
            not_run=[
                "live_node_tls_auth",
                "cloud_kms_iam_region",
                "real_provider_adapter",
                "independent_destination_receipts",
                "distributed_source_closure",
            ],
            fixture_keys="ephemeral_not_saved",
        )
        encoded = json.dumps(report, indent=2).encode()
        assert SECRET not in encoded
        (output / "report.json").write_bytes(encoded)
        (output / "policy.json").write_text(json.dumps(policy.to_dict(), indent=2))
        return report
    finally:
        session.close()
        spool.close()
        original.close()
        derivative.close()
        provider.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="new private evidence directory"
    )
    arguments = parser.parse_args()
    report = run(arguments.output)
    print(
        json.dumps(
            {
                "local_checks": report["local_checks"],
                "production_verdict": "NO_GO",
                "report": str(arguments.output / "report.json"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
