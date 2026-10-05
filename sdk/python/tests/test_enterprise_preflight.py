# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Entry-point and actual loopback checks; no simulated production receipts."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentelemetry import trace

from fabric.byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder
from fabric.call_recorder import CallRecorder
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.coverage_manifest import run_fixture_canary
from fabric.deployment_policy import DeploymentPolicy
from fabric.enterprise_preflight import (
    PreflightAttestation,
    main,
    preflight_subject_bytes,
    run_preflight,
    validate_external_attestations,
)
from fabric.evidence_attestation import EvidenceTrustKey, attestation_signing_bytes
from fabric.source_spool import SyntheticSourceSpool


def _policy(*, production: bool = False) -> DeploymentPolicy:
    return DeploymentPolicy.from_dict(
        {
            "schema_version": "fabric.deployment-policy/v1",
            "policy_id": "fixture-policy",
            "policy_version": 1,
            "tenant_id": "fixture",
            "workload_id": "fixture-workload",
            "privacy": {"tool.call.arguments": "retain_original", "tool.call.result": "omit"},
            "storage": {"backend": "local", "region": "fixture", "key_id": "fixture-key"},
            "retention": {"days": 1},
            "required_integrations": ["fabric.call_recorder"],
            "deployment": {
                "profile": "production" if production else "local",
                "image_digest": "sha256:" + "1" * 64 if production else "local",
                "tls_required": production,
                "encrypted_store_required": production,
            },
        }
    )


def _scope() -> dict[str, Any]:
    return {
        "source_ids": ["fixture-source"],
        "source_epochs": [0],
        "expected_max_records": 4096,
        "expected_max_object_bytes": 16 * 1024 * 1024,
    }


def _check(report: dict[str, Any], name: str) -> dict[str, Any]:
    return next(item for item in report["checks"] if item["name"] == name)


def test_actual_routed_fixture_detects_bypass_and_hidden_retry(tmp_path: Path) -> None:
    result = run_fixture_canary(root=str(tmp_path))
    assert result["status"] == "PASS"
    assert result["native_physical_attempts"] == 7
    assert result["recorded_logical_attempts"] == 5
    assert result["missing_physical_attempts"] == ["bypass-1", "hidden-1", "hidden-2"]
    assert result["unmatched_wrapper_attempts"] == ["hidden-wrapper"]
    assert result["full_route_coverage_complete"] is False
    assert result["production_qualified"] is False
    assert result["deployment_privacy_policy_exercised"] is False
    assert all(result["checks"].values())
    assert not list(tmp_path.iterdir())


def test_module_entrypoint_runs_actual_canary_and_writes_local_report(tmp_path: Path) -> None:
    policy, scope, output = (
        tmp_path / name for name in ("policy.json", "scope.json", "report.json")
    )
    policy.write_text(json.dumps(_policy().to_dict()))
    scope.write_text(json.dumps(_scope()))
    result = subprocess.run(  # noqa: S603 - fixed installed module and test-owned paths
        [
            sys.executable,
            "-m",
            "fabric.enterprise_preflight",
            "--policy",
            str(policy),
            "--scope",
            str(scope),
            "--filesystem-root",
            str(tmp_path),
            "--run-canary",
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text())
    assert report["verdict"] == "LOCAL_READY"
    assert report["production_verdict"] == "NO_GO"
    assert all(gate["status"] == "UNKNOWN" for gate in report["live_gates"])
    assert _check(report, "observed_recording")["status"] == "UNKNOWN"
    assert _check(report, "local_fsync_readback")["encryption_verified"] is False


def test_production_config_and_local_canary_cannot_qualify_live_environment(tmp_path: Path) -> None:
    report = run_preflight(
        _policy(production=True),
        scope=_scope(),
        filesystem_root=str(tmp_path),
        canary=True,
    )
    assert report["verdict"] == "NO_GO"
    assert report["canary"]["status"] == "PASS"
    assert all(gate["status"] == "UNKNOWN" for gate in report["live_gates"])


@pytest.mark.parametrize(
    "changed",
    [
        {"source_ids": ["one", "two"]},
        {"source_epochs": [1]},
        {"source_epochs": [False]},
        {"expected_max_records": 4097},
        {"expected_max_records": True},
        {"expected_max_object_bytes": 16 * 1024 * 1024 + 1},
        {"extra": "unsupported"},
    ],
)
def test_unsupported_scope_or_capacity_fails_closed(changed: dict[str, Any]) -> None:
    report = run_preflight(_policy(), scope={**_scope(), **changed})
    assert report["verdict"] == "NO_GO"
    assert any(item["status"] == "FAIL" for item in report["checks"])


def test_missing_proofs_remain_unknown() -> None:
    report = run_preflight(_policy())
    assert report["verdict"] == "NO_GO"
    for name in ("scope_support", "capacity", "local_fsync_readback", "routed_fixture_canary"):
        assert _check(report, name)["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    "field,value",
    [
        ("image_digest", "latest"),
        ("image_digest", "sha256:" + "A" * 64),
        ("tls_required", False),
        ("encrypted_store_required", False),
    ],
)
def test_production_configuration_rejected_at_entrypoint(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    field: str,
    value: Any,
) -> None:
    policy = _policy(production=True).to_dict()
    policy["deployment"][field] = value
    target = tmp_path / "policy.json"
    target.write_text(json.dumps(policy))
    assert main(["--policy", str(target)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["reason"] == "invalid_or_unreadable_input"


def test_duplicate_json_input_rejected_without_echo(tmp_path: Path, capsys: Any) -> None:
    target = tmp_path / "policy.json"
    target.write_text('{"schema_version":"secret","schema_version":"duplicate"}')
    assert main(["--policy", str(target)]) == 1
    assert "secret" not in capsys.readouterr().out


def test_symlink_filesystem_root_fails_without_writing(tmp_path: Path) -> None:
    root = tmp_path / "alias"
    root.symlink_to(tmp_path, target_is_directory=True)
    report = run_preflight(_policy(), filesystem_root=str(root))
    assert _check(report, "local_fsync_readback")["status"] == "FAIL"
    assert set(tmp_path.iterdir()) == {root}


def test_fsync_error_is_failed_not_encrypted(tmp_path: Path, monkeypatch: Any) -> None:
    def fail(_fd: int) -> None:
        raise OSError("secret filesystem error")

    monkeypatch.setattr("fabric.enterprise_preflight.os.fsync", fail)
    report = run_preflight(_policy(), filesystem_root=str(tmp_path))
    assert _check(report, "local_fsync_readback")["status"] == "FAIL"
    assert "secret" not in json.dumps(report)


def _signed_fixture(
    policy: DeploymentPolicy,
    *,
    gate: str = "encrypted_store",
    issued_at: int = 100,
) -> tuple[PreflightAttestation, dict[str, EvidenceTrustKey]]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    # This explicitly says fixture: authenticating it must not pass live gates.
    evidence = b'{"actual_environment_verified":false,"fixture":true}'
    subject = preflight_subject_bytes(policy, gate, evidence)
    payload = {
        "statement_type": "independent_witness",
        "issuer_id": "fixture-issuer",
        "tenant_id": policy.tenant_id,
        "run_id": policy.workload_id,
        "scope_sha256": policy.digest,
        "subject_kind": "evidence_set",
        "subject_id": "preflight." + gate,
        "subject_sha256": "sha256:" + hashlib.sha256(subject).hexdigest(),
        "issued_at": issued_at,
        "expires_at": issued_at + 100,
    }
    signature = private.sign(attestation_signing_bytes(payload, key_id="fixture-key"))
    envelope = {
        "schema_version": "fabric.evidence-attestation/v1",
        "algorithm": "Ed25519",
        "key_id": "fixture-key",
        "payload": payload,
        "signature": base64.b64encode(signature).decode(),
    }
    key = EvidenceTrustKey(
        issuer_id="fixture-issuer",
        tenant_id=policy.tenant_id,
        public_key=public,
        statement_types=frozenset({"independent_witness"}),
        valid_from=0,
        valid_until=issued_at + 1000,
    )
    return PreflightAttestation(json.dumps(envelope).encode(), evidence, "fixture-issuer"), {
        "fixture-key": key,
    }


def test_valid_fixture_signature_never_becomes_live_production_evidence() -> None:
    policy = _policy(production=True)
    supplied, keys = _signed_fixture(policy)
    report = run_preflight(
        policy,
        attestations={"encrypted_store": supplied},
        trusted_keys=keys,
        verification_time=150,
    )
    checked = next(
        item for item in report["external_attestations"] if item["name"] == "encrypted_store"
    )
    assert checked["status"] == "PASS"
    assert checked["authentic_statement_only"] is True
    assert checked["actual_environment_verified"] is False
    assert report["production_verdict"] == "NO_GO"
    assert all(item["status"] == "UNKNOWN" for item in report["live_gates"])


@pytest.mark.parametrize(
    "tampering", ["evidence", "policy", "issuer", "expiry", "key", "signature"]
)
def test_external_attestation_binding_and_authority_fail_closed(tampering: str) -> None:
    policy = _policy()
    supplied, keys = _signed_fixture(policy)
    when = 150
    if tampering == "evidence":
        supplied = PreflightAttestation(supplied.statement, b"different", supplied.issuer_id)
    elif tampering == "policy":
        value = policy.to_dict()
        value["policy_version"] = 2
        policy = DeploymentPolicy.from_dict(value)
    elif tampering == "issuer":
        supplied = PreflightAttestation(supplied.statement, supplied.evidence, "another-issuer")
    elif tampering == "expiry":
        when = 200
    elif tampering == "key":
        keys = {}
    else:
        envelope = json.loads(supplied.statement)
        envelope["signature"] = base64.b64encode(b"0" * 64).decode()
        supplied = PreflightAttestation(
            json.dumps(envelope).encode(), supplied.evidence, supplied.issuer_id
        )
    checked = validate_external_attestations(
        policy,
        attestations={"encrypted_store": supplied},
        trusted_keys=keys,
        verification_time=when,
    )
    assert next(item for item in checked if item["name"] == "encrypted_store")["status"] == "FAIL"


def test_snapshot_loss_and_projection_limit_prevent_ready() -> None:
    malformed = {"schema_version": "fabric.call-recording/v1", "starts": [{}] * 4097}
    report = run_preflight(_policy(), scope=_scope(), snapshot=malformed)
    assert _check(report, "observed_recording")["status"] == "FAIL"


def test_required_unsupported_integration_not_silently_dropped() -> None:
    value = _policy().to_dict()
    value["required_integrations"] = ["custom-missing"]
    report = run_preflight(DeploymentPolicy.from_dict(value), scope=_scope())
    assert _check(report, "required_integrations")["status"] == "FAIL"
    row = next(
        item for item in report["coverage"]["integrations"] if item["name"] == "custom-missing"
    )
    assert row["required"] is True and row["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    "health,status",
    [
        (
            {
                "status": "disabled",
                "recording_at_start": False,
                "dropped_events": 0,
                "dropped_attributes": 0,
            },
            "FAIL",
        ),
        (
            {
                "status": "partial",
                "recording_at_start": True,
                "dropped_events": 22,
                "dropped_attributes": 0,
            },
            "FAIL",
        ),
        (
            {
                "status": "unverified",
                "recording_at_start": True,
                "dropped_events": None,
                "dropped_attributes": 0,
            },
            "UNKNOWN",
        ),
        (
            {
                "status": "unverified",
                "recording_at_start": True,
                "dropped_events": 0,
                "dropped_attributes": 0,
            },
            "PASS",
        ),
    ],
)
def test_local_span_loss_sampling_and_unknown_counters(health: Any, status: str) -> None:
    report = run_preflight(_policy(), trace_health=[health])
    assert _check(report, "upstream_otel_loss")["status"] == status
    assert _check(report, "upstream_otel_loss")["exporter_delivery_verified"] is False


def test_active_provider_with_no_routed_provider_canary_cannot_be_ready(tmp_path: Path) -> None:
    from fabric.coverage_manifest import CoverageManifest, IntegrationRegistration  # noqa: PLC0415

    value = _policy().to_dict()
    value["required_integrations"] = ["openai"]
    coverage = CoverageManifest(
        (
            IntegrationRegistration(
                name="openai",
                required=True,
                installed=True,
                active=True,
                status="ACTIVE",
                reason="upstream_activation_reported",
                instrumentor_version="fixture",
                target_version="fixture",
            ),
        )
    )
    report = run_preflight(
        DeploymentPolicy.from_dict(value),
        coverage=coverage,
        filesystem_root=str(tmp_path),
        canary=True,
        scope=_scope(),
    )
    assert report["verdict"] == "NO_GO"
    assert _check(report, "required_integrations")["status"] == "PASS"
    assert _check(report, "required_canary_qualification")["status"] == "UNKNOWN"


def test_external_attestation_cli_uses_separate_trust_file(tmp_path: Path) -> None:
    policy = _policy(production=True)
    supplied, keys = _signed_fixture(policy, issued_at=int(time.time()) - 10)
    key = keys["fixture-key"]
    trust = {
        "keys": {
            "fixture-key": {
                "issuer_id": key.issuer_id,
                "tenant_id": key.tenant_id,
                "public_key": base64.b64encode(key.public_key).decode(),
                "statement_types": sorted(key.statement_types),
                "valid_from": key.valid_from,
                "valid_until": key.valid_until,
                "revoked": False,
            }
        },
        "gate_issuers": {"encrypted_store": "fixture-issuer"},
    }
    documents = {
        "encrypted_store": {
            "statement": json.loads(supplied.statement),
            "evidence": json.loads(supplied.evidence),
        }
    }
    paths = {
        name: tmp_path / (name + ".json") for name in ("policy", "trust", "attestations", "report")
    }
    for name, value in (
        ("policy", policy.to_dict()),
        ("trust", trust),
        ("attestations", documents),
    ):
        paths[name].write_text(json.dumps(value))
    assert (
        main(
            [
                "--policy",
                str(paths["policy"]),
                "--trust",
                str(paths["trust"]),
                "--attestations",
                str(paths["attestations"]),
                "--output",
                str(paths["report"]),
            ]
        )
        == 2
    )
    report = json.loads(paths["report"].read_text())
    checked = next(
        item for item in report["external_attestations"] if item["name"] == "encrypted_store"
    )
    assert checked["status"] == "PASS" and checked["actual_environment_verified"] is False
    assert report["production_verdict"] == "NO_GO"


@pytest.fixture
def real_snapshot(tmp_path: Path) -> dict[str, Any]:
    store = LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="fixture")
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store,
            roles=frozenset({"tool.call.arguments", "tool.call.result"}),
        )
    )
    root = tmp_path / "spool"
    root.mkdir(mode=0o700)
    spool = SyntheticSourceSpool(str(root), tenant_id="fixture", run_id="fixture")
    recorder = CallRecorder(
        writer,
        run_id="fixture",
        agent_id="fixture",
        source_id="fixture-source",
        source_spool=spool,
        tracer=trace.NoOpTracerProvider().get_tracer("fixture"),
    )
    try:
        assert recorder.call(b"input", lambda _: b"output") == b"output"
        assert recorder.seal_source()["status"] == "sealed"
        return recorder.snapshot()
    finally:
        writer.close()
        spool.close()


def test_real_sealed_snapshot_checks_local_loss_without_complete_claim(real_snapshot: Any) -> None:
    report = run_preflight(_policy(), snapshot=real_snapshot)
    checked = _check(report, "observed_recording")
    assert checked["status"] == "PASS"
    assert checked["independent_completeness_verified"] is False
    assert checked["original_reconstruction_verified"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("recording_gaps", 1),
        ("recording_gaps", False),
        ("unretained_drops", 1),
        ("source_epoch", 1),
        ("source_epoch", False),
        ("source_metadata_seal", None),
        ("writer_settled", False),
        ("source_spool_settled", False),
    ],
)
def test_snapshot_known_loss_or_unclosed_source_cannot_pass(
    real_snapshot: Any, field: str, value: Any
) -> None:
    real_snapshot[field] = value
    report = run_preflight(_policy(), snapshot=real_snapshot)
    assert _check(report, "observed_recording")["status"] == "FAIL"
