# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline deployment checks and a bounded local canary, never a runtime gate.

Configuration and signed statements do not establish actual TLS, cloud KMS,
IAM, retention, independent route closure or destination durability. This
version has no live adapters for those checks, so production remains NO_GO.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .call_otlp import project_call_snapshot
from .coverage_manifest import CoverageManifest, inspect_integrations, run_fixture_canary
from .deployment_policy import DeploymentPolicy
from .evidence_attestation import (
    EvidenceExpectation,
    EvidenceTrustKey,
    verify_evidence_attestation,
)

LIVE_GATES = (
    "image_identity",
    "tls",
    "encrypted_store",
    "storage_region",
    "retention",
    "tenant_iam",
    "source_identity",
    "independent_route_closure",
    "independent_outcomes",
    "four_stage_delivery",
    "issuer_qualification",
)
_MAX_INPUT_BYTES = 1024 * 1024
_MAX_PROJECTION = 4096
_MAX_OBJECT = 16 * 1024 * 1024
_SCOPE_FIELDS = {
    "source_ids",
    "source_epochs",
    "expected_max_records",
    "expected_max_object_bytes",
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _check(name: str, status: str, reason: str, **details: Any) -> dict[str, Any]:
    return {"name": name, "status": status, "reason": reason, **details}


@dataclass(frozen=True, slots=True)
class PreflightAttestation:
    """External signed statement plus its evidence, with owner-selected issuer.

    Issuer identity is an expectation configured separately from the signed
    envelope. The evidence is bound by digest, not treated as live truth.
    """

    statement: bytes
    evidence: bytes
    issuer_id: str


def preflight_subject_bytes(policy: DeploymentPolicy, gate: str, evidence: bytes) -> bytes:
    """Exact policy-bound subject to be signed by an external issuer."""
    if (
        gate not in LIVE_GATES
        or not isinstance(evidence, bytes)
        or len(evidence) > _MAX_INPUT_BYTES
    ):
        raise ValueError("unsupported gate or oversized evidence")
    return _canonical(
        {
            "schema_version": "fabric.preflight-gate-subject/v1",
            "gate": gate,
            "tenant_id": policy.tenant_id,
            "workload_id": policy.workload_id,
            "policy_sha256": policy.digest,
            "evidence_sha256": _sha(evidence),
        }
    )


def validate_external_attestations(
    policy: DeploymentPolicy,
    *,
    attestations: Mapping[str, PreflightAttestation],
    trusted_keys: Mapping[str, EvidenceTrustKey],
    verification_time: int,
) -> list[dict[str, Any]]:
    """Authenticate exact external statements; do not grant production qualification."""
    if type(verification_time) is not int or verification_time < 0:
        raise ValueError("verification_time must be a UTC Unix second")
    if set(attestations) - set(LIVE_GATES):
        raise ValueError("unknown preflight attestation gate")
    checks = []
    for gate in LIVE_GATES:
        supplied = attestations.get(gate)
        if supplied is None:
            checks.append(_check(gate, "UNKNOWN", "external_attestation_absent"))
            continue
        subject = preflight_subject_bytes(policy, gate, supplied.evidence)
        expected = EvidenceExpectation(
            statement_type="independent_witness",
            tenant_id=policy.tenant_id,
            run_id=policy.workload_id,
            scope_sha256=policy.digest,
            subject_kind="evidence_set",
            subject_id="preflight." + gate,
            subject_sha256=_sha(subject),
            issuer_id=supplied.issuer_id,
        )
        verified = verify_evidence_attestation(
            supplied.statement,
            expected=expected,
            trusted_keys=trusted_keys,
            verification_time=verification_time,
        )
        checks.append(
            _check(
                gate,
                "PASS" if verified.status == "verified" else "FAIL",
                verified.reason,
                authentic_statement_only=True,
                actual_environment_verified=False,
            )
        )
    return checks


def _filesystem_probe(root: str | None) -> dict[str, Any]:
    if root is None:
        return _check("local_fsync_readback", "UNKNOWN", "filesystem_root_absent")
    try:
        path = Path(root)
        if not path.is_absolute() or path.is_symlink() or not path.is_dir():
            return _check("local_fsync_readback", "FAIL", "filesystem_root_invalid")
        # Only random synthetic bytes enter the test file. This is a real
        # fsync/readback at the selected root, not a storage encryption test.
        with tempfile.TemporaryDirectory(prefix="fabric-preflight-", dir=path) as temporary:
            work = Path(temporary)
            probe = work / "probe"
            payload = os.urandom(256)
            fd = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            directory_fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            if probe.read_bytes() != payload:
                return _check("local_fsync_readback", "FAIL", "filesystem_readback_mismatch")
    except (OSError, ValueError):
        return _check("local_fsync_readback", "FAIL", "filesystem_probe_failed")
    return _check(
        "local_fsync_readback",
        "PASS",
        "local_file_and_directory_fsync_readback_observed",
        encryption_verified=False,
        crash_tolerance_verified=False,
    )


def _scope_checks(scope: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if scope is None:
        return [
            _check("scope_support", "UNKNOWN", "source_epoch_inventory_absent"),
            _check("capacity", "UNKNOWN", "workload_capacity_absent"),
        ]
    if set(scope) != _SCOPE_FIELDS:
        return [
            _check("scope_support", "FAIL", "scope_fields_invalid"),
            _check("capacity", "FAIL", "scope_fields_invalid"),
        ]
    sources, epochs = scope["source_ids"], scope["source_epochs"]
    supported = (
        isinstance(sources, list)
        and len(sources) == 1
        and isinstance(sources[0], str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", sources[0]) is not None
        and isinstance(epochs, list)
        and len(epochs) == 1
        and type(epochs[0]) is int
        and epochs[0] == 0
    )
    records, byte_count = scope["expected_max_records"], scope["expected_max_object_bytes"]
    capacity = (
        type(records) is int
        and 0 < records <= _MAX_PROJECTION
        and type(byte_count) is int
        and 0 < byte_count <= _MAX_OBJECT
    )
    return [
        _check(
            "scope_support",
            "PASS" if supported else "FAIL",
            "single_source_epoch_zero_only" if supported else "source_epoch_scope_unsupported",
            source_count_max=1,
            source_epochs_supported=[0],
            distributed_closure_supported=False,
            actual_closure_verified=False,
        ),
        _check(
            "capacity",
            "PASS" if capacity else "FAIL",
            "declared_capacity_within_bounds" if capacity else "declared_capacity_unsupported",
            qualified_run_max_projected_records=_MAX_PROJECTION,
            max_object_bytes=_MAX_OBJECT,
            explicit_projection_batching_available=True,
            outage_capacity_verified=False,
        ),
    ]


def _snapshot_checks(snapshot: dict[str, Any] | None) -> list[dict[str, Any]]:
    if snapshot is None:
        return [_check("observed_recording", "UNKNOWN", "target_snapshot_absent")]
    try:
        _, ids = project_call_snapshot(snapshot)
        loss = (
            any(
                type(snapshot.get(key)) is not int or snapshot[key] != 0
                for key in ("recording_gaps", "unretained_drops", "source_epoch")
            )
            or snapshot.get("writer_settled") is not True
            or snapshot.get("source_spool_settled") is not True
            or snapshot.get("source_spool_recovered_gaps") != []
            or snapshot.get("source_unsealed_epoch_ranges") != []
            or snapshot.get("recovery_history_unverified") is not False
        )
        health = snapshot.get("source_spool_health")
        loss |= not isinstance(health, dict) or any(
            type(health.get(name)) is not int or health[name] != 0
            for name in ("pending", "failed", "dropped", "unretained_drops")
        )
        source_ids = {
            row["source_id"]
            for group in ("starts", "events", "operations")
            for row in snapshot.get(group, [])
        }
        loss |= len(source_ids) != 1 or not isinstance(snapshot.get("source_metadata_seal"), dict)
        incomplete = any(
            call.get("status") not in {"ok", "error", "cancelled"}
            for call in snapshot.get("calls", [])
        )
        bad_content = any(
            event.get("status") in {"pending", "truncated", "unsupported", "dropped", "failed"}
            for event in snapshot.get("events", [])
        )
        return [
            _check(
                "observed_recording",
                "FAIL" if loss or incomplete or bad_content else "PASS",
                "recording_loss_or_incomplete"
                if loss or incomplete or bad_content
                else "local_snapshot_no_known_loss",
                projected_records=len(ids),
                independent_completeness_verified=False,
                original_reconstruction_verified=False,
            )
        ]
    except (KeyError, TypeError, ValueError, OverflowError):
        return [_check("observed_recording", "FAIL", "snapshot_invalid_or_capacity_exceeded")]


def _trace_health_check(health: Sequence[Mapping[str, Any]] | None) -> dict[str, Any]:
    if not health:
        return _check("upstream_otel_loss", "UNKNOWN", "target_span_health_absent")
    known_loss = False
    unknown = False
    for item in health:
        if not isinstance(item, Mapping):
            return _check("upstream_otel_loss", "FAIL", "target_span_health_invalid")
        known_loss |= item.get("status") in {"disabled", "partial"}
        known_loss |= item.get("recording_at_start") is False
        unknown |= item.get("recording_at_start") is not True
        for name in ("dropped_events", "dropped_attributes"):
            value = item.get(name)
            if type(value) is not int or value < 0:
                unknown = True
            elif value > 0:
                known_loss = True
    status = "FAIL" if known_loss else "UNKNOWN" if unknown else "PASS"
    return _check(
        "upstream_otel_loss",
        status,
        "local_span_loss_or_sampling" if known_loss else "local_span_counters_only",
        exporter_delivery_verified=False,
    )


def run_preflight(
    policy: DeploymentPolicy,
    *,
    coverage: CoverageManifest | None = None,
    filesystem_root: str | None = None,
    canary: bool = False,
    scope: Mapping[str, Any] | None = None,
    snapshot: dict[str, Any] | None = None,
    trace_health: Sequence[Mapping[str, Any]] | None = None,
    attestations: Mapping[str, PreflightAttestation] | None = None,
    trusted_keys: Mapping[str, EvidenceTrustKey] | None = None,
    verification_time: int | None = None,
) -> dict[str, Any]:
    """Return bounded local readiness and explicit live UNKNOWN gates.

    ``LOCAL_READY`` concerns the tested fixture and declared supported scope,
    not deployment approval. Supplied target snapshots with any known loss
    prevent local readiness. Missing target evidence remains visibly unknown.
    """
    # Reparse canonical values rather than trusting a mutable/subclassed policy.
    policy = DeploymentPolicy.from_dict(policy.to_dict())
    coverage = coverage or inspect_integrations(required=policy.required_integrations)
    registrations = {item.name: item for item in coverage.integrations}
    required = [registrations.get(name) for name in policy.required_integrations]
    ready = all(
        item is not None and item.status == "ACTIVE" and item.active is True for item in required
    )
    checks = [
        _check("policy_configuration", "PASS", "strict_policy_validated"),
        _check(
            "required_integrations",
            "PASS" if ready else "FAIL",
            "required_activation_reported"
            if ready
            else "required_capability_missing_failed_or_unknown",
            qualification_verified=False,
        ),
        _filesystem_probe(filesystem_root),
        *_scope_checks(scope),
        *_snapshot_checks(snapshot),
        _trace_health_check(trace_health),
    ]
    canary_report = None
    if canary:
        try:
            canary_report = run_fixture_canary(root=filesystem_root)
            checks.append(
                _check(
                    "routed_fixture_canary",
                    canary_report["status"],
                    "local_routed_fixture_only",
                )
            )
        except Exception:
            # Fixed metadata only; no exception text or file paths in reports.
            checks.append(_check("routed_fixture_canary", "FAIL", "local_canary_failed"))
    else:
        checks.append(_check("routed_fixture_canary", "UNKNOWN", "canary_not_run"))
    qualified_required = (
        canary_report is not None
        and canary_report["status"] == "PASS"
        and all(name == "fabric.call_recorder" for name in policy.required_integrations)
    )
    checks.append(
        _check(
            "required_canary_qualification",
            "PASS" if qualified_required else "UNKNOWN",
            "local_fixture_boundary_only"
            if qualified_required
            else "required_routed_canary_unavailable",
            production_qualified=False,
        )
    )
    external = validate_external_attestations(
        policy,
        attestations=attestations or {},
        trusted_keys=trusted_keys or {},
        verification_time=int(time.time()) if verification_time is None else verification_time,
    )
    local_names = {
        "policy_configuration",
        "required_integrations",
        "local_fsync_readback",
        "scope_support",
        "capacity",
        "routed_fixture_canary",
        "required_canary_qualification",
    }
    local_ready = all(item["status"] == "PASS" for item in checks if item["name"] in local_names)
    local_ready &= not any(item["status"] == "FAIL" for item in [*checks, *external])
    production = policy.deployment["profile"] == "production"
    return {
        "schema_version": "fabric.enterprise-preflight/v1",
        "policy_sha256": policy.digest,
        "profile": policy.deployment["profile"],
        "verdict": "LOCAL_READY" if local_ready and not production else "NO_GO",
        "production_verdict": "NO_GO",
        "runtime_enforcement": False,
        "checks": checks,
        "coverage": coverage.to_dict(),
        "canary": canary_report,
        "external_attestations": external,
        "live_gates": [
            _check(gate, "UNKNOWN", "live_environment_adapter_and_issuer_qualification_required")
            for gate in LIVE_GATES
        ],
        "limits": [
            "Policy flags, key IDs and image digests do not establish actual controls",
            "Valid signatures do not qualify issuers or live controls",
            "Local readiness is fixture-scoped and does not establish target-run completeness",
            "QualifiedRun supports one source, epoch zero, and at most 4096 projected records",
            "No runtime enforcement, distributed closure or automatic universal capture",
        ],
    }


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _read_json(path: str) -> Any:
    with Path(path).open("rb") as handle:
        body = handle.read(_MAX_INPUT_BYTES + 1)
    if len(body) > _MAX_INPUT_BYTES:
        raise ValueError("preflight input exceeds size limit")
    return json.loads(body, object_pairs_hook=_unique_pairs)


def _external_inputs(
    attestations_path: str | None,
    trust_path: str | None,
) -> tuple[dict[str, PreflightAttestation], dict[str, EvidenceTrustKey]]:
    documents = _read_json(attestations_path) if attestations_path else {}
    trust = _read_json(trust_path) if trust_path else {"keys": {}, "gate_issuers": {}}
    if (
        not isinstance(documents, dict)
        or not isinstance(trust, dict)
        or set(trust) != {"keys", "gate_issuers"}
    ):
        raise ValueError("invalid external trust input")
    keys = {}
    for key_id, value in trust["keys"].items():
        if set(value) != {
            "issuer_id",
            "tenant_id",
            "public_key",
            "statement_types",
            "valid_from",
            "valid_until",
            "revoked",
        }:
            raise ValueError("invalid external key fields")
        keys[key_id] = EvidenceTrustKey(
            **{
                key: item
                for key, item in value.items()
                if key not in {"public_key", "statement_types"}
            },
            public_key=base64.b64decode(value["public_key"], validate=True),
            statement_types=frozenset(value["statement_types"]),
        )
    inputs = {}
    for gate, value in documents.items():
        if set(value) != {"statement", "evidence"} or gate not in trust["gate_issuers"]:
            raise ValueError("attestation requires a separately configured gate issuer")
        inputs[gate] = PreflightAttestation(
            statement=_canonical(value["statement"]),
            evidence=_canonical(value["evidence"]),
            issuer_id=trust["gate_issuers"][gate],
        )
    return inputs, keys


def main(argv: Sequence[str] | None = None) -> int:
    """Installed-module CLI; 0 local-ready, 2 no-go, 1 invalid input."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--filesystem-root")
    parser.add_argument("--run-canary", action="store_true")
    parser.add_argument("--scope")
    parser.add_argument("--snapshot")
    parser.add_argument("--trace-health")
    parser.add_argument("--attestations")
    parser.add_argument("--trust")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        policy = DeploymentPolicy.from_dict(_read_json(args.policy))
        attestations, keys = _external_inputs(args.attestations, args.trust)
        report = run_preflight(
            policy,
            filesystem_root=args.filesystem_root,
            canary=args.run_canary,
            scope=_read_json(args.scope) if args.scope else None,
            snapshot=_read_json(args.snapshot) if args.snapshot else None,
            trace_health=_read_json(args.trace_health) if args.trace_health else None,
            attestations=attestations,
            trusted_keys=keys,
        )
        code = 0 if report["verdict"] == "LOCAL_READY" else 2
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        report = {
            "schema_version": "fabric.enterprise-preflight/v1",
            "verdict": "NO_GO",
            "production_verdict": "NO_GO",
            "reason": "invalid_or_unreadable_input",
        }
        code = 1
    body = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")
    else:
        print(body, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
