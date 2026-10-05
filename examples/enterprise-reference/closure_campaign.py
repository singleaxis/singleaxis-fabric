#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Finite closure campaign with a separately persisted same-host coordinator plan.

This example provides explicit propagation and journal instrumentation only.
The coordinator plans source IDs/records BEFORE starting child processes, keeps
its own fsynced plan, and witnesses that finite script's lifecycle. It shares an
OS/trust administrator with the sources: it is a reference trust boundary, not
an independent production authority or automatic coverage of arbitrary workers.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fabric.distributed_closure import (
    ChildJoin,
    ClosureEvidenceStore,
    ClosureReference,
    ClosureScope,
    ClosureValue,
    ClosureWitness,
    PropagatedContext,
    SignedClosureDocument,
    SourceEpoch,
    SourceRegistration,
    WitnessRecord,
    authenticate_propagated_context,
    closure_document_bytes,
    closure_document_id,
    closure_expectation,
    closure_sha256,
    source_epoch_records,
    verify_distributed_closure,
)
from fabric.evidence_attestation import EvidenceTrustKey, attestation_signing_bytes
from fabric.source_spool import SyntheticSourceSpool, _write_atomic


def _event(source: str, epoch: int) -> dict[str, Any]:
    return {
        "record_id": f"{source}-{epoch}-record",
        "tenant_id": "closure-reference",
        "run_id": "finite-distributed-run",
        "source_id": source,
        "source_epoch": epoch,
        "source_sequence": 0,
        "operation_id": f"{source}-{epoch}-operation",
        "attempt_id": "attempt-1",
        "boundary": "caller",
        "role": "operation.start",
        "status": "recorded",
        "observed_at": "2026-10-02T00:00:00Z",
        "call_id": f"{source}-call",
        "agent_id": source,
        "kind": "agent",
        "streaming": False,
    }


def _values(scope: ClosureScope, records: list[dict[str, Any]]) -> list[ClosureValue]:
    by_epoch = {(row["source_id"], row["source_epoch"]): row for row in records}
    first = SourceEpoch(
        "worker", 0, source_epoch_records([by_epoch[("worker", 0)]]), state="recovered"
    )
    second = SourceEpoch(
        "worker",
        1,
        source_epoch_records([by_epoch[("worker", 1)]]),
        previous_epoch_sha256=closure_sha256(closure_document_bytes(scope, first)),
    )
    parent = SourceEpoch(
        "parent",
        0,
        source_epoch_records([by_epoch[("parent", 0)]]),
        expected_children=("child-1",),
        joined_children=(
            ChildJoin(
                "child-1",
                closure_sha256(closure_document_bytes(scope, second)),
            ),
        ),
    )
    return [
        SourceRegistration("parent", "parent-issuer"),
        SourceRegistration("worker", "worker-issuer", "child-1"),
        PropagatedContext("child-1", "parent", 0, 0, "worker", "parent-call"),
        first,
        second,
        parent,
    ]


class _ReferenceAuthority:
    def __init__(self, scope: ClosureScope, now: int) -> None:
        self.scope = scope
        self.now = now
        self.private = {
            issuer: Ed25519PrivateKey.generate()
            for issuer in (
                "registry-issuer",
                "witness-issuer",
                "parent-issuer",
                "worker-issuer",
            )
        }
        self.trusted = {
            issuer: EvidenceTrustKey(
                issuer,
                scope.tenant_id,
                key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                frozenset({"source_binding", "independent_witness"}),
                now - 1,
                now + 3600,
            )
            for issuer, key in self.private.items()
        }

    def sign(self, value: ClosureValue) -> SignedClosureDocument:
        document = closure_document_bytes(self.scope, value)
        kind = json.loads(document)["kind"]
        identity = closure_document_id(self.scope, value)
        if isinstance(value, ClosureWitness):
            issuer = "witness-issuer"
        elif isinstance(value, SourceRegistration):
            issuer = "registry-issuer"
        elif isinstance(value, PropagatedContext):
            issuer = "parent-issuer"
        else:
            issuer = value.source_id + "-issuer"
        expectation = closure_expectation(self.scope, kind, identity, document, issuer)
        payload = {
            **asdict(expectation),
            "issued_at": self.now,
            "expires_at": self.now + 3600,
        }
        signing = attestation_signing_bytes(payload, key_id=issuer)
        envelope = json.loads(signing.split(b"\0", 1)[1])
        envelope["signature"] = base64.b64encode(
            self.private[issuer].sign(signing)
        ).decode()
        return SignedClosureDocument(
            kind, identity, document, json.dumps(envelope).encode()
        )


def _journal_step(
    root: Path, event: dict[str, Any], *, crash: bool
) -> list[dict[str, Any]]:
    payload = {"root": str(root), "event": event, "crash": crash}
    result = subprocess.run(  # noqa: S603 - fixed local script, no shell or secrets
        [sys.executable, str(Path(__file__).resolve()), "--journal-stdin"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if result.returncode != (23 if crash else 0):
        raise RuntimeError("closure journal subprocess failed")
    return list(json.loads(result.stdout)["records"])


def _journal_worker() -> None:
    configuration = json.load(sys.stdin)
    event = configuration["event"]
    journal = SyntheticSourceSpool(
        configuration["root"],
        tenant_id=event["tenant_id"],
        run_id=event["run_id"],
    )
    if journal.epoch != event["source_epoch"] or journal.append(event) != "pending":
        raise RuntimeError("closure source admission failed")
    if not journal.flush() or journal.status(event["record_id"]) != "spooled":
        raise RuntimeError("closure source durable settlement failed")
    if not configuration["crash"]:
        seal = journal.seal_epoch({event["source_id"]: 0})
        if seal["status"] != "sealed":
            raise RuntimeError("closure source seal failed")
    # Fresh disk readback, including recovered epochs; this is source evidence,
    # never the independent coordinator inventory.
    print(json.dumps({"records": journal.durable_records()}), flush=True)
    if configuration["crash"]:
        os._exit(23)
    journal.close()


def run_closure_campaign(output: Path) -> dict[str, Any]:
    """Create a fresh finite plan, crash/recover a source, reconcile and test gaps."""
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    coordinator = output / "coordinator"
    evidence = output / "source-control"
    parent_root = output / "parent-journal"
    worker_root = output / "worker-journal"
    for root in (coordinator, evidence, parent_root, worker_root):
        root.mkdir(mode=0o700)
    scope = ClosureScope(
        "closure-reference",
        "finite-distributed-run",
        closure_sha256(b"closure-reference-v1"),
        "parent",
        "registry-issuer",
        "witness-issuer",
        secrets.token_hex(16),
    )
    authority = _ReferenceAuthority(scope, int(time.time()))
    planned = [_event("parent", 0), _event("worker", 0), _event("worker", 1)]
    expected_values = _values(scope, planned)
    expected_documents = [
        closure_document_bytes(scope, value) for value in expected_values
    ]
    references = [
        asdict(
            ClosureReference(
                json.loads(document)["kind"],
                closure_document_id(scope, value),
                closure_sha256(document),
            )
        )
        for value, document in zip(expected_values, expected_documents, strict=True)
    ]
    # Independent finite source/lifecycle plan is fsynced before any source runs.
    plan = {"scope": asdict(scope), "records": planned, "references": references}
    _write_atomic(
        coordinator / "precommitted-plan.json",
        json.dumps(plan, sort_keys=True).encode(),
    )
    public = {
        name: {
            **asdict(key),
            "public_key": base64.b64encode(key.public_key).decode(),
            "statement_types": sorted(key.statement_types),
        }
        for name, key in authority.trusted.items()
    }
    _write_atomic(coordinator / "public-trust.json", json.dumps(public).encode())
    parent_records = _journal_step(parent_root, planned[0], crash=False)
    registration = authority.sign(expected_values[0])
    context = authority.sign(expected_values[2])
    authenticate_propagated_context(
        scope=scope,
        parent_registration=registration,
        context=context,
        expected_child_source_id="worker",
        trusted_keys=authority.trusted,
        verification_time=authority.now,
    )
    before_restart = _journal_step(worker_root, planned[1], crash=True)
    recovered = _journal_step(worker_root, planned[2], crash=False)
    if recovered[0] != before_restart[0]:
        raise RuntimeError("source restart changed record identity")
    observed_values = _values(scope, [*parent_records, *recovered])
    documents = [authority.sign(value) for value in observed_values]
    with ClosureEvidenceStore(str(evidence), scope=scope) as store:
        for proof in documents:
            store.append(proof)
    # Coordinator witnesses this script's expected child terminal and join after
    # waiting for both worker processes. It freshly reads its PRE-source plan.
    independent = json.loads((coordinator / "precommitted-plan.json").read_bytes())
    independent_records = tuple(
        WitnessRecord(
            row["source_id"],
            row["source_epoch"],
            row["record_id"],
            row["source_sequence"],
            source_epoch_records([row])[0].sha256,
        )
        for row in independent["records"]
    )
    witness_value = ClosureWitness(
        tuple(ClosureReference(**row) for row in independent["references"]),
        independent_records,
    )
    witness = authority.sign(witness_value)
    witness_root = coordinator / "proofs"
    witness_root.mkdir(mode=0o700)
    with ClosureEvidenceStore(str(witness_root), scope=scope) as store:
        store.append(witness)
    with ClosureEvidenceStore(str(evidence), scope=scope) as store:
        recovered_documents = store.load()

    def verify(
        items: list[SignedClosureDocument] | tuple[SignedClosureDocument, ...],
    ) -> dict[str, Any]:
        return asdict(
            verify_distributed_closure(
                scope=scope,
                documents=items,
                witness=witness,
                trusted_keys=authority.trusted,
                verification_time=authority.now,
            )
        )

    clean = verify(recovered_documents)
    negatives: dict[str, Any] = {}
    for scenario in ("late_child", "unjoined_child", "dead_child"):
        changed = list(observed_values)
        parent_epoch, worker_epoch = changed[-1], changed[-2]
        if not isinstance(parent_epoch, SourceEpoch) or not isinstance(
            worker_epoch, SourceEpoch
        ):
            raise RuntimeError("closure campaign invalid source plan")
        if scenario == "late_child":
            changed[-1] = replace(
                parent_epoch, expected_children=(), joined_children=()
            )
        elif scenario == "unjoined_child":
            changed[-1] = replace(parent_epoch, joined_children=())
        else:
            changed[-2] = replace(worker_epoch, state="running")
        negatives[scenario] = verify([authority.sign(value) for value in changed])
    report = {
        "status": "passed"
        if clean["complete"] and all(not row["complete"] for row in negatives.values())
        else "failed",
        "trust_boundary": "separately persisted same-host finite coordinator plan; shared OS administrator",
        "automatic_distributed_instrumentation": False,
        "production_qualified": False,
        "plan_precommitted_before_sources": True,
        "source_process_termination_tested": True,
        "recovered_source_epochs": 2,
        "clean": clean,
        "negative_cases": negatives,
    }
    _write_atomic(output / "closure-report.json", json.dumps(report, indent=2).encode())
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal-stdin", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.journal_stdin:
        _journal_worker()
    elif args.output is not None:
        print(json.dumps(run_closure_campaign(args.output), indent=2))
    else:
        parser.error("--output is required")
