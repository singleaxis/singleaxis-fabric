# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Finite authenticated reference closure; fixtures do not attest infrastructure."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fabric.distributed_closure import (
    ChildJoin,
    ClosureEvidenceStore,
    ClosureReference,
    ClosureScope,
    ClosureWitness,
    EpochRecord,
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

SCOPE = ClosureScope(
    "tenant-a", "run-a", "sha256:" + "a" * 64, "parent", "registry", "witness", "fresh-1"
)


class Campaign:
    def __init__(self, recovered: bool = False) -> None:
        self.scope = SCOPE
        self.private = {
            issuer: Ed25519PrivateKey.generate()
            for issuer in ("registry", "witness", "parent-key", "worker-key")
        }
        self.keys = {
            issuer: EvidenceTrustKey(
                issuer,
                "tenant-a",
                key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                frozenset({"source_binding", "independent_witness"}),
                100,
                200,
            )
            for issuer, key in self.private.items()
        }
        # Fixture's independent source observations are specified separately,
        # before recorder-side epoch manifests. Live deployments must replace
        # this fixture with an independently persisted source/lifecycle feed.
        self.observed = [
            WitnessRecord("parent", 0, "p0", 0, "sha256:" + "1" * 64),
            WitnessRecord("worker", 0, "w0", 0, "sha256:" + "2" * 64),
        ]
        if recovered:
            self.observed.append(WitnessRecord("worker", 1, "w1", 0, "sha256:" + "3" * 64))
        self.values: list[Any] = [
            SourceRegistration("parent", "parent-key"),
            SourceRegistration("worker", "worker-key", "child-1"),
            PropagatedContext("child-1", "parent", 0, 0, "worker", "call-parent"),
        ]
        first = SourceEpoch(
            "worker",
            0,
            (EpochRecord("w0", 0, "sha256:" + "2" * 64),),
            state="recovered" if recovered else "completed",
        )
        self.values.append(first)
        if recovered:
            self.values.append(
                SourceEpoch(
                    "worker",
                    1,
                    (EpochRecord("w1", 0, "sha256:" + "3" * 64),),
                    previous_epoch_sha256=closure_sha256(closure_document_bytes(self.scope, first)),
                )
            )
        terminal = self.values[-1]
        self.values.append(
            SourceEpoch(
                "parent",
                0,
                (EpochRecord("p0", 0, "sha256:" + "1" * 64),),
                expected_children=("child-1",),
                joined_children=(
                    ChildJoin(
                        "child-1",
                        closure_sha256(closure_document_bytes(self.scope, terminal)),
                    ),
                ),
            )
        )

    def sign(
        self,
        value: Any,
        *,
        scope: ClosureScope | None = None,
        issuer: str | None = None,
        issued_at: int = 150,
    ) -> SignedClosureDocument:
        scope = scope or self.scope
        data = closure_document_bytes(scope, value)
        kind = json.loads(data)["kind"]
        subject_id = closure_document_id(scope, value)
        if issuer is None:
            if kind == "registration":
                issuer = "registry"
            elif kind == "witness":
                issuer = "witness"
            elif kind == "context":
                issuer = "parent-key"
            else:
                issuer = "parent-key" if value.source_id == "parent" else "worker-key"
        expectation = closure_expectation(scope, kind, subject_id, data, issuer)
        payload = {**asdict(expectation), "issued_at": issued_at, "expires_at": 199}
        signing = attestation_signing_bytes(payload, key_id=issuer)
        envelope = json.loads(signing.split(b"\0", 1)[1])
        envelope["signature"] = base64.b64encode(self.private[issuer].sign(signing)).decode()
        return SignedClosureDocument(kind, subject_id, data, json.dumps(envelope).encode())

    def proofs(self) -> list[SignedClosureDocument]:
        return [self.sign(value) for value in self.values]

    def witness(
        self, docs: list[SignedClosureDocument] | None = None, **overrides: Any
    ) -> SignedClosureDocument:
        docs = self.proofs() if docs is None else docs
        refs = tuple(
            ClosureReference(doc.kind, doc.subject_id, closure_sha256(doc.document_bytes))
            for doc in docs
        )
        value = ClosureWitness(refs, tuple(self.observed))
        return self.sign(replace(value, **overrides))

    def verify(
        self,
        docs: list[SignedClosureDocument] | None = None,
        witness: SignedClosureDocument | None = None,
        **kwargs: Any,
    ) -> Any:
        docs = self.proofs() if docs is None else docs
        return verify_distributed_closure(
            scope=self.scope,
            documents=docs,
            witness=witness or self.witness(docs),
            trusted_keys=kwargs.pop("trusted_keys", self.keys),
            verification_time=160,
            **kwargs,
        )


def test_registered_children_join_exact_terminal_epoch() -> None:
    case = Campaign()
    result = case.verify()
    assert result.complete and result.reasons == ()
    assert (result.source_count, result.epoch_count, result.record_count) == (2, 2, 2)
    assert not result.production_qualified


def test_recovered_source_epochs_complete_only_with_all_independent_truth() -> None:
    case = Campaign(recovered=True)
    result = case.verify()
    assert result.complete
    assert result.epoch_count == 3


@pytest.mark.parametrize("state", ["running", "failed", "cancelled", "recovered"])
def test_dead_or_unfinished_worker_prevents_parent_success(state: str) -> None:
    case = Campaign()
    case.values[3] = replace(case.values[3], state=state)
    result = case.verify()
    assert not result.complete
    assert "source_not_completed" in result.reasons
    assert "child_join_not_terminal" in result.reasons


def test_detached_unjoined_child_is_not_finalized_by_parent_completion() -> None:
    case = Campaign()
    case.values[-1] = replace(case.values[-1], joined_children=())
    assert "unjoined_or_duplicate_child" in case.verify().reasons


def test_child_declared_after_parent_closure_invalidates_old_proof() -> None:
    case = Campaign()
    case.values[-1] = replace(case.values[-1], expected_children=(), joined_children=())
    result = case.verify()
    assert "expected_child_inventory_mismatch" in result.reasons
    assert "unjoined_or_duplicate_child" in result.reasons


def test_orphan_registration_cannot_complete() -> None:
    case = Campaign()
    case.values.pop(2)
    assert "orphan_or_duplicate_child" in case.verify().reasons


def test_missing_registered_worker_and_unregistered_epoch_fail() -> None:
    case = Campaign()
    case.values.pop(1)
    result = case.verify()
    assert not result.complete
    assert "unregistered_source" in result.reasons


def test_missing_child_epoch_remains_unresolved() -> None:
    case = Campaign()
    case.values.pop(3)
    result = case.verify()
    assert "missing_source_epoch" in result.reasons
    assert "unresolved_child" in result.reasons


@pytest.mark.parametrize("epoch", [2, 2**63 - 1])
def test_missing_epochs_do_not_use_timestamps_or_allocate_huge_ranges(epoch: int) -> None:
    case = Campaign(recovered=True)
    case.values[4] = replace(case.values[4], source_epoch=epoch)
    assert "missing_or_overlapping_epoch" in case.verify().reasons


def test_duplicate_transport_delivery_idempotent_but_epoch_equivocation_fails() -> None:
    case = Campaign()
    docs = case.proofs()
    witness = case.witness(docs)
    assert case.verify([*docs, docs[0]], witness).complete
    conflict = case.sign(replace(case.values[3], unknown_records=1))
    result = case.verify([*docs, conflict], witness)
    assert "duplicate_identity_conflict" in result.reasons


def test_overlapping_epoch_after_completed_epoch_fails() -> None:
    case = Campaign(recovered=True)
    case.values[3] = replace(case.values[3], state="completed")
    assert "epoch_state_overlap" in case.verify().reasons


def test_epoch_link_substitution_fails() -> None:
    case = Campaign(recovered=True)
    case.values[4] = replace(case.values[4], previous_epoch_sha256="sha256:" + "f" * 64)
    assert "epoch_link_mismatch" in case.verify().reasons


@pytest.mark.parametrize(
    "records",
    [
        (EpochRecord("w0", 1, "sha256:" + "2" * 64),),
        (EpochRecord("w0", 0, "sha256:" + "2" * 64), EpochRecord("w2", 0, "sha256:" + "2" * 64)),
        (EpochRecord("w0", 0, "sha256:" + "2" * 64), EpochRecord("w0", 1, "sha256:" + "2" * 64)),
    ],
)
def test_sequence_gaps_overlap_and_duplicate_record_ids_fail(
    records: tuple[EpochRecord, ...],
) -> None:
    case = Campaign()
    case.values[3] = replace(case.values[3], records=records)
    result = case.verify()
    assert not result.complete
    assert {"sequence_gap_or_overlap", "duplicate_record_identity"} & set(result.reasons)


def test_unknown_prefsync_source_truth_cannot_disappear_at_restart() -> None:
    case = Campaign(recovered=True)
    case.observed.append(WitnessRecord("worker", 0, "lost-prefsync", 1, "sha256:" + "4" * 64))
    assert "witness_source_inventory_mismatch" in case.verify().reasons


@pytest.mark.parametrize("field", ["unknown_records", "lost_records"])
def test_explicit_loss_never_complete(field: str) -> None:
    case = Campaign()
    case.values[3] = replace(case.values[3], **{field: 1})
    assert "source_loss_or_unknown" in case.verify().reasons


def test_context_forgery_and_wrong_parent_key_fail() -> None:
    case = Campaign()
    docs = case.proofs()
    docs[2] = case.sign(case.values[2], issuer="worker-key")
    assert "unauthenticated_context" in case.verify(docs).reasons
    docs = case.proofs()
    docs[2] = replace(
        docs[2], document_bytes=docs[2].document_bytes.replace(b"call-parent", b"call-forged")
    )
    assert "unauthenticated_context" in case.verify(docs).reasons


def test_parent_context_must_anchor_actual_source_sequence() -> None:
    case = Campaign()
    case.values[2] = replace(case.values[2], parent_sequence=8)
    assert "child_context_anchor_mismatch" in case.verify().reasons


def test_wrong_tenant_scope_run_or_stale_challenge_rejected() -> None:
    case = Campaign()
    for field, value in (
        ("tenant_id", "tenant-b"),
        ("run_id", "run-b"),
        ("scope_sha256", "sha256:" + "b" * 64),
        ("challenge_id", "old-challenge"),
    ):
        docs = case.proofs()
        docs[2] = case.sign(case.values[2], scope=replace(case.scope, **{field: value}))
        assert "invalid_closure_document" in case.verify(docs).reasons


def test_missing_stale_mutated_and_revoked_witness_fail() -> None:
    case = Campaign()
    docs = case.proofs()
    result = verify_distributed_closure(
        scope=case.scope,
        documents=docs,
        witness=None,
        trusted_keys=case.keys,
        verification_time=160,
    )
    assert "missing_independent_witness" in result.reasons
    witness = case.witness()
    assert (
        "unauthenticated_witness"
        in case.verify(docs, replace(witness, attestation_bytes=b"corrupt")).reasons
    )
    keys = dict(case.keys)
    keys["witness"] = replace(keys["witness"], revoked=True)
    assert "unauthenticated_witness" in case.verify(trusted_keys=keys).reasons
    stale = case.sign(ClosureWitness((), ()), scope=replace(case.scope, challenge_id="old"))
    assert "invalid_witness" in case.verify(witness=stale).reasons


@pytest.mark.parametrize(
    "overrides",
    [
        {"closed": False},
        {"unknown_sources": 1},
        {"unresolved_children": 1},
    ],
)
def test_independent_witness_must_freeze_inventory(overrides: dict[str, Any]) -> None:
    case = Campaign()
    assert "witness_not_closed" in case.verify(witness=case.witness(**overrides)).reasons


def test_witness_tail_control_and_source_substitution_fail() -> None:
    case = Campaign()
    docs = case.proofs()
    assert (
        "witness_control_inventory_mismatch" in case.verify(docs, case.witness(docs[:-1])).reasons
    )
    assert (
        "witness_source_inventory_mismatch"
        in case.verify(witness=case.witness(records=tuple(case.observed[:-1]))).reasons
    )


def test_signature_issuance_clock_skew_never_invents_causal_order() -> None:
    case = Campaign(recovered=True)
    # Child and parent clocks have inverse order; explicit hashes/positions work.
    docs = [
        case.sign(
            value,
            issued_at=101
            if isinstance(value, SourceEpoch) and value.source_id == "parent"
            else 159,
        )
        for value in case.values
    ]
    assert case.verify(docs).complete


def test_same_key_or_issuer_cannot_self_witness() -> None:
    case = Campaign()
    keys = dict(case.keys)
    keys["witness"] = replace(keys["witness"], public_key=keys["parent-key"].public_key)
    assert "issuer_roles_not_independent" in case.verify(trusted_keys=keys).reasons
    case.values[0] = replace(case.values[0], issuer_id="witness")
    assert "issuer_roles_not_independent" in case.verify().reasons


def test_duplicate_and_malformed_fields_fail_closed() -> None:
    case = Campaign()
    docs = case.proofs()
    for data in (
        b"[]",
        b"null",
        b"{}",
        b"{",
        b'{"kind":"epoch","kind":"context"}',
        b"[" * 2000 + b"]" * 2000,
    ):
        invalid = replace(docs[0], document_bytes=data)
        assert not case.verify([invalid, *docs[1:]]).complete


def test_root_only_explicitly_empty_run() -> None:
    case = Campaign()
    case.values = [case.values[0], SourceEpoch("parent", 0)]
    case.observed = []
    assert case.verify().complete


def _directory(tmp_path: Path) -> Path:
    path = tmp_path / "closure"
    path.mkdir(mode=0o700)
    return path


def test_persisted_proofs_survive_fresh_process_recovery(tmp_path: Path) -> None:
    case = Campaign(recovered=True)
    proofs = case.proofs()
    witness = case.witness(proofs)
    path = _directory(tmp_path)
    with ClosureEvidenceStore(str(path), scope=case.scope) as store:
        for proof in [*proofs, witness]:
            _assert_result_429 = store.append(proof) == "durable"
            assert _assert_result_429
        _assert_result_430 = store.append(proofs[0]) == "durable"
        assert _assert_result_430
        assert len(store.load()) == len(proofs) + 1
    script = """import json, sys
from fabric.distributed_closure import ClosureEvidenceStore, ClosureScope
scope = ClosureScope(**json.loads(sys.argv[2]))
with ClosureEvidenceStore(sys.argv[1], scope=scope) as store:
    print(json.dumps(sorted(p.subject_id for p in store.load())))
"""
    done = subprocess.run(  # noqa: S603 - fixed test program and local evidence
        [sys.executable, "-c", script, str(path), json.dumps(asdict(case.scope))],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(done.stdout) == sorted(p.subject_id for p in [*proofs, witness])
    with ClosureEvidenceStore(str(path), scope=case.scope) as store:
        loaded = store.load()
        actual = [p for p in loaded if p.kind != "witness"]
        recovered_witness = next(p for p in loaded if p.kind == "witness")
        assert case.verify(actual, recovered_witness).complete


def test_process_kill_after_durable_ack_retains_exact_proof(tmp_path: Path) -> None:
    case = Campaign()
    proof = case.proofs()[0]
    path = _directory(tmp_path)
    payload = {
        **asdict(proof),
        "document_bytes": base64.b64encode(proof.document_bytes).decode(),
        "attestation_bytes": base64.b64encode(proof.attestation_bytes).decode(),
    }
    script = """import base64, json, os, sys
from fabric.distributed_closure import ClosureEvidenceStore, ClosureScope, SignedClosureDocument
value = json.loads(sys.argv[3])
for field in ("document_bytes", "attestation_bytes"):
    value[field] = base64.b64decode(value[field])
store = ClosureEvidenceStore(sys.argv[1], scope=ClosureScope(**json.loads(sys.argv[2])))
assert store.append(SignedClosureDocument(**value)) == "durable"
os._exit(17)
"""
    done = subprocess.run(  # noqa: S603 - fixed test program and local evidence
        [
            sys.executable,
            "-c",
            script,
            str(path),
            json.dumps(asdict(case.scope)),
            json.dumps(payload),
        ],
        check=False,
    )
    assert done.returncode == 17
    with ClosureEvidenceStore(str(path), scope=case.scope) as store:
        assert store.load() == (proof,)


def test_conflicting_epoch_versions_persist_across_restart(tmp_path: Path) -> None:
    case = Campaign()
    path = _directory(tmp_path)
    with ClosureEvidenceStore(str(path), scope=case.scope) as store:
        for proof in case.proofs():
            store.append(proof)
        store.append(case.sign(replace(case.values[3], unknown_records=1)))
    with ClosureEvidenceStore(str(path), scope=case.scope) as store:
        docs = list(store.load())
        assert "duplicate_identity_conflict" in case.verify(docs).reasons


@pytest.mark.parametrize("fault", ["corrupt", "temporary", "mode", "symlink", "scope"])
def test_store_faults_never_load_complete_evidence(tmp_path: Path, fault: str) -> None:
    case = Campaign()
    path = _directory(tmp_path)
    with ClosureEvidenceStore(str(path), scope=case.scope) as store:
        store.append(case.proofs()[0])
    target = next(path.glob("proof-*.json"))
    if fault == "corrupt":
        target.write_bytes(b"{}")
    elif fault == "temporary":
        (path / ".partial.tmp").write_bytes(b"interrupted")
    elif fault == "mode":
        target.chmod(0o644)
    elif fault == "symlink":
        other = tmp_path / "other"
        target.rename(other)
        target.symlink_to(other)
    else:
        (path / "scope.json").write_bytes(b"{}")
    with pytest.raises((ValueError, OSError)):
        ClosureEvidenceStore(str(path), scope=case.scope)


def test_store_capacity_lock_scope_and_closed_state(tmp_path: Path) -> None:
    case = Campaign()
    path = _directory(tmp_path)
    with ClosureEvidenceStore(str(path), scope=case.scope, max_bytes=512) as store:
        with pytest.raises(ValueError, match="capacity"):
            store.append(case.proofs()[0])
        with pytest.raises(BlockingIOError):
            ClosureEvidenceStore(str(path), scope=case.scope)
    with pytest.raises(ValueError, match="closed"):
        store.load()
    with pytest.raises(ValueError, match="closed"):
        store.append(case.proofs()[0])
    with pytest.raises(ValueError, match="scope"):
        ClosureEvidenceStore(str(path), scope=replace(case.scope, challenge_id="other"))


def test_journal_adapter_preserves_source_canonical_record_digest() -> None:
    records = [
        {"record_id": "a", "source_sequence": 1, "observed_at": "clock-a"},
        {"record_id": "b", "source_sequence": 0, "observed_at": "clock-b"},
    ]
    result = source_epoch_records(records)
    assert [row.record_id for row in result] == ["b", "a"]
    expected = json.dumps(
        records[0], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert result[1].sha256 == closure_sha256(expected)


def test_authenticate_context_before_child_accepts_it() -> None:
    case = Campaign()
    docs = case.proofs()
    args: dict[str, Any] = {
        "scope": case.scope,
        "parent_registration": docs[0],
        "context": docs[2],
        "expected_child_source_id": "worker",
        "trusted_keys": case.keys,
        "verification_time": 160,
    }
    assert authenticate_propagated_context(**args).parent_call_id == "call-parent"
    args["expected_child_source_id"] = "other-worker"
    with pytest.raises(ValueError, match="unauthenticated"):
        authenticate_propagated_context(**args)
    args["expected_child_source_id"] = "worker"
    args["context"] = case.sign(case.values[2], issuer="worker-key")
    with pytest.raises(ValueError, match="unauthenticated"):
        authenticate_propagated_context(**args)


def test_interrupted_fsync_is_unsettled_not_durable(tmp_path: Path, monkeypatch: Any) -> None:
    case = Campaign()
    path = _directory(tmp_path)
    store = ClosureEvidenceStore(str(path), scope=case.scope)

    real = os.fsync

    def fail(_fd: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError):
        store.append(case.proofs()[0])
    monkeypatch.setattr(os, "fsync", real)
    store.close()
    with pytest.raises(ValueError, match="unsettled"):
        ClosureEvidenceStore(str(path), scope=case.scope)


def test_reference_campaign_runs_real_source_process_restart(tmp_path: Path) -> None:
    import runpy  # noqa: PLC0415 - isolated optional executable example import

    example = (
        Path(__file__).resolve().parents[3] / "examples/enterprise-reference/closure_campaign.py"
    )
    entry = runpy.run_path(str(example))
    report = entry["run_closure_campaign"](tmp_path / "campaign")
    assert report["status"] == "passed"
    assert report["plan_precommitted_before_sources"] is True
    assert report["source_process_termination_tested"] is True
    assert report["clean"]["complete"] is True
    assert report["clean"]["epoch_count"] == 3
    assert all(not row["complete"] for row in report["negative_cases"].values())
    assert report["automatic_distributed_instrumentation"] is False
    assert report["production_qualified"] is False
    path = tmp_path / "campaign" / "closure-report.json"
    assert json.loads(path.read_bytes()) == json.loads(json.dumps(report))


def test_duplicate_children_and_orphan_joins_are_not_set_collapsed() -> None:
    case = Campaign()
    parent = case.values[-1]
    case.values[-1] = replace(
        parent,
        expected_children=("child-1", "child-1"),
        joined_children=(*parent.joined_children, *parent.joined_children),
    )
    result = case.verify()
    assert "expected_child_inventory_mismatch" in result.reasons
    assert "unjoined_or_duplicate_child" in result.reasons
    case.values[-1] = replace(parent, joined_children=(ChildJoin("orphan", "sha256:" + "f" * 64),))
    assert "orphan_join" in case.verify().reasons


def test_child_cycle_cannot_hide_behind_a_separate_root() -> None:
    case = Campaign()
    private = Ed25519PrivateKey.generate()
    case.private["other-key"] = private
    case.keys["other-key"] = EvidenceTrustKey(
        "other-key",
        "tenant-a",
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        frozenset({"source_binding"}),
        100,
        200,
    )
    case.values[2] = replace(case.values[2], parent_source_id="other")
    case.values.extend(
        [
            SourceRegistration("other", "other-key", "child-2"),
            PropagatedContext("child-2", "worker", 0, 0, "other", "worker-call"),
        ]
    )
    docs = case.proofs()
    assert "child_cycle" in case.verify(docs).reasons


def test_lost_directory_fsync_ack_retries_exact_control_proof(
    tmp_path: Path, monkeypatch: Any
) -> None:
    case = Campaign()
    path = _directory(tmp_path)
    store = ClosureEvidenceStore(str(path), scope=case.scope)
    real = os.fsync
    calls = 0

    def fail_directory_once(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("directory flush unavailable")
        real(fd)

    monkeypatch.setattr(os, "fsync", fail_directory_once)
    proof = case.proofs()[0]
    with pytest.raises(OSError):
        store.append(proof)
    monkeypatch.setattr(os, "fsync", real)
    _assert_result_669 = store.append(proof) == "durable"
    assert _assert_result_669
    assert store.load() == (proof,)
    store.close()
