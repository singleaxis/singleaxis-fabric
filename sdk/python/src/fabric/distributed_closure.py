# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Authenticated, conservative multi-source closure for a finite declared run.

This optional offline verifier does not change CallRecorder or its legacy
single-epoch qualified verifier. A source registry, each source, and a separate
witness issue purpose-bound Ed25519 statements using ``evidence_attestation``.
No timestamp is interpreted as execution order. Explicit parent anchors,
per-source sequence positions, epoch hash links and joined-child hashes supply
only the causal edges actually witnessed.

The owner must provision the registry/source/witness identities and a fresh
challenge independently. A witness must observe source dispatch/child lifecycle
and freeze its own inventory; signing a recorder-derived inventory is NOT
independent truth. Cryptographic role separation cannot establish operational
independence. ``complete`` concerns this declared evidence inventory only, never
production qualification, coverage of undeclared routes or destination delivery.
All identifiers must be opaque; documents contain no captured customer bytes.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import threading
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .evidence_attestation import (
    EvidenceExpectation,
    EvidenceTrustKey,
    verify_evidence_attestation,
)
from .source_spool import _read_secure, _sync_directory, _write_atomic

_SCHEMA = "fabric.distributed-closure/v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_DOCUMENT = 64 << 20
_MAX_ROWS = 100_000
_MAX_COUNTER = 2**63 - 1
_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700
_KINDS = frozenset({"registration", "context", "epoch", "witness"})


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def closure_sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _id(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _digest(value: object) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _counter(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_COUNTER


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_closure_field")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class ClosureScope:
    tenant_id: str
    run_id: str
    scope_sha256: str
    root_source_id: str
    registry_issuer_id: str
    witness_issuer_id: str
    challenge_id: str

    def __post_init__(self) -> None:
        if (
            not all(_id(value) for key, value in asdict(self).items() if key != "scope_sha256")
            or not _digest(self.scope_sha256)
            or self.registry_issuer_id == self.witness_issuer_id
        ):
            raise ValueError("invalid_closure_scope")


@dataclass(frozen=True, slots=True)
class SourceRegistration:
    source_id: str
    issuer_id: str
    parent_context_id: str | None = None


@dataclass(frozen=True, slots=True)
class PropagatedContext:
    context_id: str
    parent_source_id: str
    parent_epoch: int
    parent_sequence: int
    child_source_id: str
    parent_call_id: str


@dataclass(frozen=True, slots=True)
class EpochRecord:
    record_id: str
    source_sequence: int
    sha256: str


@dataclass(frozen=True, slots=True)
class ChildJoin:
    context_id: str
    child_epoch_sha256: str


@dataclass(frozen=True, slots=True)
class SourceEpoch:
    source_id: str
    source_epoch: int
    records: tuple[EpochRecord, ...] = ()
    previous_epoch_sha256: str | None = None
    expected_children: tuple[str, ...] = ()
    joined_children: tuple[ChildJoin, ...] = ()
    state: str = "completed"
    unknown_records: int = 0
    lost_records: int = 0


@dataclass(frozen=True, slots=True)
class ClosureReference:
    kind: str
    subject_id: str
    sha256: str


@dataclass(frozen=True, slots=True)
class WitnessRecord:
    source_id: str
    source_epoch: int
    record_id: str
    source_sequence: int
    sha256: str


@dataclass(frozen=True, slots=True)
class ClosureWitness:
    references: tuple[ClosureReference, ...]
    records: tuple[WitnessRecord, ...]
    closed: bool = True
    unknown_sources: int = 0
    unresolved_children: int = 0


ClosureValue = SourceRegistration | PropagatedContext | SourceEpoch | ClosureWitness
_TYPES = {
    SourceRegistration: "registration",
    PropagatedContext: "context",
    SourceEpoch: "epoch",
    ClosureWitness: "witness",
}


@dataclass(frozen=True, slots=True)
class SignedClosureDocument:
    kind: str
    subject_id: str
    document_bytes: bytes
    attestation_bytes: bytes


@dataclass(frozen=True, slots=True)
class ClosureVerification:
    complete: bool
    reasons: tuple[str, ...]
    source_count: int = 0
    epoch_count: int = 0
    record_count: int = 0
    production_qualified: bool = False


def _subject(kind: str, body: Mapping[str, Any], scope: ClosureScope) -> str:
    if kind == "registration":
        return str(body["source_id"])
    if kind == "context":
        return str(body["context_id"])
    if kind == "epoch":
        return (
            "epoch:"
            + hashlib.sha256(_canonical([body["source_id"], body["source_epoch"]])).hexdigest()
        )
    return scope.challenge_id


def closure_document_bytes(scope: ClosureScope, value: ClosureValue) -> bytes:
    """Serialize a closed control document; the caller's issuer signs it separately."""
    kind = _TYPES.get(type(value))
    if kind is None:
        raise ValueError("invalid_closure_value")
    body = asdict(value)
    data = _canonical({"schema_version": _SCHEMA, "kind": kind, "scope": asdict(scope), **body})
    _parse(SignedClosureDocument(kind, _subject(kind, body, scope), data, b""), scope)
    return data


def closure_document_id(scope: ClosureScope, value: ClosureValue) -> str:
    kind = _TYPES.get(type(value))
    if kind is None:
        raise ValueError("invalid_closure_value")
    return _subject(kind, asdict(value), scope)


def closure_expectation(
    scope: ClosureScope,
    kind: str,
    subject_id: str,
    document_bytes: bytes,
    issuer_id: str,
) -> EvidenceExpectation:
    """Existing external attestation API, without retaining any private key."""
    if kind not in _KINDS:
        raise ValueError("invalid_closure_kind")
    statement = "independent_witness" if kind == "witness" else "source_binding"
    return EvidenceExpectation(
        statement,
        scope.tenant_id,
        scope.run_id,
        scope.scope_sha256,
        "evidence_set" if kind == "witness" else "source",
        subject_id,
        closure_sha256(document_bytes),
        issuer_id,
    )


def source_epoch_records(records: Sequence[Mapping[str, Any]]) -> tuple[EpochRecord, ...]:
    """Hash exact journal metadata bytes, not source truth or a durability assertion.

    Use records from SourceJournal.readback_sealed_epoch for actual fresh source
    readback. Hash encoding is the journal's canonical ensure_ascii=False JSON.
    The separate witness must supply its own observations, not call this on a
    recorder snapshot and thereby claim independence.
    """
    result = []
    for record in records:
        raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        result.append(
            EpochRecord(record["record_id"], record["source_sequence"], closure_sha256(raw))
        )
    return tuple(sorted(result, key=lambda item: item.source_sequence))


def _rows(value: object) -> bool:
    return isinstance(value, list) and len(value) <= _MAX_ROWS


def _record(row: object, *, witness: bool = False) -> bool:
    fields = {"record_id", "source_sequence", "sha256"}
    if witness:
        fields |= {"source_id", "source_epoch"}
    return (
        isinstance(row, dict)
        and set(row) == fields
        and _id(row["record_id"])
        and _counter(row["source_sequence"])
        and _digest(row["sha256"])
        and (not witness or (_id(row["source_id"]) and _counter(row["source_epoch"])))
    )


def _valid_body(kind: str, body: dict[str, Any]) -> bool:
    if kind == "registration":
        return (
            set(body) == {"source_id", "issuer_id", "parent_context_id"}
            and _id(body["source_id"])
            and _id(body["issuer_id"])
            and (body["parent_context_id"] is None or _id(body["parent_context_id"]))
        )
    if kind == "context":
        return (
            set(body)
            == {
                "context_id",
                "parent_source_id",
                "parent_epoch",
                "parent_sequence",
                "child_source_id",
                "parent_call_id",
            }
            and all(
                _id(body[key])
                for key in ("context_id", "parent_source_id", "child_source_id", "parent_call_id")
            )
            and _counter(body["parent_epoch"])
            and _counter(body["parent_sequence"])
            and body["child_source_id"] != body["parent_source_id"]
        )
    if kind == "epoch":
        return (
            set(body)
            == {
                "source_id",
                "source_epoch",
                "records",
                "previous_epoch_sha256",
                "expected_children",
                "joined_children",
                "state",
                "unknown_records",
                "lost_records",
            }
            and _id(body["source_id"])
            and _counter(body["source_epoch"])
            and (body["previous_epoch_sha256"] is None or _digest(body["previous_epoch_sha256"]))
            and _rows(body["records"])
            and all(_record(row) for row in body["records"])
            and _rows(body["expected_children"])
            and all(_id(x) for x in body["expected_children"])
            and _rows(body["joined_children"])
            and all(
                isinstance(row, dict)
                and set(row) == {"context_id", "child_epoch_sha256"}
                and _id(row["context_id"])
                and _digest(row["child_epoch_sha256"])
                for row in body["joined_children"]
            )
            and isinstance(body["state"], str)
            and body["state"] in {"completed", "recovered", "failed", "cancelled", "running"}
            and _counter(body["unknown_records"])
            and _counter(body["lost_records"])
        )
    if kind == "witness":
        return (
            set(body)
            == {"references", "records", "closed", "unknown_sources", "unresolved_children"}
            and type(body["closed"]) is bool
            and _counter(body["unknown_sources"])
            and _counter(body["unresolved_children"])
            and _rows(body["references"])
            and _rows(body["records"])
            and all(_record(row, witness=True) for row in body["records"])
            and all(
                isinstance(row, dict)
                and set(row) == {"kind", "subject_id", "sha256"}
                and isinstance(row["kind"], str)
                and row["kind"] in _KINDS - {"witness"}
                and _id(row["subject_id"])
                and _digest(row["sha256"])
                for row in body["references"]
            )
        )
    return False


def _parse(proof: SignedClosureDocument, scope: ClosureScope) -> dict[str, Any]:
    if (
        not isinstance(proof, SignedClosureDocument)
        or not isinstance(proof.kind, str)
        or proof.kind not in _KINDS
        or not _id(proof.subject_id)
        or not isinstance(proof.document_bytes, bytes)
        or len(proof.document_bytes) > _MAX_DOCUMENT
        or not isinstance(proof.attestation_bytes, bytes)
    ):
        raise ValueError("invalid_closure_document")
    value = json.loads(proof.document_bytes, object_pairs_hook=_unique)
    if (
        not isinstance(value, dict)
        or value.pop("schema_version", None) != _SCHEMA
        or value.pop("kind", None) != proof.kind
        or value.pop("scope", None) != asdict(scope)
        or not _valid_body(proof.kind, value)
        or _subject(proof.kind, value, scope) != proof.subject_id
    ):
        raise ValueError("invalid_closure_document")
    expected = {"schema_version": _SCHEMA, "kind": proof.kind, "scope": asdict(scope), **value}
    if _canonical(expected) != proof.document_bytes:
        raise ValueError("noncanonical_closure_document")
    return value


def _authenticated(
    proof: SignedClosureDocument,
    scope: ClosureScope,
    issuer: str,
    keys: Mapping[str, EvidenceTrustKey],
    now: int,
) -> bool:
    return (
        verify_evidence_attestation(
            proof.attestation_bytes,
            expected=closure_expectation(
                scope, proof.kind, proof.subject_id, proof.document_bytes, issuer
            ),
            trusted_keys=keys,
            verification_time=now,
        ).status
        == "verified"
    )


def authenticate_propagated_context(
    *,
    scope: ClosureScope,
    parent_registration: SignedClosureDocument,
    context: SignedClosureDocument,
    expected_child_source_id: str,
    trusted_keys: Mapping[str, EvidenceTrustKey],
    verification_time: int,
) -> PropagatedContext:
    """Verify registration and exact child audience before accepting propagation.

    A verified context authorizes identity/correlation only, never an action or
    complete-run claim. The child must still register, settle and be joined.
    """
    try:
        parent = _parse(parent_registration, scope)
        child = _parse(context, scope)
        if (
            parent_registration.kind != "registration"
            or context.kind != "context"
            or child["parent_source_id"] != parent["source_id"]
            or child["child_source_id"] != expected_child_source_id
            or not _role_separation(scope, {parent["source_id"]: parent}, trusted_keys)
            or not _authenticated(
                parent_registration,
                scope,
                scope.registry_issuer_id,
                trusted_keys,
                verification_time,
            )
            or not _authenticated(
                context, scope, parent["issuer_id"], trusted_keys, verification_time
            )
        ):
            raise ValueError("unauthenticated_propagated_context")
        return PropagatedContext(**child)
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        raise ValueError("unauthenticated_propagated_context") from None


def _record_key(row: Mapping[str, Any]) -> tuple[str, int, str, int, str]:
    return (
        row["source_id"],
        row["source_epoch"],
        row["record_id"],
        row["source_sequence"],
        row["sha256"],
    )


def _role_separation(
    scope: ClosureScope,
    registrations: Mapping[str, dict[str, Any]],
    keys: Mapping[str, EvidenceTrustKey],
) -> bool:
    issuers = {row["issuer_id"] for row in registrations.values()}
    if issuers & {scope.registry_issuer_id, scope.witness_issuer_id}:
        return False
    # Shared source keys cannot authenticate which of two registered workers
    # emitted a statement. Registry, witness and each source need distinct keys.
    if len(issuers) != len(registrations):
        return False
    owners: dict[bytes, str] = {}
    allowed = issuers | {scope.registry_issuer_id, scope.witness_issuer_id}
    for key in keys.values():
        if key.tenant_id != scope.tenant_id or key.revoked:
            continue
        if key.issuer_id not in allowed:
            continue
        if key.public_key in owners and owners[key.public_key] != key.issuer_id:
            return False
        owners[key.public_key] = key.issuer_id
    return True


def _check_sources(  # noqa: PLR0912, PLR0915
    scope: ClosureScope,
    registrations: dict[str, dict[str, Any]],
    contexts: dict[str, dict[str, Any]],
    epochs: dict[tuple[str, int], dict[str, Any]],
    digests: dict[tuple[str, int], str],
    reasons: set[str],
) -> list[dict[str, Any]]:
    roots = {source for source, row in registrations.items() if row["parent_context_id"] is None}
    if roots != {scope.root_source_id}:
        reasons.add("root_inventory_mismatch")
    used_contexts = [
        row["parent_context_id"]
        for row in registrations.values()
        if row["parent_context_id"] is not None
    ]
    if set(used_contexts) != set(contexts) or len(used_contexts) != len(set(used_contexts)):
        reasons.add("orphan_or_duplicate_child")
    checked_nodes: set[str] = set()
    for source, registration in registrations.items():
        context_id = registration["parent_context_id"]
        if context_id is not None and (
            context_id not in contexts or contexts[context_id]["child_source_id"] != source
        ):
            reasons.add("child_registration_mismatch")
        seen: set[str] = set()
        node = source
        while node in registrations and node != scope.root_source_id and node not in checked_nodes:
            if node in seen:
                reasons.add("child_cycle")
                break
            seen.add(node)
            context = contexts.get(registrations[node]["parent_context_id"])
            if context is None:
                reasons.add("orphan_child")
                break
            node = context["parent_source_id"]
        if node not in registrations:
            reasons.add("unregistered_parent")
        checked_nodes.update(seen)
    chains: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for (source, number), row in epochs.items():
        chains.setdefault(source, []).append((number, row))
    for chain in chains.values():
        chain.sort(key=lambda item: item[0])
    children: dict[str, set[str]] = {}
    for name, row in contexts.items():
        children.setdefault(row["parent_source_id"], set()).add(name)
    records: list[dict[str, Any]] = []
    all_record_ids: set[str] = set()
    for source in registrations:
        chain = chains.get(source, [])
        if not chain:
            reasons.add("missing_source_epoch")
            continue
        if [number for number, _ in chain] != list(range(len(chain))):
            reasons.add("missing_or_overlapping_epoch")
        expected_children: list[str] = []
        joined: list[str] = []
        for index, (number, epoch) in enumerate(chain):
            previous = None if index == 0 else digests[(source, chain[index - 1][0])]
            if epoch["previous_epoch_sha256"] != previous:
                reasons.add("epoch_link_mismatch")
            last = index == len(chain) - 1
            if epoch["state"] != ("completed" if last else "recovered"):
                reasons.add("source_not_completed" if last else "epoch_state_overlap")
            if epoch["lost_records"] or epoch["unknown_records"]:
                reasons.add("source_loss_or_unknown")
            positions = [row["source_sequence"] for row in epoch["records"]]
            if sorted(positions) != list(range(len(positions))):
                reasons.add("sequence_gap_or_overlap")
            for row in epoch["records"]:
                if row["record_id"] in all_record_ids:
                    reasons.add("duplicate_record_identity")
                all_record_ids.add(row["record_id"])
                records.append({"source_id": source, "source_epoch": number, **row})
            position_set = set(positions)
            for child_id in epoch["expected_children"]:
                expected_children.append(child_id)
                context = contexts.get(child_id)
                if (
                    context is None
                    or (context["parent_source_id"], context["parent_epoch"]) != (source, number)
                    or context["parent_sequence"] not in position_set
                ):
                    reasons.add("child_context_anchor_mismatch")
            for join in epoch["joined_children"]:
                joined.append(join["context_id"])
                context = contexts.get(join["context_id"])
                if context is None or context["parent_source_id"] != source:
                    reasons.add("orphan_join")
                    continue
                child_chain = chains.get(context["child_source_id"], [])
                if not child_chain:
                    reasons.add("unresolved_child")
                    continue
                child_number, child_epoch = child_chain[-1]
                if (
                    child_epoch["state"] != "completed"
                    or join["child_epoch_sha256"]
                    != digests[(context["child_source_id"], child_number)]
                    or number < context["parent_epoch"]
                ):
                    reasons.add("child_join_not_terminal")
        required = children.get(source, set())
        if set(expected_children) != required or len(expected_children) != len(required):
            reasons.add("expected_child_inventory_mismatch")
        if set(joined) != required or len(joined) != len(required):
            reasons.add("unjoined_or_duplicate_child")
    if any(source not in registrations for source, _ in epochs):
        reasons.add("unregistered_source")
    return records


def verify_distributed_closure(  # noqa: PLR0912, PLR0915
    *,
    scope: ClosureScope,
    documents: Sequence[SignedClosureDocument],
    witness: SignedClosureDocument | None,
    trusted_keys: Mapping[str, EvidenceTrustKey],
    verification_time: int,
) -> ClosureVerification:
    """Fail closed on any unaccounted source, child, epoch, record or evidence.

    Exact duplicate transport deliveries are idempotent. Different signed
    envelopes at one identity/epoch fail conservatively, even if both verify.
    Epoch manifests are immutable final evidence; do not persist provisional
    running snapshots at the same identity and later overwrite them.
    This method never fetches or manufactures independent witness evidence.
    """
    if not isinstance(scope, ClosureScope) or not _counter(verification_time):
        raise ValueError("invalid_closure_verification_input")
    if not isinstance(documents, (list, tuple)) or len(documents) > _MAX_ROWS:
        return ClosureVerification(False, ("closure_capacity_exceeded",))
    reasons: set[str] = set()
    parsed: dict[tuple[str, str], tuple[SignedClosureDocument, dict[str, Any]]] = {}
    total = 0
    for proof in documents:
        try:
            body = _parse(proof, scope)
            if proof.kind == "witness":
                raise ValueError("unexpected_witness")
            total += len(proof.document_bytes) + len(proof.attestation_bytes)
            if total > _MAX_DOCUMENT:
                return ClosureVerification(False, ("closure_capacity_exceeded",))
            identity = (proof.kind, proof.subject_id)
            if identity in parsed and parsed[identity][0] != proof:
                reasons.add("duplicate_identity_conflict")
            parsed[identity] = (proof, body)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            reasons.add("invalid_closure_document")
    registrations = {
        row["source_id"]: row for (kind, _), (_, row) in parsed.items() if kind == "registration"
    }
    contexts = {
        row["context_id"]: row for (kind, _), (_, row) in parsed.items() if kind == "context"
    }
    epochs = {
        (row["source_id"], row["source_epoch"]): row
        for (kind, _), (_, row) in parsed.items()
        if kind == "epoch"
    }
    digests = {
        (row["source_id"], row["source_epoch"]): closure_sha256(proof.document_bytes)
        for (kind, _), (proof, row) in parsed.items()
        if kind == "epoch"
    }
    if not _role_separation(scope, registrations, trusted_keys):
        reasons.add("issuer_roles_not_independent")
    for (kind, _), (proof, row) in parsed.items():
        issuer = scope.registry_issuer_id
        if kind in {"context", "epoch"}:
            source = row["parent_source_id"] if kind == "context" else row["source_id"]
            registration = registrations.get(source)
            if registration is None:
                reasons.add("unregistered_source")
                continue
            issuer = registration["issuer_id"]
        if not _authenticated(proof, scope, issuer, trusted_keys, verification_time):
            reasons.add("unauthenticated_" + kind)
    records = _check_sources(scope, registrations, contexts, epochs, digests, reasons)
    if witness is None:
        reasons.add("missing_independent_witness")
    else:
        try:
            observed = _parse(witness, scope)
            if witness.kind != "witness" or not _authenticated(
                witness, scope, scope.witness_issuer_id, trusted_keys, verification_time
            ):
                reasons.add("unauthenticated_witness")
            else:
                references = {
                    (kind, subject, closure_sha256(proof.document_bytes))
                    for (kind, subject), (proof, _) in parsed.items()
                }
                supplied = [
                    (row["kind"], row["subject_id"], row["sha256"])
                    for row in observed["references"]
                ]
                if set(supplied) != references or len(supplied) != len(references):
                    reasons.add("witness_control_inventory_mismatch")
                expected_records = {_record_key(row) for row in records}
                supplied_records = [_record_key(row) for row in observed["records"]]
                if set(supplied_records) != expected_records or len(supplied_records) != len(
                    expected_records
                ):
                    reasons.add("witness_source_inventory_mismatch")
                if (
                    not observed["closed"]
                    or observed["unknown_sources"]
                    or observed["unresolved_children"]
                ):
                    reasons.add("witness_not_closed")
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            reasons.add("invalid_witness")
    return ClosureVerification(
        not reasons, tuple(sorted(reasons)), len(registrations), len(epochs), len(records)
    )


class ClosureEvidenceStore:
    """Explicit fsynced, append-only control evidence; never on the action path.

    Proofs retain their exact signed bytes across restart. Conflicting identity
    writes persist both versions so they cannot be forgotten by ignoring an
    exception. Every read freshly verifies mode/owner/content-addressed filename.
    An interrupted temporary write or any corruption blocks load. Directory
    retention/deletion, key custody and trusted witness operation belong to the
    deployment owner; this stores opaque metadata, not private signing keys.
    """

    def __init__(self, root: str, *, scope: ClosureScope, max_bytes: int = _MAX_DOCUMENT) -> None:
        path = Path(root)
        info = path.lstat()
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != _DIRECTORY_MODE
            or info.st_uid != os.geteuid()
            or type(max_bytes) is not int
            or not 0 < max_bytes <= _MAX_DOCUMENT
        ):
            raise ValueError("unsafe_closure_store")
        self.root = path
        self.scope = scope
        self.max_bytes = max_bytes
        self._mutex = threading.Lock()
        self._closed = False
        self._fd = os.open(path / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(self._fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != _FILE_MODE
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
            ):
                raise ValueError("unsafe_closure_store")
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            scope_bytes = _canonical(asdict(scope))
            scope_path = path / "scope.json"
            if scope_path.exists():
                if _read_secure(scope_path, 4096) != scope_bytes:
                    raise ValueError("closure_store_scope_mismatch")
            else:
                if set(os.listdir(path)) != {".lock"}:
                    raise ValueError("closure_store_missing_scope")
                _write_atomic(scope_path, scope_bytes)
            self.load()
        except BaseException:
            os.close(self._fd)
            raise

    def _entry(self, proof: SignedClosureDocument) -> bytes:
        _parse(proof, self.scope)
        if len(proof.attestation_bytes) > 64 << 10:
            raise ValueError("closure_attestation_too_large")
        return _canonical(
            {
                "kind": proof.kind,
                "subject_id": proof.subject_id,
                "document": base64.b64encode(proof.document_bytes).decode("ascii"),
                "attestation": base64.b64encode(proof.attestation_bytes).decode("ascii"),
            }
        )

    def append(self, proof: SignedClosureDocument) -> str:
        """Return durable only after file and directory fsync; retries are idempotent."""
        data = self._entry(proof)
        name = "proof-" + hashlib.sha256(data).hexdigest() + ".json"
        with self._mutex:
            if self._closed:
                raise ValueError("closure_store_closed")
            self._load()
            target = self.root / name
            if target.exists():
                if _read_secure(target, self.max_bytes) != data:
                    raise ValueError("closure_store_corrupt")
                # Settle a prior successful rename whose directory fsync failed.
                _sync_directory(self.root)
                return "durable"
            used = sum(item.lstat().st_size for item in self.root.iterdir())
            if used + len(data) > self.max_bytes:
                raise ValueError("closure_store_capacity")
            _write_atomic(target, data)
            return "durable"

    def _load(self) -> tuple[SignedClosureDocument, ...]:
        if _read_secure(self.root / "scope.json", 4096) != _canonical(asdict(self.scope)):
            raise ValueError("closure_store_scope_mismatch")
        result = []
        used = 0
        for path in sorted(self.root.iterdir()):
            if path.name in {".lock", "scope.json"}:
                continue
            if re.fullmatch(r"proof-[0-9a-f]{64}\.json", path.name) is None:
                raise ValueError("closure_store_unsettled_or_corrupt")
            data = _read_secure(path, self.max_bytes - used)
            used += len(data)
            if path.name != "proof-" + hashlib.sha256(data).hexdigest() + ".json":
                raise ValueError("closure_store_corrupt")
            value = json.loads(data, object_pairs_hook=_unique)
            if not isinstance(value, dict) or set(value) != {
                "kind",
                "subject_id",
                "document",
                "attestation",
            }:
                raise ValueError("closure_store_corrupt")
            proof = SignedClosureDocument(
                value["kind"],
                value["subject_id"],
                base64.b64decode(value["document"], validate=True),
                base64.b64decode(value["attestation"], validate=True),
            )
            if self._entry(proof) != data:
                raise ValueError("closure_store_corrupt")
            result.append(proof)
            if len(result) > _MAX_ROWS:
                raise ValueError("closure_store_capacity")
        return tuple(result)

    def load(self) -> tuple[SignedClosureDocument, ...]:
        with self._mutex:
            if self._closed:
                raise ValueError("closure_store_closed")
            return self._load()

    def close(self) -> None:
        with self._mutex:
            if not self._closed:
                self._closed = True
                with contextlib.suppress(OSError):
                    os.close(self._fd)

    def __enter__(self) -> ClosureEvidenceStore:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
