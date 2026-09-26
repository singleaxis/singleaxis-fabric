# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline byte resolution and conservative reconciliation for spec 040.

This is an optional offline verifier, not a judge or a recorder release
completeness attestation. Its current sources lack authenticated continuity
and durable destination receipts, so it never emits a complete verdict.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fabric.content_store.local import LocalFilesystemContentStore


@dataclass(frozen=True, slots=True)
class ExpectedByteObject:
    """One independently measured boundary observation for comparison."""

    source_id: str
    boundary: str
    operation_id: str
    attempt_id: str
    role: str
    data: bytes


@dataclass(frozen=True, slots=True)
class ExpectedOperation:
    """One independently expected outcome with fields to compare exactly."""

    boundary: str
    operation_id: str
    attempt_id: str
    fields: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ByteResolution:
    status: str
    data: bytes | None = None
    reason: str | None = None


class SyntheticByteResolver:
    """Read only exact object IDs in the explicitly configured tenant store."""

    def __init__(self, store: LocalFilesystemContentStore, *, tenant_id: str) -> None:
        if store.tenant_id != tenant_id:
            raise ValueError("resolver store tenant mismatch")
        self.store = store
        self.tenant_id = tenant_id

    def resolve(self, descriptor: dict[str, Any]) -> ByteResolution:  # noqa: PLR0911, PLR0912 - explicit refusal states
        if descriptor.get("tenant_id") != self.tenant_id:
            return ByteResolution("denied", reason="tenant_mismatch")
        status = descriptor.get("status")
        if status == "pending":
            return ByteResolution("pending")
        if status != "stored":
            return ByteResolution("unverified", reason="object_not_stored")
        object_id = descriptor.get("object_id")
        ref = descriptor.get("ref")
        if not isinstance(object_id, str) or not isinstance(ref, str):
            return ByteResolution("unverified", reason="identity_missing")
        parsed = urlsplit(ref)
        if parsed.scheme != "file" or parsed.netloc or parsed.query or parsed.fragment:
            return ByteResolution("denied", reason="unsafe_ref")
        try:
            expected_ref = self.store.evidence_ref_for(object_id)
        except ValueError:
            return ByteResolution("denied", reason="unsafe_object_id")
        if ref != expected_ref:
            return ByteResolution("denied", reason="ref_not_canonical")
        target = Path(parsed.path)
        if target.is_symlink() or target.parent.is_symlink() or target.parent.parent.is_symlink():
            return ByteResolution("denied", reason="symlinked_store_path")
        try:
            stored_descriptor = self.store.read_descriptor(ref)
            data = self.store.read(ref)
        except FileNotFoundError:
            return ByteResolution("missing", reason="content_or_descriptor_missing")
        except ValueError:
            return ByteResolution("denied", reason="store_rejected_ref")
        except Exception:
            return ByteResolution("unverified", reason="store_read_failed")
        if stored_descriptor != descriptor:
            return ByteResolution("corrupted", reason="descriptor_disagreement")
        length = descriptor.get("stored_byte_length")
        digest = descriptor.get("stored_sha256")
        source_length = descriptor.get("source_byte_length")
        source_digest = descriptor.get("source_sha256")
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        if (
            not isinstance(length, int)
            or isinstance(length, bool)
            or length != len(data)
            or digest != actual
            or descriptor.get("representation") != "exact"
            or source_length != length
            or source_digest != actual
        ):
            return ByteResolution("corrupted", reason="byte_length_or_digest_mismatch")
        return ByteResolution("available", data=data)


def reconcile_synthetic_run(  # noqa: PLR0912, PLR0915 - every evidence failure is explicit
    snapshot: dict[str, Any],
    expected: list[ExpectedByteObject],
    resolver: SyntheticByteResolver,
    *,
    expected_operations: list[ExpectedOperation] | None = None,
) -> dict[str, Any]:
    """Compare exact objects and source order; never certify missing proofs.

    ``expected`` must be built from independent endpoint, fixture, and
    filesystem records. This function cannot authenticate that provenance.
    """
    discrepancies: list[dict[str, Any]] = []
    for gap in snapshot.get("source_spool_recovered_gaps", []):
        discrepancies.append({"kind": "source_spool_recovered_sequence_gap", **gap})
    observed = snapshot.get("events", [])
    operations = snapshot.get("operations", [])
    if (
        not isinstance(observed, list)
        or not isinstance(operations, list)
        or snapshot.get("tenant_id") != resolver.tenant_id
    ):
        raise ValueError("snapshot tenant, events or operations invalid")
    by_key: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    by_source: dict[str, list[int]] = {}
    for event in observed:
        key = tuple(
            event.get(field, "")
            for field in ("source_id", "boundary", "operation_id", "attempt_id", "role")
        )
        by_key.setdefault(key, []).append(event)
        if event.get("status") in {
            "dropped",
            "failed",
            "truncated",
            "unsupported",
            "not_captured",
            "pending",
            "redacted",
        }:
            discrepancies.append(
                {
                    "kind": "incomplete_evidence",
                    "record_id": event.get("record_id"),
                    "source_id": event.get("source_id"),
                    "boundary": event.get("boundary"),
                    "role": event.get("role"),
                    "status": event.get("status"),
                }
            )
    for event in [*observed, *operations]:
        source = event.get("source_id")
        sequence = event.get("source_sequence")
        if isinstance(source, str) and isinstance(sequence, int) and not isinstance(sequence, bool):
            by_source.setdefault(source, []).append(sequence)
        else:
            discrepancies.append(
                {"kind": "source_identity_or_sequence_invalid", "record_id": event.get("record_id")}
            )
        if event.get("source_spool_status") in {"dropped", "failed"} or event.get(
            "source_spool_submission_failed"
        ):
            discrepancies.append(
                {
                    "kind": "source_spool_gap",
                    "record_id": event.get("record_id"),
                    "source_id": source,
                    "boundary": event.get("boundary"),
                    "role": event.get("role"),
                    "status": event.get("source_spool_status", "failed"),
                }
            )
    for source, sequences in sorted(by_source.items()):
        if sorted(sequences) != list(range(len(sequences))):
            discrepancies.append(
                {
                    "kind": "source_sequence_gap_or_duplicate",
                    "source_id": source,
                    "observed": sequences,
                }
            )
        if snapshot.get("source_high_water", {}).get(source) != max(sequences):
            discrepancies.append({"kind": "source_high_water_mismatch", "source_id": source})
    for item in expected:
        key = (item.source_id, item.boundary, item.operation_id, item.attempt_id, item.role)
        matches = by_key.pop(key, [])
        if not matches:
            discrepancies.append(
                {
                    "kind": "missing_required_object",
                    "source_id": item.source_id,
                    "boundary": item.boundary,
                    "operation_id": item.operation_id,
                    "attempt_id": item.attempt_id,
                    "role": item.role,
                }
            )
            continue
        # A stream may have several chunks; order is the source sequence.
        matches.sort(key=lambda event: event.get("source_sequence", -1))
        available: list[bytes] = []
        chunk_indices: list[int] = []
        for event in matches:
            descriptor = event.get("descriptor")
            if not isinstance(descriptor, dict):
                continue
            resolution = resolver.resolve(descriptor)
            if resolution.status != "available" or resolution.data is None:
                discrepancies.append(
                    {
                        "kind": "unresolved_object",
                        "record_id": event.get("record_id"),
                        "role": item.role,
                        "resolution": resolution.status,
                    }
                )
                continue
            available.append(resolution.data)
            if "chunk_index" in descriptor:
                chunk_indices.append(descriptor["chunk_index"])
        if chunk_indices and chunk_indices != list(range(len(matches))):
            discrepancies.append(
                {
                    "kind": "stream_chunk_gap_or_duplicate",
                    "role": item.role,
                    "operation_id": item.operation_id,
                    "observed": chunk_indices,
                }
            )
        actual = b"".join(available)
        if len(available) == len(matches) and actual != item.data:
            discrepancies.append(
                {
                    "kind": "byte_mismatch",
                    "source_id": item.source_id,
                    "boundary": item.boundary,
                    "operation_id": item.operation_id,
                    "role": item.role,
                    "expected_sha256": "sha256:" + hashlib.sha256(item.data).hexdigest(),
                    "observed_sha256": "sha256:" + hashlib.sha256(actual).hexdigest(),
                }
            )
    for key, extras in sorted(by_key.items()):
        for event in extras:
            discrepancies.append(
                {
                    "kind": "unexpected_object",
                    "source_id": key[0],
                    "boundary": key[1],
                    "operation_id": key[2],
                    "attempt_id": key[3],
                    "role": key[4],
                    "record_id": event.get("record_id"),
                }
            )
    if expected_operations is not None:
        remaining = list(operations)
        for expected_operation in expected_operations:
            matches = [
                operation
                for operation in remaining
                if all(
                    operation.get(field) == getattr(expected_operation, field)
                    for field in ("boundary", "operation_id", "attempt_id")
                )
            ]
            match = next(
                (
                    operation
                    for operation in matches
                    if all(
                        operation.get(field) == value
                        for field, value in expected_operation.fields.items()
                    )
                ),
                None,
            )
            if match is None:
                discrepancies.append(
                    {
                        "kind": "missing_or_mismatched_operation_outcome",
                        "boundary": expected_operation.boundary,
                        "operation_id": expected_operation.operation_id,
                        "attempt_id": expected_operation.attempt_id,
                    }
                )
            else:
                remaining.remove(match)
        for operation in remaining:
            discrepancies.append(
                {
                    "kind": "unexpected_operation_outcome",
                    "boundary": operation.get("boundary"),
                    "operation_id": operation.get("operation_id"),
                    "attempt_id": operation.get("attempt_id"),
                }
            )
    return {
        "schema_version": "fabric.synthetic-discrepancy/v1",
        "run_id": snapshot.get("run_id"),
        "verdict": "partial" if discrepancies else "unverified",
        "complete_verdict_available": False,
        "proofs_missing": [
            "authenticated_source_identity",
            "persisted_epoch_and_sequence",
            "durable_destination_receipt",
            "independent_feed_authentication",
        ],
        "discrepancies": discrepancies,
    }
