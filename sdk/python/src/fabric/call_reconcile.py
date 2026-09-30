# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Read-only, conservative comparison of custom-agent calls (spec 043).

Witnesses come from independently collected provider, filesystem or database
records. Their labels document origin, not authentication. This verifier never
turns caller-supplied trust flags or receipts into a completeness attestation.
It emits identifiers and statuses, never the compared content or exceptions.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, TypeGuard

from .byte_resolver import ByteEvidenceResolver
from .synthetic_reconcile import SyntheticByteResolver

_OP_FIELDS = ("run_id", "source_id", "boundary", "operation_id", "attempt_id")
_OBJECT_FIELDS = (*_OP_FIELDS, "role", "chunk_index")
_IDENTITY_FIELDS = (
    *_OP_FIELDS,
    "tenant_id",
    "source_epoch",
    "source_sequence",
    "object_id",
    "role",
)


@dataclass(frozen=True, slots=True)
class CallByteWitness:
    """One independent observation; streamed data uses one witness per chunk."""

    run_id: str
    source_id: str
    boundary: str
    operation_id: str
    attempt_id: str
    role: str
    data: bytes
    chunk_index: int | None = None
    witness_source: str = "fixture"


@dataclass(frozen=True, slots=True)
class CallOperationWitness:
    """An observed physical attempt and its independently checked outcome."""

    run_id: str
    source_id: str
    boundary: str
    operation_id: str
    attempt_id: str
    outcome: dict[str, Any]
    witness_source: str = "fixture"


@dataclass(frozen=True, slots=True)
class RouteDeclaration:
    """Operator inventory, not proof that unlisted routes are inaccessible."""

    route_id: str
    version: str
    boundary: str
    reachable: bool = True
    observed: bool = True


def _key(record: dict[str, Any], fields: tuple[str, ...]) -> tuple[Any, ...]:
    return tuple(record.get(field) for field in fields)


def _witness_key(witness: Any, fields: tuple[str, ...]) -> tuple[Any, ...]:
    return tuple(getattr(witness, field) for field in fields)


def _identity(key: tuple[Any, ...], fields: tuple[str, ...]) -> dict[str, Any]:
    return dict(zip(fields, key, strict=True))


def _valid_counter(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _check_source_journal(
    snapshot: dict[str, Any],
    records: list[dict[str, Any]],
    issues: list[dict[str, Any]],
) -> None:
    if snapshot.get("source_spool_recovered_gaps"):
        issues.append({"kind": "source_spool_recovered_gap"})
    if snapshot.get("source_epoch_persisted") is not True:
        return
    health = snapshot.get("source_spool_health", {})
    if not isinstance(health, dict):
        issues.append({"kind": "source_spool_health_invalid"})
        health = {}
    for field in ("failed", "dropped", "pending"):
        value = health.get(field)
        if not _valid_counter(value) or value != 0:
            issues.append({"kind": "source_spool_health_gap", "stage": field})
    if snapshot.get("source_spool_settled") is not True:
        issues.append({"kind": "source_spool_not_settled"})
    for record in records:
        if record.get("source_spool_status") != "spooled":
            issues.append(
                {"kind": "source_spool_record_unpersisted", "record_id": record.get("record_id")}
            )
    recovered = snapshot.get("recovered_records", [])
    if not isinstance(recovered, list) or any(
        not isinstance(record, dict)
        or ("object_id" in record and record.get("recovery_resolution") != "available")
        for record in recovered
    ):
        issues.append({"kind": "recovered_records_unresolved"})


def _check_sequences(
    snapshot: dict[str, Any], records: list[dict[str, Any]], issues: list[dict[str, Any]]
) -> None:
    by_source: dict[str, list[int]] = defaultdict(list)
    record_ids: Counter[str] = Counter()
    for record in records:
        source, sequence = record.get("source_id"), record.get("source_sequence")
        if not isinstance(source, str) or not _valid_counter(sequence):
            issues.append({"kind": "invalid_source_sequence"})
            continue
        by_source[source].append(sequence)
        record_id = record.get("record_id")
        if isinstance(record_id, str):
            record_ids[record_id] += 1
        else:
            issues.append({"kind": "missing_record_identity", "source_id": source})
        if record.get("source_epoch") != snapshot.get("source_epoch"):
            issues.append({"kind": "source_epoch_mismatch", "source_id": source})
        if record.get("run_id") != snapshot["run_id"]:
            issues.append({"kind": "record_run_mismatch", "source_id": source})
        if record.get("tenant_id") != snapshot["tenant_id"]:
            issues.append({"kind": "record_tenant_mismatch", "source_id": source})
    for record_id, count in record_ids.items():
        if count > 1:
            issues.append({"kind": "duplicate_record", "record_id": record_id})
    water = snapshot.get("source_high_water", {})
    if not isinstance(water, dict):
        issues.append({"kind": "source_high_water_invalid"})
        water = {}
    for source in sorted(set(by_source) | set(water)):
        sequences = sorted(by_source.get(source, []))
        high_water = water.get(source)
        if (
            not sequences
            or not _valid_counter(high_water)
            or high_water != sequences[-1]
            or sequences != list(range(len(sequences)))
        ):
            issues.append({"kind": "source_sequence_gap_or_duplicate", "source_id": source})


def _check_calls(  # noqa: PLR0912 - explicit lifecycle, stream and graph checks
    calls: list[dict[str, Any]],
    operations: list[dict[str, Any]],
    events: list[dict[str, Any]],
    issues: list[dict[str, Any]],
) -> None:
    ids = Counter(call.get("call_id") for call in calls)
    for call in calls:
        call_id = call.get("call_id")
        details = {"call_id": call_id, "operation_id": call.get("operation_id")}
        if not isinstance(call_id, str) or ids[call_id] != 1:
            issues.append({"kind": "call_identity_invalid_or_duplicate", **details})
        parent = call.get("parent_call_id")
        if parent is not None and (parent not in ids or parent == call_id):
            issues.append({"kind": "call_parent_missing_or_invalid", **details})
        outcomes = [item for item in operations if item.get("call_id") == call_id]
        if len(outcomes) != 1:
            issues.append({"kind": "call_outcome_missing_or_duplicate", **details})
        elif (
            outcomes[0].get("outcome", {}).get("result_status") != call.get("status")
            # A partial stream deliberately uses a deferred operation outcome.
            and not (
                call.get("status") == "partial"
                and outcomes[0].get("outcome", {}).get("result_status") == "deferred"
            )
        ):
            issues.append({"kind": "call_outcome_status_mismatch", **details})
        if call.get("status") not in {"ok", "error", "cancelled"}:
            issues.append({"kind": "incomplete_call", **details})
        if call.get("streaming"):
            chunks = [
                event.get("descriptor", {}).get("chunk_index")
                for event in sorted(events, key=lambda item: item.get("source_sequence", -1))
                if event.get("call_id") == call_id
                and event.get("descriptor", {}).get("chunk_index") is not None
            ]
            count = call.get("chunk_count")
            if not _valid_counter(count) or chunks != list(range(count)):
                issues.append({"kind": "stream_chunk_gap_or_duplicate", **details})
            if call.get("status") != "ok":
                issues.append({"kind": "partial_stream", **details})
    for record in [*events, *operations]:
        if record.get("call_id") not in ids:
            issues.append({"kind": "record_call_missing", "record_id": record.get("record_id")})
            continue
        lifecycle = next(call for call in calls if call.get("call_id") == record.get("call_id"))
        for field in ("operation_id", "attempt_id", "parent_call_id", "agent_id"):
            if record.get(field) != lifecycle.get(field):
                issues.append(
                    {
                        "kind": "record_call_identity_mismatch",
                        "field": field,
                        "record_id": record.get("record_id"),
                        "call_id": record.get("call_id"),
                    }
                )
    parents = {call.get("call_id"): call.get("parent_call_id") for call in calls}
    for call_id in parents:
        seen: set[str] = set()
        current = call_id
        while isinstance(current, str) and current in parents:
            if current in seen:
                issues.append({"kind": "call_parent_cycle", "call_id": call_id})
                break
            seen.add(current)
            current = parents[current]


def _check_objects(  # noqa: PLR0912 - distinct evidence failure states
    events: list[dict[str, Any]],
    expected: list[CallByteWitness],
    resolver: SyntheticByteResolver | ByteEvidenceResolver,
    issues: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    observed: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    objects: Counter[str] = Counter()
    withheld: list[dict[str, Any]] = []
    for event in events:
        descriptor = event.get("descriptor", {})
        key = _key({**event, "chunk_index": descriptor.get("chunk_index")}, _OBJECT_FIELDS)
        observed[key].append(event)
        if descriptor:
            for field in _IDENTITY_FIELDS:
                if descriptor.get(field) != event.get(field):
                    issues.append(
                        {
                            "kind": "descriptor_identity_mismatch",
                            "field": field,
                            **_identity(key, _OBJECT_FIELDS),
                        }
                    )
            objects[descriptor.get("object_id")] += 1
        if event.get("status") != "stored":
            row = {**_identity(key, _OBJECT_FIELDS), "status": event.get("status", "absent")}
            withheld.append(row)
            issues.append({"kind": "incomplete_required_content", **row})
    for object_id, count in objects.items():
        if count > 1:
            issues.append({"kind": "duplicate_content_object", "object_id": object_id})
    expected_keys: Counter[tuple[Any, ...]] = Counter()
    for witness in expected:
        if not isinstance(witness.data, bytes):
            raise TypeError("witness data must be bytes")
        key = _witness_key(witness, _OBJECT_FIELDS)
        expected_keys[key] += 1
        matches = observed.get(key, [])
        details = _identity(key, _OBJECT_FIELDS)
        if not matches:
            issues.append({"kind": "missing_required_object", **details})
        elif len(matches) != 1:
            issues.append({"kind": "duplicate_observed_object", **details})
        for event in matches:
            descriptor = event.get("descriptor")
            if not isinstance(descriptor, dict):
                issues.append({"kind": "missing_descriptor", **details})
                continue
            result = resolver.resolve(descriptor)
            if result.status != "available" or result.data is None:
                issues.append({"kind": "unresolved_object", "resolution": result.status, **details})
            elif descriptor.get("representation") != "exact":
                issues.append({"kind": "original_content_unavailable", **details})
            elif result.data != witness.data:
                issues.append({"kind": "byte_mismatch", **details})
    for key, count in expected_keys.items():
        if count > 1:
            issues.append({"kind": "duplicate_witness_object", **_identity(key, _OBJECT_FIELDS)})
    for key in observed.keys() - expected_keys.keys():
        issues.append({"kind": "unexpected_object", **_identity(key, _OBJECT_FIELDS)})
    return withheld


def _review_copies(  # noqa: PLR0912 - separate provenance, availability and integrity checks
    events: list[dict[str, Any]],
    issues: list[dict[str, Any]],
    resolver: ByteEvidenceResolver | None,
) -> list[dict[str, Any]]:
    """Verify review integrity separately; it never replaces original evidence."""
    rows = []
    for event in events:
        copies = event.get("derivatives", [])
        if not isinstance(copies, list):
            issues.append({"kind": "review_copy_list_invalid", "record_id": event.get("record_id")})
            continue
        if (
            event.get("descriptor", {}).get("privacy_mode") == "original_plus_masked"
            and len(copies) != 1
        ):
            issues.append(
                {
                    "kind": "required_review_copy_missing_or_duplicate",
                    "record_id": event.get("record_id"),
                }
            )
        masked_only = event.get("descriptor", {}).get("privacy_mode") == "masked_only"
        candidates = [event["descriptor"]] if masked_only else copies
        for copy in candidates:
            if not isinstance(copy, dict):
                issues.append({"kind": "review_copy_invalid", "record_id": event.get("record_id")})
                continue
            row = {
                "record_id": event.get("record_id"),
                "object_id": copy.get("object_id"),
                "role": event.get("role"),
                "operation_id": event.get("operation_id"),
                "attempt_id": event.get("attempt_id"),
                "status": copy.get("status", "absent"),
                "resolution": "unverified",
                "representation": copy.get("representation"),
                "reason": "separate_review_store_resolution_required",
                "integrity": "unverified",
                "source_trust": "unverified",
                "storage_report": "masked_stored"
                if copy.get("status") == "redacted"
                else "withheld",
            }
            rows.append(row)
            if copy.get("status") != "redacted":
                issues.append({"kind": "required_review_copy_unavailable", **row})
            if not masked_only:
                link = {"relation": "derived_from", "object_id": event.get("object_id")}
                if copy.get("links") != [link]:
                    issues.append({"kind": "review_copy_original_link_mismatch", **row})
            if any(
                copy.get(field) != event.get(field) for field in (*_OP_FIELDS, "role", "tenant_id")
            ):
                issues.append({"kind": "review_copy_identity_mismatch", **row})
            if resolver is not None:
                result = resolver.resolve(copy)
                row.update(resolution=result.status, reason=result.reason)
                if result.status == "available" and result.representation == "redacted":
                    row["integrity"] = "verified"
                else:
                    issues.append({"kind": "required_review_copy_unresolved", **row})
    object_ids = Counter(row.get("object_id") for row in rows)
    for object_id, count in object_ids.items():
        if count != 1:
            issues.append({"kind": "duplicate_review_object", "object_id": object_id})
    return rows


def _check_operations(
    operations: list[dict[str, Any]],
    expected: list[CallOperationWitness],
    issues: list[dict[str, Any]],
) -> None:
    observed: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for operation in operations:
        key = _key(operation, _OP_FIELDS)
        observed[key].append(operation)
        if operation.get("outcome", {}).get("result_status") not in {"ok", "error", "cancelled"}:
            issues.append({"kind": "incomplete_operation_outcome", **_identity(key, _OP_FIELDS)})
    keys: Counter[tuple[Any, ...]] = Counter()
    for witness in expected:
        key = _witness_key(witness, _OP_FIELDS)
        keys[key] += 1
        matches = observed.get(key, [])
        details = _identity(key, _OP_FIELDS)
        if not matches:
            issues.append({"kind": "missing_operation_outcome", **details})
        elif len(matches) != 1:
            issues.append({"kind": "duplicate_operation_outcome", **details})
        if not witness.outcome or "result_status" not in witness.outcome:
            issues.append({"kind": "witness_outcome_incomplete", **details})
        for match in matches:
            if match.get("outcome") != witness.outcome:
                issues.append({"kind": "operation_outcome_mismatch", **details})
    for key, count in keys.items():
        if count > 1:
            issues.append({"kind": "duplicate_witness_outcome", **_identity(key, _OP_FIELDS)})
    for key in observed.keys() - keys.keys():
        issues.append({"kind": "unexpected_operation_outcome", **_identity(key, _OP_FIELDS)})


def reconcile_call_run(  # noqa: PLR0912 - explicit qualification checks
    snapshot: dict[str, Any],
    expected: list[CallByteWitness],
    resolver: SyntheticByteResolver | ByteEvidenceResolver,
    *,
    expected_operations: list[CallOperationWitness],
    routes: list[RouteDeclaration],
    review_resolver: ByteEvidenceResolver | None = None,
) -> dict[str, Any]:
    """Compare each object/attempt; matching local records remain unverified.

    Construct witnesses from separate observations, never by copying the
    recorder snapshot. An inventory cannot detect arbitrary invisible calls;
    its declarations require independent closure testing at deployment time.
    This function performs no writes, database queries or network requests.
    """
    if (
        snapshot.get("schema_version") != "fabric.call-recording/v1"
        or snapshot.get("tenant_id") != resolver.tenant_id
        or not isinstance(snapshot.get("run_id"), str)
        or any(
            not isinstance(snapshot.get(field), list) for field in ("events", "operations", "calls")
        )
    ):
        raise ValueError("invalid call snapshot schema, tenant or records")
    events, operations, calls = (snapshot[field] for field in ("events", "operations", "calls"))
    starts = snapshot.get("starts", [])
    if not isinstance(starts, list) or any(
        not isinstance(item, dict) for item in [*events, *operations, *calls, *starts]
    ):
        raise ValueError("snapshot records must be mappings")
    if review_resolver is not None:
        if review_resolver.view != "review" or review_resolver.tenant_id != resolver.tenant_id:
            raise ValueError("review resolver requires the matching tenant and review view")
        if any(
            event.get("descriptor", {}).get("privacy_mode") == "original_plus_masked"
            for event in events
        ):
            original = (
                resolver
                if isinstance(resolver, ByteEvidenceResolver)
                else ByteEvidenceResolver(
                    resolver.store,
                    tenant_id=resolver.tenant_id,
                )
            )
            original.authorize_separate_review(review_resolver)
    issues: list[dict[str, Any]] = []
    for field in ("recording_gaps", "unretained_drops"):
        value = snapshot.get(field)
        if not _valid_counter(value) or value != 0:
            issues.append({"kind": field})
    if snapshot.get("writer_settled") is not True:
        issues.append({"kind": "writer_not_settled"})
    if not calls or not expected_operations:
        issues.append({"kind": "no_independently_witnessed_calls"})
    records = [*starts, *events, *operations]
    _check_source_journal(snapshot, records, issues)
    _check_sequences(snapshot, records, issues)
    _check_calls(calls, operations, [*starts, *events], issues)
    if "starts" in snapshot:
        counts = Counter(record.get("call_id") for record in starts)
        for call in calls:
            if counts[call.get("call_id")] != 1:
                issues.append(
                    {"kind": "call_start_missing_or_duplicate", "call_id": call.get("call_id")}
                )
    withheld = _check_objects(events, expected, resolver, issues)
    review_copies = _review_copies(events, issues, review_resolver)
    _check_operations(operations, expected_operations, issues)
    witnesses: list[CallByteWitness | CallOperationWitness] = [*expected, *expected_operations]
    for witness in witnesses:
        if witness.run_id != snapshot["run_id"]:
            issues.append({"kind": "witness_run_mismatch", "operation_id": witness.operation_id})
    if not routes:
        issues.append({"kind": "route_inventory_missing"})
    route_ids = Counter(route.route_id for route in routes)
    route_rows = []
    for route in routes:
        if not route.version or route_ids[route.route_id] != 1:
            issues.append(
                {"kind": "route_version_missing_or_duplicate", "route_id": route.route_id}
            )
        if route.reachable and not route.observed:
            issues.append({"kind": "reachable_unobserved_route", "route_id": route.route_id})
        route_rows.append(
            {
                "route_id": route.route_id,
                "version": route.version,
                "boundary": route.boundary,
                "reachable": route.reachable,
                "observed": route.observed,
                "closure_proof": "unavailable",
                "operation_ids": sorted(
                    {
                        item["operation_id"]
                        for item in operations
                        if item.get("boundary") == route.boundary
                    }
                ),
            }
        )
    declared = {route.boundary for route in routes if route.reachable and route.observed}
    for record in [*events, *operations]:
        if record.get("boundary") not in declared:
            issues.append(
                {"kind": "undeclared_observed_boundary", "boundary": record.get("boundary")}
            )
    sort_key = lambda row: json.dumps(row, sort_keys=True, separators=(",", ":"))  # noqa: E731
    return {
        "schema_version": "fabric.call-reconciliation/v1",
        "run_id": snapshot["run_id"],
        "tenant_id": snapshot["tenant_id"],
        "verdict": "partial" if issues else "unverified",
        "complete_verdict_available": False,
        "discrepancies": sorted(issues, key=sort_key),
        "withheld_content": sorted(withheld, key=sort_key),
        "review_copies": sorted(review_copies, key=sort_key),
        "route_inventory": {
            "schema_version": "fabric.route-inventory/v1",
            "routes": sorted(route_rows, key=sort_key),
        },
        "receipt_stages": {
            stage: {
                "status": "unavailable",
                "reason": "trusted_receipt_verification_not_implemented",
            }
            for stage in (
                "source_persistence",
                "node_acceptance",
                "destination_acceptance",
                "destination_durable_readback",
            )
        },
        "proofs_missing": [
            "authenticated_source_identity",
            "persisted_source_continuity",
            "independent_feed_authentication",
            "route_closure",
            "trusted_stage_receipts",
        ],
        "witness_sources": sorted({item.witness_source for item in witnesses}),
    }
