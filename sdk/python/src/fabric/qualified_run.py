# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Optional offline exact-evidence verification for one declared source epoch.

Issuer authentication is not issuer qualification or deployment approval.
Private keys, route controls and evidence production remain outside Fabric.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .byte_resolver import ByteEvidenceResolver, ByteResolution
from .call_otlp import project_call_snapshot
from .call_reconcile import (
    CallByteWitness,
    CallOperationWitness,
    RouteDeclaration,
    reconcile_call_run,
)
from .evidence_attestation import (
    EvidenceExpectation,
    EvidenceTrustKey,
    verify_evidence_attestation,
)
from .independent_feed import (
    IndependentFeedByteResolver,
    IndependentFeedExpectation,
    verify_independent_feed,
)
from .receipt_sets import (
    EvidenceSetEntry,
    ReceiptSetExpectation,
    metadata_entries,
    verify_receipt_set,
)
from .source_spool import SyntheticSourceSpool

_STAGES = ("source_spooled", "node_accepted", "destination_accepted", "destination_durable")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_ROWS = 4096
_MAX_TOTAL = 64 << 20
_MAX_OBJECT = 16 << 20
_MAX_SNAPSHOT_DEPTH = 12
_MAX_MAPPING_FIELDS = 256
_PAIR_SIZE = 2


@dataclass(frozen=True, slots=True)
class QualifiedFeedInput:
    manifest_bytes: bytes | None
    attestation_bytes: bytes | None
    expectation: IndependentFeedExpectation
    byte_resolver: IndependentFeedByteResolver


@dataclass(frozen=True, slots=True)
class QualifiedRunExpectation:
    tenant_id: str
    run_id: str
    scope_sha256: str
    source_id: str
    source_epoch: int
    routes: tuple[RouteDeclaration, ...]
    feeds: tuple[IndependentFeedExpectation, ...]
    source_issuer_id: str
    closure_issuer_id: str
    closure_set_id: str
    stage_issuers: tuple[tuple[str, str], ...]
    stage_set_ids: tuple[tuple[str, str], ...]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def source_binding_subject_bytes(expectation: QualifiedRunExpectation) -> bytes:
    """Canonical subject for an externally issued source-binding statement."""
    return _canonical(
        {
            "tenant_id": expectation.tenant_id,
            "run_id": expectation.run_id,
            "source_id": expectation.source_id,
            "source_epoch": expectation.source_epoch,
        }
    )


def route_closure_subject_bytes(expectation: QualifiedRunExpectation) -> bytes:
    """Bind the exact approved route inventory; do not install route controls."""
    return _canonical(
        {
            "tenant_id": expectation.tenant_id,
            "run_id": expectation.run_id,
            "scope_sha256": expectation.scope_sha256,
            "source_id": expectation.source_id,
            "source_epoch": expectation.source_epoch,
            "routes": [
                {
                    "route_id": route.route_id,
                    "version": route.version,
                    "boundary": route.boundary,
                    "reachable": route.reachable,
                    "observed": route.observed,
                }
                for route in sorted(expectation.routes, key=lambda item: item.route_id)
            ],
        }
    )


def _identifier(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _bounded_snapshot(value: object) -> None:
    """Limit input traversal before copying/serializing caller-owned values."""
    budget = [100000, 1 << 20]

    def visit(item: object, depth: int) -> None:
        budget[0] -= 1
        if budget[0] < 0 or depth > _MAX_SNAPSHOT_DEPTH:
            raise ValueError("snapshot_bounds_invalid")
        if isinstance(item, str):
            budget[1] -= len(item)
            if budget[1] < 0:
                raise ValueError("snapshot_bounds_invalid")
        elif isinstance(item, dict):
            if len(item) > _MAX_MAPPING_FIELDS:
                raise ValueError("snapshot_bounds_invalid")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("snapshot_bounds_invalid")
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > _MAX_ROWS:
                raise ValueError("snapshot_bounds_invalid")
            for child in item:
                visit(child, depth + 1)
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise ValueError("snapshot_bounds_invalid")

    visit(value, 0)


def _valid_expectation(value: QualifiedRunExpectation) -> bool:  # noqa: PLR0911
    if not isinstance(value, QualifiedRunExpectation):
        return False
    if (
        not all(
            _identifier(getattr(value, field))
            for field in (
                "tenant_id",
                "run_id",
                "source_id",
                "source_issuer_id",
                "closure_issuer_id",
                "closure_set_id",
            )
        )
        or not isinstance(value.scope_sha256, str)
        or not _SHA.fullmatch(value.scope_sha256)
    ):
        return False
    # This first verifier must never hide a previous or additional epoch.
    if type(value.source_epoch) is not int or value.source_epoch != 0:
        return False
    if (
        not isinstance(value.routes, tuple)
        or not 0 < len(value.routes) <= _MAX_ROWS
        or not isinstance(value.feeds, tuple)
        or not 0 < len(value.feeds) <= _MAX_ROWS
    ):
        return False
    if any(
        not isinstance(route, RouteDeclaration)
        or not all(_identifier(item) for item in (route.route_id, route.version, route.boundary))
        or type(route.reachable) is not bool
        or type(route.observed) is not bool
        for route in value.routes
    ) or len({route.route_id for route in value.routes}) != len(value.routes):
        return False
    routes = {route.route_id: route for route in value.routes}
    covered = set()
    for feed in value.feeds:
        if not isinstance(feed, IndependentFeedExpectation) or not all(
            _identifier(item) for item in (feed.feed_id, feed.route_id)
        ):
            return False
        route = routes.get(feed.route_id)
        if (
            route is None
            or not route.reachable
            or not route.observed
            or (feed.route_version, feed.boundary) != (route.version, route.boundary)
            or (feed.tenant_id, feed.run_id, feed.scope_sha256, feed.source_id, feed.source_epoch)
            != (
                value.tenant_id,
                value.run_id,
                value.scope_sha256,
                value.source_id,
                value.source_epoch,
            )
        ):
            return False
        covered.add(feed.route_id)
    if len({feed.feed_id for feed in value.feeds}) != len(value.feeds):
        return False
    if covered != {route.route_id for route in value.routes if route.reachable and route.observed}:
        return False
    for pairs in (value.stage_issuers, value.stage_set_ids):
        if (
            not isinstance(pairs, tuple)
            or len(pairs) != len(_STAGES)
            or any(not isinstance(pair, tuple) or len(pair) != _PAIR_SIZE for pair in pairs)
            or any(not isinstance(pair[0], str) for pair in pairs)
            or {pair[0] for pair in pairs} != set(_STAGES)
            or any(not _identifier(pair[1]) for pair in pairs)
        ):
            return False
    return True


class _FeedReadCache:
    """Reuse the exact first authenticated read, never resolve a second object."""

    def __init__(self, delegate: IndependentFeedByteResolver, budget: list[int]) -> None:
        self.delegate = delegate
        self.tenant_id = delegate.tenant_id
        self.issuer_id = delegate.issuer_id
        self.objects: dict[str, bytes] = {}
        self.budget = budget

    def resolve(self, byte_object_id: str, max_bytes: int) -> bytes:
        if byte_object_id in self.objects:
            return self.objects[byte_object_id]
        data = self.delegate.resolve(byte_object_id, min(max_bytes, self.budget[0], _MAX_OBJECT))
        if not isinstance(data, bytes) or len(data) > min(max_bytes, self.budget[0], _MAX_OBJECT):
            raise ValueError("independent_byte_limit")
        self.budget[0] -= len(data)
        self.objects[byte_object_id] = data
        return data


class _OriginalReadCache(ByteEvidenceResolver):
    def __init__(self, delegate: ByteEvidenceResolver) -> None:
        super().__init__(delegate.store, tenant_id=delegate.tenant_id, view=delegate.view)
        self.delegate = delegate
        self.objects: dict[bytes, ByteResolution] = {}

    def resolve(self, descriptor: dict[str, Any]) -> ByteResolution:
        key = _canonical(descriptor)
        if key not in self.objects:
            self.objects[key] = self.delegate.resolve(descriptor)
        return self.objects[key]


def _source_records(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    records = [*snapshot["starts"], *snapshot["events"], *snapshot["operations"]]
    if len(records) > _MAX_ROWS or any(not isinstance(row, dict) for row in records):
        raise ValueError("snapshot_records_invalid")
    return records


def _read_source(
    snapshot: dict[str, Any],
    expectation: QualifiedRunExpectation,
    source_spool: SyntheticSourceSpool,
) -> dict[str, Any]:
    if not isinstance(source_spool, SyntheticSourceSpool):
        raise ValueError("source_readback_unavailable")
    readback = source_spool.readback_sealed_epoch(expectation.source_epoch)
    seal, records = readback["seal"], readback["records"]
    snapshot_records = _source_records(snapshot)
    indexed = {row["record_id"]: row for row in snapshot_records}
    if len(indexed) != len(snapshot_records) or len(records) != len(indexed):
        raise ValueError("source_record_set_mismatch")
    for row in records:
        current = indexed.get(row["record_id"])
        if current is None:
            raise ValueError("source_record_set_mismatch")
        for key, value in row.items():
            if "object_id" in row and key in {"status", "status_reason"}:
                if (
                    row.get("status") not in {"pending", "stored"}
                    or current.get("status") != "stored"
                ):
                    raise ValueError("source_content_state_mismatch")
                continue
            if key not in current or current[key] != value:
                raise ValueError("source_record_mismatch")
    if (
        seal.get("tenant_id") != expectation.tenant_id
        or seal.get("run_id") != expectation.run_id
        or seal.get("source_epoch") != expectation.source_epoch
        or seal.get("source_high_water") != snapshot.get("source_high_water")
        or seal.get("record_count") != len(records)
        or set(seal.get("source_high_water", {})) != {expectation.source_id}
        or snapshot.get("source_metadata_seal") != seal
    ):
        raise ValueError("source_seal_mismatch")
    return readback


def _receipt_expectations(
    snapshot: dict[str, Any],
    expectation: QualifiedRunExpectation,
    resolver: ByteEvidenceResolver,
    readback: dict[str, Any],
) -> dict[str, ReceiptSetExpectation]:
    contents: list[EvidenceSetEntry] = []
    used = 0
    for event in snapshot["events"]:
        descriptor = event["descriptor"]
        result = resolver.resolve(descriptor)
        if result.status != "available" or not isinstance(result.data, bytes):
            raise ValueError("content_readback_unavailable")
        data = result.data
        digest = _sha(data)
        if (
            descriptor.get("representation") != "exact"
            or descriptor.get("source_byte_length") != len(data)
            or descriptor.get("stored_byte_length") != len(data)
            or descriptor.get("source_sha256") != digest
            or descriptor.get("stored_sha256") != digest
        ):
            raise ValueError("content_readback_mismatch")
        used += len(data)
        if used > _MAX_TOTAL:
            raise ValueError("aggregate_byte_limit")
        contents.append(
            EvidenceSetEntry("content_object", descriptor["object_id"], digest, len(data))
        )
    source = [
        EvidenceSetEntry(
            "source_record", row["record_id"], _sha(_canonical(row)), len(_canonical(row))
        )
        for row in readback["records"]
    ]
    seal_bytes = _canonical(readback["seal"])
    source.append(
        EvidenceSetEntry("source_seal", expectation.source_id, _sha(seal_bytes), len(seal_bytes))
    )
    metadata = metadata_entries(project_call_snapshot(snapshot)[0])
    issuers, ids = dict(expectation.stage_issuers), dict(expectation.stage_set_ids)
    sets = {
        "source_spooled": (*source, *contents),
        "node_accepted": metadata,
        "destination_accepted": metadata,
        "destination_durable": (*metadata, *contents),
    }
    return {
        stage: ReceiptSetExpectation(
            stage,
            expectation.tenant_id,
            expectation.run_id,
            expectation.scope_sha256,
            ids[stage],
            issuers[stage],
            tuple(entries),
        )
        for stage, entries in sets.items()
    }


def qualified_receipt_expectations(
    snapshot: dict[str, Any],
    *,
    expectation: QualifiedRunExpectation,
    resolver: ByteEvidenceResolver,
    source_spool: SyntheticSourceSpool,
) -> dict[str, ReceiptSetExpectation]:
    """Read actual evidence to prepare expected sets, not to issue receipts.

    Each external issuer must independently witness its own stage before
    signing these sets. Calling this helper never authenticates any stage.
    """
    if not _valid_expectation(expectation):
        raise ValueError("expectation_invalid")
    return _receipt_expectations(
        snapshot, expectation, resolver, _read_source(snapshot, expectation, source_spool)
    )


def _proof(
    document: bytes | None,
    *,
    expectation: QualifiedRunExpectation,
    kind: str,
    trusted_keys: Mapping[str, EvidenceTrustKey],
    verification_time: int,
) -> tuple[str, str]:
    if document is None:
        return "unverified", "proof_unavailable"
    source = kind == "source_binding"
    result = verify_evidence_attestation(
        document,
        expected=EvidenceExpectation(
            kind,
            expectation.tenant_id,
            expectation.run_id,
            expectation.scope_sha256,
            "source" if source else "evidence_set",
            expectation.source_id if source else expectation.closure_set_id,
            _sha(
                source_binding_subject_bytes(expectation)
                if source
                else route_closure_subject_bytes(expectation)
            ),
            expectation.source_issuer_id if source else expectation.closure_issuer_id,
        ),
        trusted_keys=trusted_keys,
        verification_time=verification_time,
    )
    if result.status == "verified":
        return "verified", result.reason
    unavailable = result.reason in {"unknown_key", "verification_dependency_unavailable"}
    return ("unverified" if unavailable else "invalid"), result.reason


def verify_qualified_call_run(  # noqa: PLR0912, PLR0915 - explicit proof gates
    snapshot: dict[str, Any],
    *,
    expectation: QualifiedRunExpectation,
    feeds: tuple[QualifiedFeedInput, ...],
    resolver: ByteEvidenceResolver,
    source_spool: SyntheticSourceSpool | None,
    source_binding_attestation: bytes | None,
    route_closure_attestation: bytes | None,
    receipts: Mapping[str, tuple[bytes | None, bytes | None]],
    trusted_keys: Mapping[str, EvidenceTrustKey],
    verification_time: int,
) -> dict[str, Any]:
    """Verify raw bounded proofs without trusting reported status booleans."""
    reasons: set[str] = set()
    missing: set[str] = set()
    feed_results: list[dict[str, str]] = []
    stages: dict[str, dict[str, str]] = {}
    counts = {"operations": 0, "byte_objects": 0}

    def finish() -> dict[str, Any]:
        return {
            "schema_version": "fabric.qualified-call-run/v1",
            "verdict": "partial"
            if reasons
            else "unverified"
            if missing
            else "verified_complete_for_declared_scope",
            "reason_codes": sorted(reasons | missing),
            "feeds": feed_results,
            "receipt_stages": stages,
            "counts": counts,
        }

    if not _valid_expectation(expectation):
        reasons.add("expectation_invalid")
        return finish()
    try:
        _bounded_snapshot(snapshot)
        snapshot = json.loads(_canonical(snapshot))  # freeze caller-owned mutable inputs
        if len(_canonical(snapshot)) > 1 << 20:
            raise ValueError()
        records = _source_records(snapshot)
        if (
            snapshot.get("schema_version") != "fabric.call-recording/v1"
            or snapshot.get("tenant_id") != expectation.tenant_id
            or snapshot.get("run_id") != expectation.run_id
            or snapshot.get("source_epoch") != expectation.source_epoch
            or type(snapshot.get("source_epoch")) is not int
            or any(type(row.get("source_epoch")) is not int for row in records)
            or any(row.get("source_id") != expectation.source_id for row in records)
            or snapshot.get("recovery_history_unverified")
            or snapshot.get("recovered_records")
            or snapshot.get("source_unsealed_epoch_ranges")
            or not isinstance(resolver, ByteEvidenceResolver)
            or resolver.tenant_id != expectation.tenant_id
            or resolver.view != "original"
            or not 0 < resolver.max_object_bytes <= _MAX_OBJECT
        ):
            raise ValueError()
    except Exception:
        reasons.add("snapshot_identity_or_bounds_invalid")
        return finish()
    # A missing witness cannot hide a known recorder failure.
    health = snapshot.get("source_spool_health", {})
    if (
        snapshot.get("recording_gaps") != 0
        or snapshot.get("unretained_drops") != 0
        or snapshot.get("writer_settled") is not True
        or snapshot.get("source_spool_settled") is not True
        or not isinstance(health, dict)
        or any(
            type(health.get(key)) is not int or health[key] != 0
            for key in ("failed", "dropped", "pending")
        )
        or snapshot.get("recovered_gaps")
    ):
        reasons.add("known_recorder_loss_or_unsettled")
    if any(route.reachable and not route.observed for route in expectation.routes):
        reasons.add("reachable_unobserved_route")
    if not isinstance(feeds, tuple) or len(feeds) > _MAX_ROWS:
        reasons.add("feed_registry_invalid")
        return finish()
    registry = {feed.feed_id: feed for feed in expectation.feeds}
    supplied: set[str] = set()
    byte_witnesses: list[CallByteWitness] = []
    operation_witnesses: list[CallOperationWitness] = []
    attempts: set[tuple[str, str, str]] = set()
    aggregate = 0
    read_budget = [_MAX_TOTAL]
    materialized_rows = 0
    for feed in feeds:
        if (
            not isinstance(feed, QualifiedFeedInput)
            or not isinstance(feed.expectation, IndependentFeedExpectation)
            or not _identifier(feed.expectation.feed_id)
            or registry.get(feed.expectation.feed_id) != feed.expectation
            or feed.expectation.feed_id in supplied
        ):
            reasons.add("feed_registry_mismatch")
            continue
        supplied.add(feed.expectation.feed_id)
        try:
            cache = _FeedReadCache(feed.byte_resolver, read_budget)
            result = verify_independent_feed(
                feed.manifest_bytes,
                feed.attestation_bytes,
                expectation=feed.expectation,
                trusted_keys=trusted_keys,
                byte_resolver=cache,
                verification_time=verification_time,
            )
            feed_results.append(
                {
                    "feed_id": feed.expectation.feed_id,
                    "status": result.status,
                    "reason": result.reason,
                }
            )
            if result.status != "verified":
                (missing if result.status == "unverified" else reasons).add(
                    "independent_feed_" + result.status
                )
                continue
            doc = json.loads(feed.manifest_bytes or b"")
            materialized_rows += len(doc["records"])
            if materialized_rows > _MAX_ROWS:
                raise ValueError()
            for row in doc["records"]:
                common = (
                    expectation.run_id,
                    expectation.source_id,
                    feed.expectation.boundary,
                    row["operation_id"],
                    row["attempt_id"],
                )
                if row["kind"] == "operation":
                    key = common[2:]
                    if key in attempts:
                        reasons.add("duplicate_feed_attempt")
                    attempts.add(key)
                    operation_witnesses.append(
                        CallOperationWitness(*common, row["outcome"], feed.expectation.feed_id)
                    )
                else:
                    data = cache.objects[row["byte_object_id"]]
                    if len(data) != row["byte_length"] or _sha(data) != row["sha256"]:
                        raise ValueError()
                    aggregate += len(data)
                    if aggregate > _MAX_TOTAL:
                        raise ValueError()
                    byte_witnesses.append(
                        CallByteWitness(
                            *common, row["role"], data, row["chunk_index"], feed.expectation.feed_id
                        )
                    )
        except Exception:
            reasons.add("independent_feed_materialization_failed")
    if supplied != set(registry):
        missing.add("independent_feed_unavailable")
    counts.update(operations=len(operation_witnesses), byte_objects=len(byte_witnesses))
    original_cache = _OriginalReadCache(resolver)
    # Do not classify a missing native feed as a known missing captured object.
    if not missing.intersection({"independent_feed_unavailable", "independent_feed_unverified"}):
        try:
            compared = reconcile_call_run(
                snapshot,
                byte_witnesses,
                original_cache,
                expected_operations=operation_witnesses,
                routes=list(expectation.routes),
            )
            if compared["discrepancies"]:
                reasons.add("reconstruction_discrepancy")
        except Exception:
            reasons.add("reconstruction_invalid")
    for kind, document in (
        ("source_binding", source_binding_attestation),
        ("route_closure", route_closure_attestation),
    ):
        try:
            status, _reason = _proof(
                document,
                expectation=expectation,
                kind=kind,
                trusted_keys=trusted_keys,
                verification_time=verification_time,
            )
            if status != "verified":
                (missing if status == "unverified" else reasons).add(kind + "_" + status)
        except Exception:
            reasons.add(kind + "_invalid")
    expected_sets: dict[str, ReceiptSetExpectation] = {}
    if source_spool is None:
        missing.add("source_readback_unavailable")
    else:
        try:
            readback = _read_source(snapshot, expectation, source_spool)
            expected_sets = _receipt_expectations(snapshot, expectation, original_cache, readback)
        except Exception:
            reasons.add("source_or_content_readback_failed")
    if not isinstance(receipts, Mapping):
        reasons.add("receipt_registry_invalid")
        return finish()
    if set(receipts) - set(_STAGES):
        reasons.add("unexpected_receipt_stage")
    for stage in _STAGES:
        if stage not in expected_sets:
            stages[stage] = {"status": "unverified", "reason": "readback_unavailable"}
            missing.add(stage + "_unverified")
            continue
        try:
            pair = receipts.get(stage, (None, None))
            result_receipt = verify_receipt_set(
                pair[0],
                pair[1],
                expectation=expected_sets[stage],
                trusted_keys=trusted_keys,
                verification_time=verification_time,
            )
            stages[stage] = {"status": result_receipt.status, "reason": result_receipt.reason}
            if result_receipt.status != "verified":
                (missing if result_receipt.status == "unverified" else reasons).add(
                    stage + "_" + result_receipt.status
                )
        except Exception:
            stages[stage] = {"status": "invalid", "reason": "receipt_invalid"}
            reasons.add(stage + "_invalid")
    return finish()
