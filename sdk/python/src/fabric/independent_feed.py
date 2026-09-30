# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Bounded offline check of an independently issued operation/byte feed.

This verifies one feed, not a complete Fabric run. The resolver and expected
native ledger are deployment-controlled inputs; their provenance is qualified
outside this module. No raw bytes or comparison witnesses leave the result.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .evidence_attestation import (
    EvidenceExpectation,
    EvidenceTrustKey,
    verify_evidence_attestation,
)

_MAX_DOCUMENT = 1 << 20
_MAX_ROWS = 4096
_MAX_OBJECT = 16 << 20
_MAX_TOTAL = 64 << 20
_MAX_DEPTH = 8
_MAX_CURSOR = (1 << 53) - 1
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_TOP = frozenset(
    {
        "schema_version",
        "feed_id",
        "tenant_id",
        "run_id",
        "scope_sha256",
        "route_id",
        "route_version",
        "source_id",
        "source_epoch",
        "boundary",
        "cursor_domain",
        "cursor_start",
        "cursor_end",
        "records",
    }
)
_COMMON = frozenset({"cursor", "kind", "operation_id", "attempt_id"})
_OP = _COMMON | {"outcome"}
_BYTE = _COMMON | {"role", "chunk_index", "byte_length", "sha256", "byte_object_id"}
_OUTCOME = frozenset(
    {
        "result_status",
        "http_status",
        "returncode",
        "signal_number",
        "timed_out",
        "artifact_present",
        "artifact_size",
        "artifact_phase",
        "artifact_path_sha256",
    }
)


@dataclass(frozen=True, slots=True)
class ExpectedRole:
    role: str
    chunk_count: int | None = None  # None means one nonstream object.


@dataclass(frozen=True, slots=True)
class ExpectedAttempt:
    operation_id: str
    attempt_id: str
    outcome: Mapping[str, object]
    roles: tuple[ExpectedRole, ...]


@dataclass(frozen=True, slots=True)
class IndependentFeedExpectation:
    feed_id: str
    tenant_id: str
    run_id: str
    scope_sha256: str
    route_id: str
    route_version: str
    source_id: str
    source_epoch: int
    boundary: str
    cursor_domain: str
    cursor_start: int
    cursor_end: int
    issuer_id: str
    attempts: tuple[ExpectedAttempt, ...]


class IndependentFeedByteResolver(Protocol):
    """Trusted, separately qualified tenant/issuer-bound byte store reader."""

    tenant_id: str
    issuer_id: str

    def resolve(self, byte_object_id: str, max_bytes: int) -> bytes: ...


@dataclass(frozen=True, slots=True)
class IndependentFeedVerification:
    status: str
    reason: str
    feed_sha256: str | None = None
    operation_count: int = 0
    byte_count: int = 0


def _result(
    status: str, reason: str, digest: str | None = None, ops: int = 0, data: int = 0
) -> IndependentFeedVerification:
    return IndependentFeedVerification(status, reason, digest, ops, data)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate field")
        out[key] = value
    return out


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _depth(value: object, level: int = 0) -> bool:
    if level > _MAX_DEPTH:
        return False
    if isinstance(value, dict):
        return all(_depth(child, level + 1) for child in value.values())
    if isinstance(value, list):
        return all(_depth(child, level + 1) for child in value)
    return True


def _id(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _integer(value: object, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _digest(value: object) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _outcome(value: object) -> bool:
    if not isinstance(value, dict) or not value or set(value) - _OUTCOME:
        return False
    if not isinstance(value.get("result_status"), str) or value["result_status"] not in {
        "ok",
        "error",
        "cancelled",
    }:
        return False
    checks = {
        "http_status": lambda item: _integer(item, 100, 599),
        "returncode": lambda item: _integer(item, -255, 255),
        "signal_number": lambda item: item is None or _integer(item, 1, 128),
        "timed_out": lambda item: isinstance(item, bool),
        "artifact_present": lambda item: isinstance(item, bool),
        "artifact_size": lambda item: _integer(item, 0, _MAX_OBJECT),
        "artifact_phase": lambda item: isinstance(item, str) and item in {"before", "after"},
        "artifact_path_sha256": lambda item: (
            isinstance(item, str) and _HEX.fullmatch(item) is not None
        ),
    }
    return all(checks[key](item) for key, item in value.items() if key != "result_status")


def _valid_expectation(expected: IndependentFeedExpectation) -> bool:  # noqa: PLR0911
    # Explicit early exits make each bounded trust-input validation auditable.
    if not isinstance(expected, IndependentFeedExpectation):
        return False
    if not all(
        _id(getattr(expected, key))
        for key in (
            "feed_id",
            "tenant_id",
            "run_id",
            "route_id",
            "route_version",
            "source_id",
            "boundary",
            "cursor_domain",
            "issuer_id",
        )
    ) or not _digest(expected.scope_sha256):
        return False
    if not _integer(expected.source_epoch, 0, _MAX_CURSOR) or not _integer(
        expected.cursor_start, 0, _MAX_CURSOR
    ):
        return False
    if not _integer(expected.cursor_end, expected.cursor_start - 1, _MAX_CURSOR):
        return False
    if (
        not isinstance(expected.attempts, tuple)
        or expected.cursor_end - expected.cursor_start + 1 > _MAX_ROWS
        or len(expected.attempts) > _MAX_ROWS
    ):
        return False
    seen: set[tuple[str, str]] = set()
    expected_rows = 0
    for attempt in expected.attempts:
        if (
            not isinstance(attempt, ExpectedAttempt)
            or not _id(attempt.operation_id)
            or not _id(attempt.attempt_id)
            or not isinstance(attempt.outcome, Mapping)
            or not _outcome(dict(attempt.outcome))
        ):
            return False
        key = (attempt.operation_id, attempt.attempt_id)
        if key in seen or not isinstance(attempt.roles, tuple):
            return False
        seen.add(key)
        expected_rows += 1
        role_ids: set[str] = set()
        for role in attempt.roles:
            if not isinstance(role, ExpectedRole) or not _id(role.role) or role.role in role_ids:
                return False
            if role.chunk_count is not None and not _integer(role.chunk_count, 1, _MAX_ROWS):
                return False
            expected_rows += 1 if role.chunk_count is None else role.chunk_count
            if expected_rows > _MAX_ROWS:
                return False
            role_ids.add(role.role)
    return expected_rows == expected.cursor_end - expected.cursor_start + 1


def _valid_top(doc: object, expected: IndependentFeedExpectation) -> bool:
    if (
        not isinstance(doc, dict)
        or set(doc) != _TOP
        or doc["schema_version"] != "fabric.independent-feed/v1"
    ):
        return False
    for field in (
        "feed_id",
        "tenant_id",
        "run_id",
        "scope_sha256",
        "route_id",
        "route_version",
        "source_id",
        "source_epoch",
        "boundary",
        "cursor_domain",
    ):
        if doc[field] != getattr(expected, field):
            return False
    return (
        _integer(doc["source_epoch"], 0, _MAX_CURSOR)
        and isinstance(doc["records"], list)
        and len(doc["records"]) <= _MAX_ROWS
        and _integer(doc["cursor_start"], 0, _MAX_CURSOR)
        and _integer(doc["cursor_end"], doc["cursor_start"] - 1, _MAX_CURSOR)
    )


def _rows(  # noqa: PLR0911, PLR0912
    doc: dict[str, Any], expected: IndependentFeedExpectation
) -> tuple[str, str, list[dict[str, Any]], list[dict[str, Any]]]:
    # Keep distinct fixed rejection reasons for each feed-shape failure.
    if doc["cursor_start"] > expected.cursor_start or doc["cursor_end"] < expected.cursor_end:
        return "incomplete", "cursor_interval_missing", [], []
    if doc["cursor_start"] < expected.cursor_start or doc["cursor_end"] > expected.cursor_end:
        return "invalid", "cursor_interval_extra", [], []
    rows = doc["records"]
    if len(rows) < expected.cursor_end - expected.cursor_start + 1:
        return "incomplete", "cursor_row_missing", [], []
    if len(rows) > expected.cursor_end - expected.cursor_start + 1:
        return "invalid", "cursor_row_extra", [], []
    operations: list[dict[str, Any]] = []
    byte_rows: list[dict[str, Any]] = []
    object_ids: set[str] = set()
    for index, row in enumerate(rows):
        if (
            not isinstance(row, dict)
            or not _integer(
                row.get("cursor"), expected.cursor_start + index, expected.cursor_start + index
            )
            or not _id(row.get("operation_id"))
            or not _id(row.get("attempt_id"))
        ):
            return "invalid", "cursor_or_identity_invalid", [], []
        if row.get("kind") == "operation":
            if set(row) != _OP or not _outcome(row["outcome"]):
                return "invalid", "operation_invalid", [], []
            operations.append(row)
        elif row.get("kind") == "byte":
            if (
                set(row) != _BYTE
                or not _id(row["role"])
                or not _id(row["byte_object_id"])
                or not _digest(row["sha256"])
                or not _integer(row["byte_length"], 0, _MAX_OBJECT)
            ):
                return "invalid", "byte_row_invalid", [], []
            if row["chunk_index"] is not None and not _integer(
                row["chunk_index"], 0, _MAX_ROWS - 1
            ):
                return "invalid", "chunk_index_invalid", [], []
            if row["byte_object_id"] in object_ids:
                return "invalid", "duplicate_byte_object", [], []
            object_ids.add(row["byte_object_id"])
            byte_rows.append(row)
        else:
            return "invalid", "record_kind_invalid", [], []
    wanted_ops = {
        (item.operation_id, item.attempt_id): dict(item.outcome) for item in expected.attempts
    }
    actual_ops: dict[tuple[str, str], dict[str, Any]] = {}
    for row in operations:
        key = (row["operation_id"], row["attempt_id"])
        if key in actual_ops:
            return "invalid", "duplicate_attempt", [], []
        actual_ops[key] = row["outcome"]
    if actual_ops.keys() - wanted_ops.keys():
        return "invalid", "unexpected_attempt", [], []
    if wanted_ops.keys() - actual_ops.keys():
        return "incomplete", "attempt_missing", [], []
    if actual_ops != wanted_ops:
        return "invalid", "outcome_mismatch", [], []
    wanted_bytes: set[tuple[str, str, str, int | None]] = set()
    for attempt in expected.attempts:
        for role in attempt.roles:
            indices = (None,) if role.chunk_count is None else range(role.chunk_count)
            wanted_bytes.update(
                (attempt.operation_id, attempt.attempt_id, role.role, index) for index in indices
            )
    actual_bytes: set[tuple[str, str, str, int | None]] = set()
    chunk_order: dict[tuple[str, str, str], list[int | None]] = {}
    for row in byte_rows:
        byte_key = (row["operation_id"], row["attempt_id"], row["role"], row["chunk_index"])
        if byte_key in actual_bytes:
            return "invalid", "duplicate_byte_role", [], []
        actual_bytes.add(byte_key)
        chunk_order.setdefault(byte_key[:3], []).append(byte_key[3])
    if actual_bytes - wanted_bytes:
        return "invalid", "unexpected_byte_role", [], []
    if wanted_bytes - actual_bytes:
        return "incomplete", "required_byte_missing", [], []
    for attempt in expected.attempts:
        for role in attempt.roles:
            expected_order = [None] if role.chunk_count is None else list(range(role.chunk_count))
            if (
                chunk_order.get((attempt.operation_id, attempt.attempt_id, role.role))
                != expected_order
            ):
                return "invalid", "chunk_order_invalid", [], []
    return "verified", "shape_complete", operations, byte_rows


def verify_independent_feed(  # noqa: PLR0911, PLR0912
    manifest_bytes: bytes | None,
    attestation_bytes: bytes | None,
    *,
    expectation: IndependentFeedExpectation,
    trusted_keys: Mapping[str, EvidenceTrustKey],
    byte_resolver: IndependentFeedByteResolver,
    verification_time: int,
) -> IndependentFeedVerification:
    """Verify one offline feed; never promote a Fabric run verdict."""
    if not _valid_expectation(expectation):
        return _result("unverified", "expectation_unavailable")
    if manifest_bytes is None or attestation_bytes is None:
        return _result("unverified", "feed_or_attestation_unavailable")
    if (
        not isinstance(manifest_bytes, bytes)
        or not isinstance(attestation_bytes, bytes)
        or len(manifest_bytes) > _MAX_DOCUMENT
    ):
        return _result("invalid", "document_invalid")
    try:
        doc = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        if not _depth(doc) or _canonical(doc) != manifest_bytes:
            return _result("invalid", "document_noncanonical")
    except (ValueError, UnicodeError, TypeError, RecursionError):
        return _result("invalid", "document_invalid")
    if not _valid_top(doc, expectation):
        return _result("invalid", "manifest_identity_or_shape_invalid")
    digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    state, reason, operations, byte_rows = _rows(doc, expectation)
    if state != "verified":
        return _result(state, reason, digest)
    attested = verify_evidence_attestation(
        attestation_bytes,
        expected=EvidenceExpectation(
            statement_type="independent_witness",
            tenant_id=expectation.tenant_id,
            run_id=expectation.run_id,
            scope_sha256=expectation.scope_sha256,
            subject_kind="evidence_set",
            subject_id=expectation.feed_id,
            subject_sha256=digest,
            issuer_id=expectation.issuer_id,
        ),
        trusted_keys=trusted_keys,
        verification_time=verification_time,
    )
    if attested.status != "verified":
        state = (
            "unverified"
            if attested.reason in {"unknown_key", "verification_dependency_unavailable"}
            else "invalid"
        )
        return _result(state, "attestation_" + attested.reason, digest)
    try:
        resolver_tenant = byte_resolver.tenant_id
        resolver_issuer = byte_resolver.issuer_id
    except Exception:
        return _result("unverified", "resolver_unavailable", digest)
    if resolver_tenant != expectation.tenant_id or resolver_issuer != expectation.issuer_id:
        return _result("invalid", "resolver_binding_mismatch", digest)
    if sum(row["byte_length"] for row in byte_rows) > _MAX_TOTAL:
        return _result("invalid", "aggregate_byte_limit", digest)
    used = 0
    for row in byte_rows:
        try:
            value = byte_resolver.resolve(
                row["byte_object_id"], min(_MAX_OBJECT, row["byte_length"] + 1)
            )
        except Exception:
            return _result("unverified", "byte_read_unavailable", digest)
        if (
            not isinstance(value, bytes)
            or len(value) > _MAX_OBJECT
            or len(value) != row["byte_length"]
            or "sha256:" + hashlib.sha256(value).hexdigest() != row["sha256"]
        ):
            return _result("invalid", "byte_read_mismatch", digest)
        used += len(value)
        if used > _MAX_TOTAL:
            return _result("invalid", "aggregate_byte_limit", digest)
    return _result("verified", "feed_verified", digest, len(operations), len(byte_rows))
