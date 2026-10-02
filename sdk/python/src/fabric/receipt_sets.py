# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Bounded exact-set receipt verification, offline and separate by stage.

A verified signature authenticates an issuer's statement. It does not prove
that the issuer observed fsync, independent systems or production controls.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from .content_join import CONTENT_JOIN_FIELDS, validate_content_join
from .evidence_attestation import (
    EvidenceExpectation,
    EvidenceTrustKey,
    verify_evidence_attestation,
)
from .synthetic_otlp import _BOUNDARIES, _ROLES, _STATUSES

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_BYTES = 1024 * 1024
_MAX_ENTRIES = 4096
_MAX_OBJECT_BYTES = 16 * 1024 * 1024
_MAX_COUNTER = 2**63 - 1
_MAX_COUNTER_CHARS = 19
_MAX_TIMESTAMP_CHARS = 40
_MAX_OTLP_DEPTH = 10
_STAGES = frozenset(
    {"source_spooled", "node_accepted", "destination_accepted", "destination_durable"}
)
_KINDS = frozenset({"source_record", "metadata_record", "content_object", "source_seal"})
_IDENTITY_FIELDS = frozenset(
    {
        "record_id",
        "tenant_id",
        "run_id",
        "source_id",
        "operation_id",
        "attempt_id",
        "call_id",
        "agent_id",
        "parent_call_id",
        "stream_id",
        "content_object_id",
    }
)
_COUNTERS = frozenset(
    {"source_epoch", "source_sequence", "chunk_index", "policy_version", "content_byte_length"}
)
_FIXED_VALUES = {
    "event_class": frozenset({"evidence"}),
    "schema_version": frozenset({"agent.evidence.event/v1"}),
    "provenance": frozenset({"caller_reported"}),
    "boundary": _BOUNDARIES,
    "role": _ROLES,
    "status": _STATUSES | {"observed"},
    "call_phase": frozenset({"start", "outcome"}),
    "call_kind": frozenset({"model", "tool", "database", "agent"}),
    "result_status": frozenset({"ok", "error", "cancelled", "deferred"}),
}
_MAX_ATTRIBUTES = len(
    _IDENTITY_FIELDS | _COUNTERS | _FIXED_VALUES.keys() | CONTENT_JOIN_FIELDS | {"observed_at"}
)
_REQUIRED_METADATA = frozenset(
    {
        "event_class",
        "schema_version",
        "record_id",
        "tenant_id",
        "run_id",
        "source_id",
        "operation_id",
        "attempt_id",
        "source_epoch",
        "source_sequence",
        "boundary",
        "status",
        "provenance",
        "observed_at",
    }
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _identifier(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("invalid metadata document")
        result[key] = value
    return result


def _depth(value: object, depth: int = 0) -> None:
    # The closed OTLP grouping adds structural wrappers around record values.
    if depth > _MAX_OTLP_DEPTH:
        raise ValueError("invalid metadata document")
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, depth + 1)


@dataclass(frozen=True, slots=True)
class EvidenceSetEntry:
    kind: str
    identifier: str
    sha256: str
    byte_length: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.kind, str)
            or self.kind not in _KINDS
            or not _identifier(self.identifier)
            or not isinstance(self.sha256, str)
            or _DIGEST.fullmatch(self.sha256) is None
            or isinstance(self.byte_length, bool)
            or not isinstance(self.byte_length, int)
            or not 0 <= self.byte_length <= _MAX_OBJECT_BYTES
        ):
            raise ValueError("invalid evidence set entry")


@dataclass(frozen=True, slots=True)
class ReceiptSetExpectation:
    stage: str
    tenant_id: str
    run_id: str
    scope_sha256: str
    set_id: str
    issuer_id: str
    entries: tuple[EvidenceSetEntry, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.stage, str)
            or self.stage not in _STAGES
            or not all(
                _identifier(item)
                for item in (self.tenant_id, self.run_id, self.set_id, self.issuer_id)
            )
            or not isinstance(self.scope_sha256, str)
            or _DIGEST.fullmatch(self.scope_sha256) is None
            or not isinstance(self.entries, tuple)
            or len(self.entries) > _MAX_ENTRIES
            or any(not isinstance(item, EvidenceSetEntry) for item in self.entries)
            or len({(item.kind, item.identifier) for item in self.entries}) != len(self.entries)
        ):
            raise ValueError("invalid receipt set expectation")


@dataclass(frozen=True, slots=True)
class ReceiptSetVerification:
    status: str
    reason: str
    set_sha256: str | None = None
    entry_count: int = 0


def receipt_set_bytes(expectation: ReceiptSetExpectation) -> bytes:
    """Build a closed manifest from independently supplied exact readbacks."""
    value = asdict(expectation)
    value["schema_version"] = "fabric.receipt-set/v1"
    value["entries"] = [
        asdict(item)
        for item in sorted(expectation.entries, key=lambda item: (item.kind, item.identifier))
    ]
    document = _canonical(value)
    if len(document) > _MAX_BYTES:
        raise ValueError("receipt set exceeds manifest capacity")
    return document


def verify_receipt_set(
    manifest_bytes: bytes | None,
    attestation_bytes: bytes | None,
    *,
    expectation: ReceiptSetExpectation,
    trusted_keys: Mapping[str, EvidenceTrustKey],
    verification_time: int,
) -> ReceiptSetVerification:
    """Require canonical exact-set equality and a purpose-specific signature."""
    if manifest_bytes is None or attestation_bytes is None:
        return ReceiptSetVerification("unverified", "missing_receipt_proof")
    expected = receipt_set_bytes(expectation)
    if (
        not isinstance(manifest_bytes, bytes)
        or len(manifest_bytes) > _MAX_BYTES
        or manifest_bytes != expected
    ):
        return ReceiptSetVerification("invalid", "receipt_set_mismatch")
    digest = "sha256:" + hashlib.sha256(expected).hexdigest()
    result = verify_evidence_attestation(
        attestation_bytes,
        expected=EvidenceExpectation(
            expectation.stage,
            expectation.tenant_id,
            expectation.run_id,
            expectation.scope_sha256,
            "evidence_set",
            expectation.set_id,
            digest,
            expectation.issuer_id,
        ),
        trusted_keys=trusted_keys,
        verification_time=verification_time,
    )
    if result.status != "verified":
        if result.reason in {"verification_dependency_unavailable", "unknown_key"}:
            return ReceiptSetVerification("unverified", result.reason)
        return ReceiptSetVerification("invalid", "receipt_attestation_invalid")
    return ReceiptSetVerification("verified", "verified", digest, len(expectation.entries))


def _attribute_value(key: str, value: object) -> str | int:
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError("invalid metadata document")
    if key in _COUNTERS:
        raw = value.get("intValue")
        if (
            not isinstance(raw, str)
            or not raw.isascii()
            or not raw.isdecimal()
            or len(raw) > _MAX_COUNTER_CHARS
            or str(int(raw)) != raw
            or int(raw) > _MAX_COUNTER
        ):
            raise ValueError("invalid metadata document")
        return int(raw)
    raw = value.get("stringValue")
    if not isinstance(raw, str):
        raise ValueError("invalid metadata document")
    if key in _IDENTITY_FIELDS:
        valid = _identifier(raw)
    elif key in _FIXED_VALUES:
        valid = raw in _FIXED_VALUES[key]
    elif key in CONTENT_JOIN_FIELDS:
        # Validate the whole governed binding after every attribute is decoded.
        valid = True
    elif key == "observed_at":
        # Only the projection's bounded UTC timestamp grammar is permitted.
        valid = len(raw) <= _MAX_TIMESTAMP_CHARS and raw.endswith("Z")
        if valid:
            try:
                datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                valid = False
    else:
        valid = False
    if not valid:
        raise ValueError("invalid metadata document")
    return raw


def _metadata_entry(record: object) -> EvidenceSetEntry:
    if (
        not isinstance(record, dict)
        or set(record) != {"eventName", "attributes"}
        or record["eventName"]
        not in {"agent.evidence.call", "agent.evidence.content", "agent.evidence.artifact"}
        or not isinstance(record["attributes"], list)
        or len(record["attributes"]) > _MAX_ATTRIBUTES
    ):
        raise ValueError("invalid metadata document")
    attributes: dict[str, str | int] = {}
    for attribute in record["attributes"]:
        if (
            not isinstance(attribute, dict)
            or set(attribute) != {"key", "value"}
            or not isinstance(attribute["key"], str)
            or attribute["key"] in attributes
        ):
            raise ValueError("invalid metadata document")
        attributes[attribute["key"]] = _attribute_value(attribute["key"], attribute["value"])
    if not attributes.keys() >= _REQUIRED_METADATA:
        raise ValueError("invalid metadata document")
    validate_content_join(attributes)
    body = _canonical({"eventName": record["eventName"], "attributes": attributes})
    return EvidenceSetEntry(
        "metadata_record",
        str(attributes["record_id"]),
        "sha256:" + hashlib.sha256(body).hexdigest(),
        len(body),
    )


def metadata_entries(payload: bytes) -> tuple[EvidenceSetEntry, ...]:  # noqa: PLR0912
    """Normalize exact safe record attributes, ignoring only OTLP grouping.

    The first interface accepts only the projection's closed grouping format;
    richer OTLP bodies must be explicitly converted by an authorized witness.
    """
    try:
        if not isinstance(payload, bytes) or len(payload) > _MAX_BYTES:
            raise ValueError("invalid metadata document")
        document = json.loads(payload, object_pairs_hook=_unique_fields)
        _depth(document)
        if not isinstance(document, dict) or set(document) != {"resourceLogs"}:
            raise ValueError("invalid metadata document")
        entries: list[EvidenceSetEntry] = []
        if not isinstance(document["resourceLogs"], list):
            raise ValueError("invalid metadata document")
        for resource in document["resourceLogs"]:
            if not isinstance(resource, dict) or set(resource) != {"scopeLogs"}:
                raise ValueError("invalid metadata document")
            if not isinstance(resource["scopeLogs"], list):
                raise ValueError("invalid metadata document")
            for scope in resource["scopeLogs"]:
                if not isinstance(scope, dict) or set(scope) != {"logRecords"}:
                    raise ValueError("invalid metadata document")
                if not isinstance(scope["logRecords"], list):
                    raise ValueError("invalid metadata document")
                for record in scope["logRecords"]:
                    entries.append(_metadata_entry(record))
                    if len(entries) > _MAX_ENTRIES:
                        raise ValueError("invalid metadata document")
        if len({item.identifier for item in entries}) != len(entries):
            raise ValueError("invalid metadata document")
        return tuple(sorted(entries, key=lambda item: (item.kind, item.identifier)))
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        raise ValueError("invalid metadata document") from None
