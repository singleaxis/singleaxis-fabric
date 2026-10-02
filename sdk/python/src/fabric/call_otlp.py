# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline metadata-only projection for custom-agent source records.

This optional test bridge has no background sender, replay, or durable receipt
claim. Protected bytes, storage references and arbitrary outcome text never
enter the emitted OTLP document.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, TypeGuard

from .synthetic_otlp import (
    _MAX_EVENTS,
    _attribute,
    _checked_id,
    _export_projected_metadata,
    project_synthetic_snapshot,
)

_MAX_INT64 = 2**63 - 1
_KINDS = frozenset({"model", "tool", "database", "agent"})
_OUTCOMES = frozenset({"ok", "error", "cancelled", "deferred"})


def _safe_counter(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_INT64


def _call_fields(event: dict[str, Any]) -> dict[str, str | int]:
    fields: dict[str, str | int] = {
        key: _checked_id(key, event.get(key)) for key in ("call_id", "agent_id")
    }
    if event.get("parent_call_id") is not None:
        fields["parent_call_id"] = _checked_id("parent_call_id", event["parent_call_id"])
        if fields["parent_call_id"] == fields["call_id"]:
            raise ValueError("invalid call parent")
    for key in ("source_epoch", "source_sequence"):
        if not _safe_counter(event.get(key)):
            raise ValueError("invalid source counter")
    if "stream_id" in event or "chunk_index" in event:
        fields["stream_id"] = _checked_id("stream_id", event.get("stream_id"))
        index = event.get("chunk_index")
        if not _safe_counter(index):
            raise ValueError("invalid chunk index")
        fields["chunk_index"] = index
    return fields


def _records(payload: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = json.loads(payload)["resourceLogs"][0]["scopeLogs"][0][
        "logRecords"
    ]
    return records


def project_call_snapshot(  # noqa: PLR0912, PLR0915 - closed metadata validation
    snapshot: dict[str, Any],
) -> tuple[bytes, list[str]]:
    """Project every live source start, byte observation and terminal outcome.

    The caller must inspect the offline report for gaps and recovered history.
    Unknown fields are discarded. Invalid required metadata rejects the whole
    batch rather than silently hiding a source record. This function never
    resolves content or accesses a network/store.
    """
    if snapshot.get("schema_version") != "fabric.call-recording/v1":
        raise ValueError("unsupported call snapshot")
    groups = [snapshot.get(name, []) for name in ("starts", "events", "operations")]
    if any(not isinstance(group, list) for group in groups):
        raise ValueError("call record collections must be lists")
    if sum(len(group) for group in groups) > _MAX_EVENTS:
        raise ValueError("call event batch must be bounded")
    starts, events, operations = groups
    if any(not isinstance(event, dict) for group in groups for event in group):
        raise ValueError("invalid call source record")
    tenant = _checked_id("tenant_id", snapshot.get("tenant_id"))
    run = _checked_id("run_id", snapshot.get("run_id"))
    base = {
        "schema_version": "fabric.synthetic-capture/v1",
        "tenant_id": tenant,
        "run_id": run,
        "events": events,
    }
    projected, ids = project_synthetic_snapshot(base)
    records = _records(projected)
    for event, record in zip(events, records, strict=True):
        extra = _call_fields(event)
        descriptor = event.get("descriptor")
        if isinstance(descriptor, dict):
            for key in (
                "run_id",
                "source_id",
                "source_epoch",
                "source_sequence",
                "operation_id",
                "attempt_id",
                "boundary",
                "role",
                "object_id",
                "stream_id",
                "chunk_index",
            ):
                if event.get(key) != descriptor.get(key):
                    raise ValueError("call content identity mismatch")
        record["attributes"].extend(_attribute(key, value) for key, value in extra.items())
    for phase, lifecycle in (("start", starts), ("outcome", operations)):
        for event in lifecycle:
            if event.get("role") != "operation." + phase or event.get("status") != "recorded":
                raise ValueError("invalid call lifecycle record")
            extra = _call_fields(event)
            kind = event.get("kind")
            if kind not in _KINDS:
                raise ValueError("invalid call kind")
            extra.update(call_phase=phase, call_kind=kind)
            if phase == "outcome":
                outcome = event.get("outcome")
                result = outcome.get("result_status") if isinstance(outcome, dict) else None
                if result not in _OUTCOMES:
                    raise ValueError("invalid call outcome")
                extra["result_status"] = result
            # Reuse the closed envelope validation without projecting the raw
            # lifecycle role/outcome. The placeholder role is removed below.
            envelope = {**event, "role": "interaction.payload", "status": "pending"}
            payload, lifecycle_ids = project_synthetic_snapshot({**base, "events": [envelope]})
            record = _records(payload)[0]
            record["eventName"] = "agent.evidence.call"
            record["attributes"] = [
                item for item in record["attributes"] if item["key"] not in {"role", "status"}
            ]
            extra["status"] = "observed"
            record["attributes"].extend(_attribute(key, value) for key, value in extra.items())
            records.append(record)
            ids.extend(lifecycle_ids)
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate call source record identity")

    # Ordered by source and epoch; timestamps never invent a global ordering.
    def order(record: dict[str, Any]) -> tuple[str, int, int]:
        attrs = {item["key"]: item["value"] for item in record["attributes"]}
        return (
            attrs["source_id"]["stringValue"],
            int(attrs["source_epoch"]["intValue"]),
            int(attrs["source_sequence"]["intValue"]),
        )

    records.sort(key=order)
    ids = [
        next(
            item["value"]["stringValue"]
            for item in record["attributes"]
            if item["key"] == "record_id"
        )
        for record in records
    ]
    document = {"resourceLogs": [{"scopeLogs": [{"logRecords": records}]}]}
    return json.dumps(document, separators=(",", ":"), allow_nan=False).encode("utf-8"), ids


def export_call_snapshot(
    snapshot: dict[str, Any],
    endpoint: str,
    *,
    timeout_s: float = 10.0,
    ca_cert_path: str | None = None,
    client_cert_path: str | None = None,
    client_key_path: str | None = None,
    bearer_token_path: str | None = None,
) -> dict[str, Any]:
    """Send once to a controlled loopback Node, with optional verified mTLS."""
    payload, ids = project_call_snapshot(snapshot)
    return _export_projected_metadata(
        payload,
        ids,
        endpoint,
        timeout_s=timeout_s,
        ca_cert_path=ca_cert_path,
        client_cert_path=client_cert_path,
        client_key_path=client_key_path,
        bearer_token_path=bearer_token_path,
    )


def project_call_snapshot_batches(
    snapshot: dict[str, Any], *, batch_size: int = _MAX_EVENTS
) -> list[tuple[bytes, list[str]]]:
    """Validate and partition the live journal view without losing record identity.

    This does not export, acknowledge, or requalify recovered epochs. Each batch
    retains source ordering; a retry must use the same immutable snapshot.
    All batches are validated before returning any, so malformed later records
    cannot cause a partially emitted projection through this API.
    """
    if isinstance(batch_size, bool) or not isinstance(batch_size, int):
        raise ValueError("batch_size must be an integer")
    if not 1 <= batch_size <= _MAX_EVENTS:
        raise ValueError("batch_size exceeds projection bounds")
    if snapshot.get("schema_version") != "fabric.call-recording/v1":
        raise ValueError("unsupported call snapshot")
    indexed: list[tuple[str, dict[str, Any]]] = []
    identities: set[str] = set()
    counters: set[tuple[str, int, int]] = set()
    for group in ("starts", "events", "operations"):
        records = snapshot.get(group, [])
        if not isinstance(records, list):
            raise ValueError("call record collections must be lists")
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("invalid call source record")
            identity = _checked_id("record_id", record.get("record_id"))
            source = _checked_id("source_id", record.get("source_id"))
            epoch, sequence = record.get("source_epoch"), record.get("source_sequence")
            if not _safe_counter(epoch) or not _safe_counter(sequence):
                raise ValueError("invalid source counter")
            counter = (source, epoch, sequence)
            if identity in identities or counter in counters:
                raise ValueError("duplicate call record identity or source sequence")
            identities.add(identity)
            counters.add(counter)
            indexed.append((group, record))
    indexed.sort(
        key=lambda item: (item[1]["source_id"], item[1]["source_epoch"], item[1]["source_sequence"])
    )
    result: list[tuple[bytes, list[str]]] = []
    for offset in range(0, len(indexed), batch_size):
        window = indexed[offset : offset + batch_size]
        partition = {
            **snapshot,
            **{
                group: [record for name, record in window if name == group]
                for group in ("starts", "events", "operations")
            },
        }
        result.append(project_call_snapshot(partition))
    if not indexed:
        result.append(project_call_snapshot(snapshot))
    return result


def call_batch_manifest(
    snapshot: dict[str, Any], *, batch_size: int = _MAX_EVENTS
) -> dict[str, Any]:
    """Content-free exact-set manifest for caller-managed retries/readback.

    Digests bind the projected payloads, not durability. A destination must
    independently acknowledge/read back the listed records. No receipts are
    fabricated here; a cursor alone cannot be treated as delivery success.
    """
    batches = project_call_snapshot_batches(snapshot, batch_size=batch_size)
    entries = [
        {
            "index": index,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "record_ids": ids,
            "record_count": len(ids),
        }
        for index, (payload, ids) in enumerate(batches)
    ]
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema_version": "fabric.call-batch-manifest/v1",
        "tenant_id": snapshot["tenant_id"],
        "run_id": snapshot["run_id"],
        "snapshot_digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "batches": entries,
        "record_count": sum(len(ids) for _, ids in batches),
        "delivery_status": "not_sent",
        "durability_status": "unverified",
        "scope": "live_snapshot_only",
    }
