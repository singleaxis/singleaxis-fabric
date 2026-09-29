# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline metadata-only projection for custom-agent source records.

This optional test bridge has no background sender, replay, or durable receipt
claim. Protected bytes, storage references and arbitrary outcome text never
enter the emitted OTLP document.
"""

from __future__ import annotations

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
