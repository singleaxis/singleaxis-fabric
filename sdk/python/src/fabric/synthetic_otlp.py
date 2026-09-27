# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline, loopback-only AEEP metadata projection for the synthetic slice.

This is deliberately not a background delivery worker or durable receipt.
It never exports byte objects, local refs, paths, commands, or outcome values.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

_MAX_EVENTS = 4096
_MAX_TIMESTAMP_CHARS = 40
_MAX_TIMEOUT_S = 60
_MAX_RESPONSE_BYTES = 65536
_HTTP_OK = 200
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ROLES = frozenset(
    {
        "model.request.instructions",
        "model.request.messages",
        "model.request.tool_definitions",
        "model.request.parameters",
        "model.output.messages",
        "tool.definition",
        "tool.call.arguments",
        "tool.call.result",
        "retrieval.query",
        "retrieval.results",
        "memory.write.content",
        "memory.read.content",
        "side_effect.request",
        "side_effect.result",
        "context.file",
        "interaction.payload",
        "terminal.argv",
        "terminal.stdin",
        "terminal.stdout",
        "terminal.stderr",
        "remote.request",
        "remote.result",
        "remote.stream",
        "database.query",
        "database.parameters",
        "database.rows",
        "database.mutation",
        "network.request",
        "network.response",
        "network.stream",
        "sandbox.config",
        "sandbox.output",
        "artifact.before",
        "artifact.after",
        "service.receipt",
    }
)
_STATUSES = frozenset(
    {
        "pending",
        "stored",
        "truncated",
        "redacted",
        "not_captured",
        "unsupported",
        "dropped",
        "failed",
    }
)
_BOUNDARIES = frozenset(
    {"caller", "provider_bound", "tool", "terminal", "sandbox", "remote", "host", "service"}
)


def _attribute(key: str, value: str | int) -> dict[str, Any]:
    if isinstance(value, int) and not isinstance(value, bool):
        return {"key": key, "value": {"intValue": str(value)}}
    if isinstance(value, str):
        return {"key": key, "value": {"stringValue": value}}
    raise ValueError("invalid evidence metadata type")


def _checked_id(key: str, value: Any) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"invalid {key} identifier")
    return value


def project_synthetic_snapshot(snapshot: dict[str, Any]) -> tuple[bytes, list[str]]:  # noqa: PLR0912
    """Build bounded OTLP/HTTP JSON from a settled post-run snapshot.

    Rejects malformed metadata rather than silently omitting an event. No
    operation outcome or source-health projection is claimed in this first
    bridge; those remain offline-only and block complete-run qualification.
    """
    if snapshot.get("schema_version") != "fabric.synthetic-capture/v1":
        raise ValueError("unsupported synthetic snapshot")
    events = snapshot.get("events")
    if not isinstance(events, list) or len(events) > _MAX_EVENTS:
        raise ValueError("synthetic event batch must be bounded")
    tenant = _checked_id("tenant_id", snapshot.get("tenant_id"))
    run = _checked_id("run_id", snapshot.get("run_id"))
    records: list[dict[str, Any]] = []
    record_ids: list[str] = []
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("invalid synthetic event")
        fields: dict[str, str | int] = {
            "event_class": "evidence",
            "schema_version": "agent.evidence.event/v1",
            "record_id": _checked_id("record_id", event.get("record_id")),
            "tenant_id": tenant,
            "run_id": run,
            "source_id": _checked_id("source_id", event.get("source_id")),
            "operation_id": _checked_id("operation_id", event.get("operation_id")),
            "attempt_id": _checked_id("attempt_id", event.get("attempt_id")),
        }
        if event.get("tenant_id") != tenant or event.get("run_id") != run:
            raise ValueError("synthetic event tenant/run mismatch")
        for key in ("source_epoch", "source_sequence"):
            number = event.get(key)
            if not isinstance(number, int) or isinstance(number, bool) or number < 0:
                raise ValueError(f"invalid {key}")
            fields[key] = number
        boundary, role, status = (event.get(key) for key in ("boundary", "role", "status"))
        if boundary not in _BOUNDARIES or role not in _ROLES or status not in _STATUSES:
            raise ValueError("invalid evidence boundary/role/status")
        fields.update(boundary=boundary, role=role, status=status, provenance="caller_reported")
        observed = event.get("observed_at")
        if (
            not isinstance(observed, str)
            or len(observed) > _MAX_TIMESTAMP_CHARS
            or not observed.endswith("Z")
        ):
            raise ValueError("invalid observed_at")
        try:
            datetime.fromisoformat(observed.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid observed_at") from exc
        fields["observed_at"] = observed
        descriptor = event.get("descriptor")
        if status == "stored":
            if not isinstance(descriptor, dict) or descriptor.get("status") != "stored":
                raise ValueError("stored event lacks settled descriptor")
            object_id = _checked_id("content_object_id", descriptor.get("object_id"))
            digest = descriptor.get("stored_sha256")
            if descriptor.get("tenant_id") != tenant or descriptor.get("source_sha256") != digest:
                raise ValueError("descriptor identity/digest mismatch")
            if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
                raise ValueError("invalid content digest")
            fields["content_object_id"] = object_id
            fields["content_sha256"] = digest
        name = (
            "agent.evidence.artifact" if role.startswith("artifact.") else "agent.evidence.content"
        )
        records.append(
            {"eventName": name, "attributes": [_attribute(k, v) for k, v in fields.items()]}
        )
        record_ids.append(str(fields["record_id"]))
    document = {"resourceLogs": [{"scopeLogs": [{"logRecords": records}]}]}
    return json.dumps(document, separators=(",", ":"), allow_nan=False).encode("utf-8"), record_ids


def export_synthetic_snapshot(  # noqa: PLR0912
    snapshot: dict[str, Any],
    endpoint: str,
    *,
    timeout_s: float = 10.0,
    ca_cert_path: str | None = None,
    client_cert_path: str | None = None,
    client_key_path: str | None = None,
) -> dict[str, Any]:
    """Post settled metadata to a controlled loopback Node, off the action path.

    HTTPS requires explicit CA verification and a client certificate/key;
    insecure verification is never offered by this test-only bridge.
    """
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/v1/logs"
    ):
        raise ValueError("synthetic OTLP endpoint must be loopback /v1/logs")
    if timeout_s <= 0 or timeout_s > _MAX_TIMEOUT_S:
        raise ValueError("invalid OTLP timeout")
    tls_paths = (ca_cert_path, client_cert_path, client_key_path)
    if parsed.scheme == "https" and any(not path for path in tls_paths):
        raise ValueError("HTTPS synthetic OTLP requires CA and client certificate/key")
    if parsed.scheme == "http" and any(path is not None for path in tls_paths):
        raise ValueError("HTTP synthetic OTLP cannot accept TLS certificate options")
    payload, ids = project_synthetic_snapshot(snapshot)
    if parsed.scheme == "https":
        context = ssl.create_default_context(cafile=ca_cert_path)
        if client_cert_path is None or client_key_path is None:
            raise ValueError("HTTPS synthetic OTLP requires client certificate/key")
        context.load_cert_chain(client_cert_path, client_key_path)
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            parsed.hostname, parsed.port or 443, timeout=timeout_s, context=context
        )
    else:
        connection = http.client.HTTPConnection(
            parsed.hostname, parsed.port or 80, timeout=timeout_s
        )
    try:
        connection.request(
            "POST", "/v1/logs", body=payload, headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        if response.status != _HTTP_OK:
            raise ValueError("OTLP Node did not accept metadata batch")
        body = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(body) > _MAX_RESPONSE_BYTES:
            raise ValueError("OTLP response too large")
        result = json.loads(body) if body else {}
        if not isinstance(result, dict):
            raise ValueError("invalid OTLP response")
        partial = result.get("partialSuccess", {})
        rejected = partial.get("rejectedLogRecords", 0) if isinstance(partial, dict) else -1
        if isinstance(rejected, str) and re.fullmatch(r"[0-9]+", rejected):
            rejected = int(rejected)
        if not isinstance(rejected, int) or rejected < 0:
            raise ValueError("invalid OTLP partial success")
        return {
            "receipt_stage": "node_accepted" if rejected == 0 else "partial",
            "submitted_record_ids": ids,
            "rejected_count": rejected,
            "destination_durable": False,
        }
    finally:
        connection.close()
