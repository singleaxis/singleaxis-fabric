# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A raw OTLP/HTTP client for the Node's reject-path tests (scenario 6).

It holds the Node's own ingress bearer token (standing in for a buggy or compromised
agent of the bound source) and posts hand-built trace and content requests so the harness
can confirm the Node *rejects* records that are not what the bound source would send:
a record that names another tenant or source, a receiver-owned stamp set by the sender,
duplicate attribute keys, malformed descriptors, path-traversal ids and oversized values.
The harness asserts each is dropped (counted, content-free log) or stripped, never stored
and never in the Node's telemetry. Building these requests needs only the public OTLP
protobufs and the content encoder; nothing here changes Fabric.
"""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

from fabric.wire._content import encode_content_request


def _kv(key: str, value: Any):  # noqa: ANN202
    from opentelemetry.proto.common.v1 import common_pb2  # noqa: PLC0415

    kv = common_pb2.KeyValue(key=key)
    if isinstance(value, bool):
        kv.value.bool_value = value
    elif isinstance(value, int):
        kv.value.int_value = value
    elif isinstance(value, list):
        for item in value:
            kv.value.array_value.values.add(string_value=str(item))
    else:
        kv.value.string_value = str(value)
    return kv


def _manual_content(descriptor: dict[str, Any], body: bytes) -> bytes:
    """The same request shape as ``encode_content_request`` without its validation, so a
    malformed descriptor (wrong types, missing keys, bad ``captured_at``) reaches the Node
    instead of failing in the client."""
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2 as lp  # noqa: PLC0415

    req = lp.ExportLogsServiceRequest()
    rl = req.resource_logs.add()
    rl.resource.attributes.append(_kv("service.name", "svc-" + "a" * 32))
    sl = rl.scope_logs.add()
    sl.scope.name = "fabric.wire"
    rec = sl.log_records.add()
    rec.time_unix_nano = time.time_ns()
    rec.body.bytes_value = bytes(body)
    for key, value in {"event_class": "content", **descriptor}.items():
        if isinstance(value, int) and not isinstance(value, bool):
            value = max(min(value, (1 << 63) - 1), -(1 << 63))
        rec.attributes.append(_kv(key, value if isinstance(value, (bool, int, list)) else str(value)))
    return req.SerializeToString()


class RawClient:
    def __init__(self, node) -> None:  # noqa: ANN001
        self.node = node
        self.ctx = ssl.create_default_context(cafile=str(node.tls / "ca.crt"))

    def _post(self, port_name: str, path: str, body: bytes) -> int:
        req = urllib.request.Request(
            f"https://127.0.0.1:{self.node.ports[port_name]}{path}", data=body, method="POST",
            headers={"Content-Type": "application/x-protobuf",
                     "Authorization": f"Bearer {self.node.ingress_token}"})  # fmt: skip
        try:
            with urllib.request.urlopen(req, timeout=60, context=self.ctx) as r:
                return r.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except OSError:
            return -1

    def content(self, descriptor: dict[str, Any], body: bytes,
                add_attrs: list[tuple[str, Any]] | None = None) -> int:  # fmt: skip
        """One content log record; ``add_attrs`` are appended after encoding, so a key may
        repeat (the protobuf permits it; the Node must read it safely)."""
        try:
            payload = encode_content_request(descriptor, body, service_name="svc-" + "a" * 32)
        except Exception:  # noqa: BLE001 - the SDK encoder refuses it; the Node must too
            payload = _manual_content(descriptor, body)
        if add_attrs:
            from opentelemetry.proto.collector.logs.v1 import logs_service_pb2 as lp  # noqa: PLC0415

            req = lp.ExportLogsServiceRequest.FromString(payload)
            rec = req.resource_logs[0].scope_logs[0].log_records[0]
            for key, value in add_attrs:
                rec.attributes.append(_kv(key, value))
            payload = req.SerializeToString()
        return self._post("otlp_content", "/v1/logs", payload)

    def trace(self, attr_lists: list[list[tuple[str, Any]]],
              resource: list[tuple[str, Any]] | None = None) -> int:  # fmt: skip
        """One trace request; each item in ``attr_lists`` is one span's attributes (a list,
        so a key may repeat)."""
        from opentelemetry.proto.collector.trace.v1 import trace_service_pb2 as tp  # noqa: PLC0415
        from opentelemetry.proto.trace.v1 import trace_pb2  # noqa: PLC0415

        rs = trace_pb2.ResourceSpans()
        rs.resource.attributes.extend(_kv(k, v) for k, v in (resource or [("service.name", "svc-" + "b" * 32)]))
        ss = rs.scope_spans.add()
        ss.scope.name = "fabric.wire"
        for attrs in attr_lists:
            span = ss.spans.add()
            span.trace_id = uuid.uuid4().bytes
            span.span_id = uuid.uuid4().bytes[:8]
            span.name = "fabric.model_call"
            span.kind = 3
            span.start_time_unix_nano = time.time_ns()
            span.end_time_unix_nano = time.time_ns()
            span.attributes.extend(_kv(k, v) for k, v in attrs)
        req = tp.ExportTraceServiceRequest(resource_spans=[rs])
        return self._post("otlp_http", "/v1/traces", req.SerializeToString())
