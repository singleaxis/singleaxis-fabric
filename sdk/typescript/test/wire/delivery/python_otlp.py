# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The Python side of the OTLP parity tests (spec 055 §9.5, unit 055-t12).

Reads one JSON request on stdin and prints the exact bytes Python's sender sends:

- ``spans``: for each spool record, the ``ExportTraceServiceRequest`` of the span
  ``fabric.wire._sender.Sender._span`` builds for it, encoded by OpenTelemetry's
  ``encode_spans`` (what ``OTLPSpanExporter`` posts), and the one request of all of them;
- ``content``: ``fabric.wire._content.encode_content_records`` of each item and of all;
- ``responses``: for each hex response body of a 2xx, whether ``NodeContentClient._post``
  takes it as rejecting records (its own parse, with the parse error suppressed).

The producer labels are substituted as spec 055 §7.3 allows: the capture-point version
and the SDK scope name are the TypeScript ones given in the request.
"""

from __future__ import annotations

import json
import sys

from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans

from fabric import tracing
from fabric.wire import _sender
from fabric.wire._content import encode_content_records


def _rejects(body: bytes) -> bool:
    """``NodeContentClient._post`` on a 2xx: a parse error means accepted."""
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2  # noqa: PLC0415

    try:
        reply = logs_service_pb2.ExportLogsServiceResponse.FromString(body)
    except Exception:  # noqa: BLE001 - as _post's contextlib.suppress(Exception)
        return False
    return bool(reply.partial_success.rejected_log_records)


def main() -> None:
    request = json.loads(sys.stdin.read())
    _sender.__version__ = request["version"]  # type: ignore[attr-defined]
    tracing.FABRIC_SDK_NAME = request["sdk_name"]  # type: ignore[misc]
    sender = _sender.Sender.__new__(_sender.Sender)
    sender.service_name = request["service_name"]
    sender._resource = _sender.Resource({"service.name": request["service_name"]})
    spans = [sender._span(json.loads(text)) for text in request["records"]]
    items = []
    for item in request["content"]:
        descriptor = json.loads(item["fixture"])["attributes"]
        descriptor.pop("event_class", None)
        items.append((descriptor, bytes.fromhex(item["body_hex"])))
    service = request["service_name"]
    out = {
        "spans": [encode_spans([span]).SerializeToString().hex() for span in spans],
        "spans_all": encode_spans(spans).SerializeToString().hex(),
        "content": [
            encode_content_records([item], service_name=service).hex() for item in items
        ],
        "content_all": encode_content_records(items, service_name=service).hex(),
        "responses": [
            _rejects(bytes.fromhex(body)) for body in request.get("responses", [])
        ],
    }
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
