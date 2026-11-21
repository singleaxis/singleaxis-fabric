# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The Python side of the OTLP parity tests (spec 055 §9.5, unit 055-t12).

Reads one JSON request on stdin and prints the exact bytes Python's sender sends:

- ``spans``: for each spool record, the ``ExportTraceServiceRequest`` of the span
  ``fabric.wire._sender.Sender._span`` builds for it, encoded by OpenTelemetry's
  ``encode_spans`` (what ``OTLPSpanExporter`` posts), and the one request of all of them;
- ``content``: ``fabric.wire._content.encode_content_records`` of each item and of all.

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
    }
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
