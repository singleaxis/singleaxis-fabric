# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Re-record the example emitters (test fixtures only). Starts a loopback OTLP/HTTP
sink, runs one emitter against it and writes what the runtime sent as OTLP/JSON.

    uv run --with opentelemetry-sdk --with opentelemetry-exporter-otlp-proto-http \
        python record.py python access_gateway.py ../recorded/access-gateway.otlp.json
    python record.py node approval_service.mjs ../recorded/approval-service.otlp.json

(the Node emitter needs @opentelemetry/sdk-trace-node, resources and
exporter-trace-otlp-http resolvable from its directory)."""

import base64
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

BODIES: list[dict] = []
_ID_KEYS = {"traceId": 16, "spanId": 8, "parentSpanId": 8}


def _hex_ids(node):
    """protojson writes ids as base64; OTLP/JSON wants lowercase hex."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _ID_KEYS and isinstance(value, str):
                node[key] = base64.b64decode(value).hex()
            else:
                _hex_ids(value)
    elif isinstance(node, list):
        for item in node:
            _hex_ids(item)


class Sink(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _body(self) -> bytes:
        """The request body: a Content-Length body, or a chunked one (the Node.js
        exporter streams without a length)."""
        length = self.headers.get("Content-Length")
        if length is not None:
            return self.rfile.read(int(length))
        body = b""
        while True:
            size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while self.rfile.readline().strip():
                    pass
                return body
            body += self.rfile.read(size)
            self.rfile.readline()

    def do_POST(self):
        body = self._body()
        if self.headers.get("Content-Encoding") == "gzip":
            import gzip

            body = gzip.decompress(body)
        if self.headers.get("Content-Type", "").startswith("application/json"):
            BODIES.append(json.loads(body))
            reply, kind = b"{}", "application/json"
        else:
            from google.protobuf.json_format import MessageToDict
            from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
                ExportTraceServiceRequest,
            )

            document = MessageToDict(ExportTraceServiceRequest.FromString(body))
            _hex_ids(document)
            BODIES.append(document)
            reply, kind = b"", "application/x-protobuf"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


def main() -> None:
    runtime, script, out = sys.argv[1:4]
    server = HTTPServer(("127.0.0.1", 0), Sink)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    endpoint = f"http://127.0.0.1:{server.server_port}/v1/traces"
    command = [sys.executable if runtime == "python" else runtime, script, endpoint]
    subprocess.run(command, check=True)
    server.shutdown()
    merged = {
        "resourceSpans": [rs for body in BODIES for rs in body.get("resourceSpans", [])]
    }
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(merged, handle, indent=2, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
