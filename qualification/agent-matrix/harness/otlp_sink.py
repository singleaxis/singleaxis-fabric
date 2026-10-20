# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A loopback OTLP/HTTP receiver for local file mode: each trace export request is
written verbatim as ``NNNNNN.otlp`` (what ``python -m fabric.reconstruct --spans DIR``
reads); logs and metrics are kept beside it for the leak scan."""

from __future__ import annotations

import gzip
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


class OtlpSink:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self._count = 0
        self._lock = threading.Lock()
        sink = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:  # noqa: N802
                data = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if self.headers.get("Content-Encoding", "").lower() == "gzip":
                    data = gzip.decompress(data)
                kind = self.path.rstrip("/").rsplit("/", 1)[-1]  # traces | logs | metrics
                with sink._lock:
                    sink._count += 1
                    n = sink._count
                suffix = ".otlp" if kind == "traces" else f".{kind}.bin"
                (sink.directory / f"{n:06d}{suffix}").write_bytes(data)
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = int(self.httpd.server_address[1])
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _value(v: Any) -> Any:
    which = v.WhichOneof("value")
    if which == "array_value":
        return [_value(x) for x in v.array_value.values]
    if which == "kvlist_value":
        return {kv.key: _value(kv.value) for kv in v.kvlist_value.values}
    return getattr(v, which) if which else None


def read_spans(directory: Path) -> list[dict[str, Any]]:
    """Every span in the ``*.otlp`` files, as ``{name, attributes, resource}``."""
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (  # noqa: PLC0415
        ExportTraceServiceRequest,
    )

    spans: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.otlp")):
        request = ExportTraceServiceRequest()
        request.ParseFromString(path.read_bytes())
        for rs in request.resource_spans:
            resource = {kv.key: _value(kv.value) for kv in rs.resource.attributes}
            for ss in rs.scope_spans:
                for span in ss.spans:
                    spans.append({
                        "name": span.name, "resource": resource,
                        "attributes": {kv.key: _value(kv.value) for kv in span.attributes},
                        "start_ns": span.start_time_unix_nano, "end_ns": span.end_time_unix_nano,
                    })  # fmt: skip
    return spans
