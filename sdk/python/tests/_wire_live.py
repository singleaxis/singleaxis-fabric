# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A live rig for zero-code wire capture in real child interpreters (the agent-matrix
repro cases): a loopback OpenAI-compatible model server, a loopback OTLP/HTTP sink that
writes each trace export as ``NNNNNN.otlp`` (what ``fabric.reconstruct --spans`` reads),
and an agent runner that installs capture only through ``FABRIC_*`` variables and the
autoload ``sitecustomize`` on ``PYTHONPATH`` (so spawned children capture too)."""

from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from fabric.wire.__main__ import autoload_path

TENANT = "live-tenant"
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


def _serve(handler: type[BaseHTTPRequestHandler]) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class FakeModel:
    """Chat Completions on ``/v1/chat/completions``: JSON, or SSE when ``stream`` is set.
    ``requests`` counts every POST body the server read completely."""

    def __init__(self) -> None:
        self.requests: list[bytes] = []
        self._lock = threading.Lock()
        model = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                with model._lock:
                    model.requests.append(raw)
                body = json.loads(raw or b"{}")
                if body.get("stream"):
                    data, media = sse_chat(), "text/event-stream"
                else:
                    data, media = chat_json(), "application/json"
                self.send_response(200)
                self.send_header("Content-Type", media)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = _serve(Handler)
        self.port = int(self._server.server_address[1])

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def endpoints(self) -> str:
        return json.dumps([{
            "endpoint_id": "fake-openai", "dialect": "openai", "hosts": ["127.0.0.1"],
            "ports": [self.port], "path_prefix": "/v1", "schemes": ["http"],
        }])  # fmt: skip

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def chat_json() -> bytes:
    return json.dumps({
        "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "m",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }).encode()  # fmt: skip


def sse_chat() -> bytes:
    events = [
        {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m", "choices": [
            {"index": 0, "delta": {"role": "assistant", "content": "h"}, "finish_reason": None}]},
        {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m", "choices": [
            {"index": 0, "delta": {"content": "i"}, "finish_reason": None}]},
        {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m", "choices": [
            {"index": 0, "delta": {}, "finish_reason": "stop"}]},
    ]  # fmt: skip
    return b"".join(b"data: " + json.dumps(e).encode() + b"\n\n" for e in events) + (
        b"data: [DONE]\n\n"
    )


class OtlpSink:
    """Writes every trace export request verbatim as ``NNNNNN.otlp``."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self._count = 0
        self._lock = threading.Lock()
        sink = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                data = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if self.headers.get("Content-Encoding", "").lower() == "gzip":
                    data = gzip.decompress(data)
                with sink._lock:
                    sink._count += 1
                    name = f"{sink._count:06d}.otlp"
                if self.path.rstrip("/").endswith("/traces"):
                    (sink.directory / name).write_bytes(data)
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.end_headers()

        self._server = _serve(Handler)
        self.endpoint = f"http://127.0.0.1:{self._server.server_address[1]}/v1/traces"

    def spans(self) -> list[dict[str, Any]]:
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (  # noqa: PLC0415
            ExportTraceServiceRequest,
        )

        found: list[dict[str, Any]] = []
        for path in sorted(self.directory.glob("*.otlp")):
            request = ExportTraceServiceRequest()
            request.ParseFromString(path.read_bytes())
            for resource in request.resource_spans:
                for scope in resource.scope_spans:
                    for span in scope.spans:
                        values = {kv.key: _value(kv.value) for kv in span.attributes}
                        found.append({"name": span.name, "attributes": values})
        return found

    def exchanges(self) -> list[dict[str, Any]]:
        spans = self.spans()
        return [s["attributes"] for s in spans if "fabric.wire.exchange_id" in s["attributes"]]

    def losses(self) -> list[dict[str, Any]]:
        return [s["attributes"] for s in self.spans() if "fabric.loss.reason" in s["attributes"]]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _value(value: Any) -> Any:
    which = value.WhichOneof("value")
    if which == "array_value":
        return [_value(item) for item in value.array_value.values]
    return getattr(value, which) if which else None


def capture_env(model: FakeModel, sink: OtlpSink, store: Path, **extra: str) -> dict[str, str]:
    """Zero-code local file mode: the autoload and ``FABRIC_*``/``OTEL_*`` variables only,
    and no proxy variable at all (spec 047: capture delivery never depends on them)."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("FABRIC_", "OTEL_")) and k.upper() not in _PROXY_VARS}  # fmt: skip
    env.update({
        "PYTHONPATH": autoload_path(), "FABRIC_WIRE_AUTOLOAD": "1",
        "FABRIC_WIRE_STORE": f"file://{store}", "FABRIC_TENANT_ID": TENANT,
        "FABRIC_WIRE_ENDPOINTS": model.endpoints(),
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": sink.endpoint, "OTEL_SERVICE_NAME": "live-agent",
        "LIVE_MODEL_BASE": model.base, "PYTHONUNBUFFERED": "1",
    })  # fmt: skip
    env.update(extra)
    return env


def run_agent(
    script: Path, env: dict[str, str], *args: str, timeout_s: float = 90.0
) -> dict[str, Any]:
    """Run ``script`` to completion in its own session; a hang is killed and reported."""
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, str(script), *args], env=env, cwd=str(script.parent),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )  # fmt: skip
    try:
        out, err = proc.communicate(timeout=timeout_s)
        hung = False
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, 9)
        out, err = proc.communicate()
        hung = True
    text = {"stdout": out.decode("utf-8", "replace"), "stderr": err.decode("utf-8", "replace")}
    return {"returncode": proc.returncode, "hung": hung, **text}


def reconstruct(spans: Path, store: Path, out: Path) -> dict[str, Any]:
    """``python -m fabric.reconstruct`` over the sink's files and the local store; the
    report (``{}`` when there was nothing to reconstruct)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_"))}
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fabric.reconstruct", "--spans", str(spans), "--store-root",
         str(store), "--tenant", TENANT, "--out", str(out)],
        env=env, capture_output=True, timeout=120, check=False,
    )  # fmt: skip
    return json.loads(out.read_text("utf-8")) if out.exists() else {}


def wait_for(predicate: Any, timeout_s: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return bool(predicate())


def verdicts(report: dict[str, Any]) -> list[str]:
    """Every run's verdict (one run per source epoch without ``fabric.wire.run()``)."""
    return [run["verdict"] for run in report.get("runs", [])]
