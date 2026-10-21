# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Per-process wire-capture throughput (chaos report D4).

One captured process offers small model calls from many threads against a loopback fake
model, with the agent spool (encrypted, fsync'd) and a loopback fake Node that accepts
every span and content record. Reports what the capture worker kept up with:

- ``offered``: model calls the application made (each one is a matched exchange);
- ``spooled``: exchange records made durable on the spool;
- ``dropped``: exchanges shed (``queue_full``, accounted as losses);
- ``capture_per_s``: spooled exchanges per second of load (the worker's sustained rate);
- ``delivered`` / ``drain_s``: records delivered to the fake Node, and how long after the
  load the backlog took to deliver.

Usage::

    python scripts/qualification/bench_wire_capture_throughput.py \
        [--threads 64] [--seconds 10] [--no-node]

``--no-node`` leaves the Node unreachable (spool only), isolating the capture worker from
the sender's delivery work. ``--model-latency-ms`` makes each model call wait (an LLM's
think time), so application threads mostly wait on I/O as real agents do; without it the
application threads are CPU-bound against a loopback model and take the GIL from the
capture worker (the worker then gets roughly one GIL turn in ``threads`` + 1). Needs the SDK with ``otlp`` and ``signing`` extras and httpx.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

TENANT, SOURCE = "t-bench", "s-" + "b" * 32
REPLY = json.dumps({
    "id": "chatcmpl-bench", "object": "chat.completion", "model": "bench-model",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                 "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 12, "completion_tokens": 1},
}).encode()  # fmt: skip


class _Quiet(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _reply(self, body: bytes, ctype: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Model(_Quiet):
    latency_s = 0.0

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.latency_s:
            time.sleep(self.latency_s)  # a model's think time: the app waits on I/O
        self._reply(REPLY, "application/json")


class _Node(_Quiet):
    counts: dict[str, int] = {"/v1/traces": 0, "/v1/logs": 0}
    lock = threading.Lock()

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with self.lock:
            self.counts[self.path] = self.counts.get(self.path, 0) + 1
        self._reply(b"", "application/x-protobuf")


def _serve(handler: type[BaseHTTPRequestHandler]) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _child(args: argparse.Namespace) -> None:
    """The captured application: ``--threads`` threads calling the model for ``--seconds``."""
    import httpx  # noqa: PLC0415

    import fabric.wire  # noqa: PLC0415

    handle = fabric.wire._HANDLE  # installed by the autoload, as in production
    assert handle is not None and handle.capturing, "capture not installed"
    url, stop, offered = os.environ["BENCH_MODEL_URL"], threading.Event(), [0]
    lock = threading.Lock()
    body = json.dumps({"model": "bench-model", "messages": [
        {"role": "user", "content": "x" * args.body_bytes}]}).encode()  # fmt: skip

    def worker() -> None:
        with httpx.Client(timeout=30) as client:
            while not stop.is_set():
                client.post(
                    url, content=body, headers={"Content-Type": "application/json"}
                )
                with lock:
                    offered[0] += 1

    threads = [threading.Thread(target=worker) for _ in range(args.threads)]
    started = time.monotonic()
    for thread in threads:
        thread.start()
    time.sleep(args.seconds)
    stop.set()
    for thread in threads:
        thread.join()
    load_s = time.monotonic() - started
    at_stop = handle.stats()
    drained = handle.flush(args.drain_timeout)
    drain_s = time.monotonic() - started - load_s
    stats = handle.stats()
    print(json.dumps({
        "offered": offered[0], "load_s": round(load_s, 2), "flushed": drained,
        "drain_s": round(drain_s, 2), "spooled_at_stop": at_stop.spooled,
        **{k: getattr(stats, k) for k in ("submitted", "dropped", "spooled", "delivered",
                                          "spool_full_drops", "internal_errors")},
    }))  # fmt: skip


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--threads", type=int, default=64)
    parser.add_argument("--seconds", type=float, default=10.0)
    parser.add_argument("--body-bytes", type=int, default=256)
    parser.add_argument("--drain-timeout", type=float, default=120.0)
    parser.add_argument("--model-latency-ms", type=float, default=0.0)
    parser.add_argument("--no-node", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        _child(args)
        return 0
    _Model.latency_s = args.model_latency_ms / 1000
    model, node = _serve(_Model), _serve(_Node)
    node_port = (
        9 if args.no_node else node.server_address[1]
    )  # discard port: unreachable
    with tempfile.TemporaryDirectory(prefix="fabric-bench-") as tmp:
        root = Path(tmp)
        roles = (
            "model.exchange.request",
            "model.exchange.response",
            "model.exchange.part",
        )
        policy = {
            "schema_version": "fabric.deployment-policy/v1", "policy_id": "bench",
            "policy_version": 1, "tenant_id": TENANT, "workload_id": "bench",
            "privacy": dict.fromkeys(roles, "retain_original"),
            "storage": {"backend": "local", "region": "local", "key_id": "bench-key"},
            "retention": {"days": 1}, "required_integrations": [],
            "deployment": {
                "profile": "production", "image_digest": "sha256:" + "0" * 64,
                "tls_required": True, "encrypted_store_required": True,
            },
        }  # fmt: skip
        (root / "policy.json").write_text(json.dumps(policy), "utf-8")
        autoload = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "fabric.wire", "--print-autoload-path"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()  # fmt: skip
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("FABRIC_", "OTEL_"))
        }
        env |= {
            # An outer PYTHONPATH (e.g. another checkout's src, for before/after) is kept.
            "PYTHONPATH": os.pathsep.join(filter(None, [autoload, os.environ.get("PYTHONPATH")])),
            "FABRIC_WIRE_AUTOLOAD": "1", "FABRIC_TENANT_ID": TENANT,
            "FABRIC_SOURCE_ID": SOURCE, "FABRIC_WIRE_SPOOL_DIR": str(root / "spool"),
            "FABRIC_WIRE_CONTENT_ENDPOINT": f"http://127.0.0.1:{node_port}/v1/logs",
            "OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{node_port}",
            "OTEL_SERVICE_NAME": "bench-agent", "FABRIC_WIRE_ID_KEY": "k" * 32,
            "FABRIC_CAPTURE_POLICY": str(root / "policy.json"),
            "FABRIC_WIRE_SPOOL_KEY": base64.b64encode(b"\x07" * 32).decode(),
            "FABRIC_WIRE_ENDPOINTS": json.dumps([{
                "endpoint_id": "bench-model", "dialect": "openai", "hosts": ["127.0.0.1"],
                "ports": [model.server_address[1]], "path_prefix": "/v1",
                "schemes": ["http"], "provider_name": "openai",
            }]),
            "BENCH_MODEL_URL": f"http://127.0.0.1:{model.server_address[1]}/v1/chat/completions",
        }  # fmt: skip
        argv = [sys.executable, __file__, "--child", "--threads", str(args.threads),
                "--seconds", str(args.seconds), "--body-bytes", str(args.body_bytes),
                "--drain-timeout", str(0 if args.no_node else args.drain_timeout)]  # fmt: skip
        done = subprocess.run(
            argv, env=env, capture_output=True, text=True, check=False
        )  # noqa: S603
        if done.returncode:
            sys.stderr.write(done.stderr)
            return done.returncode
        result: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    result["capture_per_s"] = round(result["spooled_at_stop"] / result["load_s"], 1)
    result["offered_per_s"] = round(result["offered"] / result["load_s"], 1)
    result["drop_pct"] = round(100 * result["dropped"] / max(1, result["offered"]), 1)
    result["node_spans_posts"] = _Node.counts.get("/v1/traces", 0)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
