# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The canary of ``fabric verify`` (spec 058 §5.6 step 3): ``python -m fabric.cli._canary
LABEL`` installs wire capture from its environment (the project's compiled environment,
which ``verify`` passes), sends one model exchange to a fake model server it starts on
loopback, closes the run and delivers the spool. Everything after that, the Node, the
destination and the reader, is the user's real path.

It runs in its own process so its capture never touches the CLI's, and prints one JSON
line: whether capture installed, whether the Node took the records, and, when capture did
not install, the SDK's reason and fix (from its status file). It contacts only the fake
model server and the configured Node; it resolves no name of its own (I4)."""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ENDPOINT_ID = "fabric-canary"
MODEL = "fabric-canary"
CLOSE_TIMEOUT_S = 20.0
_ANSWER = {
    "id": "chatcmpl-fabric-canary",
    "object": "chat.completion",
    "created": 0,
    "model": MODEL,
    "choices": [
        {
            "index": 0,
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": "canary received"},
        }
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
}


class _Model(http.server.BaseHTTPRequestHandler):
    """An OpenAI Chat Completions endpoint that answers every request the same way."""

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = json.dumps(_ANSWER).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _Server(http.server.ThreadingHTTPServer):
    """``HTTPServer.server_bind`` asks the resolver for this machine's name: skipped (I4)."""

    daemon_threads = True

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "localhost", int(self.server_address[1])


def _endpoints(existing: str | None, port: int) -> str:
    matchers: list[Any] = []
    if existing:
        try:
            parsed = json.loads(existing)
            matchers = parsed if isinstance(parsed, list) else []
        except ValueError:
            matchers = []
    matchers.append(
        {
            "endpoint_id": ENDPOINT_ID,
            "dialect": "openai",
            "hosts": ["127.0.0.1"],
            "ports": [port],
            "schemes": ["http"],
            "path_prefix": "/v1",
        }
    )
    return json.dumps(matchers, separators=(",", ":"))


def _status(path: str) -> dict[str, Any] | None:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def run(label: str, status_file: str) -> dict[str, Any]:
    server = _Server(("127.0.0.1", 0), _Model)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = int(server.server_address[1])
    for name in ("FABRIC_WIRE_AUTOLOAD", "FABRIC_RUN_ID", "FABRIC_RUN_RESUME_TOKEN"):
        os.environ.pop(name, None)
    os.environ["FABRIC_WIRE_ENDPOINTS"] = _endpoints(os.environ.get("FABRIC_WIRE_ENDPOINTS"), port)
    os.environ["FABRIC_WIRE_STATUS_FILE"] = status_file
    out: dict[str, Any] = {"label": label, "installed": False, "delivered": False}
    try:
        import httpx  # noqa: PLC0415
    except ImportError:
        out["error"] = "httpx_missing"
        return out
    from fabric import wire  # noqa: PLC0415

    handle = wire.install_from_env()
    if handle is None or not handle.capturing:
        out["status"] = _status(status_file)
        return out
    out["installed"] = True
    try:
        with wire.run(label), httpx.Client(trust_env=False, timeout=10.0) as client:
            response = client.post(
                f"http://127.0.0.1:{port}/v1/chat/completions",
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": "fabric verify canary"}],
                },
            )
            out["model_status"] = response.status_code
    except Exception as exc:  # the fake server is ours: a failure here is reported, not raised
        out["error"] = type(exc).__name__
    out["delivered"] = bool(handle.close(CLOSE_TIMEOUT_S))
    out["status"] = _status(status_file)
    server.shutdown()
    return out


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:  # noqa: PLR2004 - LABEL STATUS_FILE
        sys.stderr.write("usage: python -m fabric.cli._canary LABEL STATUS_FILE\n")
        return 2
    sys.stdout.write(json.dumps(run(args[0], args[1]), sort_keys=True, default=str) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
