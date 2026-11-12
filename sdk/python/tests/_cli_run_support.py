# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the ``fabric run``, ``verify``, ``show`` and ``doctor`` tests (spec 058
WP8-4, WP8-5): a project made by ``fabric init``, a fake model server, the local-dir sink
standing in for the Node (plain HTTP on loopback, so no Docker is needed), a fake TLS Node
with the project's own certificate, a plain httpx agent, and the G8 child program."""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import ssl
import sys
import threading
from pathlib import Path
from typing import Any

from fabric.cli import _init, _localsink

from ._cli_support import parse

#: A plain httpx tool loop against OPENAI_BASE_URL: one tool call, one answer. It knows
#: nothing about Fabric. argv[1] (optional) is its exit code.
AGENT = """
import json, os, sys
import httpx
base = os.environ["OPENAI_BASE_URL"].rstrip("/")
messages = [{"role": "user", "content": "What time is it in UTC?"}]
with httpx.Client(trust_env=False, timeout=10) as client:
    for _ in range(4):
        reply = client.post(base + "/chat/completions", json={"model": "fake-model",
                            "messages": messages}).json()["choices"][0]["message"]
        messages.append(reply)
        if not reply.get("tool_calls"):
            break
        for call in reply["tool_calls"]:
            messages.append({"role": "tool", "tool_call_id": call["id"],
                             "content": json.dumps({"time": "12:00"})})
print(json.dumps({"answer": messages[-1]["content"]}))
sys.exit(int(sys.argv[1]) if len(sys.argv) > 1 else 0)
"""

#: The G8 child: prints its argv and what it read on stdin, writes a fixed line on
#: stderr, dumps its environment, working directory and pid to argv[1], exits 7.
CHILD = """
import hashlib, json, os, sys
data = sys.stdin.buffer.read()
sys.stdout.write(json.dumps({"argv": sys.argv[1:], "stdin": hashlib.sha256(data).hexdigest()}))
sys.stdout.write("\\n")
sys.stderr.write("child stderr line\\n")
with open(sys.argv[1], "w") as handle:
    json.dump({"env": dict(os.environ), "cwd": os.getcwd(), "pid": os.getpid()}, handle)
sys.exit(7)
"""


class _Server(http.server.ThreadingHTTPServer):
    """No resolver call at bind (``HTTPServer.server_bind`` asks for this machine's name)."""

    daemon_threads = True

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "localhost", int(self.server_address[1])


class FakeModel:
    """OpenAI Chat Completions: the first request gets a ``get_time`` tool call, the next
    the answer. ``url`` is the base URL (``.../v1``)."""

    def __init__(self) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                tools = [m for m in payload["messages"] if m.get("role") == "tool"]
                message: dict[str, Any] = (
                    {"role": "assistant", "content": "It is noon in UTC."}
                    if tools
                    else {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_time_1",
                                "type": "function",
                                "function": {"name": "get_time", "arguments": '{"zone": "UTC"}'},
                            }
                        ],
                    }
                )
                body = json.dumps(
                    {
                        "id": "chatcmpl-1",
                        "object": "chat.completion",
                        "model": "fake-model",
                        "choices": [
                            {
                                "index": 0,
                                "message": message,
                                "finish_reason": "stop" if tools else "tool_calls",
                            }
                        ],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 3},
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        self.server = _Server(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class Sink:
    """The local-dir sink on loopback, standing in for the Node + sink pair: OTLP/HTTP
    requests become files in ``<data>/spans``, as `fabric up` delivers them."""

    def __init__(self, data_dir: Path) -> None:
        self.server = _localsink.serve(data_dir, "127.0.0.1", 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class FakeNode:
    """A TLS listener with the project's generated Node certificate that answers every
    OTLP request with 200 (the passivity tests' reachable Node)."""

    def __init__(self, secrets_dir: Path, port: int) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(secrets_dir / "node.crt", secrets_dir / "node.key")
        self.server = _Server(("127.0.0.1", port), Handler)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def free_port() -> int:
    import socket  # noqa: PLC0415

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def base_env(tmp_path: Path) -> dict[str, str]:
    """A clean environment: no FABRIC_* or OTEL_* of the developer's shell."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path / "home"),
        "XDG_STATE_HOME": str(tmp_path / "xdg"),
    }


def make_project(
    tmp_path: Path, env: dict[str, str], *, port: int | None = None, extra: str = ""
) -> Path:
    """``fabric init`` in a new project directory; returns it. The Node endpoint's port is
    ``port`` (default: a free one, so nothing on this machine answers)."""
    project = tmp_path / "agent-project"
    project.mkdir(exist_ok=True)
    (project / "fabric.yaml").write_text(
        "schema: fabric.config/v1\nnode:\n  endpoint: "
        f"https://localhost:{port or free_port()}\n{extra}"
    )
    _init.run(parse(["init", "--quiet"]), environ=env, cwd=project)
    return project


def secrets_dir(env: dict[str, str]) -> Path:
    (found,) = (Path(env["XDG_STATE_HOME"]) / "fabric").iterdir()
    return found / "secrets"


def write(path: Path, source: str) -> Path:
    path.write_text(source)
    return path


PYTHON = sys.executable
