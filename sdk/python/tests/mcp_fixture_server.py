# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A fixture MCP server for the spec 057 WP7-7 and WP7-8 tests (a test fixture only: no
product ships it).

It speaks MCP's JSON-RPC 2.0 messages by hand, over stdio (``python mcp_fixture_server.py``)
or Streamable HTTP (:class:`HttpServer`), so every message the tests assert on is one this
file wrote. It lists three tools with annotations (one destructive), and on request:

- ``change_tools``: sends ``notifications/tools/list_changed`` and lists a fourth tool from
  then on (an inventory change mid-run, F11);
- ``delete_branch``: asks the client for confirmation (``elicitation/create``) and answers
  with what the client said;
- ``read_file``: asks the client for its roots (``roots/list``);
- ``fail``: a tool result with ``isError: true`` (F14);
- a tool it does not have (``missing``): a JSON-RPC error (-32602, N25);
- any method it does not know (``resources/read``): a JSON-RPC error (-32601, N25).

Every message it receives and sends is appended to a ground-truth ledger
(``MCP_FIXTURE_LEDGER`` for stdio, :attr:`HttpServer.ledger` for HTTP) that is independent
of Fabric.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

SERVER_NAME = "repo-tools"
SERVER_VERSION = "1.4.0"
TOOLS: list[dict[str, Any]] = [
    {"name": "read_file", "description": "Read a file in a root.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "delete_branch", "description": "Delete a branch.",
     "inputSchema": {"type": "object", "properties": {"branch": {"type": "string"}}},
     "annotations": {"readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": True}},
    {"name": "fail", "description": "Always fails.",
     "inputSchema": {"type": "object", "properties": {}}},
]  # fmt: skip
EXTRA_TOOL: dict[str, Any] = {
    "name": "change_tools", "description": "Change the tool list.",
    "inputSchema": {"type": "object", "properties": {}},
    "annotations": {"openWorldHint": True},
}  # fmt: skip
CHANGED_TOOL: dict[str, Any] = {
    "name": "write_file", "description": "Write a file.",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    "annotations": {"destructiveHint": True},
}  # fmt: skip


def _text(text: str, *, error: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if error:
        result["isError"] = True
    return result


class Logic:
    """The server's behaviour, transport-free. ``ask(method, params)`` sends a request to
    the client and returns its answer; ``notify(method)`` sends a notification."""

    def __init__(self) -> None:
        self.changed = False
        self.asked = 0

    def tools(self) -> list[dict[str, Any]]:
        return [*TOOLS, EXTRA_TOOL, *([CHANGED_TOOL] if self.changed else [])]

    def handle(self, message: dict[str, Any], ask: Callable[[str, dict[str, Any]], Any],
               notify: Callable[[str], None]) -> dict[str, Any] | None:  # fmt: skip
        """The answer to one client message (``None`` for a notification or response)."""
        if "method" not in message or "id" not in message:
            return None
        ident, method = message["id"], message["method"]
        params = message.get("params") or {}
        if method == "initialize":
            result: Any = {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": "fixture server",
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": self.tools()}
        elif method == "tools/call" and params.get("name") == "missing":
            return {"jsonrpc": "2.0", "id": ident,
                    "error": {"code": -32602, "message": "Unknown tool"}}  # fmt: skip
        elif method == "tools/call":
            result = self._call(params, ask, notify)
        else:
            return {"jsonrpc": "2.0", "id": ident,
                    "error": {"code": -32601, "message": "Method not found"}}  # fmt: skip
        return {"jsonrpc": "2.0", "id": ident, "result": result}

    def _call(self, params: dict[str, Any], ask: Callable[[str, dict[str, Any]], Any],
              notify: Callable[[str], None]) -> dict[str, Any]:  # fmt: skip
        name = params.get("name")
        if name == "change_tools":
            self.changed = True
            notify("notifications/tools/list_changed")
            return _text("tools changed")
        if name == "delete_branch":
            answer = ask("elicitation/create", {
                "mode": "form",
                "message": "Delete branch " + str((params.get("arguments") or {}).get("branch")),
                "requestedSchema": {"type": "object",
                                    "properties": {"confirm": {"type": "boolean"}}},
            })  # fmt: skip
            action = answer.get("action") if isinstance(answer, dict) else None
            return _text(f"elicitation {action}", error=action != "accept")
        if name == "read_file":
            answer = ask("roots/list", {})
            roots = answer.get("roots", []) if isinstance(answer, dict) else []
            return _text(f"{len(roots)} roots")
        if name == "fail":
            return _text("permission denied: fixture", error=True)
        return _text(f"unknown tool {name}", error=True)


# ------------------------------------------------------------------------------- stdio


def _ledger(path: str | None, direction: str, message: Any) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"direction": direction, "message": message}) + "\n")


def serve_stdio() -> None:
    """One session on stdin/stdout, newline-delimited (the MCP stdio transport)."""
    ledger = os.environ.get("MCP_FIXTURE_LEDGER")
    logic = Logic()
    lines: Iterator[str] = iter(sys.stdin.readline, "")

    def send(message: dict[str, Any]) -> None:
        _ledger(ledger, "server_to_client", message)
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    def read() -> dict[str, Any] | None:
        for line in lines:
            if line.strip():
                message: dict[str, Any] = json.loads(line)
                _ledger(ledger, "client_to_server", message)
                return message
        return None

    def ask(method: str, params: dict[str, Any]) -> Any:
        logic.asked += 1
        ident = f"s-{logic.asked}"
        send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        while (message := read()) is not None:
            if message.get("id") == ident and "method" not in message:
                return message.get("result", {})
        return {}

    def notify(method: str) -> None:
        send({"jsonrpc": "2.0", "method": method})

    while (message := read()) is not None:
        answer = logic.handle(message, ask, notify)
        if answer is not None:
            send(answer)


# ------------------------------------------------------------------------ Streamable HTTP


class HttpServer:
    """One MCP endpoint (``POST /mcp``) over Streamable HTTP on 127.0.0.1. A request that
    makes the server ask the client something is answered as an SSE stream (the question,
    then the result); every other request as one JSON body. The client's answer to a
    question arrives as its own POST (202)."""

    def __init__(self) -> None:
        self.logic = Logic()
        self.ledger: list[dict[str, Any]] = []
        self.answers: dict[str, queue.Queue[Any]] = {}
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                self.send_response(405)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_DELETE(self) -> None:
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                message = json.loads(self.rfile.read(length))
                outer._record("client_to_server", message)
                if "method" not in message or "id" not in message:
                    if "id" in message and "method" not in message:
                        waiting = outer.answers.get(str(message["id"]))
                        if waiting is not None:
                            waiting.put(message.get("result", {}))
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if message["method"] == "tools/call":
                    self._stream(message)
                    return
                answer = outer.logic.handle(message, self._no_ask, lambda m: None)
                outer._record("server_to_client", answer)
                body = json.dumps(answer).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                if message["method"] == "initialize":
                    self.send_header("Mcp-Session-Id", "fixture-session-1")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            @staticmethod
            def _no_ask(method: str, params: dict[str, Any]) -> Any:
                raise RuntimeError("only tools/call asks the client")

            def _event(self, message: dict[str, Any]) -> None:
                outer._record("server_to_client", message)
                data = f"event: message\ndata: {json.dumps(message)}\n\n".encode()
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()

            def _stream(self, message: dict[str, Any]) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()

                def ask(method: str, params: dict[str, Any]) -> Any:
                    with outer.lock:
                        outer.logic.asked += 1
                        ident = f"s-{outer.logic.asked}"
                        waiting: queue.Queue[Any] = queue.Queue()
                        outer.answers[ident] = waiting
                    self._event({"jsonrpc": "2.0", "id": ident, "method": method,
                                 "params": params})  # fmt: skip
                    return waiting.get(timeout=10)

                def notify(method: str) -> None:
                    self._event({"jsonrpc": "2.0", "method": method})

                answer = outer.logic.handle(message, ask, notify)
                if answer is not None:
                    self._event(answer)
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def _record(self, direction: str, message: Any) -> None:
        with self.lock:
            self.ledger.append({"direction": direction, "message": message})

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    def __enter__(self) -> HttpServer:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":
    serve_stdio()
