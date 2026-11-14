# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-1 fixture MCP servers (spec 057 §10.2; a test fixture, never shipped).

Two servers, each speaking MCP's JSON-RPC 2.0 by hand so every message the harness checks
is one this file wrote:

- ``tickets`` lists three tools, one annotated destructive (``lookup_weather`` read-only
  and open-world, ``create_ticket``, ``delete_ticket`` destructive). A ``create_ticket``
  call changes its tool list mid-run (``notifications/tools/list_changed``; a later
  ``tools/list`` adds ``close_ticket``, destructive) and asks the user to confirm
  (``elicitation/create``, its message carrying the elicitation canary). An accepted
  confirmation creates ``TCK-1001``; anything else is a tool result with ``isError``.
- ``notes`` lists ``add_note``, ``list_notes`` and ``word_count`` (read-only). Its first
  ``add_note`` asks the client for its roots (``roots/list``), where the client exposes the
  secret-path canary.

Either server runs over stdio (``python mcp_server.py --stdio NAME``, newline-delimited
JSON-RPC on stdin and stdout) or Streamable HTTP (:class:`HttpServer`, ``POST /mcp``; a
call that makes the server ask the client something is answered as an SSE stream). Every
message a server receives and sends is appended to its ground-truth ledger, written by
this file and never by Fabric: ``SC_RA1_MCP_LEDGER`` for stdio, a file the harness names
for HTTP.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

PROTOCOL = "2025-06-18"
VERSIONS = {"tickets": "2.1.0", "notes": "0.9.3"}
LEDGER_ENV = "SC_RA1_MCP_LEDGER"
CANARY_ENV = "SC_RA1_ELICITATION_CANARY"


def _tool(
    name: str,
    description: str,
    properties: dict[str, Any],
    annotations: dict[str, bool] | None = None,
) -> dict[str, Any]:
    tool: dict[str, Any] = {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties},
    }
    if annotations is not None:
        tool["annotations"] = annotations
    return tool


TICKETS: list[dict[str, Any]] = [
    _tool(
        "lookup_weather",
        "Current weather for a city.",
        {"city": {"type": "string"}},
        {"readOnlyHint": True, "openWorldHint": True},
    ),
    _tool(
        "create_ticket",
        "Create a ticket.",
        {"title": {"type": "string"}, "body": {"type": "string"}},
        {"readOnlyHint": False, "destructiveHint": False},
    ),
    _tool(
        "delete_ticket",
        "Delete a ticket.",
        {"id": {"type": "string"}},
        {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
    ),
]
CLOSE_TICKET = _tool(
    "close_ticket", "Close a ticket.", {"id": {"type": "string"}}, {"destructiveHint": True}
)
NOTES: list[dict[str, Any]] = [
    _tool("add_note", "Add a note.", {"text": {"type": "string"}}, {"readOnlyHint": False}),
    _tool("list_notes", "List the notes.", {}, {"readOnlyHint": True}),
    _tool("word_count", "Count the words in the notes.", {}, {"readOnlyHint": True}),
]
WEATHER = {"Berlin": "8C, light rain", "Lisbon": "19C, sunny"}


def _text(text: str, *, error: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if error:
        result["isError"] = True
    return result


class Logic:
    """One server's behaviour, transport-free. ``ask(method, params)`` sends a request to
    the client and returns its answer; ``notify(method)`` sends a notification."""

    def __init__(self, name: str, canary: str) -> None:
        if name not in VERSIONS:
            raise ValueError(f"unknown fixture server {name!r}: use tickets or notes")
        self.name, self.canary = name, canary
        self.changed = False
        self.asked = 0
        self.notes: list[str] = []
        self.roots: int | None = None

    def tools(self) -> list[dict[str, Any]]:
        if self.name == "notes":
            return list(NOTES)
        return [*TICKETS, *([CLOSE_TICKET] if self.changed else [])]

    def handle(
        self,
        message: dict[str, Any],
        ask: Callable[[str, dict[str, Any]], Any],
        notify: Callable[[str], None],
    ) -> dict[str, Any] | None:
        """The answer to one client message (``None`` for a notification or response)."""
        if "method" not in message or "id" not in message:
            return None
        ident, method = message["id"], message["method"]
        params = message.get("params") or {}
        if method == "initialize":
            result: Any = {
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": self.name, "version": VERSIONS[self.name]},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": self.tools()}
        elif method == "tools/call":
            result = self._call(params, ask, notify)
        else:
            return {
                "jsonrpc": "2.0",
                "id": ident,
                "error": {"code": -32601, "message": "Method not found"},
            }
        return {"jsonrpc": "2.0", "id": ident, "result": result}

    def _call(
        self,
        params: dict[str, Any],
        ask: Callable[[str, dict[str, Any]], Any],
        notify: Callable[[str], None],
    ) -> dict[str, Any]:
        name, args = params.get("name"), params.get("arguments") or {}
        if self.name == "notes":
            return self._notes(str(name), args, ask)
        if name == "lookup_weather":
            city = str(args.get("city"))
            return _text(f"{city}: {WEATHER.get(city, 'no data')}")
        if name == "create_ticket":
            if not self.changed:
                self.changed = True
                notify("notifications/tools/list_changed")
            answer = ask(
                "elicitation/create",
                {
                    "message": f"Create the ticket {args.get('title')!s}? {self.canary}",
                    "requestedSchema": {
                        "type": "object",
                        "properties": {"confirm": {"type": "boolean"}},
                    },
                },
            )
            action = answer.get("action") if isinstance(answer, dict) else None
            if action == "accept":
                return _text("Created TCK-1001")
            return _text(f"ticket not created: the user answered {action}", error=True)
        if name in ("delete_ticket", "close_ticket"):
            return _text(f"{name}: no such ticket", error=True)
        return _text(f"unknown tool {name}", error=True)

    def _notes(
        self, name: str, args: dict[str, Any], ask: Callable[[str, dict[str, Any]], Any]
    ) -> dict[str, Any]:
        if name == "add_note":
            if self.roots is None:
                answer = ask("roots/list", {})
                roots = answer.get("roots", []) if isinstance(answer, dict) else []
                self.roots = len(roots) if isinstance(roots, list) else 0
            self.notes.append(str(args.get("text")))
            return _text(f"note {len(self.notes)} added")
        if name == "list_notes":
            return _text("\n".join(f"{i}. {n}" for i, n in enumerate(self.notes, 1)) or "none")
        if name == "word_count":
            return _text(f"{sum(len(n.split()) for n in self.notes)} words")
        return _text(f"unknown tool {name}", error=True)


def _append(path: str | os.PathLike[str] | None, row: dict[str, Any]) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


# ------------------------------------------------------------------------------- stdio


def serve_stdio(name: str) -> None:
    """One session on stdin/stdout, newline-delimited (the MCP stdio transport)."""
    ledger = os.environ.get(LEDGER_ENV)
    logic = Logic(name, os.environ.get(CANARY_ENV, ""))
    lines: Iterator[str] = iter(sys.stdin.readline, "")

    def send(message: dict[str, Any]) -> None:
        _append(
            ledger,
            {
                "server": name,
                "transport": "stdio",
                "direction": "server_to_client",
                "message": message,
            },
        )
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    def read() -> dict[str, Any] | None:
        for line in lines:
            if line.strip():
                message: dict[str, Any] = json.loads(line)
                _append(
                    ledger,
                    {
                        "server": name,
                        "transport": "stdio",
                        "direction": "client_to_server",
                        "message": message,
                    },
                )
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
    """One server's MCP endpoint (``POST /mcp``) over Streamable HTTP on 127.0.0.1. A
    ``tools/call`` is answered as an SSE stream (any question to the client, then the
    result); every other request as one JSON body. The client's answer to a question
    arrives as its own POST (202)."""

    def __init__(self, name: str, ledger: Path, canary: str) -> None:
        self.name, self.ledger_path = name, ledger
        self.logic = Logic(name, canary)
        self.answers: dict[str, queue.Queue[Any]] = {}
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def _empty(self, status: int) -> None:
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:
                self._empty(405)

            def do_DELETE(self) -> None:
                self._empty(200)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                message = json.loads(self.rfile.read(length))
                outer._record("client_to_server", message)
                if "method" not in message or "id" not in message:
                    if "id" in message and "method" not in message:
                        waiting = outer.answers.get(str(message["id"]))
                        if waiting is not None:
                            waiting.put(message.get("result", {}))
                    self._empty(202)
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
                    self.send_header("Mcp-Session-Id", f"{outer.name}-session-1")
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
                    self._event({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
                    return waiting.get(timeout=30)

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
            _append(
                self.ledger_path,
                {
                    "server": self.name,
                    "transport": "http",
                    "direction": direction,
                    "message": message,
                },
            )

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.origin}/mcp"

    def __enter__(self) -> HttpServer:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--stdio":  # noqa: PLR2004
        raise SystemExit("usage: mcp_server.py --stdio tickets|notes")
    serve_stdio(sys.argv[2])
