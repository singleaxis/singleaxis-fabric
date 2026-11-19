#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The fixture model server of the TTFR test (spec 058 §3.3): an OpenAI-compatible
``/v1/chat/completions`` endpoint that asks for one ``get_weather`` tool call, then answers
with the tool's result. Over TLS when given a certificate, so the agent reaches it by a host
name that is in no endpoint table (``my-llm.example.com``). Standard library only.

    python3 model_server.py --port 443 --cert leaf.crt --key leaf.key \\
        --api-key KEY --ready-file ready.json
"""

from __future__ import annotations

import argparse
import contextlib
import json
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ANSWER = "It is 18.5 C in Lisbon."


def handler(api_key: str, counter: dict[str, int]) -> type[BaseHTTPRequestHandler]:
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            with lock:
                counter["requests"] += 1
                call = counter["requests"]
            if not self.path.endswith("/chat/completions"):
                self._send(404, {"error": {"message": f"no route {self.path}"}})
                return
            if self.headers.get("Authorization") != f"Bearer {api_key}":
                self._send(401, {"error": {"message": "bad key"}})
                return
            messages = json.loads(body)["messages"]
            results = [m for m in messages if m.get("role") == "tool"]
            if not results:
                message: dict[str, Any] = {
                    "role": "assistant", "content": None,
                    "tool_calls": [{"id": f"call_weather_{call}", "type": "function",
                                    "function": {"name": "get_weather",
                                                 "arguments": json.dumps({"city": "Lisbon"})}}],
                }  # fmt: skip
                finish = "tool_calls"
            else:
                celsius = json.loads(results[-1]["content"])["celsius"]
                message = {
                    "role": "assistant",
                    "content": f"It is {celsius} C in Lisbon.",
                }
                finish = "stop"
            self._send(200, {
                "id": f"chatcmpl-ttfr-{call}", "object": "chat.completion", "created": 1_763_000_000,
                "model": "fixture-model-2026",
                "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                "usage": {"prompt_tokens": 20 + call, "completion_tokens": 9, "total_tokens": 29 + call},
            })  # fmt: skip

        def _send(self, status: int, document: dict[str, Any]) -> None:
            data = json.dumps(document).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    options = parser.parse_args(argv)
    counter = {"requests": 0}
    server = ThreadingHTTPServer(
        (options.host, options.port), handler(options.api_key, counter)
    )
    if options.cert:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(options.cert, options.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    options.ready_file.write_text(json.dumps({"port": server.server_address[1]}))
    with contextlib.suppress(KeyboardInterrupt):  # the harness stops it: a clean exit
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
