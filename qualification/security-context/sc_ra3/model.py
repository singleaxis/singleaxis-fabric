# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-3 model stand-in: an OpenAI Chat Completions server on a real loopback socket.

It answers each request with the body for the number of assistant turns the request
already carries, so the same conversation gets the same bytes. The bodies come from a
script (:func:`scripted`, the fixture mode) or from what a live model answered in the
capture-on run (the live mode's capture-off twin replays them byte for byte).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping, Sequence
from http.server import BaseHTTPRequestHandler
from typing import Any

from .approval_service import LoopbackHTTPServer

MODEL = "sc-ra3-fixture-model"


def completion(index: int, turn: Sequence[tuple[str, str, dict[str, Any]]] | str) -> str:
    """One Chat Completions body: tool calls ``(id, name, arguments)`` or a final answer."""
    if isinstance(turn, str):
        message: dict[str, Any] = {"role": "assistant", "content": turn}
        finish = "stop"
    else:
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args, sort_keys=True)},
                }
                for call_id, name, args in turn
            ],
        }
        finish = "tool_calls"
    return json.dumps(
        {
            "id": f"chatcmpl-sc-ra3-{index}",
            "object": "chat.completion",
            "created": 1794614400,
            "model": MODEL,
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {
                "prompt_tokens": 50 + index,
                "completion_tokens": 12,
                "total_tokens": 62 + index,
            },
        },
        sort_keys=True,
    )


def scripted(turns: Sequence[Sequence[tuple[str, str, dict[str, Any]]] | str]) -> list[str]:
    return [completion(i, turn) for i, turn in enumerate(turns)]


class FixtureModel:
    """``start()`` binds ``127.0.0.1`` on a free port; ``base_url`` ends in ``/v1``.

    ``routes`` (task text -> bodies) answers each conversation by its user message, and
    ``expect_key`` answers 401 to a request without ``Authorization: Bearer <key>``: the
    stand-in for a live endpoint the live mode's tests use."""

    def __init__(
        self,
        bodies: Sequence[str],
        *,
        routes: Mapping[str, Sequence[str]] | None = None,
        expect_key: str | None = None,
    ) -> None:
        self.bodies = list(bodies)
        self.routes = {k: list(v) for k, v in (routes or {}).items()}
        self.expect_key = expect_key
        self.unauthorised = 0
        self.requests = 0
        self.exhausted = 0
        self._server: LoopbackHTTPServer | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("not started")
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def endpoints_json(self) -> str:
        """``FABRIC_WIRE_ENDPOINTS`` naming this plain-http model for wire capture."""
        return json.dumps(
            [
                {
                    "endpoint_id": "sc-ra3-model",
                    "dialect": "openai",
                    "hosts": ["127.0.0.1"],
                    "ports": [self.port],
                    "path_prefix": "/v1",
                    "schemes": ["http"],
                    "provider_name": "openai",
                }
            ]
        )

    def start(self) -> FixtureModel:
        model = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                turn = sum(1 for m in body.get("messages", ()) if m.get("role") == "assistant")
                task = next(
                    (m.get("content") for m in body.get("messages", ()) if m.get("role") == "user"),
                    None,
                )
                bodies = model.routes.get(str(task), model.bodies)
                model.requests += 1
                if model.expect_key is not None and self.headers.get("Authorization") != (
                    f"Bearer {model.expect_key}"
                ):
                    model.unauthorised += 1
                    data, status = b'{"error": {"message": "unauthorised"}}', 401
                elif turn >= len(bodies):
                    model.exhausted += 1
                    data, status = b'{"error": {"message": "script exhausted"}}', 500
                else:
                    data, status = bodies[turn].encode(), 200
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(
            target=self._server.serve_forever, name="sc-ra3-model", daemon=True
        ).start()
        return self

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
