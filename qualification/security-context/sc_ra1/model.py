# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-1 fixture model: replays recorded responses, byte for byte.

A loopback HTTP server that answers ``POST /v1/chat/completions`` and ``POST /v1/messages``
from a cassette (``cassette.json``): each session's responses in the order the agent asks
for them, picked by the session header the agent sends in replay. Nothing is generated:
every body is one a real model returned (the session's ``provenance`` says where and
when), except the provider-safety bodies, which are the documented response shapes of the
contract fixtures (``contracts/coverage/v1/fixtures/provider-safety``; no provider returns a
filtered or refused response on demand, spec 057 revision 3.6 note 5).

A request past the end of a session's responses gets 410 and the agent stops; the harness
fails any run in which that happens.
"""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .agent import SESSION_HEADER

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CASSETTE = HERE / "cassette.json"


@dataclass(frozen=True)
class Reply:
    status: int
    content_type: str
    body: bytes


def _fixture_reply(entry: Mapping[str, Any]) -> Reply:
    """A provider-safety contract fixture case, as the provider would send it."""
    doc = json.loads((REPO / entry["contract_fixture"]).read_text(encoding="utf-8"))
    case = doc["cases"][int(entry["case"])]
    if case.get("stream"):
        raise ValueError("SC-RA-1 replays the non-streamed safety cases only")
    body = json.dumps(case["response"], separators=(",", ":")).encode()
    return Reply(200, "application/json", body)


def load(path: Path = CASSETTE) -> dict[str, list[Reply]]:
    """Every session's replies, in order."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, list[Reply]] = {}
    for name, session in doc["sessions"].items():
        replies = []
        for entry in session["responses"]:
            if "contract_fixture" in entry:
                replies.append(_fixture_reply(entry))
            else:
                replies.append(
                    Reply(
                        int(entry["status"]),
                        entry["content_type"],
                        base64.b64decode(entry["body_b64"]),
                    )
                )
        out[name] = replies
    return out


@dataclass
class FixtureModel:
    """The replay server on 127.0.0.1 (``base_url`` ends in ``/v1``)."""

    replies: dict[str, list[Reply]]
    served: dict[str, int] = field(default_factory=dict)
    exhausted: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        model = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                session = self.headers.get(SESSION_HEADER, "")
                reply = model.next(session, self.path)
                self.send_response(reply.status)
                self.send_header("Content-Type", reply.content_type)
                self.send_header("Content-Length", str(len(reply.body)))
                self.end_headers()
                self.wfile.write(reply.body)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def next(self, session: str, path: str) -> Reply:
        with self._lock:
            index = self.served.get(session, 0)
            self.served[session] = index + 1
            replies = self.replies.get(session, [])
            if index >= len(replies):
                self.exhausted.append(f"{session}#{index} {path}")
                return Reply(410, "application/json", b'{"error":"cassette exhausted"}')
            return replies[index]

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def start(self) -> FixtureModel:
        self._thread.start()
        return self

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
