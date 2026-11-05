# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The deterministic OpenAI-compatible fixture model of AR-1 (spec 056 §6.2).

It answers ``POST /v1/chat/completions`` on a real TCP socket with the scripted turns
of the AR-1 run, choosing the turn by the tool results the request feeds back:

1. no tool result yet: ``run_shell`` (T1) with ``ls DATA && sha256sum DATA/a.txt``;
2. T1's result: ``fetch_url`` (T2) of the fixture host;
3. T2's result: two ``run_shell`` calls in one response (T3a, T3b), with different
   outputs;
4. both T3 results: ``run_python`` (T4). This response is held for ``hold_ms``: the
   agent's background thread runs ``uname -a`` while the request is in flight, so no
   tool call is open (step 5); every other reply takes ``latency_ms``;
5. T4's result: the final answer (step 7).

The production script (spec 056 §6.2 "AR-1 production") inserts two turns before the
answer: T4's result gets ``run_container`` (T8, step 8) and T8's result ``run_remote``
(T9, step 9); T9's result gets the final answer.

A request that does not feed back exactly the results the script expects gets HTTP 400,
so a broken agent loop fails the run instead of drifting. Every request is counted with
the tool-call ids it carried. The model never sees Fabric; it is a stand-in for a
provider and holds no credentials.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

MODEL = "ar1-fixture-model"
T1, T2, T3A, T3B, T4 = (
    "call_ar1_t1_run_shell",
    "call_ar1_t2_fetch_url",
    "call_ar1_t3a_run_shell",
    "call_ar1_t3b_run_shell",
    "call_ar1_t4_run_python",
)
T8, T9 = "call_ar1_t8_run_container", "call_ar1_t9_run_remote"
FINAL_ANSWER = (
    "AR-1 complete: listed the data, fetched the fixture host, ran two commands and a "
    "sandboxed script."
)
# The run_python payload: deterministic output of at least 16 bytes (rule A1's floor).
PYTHON_CODE = "print('sandbox result:', sum(range(10)), 'from run_python')"
# Step 8's two commands in the container, and step 9's remote command (its output is the
# fixture E2B service's script for it).
CONTAINER_COMMANDS = "echo ar1 container step one; echo ar1 container step two"
REMOTE_COMMAND = "python3 -c 'print(\"ar1 remote sandbox result 45\")'"
REMOTE_OUTPUT = "ar1 remote sandbox result 45\n"


@dataclass(frozen=True)
class Script:
    """What the scripted turns name: the data directory, the fixture host URL and the
    SHA-256 tool of this platform (``sha256sum``)."""

    data_dir: str
    fixture_url: str
    sha_tool: str = "sha256sum"
    production: bool = False

    @property
    def step1(self) -> str:
        return f"ls {self.data_dir} && {self.sha_tool} {self.data_dir}/a.txt"

    @property
    def step3a(self) -> str:
        return f"cat {self.data_dir}/b.txt | tr a-z A-Z"

    @property
    def step3b(self) -> str:
        return f"cat {self.data_dir}/c.txt | tr a-z A-Z"

    def turn(self, fed: list[str]) -> tuple[dict[str, Any], str] | None:  # noqa: PLR0911
        """The assistant message and finish reason for a request whose tool messages
        carry the ``fed`` tool-call ids in order; ``None`` when the script has no turn
        for them."""
        if fed == []:
            return _calls(_call(T1, "run_shell", {"command": self.step1})), "tool_calls"
        if fed == [T1]:
            return _calls(_call(T2, "fetch_url", {"url": self.fixture_url})), "tool_calls"
        if fed == [T1, T2]:
            return _calls(
                _call(T3A, "run_shell", {"command": self.step3a}),
                _call(T3B, "run_shell", {"command": self.step3b}),
            ), "tool_calls"
        if fed == [T1, T2, T3A, T3B]:
            return _calls(_call(T4, "run_python", {"code": PYTHON_CODE})), "tool_calls"
        if self.production:
            if fed == [T1, T2, T3A, T3B, T4]:
                return _calls(
                    _call(T8, "run_container", {"commands": CONTAINER_COMMANDS})
                ), "tool_calls"
            if fed == [T1, T2, T3A, T3B, T4, T8]:
                return _calls(_call(T9, "run_remote", {"command": REMOTE_COMMAND})), "tool_calls"
            if fed == [T1, T2, T3A, T3B, T4, T8, T9]:
                return {"role": "assistant", "content": FINAL_ANSWER}, "stop"
            return None
        if fed == [T1, T2, T3A, T3B, T4]:
            return {"role": "assistant", "content": FINAL_ANSWER}, "stop"
        return None


def _call(call_id: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


def _calls(*calls: dict[str, Any]) -> dict[str, Any]:
    return {"role": "assistant", "content": None, "tool_calls": list(calls)}


@dataclass
class Seen:
    """One request as the model saw it: the fed tool-call ids, the HTTP status sent and
    the receive and reply times (Unix ns)."""

    fed: list[str]
    status: int
    received_ns: int
    replied_ns: int = 0


@dataclass
class FixtureModel:
    """The fixture model server; ``start()`` binds ``host`` on a free port."""

    script: Script
    host: str = "127.0.0.1"
    hold_ms: int = 900
    # Every reply takes this long (a provider takes far longer): a model call shorter than
    # the agent's declared clock uncertainty would put each effect inside the margin of the
    # previous tool call's window too, and rule A3 would then (rightly) list both.
    latency_ms: int = 40
    seen: list[Seen] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _server: ThreadingHTTPServer | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("not started")
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/v1"

    def start(self) -> FixtureModel:
        model = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                received = time.time_ns()
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path != "/v1/chat/completions":
                    self._reply(404, {"error": {"message": "not found"}})
                    return
                try:
                    payload = json.loads(body)
                    fed = [
                        str(m.get("tool_call_id"))
                        for m in payload.get("messages", ())
                        if isinstance(m, dict) and m.get("role") == "tool"
                    ]
                except (ValueError, AttributeError):
                    fed = ["<unparsed>"]
                turn = model.script.turn(fed)
                seen = Seen(fed, 200 if turn is not None else 400, received)
                with model._lock:
                    model.seen.append(seen)
                    number = len(model.seen)
                if turn is None:
                    self._reply(400, {"error": {"message": "unexpected tool results"}})
                    return
                held = model.hold_ms if fed == [T1, T2, T3A, T3B] else model.latency_ms
                time.sleep(held / 1000)  # step 5 runs while the fourth request is in flight
                message, finish = turn
                self._reply(
                    200,
                    {
                        "id": f"chatcmpl-ar1-{number}",
                        "object": "chat.completion",
                        "created": 1_790_000_000 + number,
                        "model": MODEL,
                        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                        "usage": {
                            "prompt_tokens": 40 + number,
                            "completion_tokens": 12,
                            "total_tokens": 52 + number,
                        },
                    },
                )
                seen.replied_ns = time.time_ns()

            def _reply(self, status: int, document: dict[str, Any]) -> None:
                data = json.dumps(document).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = ThreadingHTTPServer((self.host, 0), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, name="ar1-model", daemon=True).start()
        return self

    def endpoints_json(self) -> str:
        """``FABRIC_WIRE_ENDPOINTS`` naming this plain-http model for wire capture."""
        return json.dumps(
            [
                {
                    "endpoint_id": "ar1-model",
                    "dialect": "openai",
                    "hosts": [self.host],
                    "ports": [self.port],
                    "path_prefix": "/v1",
                    "schemes": ["http"],
                    "provider_name": "openai",
                }
            ]
        )

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
