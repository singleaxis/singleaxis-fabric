# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The live model key never reaches a process the agent starts.

The tools the model asks for (``run_shell``, ``python_exec``) and the stdio MCP servers are
child processes of the agent. Before the fix they inherited the agent's whole environment,
the key included, so a model that ran ``env`` got the key back as a tool result: into the
outputs file, the next request body (retained in the content store under
``model.exchange.request``) and the recorded cassette's following responses.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from sc_ra1 import agent
from sc_ra1.harness import agent_environment

KEY = "stand-in-" + os.urandom(8).hex()
KEY_ENV = "SC_RA1_MODEL_KEY"


def _completion(message: dict[str, Any], finish: str) -> bytes:
    return json.dumps({"choices": [{"message": message, "finish_reason": finish}]}).encode()


REPLIES = [
    _completion(
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "run_shell",
                        "arguments": json.dumps({"command": f"env; echo key=${KEY_ENV}"}),
                    },
                },
                {
                    "id": "call_2",
                    "type": "function",
                    "function": {
                        "name": "python_exec",
                        "arguments": json.dumps(
                            {"code": f"import os; print(os.environ.get('{KEY_ENV}'))"}
                        ),
                    },
                },
            ],
        },
        "tool_calls",
    ),
    _completion({"role": "assistant", "content": "done"}, "stop"),
]


def test_take_model_key_removes_the_variable() -> None:
    environ = {KEY_ENV: "k", "OTHER": "x"}
    assert agent.take_model_key({"api_key_env": KEY_ENV}, environ) == "k"
    assert environ == {"OTHER": "x"}
    assert agent.take_model_key({"api_key_env": None}, environ) == ""
    assert agent.take_model_key({}, environ) == ""


def test_a_tool_that_prints_the_environment_never_sees_the_model_key(tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:
            return

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            seen.append({"auth": self.headers.get("authorization"), "body": body})
            reply = REPLIES[len(seen) - 1]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    plan = {
        "model": "m",
        "api_key_env": KEY_ENV,
        "workspace": str(workspace),
        "ledger": str(tmp_path / "ledger.jsonl"),
        "outputs": str(tmp_path / "outputs.json"),
        "system_prompt": "s",
        "sessions": [
            {
                "name": "key",
                "kind": "loop",
                "dialect": "openai",
                "stream": False,
                "max_turns": 3,
                "task": "t",
                "base_url": f"http://127.0.0.1:{server.server_address[1]}/v1",
                "replay": False,
                "tools_first": ["run_shell", "python_exec"],
                "tools_then": ["run_shell", "python_exec"],
                "tool_choice_first": None,
            }
        ],
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_"))}
    env.pop("PYTHONPATH", None)
    env[KEY_ENV] = KEY
    try:
        done = subprocess.run(  # noqa: S603 - this interpreter, the harness's own agent
            [sys.executable, agent.__file__, str(plan_path)],
            env=env,
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
    assert done.returncode == 0, done.stderr
    # the endpoint got the key, in the header only
    assert [r["auth"] for r in seen] == [f"Bearer {KEY}"] * 2
    assert all(KEY.encode() not in r["body"] for r in seen)
    # the tools ran, and saw no key
    outputs = json.loads((tmp_path / "outputs.json").read_text())
    tools = outputs["key"]["tools"]
    assert [t["exit_code"] for t in tools] == [0, 0]
    assert "key=\n" in tools[0]["stdout"] and tools[1]["stdout"] == "None\n"
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert KEY.encode() not in path.read_bytes(), path
    assert KEY not in done.stdout + done.stderr


def test_the_agent_is_not_given_the_callers_credentials() -> None:
    """A live model can ask ``run_shell`` for ``env``; what it prints goes to the model
    endpoint in the next request and into the content store. The agent's environment leaves
    out every variable named like a credential, and the harness's and Fabric's own."""
    caller = {
        "PATH": "/usr/bin",
        "HOME": "/home/u",
        "LANG": "C.UTF-8",
        "AWS_SECRET_ACCESS_KEY": "a",
        "GH_TOKEN": "b",
        "ANTHROPIC_API_KEY": "c",
        "db_password": "d",
        "SSH_AUTH_SOCK": "/run/agent.sock",
        "GOOGLE_APPLICATION_CREDENTIALS": "/k.json",
        "SC_RA1_MODEL_KEY": "e",
        "SC_RA1_MODEL_KEY_FILE": "/k",
        "FABRIC_WIRE_ID_KEY": "f",
        "OTEL_EXPORTER_OTLP_HEADERS": "g",
        "PYTHONPATH": "/x",
    }
    assert agent_environment(caller) == {"PATH": "/usr/bin", "HOME": "/home/u", "LANG": "C.UTF-8"}
