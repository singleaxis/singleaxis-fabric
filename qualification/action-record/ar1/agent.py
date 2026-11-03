# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The AR-1 agent (spec 056 §6.2): a plain Python agent on the OpenAI SDK, no framework.

It imports nothing from Fabric. Capture is switched on only from outside, by the
zero-code autoload path on ``PYTHONPATH`` and ``FABRIC_*`` variables the harness sets;
with them unset the same script runs with capture off (negative variant (e)).

The loop calls the model until it answers, running each tool call it returns:

- ``run_shell(command)``: ``subprocess.run(command, shell=True, capture_output=True)``,
  with ``AR1_STEP_SECRET`` in the child's environment (the step 1 privacy canary);
- ``fetch_url(url)``: ``curl`` under ``sh``, its output cut at 64 KiB by ``head``; the
  bearer token is passed in the environment (``AR1_FETCH_TOKEN``) and expanded by the
  shell, so it is in the HTTP header and never in an argument Fabric sees (step 2's
  canary);
- ``run_python(code)``: in a child-process sandbox, ``bwrap`` when ``AR1_SANDBOX=bwrap``
  (the harness probes it), else a ``python -I`` runner that starts the code in its own
  isolated child (step 4).

Parallel tool calls of one response run concurrently on threads (step 3). With the
fourth model request a background thread, not a tool, runs ``uname -a`` while that
request is in flight (step 5; the fixture model holds that reply). Before the last
request the agent process itself opens a TCP connection to the fixture host (step 6).

Prints one JSON line: the answer, each tool call's exit code and output digest, the
background command's, the ping reply and the sandbox used. The outputs are what
variant (e) compares with capture off and on; nothing else is reported.
"""

# The agent runs fixed, scripted commands on purpose: it is the workload under test.
# ruff: noqa: S108, S602, S603, S607, PLW1510

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from openai import OpenAI

TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "Run a shell command and return its output.",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "Fetch a URL with the agent's credentials.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_python",
            "description": "Run Python code in a sandbox.",
            "parameters": {
                "type": "object",
                "properties": {"code": {"type": "string"}},
                "required": ["code"],
            },
        },
    },
]
FETCH_SCRIPT = (
    'curl -fsS --max-time 10 -H "Authorization: Bearer $AR1_FETCH_TOKEN" "$1" | head -c 65536'
)
# The python -I runner: the sandbox launcher process starts the code in an isolated child.
RUNNER = (
    "import subprocess, sys\n"
    "r = subprocess.run([sys.executable, '-I', '-S', '-c', sys.argv[1]], capture_output=True,"
    " text=True, timeout=30)\n"
    "sys.stdout.write(r.stdout); sys.stderr.write(r.stderr); raise SystemExit(r.returncode)\n"
)
BACKGROUND_TURN = 4
MAX_TURNS = 8


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _bwrap_argv(code: str) -> list[str]:
    return [
        "bwrap",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--unshare-net",
        "--die-with-parent",
        sys.executable,
        "-I",
        "-S",
        "-c",
        code,
    ]


class Agent:
    def __init__(self) -> None:
        self.client = OpenAI(
            base_url=os.environ["AR1_MODEL_BASE_URL"],
            api_key="ar1-not-a-real-key",
            max_retries=0,
            timeout=60,
        )
        self.secret = os.environ.get("AR1_STEP_SECRET", "")
        self.token = os.environ.get("AR1_FETCH_TOKEN", "")
        # The harness probes bwrap and names the sandbox: a probe here would be one more
        # subprocess in the run, which no tool call explains.
        self.sandbox = os.environ.get("AR1_SANDBOX", "python")
        self.results: list[dict[str, Any]] = []
        self.background: dict[str, Any] = {}
        self.ping = ""

    # -- tools --------------------------------------------------------------------------

    def run_shell(self, command: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "AR1_STEP_SECRET": self.secret}
        return subprocess.run(
            command, shell=True, capture_output=True, text=True, env=env, timeout=60
        )

    def fetch_url(self, url: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "AR1_FETCH_TOKEN": self.token}
        return subprocess.run(
            ["sh", "-c", FETCH_SCRIPT, "fetch_url", url],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

    def run_python(self, code: str) -> subprocess.CompletedProcess[str]:
        argv = (
            _bwrap_argv(code)
            if self.sandbox == "bwrap"
            else [sys.executable, "-I", "-S", "-c", RUNNER, code]
        )
        return subprocess.run(argv, capture_output=True, text=True, timeout=60)

    def call_tool(self, call: Any) -> dict[str, Any]:
        arguments = json.loads(call.function.arguments or "{}")
        name = call.function.name
        if name == "run_shell":
            done = self.run_shell(str(arguments["command"]))
        elif name == "fetch_url":
            done = self.fetch_url(str(arguments["url"]))
        elif name == "run_python":
            done = self.run_python(str(arguments["code"]))
        else:
            raise SystemExit(f"unknown tool {name!r}")
        text = done.stdout if done.returncode == 0 else f"exit {done.returncode}\n{done.stderr}"
        self.results.append(
            {
                "call": call.id,
                "tool": name,
                "exit_code": done.returncode,
                "stdout_sha256": _digest(done.stdout),
            }
        )
        return {"role": "tool", "tool_call_id": call.id, "content": text}

    # -- not tools ----------------------------------------------------------------------

    def background_uname(self) -> None:
        time.sleep(0.15)  # the fourth request is on the wire by now
        done = subprocess.run(["uname", "-a"], capture_output=True, text=True, timeout=30)
        self.background = {"exit_code": done.returncode, "stdout_sha256": _digest(done.stdout)}

    def ping_fixture_host(self) -> None:
        address = (os.environ["AR1_FIXTURE_HOST"], int(os.environ["AR1_FIXTURE_PORT"]))
        family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect(address)
            sock.sendall(b"AR1-PING\n")
            self.ping = sock.recv(64).decode().strip()

    # -- the loop -----------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "You are the AR-1 qualification agent."},
            {"role": "user", "content": "Inspect the data, fetch the resource, run the checks."},
        ]
        background: threading.Thread | None = None
        answer = None
        for turn in range(1, MAX_TURNS + 1):
            if turn == BACKGROUND_TURN:
                background = threading.Thread(target=self.background_uname, name="ar1-uname")
                background.start()
            response = self.client.chat.completions.create(
                model="ar1-fixture-model",
                messages=messages,  # type: ignore[arg-type]
                tools=TOOLS,  # type: ignore[arg-type]
            )
            message = response.choices[0].message
            if not message.tool_calls:
                answer = message.content
                break
            messages.append(message.model_dump(exclude_none=True))
            with ThreadPoolExecutor(max_workers=len(message.tool_calls)) as pool:
                messages.extend(pool.map(self.call_tool, message.tool_calls))
            names = [
                getattr(getattr(c, "function", None), "name", None) for c in message.tool_calls
            ]
            if "run_python" in names:
                self.ping_fixture_host()  # step 6, before the request that ends the run
        if background is not None:
            background.join()
        return {
            "answer": answer,
            "tools": self.results,
            "background": self.background,
            "ping": self.ping,
            "sandbox": self.sandbox,
        }


def main() -> int:
    summary = Agent().run()
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["answer"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
