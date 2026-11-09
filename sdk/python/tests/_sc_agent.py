# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The agent of the spec 057 P0 acceptance runs (SC-0 and SC-CP, §10.1).

A plain, hand-written Python tool loop: it posts OpenAI Chat Completions requests with
httpx's default transport to a fixture model, dispatches each tool call through its own
code and runs the tool as a subprocess. No framework, no agent SDK, no Fabric import in
the loop itself: capture comes only from what the harness installs around it (wire
capture, the exec hook) and, where a run says so, from explicit ``fabric.records`` lines
the agent's own code adds.

- :class:`FixtureModel` is a local HTTP server that answers each request from a fixed
  script, chosen by how many assistant turns the request already carries. Its bytes are
  deterministic: the same request gives the same response bytes.
- :class:`ToolLoop` is the agent. ``check`` is its in-code permission check
  (``can_use(user, tool, args)``); the dispatcher calls it before each tool and returns
  :data:`REFUSAL` when it says no or raises ``PermissionError``.
- :class:`Ledger` is the harness's ground truth, independent of Fabric: it wraps the check
  and writes ``(provider tool-call id, decision)`` for every check to its own file.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx

MODEL = "fixture-model"
USER = "dev-7"
REFUSAL = "permission denied"
SYSTEM_PROMPT = "You operate a build workspace through the tools you are given."
TOOLS: list[dict[str, Any]] = [
    {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": {arg: {"type": "string"}},
                       "required": [arg]},
    }}
    for name, arg, description in (
        ("run_command", "cmd", "Run one command in the workspace."),
        ("list_dir", "path", "List a directory."),
        ("read_file", "path", "Print a file."),
        ("admin_shell", "cmd", "Run a command as the workspace administrator."),
    )
]  # fmt: skip


@dataclass(frozen=True)
class Call:
    """One tool call the fixture model issues: its provider id, tool and arguments."""

    id: str
    name: str
    args: Mapping[str, str]


Turn = Sequence[Call] | str  # tool calls, or the final answer text


def _completion(index: int, turn: Turn) -> bytes:
    if isinstance(turn, str):
        message: dict[str, Any] = {"role": "assistant", "content": turn}
        finish = "stop"
    else:
        message = {"role": "assistant", "content": None, "tool_calls": [
            {"id": c.id, "type": "function",
             "function": {"name": c.name, "arguments": json.dumps(dict(c.args), sort_keys=True)}}
            for c in turn
        ]}  # fmt: skip
        finish = "tool_calls"
    body = {
        "id": f"chatcmpl-sc-{index}", "object": "chat.completion", "created": 1791331200,
        "model": MODEL,
        "choices": [{"index": 0, "finish_reason": finish, "message": message}],
        "usage": {"prompt_tokens": 40 + index, "completion_tokens": 9},
    }  # fmt: skip
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class FixtureModel:
    """A local Chat Completions server answering from ``script`` (one entry per turn)."""

    def __init__(self, script: Sequence[Turn]) -> None:
        self.script = list(script)
        self.requests: list[bytes] = []
        model = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                model.requests.append(raw)
                messages = json.loads(raw)["messages"]
                turn = sum(1 for m in messages if m["role"] == "assistant")
                body = _completion(turn, model.script[min(turn, len(model.script) - 1)])
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1/chat/completions"

    def __enter__(self) -> FixtureModel:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


# --------------------------------------------------------------------- the agent's tools
def _command(name: str, args: Mapping[str, str]) -> list[str]:
    if name in ("run_command", "admin_shell"):
        return shlex.split(args["cmd"])
    if name == "list_dir":
        return ["ls", args["path"]]
    if name == "read_file":
        return ["cat", args["path"]]
    raise KeyError(name)


@dataclass
class Outcome:
    """What the agent observably did for one tool call: the result it sent the model, and
    the process it ran (argv, stdout, stderr, exit code), if any."""

    call_id: str
    result: str
    argv: list[str] | None = None
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"call_id": self.call_id, "result": self.result, "argv": self.argv,
                "stdout": self.stdout, "stderr": self.stderr,
                "exit_code": self.exit_code}  # fmt: skip


def can_use(user: str, tool: str, args: Mapping[str, str]) -> bool:
    """The agent's own permission check: an allow-list in plain code. ``admin_shell`` is
    refused by raising, as a helper that guards privileged entry points does."""
    if tool == "admin_shell":
        raise PermissionError(f"{user} is not a workspace administrator")
    if tool == "run_command":
        return shlex.split(args["cmd"])[0] in ("echo", "printf", "true")
    if tool == "read_file":
        return not args["path"].startswith("/etc/")
    return tool == "list_dir"


Check = Callable[[str, str, Mapping[str, str]], Any]
# A hook around each tool call, called by the agent's dispatcher: (call, phase, outcome).
Around = Callable[[Call, str, "Outcome | None"], "str | None"]


@dataclass
class ToolLoop:
    """The plain tool loop. ``check`` is consulted before every tool; ``around`` (optional)
    lets a run's own code add explicit lines around a call: ``before`` may return a refusal
    text, which skips the tool. ``report_call_id`` makes the dispatcher pass the provider
    tool-call id to a ``control_check`` scope (SC-CP's third run)."""

    url: str
    check: Check = can_use
    around: Around | None = None
    report_call_id: bool = False
    caught: list[BaseException] = field(default_factory=list)
    outcomes: list[Outcome] = field(default_factory=list)
    answer: str | None = None

    def _allowed(self, call: Call) -> bool:
        if self.report_call_id:
            from fabric import records  # noqa: PLC0415 - only the third SC-CP run reports ids

            with records.control_check(kind="permission_check", control="tool-acl") as scope:
                scope.gated_tool_call_id = call.id
                allowed = self.check(USER, call.name, call.args)
                scope.result = allowed
            return bool(allowed)
        return bool(self.check(USER, call.name, call.args))

    def dispatch(self, call: Call) -> Outcome:
        if self.around is not None:
            refusal = self.around(call, "before", None)
            if refusal is not None:
                return Outcome(call.id, refusal)
        try:
            allowed = self._allowed(call)
        except PermissionError as exc:
            self.caught.append(exc)
            allowed = False
        if not allowed:
            return Outcome(call.id, REFUSAL)
        argv = _command(call.name, call.args)
        done = subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603
        result = done.stdout if done.returncode == 0 else f"exit {done.returncode}: {done.stderr}"
        outcome = Outcome(call.id, result, argv, done.stdout, done.stderr, done.returncode)
        if self.around is not None:
            self.around(call, "after", outcome)
        return outcome

    def run(self, task: str) -> list[Outcome]:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": task},
        ]  # fmt: skip
        with httpx.Client(timeout=30.0) as client:
            for _ in range(16):
                response = client.post(self.url, json={
                    "model": MODEL, "messages": messages, "tools": TOOLS,
                })  # fmt: skip
                response.raise_for_status()
                message = response.json()["choices"][0]["message"]
                messages.append(message)
                calls = message.get("tool_calls") or []
                if not calls:
                    self.answer = message.get("content")
                    break
                for raw in calls:
                    call = Call(raw["id"], raw["function"]["name"],
                                json.loads(raw["function"]["arguments"]))  # fmt: skip
                    outcome = self.dispatch(call)
                    self.outcomes.append(outcome)
                    messages.append({"role": "tool", "tool_call_id": call.id,
                                     "content": outcome.result})  # fmt: skip
        return self.outcomes

    def observable(self) -> dict[str, Any]:
        """Everything the agent observably produced: tool results, process output and exit
        codes, and the final answer (compared across capture off and on)."""
        return {"outcomes": [o.as_dict() for o in self.outcomes], "answer": self.answer}


class Ledger:
    """The harness's own ground truth (never Fabric's): wraps a check and appends one line
    per check to ``path``: the provider tool-call id (the harness's script knows which call
    each ``(tool, args)`` is), the decision, and for a raise the exception object's id."""

    def __init__(self, path: Path, script: Sequence[Turn]) -> None:
        self.path = path
        self.ids = {(c.name, json.dumps(dict(c.args), sort_keys=True)): c.id
                    for turn in script if not isinstance(turn, str) for c in turn}  # fmt: skip
        self.raised: dict[str, BaseException] = {}

    def wrap(self, check: Check) -> Check:
        def ledgered(user: str, tool: str, args: Mapping[str, str]) -> Any:
            call_id = self.ids[(tool, json.dumps(dict(args), sort_keys=True))]
            try:
                allowed = check(user, tool, args)
            except PermissionError as exc:
                self.raised[call_id] = exc
                self._write(call_id, "deny", raised=type(exc).__name__)
                raise
            self._write(call_id, "allow" if allowed is True else "deny")
            return allowed

        return ledgered

    def _write(self, call_id: str, decision: str, raised: str | None = None) -> None:
        row = {"tool_call_id": call_id, "decision": decision, "raised": raised}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines]


__all__ = [
    "MODEL", "REFUSAL", "TOOLS", "USER", "Call", "FixtureModel", "Ledger", "Outcome",
    "ToolLoop", "Turn", "can_use",
]  # fmt: skip
