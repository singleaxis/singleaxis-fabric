# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-1 agents (spec 057 §10.2): plain, hand-written tool loops with no Fabric code.

``python agent.py PLAN.json`` runs every session the plan lists, one after the other, in
one process. Capture, when on, comes only from outside: the autoload directory on
``PYTHONPATH`` and the ``FABRIC_*`` variables the harness sets (spec 047). Nothing here
imports Fabric.

Two agent shapes:

- **loop**: a tool loop that posts the model's own HTTP API with httpx (OpenAI Chat
  Completions, streamed or not, or Anthropic Messages), runs each tool call in a disposable
  workspace (``run_shell``, ``read_file``, ``write_file``, ``python_exec``; ``pip_install``
  is refused: installs are off in the workspace) and feeds the results back. Its first
  request restricts tool choice (``required`` / ``any``), and its offered tool set changes
  after the first turn, as the plan says.
- **mcp**: the same loop on Chat Completions whose tools are the tools two MCP servers list
  (``tickets`` and ``notes``, named ``server__tool``) plus ``run_shell``. It talks to the
  servers through the MCP Python library's own client, one over Streamable HTTP and one
  over stdio (the library launches it). It answers each elicitation with the plan's answer
  and exposes one root to the servers. When a server says its tool list changed, it lists
  the tools again before the next model request, so the offered set follows.

The agent writes its own ground truth to the plan's ledger (one JSON line per event: each
request's exact bytes digest, its offered tools, tool choice and parallel setting, each
response's bytes, each tool result and its error flag, each elicitation answer, each root
it exposed) and its observable outputs (tool results, process output and exit codes, the
final answers) to the plan's outputs file. Neither is Fabric's.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

SESSION_HEADER = "x-sc-ra1-session"
SHELL_TIMEOUT_S = 60
MCP_SERVER = Path(__file__).with_name("mcp_server.py")
LOOP_TOOLS: dict[str, tuple[str, dict[str, Any]]] = {
    "run_shell": (
        "Run a shell command in the workspace (sh -c). Returns exit code, stdout, stderr.",
        {"command": {"type": "string"}},
    ),
    "read_file": ("Read a file in the workspace.", {"path": {"type": "string"}}),
    "write_file": (
        "Write a file in the workspace.",
        {"path": {"type": "string"}, "content": {"type": "string"}},
    ),
    "python_exec": (
        "Run Python code in the workspace and return its output.",
        {"code": {"type": "string"}},
    ),
    "pip_install": ("Install a Python package.", {"package": {"type": "string"}}),
}


def _dump(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Ledger:
    """The agent's ground truth: append-only JSON lines, written as events happen."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def write(self, **row: Any) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


# --------------------------------------------------------------------------------- tools
def _schema(properties: Mapping[str, Any]) -> dict[str, Any]:
    return {"type": "object", "properties": dict(properties), "required": sorted(properties)}


def openai_tool(name: str, description: str, parameters: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {"name": name, "description": description, "parameters": dict(parameters)},
    }


def anthropic_tool(name: str, description: str, parameters: Mapping[str, Any]) -> dict[str, Any]:
    return {"name": name, "description": description, "input_schema": dict(parameters)}


def loop_tools(names: Sequence[str], dialect: str) -> list[dict[str, Any]]:
    build = anthropic_tool if dialect == "anthropic" else openai_tool
    return [build(n, LOOP_TOOLS[n][0], _schema(LOOP_TOOLS[n][1])) for n in names]


def _process(argv: list[str], workspace: Path) -> dict[str, Any]:
    try:
        done = subprocess.run(  # noqa: S603 - the tool the model asked for, in the workspace
            argv,
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=SHELL_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"text": "timed out", "error": True, "exit_code": None, "stdout": "", "stderr": ""}
    text = f"exit {done.returncode}\n{done.stdout}{done.stderr}"
    return {
        "text": text,
        "error": done.returncode != 0,
        "exit_code": done.returncode,
        "stdout": done.stdout,
        "stderr": done.stderr,
    }


def run_local_tool(  # noqa: PLR0911 - one return per tool
    name: str, args: Mapping[str, Any], workspace: Path, offered: Sequence[str]
) -> dict[str, Any]:
    """One tool the agent runs itself. A tool it did not offer, or does not have, is refused
    with an error result (the model named it anyway)."""
    if name not in offered or name not in LOOP_TOOLS:
        return {"text": f"unknown tool {name}", "error": True}
    if name == "run_shell":
        return _process(["/bin/sh", "-c", str(args.get("command", ""))], workspace)
    if name == "python_exec":
        return _process([sys.executable, "-c", str(args.get("code", ""))], workspace)
    if name == "pip_install":
        return {"text": "package installs are disabled in this workspace", "error": True}
    path = (workspace / str(args.get("path", ""))).resolve()
    if workspace.resolve() not in (path, *path.parents):
        return {"text": "path outside the workspace", "error": True}
    if name == "read_file":
        try:
            return {"text": path.read_text(encoding="utf-8"), "error": False}
        except OSError as exc:
            return {"text": f"{type(exc).__name__}: {exc.strerror}", "error": True}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(args.get("content", "")), encoding="utf-8")
    return {"text": f"wrote {len(str(args.get('content', '')))} characters", "error": False}


# ---------------------------------------------------------------------------- the model
class Model:
    """One session's model API: the exact request bytes go out through httpx's default
    transport; the response is parsed as the dialect says."""

    def __init__(self, session: Mapping[str, Any], plan: Mapping[str, Any], ledger: Ledger) -> None:
        self.s, self.ledger = session, ledger
        self.dialect: str = session["dialect"]
        self.stream: bool = bool(session.get("stream"))
        self.url = session["base_url"].rstrip("/") + (
            "/messages" if self.dialect == "anthropic" else "/chat/completions"
        )
        key = os.environ.get(plan.get("api_key_env") or "", "") if not session.get("replay") else ""
        self.headers = {"content-type": "application/json"}
        if self.dialect == "anthropic":
            self.headers.update({"anthropic-version": "2023-06-01", "x-api-key": key or "replay"})
        else:
            self.headers["authorization"] = f"Bearer {key or 'replay'}"
        if session.get("replay"):
            self.headers[SESSION_HEADER] = session["name"]
        self.model: str = plan["model"]
        self.turn = 0

    def payload(
        self, system: str, messages: list[Any], tools: list[dict[str, Any]], choice: Any
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.model, "max_tokens": 2048, "temperature": 0}
        if self.dialect == "anthropic":
            body.update(system=system, messages=messages)
        else:
            body["messages"] = [{"role": "system", "content": system}, *messages]
            if self.stream:
                body["stream"] = True
        if tools:
            body["tools"] = tools
        if choice is not None:
            body["tool_choice"] = choice
        return body

    def _record_request(self, raw: bytes, body: Mapping[str, Any]) -> None:
        self.ledger.write(
            event="model_request",
            session=self.s["name"],
            turn=self.turn,
            dialect=self.dialect,
            stream=self.stream,
            path=httpx.URL(self.url).path,
            sha256=hashlib.sha256(raw).hexdigest(),
            tools=body.get("tools", []),
            tool_choice=body.get("tool_choice", "<absent>"),
            parallel_tool_calls=body.get("parallel_tool_calls", "<absent>"),
            system=hashlib.sha256(_dump(body.get("system", ""))).hexdigest(),
        )

    def _record_response(
        self, status: int, raw: bytes, ctype: str, parsed: Mapping[str, Any]
    ) -> None:
        self.ledger.write(
            event="model_response",
            session=self.s["name"],
            turn=self.turn,
            status=status,
            content_type=ctype,
            body_b64=base64.b64encode(raw).decode(),
            sha256=hashlib.sha256(raw).hexdigest(),
            tool_calls=[{"id": c["id"], "name": c["name"]} for c in parsed["calls"]],
            stop=parsed["stop"],
        )

    def call(self, client: httpx.Client, body: Mapping[str, Any]) -> dict[str, Any]:
        raw = _dump(body)
        self._record_request(raw, body)
        response = client.post(self.url, content=raw, headers=self.headers)
        data = response.read()
        parsed = self.parse(response.status_code, data)
        self._record_response(
            response.status_code, data, response.headers.get("content-type", ""), parsed
        )
        self.turn += 1
        return parsed

    async def acall(self, client: httpx.AsyncClient, body: Mapping[str, Any]) -> dict[str, Any]:
        raw = _dump(body)
        self._record_request(raw, body)
        response = await client.post(self.url, content=raw, headers=self.headers)
        data = await response.aread()
        parsed = self.parse(response.status_code, data)
        self._record_response(
            response.status_code, data, response.headers.get("content-type", ""), parsed
        )
        self.turn += 1
        return parsed

    def parse(self, status: int, data: bytes) -> dict[str, Any]:
        """``calls`` (id, name, args), ``text``, ``stop`` and the assistant ``message`` to
        append to the conversation."""
        if status != 200:  # noqa: PLR2004
            return {"calls": [], "text": None, "stop": f"http_{status}", "message": None}
        if self.dialect == "anthropic":
            doc = json.loads(data)
            blocks = [b for b in doc.get("content") or [] if b.get("type") in ("text", "tool_use")]
            calls = [
                {"id": b["id"], "name": b["name"], "args": b.get("input") or {}}
                for b in blocks
                if b["type"] == "tool_use"
            ]
            text = "".join(b.get("text", "") for b in blocks if b["type"] == "text") or None
            reply = {"role": "assistant", "content": blocks} if blocks else None
            return {
                "calls": calls,
                "text": text,
                "stop": doc.get("stop_reason"),
                "message": reply,
            }
        if self.stream:
            return self._parse_stream(data)
        choice = (json.loads(data).get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        raw_calls = msg.get("tool_calls") or []
        calls = [
            {
                "id": c["id"],
                "name": c["function"]["name"],
                "args": _args(c["function"].get("arguments")),
            }
            for c in raw_calls
        ]
        message: dict[str, Any] = {"role": "assistant", "content": msg.get("content") or None}
        if raw_calls:
            message["tool_calls"] = [
                {
                    "id": c["id"],
                    "type": "function",
                    "function": {
                        "name": c["function"]["name"],
                        "arguments": c["function"].get("arguments") or "{}",
                    },
                }
                for c in raw_calls
            ]
        return {
            "calls": calls,
            "text": msg.get("content") or None,
            "stop": choice.get("finish_reason"),
            "message": message,
        }

    @staticmethod
    def _parse_stream(data: bytes) -> dict[str, Any]:
        text, stop = "", None
        parts: dict[int, dict[str, str]] = {}
        for line in data.decode("utf-8").splitlines():
            if not line.startswith("data:") or line[5:].strip() == "[DONE]":
                continue
            chunk = json.loads(line[5:])
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                text += delta.get("content") or ""
                for call in delta.get("tool_calls") or []:
                    part = parts.setdefault(
                        call.get("index", 0), {"id": "", "name": "", "args": ""}
                    )
                    function = call.get("function") or {}
                    part["id"] += call.get("id") or ""
                    part["name"] += function.get("name") or ""
                    part["args"] += function.get("arguments") or ""
                stop = choice.get("finish_reason") or stop
        ordered = [parts[i] for i in sorted(parts)]
        calls = [{"id": p["id"], "name": p["name"], "args": _args(p["args"])} for p in ordered]
        message: dict[str, Any] = {"role": "assistant", "content": text or None}
        if ordered:
            message["tool_calls"] = [
                {
                    "id": p["id"],
                    "type": "function",
                    "function": {"name": p["name"], "arguments": p["args"] or "{}"},
                }
                for p in ordered
            ]
        return {"calls": calls, "text": text or None, "stop": stop, "message": message}


def _args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _feed(dialect: str, results: list[tuple[dict[str, Any], dict[str, Any]]]) -> list[Any]:
    """The messages that feed tool results back. Anthropic carries the literal
    ``is_error`` flag; Chat Completions has no flag."""
    if dialect == "anthropic":
        return [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": call["id"],
                        "content": out["text"],
                        "is_error": bool(out["error"]),
                    }
                    for call, out in results
                ],
            }
        ]
    return [
        {"role": "tool", "tool_call_id": call["id"], "content": out["text"]}
        for call, out in results
    ]


class Outputs:
    """What the agent observably produced, compared across capture off and on."""

    def __init__(self) -> None:
        self.sessions: dict[str, dict[str, Any]] = {}

    def tool(self, session: str, call: Mapping[str, Any], out: Mapping[str, Any]) -> None:
        row = {
            "call_id": call["id"],
            "name": call["name"],
            "result": out["text"],
            "error": bool(out["error"]),
            "exit_code": out.get("exit_code"),
            "stdout": out.get("stdout"),
            "stderr": out.get("stderr"),
        }
        self.sessions.setdefault(session, {"tools": [], "answer": None})["tools"].append(row)

    def answer(self, session: str, text: str | None, stop: Any) -> None:
        entry = self.sessions.setdefault(session, {"tools": [], "answer": None})
        entry["answer"], entry["stop"] = text, stop


# --------------------------------------------------------------------------- loop agent
def run_loop(
    session: Mapping[str, Any], plan: Mapping[str, Any], ledger: Ledger, outputs: Outputs
) -> None:
    model = Model(session, plan, ledger)
    workspace = Path(plan["workspace"])
    system = plan["system_prompt"]
    messages: list[Any] = [{"role": "user", "content": session["task"]}]
    with httpx.Client(timeout=300.0) as client:
        for turn in range(int(session["max_turns"])):
            names = session["tools_first"] if turn == 0 else session["tools_then"]
            choice = session.get("tool_choice_first") if turn == 0 else None
            parsed = model.call(
                client, model.payload(system, messages, loop_tools(names, model.dialect), choice)
            )
            if parsed["message"] is not None:
                messages.append(parsed["message"])
            if not parsed["calls"]:
                outputs.answer(session["name"], parsed["text"], parsed["stop"])
                return
            results = []
            for call in parsed["calls"]:
                out = run_local_tool(call["name"], call["args"], workspace, names)
                _note_result(ledger, session["name"], turn, call, out, model.dialect)
                outputs.tool(session["name"], call, out)
                results.append((call, out))
            messages.extend(_feed(model.dialect, results))
    outputs.answer(session["name"], None, "max_turns")


def _note_result(
    ledger: Ledger,
    session: str,
    turn: int,
    call: Mapping[str, Any],
    out: Mapping[str, Any],
    dialect: str,
) -> None:
    ledger.write(
        event="tool_result",
        session=session,
        turn=turn,
        call_id=call["id"],
        name=call["name"],
        error=bool(out["error"]),
        flag=bool(out["error"]) if dialect == "anthropic" else None,
        mcp_is_error=out.get("mcp_is_error"),
    )


# ---------------------------------------------------------------------------- MCP agent
async def run_mcp(
    session: Mapping[str, Any], plan: Mapping[str, Any], ledger: Ledger, outputs: Outputs
) -> None:
    from mcp import types  # noqa: PLC0415 - the MCP agent only
    from mcp.client.session import ClientSession  # noqa: PLC0415
    from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: PLC0415
    from mcp.client.streamable_http import streamable_http_client  # noqa: PLC0415

    name = session["name"]
    answer = session["elicitation"]
    changed: set[str] = set()

    async def elicit(context: Any, params: Any) -> Any:
        ledger.write(event="elicitation_answer", session=name, action=answer)
        return types.ElicitResult(
            action=answer, content={"confirm": True} if answer == "accept" else None
        )

    async def roots(context: Any) -> Any:
        ledger.write(event="roots_given", session=name, count=1)
        return types.ListRootsResult(roots=[types.Root(uri=plan["roots_canary"], name="work")])

    def handler_for(server: str) -> Any:
        async def handle(message: Any) -> None:
            inner = getattr(message, "root", message)
            if (
                isinstance(inner, types.ToolListChangedNotification)
                or getattr(inner, "method", None) == "notifications/tools/list_changed"
            ):
                changed.add(server)

        return handle

    sessions: dict[str, Any] = {}
    tools: dict[str, list[Any]] = {}
    async with contextlib.AsyncExitStack() as stack:
        for server, spec in sorted(session["mcp"].items()):
            if spec["transport"] == "http":
                streams = await stack.enter_async_context(streamable_http_client(spec["url"]))
            else:
                env = {
                    **os.environ,
                    "SC_RA1_MCP_LEDGER": spec["ledger"],
                    "SC_RA1_ELICITATION_CANARY": plan["elicitation_canary"],
                }
                params = StdioServerParameters(
                    command=sys.executable, args=[str(MCP_SERVER), "--stdio", server], env=env
                )
                ledger.write(
                    event="mcp_launch",
                    session=name,
                    server=server,
                    argv=[sys.executable, str(MCP_SERVER), "--stdio", server],
                )
                streams = await stack.enter_async_context(stdio_client(params))
            client = await stack.enter_async_context(
                ClientSession(
                    streams[0],
                    streams[1],
                    elicitation_callback=elicit,
                    list_roots_callback=roots,
                    message_handler=handler_for(server),
                )
            )
            await client.initialize()
            sessions[server] = client
            tools[server] = list((await client.list_tools()).tools)
        await _mcp_loop(session, plan, ledger, outputs, sessions, tools, changed)


async def _mcp_loop(
    session: Mapping[str, Any],
    plan: Mapping[str, Any],
    ledger: Ledger,
    outputs: Outputs,
    sessions: dict[str, Any],
    tools: dict[str, list[Any]],
    changed: set[str],
) -> None:
    model = Model(session, plan, ledger)
    workspace = Path(plan["workspace"])
    messages: list[Any] = [{"role": "user", "content": session["task"]}]
    async with httpx.AsyncClient(timeout=300.0) as client:
        for turn in range(int(session["max_turns"])):
            for server in sorted(changed):  # the server said its list changed: list again
                tools[server] = list((await sessions[server].list_tools()).tools)
            changed.clear()
            offered = [
                openai_tool(
                    f"{server}__{t.name}",
                    t.description or "",
                    getattr(t, "input_schema", None) or {"type": "object"},
                )
                for server in sorted(tools)
                for t in tools[server]
            ]
            offered += loop_tools(["run_shell"], "openai")
            choice = session.get("tool_choice_first") if turn == 0 else None
            parsed = await model.acall(
                client, model.payload(plan["system_prompt"], messages, offered, choice)
            )
            if parsed["message"] is not None:
                messages.append(parsed["message"])
            if not parsed["calls"]:
                outputs.answer(session["name"], parsed["text"], parsed["stop"])
                return
            names = [t["function"]["name"] for t in offered]
            results = []
            for call in parsed["calls"]:
                server, _, tool = call["name"].partition("__")
                if call["name"] in names and server in sessions:
                    result = await sessions[server].call_tool(tool, call["args"])
                    text = "\n".join(getattr(c, "text", "") for c in result.content)
                    out = {
                        "text": text,
                        "error": bool(result.is_error),
                        "mcp_is_error": bool(result.is_error),
                    }
                else:
                    out = run_local_tool(call["name"], call["args"], workspace, names)
                _note_result(ledger, session["name"], turn, call, out, "openai")
                outputs.tool(session["name"], call, out)
                results.append((call, out))
            messages.extend(_feed("openai", results))
    outputs.answer(session["name"], None, "max_turns")


def main(argv: Sequence[str]) -> int:
    plan = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    ledger = Ledger(Path(plan["ledger"]))
    outputs = Outputs()
    timing: dict[str, float] = {}
    for session in plan["sessions"]:
        started = time.perf_counter()
        if session["kind"] == "mcp":
            import anyio  # noqa: PLC0415

            anyio.run(run_mcp, session, plan, ledger, outputs)
        else:
            run_loop(session, plan, ledger, outputs)
        timing[session["name"]] = time.perf_counter() - started
    if plan.get("timing"):  # the session's own wall time, apart from interpreter start and exit
        Path(plan["timing"]).write_text(json.dumps(timing), encoding="utf-8")
    Path(plan["outputs"]).write_text(
        json.dumps(outputs.sessions, indent=1, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps({"pid": os.getpid(), "sessions": len(plan["sessions"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
