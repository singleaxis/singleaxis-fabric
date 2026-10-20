# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A deterministic fake model server, OpenAI- and Anthropic-compatible, on loopback.

Endpoints: ``/v1/chat/completions``, ``/v1/responses``, ``/v1/embeddings`` (OpenAI) and
``/v1/messages`` (Anthropic), each streaming (SSE) and non-streaming, with tool calls and
parallel tool calls. Every answer is a pure function of the request body (and, for fault
injection, of whether that exact body was seen before), so a run with capture and a run
without it receive byte-identical responses.

The scenario is chosen by the model name ``fm-s<steps>-p<parallel>-<fault>``:

- ``steps``: tool-call rounds before the final answer (a scripted ReAct sequence);
- ``parallel``: tool calls per round;
- ``fault``: ``none``; ``429`` (first sight of a body: 429 + retry-after, then success);
  ``500`` (same, with a 500); ``400`` (always a non-retryable 400); ``disc`` (first sight
  of a streamed body: half the events, then the connection is cut without the
  terminating chunk; a non-streamed body is cut mid-body).

Frameworks that run a text protocol instead of native tools are answered in their own
format: DSPy's ``[[ ## field ## ]]`` ChatAdapter (ReAct + extract) and the classic
``Thought/Action/Action Input/Final Answer`` ReAct text (CrewAI's fallback).

Every exchange is logged: exact request bytes as received (after de-chunking), the
exact response body bytes written, status, timings, and the client's User-Agent (which
names the HTTP client: ``OpenAI/Python``, ``python-requests``, ``aiohttp``...).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import socket
import threading
import time
import zlib
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

CREATED = 1_760_000_000
MODEL_RE = re.compile(r"fm-s(\d+)-p(\d+)-([a-z0-9]+)")
SECRET_ECHO_RE = re.compile(r"MATRIXSECRET[0-9A-Za-z_]+")
# Arguments for the harness tools when a protocol gives no JSON schema.
KNOWN_ARGS: dict[str, dict[str, Any]] = {
    "get_weather": {"city": "Paris"},
    "c_to_f": {"celsius": 18.5},
    "lookup": {"key": "alpha"},
}


@dataclass
class Exchange:
    seq: int
    method: str
    path: str
    user_agent: str
    request: bytes
    status: int = 0
    response: bytes = b""
    stream: bool = False
    disconnected: bool = False
    t_start: float = 0.0  # request line read
    t_body: float = 0.0  # request body read
    t_end: float = 0.0  # last response byte flushed
    model: str = ""
    kind: str = ""
    header_names: list[str] = field(default_factory=list)  # wire order: a client fingerprint

    def summary(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "method": self.method, "path": self.path,
            "user_agent": self.user_agent, "status": self.status, "stream": self.stream,
            "disconnected": self.disconnected, "model": self.model, "kind": self.kind,
            "request_sha256": hashlib.sha256(self.request).hexdigest(),
            "request_len": len(self.request),
            "response_sha256": hashlib.sha256(self.response).hexdigest(),
            "response_len": len(self.response),
            "t_start": self.t_start, "t_body": self.t_body, "t_end": self.t_end,
            "header_names": self.header_names,
        }  # fmt: skip


@dataclass
class Scenario:
    steps: int = 2
    parallel: int = 1
    fault: str = "none"


def scenario_of(model: str) -> Scenario:
    found = MODEL_RE.search(model or "")
    if not found:
        return Scenario()
    return Scenario(int(found.group(1)), max(1, int(found.group(2))), found.group(3))


def _args_for(name: str, schema: dict[str, Any] | None, step: int) -> dict[str, Any]:
    if name in KNOWN_ARGS:
        base = dict(KNOWN_ARGS[name])
        if name == "lookup":
            base["key"] = f"k{step}"
        return base
    out: dict[str, Any] = {}
    props = (schema or {}).get("properties") or {}
    for key, spec in props.items():
        kind = (spec or {}).get("type")
        out[key] = (
            step + 1 if kind in ("number", "integer") else True if kind == "boolean"
            else {} if kind == "object" else [] if kind == "array" else f"v{step}"
        )  # fmt: skip
    return out


@dataclass
class Plan:
    """What the model does next: tool calls (name, arguments) or a final text. ``step``
    numbers the response (tool-call ids derive from it); ``rounds`` counts tool rounds."""

    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    text: str | None = None
    step: int = 0


def _final_text(rounds: int, observations: list[str]) -> str:
    digest = hashlib.sha256("\x1f".join(observations).encode()).hexdigest()[:12]
    echoed = sorted(set(SECRET_ECHO_RE.findall("\n".join(observations))))
    echo = f" echo={','.join(echoed)}" if echoed else ""
    return f"Final Answer: done after {rounds} tool rounds; observed={digest}{echo} TERMINATE"


def plan(
    scenario: Scenario, tools: list[tuple[str, dict[str, Any] | None]],
    rounds: int, handed_off: bool, observations: list[str],
) -> Plan:  # fmt: skip
    names = [n for n, _ in tools]
    transfers = [n for n in names if n.startswith("transfer_to_")]
    step = rounds + (1 if handed_off else 0)  # ids stay unique across a handoff
    if transfers and not handed_off:
        return Plan(calls=[(transfers[0], {})], step=step)
    usable = [(n, s) for n, s in tools if not n.startswith("transfer_to_") and n != "final_answer"]
    if usable and rounds < scenario.steps:
        calls = []
        for j in range(scenario.parallel):
            name, schema = usable[(rounds + j) % len(usable)]
            calls.append((name, _args_for(name, schema, rounds)))
        return Plan(calls=calls, step=step)
    text = _final_text(rounds, observations)
    if "final_answer" in names:
        return Plan(calls=[("final_answer", {"answer": text})], step=step)
    return Plan(text=text, step=step)


# --------------------------------------------------------------------------- dialects


def _chat_state(body: dict[str, Any]) -> tuple[int, bool, list[str]]:
    rounds, handed_off, obs = 0, False, []
    for m in body.get("messages") or []:
        text = _text_of(m.get("content")).strip() if isinstance(m, dict) else ""
        if m.get("role") == "assistant" and not m.get("tool_calls") and text.startswith(
                "Calling tools:"):  # smolagents replays tool calls as text
            if "transfer_to_" in text:
                handed_off = True
            else:
                rounds += 1
        elif m.get("role") == "user" and text.startswith("Observation:"):
            obs.append(text)
        elif m.get("role") == "assistant" and m.get("tool_calls"):
            names = [((c.get("function") or {}).get("name") or "") for c in m["tool_calls"]]
            if all(n.startswith("transfer_to_") for n in names):
                handed_off = True
            else:
                rounds += 1
        elif m.get("role") in ("tool", "function"):
            obs.append(_text_of(m.get("content")))
    return rounds, handed_off, obs


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            _text_of(p.get("text") if isinstance(p, dict) and "text" in p else
                     p.get("content") if isinstance(p, dict) else p)
            for p in content
        )  # fmt: skip
    return "" if content is None else json.dumps(content, sort_keys=True)


def _responses_state(body: dict[str, Any]) -> tuple[int, bool, list[str]]:
    rounds, handed_off, obs = 0, False, []
    items = body.get("input")
    in_group = False
    for item in items if isinstance(items, list) else []:
        kind = item.get("type") if isinstance(item, dict) else None
        if kind == "function_call":
            if (item.get("name") or "").startswith("transfer_to_"):
                handed_off = True
                in_group = False
                continue
            if not in_group:
                rounds += 1
                in_group = True
        else:
            in_group = False
            if kind == "function_call_output":
                obs.append(_text_of(item.get("output")))
    return rounds, handed_off, obs


def _anthropic_state(body: dict[str, Any]) -> tuple[int, bool, list[str]]:
    rounds, handed_off, obs = 0, False, []
    for m in body.get("messages") or []:
        content = m.get("content")
        if not isinstance(content, list):
            continue
        if m.get("role") == "assistant":
            names = [b.get("name", "") for b in content if b.get("type") == "tool_use"]
            if names and all(n.startswith("transfer_to_") for n in names):
                handed_off = True
            elif names:
                rounds += 1
        else:
            obs += [_text_of(b.get("content")) for b in content if b.get("type") == "tool_result"]
    return rounds, handed_off, obs


def _chat_tools(body: dict[str, Any]) -> list[tuple[str, dict[str, Any] | None]]:
    out = []
    for t in body.get("tools") or []:
        fn = t.get("function") or t
        out.append((fn.get("name", ""), fn.get("parameters")))
    for fn in body.get("functions") or []:  # legacy function calling
        out.append((fn.get("name", ""), fn.get("parameters")))
    return out


def _responses_tools(body: dict[str, Any]) -> list[tuple[str, dict[str, Any] | None]]:
    return [(t.get("name", ""), t.get("parameters")) for t in body.get("tools") or []
            if t.get("type") == "function"]  # fmt: skip


def _anthropic_tools(body: dict[str, Any]) -> list[tuple[str, dict[str, Any] | None]]:
    return [(t.get("name", ""), t.get("input_schema")) for t in body.get("tools") or []]


# Text protocols (no native tools) -------------------------------------------------


def _all_text(body: dict[str, Any]) -> tuple[str, str]:
    """(system text, conversation text) of a chat or messages body."""
    system = _text_of(body.get("system")) if body.get("system") else ""
    convo = []
    for m in body.get("messages") or []:
        if m.get("role") == "system":
            system += _text_of(m.get("content"))
        else:
            convo.append(_text_of(m.get("content")))
    return system, "\n".join(convo)


def text_protocol(body: dict[str, Any], scenario: Scenario) -> str | None:
    """The reply text for DSPy or classic-ReAct prompts, else ``None``."""
    system, convo = _all_text(body)
    if "next_tool_name" in system:  # DSPy ReAct step (ChatAdapter)
        names = re.findall(r"'([A-Za-z_][A-Za-z0-9_]*)'", (re.search(
            r"next_tool_name[^\n]*Literal\[([^\]]*)\]", system) or re.search(
            r"Literal\[([^\]]*)\]", system) or [None, ""])[1] or "")  # fmt: skip
        tools = [n for n in names if n != "finish"] or ["get_weather"]
        last = convo.rsplit("[[ ## trajectory ## ]]", 1)[-1]
        done = len(set(re.findall(r"observation_(\d+)", last)))
        obs = re.findall(r"\[\[ ## observation_\d+ ## \]\]\n(.*?)(?=\n\n\[\[ ##|\Z)", last, re.S)
        if done < scenario.steps:
            name = tools[done % len(tools)]
            args = json.dumps(_args_for(name, None, done))
            return (f"[[ ## next_thought ## ]]\nI should call {name}.\n\n"
                    f"[[ ## next_tool_name ## ]]\n{name}\n\n"
                    f"[[ ## next_tool_args ## ]]\n{args}\n\n[[ ## completed ## ]]")  # fmt: skip
        return ("[[ ## next_thought ## ]]\nI can answer now.\n\n[[ ## next_tool_name ## ]]\n"
                "finish\n\n[[ ## next_tool_args ## ]]\n{}\n\n[[ ## completed ## ]]")
    if "[[ ## answer ## ]]" in system or "`answer`" in system:  # DSPy extract / predict
        obs = re.findall(r"\[\[ ## observation_\d+ ## \]\]\n(.*?)(?=\n\n\[\[ ##|\Z)", convo, re.S)
        rounds = len(set(re.findall(r"observation_(\d+)", convo)))
        return (f"[[ ## reasoning ## ]]\nThe trajectory has what I need.\n\n"
                f"[[ ## answer ## ]]\n{_final_text(rounds, [o.strip() for o in obs])}\n\n"
                "[[ ## completed ## ]]")  # fmt: skip
    if "Action Input:" in system and not body.get("tools"):  # classic ReAct text
        observations = re.findall(r"Observation:\s*(.*?)(?=\n(?:Thought|Action|Final)|\Z)",
                                  convo, re.S)  # fmt: skip
        names = re.findall(r"Tool Name:\s*([^\n]+)", system) or ["get_weather"]
        done = len(observations)
        if done < scenario.steps:
            name = names[done % len(names)].strip()
            args = json.dumps(_args_for(name, None, done))
            return f"Thought: I should use {name}.\nAction: {name}\nAction Input: {args}"
        return "Thought: I now know the final answer\n" + _final_text(
            done, [o.strip() for o in observations])
    return None


# --------------------------------------------------------------------------- rendering


def _usage(n: int) -> dict[str, int]:
    return {"prompt_tokens": 20 + n, "completion_tokens": 7, "total_tokens": 27 + n}


def chat_json(model: str, p: Plan) -> dict[str, Any]:
    if p.calls:
        message: dict[str, Any] = {"role": "assistant", "content": None, "tool_calls": [
            {"id": f"call_{p.step}_{i}", "type": "function",
             "function": {"name": n, "arguments": json.dumps(a)}}
            for i, (n, a) in enumerate(p.calls)], "refusal": None}  # fmt: skip
        finish = "tool_calls"
    else:
        message, finish = {"role": "assistant", "content": p.text, "refusal": None}, "stop"
    return {"id": f"chatcmpl-fm-{p.step}", "object": "chat.completion", "created": CREATED,
            "model": model, "system_fingerprint": "fp_fm",
            "choices": [{"index": 0, "message": message, "logprobs": None,
                         "finish_reason": finish}],
            "usage": _usage(p.step)}  # fmt: skip


def chat_events(model: str, p: Plan, include_usage: bool) -> list[bytes]:
    base = {"id": f"chatcmpl-fm-{p.step}", "object": "chat.completion.chunk",
            "created": CREATED, "model": model, "system_fingerprint": "fp_fm"}  # fmt: skip

    def chunk(delta: dict[str, Any], finish: str | None = None) -> bytes:
        doc = {**base, "choices": [{"index": 0, "delta": delta, "logprobs": None,
                                    "finish_reason": finish}]}  # fmt: skip
        return f"data: {json.dumps(doc)}\n\n".encode()

    out = [chunk({"role": "assistant", "content": "" if p.text else None})]
    if p.calls:
        for i, (name, args) in enumerate(p.calls):
            text = json.dumps(args)
            half = len(text) // 2
            out.append(chunk({"tool_calls": [{"index": i, "id": f"call_{p.step}_{i}",
                                              "type": "function",
                                              "function": {"name": name, "arguments": ""}}]}))
            out.append(chunk({"tool_calls": [{"index": i, "function": {"arguments": text[:half]}}]}))
            out.append(chunk({"tool_calls": [{"index": i, "function": {"arguments": text[half:]}}]}))
        out.append(chunk({}, "tool_calls"))
    else:
        text = p.text or ""
        for piece in (text[: len(text) // 3], text[len(text) // 3: 2 * len(text) // 3],
                      text[2 * len(text) // 3:]):  # fmt: skip
            out.append(chunk({"content": piece}))
        out.append(chunk({}, "stop"))
    if include_usage:
        out.append(f"data: {json.dumps({**base, 'choices': [], 'usage': _usage(p.step)})}\n\n"
                   .encode())  # fmt: skip
    out.append(b"data: [DONE]\n\n")
    return out


def _resp_items(p: Plan) -> list[dict[str, Any]]:
    if p.calls:
        return [{"type": "function_call", "id": f"fc_{p.step}_{i}", "call_id": f"call_{p.step}_{i}",
                 "name": n, "arguments": json.dumps(a), "status": "completed"}
                for i, (n, a) in enumerate(p.calls)]  # fmt: skip
    return [{"type": "message", "id": f"msg_fm_{p.step}", "status": "completed",
             "role": "assistant",
             "content": [{"type": "output_text", "text": p.text, "annotations": [],
                          "logprobs": []}]}]  # fmt: skip


def responses_json(model: str, p: Plan, status: str = "completed",
                   output: list[dict[str, Any]] | None = None) -> dict[str, Any]:  # fmt: skip
    return {"id": f"resp_fm_{p.step}", "object": "response", "created_at": CREATED,
            "status": status, "model": model, "output": _resp_items(p) if output is None else output,
            "parallel_tool_calls": True, "tool_choice": "auto", "tools": [],
            "error": None, "incomplete_details": None, "instructions": None, "metadata": {},
            "temperature": 1.0, "top_p": 1.0, "text": {"format": {"type": "text"}},
            "truncation": "disabled", "store": False, "background": False,
            "usage": {"input_tokens": 20 + p.step, "output_tokens": 7, "total_tokens": 27 + p.step,
                      "input_tokens_details": {"cached_tokens": 0},
                      "output_tokens_details": {"reasoning_tokens": 0}}}  # fmt: skip


def responses_events(model: str, p: Plan) -> list[bytes]:
    seq = 0
    out: list[bytes] = []

    def ev(kind: str, **data: Any) -> None:
        nonlocal seq
        doc = {"type": kind, "sequence_number": seq, **data}
        seq += 1
        out.append(f"event: {kind}\ndata: {json.dumps(doc)}\n\n".encode())

    ev("response.created", response=responses_json(model, p, "in_progress", []))
    ev("response.in_progress", response=responses_json(model, p, "in_progress", []))
    for i, item in enumerate(_resp_items(p)):
        if item["type"] == "function_call":
            ev("response.output_item.added", output_index=i,
               item={**item, "arguments": "", "status": "in_progress"})
            args = item["arguments"]
            for piece in (args[: len(args) // 2], args[len(args) // 2:]):
                ev("response.function_call_arguments.delta", item_id=item["id"],
                   output_index=i, delta=piece)
            ev("response.function_call_arguments.done", item_id=item["id"], output_index=i,
               arguments=args, name=item["name"])
        else:
            ev("response.output_item.added", output_index=i,
               item={**item, "content": [], "status": "in_progress"})
            part = {"type": "output_text", "text": "", "annotations": [], "logprobs": []}
            ev("response.content_part.added", item_id=item["id"], output_index=i,
               content_index=0, part=part)
            text = item["content"][0]["text"]
            for piece in (text[: len(text) // 2], text[len(text) // 2:]):
                ev("response.output_text.delta", item_id=item["id"], output_index=i,
                   content_index=0, delta=piece, logprobs=[])
            ev("response.output_text.done", item_id=item["id"], output_index=i,
               content_index=0, text=text, logprobs=[])
            ev("response.content_part.done", item_id=item["id"], output_index=i,
               content_index=0, part={**part, "text": text})
        ev("response.output_item.done", output_index=i, item=item)
    ev("response.completed", response=responses_json(model, p))
    return out


def _anthropic_blocks(p: Plan) -> list[dict[str, Any]]:
    if p.calls:
        return [{"type": "tool_use", "id": f"toolu_{p.step}_{i}", "name": n, "input": a}
                for i, (n, a) in enumerate(p.calls)]  # fmt: skip
    return [{"type": "text", "text": p.text}]


def anthropic_json(model: str, p: Plan) -> dict[str, Any]:
    return {"id": f"msg_fm_{p.step}", "type": "message", "role": "assistant", "model": model,
            "content": _anthropic_blocks(p),
            "stop_reason": "tool_use" if p.calls else "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 20 + p.step, "output_tokens": 7}}  # fmt: skip


def anthropic_events(model: str, p: Plan) -> list[bytes]:
    out: list[bytes] = []

    def ev(kind: str, **data: Any) -> None:
        out.append(f"event: {kind}\ndata: {json.dumps({'type': kind, **data})}\n\n".encode())

    start = {**anthropic_json(model, p), "content": [], "stop_reason": None,
             "usage": {"input_tokens": 20 + p.step, "output_tokens": 1}}  # fmt: skip
    ev("message_start", message=start)
    for i, block in enumerate(_anthropic_blocks(p)):
        if block["type"] == "tool_use":
            ev("content_block_start", index=i, content_block={**block, "input": {}})
            text = json.dumps(block["input"])
            for piece in (text[: len(text) // 2], text[len(text) // 2:]):
                ev("content_block_delta", index=i,
                   delta={"type": "input_json_delta", "partial_json": piece})
        else:
            ev("content_block_start", index=i, content_block={"type": "text", "text": ""})
            text = block["text"]
            for piece in (text[: len(text) // 2], text[len(text) // 2:]):
                ev("content_block_delta", index=i, delta={"type": "text_delta", "text": piece})
        ev("content_block_stop", index=i)
    ev("message_delta", delta={"stop_reason": "tool_use" if p.calls else "end_turn",
                               "stop_sequence": None}, usage={"output_tokens": 7})
    ev("message_stop")
    return out


def embeddings_json(model: str, body: dict[str, Any]) -> dict[str, Any]:
    inputs = body.get("input")
    items = inputs if isinstance(inputs, list) else [inputs]
    data = []
    for i, item in enumerate(items):
        digest = hashlib.sha256(json.dumps(item).encode()).digest()
        vec = [round((b - 128) / 128.0, 4) for b in digest[:16]]
        data.append({"object": "embedding", "index": i, "embedding": vec})
    return {"object": "list", "data": data, "model": model,
            "usage": {"prompt_tokens": len(items), "total_tokens": len(items)}}  # fmt: skip


# --------------------------------------------------------------------------- server


class FakeLLM:
    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.exchanges: list[Exchange] = []
        self._seen: set[str] = set()
        self._lock = threading.Lock()
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "fake-llm/1"
            sys_version = ""

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def setup(self) -> None:
                super().setup()
                self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            def parse_request(self) -> bool:
                self._t_start = time.perf_counter()
                return super().parse_request()

            def _body(self) -> bytes:
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    data = b""
                    while True:
                        size = int(self.rfile.readline().split(b";")[0].strip(), 16)
                        if size == 0:
                            self.rfile.readline()
                            return data
                        data += self.rfile.read(size)
                        self.rfile.readline()
                return self.rfile.read(int(self.headers.get("Content-Length") or 0))

            def do_GET(self) -> None:  # noqa: N802
                ex = server._new(self, b"")
                if self.path.rstrip("/").endswith("/models"):
                    self._send(ex, 200, {"object": "list", "data": [
                        {"id": "fm-s2-p1-none", "object": "model", "created": CREATED,
                         "owned_by": "fake"}]})  # fmt: skip
                else:
                    self._send(ex, 404, {"error": {"message": "not found"}})

            def do_POST(self) -> None:  # noqa: N802
                raw = self._body()
                ex = server._new(self, raw)
                try:
                    data = raw
                    if self.headers.get("Content-Encoding", "").lower() == "gzip":
                        data = gzip.decompress(raw)
                    elif self.headers.get("Content-Encoding", "").lower() == "deflate":
                        data = zlib.decompress(data)
                    body = json.loads(data or b"{}")
                except ValueError:
                    self._send(ex, 400, {"error": {"message": "bad json", "type": "invalid"}})
                    return
                server._dispatch(self, ex, body)

            def _send(self, ex: Exchange, status: int, doc: dict[str, Any],
                      headers: dict[str, str] | None = None) -> None:  # fmt: skip
                data = json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)
                self.wfile.flush()
                ex.status, ex.response, ex.t_end = status, data, time.perf_counter()

            def _stream(self, ex: Exchange, events: list[bytes], cut: bool = False) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                ex.status, ex.stream = 200, True
                sent = b""
                upto = max(1, len(events) // 2) if cut else len(events)
                for event in events[:upto]:
                    self.wfile.write(f"{len(event):x}\r\n".encode() + event + b"\r\n")
                    self.wfile.flush()
                    sent += event
                if cut:
                    ex.disconnected = True
                    ex.response, ex.t_end = sent, time.perf_counter()
                    self.close_connection = True
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
                ex.response, ex.t_end = sent, time.perf_counter()

            def _cut_body(self, ex: Exchange, doc: dict[str, Any]) -> None:
                data = json.dumps(doc).encode()
                half = data[: len(data) // 2]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(half)
                self.wfile.flush()
                ex.status, ex.response, ex.disconnected = 200, half, True
                ex.t_end = time.perf_counter()
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        self.Handler = Handler
        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.httpd.daemon_threads = True
        self.port = int(self.httpd.server_address[1])
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    # -- bookkeeping -------------------------------------------------------------

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _new(self, handler: Any, raw: bytes) -> Exchange:
        with self._lock:
            ex = Exchange(len(self.exchanges), handler.command, handler.path,
                          handler.headers.get("User-Agent", ""), raw)  # fmt: skip
            ex.t_start = getattr(handler, "_t_start", time.perf_counter())
            ex.header_names = [k for k in handler.headers.keys()]
            ex.t_body = time.perf_counter()
            self.exchanges.append(ex)
        return ex

    def _first_sight(self, raw: bytes) -> bool:
        key = hashlib.sha256(raw).hexdigest()
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            return True

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    # -- routing -------------------------------------------------------------------

    def _dispatch(self, h: Any, ex: Exchange, body: dict[str, Any]) -> None:
        path = h.path.split("?", 1)[0]
        model = str(body.get("model") or "")
        ex.model = model
        sc = scenario_of(model)
        stream = bool(body.get("stream"))
        kind = ("chat" if path.endswith("/chat/completions") else
                "responses" if path.endswith("/responses") else
                "messages" if path.endswith("/messages") else
                "embeddings" if path.endswith("/embeddings") else "unknown")  # fmt: skip
        ex.kind = kind
        if kind == "unknown":
            h._send(ex, 404, {"error": {"message": "unknown path", "type": "not_found"}})
            return
        first = self._first_sight(ex.request)
        if sc.fault == "400":
            h._send(ex, 400, _error(kind, "invalid_request_error", "scripted bad request"))
            return
        if sc.fault in ("429", "500") and first:
            code = int(sc.fault)
            h._send(ex, code, _error(kind, "rate_limit_error" if code == 429 else "api_error",
                                     "scripted transient failure"),
                    {"retry-after": "0", "retry-after-ms": "5", "x-should-retry": "true"})
            return
        if kind == "embeddings":
            h._send(ex, 200, embeddings_json(model, body))
            return
        if kind == "chat":
            text = text_protocol(body, sc)
            rounds, handed, obs = _chat_state(body)
            p = Plan(text=text, step=rounds) if text is not None else plan(
                sc, _chat_tools(body), rounds, handed, obs)  # fmt: skip
            cut = sc.fault == "disc" and first
            if stream:
                include = bool((body.get("stream_options") or {}).get("include_usage"))
                h._stream(ex, chat_events(model, p, include), cut=cut)
            elif cut:
                h._cut_body(ex, chat_json(model, p))
            else:
                h._send(ex, 200, chat_json(model, p))
            return
        if kind == "responses":
            rounds, handed, obs = _responses_state(body)
            p = plan(sc, _responses_tools(body), rounds, handed, obs)
            cut = sc.fault == "disc" and first
            if stream:
                h._stream(ex, responses_events(model, p), cut=cut)
            elif cut:
                h._cut_body(ex, responses_json(model, p))
            else:
                h._send(ex, 200, responses_json(model, p))
            return
        # anthropic messages
        text = text_protocol(body, sc)
        rounds, handed, obs = _anthropic_state(body)
        p = Plan(text=text, step=rounds) if text is not None else plan(
            sc, _anthropic_tools(body), rounds, handed, obs)  # fmt: skip
        cut = sc.fault == "disc" and first
        if stream:
            h._stream(ex, anthropic_events(model, p), cut=cut)
        elif cut:
            h._cut_body(ex, anthropic_json(model, p))
        else:
            h._send(ex, 200, anthropic_json(model, p))


def _error(kind: str, code: str, message: str) -> dict[str, Any]:
    if kind == "messages":
        return {"type": "error", "error": {"type": code, "message": message}}
    return {"error": {"message": message, "type": code, "param": None, "code": code}}


if __name__ == "__main__":  # manual use: python fake_llm.py [port]
    import sys

    srv = FakeLLM(port=int(sys.argv[1]) if len(sys.argv) > 1 else 0)
    print(srv.base, flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.close()
