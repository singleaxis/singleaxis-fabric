# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A ReAct agent for the wire-capture Node E2E, over plain httpx or the real OpenAI SDK.

Capture is activated only by the zero-code path the platform sets up (the
autoload directory on ``PYTHONPATH`` plus ``FABRIC_WIRE_*`` /
``FABRIC_TENANT_ID`` / ``OTEL_EXPORTER_OTLP_*``); the agent never installs
anything. The only Fabric API it may touch is the explicit run-scope marker
``fabric.wire.run()``, and only with ``--scopes`` (spec 043 §6). The loop is
three OpenAI-compatible chat-completions calls:

1. non-streamed: the model asks for ``get_weather``;
2. streamed (SSE): the model asks for ``c_to_f``; the agent assembles the
   tool call from the deltas;
3. non-streamed: the model answers.

``--client httpx`` drives the loop with hand-written httpx calls;
``--client openai`` uses the real ``openai`` SDK (>=3, which sends through
httpx2) exactly as an application would.

The loop runs under an ambient (host) parent span context whose W3C trace
state carries ``E2E_TRACE_STATE``, the way upstream instrumentation can put
a tenant id or credential there. Capture must keep the trace/span ids for
correlation but never forward that trace state (spec 042 §8, decision E7).

``--scopes OUTER[,INNER]`` wraps the whole loop in ``fabric.wire.run(OUTER)``
and the streamed call in a nested ``fabric.wire.run(INNER)`` (default: OUTER
again, a second scope of the same run).
``--pause-after N`` prints ``{"paused": N}`` after the N-th model call and
then blocks, so a test can SIGKILL the process mid-run.

Prints one JSON line on stdout: the answer, whether Fabric was active, the
ambient parent's trace and span ids, whether any cloud SDK (boto3/botocore)
was imported and which ``AWS_*`` variables the process saw.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import threading
from collections.abc import Callable, Iterator
from typing import Any

import httpx
from opentelemetry import context as otel_context
from opentelemetry import trace


def get_weather(city: str) -> dict[str, Any]:
    return {"city": city, "celsius": 18.5, "note": os.environ["E2E_TOOL_RESULT_MARK"]}


def c_to_f(celsius: float) -> dict[str, Any]:
    return {"fahrenheit": celsius * 9 / 5 + 32}


TOOLS = {"get_weather": get_weather, "c_to_f": c_to_f}


def _assemble_stream(response: httpx.Response) -> dict[str, Any]:
    """The assistant message from OpenAI chat-completions SSE deltas."""
    content: str | None = None
    calls: dict[int, dict[str, Any]] = {}
    done = False
    for line in response.iter_lines():
        # Like the OpenAI SDK, keep reading after [DONE] so the stream is
        # consumed to EOF. A client that stops at [DONE] is recorded as
        # ``closed_early`` (spec 042 §4.6): it closed before the transport did.
        if done or not line.startswith("data:"):
            continue
        data = line[len("data:") :].strip()
        if data == "[DONE]":
            done = True
            continue
        for choice in json.loads(data).get("choices") or ():
            delta = choice.get("delta") or {}
            if isinstance(delta.get("content"), str):
                content = (content or "") + delta["content"]
            for call in delta.get("tool_calls") or ():
                entry = calls.setdefault(call.get("index", 0), {"function": {}})
                if "id" in call:
                    entry["id"] = call["id"]
                if "type" in call:
                    entry["type"] = call["type"]
                for key, value in (call.get("function") or {}).items():
                    entry["function"][key] = entry["function"].get(key, "") + value
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if calls:
        message["tool_calls"] = [calls[index] for index in sorted(calls)]
    return message


def _httpx_step(
    client: httpx.Client, url: str, api_key: str, payload: dict[str, Any]
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {api_key}"}
    if payload.get("stream"):
        with client.stream("POST", url, headers=headers, json=payload) as response:
            response.raise_for_status()
            return _assemble_stream(response)
    response = client.post(url, headers=headers, json=payload)
    response.raise_for_status()
    return dict(response.json()["choices"][0]["message"])


def _openai_step(client: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """One call through the real OpenAI SDK; the message as the application sees it."""
    if not payload.get("stream"):
        completion = client.chat.completions.create(**payload)
        return dict(completion.choices[0].message.model_dump(exclude_unset=True))
    content: str | None = None
    calls: dict[int, dict[str, Any]] = {}
    for chunk in client.chat.completions.create(**payload):  # a real openai.Stream
        for choice in chunk.choices:
            delta = choice.delta
            if delta.content is not None:
                content = (content or "") + delta.content
            for call in delta.tool_calls or ():
                entry = calls.setdefault(call.index, {"function": {}})
                if call.id is not None:
                    entry["id"] = call.id
                if call.type is not None:
                    entry["type"] = call.type
                if call.function is not None:
                    for key in ("name", "arguments"):
                        if (value := getattr(call.function, key)) is not None:
                            entry["function"][key] = (
                                entry["function"].get(key, "") + value
                            )
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if calls:
        message["tool_calls"] = [calls[index] for index in sorted(calls)]
    return message


Scope = Callable[[int], contextlib.AbstractContextManager[Any]]


def _no_scope(step: int) -> contextlib.AbstractContextManager[Any]:
    return contextlib.nullcontext()


def react(
    step_call: Any, question: str, *, scope: Scope = _no_scope, pause_after: int = 0
) -> str:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": "You are a weather assistant. Use tools."},
        {"role": "user", "content": question},
    ]
    for step in range(5):
        tools = [{"type": "function", "function": {"name": name}} for name in TOOLS]
        payload: dict[str, Any] = {
            "model": "e2e-model",
            "messages": messages,
            "tools": tools,
        }
        if step == 1:  # the second call streams
            payload["stream"] = True
        with scope(step):
            message = step_call(payload)
        if step + 1 == pause_after:
            sys.stdout.write(json.dumps({"paused": pause_after}) + "\n")
            sys.stdout.flush()
            threading.Event().wait()  # until the test kills the process
        messages.append(message)
        calls = message.get("tool_calls") or []
        if not calls:
            return str(message.get("content"))
        for call in calls:
            result = TOOLS[call["function"]["name"]](
                **json.loads(call["function"]["arguments"])
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "content": json.dumps(result),
                }
            )
    raise RuntimeError("agent did not finish")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-url", required=True)
    parser.add_argument("--question", required=True)
    parser.add_argument("--client", choices=("httpx", "openai"), default="httpx")
    parser.add_argument("--scopes", metavar="OUTER[,INNER]", default="")
    parser.add_argument("--pause-after", type=int, default=0)
    args = parser.parse_args()
    api_key = os.environ["E2E_MODEL_API_KEY"]
    # The host's ambient span context: ids for correlation, a sensitive trace state.
    parent = trace.SpanContext(
        trace_id=int.from_bytes(os.urandom(16), "big") | 1,
        span_id=int.from_bytes(os.urandom(8), "big") | 1,
        is_remote=True,
        trace_flags=trace.TraceFlags(trace.TraceFlags.SAMPLED),
        trace_state=trace.TraceState([("hostsecret", os.environ["E2E_TRACE_STATE"])]),
    )
    token = otel_context.attach(
        trace.set_span_in_context(trace.NonRecordingSpan(parent))
    )
    try:
        answer, transport = _run(args, api_key)
        if trace.get_current_span().get_span_context() is not parent:
            raise RuntimeError("capture modified the host's span context")
    finally:
        otel_context.detach(token)
    # Whether the zero-code path patched the transport the client used; read
    # without importing Fabric.
    patched = bool(getattr(transport.handle_request, "__fabric_wire_patch__", False))
    info = {
        "answer": answer,
        "capture_active": patched,
        "trace_id": f"{parent.trace_id:032x}",
        "span_id": f"{parent.span_id:016x}",
        "cloud_sdk_imported": sorted(
            name for name in ("boto3", "botocore", "aiobotocore") if name in sys.modules
        ),
        "aws_env": sorted(name for name in os.environ if name.startswith("AWS_")),
    }
    sys.stdout.write(json.dumps(info) + "\n")
    return 0


@contextlib.contextmanager
def _outer_scope(run_id: str) -> Iterator[None]:
    if not run_id:
        yield
        return
    from fabric import wire  # the explicit run-scope API only (spec 043 §6)

    with wire.run(run_id.partition(",")[0]):
        yield


def _scope_for(run_id: str) -> Scope:
    if not run_id:
        return _no_scope

    def scope(step: int) -> contextlib.AbstractContextManager[Any]:
        if step != 1:
            return contextlib.nullcontext()
        from fabric import wire

        outer, _, inner = run_id.partition(",")
        return wire.run(inner or outer)  # nested inside the outer scope

    return scope


def _run(args: argparse.Namespace, api_key: str) -> tuple[str, Any]:
    scope, pause = _scope_for(args.scopes), args.pause_after
    if args.client == "openai":
        import httpx2
        import openai

        base_url = args.model_url.removesuffix("/chat/completions")
        with (
            openai.OpenAI(base_url=base_url, api_key=api_key, max_retries=0) as sdk,
            _outer_scope(args.scopes),
        ):
            answer = react(
                lambda payload: _openai_step(sdk, payload),
                args.question, scope=scope, pause_after=pause,
            )  # fmt: skip
        transport: Any = httpx2.HTTPTransport
    else:
        with httpx.Client(timeout=30.0) as client, _outer_scope(args.scopes):
            answer = react(
                lambda payload: _httpx_step(client, args.model_url, api_key, payload),
                args.question, scope=scope, pause_after=pause,
            )  # fmt: skip
        transport = httpx.HTTPTransport
    return answer, transport


if __name__ == "__main__":
    raise SystemExit(main())
