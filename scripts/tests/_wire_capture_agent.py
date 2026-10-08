# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A ReAct agent for the wire-capture Node E2E, over plain httpx or the real OpenAI SDK.

It imports nothing from Fabric: capture is activated only by the zero-code
path the platform sets up (the autoload directory on ``PYTHONPATH`` plus
``FABRIC_WIRE_*`` / ``FABRIC_TENANT_ID`` / ``OTEL_EXPORTER_OTLP_*``). The
loop is three OpenAI-compatible chat-completions calls:

1. non-streamed: the model asks for ``get_weather``;
2. streamed (SSE): the model asks for ``c_to_f``; the agent assembles the
   tool call from the deltas;
3. non-streamed: the model answers.

``--client httpx`` drives the loop with hand-written httpx calls;
``--client openai`` uses the real ``openai`` SDK (>=3, which sends through
httpx2) exactly as an application would.

Prints one JSON line on stdout: the answer and whether Fabric was active.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import httpx


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


def react(step_call: Any, question: str) -> str:
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
        message = step_call(payload)
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
    args = parser.parse_args()
    api_key = os.environ["E2E_MODEL_API_KEY"]
    if args.client == "openai":
        import httpx2
        import openai

        base_url = args.model_url.removesuffix("/chat/completions")
        with openai.OpenAI(base_url=base_url, api_key=api_key, max_retries=0) as sdk:
            answer = react(lambda payload: _openai_step(sdk, payload), args.question)
        transport: Any = httpx2.HTTPTransport
    else:
        with httpx.Client(timeout=30.0) as client:
            answer = react(
                lambda payload: _httpx_step(client, args.model_url, api_key, payload),
                args.question,
            )
        transport = httpx.HTTPTransport
    # Whether the zero-code path patched the transport the client used; read
    # without importing Fabric.
    patched = bool(getattr(transport.handle_request, "__fabric_wire_patch__", False))
    sys.stdout.write(json.dumps({"answer": answer, "capture_active": patched}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
