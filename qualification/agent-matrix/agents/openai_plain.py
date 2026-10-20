# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Plain ``openai`` SDK tool loop (chat completions; ``--variant responses`` for the
Responses API). The base URL is the SDK's normal ``base_url`` setting."""

from __future__ import annotations

import json
import os

import _common as c
from openai import OpenAI

ns = c.args()


def chat(client: OpenAI) -> str:
    content: object = c.prompt()
    if ns.image:
        content = [{"type": "text", "text": c.prompt()}] + [
            {"type": "image_url", "image_url": {"url": u}} for u in c.image_data_urls()]
    messages: list[dict] = [{"role": "user", "content": content}]
    for _ in range(c.MAX_STEPS):
        if ns.stream:
            text, calls = "", {}
            for chunk in client.chat.completions.create(
                model=ns.model, messages=messages, tools=c.openai_tools(), stream=True
            ):
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                text += delta.content or ""
                for tc in delta.tool_calls or []:
                    slot = calls.setdefault(tc.index, {"id": "", "name": "", "arguments": ""})
                    slot["id"] = tc.id or slot["id"]
                    if tc.function:
                        slot["name"] += tc.function.name or ""
                        slot["arguments"] += tc.function.arguments or ""
            tool_calls = [{"id": v["id"], "type": "function",
                           "function": {"name": v["name"], "arguments": v["arguments"]}}
                          for _, v in sorted(calls.items())]
        else:
            msg = client.chat.completions.create(
                model=ns.model, messages=messages, tools=c.openai_tools()
            ).choices[0].message
            text = msg.content or ""
            tool_calls = [tc.model_dump() for tc in msg.tool_calls or []]
        if not tool_calls:
            return text
        messages.append({"role": "assistant", "content": None, "tool_calls": tool_calls})
        for tc in tool_calls:
            result = c.call_tool(tc["function"]["name"], json.loads(tc["function"]["arguments"]))
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})
    raise RuntimeError("step limit")


def responses(client: OpenAI) -> str:
    content: list[dict] = [{"type": "input_text", "text": c.prompt()}]
    if ns.image:
        content += [{"type": "input_image", "image_url": u} for u in c.image_data_urls()]
    items: list[dict] = [{"role": "user", "content": content}]
    tools = [{"type": "function", "name": n, "description": c.TOOL_DESCRIPTIONS[n],
              "parameters": s} for n, s in c.TOOL_SCHEMAS.items()]
    for _ in range(c.MAX_STEPS):
        if ns.stream:
            response = None
            for event in client.responses.create(model=ns.model, input=items, tools=tools,
                                                 stream=True):
                if event.type == "response.completed":
                    response = event.response
            assert response is not None
        else:
            response = client.responses.create(model=ns.model, input=items, tools=tools)
        calls = [o for o in response.output if o.type == "function_call"]
        if not calls:
            return response.output_text
        for call in calls:
            items.append({"type": "function_call", "call_id": call.call_id, "name": call.name,
                          "arguments": call.arguments})
        for call in calls:
            items.append({"type": "function_call_output", "call_id": call.call_id,
                          "output": c.call_tool(call.name, json.loads(call.arguments))})
    raise RuntimeError("step limit")


def body() -> str:
    client = OpenAI(base_url=ns.openai_base, api_key=os.environ["OPENAI_API_KEY"])
    return responses(client) if ns.variant == "responses" else chat(client)


c.run(ns.out, body)
