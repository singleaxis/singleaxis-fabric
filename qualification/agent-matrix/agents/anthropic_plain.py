# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Plain ``anthropic`` SDK tool loop (Messages API), via the SDK's ``base_url``."""

from __future__ import annotations

import base64
import os

import _common as c
from anthropic import Anthropic

ns = c.args()


def body() -> str:
    client = Anthropic(base_url=ns.anthropic_base, api_key=os.environ["ANTHROPIC_API_KEY"])
    content: list[dict] = [{"type": "text", "text": c.prompt()}]
    if ns.image:
        content += [{"type": "image", "source": {
            "type": "base64", "media_type": "image/png",
            "data": base64.b64encode(png).decode()}} for png in c.images()]
    messages: list[dict] = [{"role": "user", "content": content}]
    tools = [{"name": n, "description": c.TOOL_DESCRIPTIONS[n], "input_schema": s}
             for n, s in c.TOOL_SCHEMAS.items()]
    for _ in range(c.MAX_STEPS):
        kwargs = dict(model=ns.model, max_tokens=512, messages=messages, tools=tools)
        if ns.stream:
            with client.messages.stream(**kwargs) as stream:
                message = stream.get_final_message()
        else:
            message = client.messages.create(**kwargs)
        uses = [b for b in message.content if b.type == "tool_use"]
        if not uses:
            return "".join(b.text for b in message.content if b.type == "text")
        messages.append({"role": "assistant",
                         "content": [b.model_dump(exclude_none=True) for b in message.content]})
        messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": u.id, "content": c.call_tool(u.name, u.input)}
            for u in uses]})
    raise RuntimeError("step limit")


c.run(ns.out, body)
