# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""asyncio fan-out: eight concurrent tool loops on one ``AsyncOpenAI`` client,
``asyncio.gather``-ed."""

from __future__ import annotations

import asyncio
import json
import os

import _common as c
from openai import AsyncOpenAI

ns = c.args()
FANOUT = 8


async def loop(client: AsyncOpenAI, i: int) -> str:
    messages: list[dict] = [{"role": "user", "content": c.prompt(f" (worker {i})")}]
    for _ in range(c.MAX_STEPS):
        if ns.stream:
            text, calls = "", {}
            stream = await client.chat.completions.create(model=ns.model, messages=messages,
                                                          tools=c.openai_tools(), stream=True)
            async for chunk in stream:
                if not chunk.choices:
                    continue
                d = chunk.choices[0].delta
                text += d.content or ""
                for tc in d.tool_calls or []:
                    s = calls.setdefault(tc.index, {"id": "", "name": "", "arguments": ""})
                    s["id"] = tc.id or s["id"]
                    if tc.function:
                        s["name"] += tc.function.name or ""
                        s["arguments"] += tc.function.arguments or ""
            tool_calls = [{"id": v["id"], "type": "function",
                           "function": {"name": v["name"], "arguments": v["arguments"]}}
                          for _, v in sorted(calls.items())]
        else:
            msg = (await client.chat.completions.create(
                model=ns.model, messages=messages, tools=c.openai_tools())).choices[0].message
            text, tool_calls = msg.content or "", [t.model_dump() for t in msg.tool_calls or []]
        if not tool_calls:
            return text
        messages.append({"role": "assistant", "content": None, "tool_calls": tool_calls})
        for tc in tool_calls:
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": c.call_tool(
                tc["function"]["name"], json.loads(tc["function"]["arguments"]))})
    raise RuntimeError("step limit")


async def main() -> list[str]:
    client = AsyncOpenAI(base_url=ns.openai_base, api_key=os.environ["OPENAI_API_KEY"])
    results = await asyncio.gather(*(loop(client, i) for i in range(FANOUT)),
                                   return_exceptions=True)
    c.TOOL_LOG.sort()  # completion order across tasks is not part of the agent's output
    return [r if isinstance(r, str) else c.exception_text(r) for r in results]


c.run(ns.out, lambda: asyncio.run(main()))
