# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""multiprocessing: a pool of four worker processes, each running tool loops with its own
``OpenAI`` client (``--variant fork`` uses the fork start method; default: spawn, the
macOS and Windows default). The ``-join`` variants close and join the pool instead of
leaving the ``with`` block, whose ``__exit__`` terminates the workers."""

from __future__ import annotations

import json
import multiprocessing
import os

import _common as c
from openai import OpenAI

TASKS = 8


def work(args: tuple[int, str, str, bool]) -> tuple[str, list]:
    """One task; an exception is returned as text (SDK exceptions do not unpickle, which
    would hang ``Pool.map`` in the parent)."""
    try:
        return _work(args)
    except Exception as exc:  # noqa: BLE001
        return c.exception_text(exc), list(c.TOOL_LOG)


def _work(args: tuple[int, str, str, bool]) -> tuple[str, list]:
    i, base, model, stream = args
    c.TOOL_LOG.clear()
    client = OpenAI(base_url=base, api_key=os.environ["OPENAI_API_KEY"])
    messages: list[dict] = [{"role": "user", "content": c.prompt(f" (task {i})")}]
    for _ in range(c.MAX_STEPS):
        if stream:
            text, calls = "", {}
            for chunk in client.chat.completions.create(model=model, messages=messages,
                                                        tools=c.openai_tools(), stream=True):
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
            msg = client.chat.completions.create(model=model, messages=messages,
                                                 tools=c.openai_tools()).choices[0].message
            text, tool_calls = msg.content or "", [t.model_dump() for t in msg.tool_calls or []]
        if not tool_calls:
            return text, list(c.TOOL_LOG)
        messages.append({"role": "assistant", "content": None, "tool_calls": tool_calls})
        for tc in tool_calls:
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": c.call_tool(
                tc["function"]["name"], json.loads(tc["function"]["arguments"]))})
    raise RuntimeError("step limit")


if __name__ == "__main__":
    ns = c.args()

    def body() -> list[str]:
        ctx = multiprocessing.get_context("fork" if ns.variant.startswith("fork") else "spawn")
        tasks = [(i, ns.openai_base, ns.model, ns.stream) for i in range(TASKS)]
        if ns.variant.endswith("join"):  # graceful: workers exit through their own cleanup
            pool = ctx.Pool(4)
            done = pool.map(work, tasks)
            pool.close()
            pool.join()
        else:  # the idiomatic context manager: __exit__ calls terminate() (SIGTERM)
            with ctx.Pool(4) as pool:
                done = pool.map(work, tasks)
        for _, log in done:
            c.TOOL_LOG.extend(log)
        c.TOOL_LOG.sort()
        return [text for text, _ in done]

    c.run(ns.out, body)
