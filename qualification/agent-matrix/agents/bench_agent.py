# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Latency benchmark: the wall time of each SDK call, measured around the call.
Kinds: ``nonstream`` (one chat completion / message), ``stream`` (one streamed call,
consumed fully), ``nonmatching`` (a GET the tee does not match: ``models.list``)."""

from __future__ import annotations

import os
import time

import _common as c

ns = c.args()
N, NS, NM, WARM = 300, 150, 150, 20


def body() -> dict:
    out: dict[str, list[float]] = {"nonstream": [], "stream": [], "nonmatching": []}
    msgs = [{"role": "user", "content": "hi"}]
    if ns.variant == "anthropic":
        from anthropic import Anthropic

        client = Anthropic(base_url=ns.anthropic_base, api_key=os.environ["ANTHROPIC_API_KEY"])
        one = lambda: client.messages.create(model="fm-s0-p1-none", max_tokens=16, messages=msgs)

        def streamed() -> None:
            with client.messages.stream(model="fm-s0-p1-none", max_tokens=16, messages=msgs) as s:
                s.get_final_message()

        other = lambda: client.models.list()
    else:
        from openai import OpenAI

        client = OpenAI(base_url=ns.openai_base, api_key=os.environ["OPENAI_API_KEY"])
        one = lambda: client.chat.completions.create(model="fm-s0-p1-none", messages=msgs)

        def streamed() -> None:
            for _ in client.chat.completions.create(model="fm-s0-p1-none", messages=msgs,
                                                    stream=True):
                pass

        other = lambda: client.models.list()
    for kind, fn, n in (("nonstream", one, N), ("stream", streamed, NS), ("nonmatching", other, NM)):
        for i in range(n + WARM):
            t0 = time.perf_counter()
            fn()
            dt = time.perf_counter() - t0
            if i >= WARM:
                out[kind].append(dt)
    return out


c.run(ns.out, body)
