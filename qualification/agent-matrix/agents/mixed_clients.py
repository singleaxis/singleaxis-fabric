# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""One process, three HTTP clients to the same model endpoint: the ``openai`` SDK
(httpx), ``requests`` and ``aiohttp``. Only the first is in Fabric's capture claim; the
probe shows what the record says about the other two."""

from __future__ import annotations

import asyncio
import json
import os

import _common as c

ns = c.args()


def body() -> list[str]:
    from openai import OpenAI

    url = ns.openai_base + "/chat/completions"
    payload = {"model": "fm-s0-p1-none", "messages": [{"role": "user", "content": c.prompt()}]}
    headers = {"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]}
    client = OpenAI(base_url=ns.openai_base, api_key=os.environ["OPENAI_API_KEY"])
    out = [client.chat.completions.create(**payload).choices[0].message.content]

    import requests

    out.append(requests.post(url, json=payload, headers=headers, timeout=30).json()
               ["choices"][0]["message"]["content"])

    import aiohttp

    async def aio() -> str:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=json.dumps(payload), headers={
                    **headers, "Content-Type": "application/json"}) as r:
                return (await r.json())["choices"][0]["message"]["content"]

    out.append(asyncio.run(aio()))
    out.append(client.chat.completions.create(**payload).choices[0].message.content)
    return out


c.run(ns.out, body)
