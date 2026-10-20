# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AG2 1.x ``Agent`` with function tools over ``OpenAIConfig(base_url=...)`` (AG2's own
``AsyncOpenAI`` client)."""

from __future__ import annotations

import asyncio
import os

import _common as c
from ag2 import Agent, ImageInput, TextInput
from ag2.config import OpenAIConfig

ns = c.args()


def get_weather(city: str) -> str:
    """Current temperature for a city, in Celsius."""
    return c.get_weather(city)


def c_to_f(celsius: float) -> str:
    """Convert Celsius to Fahrenheit."""
    return c.c_to_f(celsius)


async def main() -> str:
    config = OpenAIConfig(model=ns.model, base_url=ns.openai_base,
                          api_key=os.environ["OPENAI_API_KEY"], streaming=ns.stream)
    agent = Agent("assistant", prompt="Answer weather questions with the tools.",
                  config=config, tools=[get_weather, c_to_f])
    msg: list = [c.prompt()]
    if ns.image:
        msg = [TextInput(c.prompt())] + [ImageInput(data=png, media_type="image/png")
                                         for png in c.images()]
    reply = await agent.ask(*msg)
    return str(reply.body)


c.run(ns.out, lambda: asyncio.run(main()))
