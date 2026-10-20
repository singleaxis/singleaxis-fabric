# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AutoGen AgentChat ``AssistantAgent`` over ``OpenAIChatCompletionClient(base_url=...)``."""

from __future__ import annotations

import asyncio
import base64
import os

import _common as c
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.messages import MultiModalMessage, TextMessage
from autogen_ext.models.openai import OpenAIChatCompletionClient

ns = c.args()


async def get_weather(city: str) -> str:
    """Current temperature for a city, in Celsius."""
    return c.get_weather(city)


async def c_to_f(celsius: float) -> str:
    """Convert Celsius to Fahrenheit."""
    return c.c_to_f(celsius)


async def main() -> str:
    client = OpenAIChatCompletionClient(
        model=ns.model, base_url=ns.openai_base, api_key=os.environ["OPENAI_API_KEY"],
        model_info={"vision": True, "function_calling": True, "json_output": False,
                    "family": "unknown", "structured_output": False,
                    "multiple_system_messages": True})
    agent = AssistantAgent("assistant", model_client=client, tools=[get_weather, c_to_f],
                           max_tool_iterations=c.MAX_STEPS, model_client_stream=ns.stream)
    task: object = c.prompt()
    if ns.image:
        from autogen_core import Image

        task = MultiModalMessage(source="user", content=[c.prompt()] + [
            Image.from_base64(base64.b64encode(png).decode()) for png in c.images()])
    else:
        task = TextMessage(source="user", content=c.prompt())
    if ns.stream:
        result = None
        async for item in agent.run_stream(task=task):
            result = item
    else:
        result = await agent.run(task=task)
    await client.close()
    return str(result.messages[-1].content)


c.run(ns.out, lambda: asyncio.run(main()))
