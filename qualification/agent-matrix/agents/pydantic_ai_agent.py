# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""PydanticAI agent over ``OpenAIChatModel`` with an ``OpenAIProvider(base_url=...)``
(``--variant anthropic``: ``AnthropicModel`` with an ``AnthropicProvider(base_url=...)``)."""

from __future__ import annotations

import asyncio
import os

import _common as c
from pydantic_ai import Agent, BinaryContent
from pydantic_ai.usage import UsageLimits

ns = c.args()


def model():
    if ns.variant == "anthropic":
        from pydantic_ai.models.anthropic import AnthropicModel
        from pydantic_ai.providers.anthropic import AnthropicProvider

        return AnthropicModel(ns.model, provider=AnthropicProvider(
            base_url=ns.anthropic_base, api_key=os.environ["ANTHROPIC_API_KEY"]))
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

    return OpenAIChatModel(ns.model, provider=OpenAIProvider(
        base_url=ns.openai_base, api_key=os.environ["OPENAI_API_KEY"]))


async def main() -> str:
    agent = Agent(model(), instructions="Answer weather questions with the tools.")

    @agent.tool_plain
    def get_weather(city: str) -> str:
        """Current temperature for a city, in Celsius."""
        return c.get_weather(city)

    @agent.tool_plain
    def c_to_f(celsius: float) -> str:
        """Convert Celsius to Fahrenheit."""
        return c.c_to_f(celsius)

    task: object = c.prompt()
    if ns.image:
        task = [c.prompt()] + [BinaryContent(data=png, media_type="image/png") for png in c.images()]
    limits = UsageLimits(request_limit=2 * c.MAX_STEPS)
    if ns.stream:
        async with agent.run_stream(task, usage_limits=limits) as result:
            return str(await result.get_output())
    return str((await agent.run(task, usage_limits=limits)).output)


c.run(ns.out, lambda: asyncio.run(main()))
