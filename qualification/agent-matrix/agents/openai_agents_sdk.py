# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""OpenAI Agents SDK (Responses model by default; `--variant chat` uses the Chat
Completions model; `--variant handoff` is a triage agent handing off to a specialist).
The client is an ``AsyncOpenAI`` with the normal ``base_url``."""

from __future__ import annotations

import asyncio
import os

import _common as c
from agents import (Agent, ModelSettings, OpenAIChatCompletionsModel, OpenAIResponsesModel,
                    Runner, function_tool, set_tracing_disabled)
from openai import AsyncOpenAI

ns = c.args()
set_tracing_disabled(True)


@function_tool
def get_weather(city: str) -> str:
    """Current temperature for a city, in Celsius."""
    return c.get_weather(city)


@function_tool
def c_to_f(celsius: float) -> str:
    """Convert Celsius to Fahrenheit."""
    return c.c_to_f(celsius)


async def main() -> str:
    client = AsyncOpenAI(base_url=ns.openai_base, api_key=os.environ["OPENAI_API_KEY"])
    model = (OpenAIChatCompletionsModel(model=ns.model, openai_client=client)
             if ns.variant == "chat" else OpenAIResponsesModel(model=ns.model, openai_client=client))
    specialist = Agent(name="weather_specialist", instructions="Answer weather questions.",
                       tools=[get_weather, c_to_f], model=model,
                       model_settings=ModelSettings(parallel_tool_calls=True))
    entry = specialist
    if ns.variant == "handoff":
        entry = Agent(name="triage", instructions="Route weather questions to the specialist.",
                      handoffs=[specialist], model=model)
    task: object = c.prompt()
    if ns.image:
        task = [{"role": "user", "content": [{"type": "input_text", "text": c.prompt()}] + [
            {"type": "input_image", "image_url": u, "detail": "auto"} for u in c.image_data_urls()]}]
    if ns.stream:
        result = Runner.run_streamed(entry, task, max_turns=c.MAX_STEPS)
        async for _ in result.stream_events():
            pass
        return str(result.final_output)
    result = await Runner.run(entry, task, max_turns=c.MAX_STEPS)
    return str(result.final_output)


c.run(ns.out, lambda: asyncio.run(main()))
