# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""smolagents ``ToolCallingAgent`` over ``OpenAIServerModel`` (``api_base``)."""

from __future__ import annotations

import io
import os

import _common as c
from smolagents import OpenAIServerModel, ToolCallingAgent, tool

ns = c.args()


@tool
def get_weather(city: str) -> str:
    """Current temperature for a city, in Celsius.

    Args:
        city: The city name.
    """
    return c.get_weather(city)


@tool
def c_to_f(celsius: float) -> str:
    """Convert Celsius to Fahrenheit.

    Args:
        celsius: The temperature in Celsius.
    """
    return c.c_to_f(celsius)


def body() -> str:
    model = OpenAIServerModel(model_id=ns.model, api_base=ns.openai_base,
                              api_key=os.environ["OPENAI_API_KEY"])
    agent = ToolCallingAgent(tools=[get_weather, c_to_f], model=model, max_steps=c.MAX_STEPS,
                             stream_outputs=ns.stream, verbosity_level=0)
    images = None
    if ns.image:
        from PIL import Image

        images = [Image.open(io.BytesIO(png)) for png in c.images()]
    return str(agent.run(c.prompt(), images=images))


c.run(ns.out, body)
