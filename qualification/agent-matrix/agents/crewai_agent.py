# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CrewAI one-agent crew over ``crewai.LLM(model="openai/...", base_url=...)``."""

from __future__ import annotations

import os

import _common as c
from crewai import LLM, Agent, Crew, Task
from crewai.tools import tool

ns = c.args()


@tool("get_weather")
def get_weather(city: str) -> str:
    """Current temperature for a city, in Celsius."""
    return c.get_weather(city)


@tool("c_to_f")
def c_to_f(celsius: float) -> str:
    """Convert Celsius to Fahrenheit."""
    return c.c_to_f(celsius)


def body() -> str:
    llm = LLM(model="openai/" + ns.model, base_url=ns.openai_base,
              api_key=os.environ["OPENAI_API_KEY"], stream=ns.stream)
    agent = Agent(role="Weather analyst", goal="Answer weather questions with the tools.",
                  backstory="A careful analyst.", tools=[get_weather, c_to_f], llm=llm,
                  max_iter=c.MAX_STEPS, verbose=False, multimodal=ns.image)
    description = c.prompt()
    if ns.image:
        description += " Image: " + c.image_data_urls()[0]
    task = Task(description=description, expected_output="The temperature in Fahrenheit.",
                agent=agent)
    return str(Crew(agents=[agent], tasks=[task], verbose=False).kickoff().raw)


c.run(ns.out, body)
