# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""LangGraph prebuilt ReAct agent over LangChain's ``ChatOpenAI`` (``base_url``)."""

from __future__ import annotations

import os
import warnings

import _common as c
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from langgraph.prebuilt import create_react_agent

ns = c.args()


@tool
def get_weather(city: str) -> str:
    """Current temperature for a city, in Celsius."""
    return c.get_weather(city)


@tool
def c_to_f(celsius: float) -> str:
    """Convert Celsius to Fahrenheit."""
    return c.c_to_f(celsius)


def body() -> str:
    llm = ChatOpenAI(model=ns.model, base_url=ns.openai_base, api_key=os.environ["OPENAI_API_KEY"],
                     streaming=ns.stream)
    agent = create_react_agent(llm, [get_weather, c_to_f])
    content: object = c.prompt()
    if ns.image:
        content = [{"type": "text", "text": c.prompt()}] + [
            {"type": "image_url", "image_url": {"url": u}} for u in c.image_data_urls()]
    state = {"messages": [HumanMessage(content=content)]}
    config = {"recursion_limit": 4 * c.MAX_STEPS}
    if ns.stream:
        last = None
        for last in agent.stream(state, config=config, stream_mode="values"):
            pass
        return str(last["messages"][-1].content)
    return str(agent.invoke(state, config=config)["messages"][-1].content)


c.run(ns.out, body)
