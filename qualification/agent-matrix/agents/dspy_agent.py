# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""DSPy ``ReAct`` over ``dspy.LM("openai/...", api_base=...)`` (LiteLLM underneath). The
LM cache is off so every run reaches the model."""

from __future__ import annotations

import asyncio
import os

import _common as c
import dspy

ns = c.args()


def get_weather(city: str) -> str:
    """Current temperature for a city, in Celsius."""
    return c.get_weather(city)


def c_to_f(celsius: float) -> str:
    """Convert Celsius to Fahrenheit."""
    return c.c_to_f(celsius)


def body() -> str:
    lm = dspy.LM("openai/" + ns.model, api_base=ns.openai_base,
                 api_key=os.environ["OPENAI_API_KEY"], cache=False, num_retries=3)
    dspy.configure(lm=lm)
    if ns.image:
        sig = dspy.Signature("question: str, image: dspy.Image -> answer: str")
        program = dspy.ReAct(sig, tools=[get_weather, c_to_f], max_iters=c.MAX_STEPS)
        kwargs = {"question": c.prompt(), "image": dspy.Image(c.image_data_urls()[0])}
    else:
        program = dspy.ReAct("question -> answer", tools=[get_weather, c_to_f],
                             max_iters=c.MAX_STEPS)
        kwargs = {"question": c.prompt()}
    if ns.stream:
        streaming = dspy.streamify(program, stream_listeners=[
            dspy.streaming.StreamListener(signature_field_name="answer")])

        async def go() -> str:
            final = None
            async for item in streaming(**kwargs):
                if isinstance(item, dspy.Prediction):
                    final = item
            return str(final.answer)

        return asyncio.run(go())
    return str(program(**kwargs).answer)


c.run(ns.out, body)
