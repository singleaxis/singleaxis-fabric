# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification with the real OpenAI and Anthropic SDK clients (decision D1).

The SDKs run unmodified, with their default (httpx2) transports, against a
loopback fake on a real socket. Each call must yield exactly one exchange whose
stored request/response bytes equal the bytes on the wire. Skips when an SDK
is not installed.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from . import test_wire_httpx2 as base
from .test_wire_httpx2 import FakeLLM, Installed, assert_exact_capture

pytest.importorskip("httpx2")
fake_llm, installed = base.fake_llm, base.installed  # shared fixtures


def _drain(stream: Any) -> int:
    return sum(1 for _ in stream)


async def _adrain(stream: Any) -> int:
    return len([event async for event in stream])


def test_openai_sync_async_and_streaming(installed: Installed, fake_llm: FakeLLM) -> None:
    openai = pytest.importorskip("openai")
    base_url, messages = f"http://127.0.0.1:{fake_llm.port}/v1", [{"role": "user", "content": "x"}]
    client = openai.OpenAI(api_key="test", base_url=base_url, max_retries=0)
    reply = client.chat.completions.create(model="gpt-fake", messages=messages)
    assert reply.choices[0].message.content == "Hi."
    stream = client.chat.completions.create(model="gpt-fake", messages=messages, stream=True)
    assert _drain(stream) == 2
    client.close()

    async def run_async() -> None:
        aclient = openai.AsyncOpenAI(api_key="test", base_url=base_url, max_retries=0)
        reply = await aclient.chat.completions.create(model="gpt-fake", messages=messages)
        assert reply.choices[0].message.content == "Hi."
        stream = await aclient.chat.completions.create(
            model="gpt-fake", messages=messages, stream=True
        )
        assert await _adrain(stream) == 2
        await aclient.close()

    asyncio.run(run_async())
    # openai>=3 stops reading at ``[DONE]`` and closes the response before EOF:
    # every body byte was teed, but the stream honestly ended ``closed_early``.
    states = ["complete", "closed_early"] * 2
    found = assert_exact_capture(installed, fake_llm, states)
    assert {(a["fabric.wire.api"], a["gen_ai.provider.name"]) for a in found} == {
        ("openai.chat_completions", "openai")
    }
    assert found[0]["http.response.status_code"] == 200


def test_anthropic_sync_async_and_streaming(installed: Installed, fake_llm: FakeLLM) -> None:
    anthropic = pytest.importorskip("anthropic")
    base_url = f"http://127.0.0.1:{fake_llm.port}"
    kwargs: dict[str, Any] = {
        "model": "claude-fake-1", "max_tokens": 8, "messages": [{"role": "user", "content": "x"}],
    }  # fmt: skip
    client = anthropic.Anthropic(api_key="test", base_url=base_url, max_retries=0)
    assert client.messages.create(**kwargs).content[0].text == "Hi."
    assert _drain(client.messages.create(**kwargs, stream=True)) == 6
    with client.messages.stream(**kwargs) as stream:  # the SDK's helper stream
        assert stream.get_final_message().content[0].text == "Hi."
    client.close()

    async def run_async() -> None:
        aclient = anthropic.AsyncAnthropic(api_key="test", base_url=base_url, max_retries=0)
        assert (await aclient.messages.create(**kwargs)).content[0].text == "Hi."
        assert await _adrain(await aclient.messages.create(**kwargs, stream=True)) == 6
        await aclient.close()

    asyncio.run(run_async())
    found = assert_exact_capture(installed, fake_llm, ["complete"] * 5)
    assert {(a["fabric.wire.api"], a["gen_ai.provider.name"]) for a in found} == {
        ("anthropic.messages", "anthropic")
    }
    assert all(exchange.path == "/v1/messages" for exchange in fake_llm.seen)
