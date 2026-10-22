# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Agent matrix D3: an asyncio fan-out of 408 calls in about a second overflowed the
256-entry capture queue (34% lost in file mode, as queue_full). At default settings the
same burst is captured whole; a queue that does overflow stays an accounted loss."""

from __future__ import annotations

import textwrap
from pathlib import Path

from ._wire_live import FakeModel, OtlpSink, capture_env, reconstruct, run_agent, verdicts, wait_for

LOOPS, STEPS = 8, 51

# The agent-matrix ``gather / long50`` case: eight concurrent 51-step loops on one
# AsyncOpenAI client, each request carrying the whole growing conversation.
GATHER_AGENT = (
    textwrap.dedent(
        """
    import asyncio, os
    from openai import AsyncOpenAI

    async def loop(client, i):
        messages = [{"role": "user", "content": f"worker {i}"}]
        for step in range(STEPS):
            reply = await client.chat.completions.create(model="m", messages=messages)
            messages.append({"role": "assistant", "content": reply.choices[0].message.content})
            messages.append({"role": "user", "content": f"step {step}: " + "x" * 200})
        return "done"

    async def main():
        client = AsyncOpenAI(base_url=os.environ["LIVE_MODEL_BASE"], api_key="sk-live-fake")
        print("RESULT", await asyncio.gather(*(loop(client, i) for i in range(LOOPS))))

    asyncio.run(main())
    """
    )
    .replace("STEPS", str(STEPS))
    .replace("LOOPS", str(LOOPS))
)


def _run(tmp_path: Path, **extra: str) -> tuple[FakeModel, OtlpSink, Path, dict[str, object]]:
    model, sink = FakeModel(), OtlpSink(tmp_path / "otlp")
    (store := tmp_path / "store").mkdir()
    (script := tmp_path / "gather.py").write_text(GATHER_AGENT, encoding="utf-8")
    result = run_agent(script, capture_env(model, sink, store, **extra), timeout_s=180)
    return model, sink, store, result


def test_a_gather_fan_out_is_captured_whole_at_default_settings(tmp_path: Path) -> None:
    model, sink, store, result = _run(tmp_path)
    try:
        assert result["returncode"] == 0, str(result["stderr"])[-2000:]
        calls = LOOPS * STEPS
        assert len(model.requests) == calls
        assert wait_for(lambda: len(sink.exchanges()) >= calls, timeout_s=20)
        assert len(sink.exchanges()) == calls
        assert not sink.losses()
        found = verdicts(reconstruct(sink.directory, store, tmp_path / "report.json"))
        assert found and set(found) == {"complete_for_declared_scope"}
    finally:
        model.close()
        sink.close()


def test_an_overflowing_queue_is_an_accounted_loss(tmp_path: Path) -> None:
    model, sink, store, result = _run(tmp_path, FABRIC_WIRE_QUEUE_MAX_ITEMS="1")
    try:
        assert result["returncode"] == 0, str(result["stderr"])[-2000:]
        calls = LOOPS * STEPS
        wait_for(lambda: len(sink.exchanges()) + sum(
            int(x["fabric.loss.count"]) for x in sink.losses()) >= calls, timeout_s=20)  # fmt: skip
        lost = sum(int(x["fabric.loss.count"]) for x in sink.losses())
        assert lost and len(sink.exchanges()) + lost == calls
        assert {x["fabric.loss.reason"] for x in sink.losses()} == {"queue_full"}
        found = verdicts(reconstruct(sink.directory, store, tmp_path / "report.json"))
        assert found and "complete_for_declared_scope" not in found
    finally:
        model.close()
        sink.close()
