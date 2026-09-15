# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Decision single-use and non-overlap recorder contract."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from fabric import ConcurrentDecisionUseError, Fabric, FabricConfig, MemoryKind

if TYPE_CHECKING:
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


def test_sequential_capture_calls_do_not_trip(span_exporter: InMemorySpanExporter) -> None:
    with _client().decision(session_id="s", request_id="r") as decision:
        decision.set_attribute("k", "v")
        decision.remember(kind=MemoryKind.EPISODIC, key="m", content="c")
        decision.record_retrieval("rag", query="q", result_count=1)
        decision.checkpoint("step")
    assert any(span.name == "fabric.decision" for span in span_exporter.get_finished_spans())


def test_overlapping_mutation_is_rejected() -> None:
    with _client().decision(session_id="s", request_id="r") as decision:
        # Hold the same non-blocking overlap sentinel a concurrent capture
        # operation would hold. The public call must fail fast, not race.
        assert decision._busy.acquire(blocking=False)
        try:
            with pytest.raises(ConcurrentDecisionUseError):
                decision.set_attribute("racing", "value")
        finally:
            decision._busy.release()


def test_double_enter_and_reuse_raise() -> None:
    decision = _client().decision(session_id="s", request_id="r")
    decision.__enter__()
    try:
        with pytest.raises(RuntimeError):
            decision.__enter__()
    finally:
        decision.__exit__(None, None, None)
    with pytest.raises(RuntimeError):
        decision.__enter__()


def test_async_double_enter_raises() -> None:
    async def drive() -> None:
        decision = _client().decision(session_id="s", request_id="r")
        await decision.__aenter__()
        try:
            with pytest.raises(RuntimeError):
                await decision.__aenter__()
        finally:
            await decision.__aexit__(None, None, None)

    asyncio.run(drive())


def test_two_distinct_decisions_are_independent() -> None:
    client = _client()
    with (
        client.decision(session_id="s1", request_id="r1") as first,
        client.decision(session_id="s2", request_id="r2") as second,
    ):
        assert first._busy.acquire(blocking=False)
        try:
            second.set_attribute("independent", "ok")
        finally:
            first._busy.release()
