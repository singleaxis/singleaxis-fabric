# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Async call-style tests for passive recorder contexts and child spans."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from uuid import UUID

from opentelemetry.trace import StatusCode

from fabric import Decision, Fabric, FabricConfig, MemoryKind
from fabric._calls import FABRIC_LLM_REQUEST_MODEL, FABRIC_TOOL_NAME

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import ReadableSpan
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


def _record(decision: Decision, checkpoint_id: UUID) -> None:
    decision.set_attribute("agent.custom", "ok")
    decision.remember(kind=MemoryKind.EPISODIC, key="k", content="v")
    decision.record_retrieval("rag", query="q", result_count=2)
    decision.checkpoint("after-retrieval", checkpoint_id=checkpoint_id)


def _normalize(span: ReadableSpan) -> dict[str, object]:
    return {
        "name": span.name,
        "kind": span.kind.name,
        "status": span.status.status_code.name,
        "attributes": dict(span.attributes or {}),
        "events": [
            {"name": event.name, "attributes": dict(event.attributes or {})}
            for event in span.events
        ],
    }


def test_async_with_emits_same_span_as_sync_with(span_exporter: InMemorySpanExporter) -> None:
    checkpoint_id = UUID("00000000-0000-4000-8000-000000000001")
    decision_id = "decision-fixed-0001"
    with _client().decision(
        session_id="s", request_id="r", user_id="u", decision_id=decision_id
    ) as decision:
        _record(decision, checkpoint_id)
    sync_span = next(
        span for span in span_exporter.get_finished_spans() if span.name == "fabric.decision"
    )
    expected = _normalize(sync_span)
    span_exporter.clear()

    async def drive() -> None:
        async with _client().decision(
            session_id="s", request_id="r", user_id="u", decision_id=decision_id
        ) as decision:
            _record(decision, checkpoint_id)

    asyncio.run(drive())
    async_span = next(
        span for span in span_exporter.get_finished_spans() if span.name == "fabric.decision"
    )
    assert _normalize(async_span) == expected


def test_async_exit_records_exception(span_exporter: InMemorySpanExporter) -> None:
    async def drive() -> None:
        try:
            async with _client().decision(session_id="s", request_id="r"):
                raise RuntimeError("boom")
        except RuntimeError:
            pass

    asyncio.run(drive())
    span = next(
        span for span in span_exporter.get_finished_spans() if span.name == "fabric.decision"
    )
    assert span.status.status_code == StatusCode.ERROR
    assert any(event.name == "exception" for event in span.events)


def test_async_llm_and_tool_child_spans(span_exporter: InMemorySpanExporter) -> None:
    async def drive() -> None:
        async with _client().decision(session_id="s", request_id="r") as decision:
            async with decision.llm_call(system="anthropic", model="claude-opus-4-7") as call:
                call.set_usage(input_tokens=10, output_tokens=5)
            async with decision.tool_call("vector_search") as call:
                call.set_result_count(3)

    asyncio.run(drive())
    spans = span_exporter.get_finished_spans()
    llm = next(
        span for span in spans if (span.attributes or {}).get("gen_ai.operation.name") == "chat"
    )
    tool = next(
        span
        for span in spans
        if (span.attributes or {}).get("gen_ai.operation.name") == "execute_tool"
    )
    assert dict(llm.attributes or {})[FABRIC_LLM_REQUEST_MODEL] == "claude-opus-4-7"
    assert dict(tool.attributes or {})[FABRIC_TOOL_NAME] == "vector_search"


def test_record_retrieval_inside_async_block(span_exporter: InMemorySpanExporter) -> None:
    async def drive() -> None:
        async with _client().decision(session_id="s", request_id="r") as decision:
            decision.record_retrieval("rag", query="q", result_count=4)

    asyncio.run(drive())
    span = next(
        span for span in span_exporter.get_finished_spans() if span.name == "fabric.decision"
    )
    event = next(event for event in span.events if event.name == "fabric.retrieval")
    assert dict(event.attributes or {})["fabric.retrieval.result_count"] == 4
