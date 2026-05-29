# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Async facade for Decision / LLMCall / ToolCall.

The async surface is a thin, honest non-blocking *call style* over the
existing sync span/event logic: the same span/event bytes are emitted
whether ``with`` or ``async with`` is used, and the blocking guardrail /
adapter / transport I/O is offloaded to a worker thread via
``asyncio.to_thread`` so the event loop is never blocked.

Following the repo convention in ``test_mcp_integration.py``, coroutines
are driven with ``asyncio.run`` rather than ``pytest.mark.asyncio``
(pytest-asyncio is not a test dependency and the suite enables no asyncio
markers).
"""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING
from uuid import UUID

from opentelemetry.trace import StatusCode

from fabric import (
    CheckerVerdict,
    Fabric,
    FabricConfig,
    JudgeContext,
    LocalQueueTransport,
    MemoryKind,
    PolicyEvaluation,
    ToolAuthorization,
)
from fabric._calls import (
    FABRIC_LLM_REQUEST_MODEL,
    FABRIC_TOOL_NAME,
    LLM_CALL_SPAN_NAME,
    TOOL_CALL_SPAN_NAME,
)
from fabric.decision import SPAN_NAME
from fabric.policy import EngineVerdict

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import ReadableSpan
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )


# -- stub rails/adapters ------------------------------------------------


class _RedactingChecker:
    """Deterministic guardrail checker: replaces SECRET with [REDACTED]."""

    name = "stub-redactor"

    def __init__(self, *, barrier: threading.Event | None = None) -> None:
        self._barrier = barrier

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        if self._barrier is not None:
            # Block the worker thread until the test releases it. Proves
            # the chain runs OFF the event loop: a concurrent coroutine
            # can make progress while this is parked.
            self._barrier.wait(timeout=5.0)
        return CheckerVerdict(action="redact", modified_value=value.replace("SECRET", "[REDACTED]"))

    def close(self) -> None:
        return None


class _StubPolicyEngine:
    engine_name = "stub"

    def evaluate(
        self, *, policy_id: str, input: dict[str, object], timeout_seconds: float
    ) -> EngineVerdict:
        return EngineVerdict(decision="allow")

    def close(self) -> None:
        return None


class _StubAuthorizer:
    def authorize(self, *, tool_name: str, arguments_hash: str | None) -> ToolAuthorization:
        return ToolAuthorization(decision="allow")


def _client(*, checker: _RedactingChecker | None = None) -> Fabric:
    return Fabric(
        FabricConfig(tenant_id="acme", agent_id="support-bot"),
        guardrail_checkers=[checker] if checker is not None else None,
    )


def _attrs(span: ReadableSpan) -> dict[str, object]:
    return dict(span.attributes or {})


def _normalize(span: ReadableSpan) -> dict[str, object]:
    """Comparable, time-independent view of a span's attributes + events."""
    return {
        "name": span.name,
        "kind": span.kind.name,
        "status": span.status.status_code.name,
        "attributes": _attrs(span),
        "events": [
            {"name": ev.name, "attributes": dict(ev.attributes or {})} for ev in span.events
        ],
    }


# -- async context manager: byte-identical span -------------------------


def test_async_with_emits_same_span_as_sync_with(span_exporter: InMemorySpanExporter) -> None:
    """`async with` and `with` produce byte-identical decision spans.

    A fixed ``checkpoint_id`` is supplied so the otherwise-random uuid4
    on the checkpoint event does not introduce run-to-run noise — the
    point is to prove the async call style emits the same bytes as the
    sync one, not to test uuid generation.
    """
    fixed_ckpt = UUID("00000000-0000-4000-8000-000000000001")

    def drive_sync() -> None:
        client = _client()
        with client.decision(session_id="s", request_id="r", user_id="u") as dec:
            dec.set_attribute("agent.custom", "ok")
            dec.remember(kind=MemoryKind.EPISODIC, key="k", content="v")
            dec.record_retrieval("rag", query="q", result_count=2)
            dec.checkpoint("after-retrieval", checkpoint_id=fixed_ckpt)

    async def drive_async() -> None:
        client = _client()
        async with client.decision(session_id="s", request_id="r", user_id="u") as dec:
            dec.set_attribute("agent.custom", "ok")
            dec.remember(kind=MemoryKind.EPISODIC, key="k", content="v")
            dec.record_retrieval("rag", query="q", result_count=2)
            dec.checkpoint("after-retrieval", checkpoint_id=fixed_ckpt)

    drive_sync()
    sync_span = span_exporter.get_finished_spans()[0]
    sync_view = _normalize(sync_span)

    span_exporter.clear()

    asyncio.run(drive_async())
    async_span = span_exporter.get_finished_spans()[0]
    async_view = _normalize(async_span)

    assert async_view == sync_view


def test_async_exit_records_exception_like_sync(span_exporter: InMemorySpanExporter) -> None:
    """An exception inside `async with` marks the span ERROR, as sync does."""

    async def drive() -> None:
        client = _client()
        try:
            async with client.decision(session_id="s", request_id="r"):
                raise RuntimeError("boom")
        except RuntimeError:
            pass

    asyncio.run(drive())
    span = span_exporter.get_finished_spans()[0]
    assert span.status.status_code == StatusCode.ERROR
    assert (span.status.description or "").startswith("RuntimeError")
    assert any(ev.name == "exception" for ev in span.events)


# -- async guard methods ------------------------------------------------


def test_aguard_input_redacts_identically_to_sync(span_exporter: InMemorySpanExporter) -> None:
    """`await d.aguard_input(x)` redacts identically to sync `guard_input`."""
    sync_client = _client(checker=_RedactingChecker())
    with sync_client.decision(session_id="s", request_id="r") as dec:
        sync_out = dec.guard_input("my SECRET token")
    assert sync_out == "my [REDACTED] token"

    async def drive() -> str:
        client = _client(checker=_RedactingChecker())
        async with client.decision(session_id="s", request_id="r") as dec:
            return await dec.aguard_input("my SECRET token")

    async_out = asyncio.run(drive())
    assert async_out == sync_out


def test_aguard_output_variants_redact(span_exporter: InMemorySpanExporter) -> None:
    """All three async guard variants run the chain and redact."""

    async def drive() -> tuple[str, str]:
        client = _client(checker=_RedactingChecker())
        async with client.decision(session_id="s", request_id="r") as dec:
            chunk = await dec.aguard_output_chunk("a SECRET chunk")
            final = await dec.aguard_output_final("a SECRET final")
            return chunk, final

    chunk, final = asyncio.run(drive())
    assert chunk == "a [REDACTED] chunk"
    assert final == "a [REDACTED] final"


def test_aguard_input_runs_off_the_event_loop(span_exporter: InMemorySpanExporter) -> None:
    """The chain runs in a worker thread, so a concurrent task progresses.

    The stub checker parks on a threading.Event. While the guard call is
    awaited, a sibling coroutine increments a counter. If the guard had
    blocked the loop, the counter could not advance before the barrier is
    released — deterministic because we only release the barrier *after*
    observing the counter advanced.
    """
    barrier = threading.Event()
    progressed = asyncio.Event()

    async def drive() -> tuple[int, str]:
        client = _client(checker=_RedactingChecker(barrier=barrier))
        counter = 0

        async def sibling() -> None:
            nonlocal counter
            # The event loop is free, so this runs while the guard is
            # parked in its worker thread.
            counter += 1
            progressed.set()

        async with client.decision(session_id="s", request_id="r") as dec:
            guard_task = asyncio.create_task(dec.aguard_input("SECRET"))
            sibling_task = asyncio.create_task(sibling())
            # Sibling reaches its body while the guard thread is parked.
            await asyncio.wait_for(progressed.wait(), timeout=5.0)
            assert counter == 1
            # Now release the worker thread and collect the guard result.
            barrier.set()
            redacted = await guard_task
            await asyncio.wait_for(sibling_task, timeout=5.0)
        return counter, redacted

    counter, redacted = asyncio.run(drive())
    assert counter == 1
    assert redacted == "[REDACTED]"


# -- async child spans --------------------------------------------------


def test_async_llm_call_opens_and_closes_child_span(
    span_exporter: InMemorySpanExporter,
) -> None:
    async def drive() -> None:
        client = _client()
        # Nested (not combined): the child span must be opened *inside*
        # the entered decision so it parents correctly.
        async with client.decision(session_id="s", request_id="r") as dec:  # noqa: SIM117
            async with dec.llm_call(system="anthropic", model="claude-opus-4-7") as call:
                call.set_usage(input_tokens=10, output_tokens=5)

    asyncio.run(drive())
    spans = span_exporter.get_finished_spans()
    names = {s.name for s in spans}
    assert {SPAN_NAME, LLM_CALL_SPAN_NAME} <= names
    llm_span = next(s for s in spans if s.name == LLM_CALL_SPAN_NAME)
    assert _attrs(llm_span)[FABRIC_LLM_REQUEST_MODEL] == "claude-opus-4-7"


def test_async_tool_call_opens_and_closes_child_span(
    span_exporter: InMemorySpanExporter,
) -> None:
    async def drive() -> None:
        client = _client()
        async with client.decision(session_id="s", request_id="r") as dec:  # noqa: SIM117
            async with dec.tool_call("vector_search") as tool:
                tool.set_result_count(3)

    asyncio.run(drive())
    spans = span_exporter.get_finished_spans()
    tool_span = next(s for s in spans if s.name == TOOL_CALL_SPAN_NAME)
    assert _attrs(tool_span)[FABRIC_TOOL_NAME] == "vector_search"


# -- recording methods inside an async block ----------------------------


def test_record_retrieval_inside_async_block(span_exporter: InMemorySpanExporter) -> None:
    """A pure-CPU recording method works (and emits) inside `async with`."""

    async def drive() -> None:
        client = _client()
        async with client.decision(session_id="s", request_id="r") as dec:
            dec.record_retrieval("rag", query="q", result_count=4)

    asyncio.run(drive())
    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.retrieval"]
    assert len(events) == 1
    assert dict(events[0].attributes or {})["fabric.retrieval.result_count"] == 4
    assert _attrs(span)["fabric.retrieval_count"] == 1


# -- async I/O-bearing adapters -----------------------------------------


def test_aevaluate_policy_matches_sync(span_exporter: InMemorySpanExporter) -> None:
    """aevaluate_policy emits the same event shape as evaluate_policy."""

    def drive_sync() -> PolicyEvaluation:
        client = _client()
        with client.decision(session_id="s", request_id="r") as dec:
            return dec.evaluate_policy(_StubPolicyEngine(), policy_id="p1", input={"x": 1})

    sync_eval = drive_sync()
    sync_event = next(
        dict(e.attributes or {})
        for e in span_exporter.get_finished_spans()[0].events
        if e.name == "fabric.policy.evaluation"
    )
    span_exporter.clear()

    async def drive_async() -> PolicyEvaluation:
        client = _client()
        async with client.decision(session_id="s", request_id="r") as dec:
            return await dec.aevaluate_policy(_StubPolicyEngine(), policy_id="p1", input={"x": 1})

    async_eval = asyncio.run(drive_async())
    async_event = next(
        dict(e.attributes or {})
        for e in span_exporter.get_finished_spans()[0].events
        if e.name == "fabric.policy.evaluation"
    )

    assert async_eval.decision == sync_eval.decision == "allow"
    # evaluation_id / latency differ per run; the stable keys must match.
    stable = ("fabric.policy.engine", "fabric.policy.policy_id", "fabric.policy.decision")
    assert {k: async_event[k] for k in stable} == {k: sync_event[k] for k in stable}


def test_aauthorize_tool_call_allows(span_exporter: InMemorySpanExporter) -> None:
    async def drive() -> ToolAuthorization:
        client = _client()
        async with client.decision(session_id="s", request_id="r") as dec:
            return await dec.aauthorize_tool_call(
                _StubAuthorizer(), tool_name="search", arguments='{"q": "hi"}'
            )

    auth = asyncio.run(drive())
    assert auth.allowed
    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.tool.authorization"]
    assert len(events) == 1
    assert dict(events[0].attributes or {})["fabric.tool.authorization.decision"] == "allow"


def test_aqueue_judge_enqueues_off_loop(span_exporter: InMemorySpanExporter) -> None:
    transport = LocalQueueTransport()

    async def drive() -> None:
        client = _client()
        async with client.decision(session_id="s", request_id="r") as dec:
            await dec.aqueue_judge(
                rubric_id="r1",
                dimensions=("faithfulness",),
                context=JudgeContext(),
                transport=transport,
            )

    asyncio.run(drive())
    queued = transport.dequeue()
    assert queued is not None
    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.judge.queued"]
    assert len(events) == 1
