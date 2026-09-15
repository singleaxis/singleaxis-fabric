# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CrewAI adapter callbacks record passive, content-safe activity."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig
from fabric.adapters.crewai import attach_callbacks


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


def _event_attrs(
    span_exporter: InMemorySpanExporter,
    event_name: str,
) -> list[dict[str, object]]:
    span = span_exporter.get_finished_spans()[0]
    return [dict(ev.attributes or {}) for ev in span.events if ev.name == event_name]


def test_step_callback_records_content_safe_step_metadata(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        action = SimpleNamespace(tool="search_web", log="calling search_web(query=...)")
        hooks.step(action)

    events = _event_attrs(span_exporter, "fabric.crewai.step")
    assert len(events) == 1
    ev = events[0]
    assert ev["fabric.crewai.event_type"] == "SimpleNamespace"
    assert ev["fabric.crewai.tool"] == "search_web"
    assert ev["fabric.crewai.content_field"] == "log"
    assert ev["fabric.crewai.content_chars"] == len("calling search_web(query=...)")
    assert (
        ev["fabric.crewai.content_sha256"]
        == hashlib.sha256(b"calling search_web(query=...)").hexdigest()
    )
    assert "fabric.crewai.log_preview" not in ev


def test_step_callback_captures_modern_crewai_reasoning_fields(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Regression: current crewai (>=1.x) ``AgentAction`` has no ``.log``
    field — its reasoning lives in ``.thought`` (with ``.text`` / ``.result``
    alongside). Reading only ``.log`` made the preview silently blank on
    modern crewai. The adapter must capture ``.thought`` instead."""

    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        # Shape of a real crewai>=1.x AgentAction: no ``log`` attribute.
        action = SimpleNamespace(
            tool="search_web",
            tool_input='{"query": "..."}',
            thought="I should search the web for the answer",
            text="Thought: I should search...\nAction: search_web",
            result="",
        )
        hooks.step(action)

    ev = _event_attrs(span_exporter, "fabric.crewai.step")[0]
    assert ev["fabric.crewai.tool"] == "search_web"
    # ``thought`` is preferred over ``text`` but only its digest and length
    # are captured; reasoning content must never leak onto the span.
    thought = "I should search the web for the answer"
    assert ev["fabric.crewai.content_field"] == "thought"
    assert ev["fabric.crewai.content_chars"] == len(thought)
    assert ev["fabric.crewai.content_sha256"] == hashlib.sha256(thought.encode()).hexdigest()


def test_step_callback_captures_agentfinish_output_field(
    span_exporter: InMemorySpanExporter,
) -> None:
    """A real crewai ``AgentFinish`` carries ``.output`` / ``.text`` (no
    ``.thought`` content, no ``.log``). The adapter falls through to
    ``output`` so the final answer still lands on the span."""

    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        finish = SimpleNamespace(output="the final answer", text="Final Answer: the final answer")
        hooks.step(finish)

    ev = _event_attrs(span_exporter, "fabric.crewai.step")[0]
    assert ev["fabric.crewai.content_field"] == "output"
    assert ev["fabric.crewai.content_chars"] == len("the final answer")


def test_step_callback_handles_missing_attributes(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Duck-typed inputs without ``tool`` / reasoning fields must not crash."""

    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        hooks.step(SimpleNamespace())

    events = _event_attrs(span_exporter, "fabric.crewai.step")
    assert len(events) == 1
    assert "fabric.crewai.tool" not in events[0]
    assert "fabric.crewai.content_field" not in events[0]
    assert "fabric.crewai.content_sha256" not in events[0]
    assert "fabric.crewai.content_chars" not in events[0]


def test_step_callback_hashes_entire_long_log_without_recording_it(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    long_log = "x" * 5000
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        hooks.step(SimpleNamespace(log=long_log))

    ev = _event_attrs(span_exporter, "fabric.crewai.step")[0]
    assert ev["fabric.crewai.content_chars"] == len(long_log)
    assert ev["fabric.crewai.content_sha256"] == hashlib.sha256(long_log.encode()).hexdigest()
    assert long_log not in str(ev)


def test_task_callback_records_task_event_with_description_and_agent(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        task_output = SimpleNamespace(
            description="analyse the report",
            agent="research_agent",
            raw="a very long analysis " * 20,
        )
        hooks.task(task_output)

    events = _event_attrs(span_exporter, "fabric.crewai.task")
    assert len(events) == 1
    ev = events[0]
    description = "analyse the report"
    assert ev["fabric.crewai.task_description_chars"] == len(description)
    assert (
        ev["fabric.crewai.task_description_sha256"]
        == hashlib.sha256(description.encode()).hexdigest()
    )
    assert "fabric.crewai.task_description" not in ev
    assert ev["fabric.crewai.agent"] == "research_agent"
    assert isinstance(ev["fabric.crewai.output_chars"], int)
    assert ev["fabric.crewai.output_chars"] == len("a very long analysis " * 20)


def test_task_callback_hashes_entire_long_description_without_recording_it(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        hooks.task(SimpleNamespace(description="d" * 1000))

    ev = _event_attrs(span_exporter, "fabric.crewai.task")[0]
    assert ev["fabric.crewai.task_description_chars"] == 1000
    assert (
        ev["fabric.crewai.task_description_sha256"]
        == hashlib.sha256(("d" * 1000).encode()).hexdigest()
    )
    assert "d" * 200 not in str(ev)


def test_task_callback_handles_missing_fields(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        hooks.task(SimpleNamespace())

    ev = _event_attrs(span_exporter, "fabric.crewai.task")[0]
    assert "fabric.crewai.task_description" not in ev
    assert "fabric.crewai.task_description_sha256" not in ev
    assert "fabric.crewai.task_description_chars" not in ev
    assert "fabric.crewai.agent" not in ev
    assert "fabric.crewai.output_chars" not in ev


def test_callbacks_never_emit_raw_sensitive_content(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Prompts, reasoning, outputs, and task descriptions stay off spans."""
    sensitive_content = "patient jane@example.com diagnosis code Z99.89 token sk-live-secret"
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        hooks.step(
            SimpleNamespace(
                thought=sensitive_content,
                log=sensitive_content,
                output=sensitive_content,
                text=sensitive_content,
            )
        )
        hooks.task(SimpleNamespace(description=sensitive_content, raw=sensitive_content))

    step = _event_attrs(span_exporter, "fabric.crewai.step")[0]
    task = _event_attrs(span_exporter, "fabric.crewai.task")[0]
    assert sensitive_content not in str(step)
    assert sensitive_content not in str(task)
    assert (
        step["fabric.crewai.content_sha256"]
        == hashlib.sha256(sensitive_content.encode()).hexdigest()
    )
    assert (
        task["fabric.crewai.task_description_sha256"]
        == hashlib.sha256(sensitive_content.encode()).hexdigest()
    )
    assert task["fabric.crewai.output_chars"] == len(sensitive_content)


class _HostileEvent:
    """An event whose attribute access raises — simulates a broken or
    adversarial CrewAI object. The callback must not let this propagate
    into the host's kickoff()."""

    @property
    def tool(self) -> str:
        raise RuntimeError("boom: hostile attribute access")


def test_step_callback_never_raises_into_host(
    span_exporter: InMemorySpanExporter,
) -> None:
    """A callback failure must be swallowed (logged), never propagated —
    observability cannot break the host crew run."""

    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        # Must not raise even though reading `.tool` blows up.
        hooks.step(_HostileEvent())


def test_task_callback_never_raises_into_host(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()

    class _HostileOutput:
        @property
        def description(self) -> str:
            raise RuntimeError("boom")

    with client.decision(session_id="s", request_id="r") as dec:
        hooks = attach_callbacks(dec)
        hooks.task(_HostileOutput())
