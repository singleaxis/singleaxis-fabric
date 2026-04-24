# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CrewAI adapter for Fabric.

CrewAI does not expose a single inline "interrupt" primitive the way
LangGraph does. Its human-in-the-loop patterns are:

1. ``Task(human_input=True)`` — a static flag. When CrewAI finishes
   such a task, it prompts an operator via stdin (or a tenant-provided
   input hook) before continuing.
2. ``@human_feedback`` on a :class:`crewai.flow.flow.Flow` method —
   emits ``approved`` / ``rejected`` events that get routed to listener
   methods.
3. Enterprise ``POST /resume`` endpoint — webhook-based resumption of
   paused crews.

None of those are a function call that blocks and returns a verdict, so
this adapter does not try to forge a single ``escalate()`` call. What
it provides instead:

- Step and task callbacks that record CrewAI lifecycle events on the
  active :class:`fabric.Decision` span (so every tool call and task
  output shows up alongside guardrail, retrieval, and memory events).
- A narrow :func:`request_escalation` helper that records the Fabric
  escalation on the span and hands the canonical payload back to the
  tenant, who pairs it with whichever CrewAI HITL pattern fits their
  deployment.

Typical usage::

    from fabric.adapters.crewai import attach_callbacks, request_escalation

    with fabric.decision(session_id=s, request_id=r) as dec:
        hooks = attach_callbacks(dec)
        crew = Crew(
            agents=[...],
            tasks=[...],
            step_callback=hooks.step,
            task_callback=hooks.task,
        )
        result = crew.kickoff(inputs=...)

        if judge.score(result) < THRESHOLD:
            payload = request_escalation(
                dec,
                EscalationSummary(
                    reason="factuality below threshold",
                    rubric_id="factuality.v3",
                    triggering_score=float(judge.score(result)),
                    mode="sync",
                ),
            )
            # Route ``payload`` through whatever HITL channel your crew uses
            # (Flow @human_feedback, Task human_input hook, /resume webhook).

Install the adapter via::

    pip install "singleaxis-fabric[crewai]"

Core Fabric code does not import from this module; the optional
``crewai`` dependency is referenced only through duck typing on the
objects CrewAI hands to the callbacks — so the zero-adapter install
stays thin.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..decision import Decision

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..escalation import EscalationSummary


@dataclass(frozen=True)
class CrewCallbacks:
    """Fabric-aware callbacks ready to pass into ``Crew(...)``.

    ``step`` receives whatever CrewAI hands to ``step_callback`` (an
    ``AgentAction`` / ``AgentFinish`` in current versions). ``task``
    receives a :class:`crewai.tasks.TaskOutput`-like object. We do not
    import CrewAI types here — the callbacks only read duck-typed
    attributes and fall back to ``type(...).__name__`` when fields are
    absent, so they work across CrewAI versions without tight coupling.
    """

    step: Callable[[Any], None]
    task: Callable[[Any], None]


def attach_callbacks(decision: Decision) -> CrewCallbacks:
    """Build Fabric-aware ``step_callback`` / ``task_callback`` pair.

    Pass the returned object into ``Crew(step_callback=hooks.step,
    task_callback=hooks.task)``. Each callback adds a span event on the
    active decision so reviewers can see the CrewAI step sequence in
    the same trace as guardrail and retrieval events.
    """

    def _on_step(event: Any) -> None:
        attrs: dict[str, str | int | float | bool] = {
            "fabric.crewai.event_type": type(event).__name__,
        }
        tool = getattr(event, "tool", None)
        if isinstance(tool, str) and tool:
            attrs["fabric.crewai.tool"] = tool
        log = getattr(event, "log", None)
        if isinstance(log, str) and log:
            # Truncate to keep span attribute size bounded; full
            # transcripts belong in Langfuse, not on the decision span.
            attrs["fabric.crewai.log_preview"] = log[:200]
        decision.span.add_event("fabric.crewai.step", attributes=attrs)

    def _on_task(output: Any) -> None:
        attrs: dict[str, str | int | float | bool] = {
            "fabric.crewai.event_type": type(output).__name__,
        }
        description = getattr(output, "description", None)
        if isinstance(description, str) and description:
            attrs["fabric.crewai.task_description"] = description[:200]
        agent = getattr(output, "agent", None)
        if isinstance(agent, str) and agent:
            attrs["fabric.crewai.agent"] = agent
        raw = getattr(output, "raw", None)
        if isinstance(raw, str):
            attrs["fabric.crewai.output_chars"] = len(raw)
        decision.span.add_event("fabric.crewai.task", attributes=attrs)

    return CrewCallbacks(step=_on_step, task=_on_task)


def request_escalation(
    decision: Decision,
    summary: EscalationSummary,
) -> dict[str, object]:
    """Record a Fabric escalation on the decision span.

    Returns the framework-agnostic escalation payload
    (:meth:`EscalationSummary.to_payload`) so the tenant can hand it to
    whichever CrewAI HITL channel their crew uses — a Flow
    ``@human_feedback`` event emission, a ``Task(human_input=True)``
    input hook, or the enterprise ``/resume`` webhook.
    """

    decision.request_escalation(summary)
    return summary.to_payload()


__all__ = [
    "CrewCallbacks",
    "attach_callbacks",
    "request_escalation",
]
