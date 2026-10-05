# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Passive CrewAI activity-capture adapter for Fabric.

Step and task callbacks record CrewAI lifecycle events on the active
:class:`fabric.Decision` span. Recorder v1 never pauses, blocks, authorizes or
otherwise controls a crew.

Typical usage::

    from fabric.adapters.crewai import attach_callbacks

    with fabric.decision(session_id=s, request_id=r) as dec:
        hooks = attach_callbacks(dec)
        crew = Crew(
            agents=[...],
            tasks=[...],
            step_callback=hooks.step,
            task_callback=hooks.task,
        )
        result = crew.kickoff(inputs=...)

The adapter is dependency-free and uses duck typing. Install CrewAI directly
in the host application when needed; Fabric does not publish a convenience
extra that could silently select CrewAI's transitive dependency graph.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .._hashes import sha256_hex
from ..decision import Decision

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger("fabric.adapters.crewai")


def _sha256(value: str) -> str:
    """Return a correlation-safe digest without retaining raw CrewAI content.

    Delegates to :func:`fabric._hashes.sha256_hex` (``surrogatepass``) so a
    lone UTF-16 surrogate in hostile event text cannot raise
    ``UnicodeEncodeError`` inside the host's callback path.
    """
    return sha256_hex(value)


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
    active decision so downstream reconstruction preserves the CrewAI step
    sequence alongside other captured activity.
    """

    def _on_step(event: Any) -> None:
        # CrewAI invokes this on the host's critical path. Observability
        # must never break the crew: any failure reading a hostile event
        # object (a property that raises, an un-truncatable log) is
        # logged and swallowed rather than propagated into kickoff().
        try:
            attrs: dict[str, str | int | float | bool] = {
                "fabric.crewai.event_type": type(event).__name__,
            }
            tool = getattr(event, "tool", None)
            if isinstance(tool, str) and tool:
                attrs["fabric.crewai.tool"] = tool
            # The step object's reasoning text moved across CrewAI
            # versions: legacy ``AgentAction`` (langchain-derived) exposed
            # ``.log``; current crewai (>=1.x) replaced it with a parser
            # object carrying ``.thought`` / ``.text``, and ``AgentFinish``
            # carries ``.thought`` / ``.output`` / ``.text``. Reading only
            # ``.log`` silently captured nothing on modern crewai, so probe
            # the known field names in preference order and record the first
            # non-empty string. Reasoning, output, and parser text can contain
            # prompts, secrets, or regulated data, so raw previews never land
            # on spans. Emit only the source field plus digest and length;
            # authorized full content belongs in a customer-controlled store.
            for field in ("thought", "log", "output", "text"):
                content = getattr(event, field, None)
                if isinstance(content, str) and content:
                    attrs["fabric.crewai.content_field"] = field
                    attrs["fabric.crewai.content_sha256"] = _sha256(content)
                    attrs["fabric.crewai.content_chars"] = len(content)
                    break
            decision.span.add_event("fabric.crewai.step", attributes=attrs)
        except Exception:
            logger.warning("crewai step callback failed; skipping event", exc_info=True)

    def _on_task(output: Any) -> None:
        try:
            attrs: dict[str, str | int | float | bool] = {
                "fabric.crewai.event_type": type(output).__name__,
            }
            description = getattr(output, "description", None)
            if isinstance(description, str) and description:
                attrs["fabric.crewai.task_description_sha256"] = _sha256(description)
                attrs["fabric.crewai.task_description_chars"] = len(description)
            agent = getattr(output, "agent", None)
            if isinstance(agent, str) and agent:
                attrs["fabric.crewai.agent"] = agent
            raw = getattr(output, "raw", None)
            if isinstance(raw, str):
                attrs["fabric.crewai.output_chars"] = len(raw)
            decision.span.add_event("fabric.crewai.task", attributes=attrs)
        except Exception:
            logger.warning("crewai task callback failed; skipping event", exc_info=True)

    return CrewCallbacks(step=_on_step, task=_on_task)


__all__ = [
    "CrewCallbacks",
    "attach_callbacks",
]
