# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""LangGraph adapter for Fabric escalation flow.

LangGraph's ``interrupt()`` primitive is the canonical way to pause a
graph mid-run for human review and then resume with a value. Fabric's
escalation model is a natural fit: when the SDK recognizes that a
decision needs SASF review, it needs both to record that fact on the
decision span (so judge workers and the escalation service observe it)
and to hand control back to the host orchestrator so the user's turn
actually pauses.

This adapter wires those two sides in a single call::

    from fabric.adapters.langgraph import escalate

    with client.decision(session_id=..., request_id=...) as dec:
        ...
        verdict = escalate(dec, EscalationSummary(
            reason="factuality below threshold",
            rubric_id="factuality.v3",
            triggering_score=0.42,
            mode="sync",
        ))
        # ... graph pauses here; resumes with the signed verdict
        ...

``escalate`` records the escalation on the decision span via
``Decision.request_escalation`` and then calls
``langgraph.types.interrupt`` with the canonical payload. The return
value is whatever the orchestrator resumed the graph with — typically
the signed verdict returned by the escalation service.

Install the adapter via::

    pip install "singleaxis-fabric[langgraph]"

Core Fabric code does NOT import from this module; the optional
``langgraph`` dependency is loaded lazily inside ``escalate`` so the
zero-adapter install stays thin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..decision import Decision
    from ..escalation import EscalationSummary


def escalate(decision: Decision, summary: EscalationSummary) -> Any:
    """Record a Fabric escalation and pause the LangGraph run.

    Parameters
    ----------
    decision:
        The active :class:`fabric.Decision` context. The escalation is
        tagged on its OTel span so judge workers and downstream
        consumers observe it.
    summary:
        The :class:`fabric.EscalationSummary` describing why the
        decision is being escalated.

    Returns
    -------
    The resume value the LangGraph runtime feeds back when the graph
    is resumed. The shape is whatever the host/escalation-service
    contract defines — typically a signed verdict dict.

    Raises
    ------
    RuntimeError
        If ``langgraph`` is not installed. Install the optional extra:
        ``pip install "singleaxis-fabric[langgraph]"``.
    """

    try:
        from langgraph.types import interrupt  # type: ignore[import-not-found]  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover — exercised via monkey-patched import
        raise RuntimeError(
            "fabric.adapters.langgraph requires the optional 'langgraph' extra: "
            "pip install 'singleaxis-fabric[langgraph]'",
        ) from exc

    decision.request_escalation(summary)
    return interrupt(summary.to_payload())


__all__ = ["escalate"]
