# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Microsoft Agent Framework adapter for Fabric escalation flow.

Agent Framework (``agent-framework`` on PyPI, import path
``agent_framework``) drives Human-in-the-Loop via a workflow context:
an executor calls ``await ctx.request_info(request_data=..., response_type=...)``
to suspend the run, and the response is later delivered to a method
decorated with ``@response_handler``. That is a different shape from
LangGraph's inline ``interrupt()`` — the response is not returned from
the suspending call, it is dispatched to a separate handler.

This adapter keeps Fabric's span-side contract identical to the
LangGraph adapter (escalation attributes + ``fabric.escalation`` span
event) and wraps the MAF side with typed request / response Pydantic
models tenants can pass straight to ``ctx.request_info``.

Typical usage inside an executor::

    from fabric.adapters.agent_framework import (
        request_escalation, FabricEscalationResponse,
    )

    class ReviewExecutor(Executor):
        async def run(self, payload, ctx):
            ...
            await request_escalation(
                ctx, decision,
                EscalationSummary(
                    reason="factuality below threshold",
                    rubric_id="factuality.v3",
                    triggering_score=0.42,
                    mode="sync",
                ),
            )

        @response_handler
        async def on_verdict(
            self,
            original: FabricEscalationRequest,
            response: FabricEscalationResponse,
            ctx: WorkflowContext,
        ) -> None:
            ...

Install the adapter via::

    pip install "singleaxis-fabric[agent-framework]"

Core Fabric code does NOT import from this module; the optional
``agent-framework`` dependency is referenced only through duck typing
on the passed ``ctx`` — so the zero-adapter install stays thin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from ..decision import Decision
    from ..escalation import EscalationMode, EscalationSummary


class FabricEscalationRequest(BaseModel):
    """Typed ``request_data`` for :meth:`ctx.request_info`.

    MAF wants Pydantic models (not dicts) so it can serialise request
    data into its durable checkpoint. This is the canonical Fabric
    shape; tenants can subclass if they need to carry extra context to
    their reviewer UI.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str = Field(default="fabric.escalation", frozen=True)
    reason: str = Field(min_length=1, max_length=512)
    mode: str = "async"
    rubric_id: str | None = None
    triggering_score: float | None = None

    @classmethod
    def from_summary(cls, summary: EscalationSummary) -> FabricEscalationRequest:
        return cls(
            reason=summary.reason,
            mode=summary.mode,
            rubric_id=summary.rubric_id,
            triggering_score=summary.triggering_score,
        )


class FabricEscalationResponse(BaseModel):
    """Canonical verdict shape tenants can use as ``response_type``.

    Fields mirror the escalation-service contract described in spec 007.
    Tenants are free to define their own response model if their
    reviewer UI carries more fields — MAF only requires that the
    ``response_type`` passed to ``ctx.request_info`` matches whatever
    the ``@response_handler`` expects.
    """

    model_config = ConfigDict(extra="allow")

    approved: bool
    reviewer: str | None = None
    comments: str | None = None


async def request_escalation(
    ctx: Any,
    decision: Decision,
    summary: EscalationSummary,
    *,
    response_type: type[BaseModel] = FabricEscalationResponse,
) -> Any:
    """Record a Fabric escalation and suspend the MAF workflow.

    Parameters
    ----------
    ctx:
        The active :class:`agent_framework.WorkflowContext`. We call
        ``await ctx.request_info(request_data=..., response_type=...)``
        on it. No type import from ``agent_framework`` is needed at
        runtime — the adapter relies on duck typing so the zero-adapter
        install does not require the dependency.
    decision:
        The active :class:`fabric.Decision` context.
    summary:
        :class:`fabric.EscalationSummary` describing why this turn is
        being escalated.
    response_type:
        The Pydantic model MAF should expect when the reviewer resumes
        the workflow. Defaults to :class:`FabricEscalationResponse`.

    Returns
    -------
    Whatever ``ctx.request_info`` returns. The MAF Python HITL model
    routes the resumed response to a ``@response_handler`` method, so
    this is typically ``None`` — the verdict arrives out-of-band.
    """

    decision.request_escalation(summary)
    request = FabricEscalationRequest.from_summary(summary)
    return await ctx.request_info(request_data=request, response_type=response_type)


def build_escalation_request(
    decision: Decision,
    summary: EscalationSummary,
) -> FabricEscalationRequest:
    """Record an escalation on the decision span and return the MAF request model.

    Prefer :func:`request_escalation` when you have a ``ctx`` handy. Use
    this when the executor needs to build the request object ahead of
    time (e.g. to attach to a richer multi-field request).
    """

    decision.request_escalation(summary)
    return FabricEscalationRequest.from_summary(summary)


# Re-exported for tenants that want to refer to the escalation modes by
# the same Literal alias the core SDK uses.
if TYPE_CHECKING:
    EscalationModeAlias = EscalationMode


__all__ = [
    "FabricEscalationRequest",
    "FabricEscalationResponse",
    "build_escalation_request",
    "request_escalation",
]
