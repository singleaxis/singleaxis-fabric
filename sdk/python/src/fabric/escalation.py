# Copyright 2026 AI5 Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Escalation pause primitive.

Spec 007 describes the full escalation workflow: pause → SASF review
→ signed decision → resume. The durable machinery (checkpoint, SASF
webhook, signed verdicts) lives in the Escalation service component
and the Telemetry Bridge; the SDK only owns the **local** signal:

1. Record on the decision span that an escalation is being requested
   (attributes + a ``fabric.escalation`` span event).
2. Give hosts a flow-control exception they can catch and wire into
   whatever interrupt primitive their orchestrator exposes.

Keeping this narrow means tenants can opt into escalation without
waiting for the full downstream service to ship — the span tells
ops and the judge workers that an escalation was requested; routing
that request to a human is the escalation-service's job.

Fabric is orchestration-agnostic, so this module does **not** import
LangGraph, Agent Framework, LlamaIndex, or any specific host. The
:meth:`EscalationSummary.to_payload` helper returns the
framework-agnostic dict that tenants hand to whatever interrupt
primitive their orchestrator provides.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

EscalationMode = Literal["sync", "async", "deferred"]
"""User-facing behaviour during the pause.

Mirrors spec 007 §"User-facing behaviour during pause":

- ``sync``: the user's turn holds with a visible "reviewing" indicator.
- ``async``: the agent replies immediately with a "under review" message;
  the resumed response arrives via a side channel.
- ``deferred``: the agent tells the user the action requires approval;
  approval is tracked as a separate ticket.
"""


class EscalationRequested(Exception):  # noqa: N818 — spec 007 names the concept "escalation requested"
    """Raised by :meth:`Decision.raise_for_escalation` when the host
    opts into exception-style flow.

    Carries the :class:`EscalationSummary` so the host can hand it to
    its framework's interrupt primitive without re-deriving context.
    """

    def __init__(self, summary: EscalationSummary) -> None:
        self.summary = summary
        super().__init__(
            f"escalation requested: reason={summary.reason!r}, "
            f"rubric={summary.rubric_id!r}, mode={summary.mode!r}"
        )


class EscalationSummary(BaseModel):
    """Recorded on the decision span when an escalation is requested.

    The fields are intentionally narrow — anything richer (signed
    verdicts, reviewer ids, redacted packets) belongs to the
    escalation service, not the SDK. The SDK only reports *why* the
    escalation was requested so downstream consumers can route.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: str = Field(min_length=1, max_length=512)
    rubric_id: str | None = None
    triggering_score: float | None = None
    mode: EscalationMode = "async"

    def to_payload(self) -> dict[str, object]:
        """Serialize to the framework-agnostic escalation payload.

        Tenants hand this dict to whatever interrupt primitive their
        orchestrator exposes (LangGraph ``interrupt()``, Agent
        Framework checkpoints, a bespoke queue, etc.). Only the
        SDK-owned fields appear; downstream services attach tenant /
        agent / decision IDs from the exported span.
        """

        payload: dict[str, object] = {
            "kind": "fabric.escalation",
            "reason": self.reason,
            "mode": self.mode,
        }
        if self.rubric_id is not None:
            payload["rubric_id"] = self.rubric_id
        if self.triggering_score is not None:
            payload["triggering_score"] = self.triggering_score
        return payload
