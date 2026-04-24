# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Guardrail types exported from the public API.

Phase 1 of the SDK ships the types and the decision-span attribute
contract only. The concrete Presidio and NeMo rails land in a later
tick; until then ``Decision.guard_input`` et al. raise
``GuardrailNotConfiguredError``. Host agents should treat those
methods as "not yet wired" rather than no-ops — silent pass-through
would be a compliance footgun.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

GuardrailPhase = Literal["input", "output_stream", "output_final"]
GuardrailAction = Literal["redact", "block", "warn"]


class EntitySummary(BaseModel):
    """Redacted summary of an entity class detected by a rail.

    Never carries the raw value; only the category and a count.
    """

    model_config = ConfigDict(frozen=True)

    category: str
    count: int = Field(ge=0)


class GuardrailResult(BaseModel):
    """Outcome of a single ``check_input`` / ``check_output_*`` call.

    Matches the wire shape documented in spec 005 §"Event emission".
    """

    model_config = ConfigDict(frozen=True)

    event_id: UUID
    blocked: bool
    block_response: str | None = None
    redacted_content: str
    entities_detected: list[EntitySummary] = Field(default_factory=list)
    policies_fired: list[str] = Field(default_factory=list)
    latency_ms: float = Field(ge=0.0)


class GuardrailError(Exception):
    """Base class for guardrail-layer failures."""


class GuardrailBlocked(GuardrailError):  # noqa: N818  (spec 005 names the concept "blocked")
    """Raised when a guardrail returns ``blocked=True`` and the caller
    opted into exception-style flow.

    Carries the :class:`GuardrailResult` so the caller can emit the
    canned block response and escalate without re-running the check.
    """

    def __init__(self, result: GuardrailResult) -> None:
        self.result = result
        super().__init__(
            f"guardrail blocked: policies={result.policies_fired}, "
            f"entities={[e.category for e in result.entities_detected]}"
        )


class GuardrailNotConfiguredError(GuardrailError):
    """Raised when a ``Decision.guard_*`` method is called but no
    guardrail layer is configured on the :class:`~fabric.Fabric`
    client.

    The SDK fails loud rather than silently passing input through, so
    an agent misconfiguration cannot leak raw PII to the LLM.
    """
