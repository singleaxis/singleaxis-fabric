# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Judge context capture + queue protocol.

Spec 012 §Runtime evaluations. The SDK captures context at decision
time and ships it via a separate transport from the OTel trace
stream. Context never lands on the trace; only ``fabric.judge.queued``
metadata does.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from uuid import UUID


@dataclass(frozen=True, slots=True)
class ToolCallSnapshot:
    """Frozen snapshot of a tool call for the judge to inspect."""

    name: str
    args: dict[str, Any] = field(default_factory=dict)
    result_summary: str | None = None
    result_count: int | None = None


@dataclass(frozen=True, slots=True)
class GuardrailSnapshot:
    """Frozen snapshot of a guardrail decision for judge context."""

    phase: str
    action: str
    rail: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecisionSnapshot:
    """Frozen snapshot of a policy evaluation for judge context."""

    engine: str
    policy_id: str
    decision: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class JudgeContext:
    """Bundle of context the judge evaluates against.

    Built either explicitly by the caller or auto-populated via
    ``decision.snapshot_context()``. Travels with the JudgeRequest
    through the QueueTransport, never on the OTel trace stream.

    Tuple fields are used over list so the dataclass is hashable
    where the frozen contract requires it.
    """

    user_input: str | None = None
    agent_response: str | None = None
    system_prompt: str | None = None
    history: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    retrieval_docs: tuple[str, ...] = field(default_factory=tuple)
    memory_reads: tuple[str, ...] = field(default_factory=tuple)
    tool_calls: tuple[ToolCallSnapshot, ...] = field(default_factory=tuple)
    guardrail_events: tuple[GuardrailSnapshot, ...] = field(default_factory=tuple)
    policy_decisions: tuple[PolicyDecisionSnapshot, ...] = field(default_factory=tuple)
    ground_truth: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class JudgeRequest:
    """A judge job. Sent to the queue, consumed by a JudgeWorker."""

    request_id: UUID
    decision_id: str
    rubric_id: str
    dimensions: tuple[str, ...]
    context: JudgeContext
    payload_ref: str | None = None


@runtime_checkable
class JudgeWorker(Protocol):
    """Score one JudgeRequest. Implementations choose how (LLM,
    rule-based, classifier, ensemble). The protocol stays small.

    Returns an opaque object (typically EvalRecord) — the worker
    writes back to the trace via ``decision.record_eval()`` on the
    consumer side; the SDK does not enforce the return type.
    """

    def score(self, request: JudgeRequest) -> Any: ...


@runtime_checkable
class QueueTransport(Protocol):
    """Forward a JudgeRequest to wherever judge workers consume from.

    Implementations: LocalQueueTransport (in-process), and tenant-
    supplied adapters for NATS, Kafka, Redis Streams, SQS, etc.
    """

    def enqueue(self, request: JudgeRequest) -> None: ...
    def close(self) -> None: ...


@runtime_checkable
class DrainableTransport(Protocol):
    """Consumer side of the judge queue: pull requests off to score.

    The producer Protocol (``QueueTransport``) only declares
    ``enqueue`` / ``close``; many real transports are fire-and-forget
    on the producer (NATS publish, SQS send, Redis XADD) and expose a
    separate subscription mechanism for consumers. ``JudgeRunner``
    drains via this Protocol instead, so an in-process
    ``LocalQueueTransport`` (which already has ``dequeue``) satisfies it
    structurally, while production transports supply their own
    drainable adapter.

    ``dequeue`` returns the oldest pending request, or ``None`` when the
    queue is currently empty.
    """

    def dequeue(self) -> JudgeRequest | None: ...
