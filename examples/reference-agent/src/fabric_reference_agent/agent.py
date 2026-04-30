# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reference agent that exercises every SDK surface a Phase-1 tenant
will touch:

- Fabric client construction
- Decision-scoped span lifecycle
- Optional guardrails (skipped cleanly if no rails are wired)
- Retrieval + memory recording
- Judge-score-driven escalation

No real LLM is called — ``simulated_llm_call`` returns a canned
response so the example runs anywhere without API keys. Real agents
swap this function out for their model provider of choice; nothing
else in this file changes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from fabric import (
    EscalationSummary,
    Fabric,
    GuardrailNotConfiguredError,
    MemoryKind,
    RetrievalSource,
)

# Below this fast-tier judge score we ask for human review. Chosen to
# match the default `sasf.instruction_following` `deep_flag` threshold
# in the shipped rubrics so the reference agent and the judge workers
# line up on what "low-confidence" means.
ESCALATION_SCORE_THRESHOLD = 0.50


@dataclass(frozen=True)
class AgentResult:
    """What a single reference-agent turn returns to its host."""

    response: str
    escalated: bool
    blocked: bool
    trace_id: str


class SimulatedJudge:
    """Deterministic stand-in for the async judge tier.

    Real deployments call the judge-workers service over NATS; this
    class returns a caller-supplied score so the reference agent is
    testable without any broker running.
    """

    def __init__(self, score: float = 0.95) -> None:
        if not 0.0 <= score <= 1.0:
            raise ValueError("score must be in [0.0, 1.0]")
        self._score = score

    def score_instruction_following(self, prompt: str, response: str) -> float:
        _ = prompt, response  # signature parity with real judge
        return self._score


def simulated_llm_call(prompt: str) -> str:
    """Return a canned response that quotes the prompt.

    Swap this for a real LLM provider call in production. The prompt
    shape and return type are all the SDK sees.
    """
    return f"Simulated response to: {prompt.strip()[:120]}"


class ReferenceAgent:
    """Minimal orchestrator that drives one turn end-to-end."""

    def __init__(
        self,
        fabric: Fabric,
        *,
        judge: SimulatedJudge | None = None,
        llm_call: Callable[[str], str] = simulated_llm_call,
    ) -> None:
        self._fabric = fabric
        self._judge = judge or SimulatedJudge()
        self._llm_call = llm_call

    def run(
        self,
        *,
        user_input: str,
        session_id: str,
        request_id: str,
        user_id: str | None = None,
    ) -> AgentResult:
        """Execute one decision turn. Returns an :class:`AgentResult`.

        The happy path is:

        1. Open a Decision (span starts).
        2. Guard input — skipped if no rails are configured.
        3. Record a retrieval event (stand-in for RAG lookup).
        4. Call the LLM.
        5. Guard output — skipped if no rails are configured.
        6. Record a memory write.
        7. Score via the async judge stand-in; escalate if below
           threshold.
        """
        with self._fabric.decision(
            session_id=session_id,
            request_id=request_id,
            user_id=user_id,
        ) as decision:
            safe_input = _guard_optional(
                lambda: decision.guard_input(user_input),
                fallback=user_input,
            )

            decision.record_retrieval(
                RetrievalSource.RAG,
                query=safe_input,
                result_count=3,
                result_hashes=("doc-a", "doc-b", "doc-c"),
                source_document_ids=("kb://faq", "kb://policy"),
                latency_ms=12,
            )

            # Wrap the LLM call in a child span so the trace tree shows
            # the actual model invocation — gen_ai.* attributes light
            # up Phoenix's LLM view, Langfuse cost dashboards, etc.
            # Synthetic numbers here; in production the caller passes
            # real token counts from the LLM response.
            with decision.llm_call(
                system="simulated",
                model="reference-agent-stub-v1",
            ) as call:
                raw_response = self._llm_call(safe_input)
                call.set_usage(
                    input_tokens=len(safe_input.split()),
                    output_tokens=len(raw_response.split()),
                    finish_reason="stop",
                )

            safe_response = _guard_optional(
                lambda: decision.guard_output_final(raw_response),
                fallback=raw_response,
            )

            decision.remember(
                kind=MemoryKind.EPISODIC,
                content=safe_response,
                key=f"session:{session_id}:last_response",
                tags=("reference-agent",),
                ttl_seconds=3600,
            )

            score = self._judge.score_instruction_following(safe_input, safe_response)
            if score < ESCALATION_SCORE_THRESHOLD:
                decision.request_escalation(
                    EscalationSummary(
                        reason="low judge score",
                        rubric_id="sasf.instruction_following",
                        triggering_score=score,
                        mode="async",
                    ),
                )

            return AgentResult(
                response=safe_response,
                escalated=decision.escalation is not None,
                blocked=decision.blocked is not None,
                trace_id=decision.trace_id,
            )


def _guard_optional(run: Callable[[], str], *, fallback: str) -> str:
    """Call a guardrail method, falling back when no rails are wired.

    The SDK raises :class:`GuardrailNotConfiguredError` rather than
    silently passing content through — that's a compliance design
    choice. For demo purposes where no Presidio/NeMo sidecar is
    running, we catch that specific error only; real guardrail faults
    propagate as before.
    """
    try:
        return run()
    except GuardrailNotConfiguredError:
        return fallback
