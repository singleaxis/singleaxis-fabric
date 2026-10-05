# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reference agent that exercises the Fabric recorder-v1 capture surface.

One turn demonstrates these explicitly supplied observations:

- ``fabric.decision`` span with tenant / agent / session / request identity
- ``fabric.retrieval`` event (RAG stand-in; query is hashed locally)
- ``llm_call`` child span (OpenTelemetry GenAI semantic conventions)
- ``tool_call`` child span (arguments and results are hashed locally)
- ``fabric.memory`` write event
- ``fabric.side_effect`` event (fixture-supplied committed notification claim)
- ``fabric.checkpoint`` events bracketing the turn

No real LLM is called — ``simulated_llm_call`` returns a canned
response so the example runs anywhere without API keys. Swap it for
your provider's SDK; nothing else in this file changes.

The SDK is passive: it records supplied observations without authorizing or
altering agent actions. Instrumentation and export still have overhead.
Protection and delivery happen in the Fabric Node the spans are exported to —
judges, guardrails, and policy
engines are deliberately not part of this example.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from fabric import Fabric, MemoryKind, RetrievalSource


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class AgentResult:
    """What a single reference-agent turn returns to its host."""

    response: str
    trace_id: str
    event_counts: dict[str, int] = field(default_factory=dict)


def simulated_llm_call(prompt: str) -> str:
    """Return a canned response that quotes the prompt.

    Swap this for a real LLM provider call in production. The prompt
    shape and return type are all the SDK sees.
    """
    return f"Simulated response to: {prompt.strip()[:120]}"


class ReferenceAgent:
    """Minimal orchestrator that drives one agentic turn end-to-end."""

    def __init__(
        self,
        fabric: Fabric,
        *,
        llm_call: Callable[[str], str] = simulated_llm_call,
    ) -> None:
        self._fabric = fabric
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
        2. Checkpoint the intake.
        3. Record a retrieval event (stand-in for a RAG lookup).
        4. Call the LLM inside an ``llm_call`` child span.
        5. Call a tool inside a ``tool_call`` child span.
        6. Record a memory write and a committed side effect.
        7. Checkpoint the completed turn.
        """
        with self._fabric.decision(
            session_id=session_id,
            request_id=request_id,
            user_id=user_id,
        ) as decision:
            decision.checkpoint("intake")

            decision.record_retrieval(
                RetrievalSource.RAG,
                query=user_input,
                result_count=3,
                result_hashes=tuple(_sha256_hex(doc) for doc in ("doc-a", "doc-b", "doc-c")),
                source_document_ids=("kb://faq", "kb://policy"),
                latency_ms=12,
            )

            # Wrap the LLM call in a child span so the trace tree shows
            # the actual model invocation — gen_ai.* attributes render
            # natively in OTLP backends. Synthetic token counts here;
            # in production pass the real counts from the response.
            with decision.llm_call(
                provider="simulated",
                model="reference-agent-stub-v1",
            ) as call:
                response = self._llm_call(user_input)
                call.set_usage(
                    input_tokens=len(user_input.split()),
                    output_tokens=len(response.split()),
                    finish_reason="stop",
                )

            # This stand-in supplies a simulated tool result; Fabric records the
            # observation with hashed payloads — raw values stay local.
            with decision.tool_call("respond_to_user", call_id="call-0001") as tool:
                tool.set_arguments('{"channel": "chat"}')
                tool.set_result('{"delivered": true}')

            decision.remember(
                kind=MemoryKind.EPISODIC,
                content=response,
                key=f"session:{session_id}:last_response",
                tags=("reference-agent",),
                ttl_seconds=3600,
            )

            decision.record_side_effect(
                "notification",
                target_system="reference-agent",
                operation="response.ready",
                request_payload=response,
                committed=True,
                rollback_supported=False,
                replay_behavior="suppress",
            )

            decision.checkpoint("turn-complete")

            # Snapshot span attributes before the context exits; the
            # span object is invalid afterwards.
            attrs = dict(decision.span.attributes or {})
            return AgentResult(
                response=response,
                trace_id=decision.trace_id,
                event_counts={
                    "retrieval": int(attrs.get("fabric.retrieval_count", 0)),
                    "memory_write": int(attrs.get("fabric.memory_write_count", 0)),
                    "side_effect": int(attrs.get("fabric.side_effect_count", 0)),
                    "checkpoint": int(attrs.get("fabric.checkpoint_count", 0)),
                },
            )
