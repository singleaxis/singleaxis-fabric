# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric-reference-agent`` CLI.

Runs one reference-agent turn and prints the outcome as JSON. Pass
``--low-score`` to simulate a failing judge and exercise the
escalation path. Pass ``--enable-v04-primitives`` to demonstrate every
v0.4 SDK primitive (recall, checkpoint, record_eval, queue_judge,
evaluate_policy) in a single decision.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field

from fabric import (
    EngineVerdict,
    Fabric,
    FabricConfig,
    JudgeContext,
    LocalQueueTransport,
    MemoryKind,
    RedactionResult,
    RetrievalSource,
    SimpleLLMJudge,
    install_default_provider,
)

from .agent import ReferenceAgent, SimulatedJudge, simulated_llm_call


def _install_local_tracer() -> None:
    """Install a no-export tracer so ``trace_id`` is a real 32-hex
    value rather than the all-zeros sentinel returned by the OTel
    no-op default. Real telemetry export is the host's responsibility;
    this just gets a real ID into the example's JSON output.
    """
    install_default_provider(
        service_name="fabric-reference-agent",
        # No exporter — spans go nowhere; we just need real IDs.
        # For real telemetry pass an OTLPSpanExporter or
        # ConsoleSpanExporter here.
        exporter=None,
    )


@dataclass(slots=True)
class _DemoAllowEngine:
    """In-process PolicyEngine that always returns allow.

    Demo only — production tenants point :class:`HTTPPolicyAdapter` at
    a real OPA / Cedar sidecar, or implement their own
    :class:`PolicyEngine`.
    """

    engine_name: str = "custom:demo_allow"

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float,
    ) -> EngineVerdict:
        _ = policy_id, input, timeout_seconds  # signature parity
        return EngineVerdict(decision="allow")

    def close(self) -> None:
        return None


class _StubJudgeLLM:
    """Stand-in chat-completion client for :class:`SimpleLLMJudge`.

    Returns a canned ``"score: 0.87"`` so the demo runs without any
    real LLM provider configured.
    """

    def complete(self, prompt: str) -> str:
        _ = prompt
        return "score: 0.87"


class _StubPresidioClient:
    """In-process :class:`PresidioClient` stand-in.

    Pass-through redactor: returns the value unchanged with
    ``hashed=False``. Wired so the guardrail chain has at least one
    rail and the SDK emits ``fabric.guardrail`` span events — without
    needing the Presidio sidecar running.
    """

    def redact(self, path: str, value: str) -> RedactionResult:
        _ = path
        return RedactionResult(value=value, hashed=False, pii_category="")

    def close(self) -> None:
        return None


@dataclass(slots=True)
class V04TurnResult:
    """What one ``run_one_turn_with_v04_primitives`` call returns."""

    response: str
    trace_id: str
    judge_scores: list[float] = field(default_factory=list)
    event_counts: dict[str, int] = field(default_factory=dict)


def run_one_turn_with_v04_primitives(
    *,
    prompt: str,
    tenant_id: str = "tenant-demo",
    agent_id: str = "reference-agent",
    session_id: str = "sess-demo",
    request_id: str = "req-demo",
    user_id: str | None = None,
    workflow_id: str | None = None,
    execution_id: str | None = None,
    verbose: bool = False,
) -> V04TurnResult:
    """Run one decision that touches every v0.4 SDK primitive.

    Per turn:

    1. Open ``Fabric.decision(...)``
    2. ``guard_input`` (no-op fallback if no rails wired)
    3. ``record_retrieval`` (RAG simulation)
    4. ``checkpoint("after-retrieval")``
    5. ``recall`` an episodic memory entry
    6. ``evaluate_policy`` via an in-process always-allow engine
    7. ``llm_call`` wrapping a simulated LLM
    8. ``remember`` the response in episodic memory
    9. ``record_side_effect`` for the notification
    10. ``guard_output_final``
    11. ``record_eval`` (synchronous score)
    12. ``queue_judge`` (async, via :class:`LocalQueueTransport`)
    13. ``checkpoint("after-output")``

    After the decision exits, drains the judge queue once and scores
    each :class:`JudgeRequest` with :class:`SimpleLLMJudge`.

    Returns a :class:`V04TurnResult` with the response, trace_id,
    drained judge scores, and per-event-type counts (read from span
    attributes the SDK already maintains).
    """
    config = FabricConfig(
        tenant_id=tenant_id,
        agent_id=agent_id,
        workflow_id=workflow_id,
        execution_id=execution_id,
    )
    # Wire a pass-through Presidio stub so the guardrail chain emits
    # ``fabric.guardrail`` events end-to-end. Production deployments
    # point ``FABRIC_PRESIDIO_UNIX_SOCKET`` at the real sidecar.
    fabric = Fabric(config, presidio=_StubPresidioClient())
    policy_engine = _DemoAllowEngine()
    transport = LocalQueueTransport()

    def _say(msg: str) -> None:
        if verbose:
            print(msg)

    with fabric.decision(
        session_id=session_id,
        request_id=request_id,
        user_id=user_id,
    ) as decision:
        # 2. guard_input — fall back when no rails are wired
        try:
            safe_input = decision.guard_input(prompt)
            _say(f"guardrail: input checked → {len(safe_input)} chars")
        except Exception:
            safe_input = prompt
            _say("guardrail: skipped (no rails wired)")

        # 3. record_retrieval
        decision.record_retrieval(
            RetrievalSource.RAG,
            query=safe_input,
            result_count=2,
            result_hashes=("doc-1-hash", "doc-2-hash"),
            source_document_ids=("doc-1", "doc-2"),
            latency_ms=11,
        )
        _say("retrieval: 2 docs from RAG")

        # 4. checkpoint after retrieval
        decision.checkpoint("after-retrieval")
        _say("checkpoint: after-retrieval")

        # 5. recall a prior memory entry
        decision.recall(
            kind=MemoryKind.EPISODIC,
            key="last_query",
            content="prior turn content",
        )
        _say("memory recall: episodic last_query")

        # 6. evaluate_policy via in-process engine
        evaluation = decision.evaluate_policy(
            policy_engine,
            policy_id="reference.allow",
            input={"user": "alice"},
        )
        _say(f"policy: {evaluation.engine} → {evaluation.decision}")

        # 7. llm_call wrapping the simulated provider
        with decision.llm_call(
            system="simulated",
            model="reference-agent-stub-v1",
        ) as call:
            raw_response = simulated_llm_call(safe_input)
            call.set_usage(
                input_tokens=len(safe_input.split()),
                output_tokens=len(raw_response.split()),
                finish_reason="stop",
            )
        _say(f"llm_call: model=reference-agent-stub-v1 → {len(raw_response)} chars")

        # 8. remember the response
        decision.remember(
            kind=MemoryKind.EPISODIC,
            content=raw_response,
            key="turn",
            tags=("reference-agent",),
            ttl_seconds=3600,
        )
        _say("memory write: episodic turn")

        # 9. record_side_effect (notification stand-in for an email send)
        decision.record_side_effect(
            "notification",
            target_system="reference-agent",
            operation="response.ready",
            request_payload=raw_response,
            committed=True,
            rollback_supported=False,
            replay_behavior="suppress",
        )
        _say("side_effect: notification committed")

        # 10. guard_output_final — fall back when no rails are wired
        try:
            safe_response = decision.guard_output_final(raw_response)
            _say("guardrail: output checked")
        except Exception:
            safe_response = raw_response
            _say("guardrail: output skipped (no rails wired)")

        # 11. record_eval — synchronous score
        decision.record_eval(
            rubric_id="reference-v1",
            score=0.85,
            dimension="overall",
            evaluator_name="inline_stub",
        )
        _say("eval (sync): reference-v1 → 0.85")

        # 12. queue_judge — async, via LocalQueueTransport
        judge_ctx = JudgeContext(
            user_input=safe_input,
            agent_response=safe_response,
        )
        request = decision.queue_judge(
            rubric_id="reference-v1",
            dimensions=("faithfulness",),
            context=judge_ctx,
            transport=transport,
        )
        _say(f"judge queued: request_id={request.request_id}")

        # 13. checkpoint after output
        decision.checkpoint("after-output")
        _say("checkpoint: after-output")

        # Snapshot attributes before the span closes; ``decision.span``
        # is invalidated on context exit.
        trace_id = decision.trace_id
        attrs = dict(decision.span.attributes or {})

    # After the span closes, drain the judge queue and score each
    # request with SimpleLLMJudge.
    worker = SimpleLLMJudge(
        llm=_StubJudgeLLM(),
        prompt_template="Rate this: {agent_response}",
    )
    judge_scores: list[float] = []
    while True:
        req = transport.dequeue()
        if req is None:
            break
        record = worker.score(req)
        judge_scores.append(record.score)
        _say(
            f"judge: {record.evaluator_name} → {record.score} ({record.dimension})",
        )

    event_counts = {
        "retrieval": int(attrs.get("fabric.retrieval_count", 0)),
        "memory_write": int(attrs.get("fabric.memory_write_count", 0)),
        "memory_read": int(attrs.get("fabric.memory_read_count", 0)),
        "side_effect": int(attrs.get("fabric.side_effect_count", 0)),
        "checkpoint": int(attrs.get("fabric.checkpoint_count", 0)),
        "eval": int(attrs.get("fabric.eval_count", 0)),
        "judge_queued": int(attrs.get("fabric.judge_queued_count", 0)),
        "policy_evaluation": int(attrs.get("fabric.policy_evaluation_count", 0)),
    }

    return V04TurnResult(
        response=safe_response,
        trace_id=trace_id,
        judge_scores=judge_scores,
        event_counts=event_counts,
    )


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="fabric-reference-agent")
    parser.add_argument("--tenant-id", default="tenant-demo")
    parser.add_argument("--agent-id", default="reference-agent")
    parser.add_argument("--prompt", default="What is the capital of France?")
    parser.add_argument("--session-id", default="sess-demo")
    parser.add_argument("--request-id", default="req-demo")
    parser.add_argument("--user-id", default=None)
    parser.add_argument("--workflow-id", default=None)
    parser.add_argument("--execution-id", default=None)
    parser.add_argument(
        "--low-score",
        action="store_true",
        help="simulate a failing judge to trigger the escalation path",
    )
    parser.add_argument(
        "--enable-v04-primitives",
        action="store_true",
        help=(
            "exercise every v0.4 primitive (recall, checkpoint, record_eval, "
            "queue_judge + JudgeContext, evaluate_policy, SimpleLLMJudge) "
            "in one decision"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    _install_local_tracer()

    if args.enable_v04_primitives:
        result = run_one_turn_with_v04_primitives(
            prompt=args.prompt,
            tenant_id=args.tenant_id,
            agent_id=args.agent_id,
            session_id=args.session_id,
            request_id=args.request_id,
            user_id=args.user_id,
            workflow_id=args.workflow_id,
            execution_id=args.execution_id,
            verbose=True,
        )
        print(
            json.dumps(
                {
                    "response": result.response,
                    "trace_id": result.trace_id,
                    "judge_scores": result.judge_scores,
                    "event_counts": result.event_counts,
                },
                indent=2,
            ),
        )
        return 0

    fabric = Fabric(FabricConfig(tenant_id=args.tenant_id, agent_id=args.agent_id))
    judge = SimulatedJudge(score=0.2 if args.low_score else 0.95)
    agent = ReferenceAgent(fabric, judge=judge)
    result = agent.run(
        user_input=args.prompt,
        session_id=args.session_id,
        request_id=args.request_id,
        user_id=args.user_id,
    )
    print(
        json.dumps(
            {
                "response": result.response,
                "escalated": result.escalated,
                "blocked": result.blocked,
                "trace_id": result.trace_id,
            },
            indent=2,
        ),
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
