# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Enterprise RAG knowledge assistant — instrumented with SingleAxis Fabric.

Scenario
--------
"AcmeCorp Knowledge Assistant" answers employee questions about internal HR
and IT policy. Like most production RAG stacks it (1) guards the user input
for PII / prompt-injection, (2) checks a governance policy before answering a
sensitive HR question, (3) authorizes the vector-search tool, (4) retrieves
from *multiple* sources (a policy vector store + a knowledge graph), (5) reads
and writes *semantic memory* so it remembers a user's resolved preferences,
(6) calls an LLM to synthesize a grounded answer, (7) runs an *inline grounding
eval* (faithfulness) on the request path and queues an *async judge* for a
deeper review, and (8) when grounding is weak, escalates to a human and logs an
audit ticket as a recorded side effect. Fabric emits one hash-only audit trail
(raw content is SHA-256'd locally; queries/PII never land on the trace) that
governance and SRE both consume.

Fabric primitives / attributes this example demonstrates
--------------------------------------------------------
* ``fabric.execution`` span (execution_id / workflow_id correlation) wrapping
  the run, inherited by the decision.
* ``fabric.decision`` span with ``fabric.decision_id`` / ``fabric.execution_id``
  / ``fabric.session_id`` / ``fabric.request_id`` / tenant / agent / profile.
* ``Decision.guard_input`` -> ``fabric.guardrail`` event via an in-process
  ``GuardrailChecker`` stub (input redaction + injection block).
* ``Decision.evaluate_policy`` -> ``fabric.policy.evaluation`` event with a
  normalized verdict (``EngineVerdict`` / ``PolicyEngine``), hashed input.
* ``Decision.authorize_tool_call`` -> ``fabric.tool.authorization`` event.
* ``Decision.record_retrieval`` -> ``fabric.retrieval`` events for two sources
  (``RetrievalSource.RAG`` + ``RetrievalSource.KG``) with hashed queries.
* ``Decision.recall`` / ``Decision.remember`` -> ``fabric.memory`` read+write
  events (``MemoryKind.SEMANTIC``), hash-correlatable.
* ``Decision.llm_call`` -> child ``fabric.llm_call`` span with the GenAI
  semantic conventions, ``fabric.step.type``, usage + cache + streaming.
* ``Decision.tool_call`` -> child ``fabric.tool_call`` span (vector search).
* ``Decision.record_eval`` -> inline ``fabric.eval`` grounding/faithfulness
  score; ``Decision.queue_judge`` -> ``fabric.judge.queued`` for async review.
* ``Decision.checkpoint`` -> ``fabric.checkpoint`` save point.
* ``Decision.record_side_effect`` -> ``fabric.side_effect`` audit-ticket write
  carrying ``parent_tool_call_id`` and a ``side_effect_id`` (replay SUPPRESS).
* ``Decision.request_escalation`` -> ``fabric.escalation`` event when grounding
  is weak (``EscalationSummary``).
* ``Decision.record_replay_metadata`` -> ``fabric.replay`` envelope bundling
  checkpoint ids + suppressed side-effect ids for a (commercial) replay engine.

How to run
----------
    python3.13 -m venv /tmp/ex_rag_assistant
    /tmp/ex_rag_assistant/bin/pip install -e <repo>/sdk/python
    /tmp/ex_rag_assistant/bin/python /tmp/ex_rag_assistant/example.py

It runs fully OFFLINE (the LLM is a deterministic stub) and exits 0 with all
asserts passing. To drive a real OpenAI-compatible provider instead, see the
``call_llm`` docstring and set ``USE_REAL_LLM = True``.
"""

from __future__ import annotations

import hashlib
import json
import os

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from fabric import (
    DEFAULT_PROFILE,
    CheckerVerdict,
    EngineVerdict,
    EscalationSummary,
    Fabric,
    FabricConfig,
    JudgeContext,
    LocalQueueTransport,
    MemoryKind,
    ReplayBehavior,
    RetrievalSource,
    SideEffectType,
    ToolAuthorization,
    install_default_provider,
)

# Flip to True (and fill REAL_LLM_* below) to prove behavior against a real
# OpenAI-compatible endpoint. The committed default stays offline.
USE_REAL_LLM = False


# ---------------------------------------------------------------------------
# 1. Pluggable adapters — the bits a tenant supplies. Fabric never embeds a
#    guardrail engine, policy engine, or tool authorizer; it normalizes and
#    *emits*. These in-process stubs keep the example self-contained.
# ---------------------------------------------------------------------------
class InProcessGuardrailChecker:
    """A minimal ``fabric.GuardrailChecker`` stub.

    Redacts an employee-id pattern and BLOCKS an obvious prompt-injection
    phrase. A real deployment wires Presidio / NeMo / Lakera instead; the
    span events emitted are identical regardless of the checker behind them.
    """

    name = "acme-inprocess-guard"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        lowered = value.lower()
        if "ignore previous instructions" in lowered:
            return CheckerVerdict(
                action="block",
                reason="prompt_injection_detected",
                rail="injection",
            )
        # Redact an ACME employee id like "EMP-12345" -> "EMP-[REDACTED]".
        import re

        redacted = re.sub(r"EMP-\d+", "EMP-[REDACTED]", value)
        if redacted != value:
            return CheckerVerdict(
                action="redact", modified_value=redacted, rail="employee_id"
            )
        return CheckerVerdict(action="allow")

    def close(self) -> None:  # pragma: no cover - nothing to release
        pass


class HRPolicyEngine:
    """A ``fabric.PolicyEngine`` stub gating sensitive HR topics.

    Denies questions about other employees' compensation; allows everything
    else. The SDK hashes the input and emits ``fabric.policy.evaluation`` —
    the raw policy input never lands on the trace.
    """

    engine_name = "acme-hr-policy"

    def evaluate(
        self, *, policy_id: str, input: dict[str, object], timeout_seconds: float
    ) -> EngineVerdict:
        topic = str(input.get("topic", ""))
        if topic == "third_party_compensation":
            return EngineVerdict(
                decision="deny",
                policy_version="2026.04",
                reason="cannot disclose another employee's compensation",
            )
        return EngineVerdict(decision="allow", policy_version="2026.04")

    def close(self) -> None:  # pragma: no cover
        pass


class ToolAllowList:
    """A ``fabric.ToolAuthorizer`` stub: a static allow-list."""

    _ALLOWED = frozenset({"policy_vector_search", "knowledge_graph_lookup"})

    def authorize(
        self, *, tool_name: str, arguments_hash: str | None
    ) -> ToolAuthorization:
        if tool_name in self._ALLOWED:
            return ToolAuthorization(decision="allow")
        return ToolAuthorization(
            decision="deny", reason=f"tool {tool_name!r} not allow-listed"
        )


# ---------------------------------------------------------------------------
# 2. The LLM boundary. Deterministic stub by default; documented real hook.
# ---------------------------------------------------------------------------
def call_llm(*, system: str, prompt: str, model: str) -> tuple[str, int, int]:
    """Return ``(answer_text, input_tokens, output_tokens)``.

    Offline default: a deterministic stub so the example needs no API key.

    To use a real OpenAI-compatible provider (e.g. Fireworks), set
    ``USE_REAL_LLM = True`` and provide credentials. Build CLEAN assistant
    message dicts (only ``role`` + ``content``) — some gateways reject echoed
    refusal / annotation / audio fields::

        from openai import OpenAI
        client = OpenAI(base_url=REAL_LLM_BASE_URL, api_key=REAL_LLM_API_KEY)
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        )
        text = resp.choices[0].message.content
        usage = resp.usage
        return text, usage.prompt_tokens, usage.completion_tokens
    """
    if USE_REAL_LLM:  # pragma: no cover - exercised only with real creds
        from openai import OpenAI

        client = OpenAI(
            base_url=os.environ.get(
                "REAL_LLM_BASE_URL", "https://api.fireworks.ai/inference/v1"
            ),
            api_key=os.environ["REAL_LLM_API_KEY"],
        )
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        )
        text = resp.choices[0].message.content or ""
        usage = resp.usage
        return text, int(usage.prompt_tokens), int(usage.completion_tokens)

    # Deterministic offline stub. Grounded answer that cites the retrieved doc.
    answer = (
        "Per the 2026 remote-work policy (doc HR-RW-12), full-time staff may "
        "work remotely up to 3 days/week with manager approval."
    )
    return answer, 384, 48


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 3. The instrumented RAG workflow.
# ---------------------------------------------------------------------------
def run_assistant(fab: Fabric, transport: LocalQueueTransport) -> str:
    """Answer one employee question end-to-end, fully instrumented.

    Returns the final answer text. Emits exactly one ``fabric.execution`` +
    one ``fabric.decision`` span (with child llm/tool spans and the event
    audit trail) per call.
    """
    user_question = "I'm EMP-40912 — how many days a week can I work remotely?"

    # An optional outer correlation span. Every decision opened inside inherits
    # its execution_id / workflow_id, so a multi-turn run correlates for free.
    with fab.execution(workflow_id="knowledge-assistant-v3") as execution:
        with fab.decision(
            session_id="sess-7f3a",
            request_id="req-0001",
            user_id="user-alice",
            attributes={"fabric.app.surface": "slack"},
        ) as decision:
            # -- (a) Input guardrail: redact PII / block injection ----------
            # guard_input runs the configured chain and emits fabric.guardrail.
            safe_question = decision.guard_input(user_question)
            assert "EMP-40912" not in safe_question, "employee id should be redacted"

            # -- (b) Governance policy check before answering --------------
            policy = decision.evaluate_policy(
                HRPolicyEngine(),
                policy_id="hr.remote_work.read",
                input={"topic": "own_remote_work_policy", "user_id": "user-alice"},
            )
            if policy.decision == "deny":  # fail-closed: do not answer
                raise RuntimeError(f"policy denied: {policy.reason}")

            # -- (c) Semantic memory READ: did we resolve a preference? ----
            # recall emits fabric.memory (direction=read). The content hash is
            # symmetric with a prior remember(), so reads/writes correlate.
            prior_pref = "office: NYC-HQ; team: platform"
            decision.recall(
                kind=MemoryKind.SEMANTIC,
                key="user-alice/work-context",
                content=prior_pref,
                source="semantic-store",
            )

            # -- (d) Authorize + run the vector-search tool ----------------
            search_args = json.dumps({"q": safe_question, "top_k": 5}, sort_keys=True)
            auth = decision.authorize_tool_call(
                ToolAllowList(),
                tool_name="policy_vector_search",
                arguments=search_args,
            )
            auth.raise_for_denied()  # aborts via ToolCallDenied if not allowed

            with decision.tool_call(
                "policy_vector_search",
                call_id="tc-vec-1",
                step_type="retrieve",
            ) as tool:
                tool.set_kind("retrieval")
                tool.set_arguments(search_args)
                # (pretend) vector DB hit
                rag_doc_ids = ["HR-RW-12", "HR-RW-04"]
                tool.set_result_count(len(rag_doc_ids))
                tool.set_result(json.dumps(rag_doc_ids))
            vector_tool_call_id = "tc-vec-1"

            # -- (e) Multi-source retrieval, hashed queries ----------------
            # Source 1: the policy RAG store. Raw query is hashed locally.
            decision.record_retrieval(
                RetrievalSource.RAG,
                query=safe_question,
                result_count=len(rag_doc_ids),
                result_hashes=[_sha256(d) for d in rag_doc_ids],
                source_document_ids=rag_doc_ids,
                latency_ms=24,
            )
            # Source 2: a knowledge graph for org/manager context.
            kg_query = "manager_approval_chain(user-alice)"
            decision.record_retrieval(
                RetrievalSource.KG,
                query=kg_query,
                result_count=1,
                source_document_ids=["org-graph:approval-policy"],
                latency_ms=11,
            )

            decision.checkpoint("after-retrieval", state_hash=_sha256("retrieval-done"))

            # -- (f) Synthesize the grounded answer with the LLM -----------
            prompt = (
                f"Question: {safe_question}\n"
                f"Context docs: {rag_doc_ids}\nMemory: {prior_pref}\n"
                "Answer grounded ONLY in the context."
            )
            with decision.llm_call(
                system="fireworks",
                model="accounts/fireworks/models/kimi-k2p6",
                temperature=0.2,
                max_tokens=512,
                step_type="synthesize",
            ) as call:
                answer, in_tok, out_tok = call_llm(
                    system="You are AcmeCorp's policy assistant.",
                    prompt=prompt,
                    model="accounts/fireworks/models/kimi-k2p6",
                )
                call.set_usage(
                    input_tokens=in_tok, output_tokens=out_tok, finish_reason="stop"
                )
                call.set_cache_usage(cache_read_tokens=256)
                call.set_streaming(ttft_ms=180.0, chunk_count=12)

            # -- (g) Semantic memory WRITE: persist the resolved answer ----
            decision.remember(
                kind=MemoryKind.SEMANTIC,
                content=answer,
                key="user-alice/remote-work-answer",
                tags=["hr", "remote-work"],
                ttl_seconds=86_400,
            )

            # -- (h) Inline grounding eval + async judge -------------------
            # A cheap, on-path faithfulness check. In a real stack this is a
            # small NLI model; here we approximate (answer cites a context doc).
            grounded = any(doc in answer for doc in rag_doc_ids)
            grounding_score = 0.92 if grounded else 0.40
            decision.record_eval(
                rubric_id="grounding.faithfulness.v1",
                score=grounding_score,
                dimension="faithfulness",
                evaluator_name="acme-nli-grounding",
                evaluator_version="0.3.1",
                confidence=0.85,
            )
            # Queue a deeper async review off the request path. Context travels
            # via the transport, NOT the trace — only metadata is emitted.
            ctx = decision.snapshot_context()
            ctx = JudgeContext(
                user_input=safe_question,
                agent_response=answer,
                retrieval_docs=ctx.retrieval_docs,
                memory_reads=ctx.memory_reads,
            )
            decision.queue_judge(
                rubric_id="answer-quality.v2",
                dimensions=("faithfulness", "completeness"),
                context=ctx,
                transport=transport,
            )

            # -- (i) Weak grounding -> escalate + log an audit ticket ------
            if grounding_score < 0.6:
                decision.request_escalation(
                    EscalationSummary(
                        reason="grounding score below threshold",
                        rubric_id="grounding.faithfulness.v1",
                        triggering_score=grounding_score,
                        mode="async",
                    )
                )
                # The escalation is logged to an external ticketing system —
                # a recorded side effect tied to the vector tool call.
                decision.record_side_effect(
                    SideEffectType.TICKET_CREATE,
                    target_system="servicenow",
                    operation="create_review_ticket",
                    request_payload=json.dumps({"reason": "low-grounding"}),
                    parent_tool_call_id=vector_tool_call_id,
                    replay_behavior=ReplayBehavior.SUPPRESS,
                )

            # -- (j) Replay envelope for the (commercial) replay engine ----
            decision.record_replay_metadata(
                state_hash=_sha256("final-state"),
                tool_result_hashes=[_sha256(json.dumps(rag_doc_ids))],
            )

            _ = execution.execution_id  # correlation anchor (inherited above)
            return answer


# ---------------------------------------------------------------------------
# 4. Telemetry helpers: read the captured spans/events back out.
# ---------------------------------------------------------------------------
def _events_named(span: ReadableSpan, name: str) -> list[dict[str, object]]:
    return [dict(e.attributes or {}) for e in span.events if e.name == name]


def _span_named(spans: list[ReadableSpan], name: str) -> ReadableSpan:
    for s in spans:
        if s.name == name:
            return s
    raise AssertionError(f"no span named {name!r} captured")


def print_audit_trail(spans: list[ReadableSpan]) -> None:
    """Print a human-readable view of the Fabric audit trail."""
    print("=" * 72)
    print("CAPTURED FABRIC TELEMETRY")
    print("=" * 72)
    for span in sorted(spans, key=lambda s: s.start_time):
        attrs = dict(span.attributes or {})
        print(f"\n[span] {span.name}  (kind={span.kind.name})")
        for key in sorted(attrs):
            if key.startswith(("fabric.", "gen_ai.")):
                print(f"    {key} = {attrs[key]!r}")
        if span.events:
            print("    events:")
            for ev in span.events:
                ev_attrs = dict(ev.attributes or {})
                highlights = {
                    k: v
                    for k, v in ev_attrs.items()
                    if k.endswith(
                        (
                            ".phase",
                            ".source",
                            ".query_hash",
                            ".direction",
                            ".kind",
                            ".decision",
                            ".type",
                            ".score",
                            ".reason",
                            ".side_effect_id",
                            ".parent_tool_call_id",
                            "_version",
                            ".rubric_id",
                        )
                    )
                }
                print(f"      - {ev.name}: {highlights}")
    print("\n" + "=" * 72)


# ---------------------------------------------------------------------------
# 5. Assertions — this IS the test. Verify the emitted audit trail.
# ---------------------------------------------------------------------------
def assert_audit_trail(spans: list[ReadableSpan]) -> None:
    decision_span = _span_named(spans, "fabric.decision")
    execution_span = _span_named(spans, "fabric.execution")
    llm_span = _span_named(spans, "fabric.llm_call")
    tool_span = _span_named(spans, "fabric.tool_call")
    d_attrs = dict(decision_span.attributes or {})

    # -- identity / correlation -----------------------------------------
    assert d_attrs.get("fabric.decision_id"), (
        "decision span must carry fabric.decision_id"
    )
    assert d_attrs.get("fabric.tenant_id") == "acme-corp"
    assert d_attrs.get("fabric.agent_id") == "knowledge-assistant"
    # execution_id is inherited from the enclosing fabric.execution span.
    exec_id = dict(execution_span.attributes or {}).get("fabric.execution_id")
    assert exec_id and d_attrs.get("fabric.execution_id") == exec_id, (
        "execution_id must inherit"
    )
    assert d_attrs.get("fabric.workflow_id") == "knowledge-assistant-v3"
    # decision + execution share the same trace.
    assert decision_span.context.trace_id == execution_span.context.trace_id

    # -- guardrail event ------------------------------------------------
    guard_events = _events_named(decision_span, "fabric.guardrail")
    assert guard_events, "expected a fabric.guardrail event"
    assert guard_events[0]["fabric.guardrail.phase"] == "input"

    # -- policy evaluation ----------------------------------------------
    policy_events = _events_named(decision_span, "fabric.policy.evaluation")
    assert len(policy_events) == 1, "expected one policy evaluation"
    assert policy_events[0]["fabric.policy.decision"] == "allow"
    assert policy_events[0]["fabric.policy.engine"] == "acme-hr-policy"
    assert policy_events[0]["fabric.policy.input_hash"], "policy input must be hashed"

    # -- tool authorization ---------------------------------------------
    auth_events = _events_named(decision_span, "fabric.tool.authorization")
    assert (
        auth_events and auth_events[0]["fabric.tool.authorization.decision"] == "allow"
    )

    # -- multi-source retrieval (hashed queries) ------------------------
    retr_events = _events_named(decision_span, "fabric.retrieval")
    sources = {e["fabric.retrieval.source"] for e in retr_events}
    assert sources == {"rag", "kg"}, f"expected rag+kg retrieval, got {sources}"
    for e in retr_events:  # raw query must never appear; only a 64-hex hash
        qh = e["fabric.retrieval.query_hash"]
        assert isinstance(qh, str) and len(qh) == 64
    assert d_attrs.get("fabric.retrieval_count") == 2

    # -- semantic memory read + write -----------------------------------
    mem_events = _events_named(decision_span, "fabric.memory")
    directions = sorted(e["fabric.memory.direction"] for e in mem_events)
    assert directions == ["read", "write"], (
        f"expected one read + one write, got {directions}"
    )
    assert all(e["fabric.memory.kind"] == "semantic" for e in mem_events)
    assert d_attrs.get("fabric.memory_read_count") == 1
    assert d_attrs.get("fabric.memory_write_count") == 1

    # -- LLM child span: GenAI conventions + step taxonomy --------------
    l_attrs = dict(llm_span.attributes or {})
    assert l_attrs.get("gen_ai.system") == "fireworks"
    assert l_attrs.get("gen_ai.request.model") == "accounts/fireworks/models/kimi-k2p6"
    assert l_attrs.get("gen_ai.usage.input_tokens") == 384
    assert l_attrs.get("gen_ai.usage.output_tokens") == 48
    assert l_attrs.get("fabric.step.type") == "synthesize"
    assert l_attrs.get("fabric.llm.usage.cache_read_tokens") == 256
    assert llm_span.parent and llm_span.parent.span_id == decision_span.context.span_id

    # -- tool child span -------------------------------------------------
    t_attrs = dict(tool_span.attributes or {})
    assert t_attrs.get("fabric.tool.name") == "policy_vector_search"
    assert t_attrs.get("fabric.tool.result_count") == 2
    assert t_attrs.get("fabric.step.type") == "retrieve"

    # -- inline eval -----------------------------------------------------
    eval_events = _events_named(decision_span, "fabric.eval")
    assert eval_events and eval_events[0]["fabric.eval.dimension"] == "faithfulness"
    assert eval_events[0]["fabric.eval.score"] == 0.92  # grounded stub answer

    # -- async judge queued ---------------------------------------------
    judge_events = _events_named(decision_span, "fabric.judge.queued")
    assert (
        judge_events
        and judge_events[0]["fabric.judge.rubric_id"] == "answer-quality.v2"
    )

    # -- checkpoint ------------------------------------------------------
    cp_events = _events_named(decision_span, "fabric.checkpoint")
    assert (
        cp_events and cp_events[0]["fabric.checkpoint.step_name"] == "after-retrieval"
    )

    # -- replay envelope -------------------------------------------------
    replay_events = _events_named(decision_span, "fabric.replay")
    assert replay_events, "expected a fabric.replay envelope"
    assert replay_events[0]["fabric.replay.metadata_version"] == "1"
    assert (
        replay_events[0]["fabric.replay.decision_id"] == d_attrs["fabric.decision_id"]
    )
    assert replay_events[0]["fabric.replay.execution_id"] == exec_id

    # -- (grounded path) no escalation / side effect for the happy case --
    # The stub answer is grounded (score 0.92 >= 0.6), so neither fires.
    assert not _events_named(decision_span, "fabric.escalation")
    assert not _events_named(decision_span, "fabric.side_effect")

    print("All assertions passed: the audit trail is correct.\n")


def assert_escalation_path(fab: Fabric, exporter: InMemorySpanExporter) -> None:
    """Second run proving the WEAK-grounding branch: escalation + side effect.

    Forces a non-grounded answer so grounding_score < threshold, exercising
    ``request_escalation`` (-> fabric.escalation) and ``record_side_effect``
    (-> fabric.side_effect with parent_tool_call_id, replay SUPPRESS).
    """
    exporter.clear()  # isolate this run's spans from the happy-path run

    with fab.decision(session_id="sess-x", request_id="req-esc") as decision:
        decision.record_retrieval(
            RetrievalSource.RAG,
            query="q",
            result_count=1,
            source_document_ids=["DOC-1"],
        )
        with decision.tool_call("policy_vector_search", call_id="tc-esc") as tool:
            tool.set_result_count(0)
        decision.record_eval(
            rubric_id="grounding.faithfulness.v1",
            score=0.40,
            dimension="faithfulness",
            evaluator_name="acme-nli-grounding",
        )
        decision.request_escalation(
            EscalationSummary(
                reason="grounding score below threshold",
                rubric_id="grounding.faithfulness.v1",
                triggering_score=0.40,
                mode="async",
            )
        )
        side_effect = decision.record_side_effect(
            SideEffectType.TICKET_CREATE,
            target_system="servicenow",
            operation="create_review_ticket",
            request_payload=json.dumps({"reason": "low-grounding"}),
            parent_tool_call_id="tc-esc",
            replay_behavior=ReplayBehavior.SUPPRESS,
        )

    spans = list(exporter.get_finished_spans())
    decision_span = _span_named(spans, "fabric.decision")

    # The escalation event landed on the span...
    esc_events = _events_named(decision_span, "fabric.escalation")
    assert esc_events and esc_events[0]["fabric.escalation.triggering_score"] == 0.40
    # ...and the audit side effect carries its parent tool call + a stable id.
    se_events = _events_named(decision_span, "fabric.side_effect")
    assert se_events, "expected a fabric.side_effect event"
    assert se_events[0]["fabric.side_effect.parent_tool_call_id"] == "tc-esc"
    assert se_events[0]["fabric.side_effect.replay_behavior"] == "suppress"
    assert (
        se_events[0]["fabric.side_effect.side_effect_id"] == side_effect.side_effect_id
    )
    # The decision span status names the escalation.
    assert decision_span.status.description == "escalation_requested"
    print("Escalation path verified: fabric.escalation + fabric.side_effect emitted.\n")


# ---------------------------------------------------------------------------
# 6. Wire OTel + Fabric, run, print, assert.
# ---------------------------------------------------------------------------
def main() -> int:
    # Self-contained OTel: an in-memory exporter so we can read spans back.
    # We register it via a SimpleSpanProcessor (flush-on-end, no batching
    # delay) — ideal for a synchronous, self-checking example.
    exporter = InMemorySpanExporter()
    provider = install_default_provider(service_name="acme-knowledge-assistant")
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    config = FabricConfig(
        tenant_id="acme-corp",
        agent_id="knowledge-assistant",
        profile=DEFAULT_PROFILE,
    )
    fab = Fabric(
        config,
        tracer=provider.get_tracer("acme-knowledge-assistant"),
        guardrail_checkers=[InProcessGuardrailChecker()],
    )
    transport = LocalQueueTransport()

    answer = run_assistant(fab, transport)
    print(f"\nAssistant answer:\n  {answer}\n")

    # Confirm the async judge actually received the request off the queue.
    queued = transport.dequeue()
    assert queued is not None and queued.rubric_id == "answer-quality.v2"
    print(
        f"Judge queue received request {queued.request_id} for rubric "
        f"{queued.rubric_id!r}\n"
    )

    spans = list(exporter.get_finished_spans())
    print_audit_trail(spans)
    assert_audit_trail(spans)

    # Second run: prove the weak-grounding escalation + side-effect branch.
    assert_escalation_path(fab, exporter)

    fab.close()
    print("DONE — example ran offline, all assertions passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
