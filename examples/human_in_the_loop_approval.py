# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Human-in-the-loop (HITL) approval workflow, instrumented with SingleAxis Fabric.

Enterprise scenario
-------------------
A B2B "Accounts Payable" copilot at a fintech drafts a vendor refund and tries to
push it to the payments system. Company policy says any refund over $5,000 must be
approved by a human controller before money moves. This example models that control
end-to-end: the agent retrieves the vendor record, drafts the refund with an LLM,
runs a policy engine that returns ``escalate``, records a *deferred* escalation, and
emits the payment side effect as ``committed=False`` with ``ReplayBehavior.SUPPRESS``
so a replay can never re-send money that a human has not yet approved. It then bundles
a ReplayMetadata envelope and propagates the Fabric identity over W3C ``tracestate`` to
a downstream "approval-service" so the human review continues under the same audit trail.

Fabric primitives / attributes demonstrated
-------------------------------------------
* ``fabric.execution`` correlation span (execution_id / workflow_id / status) via
  ``Fabric.execution(...)`` — every decision inside inherits the ids.
* ``fabric.decision`` span carrying ``fabric.decision_id`` / ``fabric.execution_id``.
* ``decision.guard_input(...)`` -> ``fabric.guardrail`` event (in-process GuardrailChecker stub).
* ``decision.record_retrieval(...)`` -> ``fabric.retrieval`` event (hash-only).
* ``decision.recall(...)`` / ``decision.remember(...)`` -> ``fabric.memory`` events (MemoryKind).
* ``decision.llm_call(...)`` child span (gen_ai.* + fabric.llm.*, step.type, usage, cache, retry).
* ``decision.authorize_tool_call(...)`` -> ``fabric.tool.authorization`` event (binary gate).
* ``decision.evaluate_policy(...)`` -> ``fabric.policy.evaluation`` event (verdict ``escalate``).
* ``decision.request_escalation(...)`` -> deferred ``fabric.escalation`` event + span attrs.
* ``decision.tool_call(...)`` child span for the payment attempt (step.type, call_id).
* ``decision.record_side_effect(...)`` -> ``fabric.side_effect`` event with
  ``committed=False``, ``approval_required=True``, ``ReplayBehavior.SUPPRESS``,
  and ``parent_tool_call_id`` linking back to the tool_call span.
* ``decision.checkpoint(...)`` -> ``fabric.checkpoint`` event (replay rewind point).
* ``decision.queue_judge(...)`` -> ``fabric.judge.queued`` event (async post-hoc grading).
* ``decision.record_eval(...)`` -> ``fabric.eval`` event (inline draft-quality score).
* ``decision.record_replay_metadata(...)`` -> ``fabric.replay`` envelope bundling the
  suppressed side-effect ids + checkpoint ids the replay engine must honor.
* ``fabric.inject_decision(...)`` / ``fabric.extract(...)`` — tracestate propagation to
  the downstream approval-service.

How to run
----------
    python3.13 -m venv /tmp/ex_hitl_approval
    /tmp/ex_hitl_approval/bin/pip install -e singleaxis-fabric/sdk/python
    /tmp/ex_hitl_approval/bin/python /tmp/ex_hitl_approval/example.py

Runs fully OFFLINE with a deterministic stub LLM (no API key). To exercise a real
OpenAI-compatible provider instead, see ``call_llm`` below. The script installs an
in-memory OTel exporter, drives the workflow, prints the captured audit trail, and
asserts the emitted spans/events are correct (the asserts ARE the test).
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    CheckerVerdict,
    EngineVerdict,
    EscalationSummary,
    Fabric,
    FabricConfig,
    JudgeContext,
    LocalQueueTransport,
    MemoryKind,
    ReplayBehavior,
    SideEffectType,
    ToolAuthorization,
    extract,
    inject_decision,
    install_default_provider,
)

# Business rule: any refund at or above this threshold needs a human approval.
REFUND_APPROVAL_THRESHOLD_USD = 5_000.0


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Stub adapters — in-process implementations of the Fabric plug-in protocols.
# In production these are OPA/Cedar (policy), Lakera/Presidio (guardrails), an
# allow-list authorizer, etc. They are kept tiny here so the example runs with
# no sidecars and no network.
# ---------------------------------------------------------------------------
class PiiRedactingChecker:
    """Minimal in-process GuardrailChecker (Fabric ``GuardrailChecker`` protocol).

    Redacts an obvious account-number pattern so the raw value never reaches the
    LLM. A real deployment swaps in Presidio / Lakera; the emit contract is identical.
    """

    name = "demo-pii-redactor"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        redacted = value
        action = "allow"
        if "ACCT-" in value:
            # Mask everything after the ACCT- prefix.
            head, _, _ = value.partition("ACCT-")
            redacted = f"{head}ACCT-[REDACTED]"
            action = "redact"
        # NOTE: the chain stamps policies_fired as "<checker.name>:<rail>", so a
        # distinct rail label keeps the audit attribute readable (see bugs_found).
        return CheckerVerdict(
            action=action, modified_value=redacted, rail="account-number"
        )

    def close(self) -> None:  # pragma: no cover - nothing to release
        pass


class RefundPolicyEngine:
    """In-process PolicyEngine (Fabric ``PolicyEngine`` protocol).

    Returns ``escalate`` when a refund is at/over the approval threshold, else
    ``allow``. A real engine is OPA/Cedar evaluating a signed policy bundle.
    """

    engine_name = "custom:refund-approval"

    def evaluate(
        self, *, policy_id: str, input: dict[str, object], timeout_seconds: float
    ) -> EngineVerdict:
        amount = float(input.get("amount_usd", 0.0))
        if amount >= REFUND_APPROVAL_THRESHOLD_USD:
            return EngineVerdict(
                decision="escalate",
                policy_version="2026-06-01",
                reason=(
                    f"refund {amount:.2f} USD >= {REFUND_APPROVAL_THRESHOLD_USD:.0f} "
                    "USD threshold; controller approval required"
                ),
                evidence_ref="s3://audit/policies/refund-approval/v2026-06-01",
            )
        return EngineVerdict(decision="allow", policy_version="2026-06-01")

    def close(self) -> None:  # pragma: no cover
        pass


class PaymentsToolAuthorizer:
    """In-process ToolAuthorizer (Fabric ``ToolAuthorizer`` protocol).

    Allows the agent to *stage* a payment (the SUPPRESSED side effect) but the
    actual money movement stays gated behind the human approval recorded as an
    escalation. Here we allow staging; a deny would short-circuit via
    ``raise_for_denied``.
    """

    def authorize(
        self, *, tool_name: str, arguments_hash: str | None
    ) -> ToolAuthorization:
        if tool_name == "payments.create_refund":
            return ToolAuthorization(
                decision="allow", reason="staging allowed; commit gated"
            )
        return ToolAuthorization(decision="deny", reason="tool not on allow-list")


# ---------------------------------------------------------------------------
# LLM call. Deterministic STUB by default so the example runs offline. To use a
# real OpenAI-compatible provider (e.g. Fireworks), set FABRIC_EXAMPLE_REAL_LLM=1
# and supply the env vars below; the committed default path needs no API key.
# ---------------------------------------------------------------------------
def call_llm(*, system: str, user: str, model: str) -> dict[str, Any]:
    """Return a dict with ``text`` and token usage. Stub unless real LLM enabled.

    Real-provider wiring (OpenAI-compatible, e.g. Fireworks):

        import openai
        client = openai.OpenAI(
            base_url=os.environ["FABRIC_EXAMPLE_LLM_BASE_URL"],  # e.g. fireworks /v1
            api_key=os.environ["FABRIC_EXAMPLE_LLM_API_KEY"],
        )
        resp = client.chat.completions.create(
            model=model,
            messages=[                       # build CLEAN dicts only — some
                {"role": "system", "content": system},   # gateways reject echoed
                {"role": "user", "content": user},        # refusal/annotation fields
            ],
            temperature=0.2,
        )
        return {
            "text": resp.choices[0].message.content,
            "input_tokens": resp.usage.prompt_tokens,
            "output_tokens": resp.usage.completion_tokens,
        }
    """
    if os.environ.get("FABRIC_EXAMPLE_REAL_LLM") == "1":  # pragma: no cover - opt-in
        import openai

        client = openai.OpenAI(
            base_url=os.environ["FABRIC_EXAMPLE_LLM_BASE_URL"],
            api_key=os.environ["FABRIC_EXAMPLE_LLM_API_KEY"],
        )
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.2,
        )
        usage = resp.usage
        return {
            "text": resp.choices[0].message.content or "",
            "input_tokens": getattr(usage, "prompt_tokens", 0),
            "output_tokens": getattr(usage, "completion_tokens", 0),
        }

    # Deterministic offline stub: a drafted refund justification.
    draft = (
        "Refund justification: vendor INV-7781 was double-charged on the May invoice. "
        "Recommend issuing a full refund of 7,400.00 USD to the vendor account on file."
    )
    return {"text": draft, "input_tokens": 128, "output_tokens": 44}


# ---------------------------------------------------------------------------
# The workflow.
# ---------------------------------------------------------------------------
def run_workflow(fab: Fabric, judge_queue: LocalQueueTransport) -> dict[str, Any]:
    """Drive the HITL approval workflow once. Returns a small result dict."""
    policy_engine = RefundPolicyEngine()
    authorizer = PaymentsToolAuthorizer()

    # Outer correlation span. A retry of the same logical task would reuse the
    # execution_id and bump the attempt; here it is attempt 1.
    with fab.execution(
        workflow_id="accounts-payable-refunds",
        execution_attempt=1,
        attributes={"fabric.app.env": "prod"},
    ) as execution:
        with fab.decision(
            session_id="sess-ap-7781",
            request_id="req-ap-7781-001",
            user_id="agent-ap-copilot",
            attributes={"fabric.app.feature": "vendor-refund"},
        ) as decision:
            # 1) Guard the raw user instruction (contains a sensitive account no).
            raw_instruction = (
                "Please refund vendor INV-7781 to account ACCT-99887766 — they were "
                "double charged 7,400 USD last month."
            )
            safe_instruction = decision.guard_input(raw_instruction)

            # 2) Retrieve the vendor record (RAG). Only metadata + hashes emitted.
            decision.record_retrieval(
                "rag",
                query="vendor INV-7781 billing history",
                result_count=3,
                source_document_ids=["vendor:INV-7781", "invoice:may-2026"],
                latency_ms=22,
            )

            # 3) Recall prior approved-payee memory, then record we consulted it.
            decision.recall(
                kind=MemoryKind.SEMANTIC,
                key="approved-payees/INV-7781",
                content="payee verified 2026-03-01",
                source="payee-registry",
            )

            # Checkpoint: clean rewind point after context is assembled.
            ctx_ckpt = decision.checkpoint(
                "after-context-assembly", state_hash=_sha256(safe_instruction)
            )

            # 4) Draft the refund with the LLM, instrumented as a child span.
            refund_amount = 7_400.00
            with decision.llm_call(
                system="fireworks",
                model="accounts/fireworks/models/kimi-k2p6",
                temperature=0.2,
                max_tokens=256,
                step_id="draft-refund",
                step_type="plan",
            ) as call:
                llm_out = call_llm(
                    system="You are an accounts-payable assistant. Draft a refund.",
                    user=safe_instruction,
                    model="accounts/fireworks/models/kimi-k2p6",
                )
                call.set_usage(
                    input_tokens=int(llm_out["input_tokens"]),
                    output_tokens=int(llm_out["output_tokens"]),
                    finish_reason="stop",
                )
                call.set_cache_usage(cache_read_tokens=96)  # prompt-cache hit
                call.set_streaming(ttft_ms=180.0, chunk_count=12)
                call.set_retry(count=0)
            draft_text = str(llm_out["text"])

            # 5) Inline eval of the draft (synchronous grader on the request path).
            decision.record_eval(
                rubric_id="refund-draft-quality",
                score=0.91,
                dimension="completeness",
                evaluator_name="demo-inline-grader",
                confidence=0.8,
            )

            # 6) Authorize the payments tool BEFORE we touch it (binary gate).
            tool_args = json.dumps(
                {"vendor": "INV-7781", "amount_usd": refund_amount}, sort_keys=True
            )
            auth = decision.authorize_tool_call(
                authorizer, tool_name="payments.create_refund", arguments=tool_args
            )
            auth.raise_for_denied()  # deny would abort here

            # 7) Evaluate the refund-approval policy. Returns ``escalate``.
            policy_eval = decision.evaluate_policy(
                policy_engine,
                policy_id="ap.refund.approval",
                input={"amount_usd": refund_amount, "vendor": "INV-7781"},
            )

            # 8) Stage the payment but DO NOT commit — money is gated on approval.
            #    Wrap in a tool_call child span so the side effect can link to it.
            staged = False
            side_effect_id = None
            with decision.tool_call(
                "payments.create_refund",
                call_id="toolcall-refund-001",
                step_id="stage-refund",
            ) as tool:
                tool.set_kind("http")
                tool.set_arguments(tool_args)
                tool.set_idempotency(idempotent=True, key="refund:INV-7781:may-2026")
                if policy_eval.decision == "escalate":
                    # Record the mutation as NOT committed and SUPPRESS on replay.
                    se = decision.record_side_effect(
                        SideEffectType.PAYMENT,
                        target_system="payments-api",
                        operation="create_refund",
                        request_payload=tool_args,
                        idempotency_key="refund:INV-7781:may-2026",
                        approval_required=True,
                        committed=False,  # staged, not executed
                        rollback_supported=False,
                        replay_behavior=ReplayBehavior.SUPPRESS,
                        parent_tool_call_id="toolcall-refund-001",
                    )
                    side_effect_id = se.side_effect_id
                    tool.set_result(json.dumps({"status": "staged_pending_approval"}))
                    staged = True

            # 9) Queue an async judge job (out-of-band grading via transport).
            judge_ctx = decision.snapshot_context()
            judge_ctx = JudgeContext(
                user_input=None,  # never put raw user text on the request path
                agent_response=draft_text,
                retrieval_docs=judge_ctx.retrieval_docs,
                memory_reads=judge_ctx.memory_reads,
            )
            decision.queue_judge(
                rubric_id="refund-safety",
                dimensions=("policy_adherence", "tone"),
                context=judge_ctx,
                transport=judge_queue,
                payload_ref="s3://tenant/judge-payloads/req-ap-7781-001",
            )

            # 10) Record a DEFERRED escalation — the human controller must approve.
            decision.request_escalation(
                EscalationSummary(
                    reason=policy_eval.reason or "approval required",
                    rubric_id="ap.refund.approval",
                    triggering_score=refund_amount,
                    mode="deferred",  # tracked as a separate approval ticket
                )
            )

            # 11) Note that we wrote an audit memo to long-term memory.
            decision.remember(
                kind=MemoryKind.EPISODIC,
                content=f"refund {refund_amount} staged pending approval for INV-7781",
                key="audit/refund/INV-7781",
                tags=["refund", "pending-approval"],
            )

            # 12) Bundle the ReplayMetadata envelope. It auto-collects the
            #     checkpoint id and the SUPPRESSED side-effect id so a replay
            #     engine knows exactly which mutation it must NOT re-execute.
            decision.record_replay_metadata(state_hash=_sha256(draft_text))

            # 13) Propagate the Fabric identity to the downstream approval-service
            #     over W3C tracestate so the human review runs under the same trace.
            carrier: dict[str, str] = {}
            inject_decision(carrier, decision)

            return {
                "decision_id": decision.decision_id,
                "execution_id": execution.execution_id,
                "trace_id": decision.trace_id,
                "policy_decision": policy_eval.decision,
                "staged": staged,
                "side_effect_id": side_effect_id,
                "checkpoint_id": str(ctx_ckpt.checkpoint_id),
                "tracestate_carrier": carrier,
                "draft_text": draft_text,
            }


# ---------------------------------------------------------------------------
# Downstream service: recover the Fabric identity from the propagated header.
# ---------------------------------------------------------------------------
def downstream_approval_service(carrier: dict[str, str]) -> Any:
    """Simulate the approval-service extracting Fabric context off ``tracestate``."""
    return extract(carrier)


# ---------------------------------------------------------------------------
# Telemetry pretty-printer.
# ---------------------------------------------------------------------------
def _fmt_attr(value: Any) -> str:
    if isinstance(value, (tuple, list)):
        return "[" + ", ".join(str(v) for v in value) + "]"
    return str(value)


def print_audit_trail(spans: tuple[ReadableSpan, ...]) -> None:
    print("\n" + "=" * 78)
    print("FABRIC AUDIT TRAIL — captured spans + events")
    print("=" * 78)
    for span in spans:
        attrs = dict(span.attributes or {})
        print(f"\n[span] {span.name}  (kind={span.kind.name})")
        # Show the governance-relevant attributes first, in a stable order.
        keys_of_interest = [
            "fabric.decision_id",
            "fabric.execution_id",
            "fabric.workflow_id",
            "fabric.execution.status",
            "fabric.step.type",
            "fabric.tool.name",
            "fabric.escalated",
            "fabric.escalation.mode",
            "fabric.blocked",
            "fabric.side_effect_count",
            "fabric.policy_evaluation_count",
            "gen_ai.system",
            "gen_ai.request.model",
            "gen_ai.usage.input_tokens",
            "gen_ai.usage.output_tokens",
        ]
        for key in keys_of_interest:
            if key in attrs:
                print(f"    {key} = {_fmt_attr(attrs[key])}")
        for event in span.events:
            ev_attrs = dict(event.attributes or {})
            highlights = {
                k: v for k, v in ev_attrs.items() if k != "fabric.schema_version"
            }
            print(f"    • event {event.name}")
            for k, v in highlights.items():
                print(f"        {k} = {_fmt_attr(v)}")


# ---------------------------------------------------------------------------
# Assertions — these ARE the test for the emitted telemetry.
# ---------------------------------------------------------------------------
def _events_named(span: ReadableSpan, name: str) -> list[Any]:
    return [e for e in span.events if e.name == name]


def assert_telemetry(spans: tuple[ReadableSpan, ...], result: dict[str, Any]) -> None:
    by_name: dict[str, list[ReadableSpan]] = {}
    for span in spans:
        by_name.setdefault(span.name, []).append(span)

    # --- execution span -----------------------------------------------------
    assert "fabric.execution" in by_name, "expected a fabric.execution span"
    execution = by_name["fabric.execution"][0]
    exec_attrs = dict(execution.attributes or {})
    assert exec_attrs.get("fabric.execution.status") == "completed"
    assert exec_attrs.get("fabric.workflow_id") == "accounts-payable-refunds"
    assert exec_attrs.get("fabric.execution.attempt") == 1

    # --- decision span ------------------------------------------------------
    assert "fabric.decision" in by_name, "expected a fabric.decision span"
    decision = by_name["fabric.decision"][0]
    d_attrs = dict(decision.attributes or {})
    assert d_attrs.get("fabric.decision_id") == result["decision_id"]
    # Decision inherited the execution id from the enclosing execution span.
    assert d_attrs.get("fabric.execution_id") == result["execution_id"]
    # Deferred escalation is recorded on the decision span attributes.
    assert d_attrs.get("fabric.escalated") is True
    assert d_attrs.get("fabric.escalation.mode") == "deferred"

    # --- guardrail event ----------------------------------------------------
    guardrail_events = _events_named(decision, "fabric.guardrail")
    assert guardrail_events, "expected a fabric.guardrail event"
    assert guardrail_events[0].attributes.get("fabric.guardrail.phase") == "input"

    # --- retrieval + memory events -----------------------------------------
    assert _events_named(decision, "fabric.retrieval"), (
        "expected a fabric.retrieval event"
    )
    memory_events = _events_named(decision, "fabric.memory")
    directions = {e.attributes.get("fabric.memory.direction") for e in memory_events}
    assert {"read", "write"} <= directions, (
        f"expected read+write memory, got {directions}"
    )

    # --- policy evaluation: must be the ``escalate`` verdict ----------------
    policy_events = _events_named(decision, "fabric.policy.evaluation")
    assert policy_events, "expected a fabric.policy.evaluation event"
    pe = policy_events[0].attributes
    assert pe.get("fabric.policy.decision") == "escalate", pe.get(
        "fabric.policy.decision"
    )
    assert pe.get("fabric.policy.engine") == "custom:refund-approval"
    assert pe.get("fabric.policy.reason"), "non-allow policy must carry a reason"

    # --- tool authorization event (binary allow gate) -----------------------
    auth_events = _events_named(decision, "fabric.tool.authorization")
    assert auth_events, "expected a fabric.tool.authorization event"
    assert (
        auth_events[0].attributes.get("fabric.tool.authorization.decision") == "allow"
    )

    # --- escalation event (deferred) ----------------------------------------
    esc_events = _events_named(decision, "fabric.escalation")
    assert esc_events, "expected a fabric.escalation event"
    assert esc_events[0].attributes.get("fabric.escalation.mode") == "deferred"

    # --- side effect: staged (not committed), suppressed, linked to tool ----
    se_events = _events_named(decision, "fabric.side_effect")
    assert se_events, "expected a fabric.side_effect event"
    se = se_events[0].attributes
    assert se.get("fabric.side_effect.type") == "payment"
    assert se.get("fabric.side_effect.committed") is False, (
        "payment must NOT be committed"
    )
    assert se.get("fabric.side_effect.approval_required") is True
    assert se.get("fabric.side_effect.replay_behavior") == "suppress"
    assert se.get("fabric.side_effect.parent_tool_call_id") == "toolcall-refund-001"
    assert se.get("fabric.side_effect.side_effect_id") == result["side_effect_id"]

    # --- checkpoint + eval + judge events -----------------------------------
    assert _events_named(decision, "fabric.checkpoint"), (
        "expected a fabric.checkpoint event"
    )
    assert _events_named(decision, "fabric.eval"), "expected a fabric.eval event"
    assert _events_named(decision, "fabric.judge.queued"), (
        "expected a fabric.judge.queued event"
    )

    # --- replay metadata envelope: must carry the suppressed side-effect id -
    replay_events = _events_named(decision, "fabric.replay")
    assert replay_events, "expected a fabric.replay event"
    rp = replay_events[0].attributes
    assert rp.get("fabric.replay.decision_id") == result["decision_id"]
    assert rp.get("fabric.replay.execution_id") == result["execution_id"]
    suppressed = rp.get("fabric.replay.suppressed_side_effect_ids")
    assert suppressed and result["side_effect_id"] in suppressed, (
        "replay envelope must list the suppressed payment so it is never re-sent"
    )
    ckpts = rp.get("fabric.replay.checkpoint_ids")
    assert ckpts and result["checkpoint_id"] in ckpts

    # --- LLM child span -----------------------------------------------------
    assert "fabric.llm_call" in by_name, "expected a fabric.llm_call child span"
    llm = by_name["fabric.llm_call"][0]
    la = dict(llm.attributes or {})
    assert la.get("gen_ai.system") == "fireworks"
    assert la.get("fabric.step.type") == "plan"  # host override of the default
    assert la.get("gen_ai.usage.output_tokens") is not None
    assert la.get("fabric.llm.usage.cache_read_tokens") == 96
    # Child span is parented under the decision span (same trace).
    assert f"{llm.context.trace_id:032x}" == result["trace_id"]

    # --- tool_call child span -----------------------------------------------
    assert "fabric.tool_call" in by_name, "expected a fabric.tool_call child span"
    tc = dict(by_name["fabric.tool_call"][0].attributes or {})
    assert tc.get("fabric.tool.name") == "payments.create_refund"
    assert tc.get("fabric.tool.idempotent") is True

    # --- tracestate propagation round-trips ---------------------------------
    ctx = downstream_approval_service(result["tracestate_carrier"])
    assert ctx is not None, "downstream service must recover Fabric context"
    assert ctx.decision_id == result["decision_id"]
    assert ctx.execution_id == result["execution_id"]
    assert ctx.workflow_id == "accounts-payable-refunds"


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------
def main() -> int:
    # Self-contained OTel: in-memory exporter so we can read back what we emit.
    exporter = InMemorySpanExporter()
    provider = install_default_provider(
        service_name="ap-refund-copilot", exporter=exporter
    )
    # SimpleSpanProcessor flushes synchronously — no manual drain needed.
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    config = FabricConfig(tenant_id="acme-fintech", agent_id="ap-copilot")
    fab = Fabric(config, guardrail_checkers=[PiiRedactingChecker()])
    judge_queue = LocalQueueTransport()

    try:
        result = run_workflow(fab, judge_queue)
    finally:
        fab.close()

    spans = exporter.get_finished_spans()
    print_audit_trail(spans)

    print("\n" + "-" * 78)
    print("RESULT SUMMARY")
    print("-" * 78)
    print(f"  decision_id        : {result['decision_id']}")
    print(f"  execution_id       : {result['execution_id']}")
    print(f"  policy decision    : {result['policy_decision']}  (-> human approval)")
    print(
        f"  payment staged     : {result['staged']} (committed=False, replay=SUPPRESS)"
    )
    print(f"  side_effect_id     : {result['side_effect_id']}")
    print(
        f"  tracestate carrier : {result['tracestate_carrier'].get('tracestate', '')[:72]}..."
    )
    queued = judge_queue.dequeue()
    print(f"  judge job queued   : rubric={queued.rubric_id} dims={queued.dimensions}")

    assert_telemetry(spans, result)
    print("\nAll telemetry assertions passed. ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
