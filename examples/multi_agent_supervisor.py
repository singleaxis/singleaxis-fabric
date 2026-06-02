#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Multi-agent supervisor, instrumented with the SingleAxis Fabric SDK.

Enterprise scenario
====================
A regulated fintech runs a "deal-desk" assistant as a **supervisor /
sub-agent** topology. A supervisor agent receives an analyst's request
("summarize the risk posture of ACME Corp and draft a client email"),
decomposes it, and dispatches to three specialist sub-agents — a
*researcher* (RAG over filings), an *analyst* (reasons over retrieved
facts), and a *writer* (drafts the outbound email + files a CRM note).
Each sub-agent is an independent governed turn, but the whole run must
correlate as ONE unit of work for audit, cost attribution, and replay.

This run is the SECOND attempt of a logical task: the prior attempt
failed mid-writer (CRM 5xx), so the orchestrator retried. Fabric stamps
the retry lineage (execution_attempt / retry.previous_attempt_id) on the
correlation span and every child decision inherits it — so an auditor can
see attempt #2 reused the same execution_id and why it retried.

What this example demonstrates (fabric.* primitives / attributes)
-----------------------------------------------------------------
* ``fabric.execution`` correlation span (``Fabric.execution``) carrying
  ``fabric.execution_id`` / ``fabric.workflow_id`` /
  ``fabric.execution.status`` plus the retry lineage
  (``fabric.execution.attempt`` / ``.attempt_id`` /
  ``.retry.reason`` / ``.retry.previous_attempt_id``).
* Several child ``fabric.decision`` spans (one per sub-agent) that
  INHERIT the execution-correlation metadata — cross-step correlation
  without threading ids by hand. Each carries ``fabric.decision_id``.
* ``decision.llm_call(...)`` child spans with the step taxonomy
  (``fabric.step.type`` = ``plan`` / ``reason`` / ``draft``,
  ``fabric.step.id``) + GenAI usage, prompt-cache, streaming, and
  per-call provider retry (``set_retry``).
* ``decision.tool_call(...)`` child spans with arg/result hashes,
  ``set_idempotency``, and a step-level retry (``step_attempt`` /
  ``step_retry_reason``) modelling the writer's CRM retry.
* Input guardrail via an in-process ``GuardrailChecker`` stub
  (``fabric.guardrail`` event).
* ``decision.record_retrieval`` (``fabric.retrieval``) and
  ``remember`` / ``recall`` (``fabric.memory``) for the researcher.
* ``decision.evaluate_policy`` (``fabric.policy.evaluation``) and
  ``decision.authorize_tool_call`` (``fabric.tool.authorization``)
  gating the email send.
* ``decision.record_side_effect`` (``fabric.side_effect``) with a
  ``parent_tool_call_id`` linking the CRM mutation to its tool span,
  plus ``side_effect_id`` and ``replay_behavior``.
* ``decision.record_eval`` (``fabric.eval``) inline grade and
  ``request_escalation`` (``fabric.escalation``) when the grade is low.
* ``decision.checkpoint`` (``fabric.checkpoint``) and
  ``decision.record_replay_metadata`` (``fabric.replay``).

How to run
----------
Offline (default — deterministic stub LLM, no API key, no network)::

    python3.13 -m venv .venv
    .venv/bin/pip install -e path/to/singleaxis-fabric/sdk/python
    .venv/bin/python multi_agent_supervisor.py

It installs an in-memory OTel exporter, runs the workflow, prints the
captured audit trail, and asserts the emitted spans/events are correct.
Exit code 0 == all assertions passed.

Real LLM (optional): set ``FABRIC_EXAMPLE_USE_REAL_LLM=1`` and the
OpenAI-compatible env vars in ``call_llm`` below. The committed file
stays offline-runnable; the real path is opt-in.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from collections.abc import Sequence

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    CheckerVerdict,
    EngineVerdict,
    EscalationSummary,
    Fabric,
    FabricConfig,
    MemoryKind,
    ReplayBehavior,
    RetrievalSource,
    SideEffectType,
    ToolAuthorization,
    install_default_provider,
)

# ---------------------------------------------------------------------------
# 1. The LLM seam.
#
# Every model call goes through call_llm(). By default it returns a
# deterministic STUB so the example runs offline with no API key. To prove
# real-world behaviour, set FABRIC_EXAMPLE_USE_REAL_LLM=1 and configure an
# OpenAI-compatible provider (the block below shows Fireworks). Fabric is
# provider-agnostic — it only instruments the call via decision.llm_call().
# ---------------------------------------------------------------------------

_STUB_RESPONSES = {
    "plan": (
        "PLAN: 1) research ACME 10-K risk factors 2) analyze posture "
        "3) draft client email + file CRM note."
    ),
    "reason": (
        "ANALYSIS: ACME shows elevated liquidity risk (current ratio 0.9) "
        "and one pending regulatory matter; overall posture: CAUTION."
    ),
    "draft": (
        "Dear client, ACME Corp's latest filings indicate a cautious risk "
        "posture driven by liquidity tightness and a pending regulatory "
        "matter. We recommend a measured exposure. Regards, Deal Desk."
    ),
}


def call_llm(*, step: str, system: str, prompt: str, model: str) -> dict[str, object]:
    """Return a model completion as a uniform dict.

    Offline stub by default; real OpenAI-compatible provider when
    FABRIC_EXAMPLE_USE_REAL_LLM=1. The return shape is normalized so the
    instrumentation (decision.llm_call) is identical on both paths.
    """
    if os.environ.get("FABRIC_EXAMPLE_USE_REAL_LLM") == "1":
        # --- Real provider path (opt-in) -------------------------------
        # Wire any OpenAI-compatible endpoint. Example: Fireworks.
        #   base_url = "https://api.fireworks.ai/inference/v1"
        #   model    = "accounts/fireworks/models/kimi-k2p6"
        # Build CLEAN message dicts (role/content only) — some gateways
        # reject echoed refusal/annotation/audio fields.
        from openai import OpenAI  # imported lazily so offline needs no dep

        client = OpenAI(
            base_url=os.environ["FABRIC_EXAMPLE_LLM_BASE_URL"],
            api_key=os.environ["FABRIC_EXAMPLE_LLM_API_KEY"],
        )
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=512,
        )
        usage = resp.usage
        return {
            "text": resp.choices[0].message.content or "",
            "input_tokens": getattr(usage, "prompt_tokens", 0),
            "output_tokens": getattr(usage, "completion_tokens", 0),
            "finish_reason": resp.choices[0].finish_reason or "stop",
            "response_model": resp.model,
        }

    # --- Offline deterministic stub (default) --------------------------
    text = _STUB_RESPONSES[step]
    return {
        "text": text,
        # Deterministic but plausible token counts derived from lengths.
        "input_tokens": len(prompt) // 4,
        "output_tokens": len(text) // 4,
        "finish_reason": "stop",
        "response_model": f"{model}-stub",
    }


# ---------------------------------------------------------------------------
# 2. In-process governance stubs.
#
# Production deployments wire real adapters (Presidio/NeMo sidecars, OPA,
# Lakera). Here we use tiny in-process implementations so the example is
# self-contained — they satisfy the same Protocols the SDK expects.
# ---------------------------------------------------------------------------


class KeywordGuardrailChecker:
    """A trivial in-process GuardrailChecker (satisfies the Protocol).

    Redacts an internal account number pattern from user input so it never
    reaches the LLM. Real rails are Presidio/NeMo/Lakera; this keeps the
    example sidecar-free while still emitting a fabric.guardrail event.
    """

    name = "keyword-redactor"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        if "ACME-INTERNAL-" in value:
            redacted = value.replace("ACME-INTERNAL-4471", "[REDACTED_ACCT]")
            return CheckerVerdict(
                action="redact", modified_value=redacted, rail="acct_number"
            )
        return CheckerVerdict(action="allow")

    def close(self) -> None:  # pragma: no cover - nothing to release
        pass


class AllowListToolAuthorizer:
    """Pre-execution tool authorizer (satisfies the ToolAuthorizer Protocol).

    Allows a small set of tools; denies everything else, fail-closed.
    """

    def __init__(self, allowed: set[str]) -> None:
        self._allowed = allowed

    def authorize(
        self, *, tool_name: str, arguments_hash: str | None
    ) -> ToolAuthorization:
        if tool_name in self._allowed:
            return ToolAuthorization(decision="allow")
        return ToolAuthorization(
            decision="deny", reason=f"tool {tool_name!r} not on allow-list"
        )

    def close(self) -> None:  # pragma: no cover
        pass


class DataResidencyPolicyEngine:
    """A minimal PolicyEngine (satisfies the PolicyEngine Protocol).

    Denies an outbound email if the recipient is outside the approved
    region — a stand-in for OPA/Cedar. Returns an EngineVerdict; the SDK
    normalizes it into a fabric.policy.evaluation event.
    """

    engine_name = "custom:data-residency"

    def evaluate(
        self, *, policy_id: str, input: dict[str, object], timeout_seconds: float
    ) -> EngineVerdict:
        region = str(input.get("recipient_region", ""))
        if region in {"EU", "US"}:
            return EngineVerdict(decision="allow", policy_version="2026.02")
        return EngineVerdict(
            decision="deny",
            policy_version="2026.02",
            reason=f"recipient_region={region!r} not in approved residency set",
        )

    def close(self) -> None:  # pragma: no cover
        pass


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 3. The sub-agents. Each is one governed Decision under the shared
#    Execution. They never thread the execution_id by hand — opening the
#    Decision inside the `with execution` block inherits it.
# ---------------------------------------------------------------------------

MODEL = "accounts/fireworks/models/kimi-k2p6"


def run_researcher(fab: Fabric, *, session_id: str, user_request: str) -> str:
    """Sub-agent #1: RAG retrieval + episodic memory write. Returns findings."""
    with fab.decision(
        session_id=session_id,
        request_id="req-researcher",
        attributes={"fabric.subagent": "researcher"},
    ) as d:
        # Input guardrail: redact the internal account number before the LLM.
        safe_request = d.guard_input(user_request)

        # Record a RAG retrieval over ACME's filings (hash-only).
        d.record_retrieval(
            RetrievalSource.RAG,
            query=safe_request,
            result_count=3,
            source_document_ids=["acme-10k-2025", "acme-8k-q1", "acme-risk-memo"],
            latency_ms=42,
        )
        d.checkpoint("after-retrieval", state_hash=_sha256("retrieved:acme"))

        # The researcher LLM call — a "research" planning step.
        with d.llm_call(
            system="deal-desk-research",
            model=MODEL,
            temperature=0.2,
            step_type="plan",
            step_id="researcher.plan",
        ) as call:
            out = call_llm(
                step="plan", system="research ACME", prompt=safe_request, model=MODEL
            )
            call.set_usage(
                input_tokens=int(out["input_tokens"]),
                output_tokens=int(out["output_tokens"]),
                finish_reason=str(out["finish_reason"]),
            )
            call.set_response_model(str(out["response_model"]))
            # Prompt-cache + streaming telemetry (opt-in).
            call.set_cache_usage(cache_read_tokens=128, cache_creation_tokens=0)
            call.set_streaming(ttft_ms=180.5, chunk_count=12)

        findings = str(out["text"])
        # Persist findings to episodic memory for the analyst sub-agent.
        d.remember(
            kind=MemoryKind.EPISODIC,
            content=findings,
            key="acme.findings",
            tags=["acme"],
        )
        d.record_replay_metadata(state_hash=_sha256(findings))
        return findings


def run_analyst(fab: Fabric, *, session_id: str, findings: str) -> tuple[str, float]:
    """Sub-agent #2: reasons over recalled findings, self-grades. Returns (analysis, score)."""
    with fab.decision(
        session_id=session_id,
        request_id="req-analyst",
        attributes={"fabric.subagent": "analyst"},
    ) as d:
        # Recall what the researcher remembered (cross-sub-agent handoff).
        d.recall(
            kind=MemoryKind.EPISODIC,
            key="acme.findings",
            content=findings,
            source="researcher",
        )

        with d.llm_call(
            system="deal-desk-analyst",
            model=MODEL,
            temperature=0.1,
            step_type="reason",
            step_id="analyst.reason",
        ) as call:
            out = call_llm(
                step="reason", system="analyze posture", prompt=findings, model=MODEL
            )
            call.set_usage(
                input_tokens=int(out["input_tokens"]),
                output_tokens=int(out["output_tokens"]),
                finish_reason=str(out["finish_reason"]),
            )
            # Model a transient provider retry within this single call.
            call.set_retry(count=1, reason="upstream_429")

        analysis = str(out["text"])
        # Inline grade (synchronous eval). Low faithfulness → escalate.
        score = 0.62
        d.record_eval(
            rubric_id="faithfulness-v1",
            score=score,
            dimension="faithfulness",
            evaluator_name="inline-heuristic",
            confidence=0.8,
        )
        if score < 0.75:
            # Request human review but DON'T abort the run — async mode.
            d.request_escalation(
                EscalationSummary(
                    reason="analysis faithfulness below 0.75 threshold",
                    rubric_id="faithfulness-v1",
                    triggering_score=score,
                    mode="async",
                )
            )
        return analysis, score


def run_writer(fab: Fabric, *, session_id: str, analysis: str) -> None:
    """Sub-agent #3: drafts email, runs policy + tool-auth gates, sends, files CRM note.

    Models the writer's CRM retry (this is attempt #2 because the prior
    attempt failed here) via a step-level retry on the tool span.
    """
    with fab.decision(
        session_id=session_id,
        request_id="req-writer",
        attributes={"fabric.subagent": "writer"},
    ) as d:
        with d.llm_call(
            system="deal-desk-writer",
            model=MODEL,
            temperature=0.3,
            step_type="draft",
            step_id="writer.draft",
        ) as call:
            out = call_llm(
                step="draft", system="draft email", prompt=analysis, model=MODEL
            )
            call.set_usage(
                input_tokens=int(out["input_tokens"]),
                output_tokens=int(out["output_tokens"]),
                finish_reason=str(out["finish_reason"]),
            )
        email_body = str(out["text"])

        # Gate 1: data-residency policy on the outbound email.
        policy_engine = DataResidencyPolicyEngine()
        evaluation = d.evaluate_policy(
            policy_engine,
            policy_id="email.data_residency",
            input={"recipient_region": "EU", "channel": "email"},
        )
        assert evaluation.decision == "allow", "expected EU recipient to be allowed"

        # Gate 2: pre-execution tool authorization for the send_email tool.
        authorizer = AllowListToolAuthorizer(allowed={"send_email", "crm_write"})
        auth = d.authorize_tool_call(
            authorizer,
            tool_name="send_email",
            arguments=json.dumps({"to": "client@acme.example", "body": email_body}),
        )
        auth.raise_for_denied()  # no-op when allowed

        # Tool call: send the email (a side effect — external email send).
        with d.tool_call("send_email", call_id="tc-email-1") as tool:
            tool.set_kind("http")
            tool.set_arguments(json.dumps({"to": "client@acme.example"}))
            tool.set_result(json.dumps({"message_id": "msg-9981"}))
            tool.set_idempotency(idempotent=True, key="acme-email-attempt")
            email_tool_id = tool.span.get_span_context().span_id
        d.record_side_effect(
            SideEffectType.EMAIL_SEND,
            target_system="sendgrid",
            operation="messages.send",
            result_payload=json.dumps({"message_id": "msg-9981"}),
            parent_tool_call_id="tc-email-1",
            replay_behavior=ReplayBehavior.SUPPRESS,
        )

        # Tool call: file a CRM note. This is the step that failed on the
        # PRIOR attempt; we model a step-level retry (attempt #2 of the step)
        # and a transient retry on the inner call.
        with d.tool_call(
            "crm_write",
            call_id="tc-crm-1",
            step_type="act",
            step_id="writer.crm_note",
            step_attempt=2,
            step_attempt_id="crm-attempt-2",
            step_retry_reason="prior_attempt_5xx",
            step_retry_previous_attempt_id="crm-attempt-1",
        ) as tool:
            tool.set_kind("http")
            tool.set_arguments(json.dumps({"account": "ACME", "note": "email sent"}))
            tool.set_result(json.dumps({"crm_id": "note-5521"}))
            tool.set_retry(count=1, reason="server_error")
        d.record_side_effect(
            SideEffectType.API_MUTATION,
            target_system="salesforce",
            operation="notes.create",
            result_payload=json.dumps({"crm_id": "note-5521"}),
            idempotency_key="acme-crm-note-1",
            parent_tool_call_id="tc-crm-1",
            replay_behavior=ReplayBehavior.SUPPRESS,
        )
        _ = email_tool_id  # captured for completeness; CRM-note id is on the event

        d.record_replay_metadata(state_hash=_sha256(email_body))


# ---------------------------------------------------------------------------
# 4. The supervisor: opens ONE execution, dispatches the three sub-agents.
# ---------------------------------------------------------------------------


def run_supervisor(fab: Fabric) -> str:
    """Open the correlation span and run the sub-agents in sequence."""
    session_id = "sess-deal-desk-001"
    user_request = "Summarize ACME Corp risk posture (acct ACME-INTERNAL-4471) and draft a client email."
    # ONE execution correlates all three sub-agent decisions. This run is
    # attempt #2 — the retry lineage is stamped on the execution span and
    # inherited by every child decision.
    with fab.execution(
        workflow_id="deal-desk-summary",
        execution_attempt=2,
        execution_attempt_id="attempt-2",
        execution_retry_reason="crm_write_5xx_on_attempt_1",
        execution_retry_previous_attempt_id="attempt-1",
        attributes={"fabric.run.kind": "supervisor"},
    ) as execution:
        findings = run_researcher(fab, session_id=session_id, user_request=user_request)
        analysis, _score = run_analyst(fab, session_id=session_id, findings=findings)
        run_writer(fab, session_id=session_id, analysis=analysis)
        return execution.execution_id


# ---------------------------------------------------------------------------
# 5. Telemetry rendering + assertions (this is the test).
# ---------------------------------------------------------------------------


def _attr(span: ReadableSpan, key: str) -> object:
    return (span.attributes or {}).get(key)


def _events_named(span: ReadableSpan, name: str) -> list:
    return [e for e in span.events if e.name == name]


def print_audit_trail(spans: Sequence[ReadableSpan]) -> None:
    """Render the captured Fabric telemetry as a human-readable audit trail."""
    by_name: dict[str, list[ReadableSpan]] = defaultdict(list)
    for s in spans:
        by_name[s.name].append(s)

    print("\n" + "=" * 74)
    print("FABRIC AUDIT TRAIL — multi-agent supervisor")
    print("=" * 74)

    for ex in by_name.get("fabric.execution", []):
        print(f"\n[fabric.execution]  status={_attr(ex, 'fabric.execution.status')}")
        print(f"    execution_id = {_attr(ex, 'fabric.execution_id')}")
        print(f"    workflow_id  = {_attr(ex, 'fabric.workflow_id')}")
        print(
            f"    retry        = attempt {_attr(ex, 'fabric.execution.attempt')} "
            f"(id={_attr(ex, 'fabric.execution.attempt_id')}, "
            f"reason={_attr(ex, 'fabric.execution.retry.reason')}, "
            f"prev={_attr(ex, 'fabric.execution.retry.previous_attempt_id')})"
        )

    for d in by_name.get("fabric.decision", []):
        sub = _attr(d, "fabric.subagent")
        print(f"\n[fabric.decision]  sub-agent={sub}")
        print(f"    decision_id  = {_attr(d, 'fabric.decision_id')}")
        print(f"    execution_id = {_attr(d, 'fabric.execution_id')}  (inherited)")
        print(f"    attempt      = {_attr(d, 'fabric.execution.attempt')}  (inherited)")
        for e in d.events:
            attrs = dict(e.attributes or {})
            # Show the most audit-relevant attribute per event kind.
            highlight = (
                attrs.get("fabric.guardrail.phase")
                or attrs.get("fabric.retrieval.source")
                or attrs.get("fabric.memory.direction")
                or attrs.get("fabric.policy.decision")
                or attrs.get("fabric.tool.authorization.decision")
                or attrs.get("fabric.side_effect.type")
                or attrs.get("fabric.eval.dimension")
                or attrs.get("fabric.escalation.reason")
                or attrs.get("fabric.checkpoint.step_name")
                or attrs.get("fabric.replay.metadata_version")
                or ""
            )
            print(f"      - {e.name:<26} {highlight}")

    for c in by_name.get("fabric.llm_call", []) + by_name.get("fabric.tool_call", []):
        step = _attr(c, "fabric.step.type")
        name = _attr(c, "fabric.tool.name") or _attr(c, "fabric.llm.request.model")
        print(f"[{c.name}]  step.type={step}  {name}")

    print("\n" + "=" * 74)


def run_assertions(spans: Sequence[ReadableSpan], execution_id: str) -> None:
    """Assert the emitted spans/events form a correct audit trail."""
    by_name: dict[str, list[ReadableSpan]] = defaultdict(list)
    for s in spans:
        by_name[s.name].append(s)

    # -- Execution correlation span ------------------------------------
    execs = by_name["fabric.execution"]
    assert len(execs) == 1, f"expected 1 execution span, got {len(execs)}"
    ex = execs[0]
    assert _attr(ex, "fabric.execution_id") == execution_id
    assert _attr(ex, "fabric.workflow_id") == "deal-desk-summary"
    assert _attr(ex, "fabric.execution.status") == "completed"
    # Retry lineage stamped on the execution span.
    assert _attr(ex, "fabric.execution.attempt") == 2
    assert _attr(ex, "fabric.execution.attempt_id") == "attempt-2"
    assert _attr(ex, "fabric.execution.retry.reason") == "crm_write_5xx_on_attempt_1"
    assert _attr(ex, "fabric.execution.retry.previous_attempt_id") == "attempt-1"

    # -- Three child decisions, all correlated to the one execution ----
    decisions = by_name["fabric.decision"]
    assert len(decisions) == 3, f"expected 3 decision spans, got {len(decisions)}"
    sub_agents = {_attr(d, "fabric.subagent") for d in decisions}
    assert sub_agents == {"researcher", "analyst", "writer"}, sub_agents
    decision_ids = set()
    for d in decisions:
        did = _attr(d, "fabric.decision_id")
        assert did, "every decision span must carry fabric.decision_id"
        decision_ids.add(did)
        # Cross-step correlation: inherited execution + retry metadata.
        assert _attr(d, "fabric.execution_id") == execution_id, (
            "decision must inherit execution_id"
        )
        assert _attr(d, "fabric.workflow_id") == "deal-desk-summary"
        assert _attr(d, "fabric.execution.attempt") == 2, (
            "decision must inherit retry lineage"
        )
        assert _attr(d, "fabric.execution.attempt_id") == "attempt-2"
    assert len(decision_ids) == 3, (
        "each sub-agent decision must have a distinct decision_id"
    )

    # All three decisions and the execution share ONE trace (correlation).
    trace_ids = {s.context.trace_id for s in decisions} | {ex.context.trace_id}
    assert len(trace_ids) == 1, (
        f"all correlated spans must share one trace, got {trace_ids}"
    )

    researcher = next(
        d for d in decisions if _attr(d, "fabric.subagent") == "researcher"
    )
    analyst = next(d for d in decisions if _attr(d, "fabric.subagent") == "analyst")
    writer = next(d for d in decisions if _attr(d, "fabric.subagent") == "writer")

    # -- Researcher: guardrail + retrieval + memory + checkpoint + replay
    guards = _events_named(researcher, "fabric.guardrail")
    assert guards, "researcher must emit a guardrail event"
    assert guards[0].attributes["fabric.guardrail.phase"] == "input"
    retr = _events_named(researcher, "fabric.retrieval")
    assert retr and retr[0].attributes["fabric.retrieval.source"] == "rag"
    assert retr[0].attributes["fabric.retrieval.result_count"] == 3
    mem_writes = [
        e
        for e in _events_named(researcher, "fabric.memory")
        if e.attributes["fabric.memory.direction"] == "write"
    ]
    assert mem_writes and mem_writes[0].attributes["fabric.memory.kind"] == "episodic"
    assert _events_named(researcher, "fabric.checkpoint"), (
        "researcher checkpoint missing"
    )
    replay = _events_named(researcher, "fabric.replay")
    assert replay, "researcher replay metadata missing"
    assert replay[0].attributes["fabric.replay.execution_id"] == execution_id
    assert replay[0].attributes["fabric.replay.decision_id"] == _attr(
        researcher, "fabric.decision_id"
    )

    # -- Analyst: memory read + eval + escalation ----------------------
    mem_reads = [
        e
        for e in _events_named(analyst, "fabric.memory")
        if e.attributes["fabric.memory.direction"] == "read"
    ]
    assert mem_reads, "analyst must recall from memory (read direction)"
    evals = _events_named(analyst, "fabric.eval")
    assert evals and evals[0].attributes["fabric.eval.dimension"] == "faithfulness"
    esc = _events_named(analyst, "fabric.escalation")
    assert esc, "low faithfulness must trigger an escalation event"
    assert esc[0].attributes["fabric.escalation.mode"] == "async"
    assert _attr(analyst, "fabric.escalated") is True

    # -- Writer: policy allow, tool-auth allow, two side effects -------
    pol = _events_named(writer, "fabric.policy.evaluation")
    assert pol and pol[0].attributes["fabric.policy.decision"] == "allow"
    assert pol[0].attributes["fabric.policy.engine"] == "custom:data-residency"
    tool_auth = _events_named(writer, "fabric.tool.authorization")
    assert (
        tool_auth
        and tool_auth[0].attributes["fabric.tool.authorization.decision"] == "allow"
    )
    side_effects = _events_named(writer, "fabric.side_effect")
    assert len(side_effects) == 2, (
        f"writer should record 2 side effects, got {len(side_effects)}"
    )
    se_by_parent = {
        e.attributes.get("fabric.side_effect.parent_tool_call_id") for e in side_effects
    }
    assert se_by_parent == {"tc-email-1", "tc-crm-1"}, se_by_parent
    # Every side effect carries a stable side_effect_id.
    for e in side_effects:
        assert e.attributes.get("fabric.side_effect.side_effect_id"), (
            "side_effect_id missing"
        )

    # -- Child spans: step taxonomy + retry telemetry ------------------
    llm_calls = by_name["fabric.llm_call"]
    assert len(llm_calls) == 3, f"expected 3 llm_call spans, got {len(llm_calls)}"
    step_types = {_attr(c, "fabric.step.type") for c in llm_calls}
    assert step_types == {"plan", "reason", "draft"}, step_types
    # Analyst's reason call recorded a provider retry.
    reason_call = next(c for c in llm_calls if _attr(c, "fabric.step.type") == "reason")
    assert _attr(reason_call, "fabric.llm.retry.count") == 1
    assert _attr(reason_call, "fabric.llm.retry.reason") == "upstream_429"

    tool_calls = by_name["fabric.tool_call"]
    assert len(tool_calls) == 2, f"expected 2 tool_call spans, got {len(tool_calls)}"
    crm = next(c for c in tool_calls if _attr(c, "fabric.tool.name") == "crm_write")
    # The CRM step models attempt #2 with step-level retry lineage.
    assert _attr(crm, "fabric.step.attempt") == 2
    assert _attr(crm, "fabric.step.retry.reason") == "prior_attempt_5xx"
    assert _attr(crm, "fabric.step.retry.previous_attempt_id") == "crm-attempt-1"
    assert _attr(crm, "fabric.tool.retry.count") == 1


def main() -> int:
    # In-memory OTel provider so the example is self-contained.
    exporter = InMemorySpanExporter()
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    provider = install_default_provider(service_name="deal-desk-supervisor")
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    # One Fabric client per process. The keyword redactor is the only rail
    # wired here (sidecar-free); production adds Presidio/NeMo.
    fab = Fabric(
        FabricConfig(tenant_id="acme-bank", agent_id="deal-desk-supervisor"),
        guardrail_checkers=[KeywordGuardrailChecker()],
    )

    try:
        execution_id = run_supervisor(fab)
    finally:
        fab.close()

    spans = exporter.get_finished_spans()
    print_audit_trail(spans)
    run_assertions(spans, execution_id)

    using_real = os.environ.get("FABRIC_EXAMPLE_USE_REAL_LLM") == "1"
    print(
        f"\nAll assertions passed. Captured {len(spans)} spans "
        f"({'REAL LLM' if using_real else 'offline stub LLM'})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
