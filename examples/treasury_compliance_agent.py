# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Financial / compliance agent instrumented with the SingleAxis Fabric SDK.

Enterprise scenario
-------------------
A wealth-management firm runs an autonomous "treasury assistant" that lets a
relationship manager ask the agent, in natural language, to move client money
(e.g. "wire $250,000 from the operating account to vendor Acme Corp"). Such an
agent is a textbook regulated workflow: every turn must be governed by policy
(allow / deny / warn / escalate / redact), money-moving side effects must be
gated behind human approval, and the whole thing must leave an immutable audit
trail that ties each external mutation back to the decision and the tool call
that produced it. This example models that workflow end to end and prints the
audit trail Fabric emits so an auditor can literally see it.

The run exercises TWO turns inside one ``fabric.execution``:

  Turn 1  — "What is the balance of the operating account?"  (read-only, allowed)
  Turn 2  — "Wire $250,000 to vendor Acme Corp."             (high-risk, escalated)

Fabric primitives / attributes demonstrated
-------------------------------------------
* ``fabric.execution``                — outer correlation span; decisions inside
                                        inherit ``execution_id`` / ``workflow_id``.
* ``fabric.decision`` + ``decision_id`` — per-turn governance span, lineage anchor.
* ``decision.guard_input`` (GuardrailChecker) — PII redaction before the LLM,
  emitting ``fabric.guardrail`` events (blocked, policies; entity
  summaries are a Presidio-rail feature, not emitted by this custom rail).
* ``decision.record_retrieval``       — RAG/account-lookup provenance.
* ``decision.recall`` (MemoryKind) — read of prior approval memory.
* ``decision.llm_call`` (LLMCall)     — child ``fabric.llm_call`` span with
  ``gen_ai.*`` + ``fabric.llm.*`` usage, ``fabric.step.type``.
* ``decision.evaluate_policy`` (PolicyEngine) — normalized 5-value verdict
  (allow/deny/warn/escalate/redact) emitted as ``fabric.policy.evaluation``,
  carrying ``decision_id`` and ``input_hash``.
* ``decision.authorize_tool_call`` (ToolAuthorizer) — pre-execution binary gate
  emitting ``fabric.tool.authorization``.
* ``decision.tool_call`` (ToolCall)   — child ``fabric.tool_call`` span; its
  ``call_id`` links the side effect back to the tool.
* ``decision.record_side_effect``     — approval-required money movement with
  ``parent_tool_call_id`` linkage, ``ReplayBehavior.SUPPRESS``, ``committed``.
* ``decision.request_escalation`` / ``raise_for_escalation`` (EscalationSummary)
  — human-in-the-loop pause emitting ``fabric.escalation``.
* ``decision.record_eval``            — inline grader score (``fabric.eval``).
* ``decision.checkpoint``             — replay save point (``fabric.checkpoint``).
* ``decision.record_replay_metadata`` — versioned ``fabric.replay`` envelope.

How to run
----------
    python3.13 -m venv .venv
    .venv/bin/pip install -e path/to/singleaxis-fabric/sdk/python
    .venv/bin/python treasury_compliance_agent.py

The example is OFFLINE by default: the LLM is a deterministic stub, so no API
key is needed. To prove real-world behavior against an OpenAI-compatible
provider, set ``FABRIC_EXAMPLE_USE_REAL_LLM=1`` and the env vars in
``call_llm`` below. The committed file stays offline-runnable.
"""

from __future__ import annotations

import json
import os
from typing import Any

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    CheckerVerdict,
    EngineVerdict,
    EscalationRequested,
    EscalationSummary,
    Fabric,
    FabricConfig,
    GuardrailChecker,
    MemoryKind,
    ReplayBehavior,
    RetrievalSource,
    SideEffectType,
    ToolAuthorization,
    install_default_provider,
)

# ---------------------------------------------------------------------------
# 1. In-process governance stubs.
#
# Fabric is an emit-only library: it does NOT embed a policy engine, an LLM, a
# guardrail model, or a tool authorizer. The host plugs those in. Below are
# tiny, deterministic, in-process implementations of each plug point so the
# example is fully self-contained — in production you would swap each for an
# OPA/Cedar adapter, a Presidio sidecar, a real LLM, etc.
# ---------------------------------------------------------------------------


class RegexPIIChecker:
    """A trivial input guardrail that redacts SSN-shaped strings.

    Satisfies the :class:`fabric.GuardrailChecker` protocol. A real deployment
    wires Presidio / NeMo / Lakera here; the contract is identical.
    """

    name = "regex-pii-checker"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        # Redact anything that looks like a US SSN (NNN-NN-NNNN).
        import re

        redacted, n = re.subn(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", value)
        if n:
            return CheckerVerdict(
                action="redact",
                modified_value=redacted,
                reason=f"redacted {n} SSN-shaped entity(ies)",
                rail=self.name,
            )
        return CheckerVerdict(action="allow", modified_value=value, rail=self.name)

    def close(self) -> None:  # pragma: no cover - nothing to release
        pass


# Sanity check at import time that our stub really satisfies the protocol.
assert isinstance(RegexPIIChecker(), GuardrailChecker)


class TreasuryPolicyEngine:
    """A rule-based :class:`fabric.PolicyEngine` for money movement.

    Maps a money-movement request to Fabric's 5-value verdict vocabulary:

    * read-only operations          -> ``allow``
    * a wire above the auto limit    -> ``escalate`` (needs a human)
    * a wire to an un-vetted payee   -> ``deny``
    """

    engine_name = "treasury-rules-v1"
    AUTO_APPROVE_LIMIT_USD = 10_000

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float,
    ) -> EngineVerdict:
        operation = str(input.get("operation", ""))
        amount = float(input.get("amount_usd", 0) or 0)
        payee_vetted = bool(input.get("payee_vetted", False))

        if operation == "read_balance":
            return EngineVerdict(decision="allow", policy_version="2026-06-01")
        if operation == "wire_transfer":
            if not payee_vetted:
                return EngineVerdict(
                    decision="deny",
                    policy_version="2026-06-01",
                    reason="payee is not on the vetted-counterparty allowlist",
                    evidence_ref="kb://aml/counterparty-allowlist",
                )
            if amount > self.AUTO_APPROVE_LIMIT_USD:
                return EngineVerdict(
                    decision="escalate",
                    policy_version="2026-06-01",
                    reason=(
                        f"wire of ${amount:,.0f} exceeds the "
                        f"${self.AUTO_APPROVE_LIMIT_USD:,.0f} auto-approval limit"
                    ),
                    evidence_ref="kb://treasury/dual-control-policy",
                )
            return EngineVerdict(decision="allow", policy_version="2026-06-01")
        # Unknown operation: fail closed.
        return EngineVerdict(
            decision="deny",
            policy_version="2026-06-01",
            reason=f"unknown operation {operation!r}",
        )

    def close(self) -> None:  # pragma: no cover
        pass


class AllowlistToolAuthorizer:
    """A binary pre-execution gate: only allowlisted tools may run."""

    _ALLOWED = frozenset({"core_banking.read_balance", "core_banking.wire_transfer"})

    def authorize(
        self,
        *,
        tool_name: str,
        arguments_hash: str | None,
    ) -> ToolAuthorization:
        if tool_name in self._ALLOWED:
            return ToolAuthorization(decision="allow")
        return ToolAuthorization(
            decision="deny",
            reason=f"tool {tool_name!r} is not on the agent's allowlist",
        )


# ---------------------------------------------------------------------------
# 2. The LLM call — deterministic stub by default, real provider behind a flag.
# ---------------------------------------------------------------------------

# Per-call token accounting the stub fabricates so the example's llm_call span
# carries realistic ``gen_ai.usage.*`` numbers.
STUB_MODEL = "stub-treasury-llm-1"


def call_llm(*, system_prompt: str, user_message: str) -> dict[str, Any]:
    """Return a structured "intent" the agent acts on.

    OFFLINE by default: returns a deterministic stub keyed off the user
    message, so the example runs with no API key. The return shape mimics an
    OpenAI-compatible chat completion's parsed JSON plus a usage block.

    To use a REAL OpenAI-compatible provider (e.g. Fireworks), set
    ``FABRIC_EXAMPLE_USE_REAL_LLM=1`` and export:

        FABRIC_EXAMPLE_LLM_BASE_URL  (e.g. https://api.fireworks.ai/inference/v1)
        FABRIC_EXAMPLE_LLM_API_KEY
        FABRIC_EXAMPLE_LLM_MODEL     (e.g. accounts/fireworks/models/kimi-k2p6)

    and ``pip install openai``. The real branch builds CLEAN assistant message
    dicts (only role/content) so providers that reject echoed
    refusal/annotation/audio fields accept the request.
    """
    if os.environ.get("FABRIC_EXAMPLE_USE_REAL_LLM") == "1":
        return _call_real_llm(system_prompt=system_prompt, user_message=user_message)

    # --- deterministic stub --------------------------------------------------
    text = user_message.lower()
    if "balance" in text:
        intent: dict[str, Any] = {
            "operation": "read_balance",
            "account": "operating",
        }
    else:
        # Naive entity extraction for the demo wire request.
        intent = {
            "operation": "wire_transfer",
            "amount_usd": 250_000,
            "payee": "Acme Corp",
            "from_account": "operating",
        }
    return {
        "intent": intent,
        "model": STUB_MODEL,
        "usage": {"input_tokens": 180, "output_tokens": 24},
        "finish_reason": "stop",
    }


def _call_real_llm(
    *, system_prompt: str, user_message: str
) -> dict[str, Any]:  # pragma: no cover
    """Real OpenAI-compatible provider path (only when the env flag is set)."""
    from openai import OpenAI  # imported lazily so offline runs need no openai

    client = OpenAI(
        base_url=os.environ["FABRIC_EXAMPLE_LLM_BASE_URL"],
        api_key=os.environ["FABRIC_EXAMPLE_LLM_API_KEY"],
    )
    model = os.environ["FABRIC_EXAMPLE_LLM_MODEL"]
    # Build CLEAN message dicts — never echo provider-specific fields back.
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]
    resp = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.0,
        response_format={"type": "json_object"},
    )
    content = resp.choices[0].message.content or "{}"
    intent = json.loads(content)
    usage = resp.usage
    return {
        "intent": intent,
        "model": resp.model,
        "usage": {
            "input_tokens": getattr(usage, "prompt_tokens", 0),
            "output_tokens": getattr(usage, "completion_tokens", 0),
        },
        "finish_reason": resp.choices[0].finish_reason or "stop",
    }


SYSTEM_PROMPT = (
    "You are a treasury assistant. Extract the user's banking intent as JSON "
    "with keys operation (read_balance|wire_transfer), amount_usd, payee, "
    "from_account. Output JSON only."
)


# ---------------------------------------------------------------------------
# 3. The instrumented agent turns.
# ---------------------------------------------------------------------------


def run_read_turn(
    fab: Fabric, policy: TreasuryPolicyEngine, authorizer: AllowlistToolAuthorizer
) -> str:
    """Turn 1: a read-only balance lookup. Policy allows; tool runs; no money moves."""
    with fab.decision(
        session_id="sess-rm-7781",
        request_id="req-001",
        user_id="rm-employee-3140",
        decision_id="dec-balance-0001",
        attributes={"fabric.business.channel": "advisor-portal"},
    ) as decision:
        # 3a. Guard the raw input (redacts PII before it reaches the LLM).
        raw = "What is the balance of the operating account? My SSN is 123-45-6789."
        safe_input = decision.guard_input(raw)
        # The raw SSN must never reach the LLM: the redactor replaced it.
        assert "123-45-6789" not in safe_input
        assert "[REDACTED_SSN]" in safe_input

        # 3b. Pull account context (provenance for the audit graph).
        decision.record_retrieval(
            RetrievalSource.SQL,
            query="account_metadata:operating",
            result_count=1,
            source_document_ids=["acct:operating"],
            latency_ms=4,
        )

        # 3c. Ask the LLM for the structured intent, wrapped in a child span.
        with decision.llm_call(
            system="stub", model=STUB_MODEL, temperature=0.0, step_type="plan"
        ) as call:
            result = call_llm(system_prompt=SYSTEM_PROMPT, user_message=safe_input)
            call.set_usage(
                input_tokens=result["usage"]["input_tokens"],
                output_tokens=result["usage"]["output_tokens"],
                finish_reason=result["finish_reason"],
            )
            call.set_response_model(result["model"])
        intent = result["intent"]

        # 3d. Evaluate policy. A read is allowed.
        evaluation = decision.evaluate_policy(
            policy,
            policy_id="treasury.money-movement",
            input={
                "operation": intent["operation"],
                "amount_usd": 0,
                "payee_vetted": True,
            },
        )
        assert evaluation.decision == "allow"

        # 3e. Authorize + run the read tool. A read is not a side effect.
        auth = decision.authorize_tool_call(
            authorizer,
            tool_name="core_banking.read_balance",
            arguments={"account": "operating"}.__repr__(),
        )
        auth.raise_for_denied()
        with decision.tool_call(
            "core_banking.read_balance", call_id="tc-read-1"
        ) as tool:
            tool.set_kind("retrieval")
            tool.set_result_count(1)
            tool.set_result(json.dumps({"balance_usd": 4_812_500}))

        # 3f. Inline grader + checkpoint for completeness.
        decision.record_eval(
            rubric_id="answer.groundedness",
            score=1.0,
            dimension="faithfulness",
            evaluator_name="inline:exact-account-match",
        )
        decision.checkpoint("after-read", state_hash="a" * 64)
        return "Operating account balance is $4,812,500."


def run_wire_turn(
    fab: Fabric, policy: TreasuryPolicyEngine, authorizer: AllowlistToolAuthorizer
) -> EscalationSummary:
    """Turn 2: a high-value wire. Policy escalates; the side effect is recorded
    as approval-required + uncommitted, and the decision pauses for a human.
    """
    summary: EscalationSummary | None = None
    try:
        with fab.decision(
            session_id="sess-rm-7781",
            request_id="req-002",
            user_id="rm-employee-3140",
            decision_id="dec-wire-0002",
            attributes={"fabric.business.channel": "advisor-portal"},
        ) as decision:
            safe_input = decision.guard_input(
                "Wire $250,000 from operating to vendor Acme Corp."
            )

            # Recall whether this payee was approved on a prior turn (memory read).
            decision.recall(
                kind=MemoryKind.SEMANTIC,
                key="payee:acme-corp:vetted",
                content="true",
                source="counterparty-store",
            )

            with decision.llm_call(
                system="stub", model=STUB_MODEL, temperature=0.0, step_type="plan"
            ) as call:
                result = call_llm(system_prompt=SYSTEM_PROMPT, user_message=safe_input)
                call.set_usage(
                    input_tokens=result["usage"]["input_tokens"],
                    output_tokens=result["usage"]["output_tokens"],
                    finish_reason=result["finish_reason"],
                )
            intent = result["intent"]

            # Policy: a vetted payee above the auto-approve limit -> escalate.
            evaluation = decision.evaluate_policy(
                policy,
                policy_id="treasury.money-movement",
                input={
                    "operation": intent["operation"],
                    "amount_usd": intent["amount_usd"],
                    "payee_vetted": True,
                },
            )
            assert evaluation.decision == "escalate", evaluation.decision

            # The tool itself is allowlisted, but because policy escalated we do
            # NOT commit the wire — we record it as an approval-required,
            # uncommitted side effect linked to the tool call that produced it.
            auth = decision.authorize_tool_call(
                authorizer,
                tool_name="core_banking.wire_transfer",
                arguments=json.dumps(
                    {"amount": intent["amount_usd"], "payee": intent["payee"]}
                ),
            )
            auth.raise_for_denied()

            wire_call_id = "tc-wire-1"
            with decision.tool_call(
                "core_banking.wire_transfer", call_id=wire_call_id
            ) as tool:
                tool.set_kind("api_mutation")
                tool.set_arguments(
                    json.dumps(
                        {"amount": intent["amount_usd"], "payee": intent["payee"]}
                    )
                )
                tool.set_idempotency(idempotent=True, key="wire-req-002")
                # The side effect is recorded as PENDING APPROVAL: not committed,
                # parent_tool_call_id links it back to this tool span, and
                # SUPPRESS means a replay must never re-execute the money move.
                decision.record_side_effect(
                    SideEffectType.PAYMENT,
                    target_system="core-banking",
                    operation="wire_transfer",
                    request_payload=json.dumps(
                        {"amount_usd": intent["amount_usd"], "payee": intent["payee"]}
                    ),
                    idempotency_key="wire-req-002",
                    approval_required=True,
                    committed=False,  # held pending human approval
                    rollback_supported=False,
                    replay_behavior=ReplayBehavior.SUPPRESS,
                    parent_tool_call_id=wire_call_id,
                )

            # Record the score that triggered the escalation, then a replay
            # envelope, then request the human review and pause the turn.
            decision.record_eval(
                rubric_id="risk.money-movement",
                score=0.92,
                dimension="risk",
                evaluator_name="inline:treasury-risk",
            )
            decision.record_replay_metadata(state_hash="b" * 64)

            summary = EscalationSummary(
                reason=evaluation.reason or "high-value wire requires dual control",
                rubric_id="risk.money-movement",
                triggering_score=0.92,
                mode="deferred",
            )
            decision.request_escalation(summary)
            decision.raise_for_escalation()  # raises EscalationRequested -> pause
    except EscalationRequested as exc:
        # The host catches the pause signal and hands the payload to whatever
        # human-review queue it runs. The decision span already recorded it.
        summary = exc.summary
    assert summary is not None
    return summary


# ---------------------------------------------------------------------------
# 4. Telemetry readout + assertions (this is the test).
# ---------------------------------------------------------------------------


def _events(span: ReadableSpan, name: str) -> list[Any]:
    return [e for e in span.events if e.name == name]


def print_audit_trail(spans: list[ReadableSpan]) -> None:
    """Print the captured Fabric spans/events as a human-readable audit trail."""
    print("\n" + "=" * 74)
    print("CAPTURED FABRIC TELEMETRY (audit trail)")
    print("=" * 74)
    for span in spans:
        attrs = dict(span.attributes or {})
        print(f"\n[{span.name}]  status={span.status.status_code.name}")
        for key in (
            "fabric.execution_id",
            "fabric.workflow_id",
            "fabric.decision_id",
            "fabric.tenant_id",
            "fabric.agent_id",
            "fabric.step.type",
            "fabric.execution.status",
            "fabric.blocked",
            "fabric.escalated",
            "gen_ai.usage.input_tokens",
            "gen_ai.usage.output_tokens",
        ):
            if key in attrs:
                print(f"    {key} = {attrs[key]}")
        for event in span.events:
            ev = dict(event.attributes or {})
            # Show the most audit-relevant attribute per event type.
            highlight = (
                ev.get("fabric.policy.decision")
                or ev.get("fabric.side_effect.operation")
                or ev.get("fabric.escalation.reason")
                or ev.get("fabric.guardrail.phase")
                or ev.get("fabric.tool.authorization.decision")
                or ev.get("fabric.retrieval.source")
                or ev.get("fabric.memory.direction")
                or ev.get("fabric.eval.dimension")
                or ev.get("fabric.checkpoint.step_name")
                or ev.get("fabric.replay.metadata_version", "")
            )
            extra = ""
            if event.name == "fabric.side_effect":
                extra = (
                    f"  approval_required={ev.get('fabric.side_effect.approval_required')}"
                    f" committed={ev.get('fabric.side_effect.committed')}"
                    f" parent_tool_call_id={ev.get('fabric.side_effect.parent_tool_call_id')}"
                )
            if event.name == "fabric.policy.evaluation":
                extra = f"  reason={ev.get('fabric.policy.reason')!r}"
            print(f"      - event {event.name}: {highlight}{extra}")


def run_assertions(spans: list[ReadableSpan]) -> None:
    """Assert the emitted spans/events carry the expected audit attributes."""
    by_name: dict[str, list[ReadableSpan]] = {}
    for s in spans:
        by_name.setdefault(s.name, []).append(s)

    # -- one execution span wrapping the run --------------------------------
    execs = by_name["fabric.execution"]
    assert len(execs) == 1, f"expected 1 execution span, got {len(execs)}"
    exec_span = execs[0]
    exec_attrs = dict(exec_span.attributes or {})
    assert exec_attrs["fabric.execution.status"] == "completed"
    execution_id = exec_attrs["fabric.execution_id"]
    workflow_id = exec_attrs["fabric.workflow_id"]

    # -- two decision spans, each carrying its decision_id ------------------
    decisions = by_name["fabric.decision"]
    assert len(decisions) == 2, f"expected 2 decisions, got {len(decisions)}"
    decision_ids = {dict(d.attributes or {})["fabric.decision_id"] for d in decisions}
    assert decision_ids == {"dec-balance-0001", "dec-wire-0002"}, decision_ids
    # Decisions inherit the execution lineage from the enclosing execution.
    for d in decisions:
        da = dict(d.attributes or {})
        assert da["fabric.execution_id"] == execution_id, (
            "decision did not inherit execution_id"
        )
        assert da["fabric.workflow_id"] == workflow_id, (
            "decision did not inherit workflow_id"
        )

    read = next(
        d
        for d in decisions
        if dict(d.attributes or {})["fabric.decision_id"] == "dec-balance-0001"
    )
    wire = next(
        d
        for d in decisions
        if dict(d.attributes or {})["fabric.decision_id"] == "dec-wire-0002"
    )
    read_attrs = dict(read.attributes or {})
    wire_attrs = dict(wire.attributes or {})

    # -- guardrail redaction fired on input ---------------------------------
    g = _events(read, "fabric.guardrail")
    assert g, "expected a guardrail event on the read turn"
    g_attrs = dict(g[0].attributes or {})
    assert g_attrs["fabric.guardrail.phase"] == "input"
    assert g_attrs["fabric.guardrail.blocked"] is False
    # Our extra GuardrailChecker fired (the chain records non-Presidio rails
    # under ``policies``; entity summaries are a Presidio-rail concept). The
    # SSN-shaped string must have been picked up and redacted.
    assert "fabric.guardrail.policies" in g_attrs, g_attrs
    assert any(
        "regex-pii-checker" in p for p in g_attrs["fabric.guardrail.policies"]
    ), g_attrs

    # -- read turn: policy ALLOW, no side effects ---------------------------
    rp = _events(read, "fabric.policy.evaluation")
    assert len(rp) == 1
    rp_attrs = dict(rp[0].attributes or {})
    assert rp_attrs["fabric.policy.decision"] == "allow"
    assert rp_attrs["fabric.policy.engine"] == "treasury-rules-v1"
    assert "fabric.policy.input_hash" in rp_attrs  # raw input never on the trace
    assert not _events(read, "fabric.side_effect"), (
        "a read must not record a side effect"
    )
    assert read_attrs.get("fabric.escalated") is None
    # tool authorization allowed the read
    ra = _events(read, "fabric.tool.authorization")
    assert (
        ra
        and dict(ra[0].attributes or {})["fabric.tool.authorization.decision"]
        == "allow"
    )

    # -- wire turn: policy ESCALATE -----------------------------------------
    wp = _events(wire, "fabric.policy.evaluation")
    assert len(wp) == 1
    wp_attrs = dict(wp[0].attributes or {})
    assert wp_attrs["fabric.policy.decision"] == "escalate", wp_attrs[
        "fabric.policy.decision"
    ]
    assert wp_attrs["fabric.policy.reason"], "an escalate verdict must carry a reason"
    # the policy event is anchored to the decision lineage (decision_id) via
    # the PolicyEvaluation it normalized — verify the input was hashed.
    assert len(wp_attrs["fabric.policy.input_hash"]) == 64

    # -- wire turn: approval-required, uncommitted side effect linked to tool
    se = _events(wire, "fabric.side_effect")
    assert len(se) == 1, "expected exactly one money-movement side effect"
    se_attrs = dict(se[0].attributes or {})
    assert se_attrs["fabric.side_effect.type"] == "payment"
    assert se_attrs["fabric.side_effect.approval_required"] is True
    assert se_attrs["fabric.side_effect.committed"] is False, (
        "money must NOT be committed before approval"
    )
    assert se_attrs["fabric.side_effect.replay_behavior"] == "suppress"
    assert se_attrs["fabric.side_effect.parent_tool_call_id"] == "tc-wire-1", (
        "side effect not linked to tool call"
    )
    assert "fabric.side_effect.idempotency_key" in se_attrs
    # the linked tool span must actually exist with that call id
    tool_spans = by_name["fabric.tool_call"]
    wire_tool = [
        t
        for t in tool_spans
        if dict(t.attributes or {}).get("fabric.tool.call.id") == "tc-wire-1"
    ]
    assert wire_tool, "no fabric.tool_call span carries the linked call id tc-wire-1"

    # -- wire turn: escalation recorded + span tagged -----------------------
    esc = _events(wire, "fabric.escalation")
    assert len(esc) == 1
    esc_attrs = dict(esc[0].attributes or {})
    assert esc_attrs["fabric.escalation.mode"] == "deferred"
    assert esc_attrs["fabric.escalation.reason"]
    assert wire_attrs["fabric.escalated"] is True
    assert wire.status.status_code.name == "ERROR"  # escalation_requested status

    # -- memory read recorded on the wire turn ------------------------------
    mem = _events(wire, "fabric.memory")
    assert any(
        dict(m.attributes or {})["fabric.memory.direction"] == "read" for m in mem
    )

    # -- replay envelope on the wire turn carries the decision_id -----------
    replay = _events(wire, "fabric.replay")
    assert len(replay) == 1
    replay_attrs = dict(replay[0].attributes or {})
    assert replay_attrs["fabric.replay.decision_id"] == "dec-wire-0002"
    assert replay_attrs["fabric.replay.execution_id"] == execution_id
    # the suppressed money-move id must be carried so a replay never re-fires it
    assert "fabric.replay.suppressed_side_effect_ids" in replay_attrs

    # -- llm child spans carry usage + step taxonomy ------------------------
    llm = by_name["fabric.llm_call"]
    assert len(llm) == 2
    for span in llm:
        la = dict(span.attributes or {})
        assert la["fabric.step.type"] == "plan"
        assert la["gen_ai.usage.input_tokens"] >= 0
        assert la["fabric.llm.request.model"] == STUB_MODEL

    # -- inline evals captured ----------------------------------------------
    assert _events(read, "fabric.eval"), "read turn eval missing"
    assert _events(wire, "fabric.eval"), "wire turn eval missing"

    print("\nAll assertions passed.")


def main() -> None:
    # Install a self-contained OTel provider that captures spans in memory.
    exporter = InMemorySpanExporter()
    provider = install_default_provider(service_name="treasury-assistant")
    # SimpleSpanProcessor exports synchronously on span end — ideal for a
    # self-contained example that inspects spans right after the run.
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    config = FabricConfig(
        tenant_id="acme-wealth",
        agent_id="treasury-assistant",
        workflow_id="wf-treasury-ops",
    )
    fab = Fabric(config, guardrail_checkers=[RegexPIIChecker()])
    policy = TreasuryPolicyEngine()
    authorizer = AllowlistToolAuthorizer()

    # One execution correlates both turns; decisions inherit its ids.
    with fab.execution(
        execution_id="exec-treasury-9001", workflow_id="wf-treasury-ops"
    ):
        read_answer = run_read_turn(fab, policy, authorizer)
        escalation = run_wire_turn(fab, policy, authorizer)

    fab.close()
    print(f"Turn 1 answer : {read_answer}")
    print(
        f"Turn 2 paused : escalation requested -> {escalation.reason!r} (mode={escalation.mode})"
    )

    spans = list(exporter.get_finished_spans())
    print_audit_trail(spans)
    run_assertions(spans)


if __name__ == "__main__":
    main()
