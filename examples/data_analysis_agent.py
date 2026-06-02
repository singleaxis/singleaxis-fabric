# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Enterprise reference example: instrumenting a Data-analysis agent with SingleAxis Fabric.

Scenario
--------
A regulated FinOps team runs an internal "Data-analysis agent". An analyst asks a
natural-language question ("What was Q3 net revenue for the EMEA region?"); the agent
retrieves the right SQL table schema, authors a SELECT, runs it against the warehouse,
asks an LLM to narrate the result, and self-grades the answer for faithfulness before
returning it. Because the warehouse holds regulated financial data, every step must
leave an immutable, hash-only audit trail: who asked, which tables were touched, the
exact SQL (as a hash), whether a write was attempted, and whether a policy or guardrail
intervened. Fabric is the emit-only telemetry substrate that produces that audit trail
as OpenTelemetry spans + events — it never sees raw PII or raw SQL, only SHA-256 hashes.

This single decision turn demonstrates the realistic Data-analysis-agent shape:
input guardrail -> policy gate -> schema retrieval -> tool authorization -> SQL tool call
-> checkpoint -> cached+streamed LLM narration -> side-effect audit -> inline eval ->
async judge enqueue -> replay metadata.

Fabric primitives / attributes demonstrated
-------------------------------------------
* fabric.execution  ...... outer correlation span (execution_id / workflow / status),
                           inherited by the decision (execution.py).
* fabric.decision   ...... the agent turn span carrying fabric.decision_id /
                           fabric.execution_id / fabric.session_id / fabric.user_id.
* decision.guard_input ... in-process GuardrailChecker rail -> fabric.guardrail event
                           (PII redaction, latency; the custom rail emits
                           policies, not Presidio entity summaries).
* decision.evaluate_policy  PolicyEngine adapter -> fabric.policy.evaluation event with a
                           normalized decision + input_hash (raw input hashed locally).
* decision.record_retrieval  fabric.retrieval event for the SQL schema lookup
                           (source=sql/kg, query_hash, result_count, source_document_ids).
* decision.authorize_tool_call  pre-execution ToolAuthorizer -> fabric.tool.authorization.
* decision.tool_call ..... child fabric.tool_call span: set_kind / set_arguments (hashed)
                           / set_result (hashed) / set_result_count / set_retry /
                           set_idempotency, plus fabric.step.type / fabric.step.id.
* decision.checkpoint .... fabric.checkpoint save point (after the SQL ran).
* decision.llm_call ...... child fabric.llm_call span with GenAI conventions +
                           set_usage / set_cache_usage (prompt cache) / set_streaming
                           (ttft + chunk_count) / set_retry.
* decision.record_side_effect  fabric.side_effect event (the query-log write) carrying a
                           side_effect_id, parent_tool_call_id, and replay_behavior.
* decision.record_eval ... inline fabric.eval faithfulness score.
* decision.queue_judge ... async fabric.judge.queued grading request via a transport.
* decision.record_replay_metadata  versioned fabric.replay envelope (checkpoint ids +
                           suppressed side-effect ids).

How to run
----------
    python3.13 -m venv /tmp/ex_data_analysis
    /tmp/ex_data_analysis/bin/pip install -e <repo>/sdk/python
    /tmp/ex_data_analysis/bin/python data_analysis_agent.py

It runs fully OFFLINE (the LLM is a deterministic stub) and exits 0 with all asserts
passing. To prove real-world behavior, set FABRIC_EXAMPLE_USE_REAL_LLM=1 and supply an
OpenAI-compatible endpoint (see ``call_llm`` below) — the committed default stays offline.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
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
    JudgeContext,
    LocalQueueTransport,
    MemoryKind,
    PolicyEngine,
    ReplayBehavior,
    RetrievalSource,
    SideEffectType,
    ToolAuthorization,
    ToolAuthorizer,
    ToolErrorCategory,
    install_default_provider,
)


# ---------------------------------------------------------------------------
# In-process stubs. In production each of these is a real sidecar / adapter:
# Presidio + NeMo for guardrails, OPA / Cedar for policy, an allow-list service
# for tool authorization. Fabric only normalizes their verdicts and emits the
# audit events — the engines themselves are pluggable.
# ---------------------------------------------------------------------------


class _PiiRedactingChecker:
    """A minimal in-process :class:`fabric.GuardrailChecker`.

    Redacts anything that looks like an email so the raw analyst identity never
    reaches the LLM. A real deployment wires Presidio / NeMo / Lakera instead;
    the emitted ``fabric.guardrail`` event is identical regardless of rail.
    """

    name = "demo_pii_redactor"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        redacted = value
        action = "allow"
        if "@" in value:
            # Crude email scrub — illustrative only.
            redacted = " ".join(
                "<EMAIL_REDACTED>" if "@" in tok else tok for tok in value.split(" ")
            )
            action = "redact"
        return CheckerVerdict(action=action, modified_value=redacted, rail="pii")

    def close(self) -> None:  # pragma: no cover - nothing to release
        pass


class _RegionScopePolicyEngine:
    """A stub :class:`fabric.PolicyEngine`: analysts may only query their own region.

    Production swaps in ``OPAAdapter`` / ``CedarAdapter`` / ``HTTPPolicyAdapter``;
    the SDK normalizes whatever verdict comes back into ``fabric.policy.evaluation``.
    """

    engine_name = "demo_region_scope"

    def evaluate(
        self, *, policy_id: str, input: dict[str, object], timeout_seconds: float
    ) -> EngineVerdict:
        requested = input.get("region")
        allowed = input.get("analyst_allowed_region")
        if requested == allowed:
            return EngineVerdict(decision="allow", policy_version="2026-05-01")
        return EngineVerdict(
            decision="deny",
            policy_version="2026-05-01",
            reason=f"analyst not scoped to region {requested!r}",
        )

    def close(self) -> None:  # pragma: no cover
        pass


class _ReadOnlyWarehouseAuthorizer:
    """A stub :class:`fabric.ToolAuthorizer`: only read-only SQL tools are allowed.

    The authorizer sees the tool name and a SHA-256 of the arguments — never the
    raw SQL. It denies anything outside the read-only allow-list, failing closed.
    """

    _ALLOW = {"warehouse.run_select", "warehouse.describe_table"}

    def authorize(
        self, *, tool_name: str, arguments_hash: str | None
    ) -> ToolAuthorization:
        if tool_name in self._ALLOW:
            return ToolAuthorization(decision="allow")
        return ToolAuthorization(
            decision="deny",
            reason=f"tool {tool_name!r} is not on the read-only allow-list",
        )


# ---------------------------------------------------------------------------
# The LLM call. Deterministic stub by default so the example is offline-runnable
# with no API key. Flip FABRIC_EXAMPLE_USE_REAL_LLM=1 to call a real provider.
# ---------------------------------------------------------------------------


def call_llm(
    *, system: str, prompt: str, model: str
) -> tuple[str, dict[str, int], list[str]]:
    """Return ``(text, usage, chunks)``.

    ``usage`` carries input/output/cache token counts; ``chunks`` is the streamed
    token sequence (so the example can record streaming telemetry). The STUB path
    is fully deterministic. The real path below builds CLEAN assistant message
    dicts — some OpenAI-compatible gateways (e.g. Fireworks) reject echoed
    refusal/annotations/audio fields, so we only ever send role+content.
    """
    if os.environ.get("FABRIC_EXAMPLE_USE_REAL_LLM") != "1":
        # ----- Deterministic offline stub -----
        text = (
            "EMEA Q3 net revenue was 42.7M USD, up 8.1% quarter-over-quarter. "
            "The growth is concentrated in the DACH sub-region."
        )
        chunks = [text[i : i + 24] for i in range(0, len(text), 24)]
        usage = {
            "input_tokens": 320,
            "output_tokens": 38,
            # Most of the prompt (the stable table schema + system prompt) is a
            # prompt-cache hit on the second turn — realistic for a data agent.
            "cache_read_tokens": 256,
            "cache_creation_tokens": 0,
        }
        return text, usage, chunks

    # ----- Real provider (OpenAI-compatible). Documented, not the default. -----
    # Wire e.g. Fireworks: base_url=https://api.fireworks.ai/inference/v1,
    # model=accounts/fireworks/models/kimi-k2p6. Build a clean message list.
    from openai import OpenAI  # noqa: PLC0415 - optional dependency, real path only

    client = OpenAI(
        base_url=os.environ["FABRIC_EXAMPLE_LLM_BASE_URL"],
        api_key=os.environ["FABRIC_EXAMPLE_LLM_API_KEY"],
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ]
    stream = client.chat.completions.create(
        model=model, messages=messages, stream=True, temperature=0.0
    )
    chunks = []
    for event in stream:
        delta = event.choices[0].delta.content if event.choices else None
        if delta:
            chunks.append(delta)
    text = "".join(chunks)
    # Token usage isn't always returned with streaming; approximate for the demo.
    usage = {
        "input_tokens": max(1, len(system + prompt) // 4),
        "output_tokens": max(1, len(text) // 4),
        "cache_read_tokens": 0,
        "cache_creation_tokens": 0,
    }
    return text, usage, chunks


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The agent turn.
# ---------------------------------------------------------------------------

WORKFLOW_ID = "data-analysis-agent"
MODEL = os.environ.get("FABRIC_EXAMPLE_MODEL", "stub-analyst-llm")
SYSTEM_PROMPT = (
    "You are a financial data analyst. Given a SQL result set, narrate the answer "
    "concisely and faithfully. Never invent figures not present in the data."
)


def run_data_analysis_turn(fab: Fabric, transport: LocalQueueTransport) -> str:
    """Run one end-to-end Data-analysis agent turn, fully instrumented."""
    analyst = "analyst-7741"
    raw_question = (
        "Hi from priya.menon@example.com — what was Q3 net revenue for the EMEA region?"
    )

    # Pluggable engines (real deployments use sidecars).
    policy_engine: PolicyEngine = _RegionScopePolicyEngine()
    tool_authorizer: ToolAuthorizer = _ReadOnlyWarehouseAuthorizer()

    # An Execution is the optional outer correlation span. Every Decision opened
    # inside inherits its execution_id/workflow_id, so a multi-turn run stitches
    # together without the host threading ids by hand.
    with fab.execution(workflow_id=WORKFLOW_ID) as execution:
        with fab.decision(
            session_id="sess-emea-rev-q3",
            request_id="req-0001",
            user_id=analyst,
            attributes={"fabric.app.region": "EMEA"},
        ) as decision:
            # 1) INPUT GUARDRAIL — scrub PII before anything else sees the text.
            safe_question = decision.guard_input(raw_question)
            assert "@example.com" not in safe_question  # email was redacted

            # 2) POLICY GATE — is this analyst scoped to the requested region?
            evaluation = decision.evaluate_policy(
                policy_engine,
                policy_id="warehouse.region_scope",
                input={"region": "EMEA", "analyst_allowed_region": "EMEA"},
            )
            if evaluation.decision != "allow":
                # Fail closed: record an escalation and abort the turn.
                decision.request_escalation(
                    EscalationSummary(
                        reason=f"region policy denied: {evaluation.reason}",
                        mode="deferred",
                    )
                )
                decision.raise_for_escalation()

            # 3) SCHEMA RETRIEVAL — look up which warehouse tables answer this.
            #    Raw query is hashed locally; only metadata lands on the span.
            decision.record_retrieval(
                RetrievalSource.SQL,
                query=safe_question,
                result_count=2,
                source_document_ids=["fact_revenue", "dim_region"],
                latency_ms=12,
            )
            # Remember the resolved schema so a later turn can recall it cheaply.
            decision.remember(
                kind=MemoryKind.SEMANTIC,
                content="fact_revenue JOIN dim_region ON region_id",
                key="schema:emea_revenue",
                tags=["warehouse", "schema"],
                ttl_seconds=3600,
            )

            # 4) AUTHORIZE + RUN THE SQL TOOL.
            sql = (
                "SELECT SUM(net_revenue) FROM fact_revenue f "
                "JOIN dim_region d ON f.region_id = d.id "
                "WHERE d.name = 'EMEA' AND f.fiscal_quarter = 'Q3'"
            )
            authz = decision.authorize_tool_call(
                tool_authorizer,
                tool_name="warehouse.run_select",
                arguments=sql,
            )
            authz.raise_for_denied()  # enforce the gate

            sql_result_json = json.dumps({"net_revenue_usd": 42_700_000, "rows": 1})
            with decision.tool_call(
                "warehouse.run_select",
                call_id="tool-sql-1",
                step_id="run_sql",
                step_type="act",
            ) as tool:
                tool.set_kind("sql")
                tool.set_arguments(sql)  # hashed -> fabric.tool.arguments_hash
                # Read-only SELECTs are safely idempotent / retryable.
                tool.set_idempotency(idempotent=True, key="emea-q3-net-rev")
                tool.set_retry(count=1, reason="warehouse 503 backoff")
                # ... the host actually executes the query here ...
                tool.set_result(sql_result_json)  # hashed -> fabric.tool.result_hash
                tool.set_result_count(1)

            # 5) CHECKPOINT — a clean rewind point now that the SQL has run.
            decision.checkpoint("after-sql", state_hash=_sha256(sql + sql_result_json))

            # 6) LLM NARRATION — cached + streamed, wrapped in an llm_call span.
            prompt = (
                f"Question: {safe_question}\nSQL result: {sql_result_json}\nAnswer:"
            )
            started = time.monotonic()
            with decision.llm_call(
                system="openai",
                model=MODEL,
                temperature=0.0,
                max_tokens=256,
                step_id="narrate",
                step_type="llm_call",
            ) as call:
                answer, usage, chunks = call_llm(
                    system=SYSTEM_PROMPT, prompt=prompt, model=MODEL
                )
                ttft_ms = (time.monotonic() - started) * 1000.0
                call.set_usage(
                    input_tokens=usage["input_tokens"],
                    output_tokens=usage["output_tokens"],
                    finish_reason="stop",
                )
                call.set_cache_usage(
                    cache_read_tokens=usage["cache_read_tokens"],
                    cache_creation_tokens=usage["cache_creation_tokens"],
                )
                call.set_streaming(ttft_ms=ttft_ms, chunk_count=len(chunks))
                call.set_retry(count=0)
                call.set_response_model(MODEL)

            # 7) SIDE EFFECT — append the answered query to the immutable query log.
            #    parent_tool_call_id links it to the SQL tool span; SUPPRESS means a
            #    replay must NOT re-run this write.
            side_effect = decision.record_side_effect(
                SideEffectType.DATABASE_WRITE,
                target_system="audit_query_log",
                operation="INSERT",
                request_payload=json.dumps(
                    {"analyst": analyst, "sql_hash": _sha256(sql)}
                ),
                idempotency_key="emea-q3-net-rev-log",
                committed=True,
                replay_behavior=ReplayBehavior.SUPPRESS,
                parent_tool_call_id="tool-sql-1",
            )

            # 8) INLINE EVAL — fast faithfulness grader on the request path.
            faithful = (
                "42.7M" in answer or "42,700,000" in answer or "42700000" in answer
            )
            decision.record_eval(
                rubric_id="answer.faithfulness.v1",
                score=1.0 if faithful else 0.0,
                dimension="faithfulness",
                evaluator_name="demo_inline_grader",
                evaluator_version="1.0",
                confidence=0.9,
            )

            # 9) ASYNC JUDGE — enqueue a richer out-of-band grading request. No
            #    content lands on the trace; the context rides the transport.
            judge_ctx = JudgeContext(
                user_input=safe_question,
                agent_response=answer,
                system_prompt=SYSTEM_PROMPT,
                retrieval_docs=("fact_revenue", "dim_region"),
            )
            decision.queue_judge(
                rubric_id="answer.quality.v2",
                dimensions=("faithfulness", "completeness"),
                context=judge_ctx,
                transport=transport,
            )

            # 10) REPLAY METADATA — versioned envelope a replay engine can consume.
            decision.record_replay_metadata(
                state_hash=_sha256(answer),
                tool_result_hashes=[_sha256(sql_result_json)],
            )

            assert decision.execution_id == execution.execution_id
            assert side_effect.parent_tool_call_id == "tool-sql-1"
            return answer


# ---------------------------------------------------------------------------
# Telemetry readout + assertions (this is the test).
# ---------------------------------------------------------------------------


def _events_by_name(span: ReadableSpan) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for event in span.events:
        grouped[event.name].append(dict(event.attributes or {}))
    return grouped


def print_summary(spans: Sequence[ReadableSpan]) -> None:
    """Print the human-readable audit trail Fabric produced."""
    print("=" * 78)
    print("FABRIC TELEMETRY — captured audit trail for the Data-analysis agent turn")
    print("=" * 78)
    for span in spans:
        attrs = dict(span.attributes or {})
        print(f"\n[span] {span.name}  (kind={span.kind.name})")
        for key in sorted(attrs):
            if key.startswith(("fabric.", "gen_ai.")):
                print(f"    {key} = {attrs[key]!r}")
        for name, events in _events_by_name(span).items():
            for ev in events:
                summary = {k: v for k, v in ev.items() if k != "fabric.schema_version"}
                print(f"    * event {name}: {summary}")


def main() -> int:
    # Self-contained OTel wiring: a real TracerProvider feeding an in-memory
    # exporter so the example can print exactly what it emitted.
    exporter = InMemorySpanExporter()
    provider = install_default_provider(
        service_name="data-analysis-agent-example", exporter=exporter
    )

    config = FabricConfig(tenant_id="acme-finance", agent_id="data-analysis-agent")
    fab = Fabric(config, guardrail_checkers=[_PiiRedactingChecker()])
    transport = LocalQueueTransport()

    answer = run_data_analysis_turn(fab, transport)
    print(f"\nAgent answer: {answer}\n")

    # Drain the BatchSpanProcessor into the exporter before reading.
    provider.force_flush()
    spans = exporter.get_finished_spans()
    print_summary(spans)

    # ---------------------------------------------------------------
    # ASSERTIONS — verify the emitted spans/events form a correct audit trail.
    # ---------------------------------------------------------------
    by_name = {s.name: s for s in spans}
    assert "fabric.execution" in by_name, "execution span missing"
    assert "fabric.decision" in by_name, "decision span missing"
    assert "fabric.tool_call" in by_name, "tool_call child span missing"
    assert "fabric.llm_call" in by_name, "llm_call child span missing"

    decision_span = by_name["fabric.decision"]
    d_attrs = dict(decision_span.attributes or {})
    # Identity attributes are stamped on the decision span.
    assert d_attrs.get("fabric.decision_id"), "decision_id not stamped"
    assert d_attrs.get("fabric.execution_id"), (
        "execution_id not inherited from execution"
    )
    assert d_attrs["fabric.session_id"] == "sess-emea-rev-q3"
    assert d_attrs["fabric.user_id"] == "analyst-7741"
    assert d_attrs["fabric.app.region"] == "EMEA"
    # The decision must be parented by the execution span.
    exec_span = by_name["fabric.execution"]
    assert decision_span.parent is not None
    assert decision_span.parent.span_id == exec_span.context.span_id
    assert (dict(exec_span.attributes or {})).get(
        "fabric.execution.status"
    ) == "completed"

    d_events = _events_by_name(decision_span)

    # Guardrail: the input rail fired and redacted an EMAIL entity.
    guard = d_events["fabric.guardrail"][0]
    assert guard["fabric.guardrail.phase"] == "input"
    assert guard["fabric.guardrail.blocked"] is False

    # Policy: an allow decision with an input hash (raw input never on the trace).
    policy = d_events["fabric.policy.evaluation"][0]
    assert policy["fabric.policy.engine"] == "demo_region_scope"
    assert policy["fabric.policy.decision"] == "allow"
    assert policy["fabric.policy.input_hash"]
    assert decision_span.attributes.get("fabric.policy_evaluation_count") == 1

    # Retrieval: the SQL schema lookup, with the source documents recorded.
    retrieval = d_events["fabric.retrieval"][0]
    assert retrieval["fabric.retrieval.source"] == "sql"
    assert retrieval["fabric.retrieval.result_count"] == 2
    assert set(retrieval["fabric.retrieval.source_document_ids"]) == {
        "fact_revenue",
        "dim_region",
    }

    # Memory: a semantic schema write was recorded.
    memory = d_events["fabric.memory"][0]
    assert memory["fabric.memory.direction"] == "write"
    assert memory["fabric.memory.kind"] == "semantic"
    assert memory["fabric.memory.key"] == "schema:emea_revenue"

    # Tool authorization: the read-only SELECT was allowed.
    tool_authz = d_events["fabric.tool.authorization"][0]
    assert tool_authz["fabric.tool.name"] == "warehouse.run_select"
    assert tool_authz["fabric.tool.authorization.decision"] == "allow"

    # Checkpoint after the SQL ran.
    checkpoint = d_events["fabric.checkpoint"][0]
    assert checkpoint["fabric.checkpoint.step_name"] == "after-sql"
    assert checkpoint["fabric.checkpoint.state_hash"]

    # Side effect: the audit-log INSERT, linked to the SQL tool call, SUPPRESS-on-replay.
    side_effect = d_events["fabric.side_effect"][0]
    assert side_effect["fabric.side_effect.type"] == "database_write"
    assert side_effect["fabric.side_effect.target_system"] == "audit_query_log"
    assert side_effect["fabric.side_effect.parent_tool_call_id"] == "tool-sql-1"
    assert side_effect["fabric.side_effect.replay_behavior"] == "suppress"
    assert side_effect["fabric.side_effect.side_effect_id"]

    # Inline eval: a faithfulness score landed on the decision span.
    eval_event = d_events["fabric.eval"][0]
    assert eval_event["fabric.eval.dimension"] == "faithfulness"
    assert eval_event["fabric.eval.score"] == 1.0

    # Async judge: queued with rubric + dimensions, no content on the trace.
    judge = d_events["fabric.judge.queued"][0]
    assert judge["fabric.judge.rubric_id"] == "answer.quality.v2"
    assert set(judge["fabric.judge.dimensions"]) == {"faithfulness", "completeness"}
    assert "fabric.judge.user_input" not in judge  # content never leaks onto the span

    # Replay envelope: carries the suppressed side-effect id and a checkpoint id.
    replay = d_events["fabric.replay"][0]
    assert replay["fabric.replay.decision_id"] == d_attrs["fabric.decision_id"]
    assert replay["fabric.replay.suppressed_side_effect_ids"] == (
        side_effect["fabric.side_effect.side_effect_id"],
    )
    assert len(replay["fabric.replay.checkpoint_ids"]) == 1

    # LLM child span: GenAI conventions + cache/streaming/retry telemetry.
    llm_span = by_name["fabric.llm_call"]
    llm_attrs = dict(llm_span.attributes or {})
    assert llm_attrs["gen_ai.system"] == "openai"
    assert llm_attrs["fabric.step.type"] == "llm_call"
    assert llm_attrs["fabric.step.id"] == "narrate"
    assert llm_attrs["gen_ai.usage.input_tokens"] == 320
    assert llm_attrs["fabric.llm.usage.cache_read_tokens"] == 256
    assert llm_attrs["gen_ai.usage.cache_read_input_tokens"] == 256
    assert "fabric.llm.streaming.ttft_ms" in llm_attrs
    assert llm_attrs["fabric.llm.streaming.chunk_count"] >= 1
    assert llm_attrs["fabric.llm.retry.count"] == 0
    assert llm_span.parent.span_id == decision_span.context.span_id

    # Tool child span: hashed args/results, kind, idempotency, retry, step taxonomy.
    tool_span = by_name["fabric.tool_call"]
    t_attrs = dict(tool_span.attributes or {})
    assert t_attrs["gen_ai.tool.name"] == "warehouse.run_select"
    assert t_attrs["fabric.tool.kind"] == "sql"
    assert t_attrs["fabric.step.type"] == "act"
    assert t_attrs["fabric.step.id"] == "run_sql"
    assert t_attrs["fabric.tool.arguments_hash"]
    assert t_attrs["fabric.tool.result_hash"]
    assert t_attrs["fabric.tool.result_count"] == 1
    assert t_attrs["fabric.tool.idempotent"] is True
    assert t_attrs["fabric.tool.retry.count"] == 1
    assert tool_span.parent.span_id == decision_span.context.span_id

    # The async judge request really did land on the transport.
    queued = transport.dequeue()
    assert queued is not None
    assert queued.rubric_id == "answer.quality.v2"
    assert queued.context.agent_response == answer

    print("\n" + "=" * 78)
    print("ALL ASSERTIONS PASSED — the audit trail is complete and correct.")
    print("=" * 78)

    fab.close()
    # ToolErrorCategory is exercised in the reference for completeness of the
    # tool-error vocabulary even though this happy-path turn did not error.
    assert ToolErrorCategory.TIMEOUT.value == "timeout"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
