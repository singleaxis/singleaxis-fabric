<!-- Copyright 2026 AI5Labs Research OPC Private Limited -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SingleAxis Fabric — enterprise agent examples

Eight runnable, self-contained examples that show how to instrument a real
enterprise AI agent with the [SingleAxis Fabric Python SDK](../sdk/python).
Each one models a workflow teams actually build — customer support, RAG,
a coding agent, finance/compliance, data analysis, multi-agent
orchestration, human-in-the-loop approval, and content governance — and
records the decision, tool, memory, policy, side-effect, evaluation, and
replay evidence as OpenTelemetry spans/events.

Fabric is **emit-only**: it never runs your model, KB, policy engine, or
side effects. Your agent does that; Fabric records the hash-only,
allow-listed audit trail so an auditor (or the commercial Decision Graph)
can reconstruct exactly what happened — without raw PII ever landing on
the trace stream.

## Run any example

Each file runs **fully offline** — a deterministic stub LLM, an in-process
guardrail rail, no API key, no sidecar, no network. It prints the captured
audit trail and `assert`s that the emitted telemetry is correct (the
asserts *are* the test).

```bash
python3.13 -m venv .venv
.venv/bin/pip install -e ../sdk/python      # or: pip install singleaxis-fabric
.venv/bin/python customer_support_agent.py
```

Every example has a clearly commented hook for swapping in a real
OpenAI-compatible provider; the committed files stay offline-runnable so
they double as deterministic tests.

## The examples

| Example | Scenario | Headline primitives |
| --- | --- | --- |
| [`customer_support_agent.py`](customer_support_agent.py) | Refund agent: PII-guarded intake → KB retrieval → policy-gated refund → human escalation | guardrails, retrieval, policy, side-effect, escalation, judge |
| [`rag_knowledge_assistant.py`](rag_knowledge_assistant.py) | Grounded Q&A over multiple sources with semantic memory | retrieval (multi-source), memory read/write, inline eval, replay |
| [`coding_swe_agent.py`](coding_swe_agent.py) | SWE agent plan→act→observe loop with a flaky test run | step taxonomy, step-level retry, tool error categories |
| [`treasury_compliance_agent.py`](treasury_compliance_agent.py) | Wire-transfer approval with audit lineage | decision_id lineage, policy, tool authorization, approval side-effects |
| [`data_analysis_agent.py`](data_analysis_agent.py) | NL→SQL analyst with cached/streamed LLM | llm cache + streaming telemetry, checkpoints, eval |
| [`multi_agent_supervisor.py`](multi_agent_supervisor.py) | Supervisor correlating several sub-agent decisions | `fabric.execution` span, execution attempt/retry, cross-decision correlation |
| [`human_in_the_loop_approval.py`](human_in_the_loop_approval.py) | High-value action paused for a human verdict | deferred escalation, side-effect suppression, replay metadata, propagation |
| [`content_governance_agent.py`](content_governance_agent.py) | Content moderation + GDPR right-to-erasure | content-ref (off-trace payloads), memory erase/invalidate, hard block, policy deny/warn/redact, sync escalation |

## Primitive coverage

Together the examples exercise the full Fabric capture surface. Use this
as a map to the primitive you want to learn:

| Primitive | Where to see it |
| --- | --- |
| `fabric.decision` + `fabric.decision_id` | all |
| `fabric.execution` span + status | `multi_agent_supervisor`, `human_in_the_loop_approval` |
| execution `attempt_id` / `attempt` / `retry.*` | `multi_agent_supervisor` |
| `fabric.step.type` / `step.id` / step retry | `coding_swe_agent` |
| `fabric.llm_call` (usage, cache, streaming, retry) | `data_analysis_agent`, `customer_support_agent` |
| `fabric.tool_call` (idempotency, error category, retry) | `coding_swe_agent`, `customer_support_agent` |
| guardrail event + `record_block` / `raise_for_block` | `customer_support_agent`, `content_governance_agent` |
| `fabric.retrieval` (hashed query) | `rag_knowledge_assistant`, `customer_support_agent` |
| memory read / write / **erase** / **invalidate** | `rag_knowledge_assistant`, `content_governance_agent` |
| `fabric.policy.evaluation` — allow / deny / warn / escalate / redact | `treasury_compliance_agent`, `content_governance_agent` |
| `fabric.tool.authorization` | `customer_support_agent`, `treasury_compliance_agent` |
| `fabric.side_effect` + `side_effect_id` + `parent_tool_call_id` | `treasury_compliance_agent`, `multi_agent_supervisor` |
| `fabric.checkpoint` | `data_analysis_agent` |
| `fabric.eval` + `fabric.judge.queued` | `customer_support_agent`, `rag_knowledge_assistant` |
| escalation — sync / async / deferred | `content_governance_agent` / `multi_agent_supervisor` / `human_in_the_loop_approval` |
| `fabric.replay` metadata envelope | `human_in_the_loop_approval`, `rag_knowledge_assistant` |
| `content_ref` (off-trace payload pointers) | `content_governance_agent` |
| `tracestate` propagation (`inject_decision` / `extract`) | `human_in_the_loop_approval`, `customer_support_agent` |

## The OSS ↔ commercial boundary

These examples use only the open-source emit substrate. Reconstruction,
replay orchestration, the managed judge fleet, durable escalation /
signed-verdict resume, and Decision Graph materialization are commercial —
see [`specs/012`](../specs/012-oss-commercialization-strategy.md). The OSS
SDK produces honest, canonical telemetry; the commercial layer turns it
into operational intelligence.
