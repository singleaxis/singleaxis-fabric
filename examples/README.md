<!-- Copyright 2026 AI5Labs Research OPC Private Limited -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SingleAxis Fabric — examples

Fabric is the passive, customer-controlled AI recorder:

```text
CAPTURE -> PROTECT -> DELIVER
```

The SDK instruments your agent and emits OpenTelemetry spans; the Fabric
Node protects the record with a default-deny field allowlist and delivers
it to a destination you choose. The recorder never blocks, alters, or
delays the monitored system — there are no judges, guardrails, policy
engines, or management services in this stack.

## Recorder v1 examples

| Example | What it shows |
| --- | --- |
| [`reference-agent/`](reference-agent/) | The primary deliverable example — a minimal agentic workflow on the recorder SDK: `fabric.decision`, `record_retrieval`, `llm_call`, `tool_call`, `remember`, `record_side_effect`, `checkpoint`. Runs fully offline. |
| [`kind-quickstart/`](kind-quickstart/) | 10-minute kind install of Fabric Node (`shadow-dev` profile) plus an instrumented agent exporting OTLP to it. |
| [`harness-smoke/`](harness-smoke/) | Smoke against the Docker Compose evaluation harness in [`deploy/compose`](../deploy/compose): `make up`, `make smoke`, then check the controlled sink's `/count`. |
| [`e2e-smoke/`](e2e-smoke/) | Live OTLP span-landing flow paired with the `e2e.yml` workflow's kind smoke job. |

## Legacy pre-0.8 examples — not part of recorder v1

The top-level `*_agent.py` and `llm_guardrail_judge_demo.py` files were
written against the pre-0.8 SDK. They demonstrate APIs that were removed
in `singleaxis-fabric` 0.8 — guardrails, policy evaluation, tool
authorization, escalation, and eval/judge capture — and **do not run**
against the recorder SDK. They are kept for historical reference only;
each file carries a `LEGACY EXAMPLE` banner.

| File | Scenario it sketched |
| --- | --- |
| `llm_guardrail_judge_demo.py` | Privacy rail → LLM → asynchronous judge flow |
| `customer_support_agent.py` | Refund agent with guarded intake and human escalation |
| `rag_knowledge_assistant.py` | Grounded Q&A over multiple sources with semantic memory |
| `coding_swe_agent.py` | SWE agent plan→act→observe loop |
| `treasury_compliance_agent.py` | Wire-transfer approval with audit lineage |
| `data_analysis_agent.py` | NL→SQL analyst with cached/streamed LLM telemetry |
| `multi_agent_supervisor.py` | Supervisor correlating several sub-agent decisions |
| `human_in_the_loop_approval.py` | High-value action paused for a human verdict |
| `content_governance_agent.py` | Content moderation + GDPR right-to-erasure |

For the current recorder surface, start with
[`reference-agent/`](reference-agent/) and
[`sdk/python/README.md`](../sdk/python/README.md).
