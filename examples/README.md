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
| [`governed-content/`](governed-content/) | Opt-in governed capture: a model → tool → model run where content lands in a customer-controlled store and telemetry carries refs only. |
| [`offline-transcript/`](offline-transcript/) | Minimal record-and-read harness — SDK + local store only, no Node or services. |
| [`agent-orchestration/`](agent-orchestration/) | Full UAT demo: orchestrated agent (tools, shell execs, HTTP fetch, file write) traced through the real collector + audit receiver, reconstructed into a journal and rendered by a local viewer. |

Pre-0.8 examples that demonstrated removed APIs (guardrails, policy
evaluation, tool authorization, escalation, eval/judge capture) were
removed when the recorder scope became authoritative.

For the current recorder surface, start with
[`reference-agent/`](reference-agent/) and
[`sdk/python/README.md`](../sdk/python/README.md).
