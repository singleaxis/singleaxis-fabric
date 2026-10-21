<!-- Copyright 2026 AI5Labs Research OPC Private Limited -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SingleAxis Fabric — examples

Fabric is the passive, customer-controlled AI recorder:

```text
CAPTURE -> PROTECT -> DELIVER
```

The SDK instruments your agent and emits OpenTelemetry spans; the Fabric
Node protects the record with a default-deny field allowlist and delivers
it to a destination you choose. Recording does not authorize or alter agent
actions; instrumentation and export have measurable overhead. There are no
judges, guardrails, policy engines, or management services in this stack.

## Recorder v1 examples

| Example | What it shows |
| --- | --- |
| [`reference-agent/`](reference-agent/) | The primary deliverable example — a minimal agentic workflow on the recorder SDK: `fabric.decision`, `record_retrieval`, `llm_call`, `tool_call`, `remember`, `record_side_effect`, `checkpoint`. Runs fully offline. |
| [`kind-quickstart/`](kind-quickstart/) | 10-minute kind install of Fabric Node (`shadow-dev` profile) plus an instrumented agent exporting OTLP to it. |
| [`harness-smoke/`](harness-smoke/) | Smoke against the Docker Compose evaluation harness in [`deploy/compose`](../deploy/compose): `make up`, `make smoke`, then check the controlled sink's `/count`. |
| [`governed-content/`](governed-content/) | Opt-in governed capture: a model → tool → model run where content lands in a customer-controlled store and telemetry carries refs only. |
| [`offline-transcript/`](offline-transcript/) | Minimal record-and-read harness — SDK + local store only, no Node or services. |
| [`agent-orchestration/`](agent-orchestration/) | Offline scripted-model demo with real local tools and file writes, an agent-emitted audit-format shim, Fabric Node, a per-run journal and a local viewer. It is not an independent host audit or a production-completeness proof. |
| [`wire-capture/`](wire-capture/) | Framework-agnostic LLM wire capture (specs 047/048): a plain httpx ReAct loop against a fake OpenAI-compatible model, exact bytes in a local store, digest-only spans, then `python -m fabric.reconstruct` returning a per-scope `complete_for_declared_scope` verdict (`complete_for_observed_scopes` for the run). Runs fully offline. |
| [`redaction-service/`](redaction-service/) | A stdlib-only reference of the customer-run redaction service ([`contracts/redaction/v1`](../contracts/redaction/v1/README.md)) that performs `redact` / `masked_only` for the recorder over a Unix socket or loopback port, with Compose and Kubernetes sidecar snippets. An example, not a PII detector and not part of the recorder release. |

Pre-0.8 examples that demonstrated removed APIs (guardrails, policy
evaluation, tool authorization, escalation, eval/judge capture) were
removed when the recorder scope became authoritative.

For the current recorder surface, start with
[`reference-agent/`](reference-agent/) and
[`sdk/python/README.md`](../sdk/python/README.md).
