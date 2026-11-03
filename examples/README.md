<!-- Copyright 2026 AI5Labs Research OPC Private Limited -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SingleAxis Fabric — examples

Fabric is the passive, customer-controlled AI recorder:

```text
CAPTURE -> PROTECT -> DELIVER
```

The SDK instruments your agent and emits OpenTelemetry spans; the Fabric
Node protects the record with a default-deny field allowlist and delivers
it to a destination you choose. Recording is passive: it does not authorize
or alter agent actions, and instrumentation and export have measurable
overhead.

The current direction is reconstructing everything an agent did in a run
([spec 056](../specs/056-agent-action-reconstruction.md)): model decisions,
tool calls, the commands and effects they caused, and host-sensor evidence.
[`agent-orchestration/`](agent-orchestration/) is the closest demo of that
action-reconstruction view today.

## Recorder v1 examples

| Example | What it shows |
| --- | --- |
| [`wire-capture/`](wire-capture/) | Start here: framework-agnostic LLM wire capture (specs 047/048): a plain httpx ReAct loop against a fake OpenAI-compatible model, exact bytes in a local store, digest-only spans, then `python -m fabric.reconstruct` returning a per-scope `complete_for_declared_scope` verdict (`complete_for_observed_scopes` for the run). Runs fully offline. |
| [`reference-agent/`](reference-agent/) | A minimal agentic workflow on the explicit recorder APIs: `fabric.decision`, `record_retrieval`, `llm_call`, `tool_call`, `remember`, `record_side_effect`, `checkpoint`. Runs fully offline. |
| [`kind-quickstart/`](kind-quickstart/) | 10-minute kind install of Fabric Node (`shadow-dev` profile) plus an instrumented agent exporting OTLP to it. |
| [`harness-smoke/`](harness-smoke/) | Smoke against the local Compose harness in [`deploy/compose`](../deploy/compose): `make up`, `make smoke`, then check the controlled sink's `/count`. |
| [`governed-content/`](governed-content/) | Opt-in governed capture: a model → tool → model run where content lands in a customer-controlled store and telemetry carries refs only. |
| [`offline-transcript/`](offline-transcript/) | Minimal record-and-read harness — SDK + local store only, no Node or services. |
| [`agent-orchestration/`](agent-orchestration/) | Action-reconstruction demo (spec 056 direction): an offline scripted-model run with real local tools and file writes, an agent-emitted audit-format shim, Fabric Node, a per-run journal and a local viewer that shows what the agent did. It is not an independent host audit or a production-completeness proof. |
| [`redaction-service/`](redaction-service/) | A stdlib-only reference of the customer-run redaction service ([`contracts/redaction/v1`](../contracts/redaction/v1/README.md)) that performs `redact` / `masked_only` for the recorder over a Unix socket or loopback port, with Compose and Kubernetes sidecar snippets. Its sample rule masks an illustrative marker pattern; it is an example of the interface, not a detector, and not part of the recorder release. |
| [`enterprise/`](enterprise/) | A shared `fabric.deployment-policy/v1` fixture for the `local` profile (`policy.local.json`), used by the SDK and contract tests and as a starting point for your own policy. |

For the current recorder surface, start with
[`wire-capture/`](wire-capture/) and
[`sdk/python/README.md`](../sdk/python/README.md); see
[`reference-agent/`](reference-agent/) for the explicit APIs.
