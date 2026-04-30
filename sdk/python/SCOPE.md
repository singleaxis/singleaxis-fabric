# singleaxis-fabric SDK — scope

What the SDK does, what it doesn't, and why. Read this before
filing a "but I expected …" issue.

## What this SDK does

- **Wraps an agent turn** in `Decision`, opening one OpenTelemetry
  span (`fabric.decision`) tagged with tenant/agent/session/request
  /user identity.
- **Routes input and output through a guardrail chain** if you wire
  Presidio + NeMo sidecars. Calls `decision.guard_input(...)` and
  `decision.guard_output_final(...)` are fail-loud — if no rails are
  wired, they raise `GuardrailNotConfiguredError` rather than
  silently passing PII through.
- **Records retrievals and memory writes** — `decision.record_retrieval`
  and `decision.remember` emit span events with content hashes (raw
  text never enters the span). Your retrieval/memory store is the
  source of truth; the SDK records the metadata.
- **Provides an escalation primitive** — `decision.request_escalation`
  raises `EscalationRequested` with a typed payload your orchestrator
  catches (LangGraph `interrupt()`, MAF `request_info`, CrewAI
  `human_feedback`, or your own pause).
- **Ships orchestrator adapters** under `fabric.adapters.*` — gated
  behind extras so the core install stays framework-neutral.
- **Emits standardised attributes** — `fabric.tenant_id`,
  `fabric.agent_id`, `fabric.profile`, etc. From v0.2.0, child spans
  for LLM calls and tool calls write standard `gen_ai.*` attributes
  alongside the `fabric.*` extensions.

## What this SDK does NOT do

- **It is not an LLM SDK.** The SDK does not call OpenAI/Anthropic
  /Bedrock/etc. Tenants make their own LLM calls; from v0.2.0 the
  SDK provides `Decision.llm_call(...)` as a child-span context
  manager and optional auto-instrument extras
  (`pip install "singleaxis-fabric[openai]"`, etc.) for popular
  providers, but the call itself is yours.
- **It does not own a vector DB or memory store.** `record_retrieval`
  and `remember` record what your store did; the SDK never reads or
  writes to a vector index. Bring your own (pgvector, Qdrant, Neo4j,
  Mem0, anything).
- **It does not run guardrails by itself.** Presidio + NeMo
  Guardrails ship as separate Helm subcharts (`presidio-sidecar`,
  `nemo-sidecar`). The SDK is a fail-loud client; without wired
  sidecars, the `guard_*` methods raise.
- **It does not produce audit reports or evidence bundles.** Those
  ship with the SingleAxis commercial control plane (separate
  private repo). The SDK produces the collection inputs that a
  commercial-tier evidence pipeline can later materialize into
  bundles.
- **It does not run judge / scoring workers.** Judges (per spec 006)
  are part of the L2 commercial control plane. The SDK emits the
  decision spans that judges consume, but the workers themselves
  don't ship in OSS.
- **It does not ship a SASF Reviewer service.** The escalation
  primitive lets you pause + emit a typed payload; what consumes
  that payload (a reviewer dashboard, a Slack channel, a Linear
  ticket, the L2 commercial SASF service) is up to the operator.
- **It does not pick your observability backend.** Spans land
  wherever the chart's `otel-collector.exporter.endpoint` points
  (Langfuse, Phoenix, Datadog, Honeycomb, your own collector chain
  — see [`docs/exporting-to-your-observability-backend.md`](../../docs/exporting-to-your-observability-backend.md)).

## What you get vs. what you bring

| You bring | Fabric provides |
|---|---|
| Your agent (LangGraph / MAF / CrewAI / homegrown) | Decision-span wrapper + adapter |
| Your LLM calls | Span context manager + `gen_ai.*` conventions (v0.2.0+) |
| Your vector DB / memory store | Retrieval + memory event recording with content hashes |
| Your observability backend | OTel collector pre-wired to fan out via OTLP |
| Your secrets / IAM | Webhook validation against operator-supplied keys (no SDK opinion) |
| Your reviewer flow | Typed escalation payload + adapter to pause your orchestrator |

## Versioning

Pre-1.0: minor version bumps (0.1 → 0.2) MAY break SDK API. From
1.0: SDK + OTel attribute schemas commit to backwards-compat per
[`specs/011-roadmap.md`](../../specs/011-roadmap.md).

## See also

- [`README.md`](README.md) for the install + quickstart
- [`../../specs/002-architecture.md`](../../specs/002-architecture.md)
  for the 8-layer model
- [`../../specs/005-guardrails-inline.md`](../../specs/005-guardrails-inline.md)
  for the guardrail chain semantics
- [`../../docs/how-fabric-fits-in-your-agent-stack.md`](../../docs/how-fabric-fits-in-your-agent-stack.md)
  for the picture
