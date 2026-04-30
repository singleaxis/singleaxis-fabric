# Architecture

A short mental model. The authoritative spec is
[`specs/002-architecture.md`](../specs/002-architecture.md); this page
exists so you can orient yourself in two pages instead of
thirty.

> **Scope.** This page describes the **L1 OSS** distribution that
> ships from this repository: the Fabric SDK, guardrail sidecars,
> OTel collector, red-team runner, and Helm chart. The L2 commercial
> control plane (judge workers, context graph, telemetry bridge,
> escalation service, evidence bundles) is referenced where it sits
> in the picture, but its implementation lives in a separate private
> repository — see [`specs/001-product-vision.md`](../specs/001-product-vision.md)
> for the L1/L2 split.

## Three layers you touch

Fabric has many components; developers working with it day-to-day
only interact with three layers.

| Layer | What it is | Where it runs | When the agent talks to it |
|-------|------------|---------------|----------------------------|
| **SDK** | The Python library your agent imports (`fabric`). Opens `Decision` spans, routes through guardrail chains, emits OTel telemetry. | In-process, same trust domain as the agent. | Synchronously, on every decision — this is the one call path that must be fast. |
| **Sidecars** | Presidio (PII redaction) and NeMo Guardrails (Colang rails), exposed over Unix domain sockets. Shipped as container images; deployed alongside the agent pod. | Same pod or same node as the agent. | Synchronously on `guard_input` / `guard_output_*`, but over a UDS — no TCP, no DNS, design-budget sub-millisecond transport (benchmark suite is a follow-up release). |
| **Collector** | An OpenTelemetry Collector distribution pre-configured with the Fabric processor chain (tail sampling, attribute allowlisting, tenant scoping). | One or more per-cluster deployments. | Asynchronously — the SDK exports batched spans over OTLP; the agent request path never waits for this. |

Everything else in the repo (judge workers, escalation service,
context graph, telemetry bridge, update agent, admin UI) runs
asynchronously off the OTel stream or over a message broker. The
agent's request path never blocks on any of them.

## The one principle to internalize

> **The agent request path never blocks on a Fabric HTTP call.**

The SDK keeps the hot path to:

1. In-process span work (target `<1 ms` P99 — design budget).
2. UDS calls to guardrail sidecars (target `<100 ms` P99 budget per sidecar — design budget).
3. OTLP export over a buffered, non-blocking exporter.

The numeric budgets above are design contracts, not measured
benchmarks. A first-party benchmark suite that gates merges on P99
regressions lands as a follow-up release.

Everything else — judges, escalations, context-graph writes,
compliance evidence generation — happens off the critical path.
Spec [`004-telemetry-bridge.md`](../specs/004-telemetry-bridge.md)
and [`008-deployment-model.md`](../specs/008-deployment-model.md)
document the specific latency budgets.

This is load-bearing. Security and compliance tooling that blocks
request paths gets ripped out. Fabric stays in the path only where
the latency budget justifies it.

## Request flow, at a glance

```text
agent pod:
  agent code -> fabric.Decision
                   |-- guard_input      --UDS--> Presidio sidecar
                   |-- guard_output_*   --UDS--> NeMo rail sidecar
                   |-- record_retrieval / request_escalation (local)
                   `-- OTLP exporter (buffered, async) -----> OTel Collector
                                                                |
      +---------------------------------------------------------+
      v                 v                      v
  Langfuse      judge-workers (NATS)   telemetry-bridge (NATS)
                                                |
                                                v
                                context-graph / escalation-service
```

Everything below the OTLP hop happens after the agent returns. If
the context graph is down, judges are behind, or the escalation
service is restarting, the agent still serves requests — the
telemetry queue drains when those services recover.

## Where each piece is documented

- Overall component shape — [spec 002](../specs/002-architecture.md)
- Context Graph (provenance) — [spec 003](../specs/003-context-graph.md)
- Telemetry wire contract — [spec 004](../specs/004-telemetry-bridge.md)
- Inline guardrails — [spec 005](../specs/005-guardrails-inline.md)
- LLM-as-judge (async) — [spec 006](../specs/006-llm-as-judge.md)
- Escalation (pause/resume) — [spec 007](../specs/007-escalation-workflow.md)
- Deployment / Helm / profiles — [spec 008](../specs/008-deployment-model.md)
- Compliance mappings — [spec 009](../specs/009-compliance-mapping.md)

## What's not in this repo

This repository ships the developer-facing adoption surface — SDK,
adapters, sidecars, OTel collector, Helm chart. Components and
services maintained internally by SingleAxis (Context Graph
analytics, evidence-bundle generation, reviewer workflows, rubric
authoring) are not part of this distribution.
