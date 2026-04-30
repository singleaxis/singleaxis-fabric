# How Fabric fits in your agent stack

The 8-layer model from [`specs/002-architecture.md`](../specs/002-architecture.md)
sounds abstract until you see where Fabric ships code, where it
plugs in, and where it gets out of the way. This page is the picture.

## The 8 layers, with Fabric's role

```
┌─────────────────────────────────────────────────────────────────┐
│ L1  Orchestration & Runtime                                     │
│     LangGraph / Microsoft Agent Framework / CrewAI / custom     │
│     ◆ Fabric ships ADAPTERS — escalation + lifecycle hooks      │
├─────────────────────────────────────────────────────────────────┤
│ L2  Agent Tracing (OpenTelemetry)                               │
│     ★ Fabric's primary capture surface                          │
│     ◆ Decision span per turn, gen_ai.* + fabric.* conventions   │
├─────────────────────────────────────────────────────────────────┤
│ L3  Observability & Eval Platform                               │
│     Langfuse / Phoenix / Datadog / Honeycomb / your own         │
│     ◆ TENANT chooses; Fabric exports to whichever they pick     │
├─────────────────────────────────────────────────────────────────┤
│ L4  Red-Teaming & Testing                                       │
│     Garak / PyRIT / Promptfoo                                   │
│     ★ Fabric ships a CronJob runner that wraps these            │
├─────────────────────────────────────────────────────────────────┤
│ L5  Guardrails & Policy                                         │
│     Presidio (PII) / NeMo Guardrails (Colang)                   │
│     ★ Fabric's opinionated INLINE default, sidecars + UDS       │
├─────────────────────────────────────────────────────────────────┤
│ L6  LLM-as-Judge                                                │
│     Ragas / DeepEval / SASF rubrics                             │
│     ◆ Lives in SingleAxis commercial control plane (separate)   │
├─────────────────────────────────────────────────────────────────┤
│ L7  Security & Access Control                                   │
│     Vault / KMS / IAM                                           │
│     ◆ TENANT infrastructure; Fabric integrates, doesn't own     │
├─────────────────────────────────────────────────────────────────┤
│ L8  Context Sources                                             │
│     pgvector / Qdrant / Neo4j / Mem0 / your own                 │
│     ◆ TENANT chooses; Fabric records retrieval/memory events    │
│       but never owns the storage                                │
└─────────────────────────────────────────────────────────────────┘

★  Fabric L1 OSS ships code at this layer
◆  Adapter / integration / out-of-scope
```

## What you install (L1 OSS, this repo)

| Layer | Fabric artifact | What it gives you |
|---|---|---|
| L1 | `fabric.adapters.langgraph` / `agent_framework` / `crewai` | Clean escalation primitive bound to your orchestrator's pause/resume mechanism |
| L2 | `fabric` Python SDK + custom OTel collector distribution | Standardized decision span per turn, with identity tags + governance metadata |
| L4 | `redteam-runner` Helm subchart | Daily Garak/PyRIT runs, fail-on-findings semantics |
| L5 | `presidio-sidecar` + `nemo-sidecar` Helm subcharts | Inline PII redaction + Colang policy enforcement, fail-loud if not wired |

## What you bring (tenant)

| Layer | Tenant choice | Fabric integration |
|---|---|---|
| L1 | Your orchestration framework (LangGraph, MAF, CrewAI, or homegrown) | `pip install singleaxis-fabric[<framework>]` for the matching adapter |
| L3 | Your observability backend (Langfuse, Phoenix, Datadog, …) | Set `otel-collector.exporter.endpoint`; see [exporting-to-your-observability-backend.md](exporting-to-your-observability-backend.md) |
| L7 | Your secrets/identity infrastructure (Vault, KMS, IAM) | Reference signing keys via `valueFrom: secretKeyRef`; the `update-agent` admission webhook validates against operator-supplied trustedKeys |
| L8 | Your vector DB / memory / RAG store (pgvector, Qdrant, Neo4j, Mem0, …) | The SDK's `Decision.record_retrieval` and `Decision.remember` record event metadata + content hashes — your store is the source of truth |

## What lives in the SingleAxis commercial control plane (L2 commercial, separate repo)

| Layer | Component | What it delivers |
|---|---|---|
| L2 commercial | Telemetry Bridge (spec 004) | Sanitized egress from tenant VPC to SingleAxis SaaS |
| L6 | Judge worker pool + signed rubric library (spec 006) | Async scoring against versioned rubrics |
| L7 commercial | SASF Reviewer service (spec 007 §SASF) | Human-in-the-loop reviewer dashboard + signed verdict webhook |
| audit | Context Graph (spec 003) | Materialized provenance — every decision queryable across sessions |
| audit | Evidence Bundle exporter (spec 009) | Signed compliance bundles per regulatory regime |

These are described in this repo's `specs/` directory **as design of
record** for partner/auditor transparency. The implementations live in
the SingleAxis commercial control plane and are not deployable from
this OSS distribution.

## The picture, end to end

```
       ┌── tenant VPC ──────────────────────────────────────────────┐
       │                                                            │
       │   ┌─ Agent (L1, your code) ─────────┐                      │
       │   │  with fabric.decision(...) as d:│                      │
       │   │      d.guard_input(...)         │ → presidio sidecar (L5)
       │   │      response = llm(...)        │                      │
       │   │      d.guard_output_final(...)  │ → nemo sidecar (L5)  │
       │   │      d.request_escalation(...)  │ ─┐                   │
       │   └────────────────┬────────────────┘  │                   │
       │                    │ OTLP              │                   │
       │   ┌────────────────▼────────────────┐  │                   │
       │   │  Fabric OTel Collector (L2)     │  │                   │
       │   │  (fabricguard / fabricredact /  │  │                   │
       │   │   fabricsampler / fabricpolicy) │  │                   │
       │   └────────────────┬────────────────┘  │                   │
       │                    │                   │                   │
       │   ┌────────────────▼────────────────┐  │                   │
       │   │  Tenant's L3 backend            │  │                   │
       │   │  (Langfuse / Phoenix / Datadog) │  │                   │
       │   └─────────────────────────────────┘  │                   │
       │                                        │                   │
       │   ┌─ redteam-runner CronJob (L4) ───┐  │                   │
       │   │  Garak / PyRIT / Promptfoo      │  │                   │
       │   └─────────────────────────────────┘  │                   │
       │                                        │                   │
       └────────────────────────────────────────┼───────────────────┘
                                                │
                          ┌─────────────────────┴───────────────────┐
                          │   SingleAxis commercial control plane   │
                          │   (separate repo; partner deployments)  │
                          │                                         │
                          │   ◆ Telemetry Bridge → SaaS             │
                          │   ◆ Judge workers (L6) score decisions  │
                          │   ◆ Context Graph materializes traces   │
                          │   ◆ SASF reviewer signs verdicts        │
                          │   ◆ Evidence Bundle exporter            │
                          └─────────────────────────────────────────┘
```

The L1 OSS half stands alone. The commercial half is opt-in for
partners who want managed evidence/judge/review services on top.

## See also

- [`specs/002-architecture.md`](../specs/002-architecture.md) — full
  layer-by-layer architecture spec
- [`specs/001-product-vision.md`](../specs/001-product-vision.md) —
  the OSS / commercial split
- [`docs/quickstart.md`](quickstart.md) — install + first decision
  span in 5 minutes
- [`docs/exporting-to-your-observability-backend.md`](exporting-to-your-observability-backend.md)
  — wire L2 to your L3
