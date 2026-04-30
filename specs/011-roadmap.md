---
title: Phased Execution Roadmap
status: draft
revision: 3
last_updated: 2026-04-27
owner: project-lead
---

# 011 — Roadmap

## Summary

Fabric is built incrementally, by capability tier. Each phase is
gated on **technical and ecosystem milestones**, not calendar time
or feature completeness against any specific competitor. Where a
phase exit depends on real-world adoption ("conformance tests
exercised against N independent installations"), that signal is
named explicitly so the criterion is testable rather than
aspirational.

This spec covers the **public roadmap only**. Components and
services maintained internally by SingleAxis are referenced for
context but their detailed plans are not part of this repository.

## Non-goals

- Timeline commitments with specific dates. Sequencing matters;
  calendar time depends on headcount, scope decisions, and ecosystem
  signals not yet observed.
- Feature parity with any specific competitor. Fabric is opinionated;
  we ship what fits the architecture.
- Publishing the roadmap for components not in this repository.

## Phase 0 — Scaffolding & specs (complete)

**Goal:** publish the design of record and the repo structure.

**Status:** complete. The specs directory is at revision 1+ and the
root governance files (`LICENSE`, `CONTRIBUTING.md`, `SECURITY.md`,
`GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, `MAINTAINERS.md`) are in
place.

## Phase 1 — Foundation (v0.1.x, current)

**Goal:** ship the L2 (tracing) + L4 (red-team) + L5 (guardrails)
layers of the agent stack as a coherent OSS substrate that an
enterprise platform team can install and operate without
hand-holding.

### Scope (the L1 OSS product)

Fabric L1 OSS = **L2 Agent Tracing + L4 Red-Teaming runner + L5
Inline Guardrails + L1 Orchestration adapters** of the 8-layer
agent stack defined in spec 002. Layers L3 (observability backend),
L6 (LLM-as-Judge), L7 (Security/IAM), and L8 (Context Sources) are
either tenant-owned (L3, L7, L8) or part of the SingleAxis
commercial control plane (L6).

### Public deliverables (Apache-2.0)

- **Fabric SDK (Python):**
  - `Fabric` client, `Decision` context manager
  - Inline guardrail chain (Presidio + NeMo rails)
  - Retrieval recording (records local hashes; the L2 commercial
    Context Graph materializes the provenance — spec 003)
  - Escalation pause primitive (the SDK exception + adapters; SASF
    review service is L2 — spec 007)
  - Adapters: LangGraph, Microsoft Agent Framework, CrewAI
- **Guardrail sidecars:** Presidio (UDS), NeMo Guardrails (UDS)
- **OTel Collector distribution** with Fabric processors
- **Red-team runner** (L4): Garak/PyRIT/Promptfoo CronJob
- **Reference agent** (end-to-end SDK exerciser)
- **Helm chart** with profiles: `permissive-dev` and
  `eu-ai-act-high-risk`

### NOT in this repo (referenced for clarity)

The following are described in specs 003/004/006/007/009 as
**design of record** but ship in the SingleAxis commercial control
plane (separate private repository), not here:

- **L6 LLM-as-Judge:** judge worker pool, signed rubric library
- **Telemetry Bridge:** sanitized egress to SingleAxis SaaS
- **Context Graph:** materialized provenance store (Postgres+pgvector
  / Neo4j)
- **Escalation service:** SASF reviewer dashboard, signed verdict
  webhook, durable checkpoint resume
- **Evidence Bundle exporter:** signed compliance bundles per spec
  009

### Exit criteria (Phase 1)

- Public OSS stable enough for external adopters to install without
  hand-holding (quickstart works end-to-end on a fresh checkout)
- Inline guardrail latencies meet the published P99 budgets in
  spec 005 under representative load
- Reference agent passes the documented decision-span contract
- Released artifacts are signed (cosign keyless) and accompanied by
  SBOMs (CycloneDX and SPDX)

## Phase 2 — Capture-everything SDK + observable-by-default chart (v0.2.x)

**Goal:** earn the "open-source observability and control plane for
AI agents" framing by emitting traces that observability backends
actually render natively, and by ensuring the chart's default
deployment puts spans into a real backend.

### Public additions

- **`Decision.llm_call` + `Decision.tool_call`** child-span context
  managers writing standard `gen_ai.*` semantic conventions
  alongside `fabric.*` extensions. Phoenix LLM views, Langfuse cost
  dashboards, Honeycomb queries all light up against Fabric traces
  out of the box.
- **Auto-instrument extras** (`pip install singleaxis-fabric[openai]`,
  `[anthropic]`, `[bedrock]`, `[langchain]`, `[langgraph]`,
  `[crewai]`) wrapping the upstream
  `opentelemetry-instrumentation-*` packages with Fabric's
  content-redaction guard. Single `pip install` covers governance +
  observability for the popular SDK families.
- **Collector trace processors:** `fabricguard`, `fabricsampler`,
  `fabricredact`, and `fabricpolicy` register as trace processors
  in addition to log processors, so the SDK's spans actually pass
  through field allowlist + HMAC sampling + Presidio redaction
  before egress. Closes the gap where the chart's privacy promise
  was advertised but only applied to L2-bridge log records.
- **Bundled-Langfuse default exporter** — when `langfuse.enabled:
  true` (chart default), the otel-collector's exporter wires to the
  bundled Langfuse service automatically. The "spans go somewhere
  real out of the box" experience the v0.1.3 fail-loud guard sets up.
- **Additional SDK languages:** Go, TypeScript (same sidecar model;
  gRPC or UDS bridge)
- **Rails library:** broader NeMo Colang rail catalog organized by
  regulatory profile
- **Conformance tests:** test suite tenants run to verify their
  installation produces Fabric-compliant spans

### Entry / Exit

- **Entry:** Phase 1 exit criteria all met.
- **Exit:** Fabric traces render natively in Phoenix + Langfuse +
  Honeycomb + Datadog (verified by smoke renders). At least three
  independent organizations have published Fabric-instrumented
  agents.

## Phase 3 — Stability & general availability

**Goal:** a stable, widely-deployed substrate with API commitments
that production users can pin against.

### Public additions

- **API stability commitments** (SDK, OTel attribute wire schema)
- **Long-term support branches** for minor releases
- **Expanded adapter surface** as new orchestration frameworks
  emerge
- **First-class OpenShift, GKE, EKS recipes**

### Exit criteria

- Used in production by at least five tenants in regulated sectors
  running the OSS standalone
- A recognised regulator or auditor cites Fabric by name in
  published guidance
- Documented upgrade paths from earlier versions
- Full SRE runbooks for operations
- Certified partnerships with upstream components (Presidio, NeMo,
  OpenTelemetry)
- Project governance moves toward (optional) foundation neutrality
  if warranted

## Risk register

| Risk | Mitigation |
|------|------------|
| Regulation changes faster than we can ship | Signed rubric channel (operated as a service) lets policy updates flow to operators without a full chart release. |
| A foundational dependency (Presidio, NeMo, LangGraph) goes in a hostile direction | Adapter layer in the SDK isolates upstream changes; components are swappable without breaking Fabric wire contracts. |
| Open-source contribution flow fails to materialise | Deep integration partnerships (OpenTelemetry, Presidio, NeMo) substitute for community-maintainer model. |
| Competitive closed platforms commoditise "compliance" framing | Fabric's wedge is the open substrate combined with the attestation network. A closed platform cannot credibly offer the OSS; a non-attested OSS cannot offer the verdict. |

## References

- [001 — Product Vision & Positioning](001-product-vision.md)
- [000 — Overview & Conventions](000-overview.md)
