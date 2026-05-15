---
title: PRD - Operational Infrastructure for Autonomous Systems
status: draft
revision: 2
last_updated: 2026-05-14
owner: product
---

# 012 - PRD: Operational Infrastructure for Autonomous Systems

## Executive summary

SingleAxis Fabric is operational middleware for production AI agents and
autonomous workflows. Fabric standardizes how autonomous software emits
execution telemetry, policy decisions, tool causality, memory lineage,
human interventions, side effects, replay metadata, and compliance-ready
operational records.

Fabric is not another agent framework, prompt management tool, chatbot
UI, model gateway, vector database, or SIEM. It sits between agents,
tools, workflows, policies, humans, memory systems, and observability
backends, then gives those systems shared operational semantics.

The product thesis:

> The next decade of AI infrastructure will be won by systems that make
> autonomous software operationally trustworthy. Fabric exists to become
> that operational layer.

The open-source repo should provide the capture substrate: SDKs,
framework adapters, OpenTelemetry mappings, collector processors,
guardrail sidecars, local debugging, canonical schemas, and conformance
tests. The commercial product should provide the operational intelligence
layer: Decision Graph, replay orchestration, runtime evaluations,
governance workflows, retention, signed audit bundles, and enterprise
control planes.

## Product vision

**Vision:** Become the operational nervous system for autonomous
software.

Fabric should become the default infrastructure layer enterprises use to
observe, govern, debug, replay, audit, and evaluate AI-driven systems.

**North star:** A platform team can instrument an autonomous workflow in
less than one day, reconstruct the causal chain of a production incident
in less than five minutes, and produce governance evidence without
shipping raw customer content to SingleAxis.

## Problem statement

Modern agent systems are operationally fragile. Existing AI
observability products often show prompts, token usage, model latency,
and isolated traces, but production autonomous systems need more:

- workflow-aware execution lineage
- cross-system causal correlation
- tool invocation and side-effect attribution
- policy decision lineage
- memory read/write/invalidation lineage
- human intervention traceability
- replay-safe operation metadata
- multi-tenant governance and scoped access
- compliance-ready operational records

Without a standard layer, teams build one-off telemetry schemas for each
framework, tool stack, and business workflow. That makes debugging slow,
governance inconsistent, and audits manual.

Fabric addresses the gap by defining the operational semantics for
autonomous software.

## Goals

| Goal | Description |
|---|---|
| Standardize autonomous-system telemetry | Unified execution schema across agent and workflow frameworks |
| Enable reconstruction-first replay | Emit deterministic metadata for later reconstruction and controlled replay |
| Provide causal observability | Link agents, tools, memory, policies, humans, and side effects in one graph |
| Support regulated industries | Produce compliance-ready operational lineage |
| Minimize vendor lock-in | Stay OpenTelemetry-native and standards-forward |
| Enable governance | Track policy decisions, budgets, guardrails, and escalations |
| Support multi-agent systems | Correlate distributed execution across agents and workflows |

## Non-goals

Fabric will not:

- replace agent frameworks
- provide model hosting
- become a vector database
- replace workflow engines
- become a SIEM
- provide a full orchestration runtime
- become a chatbot product
- infer hidden model reasoning
- guarantee exact token-level deterministic replay for nondeterministic
  LLM calls

## Product principles

1. **Open standards first.** Fabric must emit OpenTelemetry, align with
   OpenTelemetry GenAI semantic conventions, support CloudEvents where
   useful, and avoid proprietary lock-in on the capture path.
2. **Replayability by design.** Every primitive must emit enough
   metadata for deterministic reconstruction and, where possible,
   replay-safe execution.
3. **Policy-as-code.** Governance must be declarative, inspectable,
   versioned, and auditable.
4. **Multi-tenant by default.** All telemetry must support tenant
   attribution, scoped access, and organization isolation.
5. **Framework agnostic.** Fabric integrates with LangGraph, CrewAI,
   OpenAI Agents SDK, Microsoft Agent Framework, Temporal, Restate, MCP
   ecosystems, and custom runtimes.
6. **Side effects are first-class.** Autonomous systems are risky because
   they do things. Writes to CRMs, tickets, databases, email, payments,
   files, and APIs must be modeled explicitly.
7. **OSS capture, commercial intelligence.** The standard capture layer
   should be open and inspectable. The paid layer should turn capture
   into Decision Graph intelligence, replay orchestration, governance,
   evaluations, and evidence.

## Target users

### Primary persona: Platform engineer

Responsibilities:

- Deploys production AI systems.
- Owns observability, reliability, governance hooks, and production
  incident response.
- Integrates agent frameworks, workflow engines, and enterprise tools.

Pain points:

- No replayability.
- Inconsistent telemetry.
- Unknown causal chains.
- Vendor lock-in.
- Missing audit evidence.

### Secondary persona: AI infrastructure team

Responsibilities:

- Operates LLM gateways and model providers.
- Manages agent frameworks and memory systems.
- Enforces guardrails and budget controls.
- Tracks cost, latency, and quality.

Pain points:

- Difficult cross-system debugging.
- No standard telemetry layer across frameworks.
- Weak policy traceability.
- Unclear memory influence.

### Tertiary persona: Risk and compliance teams

Responsibilities:

- Audit reviews.
- Regulatory reporting.
- Evidence collection.
- Governance validation.

Pain points:

- Missing lineage.
- Incomplete audit trails.
- Inability to reconstruct decisions.
- Human review decisions disconnected from execution traces.

## High-level architecture

```text
Agents / Workflows / Tools
            |
            v
        Fabric SDK
            |
            v
    Fabric Collector Layer
            |
            v
  Causality + Governance Plane
            |
            v
  Replay + Audit + Eval Layer
            |
            v
Existing Customer Backends
```

## Core product components

### 1. Fabric SDK

Responsibilities:

- instrumentation
- decision lifecycle tracking
- execution and workflow context propagation
- memory read/write tracking
- tool invocation tracking
- side-effect metadata emission
- policy and human-intervention event emission

Supported languages:

| Language | Target |
|---|---|
| Python | v1 |
| TypeScript | v1 |
| Go | v2 |
| Java | v2 |

### 2. Fabric Collector

Based on OpenTelemetry Collector.

Responsibilities:

- telemetry normalization
- enrichment
- redaction
- routing
- policy enforcement
- tenant scoping
- backend fan-out

### 3. Decision Graph Engine (commercial)

Responsibilities:

- causal graph construction
- cross-system lineage reconstruction
- cross-decision correlation
- replay indexing
- side-effect graphing
- governance and evidence query APIs

The Decision Graph is the commercial system of record. The canonical
schema and event contracts remain public; the production materializer,
query layer, retention controls, and graph intelligence are commercial.

### 4. Replay Engine (commercial)

Responsibilities:

- deterministic reconstruction from retained metadata
- historical workflow replay where supported by the underlying workflow
  engine
- side-effect suppression
- replay-safe execution envelopes
- counterfactual and simulation primitives in later phases

Replay must be positioned carefully:

- v1 means **reconstruction metadata**, not exact LLM determinism.
- v2 means **side-effect-safe replay** for workflow engines that support
  checkpoints and idempotency.
- v3 means **simulation and counterfactual analysis**.

### 5. Governance Engine

Responsibilities:

- policy enforcement hooks
- policy decision logging
- budget controls
- escalation workflows
- signed policy/version lineage

Policy evaluation hooks and local policy events should be OSS.
Enterprise policy management, history, approvals, reporting, and signed
policy packs are commercial.

### 6. Runtime Evaluation Layer (commercial)

Responsibilities:

- drift detection
- runtime scoring
- longitudinal evaluation
- regression detection
- policy-adherence scoring
- risk trend analysis

## Core data model

Fabric's primary primitive is `Decision`, but production autonomous
systems require a hierarchy:

| Primitive | Meaning |
|---|---|
| `Execution` | Full workflow, run, job, or long-lived autonomous task |
| `Decision` | Agent choice point or governance-relevant branch |
| `Step` | LLM call, tool call, memory event, policy check, or evaluator action |
| `SideEffect` | External state mutation or irreversible operation |
| `Intervention` | Human, policy, or system override |
| `Checkpoint` | State boundary used for reconstruction or replay |

Canonical `Decision` shape:

```json
{
  "decision_id": "",
  "tenant_id": "",
  "agent_id": "",
  "workflow_id": "",
  "execution_id": "",
  "session_id": "",
  "inputs": {},
  "outputs": {},
  "tool_calls": [],
  "memory_reads": [],
  "memory_writes": [],
  "policy_decisions": [],
  "human_interventions": [],
  "side_effects": [],
  "timestamps": {},
  "replay_metadata": {}
}
```

Canonical `SideEffect` shape:

```json
{
  "side_effect_id": "",
  "decision_id": "",
  "tool_call_id": "",
  "effect_type": "external_write",
  "target_system": "salesforce",
  "operation": "case.update",
  "idempotency_key": "",
  "approval_required": true,
  "committed": true,
  "rollback_supported": false,
  "replay_behavior": "suppress",
  "result_hash": ""
}
```

## Key features

### Decision tracking

All governance-relevant agent activity should be wrapped in:

```python
with fabric.decision():
    ...
```

Requirements:

- unique correlation IDs
- tenant attribution
- workflow and execution correlation
- replay metadata emission
- OpenTelemetry span emission
- stable `fabric.*` attributes mirroring important GenAI semantic
  convention fields

### LLM call tracking

Captured fields:

- model name
- provider
- token usage
- latency
- cache usage
- finish reason
- streaming metrics
- error classification

Standards:

- OpenTelemetry GenAI semantic conventions
- stable Fabric mirrors for fields that must not break when upstream
  conventions evolve

### Tool invocation tracking

Requirements:

- invocation lineage
- parameter hashing
- latency
- retry tracking
- error classification
- side-effect attribution
- idempotency key capture where present

### Side-effect tracking

Requirements:

- distinguish reads from writes
- classify irreversible operations
- record approval requirements
- record commit/rollback status
- record replay behavior: `replay`, `suppress`, `mock`, or `manual`
- link side effects to the tool call and decision that caused them

### Memory lineage

Track:

- memory reads
- memory writes
- retrieval lineage
- retrieval influence
- memory invalidation
- right-to-erasure metadata
- source document IDs and content hashes

### Policy enforcement

Integrations:

- OPA
- Cedar
- tenant policy services

Requirements:

- policy versioning
- decision causality
- explainability
- audit logging
- deny/warn/allow outcomes
- policy bundle signatures

### PII / PHI protection

Integrations:

- Presidio
- Cloud DLP providers
- tenant custom recognizers

Requirements:

- redaction
- tokenization
- HMAC fingerprinting
- policy-aware export
- raw-content-off-by-default posture

### Replayability

Requirements:

- deterministic checkpoints where the underlying workflow supports them
- workflow correlation
- state reconstruction
- side-effect suppression
- tool-result hashing
- model/provider/version capture
- prompt/template/version capture when enabled by policy

### Human escalation

Requirements:

- escalation metadata
- reviewer attribution
- SLA tracking
- workflow pause/resume support
- signed verdicts
- fail-open, fail-closed, and defer policies

### Runtime evaluations

Requirements:

- continuous scoring
- drift detection
- policy adherence scoring
- regression detection
- judge/rubric versioning
- longitudinal risk trends

## Open source vs commercial boundary

### Open source components

| Component | OSS |
|---|---|
| SDKs | Yes |
| OpenTelemetry mappings | Yes |
| Framework adapters | Yes |
| Basic replay hooks and metadata emitters | Yes |
| Collector processors | Yes |
| Basic guardrail sidecars | Yes |
| Local debugging UI | Yes |
| Canonical schemas and conformance tests | Yes |
| Red-team runner wrapper | Yes |
| Reference agents | Yes |

### Commercial components

| Component | Commercial |
|---|---|
| Decision Graph engine | Yes |
| Replay orchestration | Yes |
| Runtime evaluation system | Yes |
| Compliance mapping packs | Yes |
| Signed audit bundles | Yes |
| Long-term WORM retention | Yes |
| HITL orchestration | Yes |
| Cross-decision lineage analytics | Yes |
| Governance control plane | Yes |
| Enterprise admin UI | Yes |

## Build vs integrate

Fabric should not rebuild commodity safety and red-team engines from
scratch. Fabric should integrate best-in-class tools and own the
operational contract around them.

| Capability | Default approach | Fabric-owned value |
|---|---|---|
| PII / PHI redaction | Presidio and cloud DLP providers | tenant HMACs, policy-aware export, fail-closed wiring |
| Guardrails | NeMo Guardrails, OPA, Cedar | canonical events, profile rules, latency posture |
| Red teaming | Garak, PyRIT, Promptfoo | normalized runner, scheduled jobs, evidence-grade telemetry |
| Observability | OpenTelemetry and existing backends | autonomous-system semantics and Decision Graph correlation |
| Workflow replay | Temporal, Restate, framework checkpoints | replay metadata, side-effect suppression, audit-safe reconstruction |

Fabric should build:

- the Decision schema
- the Execution/Step/SideEffect model
- Decision Graph materialization
- replay indexing and side-effect suppression metadata
- signed policies and rubrics
- evidence bundles
- governance workflows
- conformance tests

## Commercialization strategy

### OSS strategy

Goals:

- ecosystem adoption
- protocol standardization
- developer mindshare
- integration ecosystem

License: Apache-2.0 for the public capture substrate.

### Commercial strategy

Monetize:

- governance
- operational intelligence
- compliance
- replay orchestration
- enterprise workflows
- runtime evaluations
- retention and evidence

### Deployment models

| Model | Availability |
|---|---|
| Self-hosted OSS | Yes |
| Enterprise self-hosted | Yes |
| Managed cloud | Future |
| Air-gapped deployment | Enterprise |

### Pricing strategy

| Tier | Model |
|---|---|
| OSS | Free |
| Enterprise | Per environment, tenant, and governed agent/workflow |
| Cloud | Usage-based with included decision volumes |
| Compliance add-ons | Premium |
| Retention and evidence | Premium |

## Compliance requirements

| Standard | Support |
|---|---|
| EU AI Act | Operational evidence |
| ISO/IEC 42001 | Governance lineage |
| NIST AI RMF | Risk monitoring |
| HIPAA | PHI handling |
| SOC 2 | Audit traceability |
| SR 11-7 | Model-risk operational evidence |

Fabric must avoid claiming that installing the product creates legal
compliance. Fabric produces technical evidence, operational lineage, and
governance workflows that customers and auditors can use.

## Scalability requirements

Targets should be staged.

| Metric | v1 target | Enterprise target |
|---|---:|---:|
| SDK overhead | `<5ms p99` | `<2ms p99` |
| Collector overhead | `<5ms/span` | `<2ms/span` |
| Span ingestion | `10k-50k/sec` | `1M+/sec` |
| Decision Graph read latency | `<1s p95` | `<500ms p95` |
| Replay startup | `<30s` | `<5s` |
| Metadata completeness | `>99%` | `>99.9%` |

## Reliability requirements

| Requirement | Target |
|---|---|
| Collector HA | Multi-replica, zone-aware for enterprise |
| Backpressure support | Mandatory |
| Ingestion semantics | At-least-once with idempotent materialization |
| Decision Graph writes | Replayable and idempotent |
| Replay correctness | Reconstruction-first; deterministic only where runtime supports it |
| Data durability | Customer storage tier dependent; enterprise WORM optional |

## Security requirements

- zero-trust architecture
- workload identity support
- SPIFFE/SPIRE integration
- encrypted transport
- attribute-level redaction
- raw content disabled by default
- audit logging
- tamper detection
- signed policies, rubrics, profiles, and release artifacts
- tenant-controlled keys for commercial self-hosted deployments

## Integration targets

### Agent frameworks

- LangGraph
- CrewAI
- OpenAI Agents SDK
- Microsoft Agent Framework
- AutoGen
- custom runtimes

### Workflow engines

- Temporal
- Restate

### Observability backends

- Langfuse
- Phoenix
- Datadog
- Honeycomb
- Grafana
- Tempo
- Jaeger

### Policy systems

- OPA
- Cedar
- tenant policy services

### Enterprise systems

- Vault and cloud KMS
- SIEM
- Jira
- ServiceNow
- Slack / Teams
- GRC systems
- object storage and WORM archives

## Success metrics

| Metric | Target |
|---|---:|
| SDK install-to-first-trace | `<10 min` |
| OSS GitHub stars | `10k+` |
| Enterprise conversion | `5%+` |
| P99 SDK overhead | `<5ms` |
| Replay reconstruction metadata completeness | `>99.9%` |
| Incident debugging time reduction | `50%` |
| Production decisions with required telemetry | `>99%` |
| Mandatory rail activation in strict profiles | `100%` |

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Becoming "just observability" | Focus product language on causality, side effects, replay, and governance |
| Overpromising replay | Use reconstruction-first language and stage replay support by runtime |
| Vendor ecosystem fragmentation | Keep the capture substrate standards-first and framework-agnostic |
| Excessive ingestion costs | Sampling, tiered retention, compression, hot/cold storage |
| Regulatory churn | Keep compliance mappings and policy packs commercial and updatable |
| Framework churn | Adapter abstraction and conformance tests |
| Closed egress slows security approval | Make tenant-side egress inspectable; keep SaaS ingest and analytics commercial |
| Side effects are under-modeled | Make `SideEffect` a first-class primitive in v1 schemas |

## Roadmap

### v1 - Open capture substrate

- Python SDK
- TypeScript SDK
- OpenTelemetry integration
- collector processors
- canonical Decision / Execution / Step / SideEffect schemas
- basic replay hooks and metadata
- LangGraph and CrewAI adapters
- local debugging flow
- conformance tests

### v2 - Decision Graph and policy lineage

- commercial Decision Graph engine
- cross-decision lineage
- policy decision history
- Temporal / Restate integration
- side-effect indexing
- replay-safe operation metadata

### v3 - Replay orchestration and runtime evaluations

- replay orchestration
- side-effect suppression
- runtime scoring
- drift detection
- memory lineage graph
- regression analysis

### v4 - Autonomous workflow governance

- multi-agent coordination observability
- autonomous workflow governance
- execution simulation
- counterfactual analysis
- enterprise governance marketplace

## Current repository implications

Immediate engineering actions:

1. Keep the public provenance spec named Decision Graph.
2. Move commercial implementation code out of the OSS repo and into the
   private `singleaxis-fabric-internal` repo.
3. Keep only public contracts, architecture, schemas, SDKs, sidecars,
   collector processors, examples, and deployment profiles in this repo.
4. Update docs to describe Fabric as operational infrastructure for
   autonomous systems, with audit/compliance as a paid use case.
5. Add first-class `SideEffect`, `Execution`, and `Checkpoint` schema
   work before broadening framework support.

## Strategic positioning

Fabric is positioned as:

> Operational infrastructure for autonomous systems.

Fabric is not:

- chatbot analytics
- prompt tooling
- model management
- a model gateway
- an orchestration framework

Fabric's long-term moat:

- operational semantics
- causality lineage
- replayability
- side-effect governance
- runtime evaluation infrastructure
- auditability

## References

- OpenTelemetry GenAI semantic conventions:
  <https://opentelemetry.io/docs/specs/semconv/gen-ai/>
- OpenTelemetry GenAI agent spans:
  <https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/>
- Microsoft Presidio:
  <https://microsoft.github.io/presidio/>
- NVIDIA NeMo Guardrails:
  <https://developer.nvidia.com/nemo-guardrails>
- NVIDIA Garak:
  <https://github.com/NVIDIA/garak>
- Microsoft PyRIT:
  <https://github.com/microsoft/PyRIT>
- Promptfoo:
  <https://github.com/promptfoo/promptfoo>
