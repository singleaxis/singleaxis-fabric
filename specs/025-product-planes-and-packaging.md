---
title: Product planes, packaging, and deployment model
status: superseded
revision: 1
last_updated: 2026-08-25
owner: product-architecture
superseded_by: 027
---

# 025 — Product planes, packaging, and deployment model

> **Superseded. Do not implement recorder v1 from this document.**
> [Spec 027](027-recorder-v1.md) replaces its six-plane packaging model with
> the release boundary `CAPTURE -> PROTECT -> DELIVER`. This file is retained
> only to explain earlier architectural decisions.

## Summary

Fabric is a reconstruction-first operational substrate for AI agents. Its
open-source spine captures agent activity, normalizes it into a public
contract, applies approved privacy transformations, preserves causal identity,
and relays the resulting telemetry to a destination chosen by the operator.

PII engines, guardrails, authorization systems, judges, red-team tools, and
governance products are integrations around that spine. They share trace
identity and emit results into the same activity contract, but they do not all
run in the request path and they are not all mandatory for every deployment.

This spec replaces the eight-layer model as the product packaging and
deployment model. The eight-layer model in spec 002 remains useful as a
technology taxonomy; it must not be used to imply that a customer installs all
eight layers or that all layers ship in one product.

## Goals

1. Give customers one stable explanation of what Fabric is and what each part
   does.
2. Separate the runtime execution plane from telemetry, assurance,
   governance, and management.
3. Make the OSS/commercial boundary explicit and technically enforceable.
4. Support customer-built agents, framework-based agents, off-the-shelf
   agents, existing OpenTelemetry estates, and isolated deployments.
5. Define the contracts every component and adapter must share.
6. Provide a feature-slice structure that keeps implementation small,
   testable, and releasable.

## Non-goals

- Fabric is not an agent framework, model host, vector database, SIEM, or
  secrets manager.
- Fabric does not infer hidden model reasoning.
- Fabric does not guarantee that every off-the-shelf agent exposes enough
  semantic detail for complete reconstruction.
- Fabric does not claim deterministic reproduction of nondeterministic model
  output or external side effects.
- Installing a profile does not by itself create legal compliance,
  certification, or regulatory approval.

## Product decision

The product uses six named planes. Only Connect and Observe are universally
required for Fabric's reconstruction purpose. Relay is an Observe deployment
role. Control and Assurance are selected according to the use case and
assurance level. Governance and Management consume or configure the other
planes; they are not part of the agent request path.

```text
                         Fabric Management
        agents · profiles · policies · approvals · versions · rollout
                                  │
                 desired state    │    status / evidence
                                  ▼

Agent or agent traffic
        │
        ▼
   CONNECT ───────▶ CONTROL ───────▶ OBSERVE ───────▶ RELAY ───────▶ destinations
 integrate          prevent or       record and       securely        customer OTLP
 and identify       authorize        correlate        deliver         or SingleAxis
        │                │                │
        └────────────────┴────────────────┘
                         shared trace identity
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
                ASSURANCE                   GOVERNANCE
             test and evaluate        investigate, graph,
             before and after         replay and prove
             deployment
```

### Fabric Connect

Connect gets activity into Fabric and assigns trustworthy workload identity.
It includes SDKs, framework adapters, auto-instrumentation, gateways, OTLP
receivers, vendor connectors, and propagation libraries. A connector must say
which semantic surfaces it can observe. Network visibility alone must never be
represented as full decision visibility.

### Fabric Control

Control makes a synchronous runtime decision before a sensitive action is
completed. It includes PII transformation before model or tool exposure,
content guardrails, policy evaluation, tool authorization, budgets, and human
escalation hooks.

Control is optional at the product level and mandatory only when a deployment
profile or customer policy selects it. A control integration must define its
failure posture: fail closed, fail open with an explicit event, or unavailable
for that operation. Silent bypass is forbidden.

### Fabric Observe

Observe is the OSS core. It captures activity, normalizes it to the public
contract, correlates events into decisions and executions, applies collector
privacy and allowlist rules, records provenance, and exposes delivery health.

Observe does not need the raw prompt to reconstruct the operational decision
path. Raw content is disabled by default. Approved content stores may be
referenced using hashes and access-controlled content references.

The Collector receives and processes telemetry. The Relay is a hardened
deployment role of Observe that queues, encrypts, and exports approved
telemetry across a trust boundary. A combined Collector/Relay process is valid
for small deployments; regulated deployments may separate the roles.

### Fabric Assurance

Assurance asks whether the system behaves acceptably. It includes unit and
scenario evaluation, adversarial testing, red teaming, regression suites,
LLM-as-judge adapters, human evaluation, and continuous post-deployment
evaluation.

Red teaming is primarily pre-deployment and scheduled testing, not telemetry.
Judge execution is normally asynchronous and post-hoc. Both produce
trace-correlated findings that Observe can transport and Governance can retain.
Neither belongs in the critical path unless a specific control policy promotes
an evaluation to a blocking gate.

### Fabric Governance

Governance turns records into durable organizational evidence. It includes the
Decision Graph, incident cases, controlled reconstruction, replay
orchestration, evidence bundles, retention and legal hold, erasure workflows,
audit access, and regulator-shaped reporting.

The OSS contract enables any backend to build this plane. SingleAxis provides
the managed/private implementation; the public SDK and collector must remain
usable with a customer-owned backend.

### Fabric Management

Management is the desired-state control plane. It registers agents and
deployments, versions profiles and policies, records approvals, distributes
configuration, observes rollout health, and links installed components to the
governance record.

Management must configure the data plane through signed, versioned resources.
It must never become a hidden telemetry dependency: a deployed agent continues
under its last approved configuration when Management is temporarily
unavailable.

## Artifact model

| Artifact | Form | Primary plane | Purpose |
|---|---|---|---|
| Fabric SDK | language package | Connect / Observe | Instrument agent code and propagate identity |
| Fabric Adapter | library, plugin, or receiver | Connect | Integrate a framework, runtime, guardrail, judge, or vendor |
| Fabric Gateway | proxy service | Connect / Control | Observe or control LLM, MCP, and tool traffic without agent-code changes |
| Fabric Collector | daemon | Observe | Receive, normalize, redact, correlate, and route telemetry |
| Fabric Relay | hardened daemon role | Observe | Durably and securely export approved telemetry |
| Fabric Control | sidecar, gateway, or library | Control | Enforce runtime policy close to the protected operation |
| Fabric Assurance Runner | CLI, container, or worker | Assurance | Run tests, red teams, and evaluations and emit correlated results |
| Fabric Site Controller | operator and local agent | Management | Install and reconcile signed desired state |
| SingleAxis Platform | SaaS or private deployment | Management / Governance / Assurance | Manage fleets, evaluate activity, build Decision Graphs, and retain evidence |

The repository is a monorepo because the public contract, SDKs, collector,
sidecars, chart, examples, and release qualification must change atomically.
Independent artifacts keep independent versions only where compatibility is
explicitly tested; a Fabric release manifest records the compatible set.

## Shared activity contract

Every adapter and plane joins work through the same correlation envelope. A
record must carry the fields applicable to its scope:

- contract and schema version;
- tenant and environment identity;
- agent and deployment identity;
- execution, workflow, decision, trace, span, and parent identifiers;
- event kind and timestamps;
- source component and version;
- policy, guardrail, rubric, test-suite, or approval version when applicable;
- outcome, error, and side-effect status;
- content digest or approved content reference, never unapproved raw content;
- privacy transformation and dropped-field diagnostics.

The canonical contract lives under `contracts/`. Language SDKs implement it;
they do not own it. Contract fixtures declare exact implementation support and
are digest-pinned. A new integration is incomplete until it passes the shared
conformance suite.

## Lifecycle placement

| Lifecycle phase | Required baseline | Optional or risk-selected additions | Produced record |
|---|---|---|---|
| Discover and register | Connect identity and capability inventory | passive gateway or eBPF discovery | agent/deployment registration |
| Integrate | SDK, adapter, gateway, or OTLP receiver | Control bindings | conformance and connection result |
| Pre-deployment | local Observe verification | red team, scenario evals, policy simulation, approval gate | signed qualification result |
| Deploy | Collector/Relay and approved profile | Site Controller rollout | versioned deployment record |
| Runtime | Connect + Observe + delivery health | PII, guardrails, authorization, escalation | decision/execution traces and control events |
| Continuous assurance | trace sampling and health | judges, drift checks, scheduled red teams | correlated findings and trends |
| Incident and audit | retained activity contract | Decision Graph, controlled replay, evidence export | incident case and evidence bundle |

## Assurance levels

Profiles express required controls; customers do not assemble regulated
posture from unrelated toggles.

| Level | Intended use | Required posture |
|---|---|---|
| A0 — Development | local experiments with synthetic data | local capture, debug export, no compliance claim |
| A1 — Observed | internal, low-impact agents | stable identity, normalized traces, privacy defaults, authenticated export, delivery monitoring |
| A2 — Controlled | agents that access sensitive data or tools | A1 plus selected inline controls, authorization events, durable relay, pre-deploy assurance, approvals, incident retention |
| A3 — Regulated / critical | high-impact or regulated workflows | A2 plus customer-approved policy profile, segregation of duties, signed configuration, continuous assurance, WORM-capable evidence destination, tested recovery and controlled reconstruction |

These are product assurance levels, not legal classifications. The customer
maps them to its risk assessment and applicable obligations.

## Integration and deployment models

### 1. Native SDK

Use when the customer controls agent code. It provides the richest decision,
tool, memory, policy, and side-effect semantics. The SDK emits asynchronously
to a local or cluster Collector.

### 2. Framework adapter or auto-instrumentation

Use when the customer controls packaging but wants minimal code changes. The
adapter maps framework callbacks to the public contract. Capability manifests
must disclose missing surfaces and raw-content behavior.

### 3. Gateway or service-mesh interception

Use for off-the-shelf agents when model, MCP, or tool traffic can be routed
through a customer-controlled endpoint. A gateway can capture request/response
boundaries and enforce policy without modifying agent code. It cannot observe
private in-process planning or local state that never crosses the gateway.

### 4. Existing OpenTelemetry or vendor telemetry

Use when the customer already instruments the agent. An OTLP receiver or
vendor adapter normalizes their spans and preserves original identifiers. The
adapter adds Fabric identity and emits an explicit coverage report instead of
requiring wholesale reinstrumentation.

### 5. eBPF-assisted discovery

Use eBPF to discover processes, network dependencies, destinations, and
unencrypted protocol metadata where legally and operationally approved. eBPF
is a supplement, not the primary semantic capture mechanism. TLS, application
encryption, kernel/platform limits, and missing business context prevent it
from proving everything an agent decided.

### 6. Isolated or customer-managed deployment

Run SDKs, Collector, Relay, controls, and optional Assurance entirely inside
the customer boundary. Relay may target a customer-owned backend, an approved
private SingleAxis deployment, or a one-way export process. No public Fabric
component phones home by default.

## Declarative setup model

The target operator experience is one signed desired-state document applied by
`fabricctl` or reconciled by the Site Controller. The management API and file
use the same resource model:

```yaml
apiVersion: fabric.singleaxis.dev/v1alpha1
kind: FabricDeployment
metadata:
  name: payments-agent-prod
spec:
  assuranceLevel: A3
  connection:
    mode: sdk
    tenantIdFrom: tenant-identity
  controls:
    profileRef: payments-agent-controls-v4
  observe:
    contentMode: hash-only
    relayRef: regulated-relay-eu-west
  assurance:
    planRef: payments-release-gate-v7
  rollout:
    approvalRef: change-1842
```

Secrets are references, not inline values. The controller verifies signatures,
resolves approved references, renders component-native configuration, reports
status, and records the effective digest. The OSS CLI must always support local
inspection and verification without a SingleAxis account.

## Public and private boundary

### Public OSS

- activity schemas, semantic conventions, fixtures, and conformance tooling;
- SDKs, propagation, framework adapters, auto-instrumentation, and public
  gateway/receiver interfaces;
- Collector processors and customer-controlled Relay deployment;
- local privacy/control clients and reference sidecars;
- Assurance runner interfaces and local/offline runners;
- Helm packaging, profiles, `fabricctl`, examples, and release verification.

### SingleAxis private implementation

- Decision Graph materialization and enterprise query APIs;
- managed/private Assurance workers and proprietary rubric or policy packs;
- governance workflows, evidence, retention, legal hold, and controlled replay;
- fleet Management service, approvals, rollout, SSO/SCIM/RBAC, and enterprise
  connectors;
- private deployment overlays and regulatory mappings maintained as a service.

Public code must not import private code. Private services consume public
contracts exactly as any customer backend can. Optional SingleAxis export is a
configured Relay destination, not a hidden code path.

## Feature-slice contract

Every feature is planned and reviewed as a small vertical slice. Its issue or
spec must name:

1. product plane and lifecycle phase;
2. artifact and repository owner;
3. public contract change, or an explicit statement that none is needed;
4. supported integration/deployment models;
5. privacy classification and raw-content behavior;
6. identity, authentication, and authorization boundary;
7. latency and backpressure behavior;
8. fail-open/fail-closed semantics and recovery;
9. conformance, unit, integration, security, packaging, and upgrade tests;
10. operator documentation, diagnostics, and rollback;
11. OSS, private, or customer-owned placement;
12. measurable acceptance criteria and explicitly deferred work.

A feature is not released because its library tests pass. The released wheel,
npm package, image, and chart must be built, inspected, smoke-tested, signed,
and tied to the exact source and workflow evidence.

## Current implementation state

| Plane | Current OSS state | Next maturity boundary |
|---|---|---|
| Connect | Python and TypeScript SDKs, framework adapters, MCP integration, auto-instrumentation, connector capability contract | gateway implementation, vendor receivers, broader language/framework coverage |
| Control | PII and guardrail clients/sidecars, policy and tool-authorization primitives, escalation emission | declarative bindings, identity-aware gateway enforcement, policy distribution |
| Observe | decision/execution primitives, public activity contract, custom Collector processors, mTLS ingress, durable authenticated Relay, strict Helm/upgrade qualification | certificate-to-tenant binding, delivery alerts, live failure and recovery qualification |
| Assurance | red-team runner packaging, judge adapters and queue/eval emission, common `AssuranceFinding` contract | runner emission conformance, release-gate CLI, continuous worker integration |
| Governance | public events and reconstruction/replay metadata | implemented in the SingleAxis platform or a customer backend, not the OSS runtime |
| Management | strict `FabricDeployment` resource plus offline `fabricctl` validate, digest, and plan | signature/approval verification, Site Controller, agent registry and rollout status |

## Security considerations

- Treat the agent, its plugins, and all telemetry producers as potentially
  compromised. Authenticate ingress and bind identity independently of
  self-asserted attributes where the deployment supports it.
- Raw prompts, completions, reasoning, tool payloads, and PII are denied from
  telemetry by default. Hashes are identifiers, not anonymization guarantees.
- Apply redaction and allowlisting before any cross-boundary export. Record the
  processor and policy version without echoing rejected content.
- Use TLS with server verification and secret-backed authentication for remote
  export. Regulated profiles must reject insecure endpoints.
- Queueing changes delivery semantics. Document at-least-once behavior,
  duplicates, capacity, overflow, and confirmed loss; never imply exactly-once
  telemetry.
- Sign releases and desired-state resources, pin immutable artifact digests,
  and record the effective configuration digest.
- Separate policy authors, deployment approvers, operators, investigators, and
  evidence custodians at A3.

## Operational considerations

- The agent request path must not depend on the availability of Governance or
  Management. Inline Control dependencies need bounded timeouts and an explicit
  failure posture.
- Collector health is not delivery health. Expose accepted, transformed,
  queued, retried, dropped, and delivered telemetry signals.
- A restart must preserve queued data when the selected assurance profile
  requires durable delivery.
- Upgrades need schema compatibility, configuration migration, rollback, and
  N-1/N compatibility tests.
- Every connector publishes a capability manifest so customers can compare
  semantic coverage before deployment.

## Open questions

1. How should the verified OTLP client-certificate identity be mapped to tenant,
   agent, environment, and deployment attributes without trusting producer
   assertions? Resolver: security architecture, before A3 controller apply.
2. Is Relay a separately branded binary or a hardened Collector profile for
   the first stable release? Resolver: product architecture, before v1.0.
3. Which `FabricDeployment` resources belong in OSS versus only in the
   SingleAxis Management API? Resolver: product and community maintainers,
   before Site Controller implementation.
4. What is the stable common finding schema across red-team, judge, human, and
   deterministic evaluators? Resolver: Assurance owner, before continuous
   evaluation packaging.

## References

- [Spec 003 — Decision Graph](003-decision-graph.md)
- [Spec 005 — Inline guardrails](005-guardrails-inline.md)
- [Spec 008 — Deployment model](008-deployment-model.md)
- [Spec 012 — public distribution architecture](012-oss-commercialization-strategy.md)
- [Spec 023 — Generic interaction capture](023-generic-interaction-capture.md)
- [OSS / commercial boundary](../docs/oss-commercial-boundary.md)
- [Building Fabric](../docs/building-fabric.md)
