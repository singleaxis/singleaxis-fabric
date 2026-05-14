# OSS / Commercial Boundary

Fabric uses an open-core strategy with a hard boundary:

- **OSS:** capture, schemas, local controls, adapters, conformance.
- **Commercial:** intelligence, retention, replay orchestration,
  governance workflows, evaluations, evidence, and enterprise operations.

## Public repo

The public `singleaxis-fabric` repo should contain:

| Area | Examples |
|---|---|
| SDKs | Python, TypeScript, future Go/Java clients |
| Framework adapters | LangGraph, CrewAI, OpenAI Agents SDK, Microsoft Agent Framework |
| OpenTelemetry contracts | `fabric.*` attributes, GenAI mappings, span/event schemas |
| Collector processors | allowlist, redaction, routing, sampling, policy hooks |
| Guardrail sidecars | Presidio, NeMo clients and packaging |
| Local red-team wrapper | Garak, PyRIT, Promptfoo runner normalization |
| Helm Layer 1 chart | collector, sidecars, local observability, profiles |
| Reference agents | smoke agents and examples |
| Conformance tests | fixtures that validate emitted telemetry |
| Public specs | architecture, schemas, deployment posture |

## Commercial repo

The private `singleaxis-fabric-internal` repo should contain:

| Area | Examples |
|---|---|
| Decision Graph engine | graph builder, stores, query APIs, replay indexes |
| Replay orchestration | checkpoint coordination, side-effect suppression |
| Runtime evals | judge workers, rubric routing, drift analysis |
| Governance control plane | policy history, approvals, org-wide controls |
| Evidence | signed bundles, retention jobs, compliance mappings |
| HITL workflows | reviewer queues, signed verdicts, SLAs |
| Enterprise UI | admin, audit, evidence, reviewer surfaces |
| Enterprise integrations | SIEM, GRC, ticketing, SSO/SCIM, WORM storage |

## Boundary rules

1. Public code must not import from private code.
2. Public docs may describe commercial behavior, but must label it as
   commercial or roadmap.
3. Commercial egress must be opt-in and inspectable.
4. The public capture path must never phone home.
5. Public schemas must be stable enough for third-party tooling.
6. Commercial code should not live under `_internal/` in the public repo.
7. Compliance claims must say "technical evidence" unless certification
   is actually provided.

## Build decisions

Open source the parts that create trust and ecosystem adoption. Sell the
parts that create operational outcomes.

Do not monetize SDK installation. Monetize governed agents, Decision
Graph intelligence, replay, retention, evaluations, workflows, evidence,
enterprise integrations, and support.

## Current split

Commercial staging code has been moved out of this repo to:

```text
../singleaxis-fabric-internal/
```

The public repo now carries the design contracts and OSS substrate only.
