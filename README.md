# SingleAxis Fabric

> **The open-source substrate for audit-ready AI agents.**
>
> Drop it into your agent code. Get standardized decision tracing,
> inline guardrails, and a clean escalation primitive from day one.

---

Fabric is an Apache-2.0 SDK and sidecar set that instruments enterprise
AI agents with what regulators, compliance officers, and security teams
actually ask for:

- Standardized **decision spans** (OpenTelemetry) that record what the
  agent did, what it retrieved, what it decided — all queryable
- Inline **guardrails** that fail loud: Presidio for PII redaction,
  NeMo Guardrails for Colang policy rails
- A structured **escalation primitive** for human-in-the-loop review
  when automated checks flag a decision
- **Retrieval recording** that maps onto the Context Graph provenance
  model (spec 003)
- First-class adapters for **LangGraph, Microsoft Agent Framework, and
  CrewAI**

Fabric is purpose-built for organisations deploying LLM agents under
regulatory scrutiny: EU AI Act, NIST AI RMF, ISO 42001, SR 11-7, HIPAA,
GDPR.

## Status

**Pre-alpha.** Fabric is under active development. The `specs/`
directory is the design of record. No components in this repository
are production-ready yet.

## What's in this repo

The public Fabric repo carries the **developer-facing adoption layer**
— Layer 1 in spec [012](specs/012-oss-commercialization-strategy.md).
All of it is Apache-2.0.

- **Fabric SDK (Python)** — `Fabric` client, `Decision` context
  manager, guardrail + escalation + retrieval types, framework
  adapters for LangGraph, Microsoft Agent Framework, and CrewAI.
  See [`sdk/python/`](sdk/python/).
- **Guardrail sidecars** — Presidio (PII redaction) and NeMo
  Guardrails (Colang rails), exposed over Unix domain sockets.
- **OTel Collector distribution** — an OpenTelemetry Collector build
  with the Fabric-standard processor chain pre-configured.
- **Reference agent** — end-to-end example that exercises the happy
  path. See [`examples/reference-agent/`](examples/reference-agent/).
- **Helm chart** — for deploying Layer 1 components inside a tenant
  VPC.
- **Specs** — the design of record in [`specs/`](specs/).

`pip install singleaxis-fabric`, `helm install fabric`, no signup, no
phone-home.

## What's not in this repo

Fabric's commercial surface — advanced Context Graph analytics,
cross-trace pattern detection, signed rubric content, evidence bundle
generation, auditor-grade compliance dashboards, reviewer workflows,
and the SingleAxis attestation network — is **not** open-source. It
lives as SingleAxis internal tooling and, in time, as commercial
products.

This is a deliberate choice. See [`specs/012-oss-commercialization-strategy.md`](specs/012-oss-commercialization-strategy.md)
for the full layer model and rationale.

## The OSS and services

| Door | For whom | What you get | Cost |
|------|----------|-------|------|
| **OSS (Layer 1)** | Engineering teams instrumenting an agent for traceability and inline guardrails | The code in this repo | Free (Apache-2.0) |
| **Services** (SingleAxis) | Regulated enterprises needing implementation, rubric authoring, managed operations, and evidence preparation | Layer 1 + SingleAxis's internal tooling and expertise | Commercial engagement |

Both sides are honest about what they are. The OSS is genuinely useful
standalone. The services are where SingleAxis's accumulated expertise
lives. See [`specs/013-design-partner-model.md`](specs/013-design-partner-model.md)
for the current engagement model.

## Getting started

Fabric is pre-alpha. The shortest path to running code:

1. [`docs/quickstart.md`](docs/quickstart.md) — install the SDK,
   wrap one agent turn, see telemetry in 5 minutes.
2. [`docs/architecture.md`](docs/architecture.md) — the 3-layer
   mental model (SDK / sidecars / collector).
3. [`docs/deployment.md`](docs/deployment.md) — Helm chart,
   profiles, what "audit-ready" means in Phase 1a.
4. [`examples/reference-agent/`](examples/reference-agent/) — a
   runnable end-to-end example exercising every SDK surface.

For the full design of record and positioning:

- [`specs/001-product-vision.md`](specs/001-product-vision.md) —
  positioning.
- [`specs/012-oss-commercialization-strategy.md`](specs/012-oss-commercialization-strategy.md)
  — what's in vs. out of this repo.
- [`sdk/python/README.md`](sdk/python/README.md) — SDK reference.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Fabric uses the
[Developer Certificate of Origin](https://developercertificate.org/)
(DCO) — every commit must be signed off (`git commit -s`).

## Security

To report a vulnerability, please follow the private disclosure process
in [`SECURITY.md`](SECURITY.md). **Do not** open a public issue for
security findings.

## Governance

Fabric is maintained by AI5Labs Research OPC Private Limited (SingleAxis) as an open project.
See [`GOVERNANCE.md`](GOVERNANCE.md) for decision-making, maintainer
appointment, and release processes.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE)
and [`NOTICE`](NOTICE).

SingleAxis, SASF, and the Fabric word mark are trademarks of AI5 Labs,
Inc. The trademarks are **not** licensed under Apache-2.0; see
[`GOVERNANCE.md`](GOVERNANCE.md) for the trademark policy.
