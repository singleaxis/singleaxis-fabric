---
title: OSS Distribution & Commercialization Strategy
status: draft
revision: 1
last_updated: 2026-04-20
owner: project-lead
---

# 012 — OSS Distribution & Commercialization Strategy

## Summary

Fabric is built in three layers, released on a three-phase customer
schedule, and commercialized through services-first economics that
transition to product-tier revenue as the services business generates
reusable patterns. The public OSS repo carries **Layer 1 only**. Layers 2
and 3 stay internal or proprietary until customer-derived learning has
been extracted.

This spec updates the earlier "same Fabric to both doors, no
feature-gating" framing in [001](001-product-vision.md) and the
feature-complete-OSS-by-phase framing in [011](011-roadmap.md). Those
specs will be revised in follow-up PRs to conform with this one.

## Goals

1. **Maximize Layer 1 adoption as a services lead funnel.** Every
   `pip install singleaxis-fabric` is a potential implementation conversation.
2. **Hold Layer 2 internally to encode SingleAxis's accumulated
   learning.** Cross-tenant pattern recognition, advanced Context Graph
   analytics, judge routing, and rubric content are services
   differentiation — not OSS giveaways.
3. **Ship Layer 3 as a proprietary product when the market asks for
   it.** Evidence bundles, audit reports, compliance dashboards, HITL
   workflows, signatures, and certification are future product revenue.
   Not distributed free.
4. **Sequence releases by customer milestones, not calendar time.** 0–3
   paying customers = Layer 1 only. 3–10 = harden Layer 2 internally.
   10+ = productize Layer 3.
5. **Never open-source a future product before extracting value from
   it.** This is the controlling principle. Any tension resolves in
   favor of holding leverage.

## Non-goals

1. **Not pure-Apache everything.** Prior plan-of-record (001) said "no
   feature-gating for commercial reasons." That rule is withdrawn. Some
   capabilities stay proprietary.
2. **Not a single-license repo.** The public Fabric repo is Apache-2.0.
   Internal tooling and proprietary products live in separate repos
   with separate licensing.
3. **Not a moat built on code secrecy.** The proprietary parts are
   *content* (rubrics, playbooks, corpus) and *process* (reviewer
   network, attestation) more than *code*. Code secrecy is tactical,
   not strategic.
4. **Not a closed distribution.** Layer 1 is and will remain Apache-2.0
   OSS. "Hold some layers internal" means they are not in the public
   repo at all — not that they are source-available with commercial
   restrictions.

## Design — the three layers

### Layer 1 — Developer Adoption (OSS, Apache-2.0)

**Purpose:** get installed, get used, generate inbound implementation
leads.

Includes:

- Fabric SDK (Python) — `Fabric` client, `Decision` context manager,
  guardrail types, escalation pause primitive, retrieval recording
- Framework adapters: LangGraph, Microsoft Agent Framework, CrewAI
- Guardrail sidecars: Presidio (PII redaction), NeMo Guardrails
  (Colang rails), exposed over UDS
- OTel Collector distribution with the Fabric-standard processor chain
- Reference agent demonstrating end-to-end happy path
- CLI for local install, upgrade, config
- Wire schema for the OTel attributes Fabric emits (so auditors and
  integrators can read them without our tooling)

Characteristics:

- Easy to install (`pip install`, `helm install`, no signup)
- Works locally, no phone-home
- Genuinely useful as a standalone tool — not crippled to force upgrade
- Released under Apache-2.0 in the public `singleaxis-fabric` repo

### Layer 2 — Decision Intelligence (internal)

**Purpose:** encode SingleAxis's accumulated expertise so consulting
engagements compound rather than reset each time.

Includes:

- Context Graph advanced features: cross-trace linkage, pattern
  detection, reasoning reconstruction beyond raw spans
- Telemetry Bridge — the tenant→SingleAxis sanitized egress path (how
  we observe cross-customer patterns)
- Judge routing, ensemble logic, confidence calibration
- Signed rubric content, benchmark corpus, calibration datasets
- Implementation playbooks (vertical-specific: HIPAA, SR 11-7,
  EU AI Act high-risk)
- Vertical-specific `values.yaml` presets
- Red-team corpora derived from client engagements

Characteristics:

- Lives in a private SingleAxis-internal repo, not the public Fabric
  tree
- Used to deliver services to design partners and implementation
  clients
- Not licensed, not distributed — services deliverable only
- Matures toward productization as patterns repeat across 3+ customers

### Layer 3 — Trust & Audit (future proprietary product)

**Purpose:** become the revenue tier once market demand is real.

Includes:

- Evidence bundle generator (signed, schema-validated, auditor-ready)
- Audit reports and compliance dashboards
- Auditor-grade UI (distinct from any developer-facing Admin UI)
- HITL workflows and reviewer queue
- Signing service, reviewer pool, attestation infrastructure (when
  built)
- Hosted evidence archive
- Cross-tenant incident signal aggregation
- Insured / certified rubric library

Characteristics:

- Not in any public OSS repo
- Not licensed to customers until productized
- Ships when a paying customer is asking for it, not on speculation

## Design — phased release by customer count

Each phase is gated on **SingleAxis's own paying services customers**,
not calendar time or feature completeness.

### Phase 1 — Zero to three customers (now)

- **Public repo:** Layer 1 only — SDK, adapters, sidecars, OTel
  collector, reference agent, CLI.
- **Internal:** Layer 2 infrastructure built as internal tooling to
  deliver services.
- **Proprietary:** Layer 3 deferred. Do not build the evidence bundle
  exporter in the public repo. Do not build the auditor-grade UI.
- **Pitch:** "We are the team that deploys AI systems safely in
  regulated environments. We have an internal system that makes it
  work."
- **Revenue model:** Implementation services. Retainer + deliverable.

### Phase 2 — Three to ten customers

- Layer 1 matures: more frameworks, more language SDKs (Go, TS), more
  rails, broader sidecar surface.
- Layer 2 hardens: pattern library grows from what's repeated across
  customers. Start packaging reusable templates (not products yet).
- Layer 3 begins: first drafts of evidence bundles written for specific
  customer audits. Not productized.
- **Pitch:** "We are the team whose system powers AI compliance for
  ${industry}. Here are ${count} case studies."
- **Revenue model:** Implementation services + Layer 2 managed tooling
  (delivered as part of the engagement, not licensed).

### Phase 3 — Ten-plus customers

- Layer 1 stable, documented, community contributions flowing.
- Layer 2 productized as a commercial offering (subscription or hosted,
  depending on fit).
- Layer 3 productized: evidence bundles, compliance dashboards,
  reviewer workflows ship as a named product.
- **Pitch:** "Fabric is the standard for audit-ready AI systems.
  SingleAxis certifies what Fabric produces."
- **Revenue model:** Implementation + Layer 2 subscription + Layer 3
  certification/audit fees.

## Design — licensing posture

- **Public Fabric repo:** Apache-2.0 for everything in-tree. No BSL, no
  AGPL, no dual-license tiers.
- **Trademark:** "SingleAxis", "SASF", and the "Fabric" word mark are
  trademarks of AI5 Labs, Inc. Not licensed under Apache-2.0. See
  `GOVERNANCE.md`.
- **Internal tooling:** private repo, no license granted to third
  parties.
- **Layer 3 product:** commercial license when it ships. Not disclosed
  in advance.

Licensing is the simplest possible story: Layer 1 is OSS, everything
else is SingleAxis's. Do not add dual-license tiers, contributor-license
gymnastics, or retroactive open-core pivots.

## Design — positioning

### External today

> "SingleAxis deploys AI systems safely in regulated environments. We
> ship Fabric — an open-source compliance-aware integration substrate —
> and provide implementation, configuration, and evidence preparation
> as a service."

### External in 12–18 months

> "Fabric is the open substrate for audit-ready AI systems. SingleAxis
> is the commercial operator: implementation, attestation, and
> evidence."

### Internal

> "Fabric is our unfair advantage. The OSS layer gets us on the laptop.
> The internal layer wins engagements. The product layer is the
> endgame."

Do **not** use "certification" language externally until the attestation
infrastructure (Layer 3) is real. "Audit-ready" is the current-phase
claim. "Certified by SingleAxis" is the Phase 3 claim.

## What changes in the repo

The current public repo contains components that are Layer 2 or Layer 3
under this spec. They will be moved to an internal SingleAxis repo
prior to any public release. Summary:

| Component | Current location | Disposition | Rationale |
|---|---|---|---|
| `sdk/` (all) | public | stays public | Layer 1 |
| `components/nemo-sidecar` | public | stays public | Layer 1 guardrail |
| `components/telemetry-bridge/presidio-sidecar` | public | stays public (move path out of bridge subtree) | Layer 1 guardrail |
| `components/otel-collector-fabric` | public | stays public | Layer 1 distribution |
| `examples/reference-agent` | public | stays public | Layer 1 adoption tool |
| `components/telemetry-bridge` (non-sidecar parts) | public | move internal | Cross-customer pattern observation (Layer 2) |
| `components/context-graph` (advanced features) | public | move internal | Cross-trace linkage, reasoning reconstruction (Layer 2) |
| `components/context-graph` (schema + basic ingest) | public | evaluate at Phase 2 entry | Could be Layer 1 if schema stops carrying learning |
| `components/judge-workers` (runtime) | public | stays public | Tenants run it inline (Layer 1) |
| `components/judge-workers` (routing, rubric content) | public | move internal | Routing + signed rubrics (Layer 2) |
| `components/escalation-service` | public | move internal | HITL workflow (Layer 3 territory) |
| `components/fabric-admin-ui` | public | move internal | Trends toward Layer 3 auditor-grade product |
| `components/redteam-runner` | public | evaluate at Phase 2 entry | Corpora become Layer 2; harness could stay Layer 1 |
| `components/update-agent` | public | stays public (pending review) | GitOps pull channel is infrastructure, not differentiation |

File moves are tracked separately (see task #68). **No file moves until
this spec is accepted.**

## Security considerations

This spec does not change security posture. Layer 1 components retain
their guardrail and isolation semantics. Layer 2/3 movement is
repo-structure only; data-path security (tenant-VPC-only for raw
content, sanitized-egress-only for Bridge) is unchanged.

## Operational considerations

- **Existing PRs and spec contributions** that target components moving
  to internal will need disposition: merge before move, rebase
  post-move, or close with a note.
- **Helm charts** in `charts/fabric/charts/*` that reference Layer 2/3
  components will need companion charts in the internal repo, or the
  public Fabric chart refactored to reference Layer 1 only.
- **CI** will split: public repo retains Layer 1 tests. Internal repo
  takes Layer 2/3.
- **Documentation** in `docs/` is generated from specs. Once this spec
  lands and 001/011 are revised, `docs/` rebuilds automatically.

## Principle (non-negotiable)

> **Never open-source a future product before extracting value from
> it.**

When in tension, this principle wins. "Open-source everything because
open-source is virtuous" is not the right trade when the company has no
product moat yet and services revenue is the only thing paying
salaries.

## Open questions

- **Q1.** Should the Context Graph schema + ingest be Layer 1 now, or
  held in Layer 2 through Phase 1? *Resolver: project lead. Deadline:
  before first design partner signs.*
- **Q2.** Does the OTel Collector distribution itself stay Layer 1, or
  is the Fabric-specific processor configuration a Layer 2 asset?
  *Resolver: security + product. Deadline: before Phase 2 entry.*
- **Q3.** When Layer 2 productizes (Phase 2/3), under what license?
  Commercial closed-source is default; open-core is on the table only
  if market dynamics demand it. *Resolver: project lead. Deadline: at
  Phase 2 entry.*
- **Q4.** Does the public repo roadmap hint at Layer 2/3, or stay
  silent to avoid telegraphing future commercial moves? *Resolver:
  project lead. Deadline: before 011 revision.*

## References

- [001 — Product Vision & Positioning](001-product-vision.md) — being
  revised to conform
- [011 — Phased Execution Roadmap](011-roadmap.md) — being revised to
  conform
- [013 — Design Partner Model](013-design-partner-model.md) — companion
  spec for Phase 1 execution
