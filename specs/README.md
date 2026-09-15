# SingleAxis Fabric — Design of Record

This directory is the **source of truth** for Fabric's product positioning,
architecture, and major design decisions. Every non-trivial change to the
codebase must either implement something here or come with a spec change.

## How specs are numbered

Specs are numbered with a three-digit zero-padded prefix. New specs take
the next unused number. Numbers are never reused; a superseded spec
remains in place with `Status: superseded by NNN`.

Numbers 013-018 and 024 are reserved. They are intentionally absent here; the
next unused public number is 028.

Spec [027](027-recorder-v1.md) is the authoritative product and release scope
for the first stable OSS recorder. Older capability specs remain as historical
design records or optional implementation references; they do not add artifacts
to the recorder release unless 027 is revised first.

## Status values

Every spec declares a `Status` in its header:

| Status | Meaning |
|--------|---------|
| `draft` | Under discussion; not binding |
| `accepted` | Decided; implementation may begin |
| `implemented` | Behaviour in the code matches the spec |
| `deprecated` | No longer recommended but still supported |
| `superseded` | Replaced by a newer spec (points to successor) |

## How to propose a change

1. Open a pull request that adds a new spec under `specs/` with
   `Status: draft`, or modifies an existing one.
2. Allow 7 calendar days of discussion (lazy consensus; see
   [`../GOVERNANCE.md`](../GOVERNANCE.md)).
3. On acceptance, the PR is merged with `Status: accepted`.
4. When implementation lands, update to `Status: implemented` in a
   follow-up PR.

## Index

| # | Title | Status |
|---|-------|--------|
| [000](000-overview.md) | Overview & conventions | accepted |
| [001](001-product-vision.md) | Product vision & positioning | accepted |
| [002](002-architecture.md) | Eight-layer architecture & Fabric Control Plane | accepted |
| [003](003-decision-graph.md) | Decision Graph — unified provenance artifact | accepted |
| [004](004-telemetry-bridge.md) | Telemetry Bridge & sanitized egress | accepted |
| [005](005-guardrails-inline.md) | Inline guardrails & latency budget | draft |
| [006](006-llm-as-judge.md) | LLM-as-Judge architecture | implemented |
| [007](007-escalation-workflow.md) | Escalation, pause, and SASF review loop | implemented |
| [008](008-deployment-model.md) | Deployment model & Helm chart | accepted |
| [009](009-compliance-mapping.md) | Regulation-to-layer mapping | accepted |
| [010](010-development-standards.md) | Development, testing, and release standards | accepted |
| [011](011-roadmap.md) | Phased execution roadmap | draft |
| [012](012-oss-commercialization-strategy.md) | Public distribution architecture | accepted |
| [019](019-policy-engine.md) | Policy Engine — decision-level policy evaluation primitive | implemented |
| [020](020-execution-step-capture.md) | Execution & Step capture — outer correlation + lifecycle primitives | implemented |
| [021](021-replay-metadata.md) | ReplayMetadata envelope — emit-only reconstruction metadata | implemented |
| [022](022-surface-logging.md) | Agent surface logging — MCP inventory, skills, delegation, hooks, file access | implemented |
| [023](023-generic-interaction-capture.md) | Generic interaction capture — universal primitive, baseline, tags, signatures | implemented |
| [025](025-product-planes-and-packaging.md) | Product planes, packaging, and deployment model | superseded |
| [026](026-fabricctl-lifecycle.md) | `fabricctl` lifecycle and deployment bundle | accepted |
| [027](027-recorder-v1.md) | Recorder-first OSS release | accepted |
