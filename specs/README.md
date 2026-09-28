# SingleAxis Fabric — Design of Record

This directory is the **source of truth** for Fabric's product positioning,
architecture, and major design decisions. Every non-trivial change to the
codebase must either implement something here or come with a spec change.

## How specs are numbered

Specs are numbered with a three-digit zero-padded prefix. New specs take
the next unused number. Numbers are never reused; a superseded spec
remains in place with `Status: superseded by NNN`.

Numbers 013-018 and 024 are reserved. They are intentionally absent here; the
next unused public number is 040.

Spec [027](027-recorder-v1.md) is the authoritative product and release scope
for the first stable OSS recorder. Specs describing capabilities outside
that scope (guardrails, judges, policy engines, the telemetry bridge, the
deployment-bundle lifecycle, platform architecture) were removed when the
recorder scope became authoritative; their history lives in git.

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
| [001](001-product-vision.md) | Product vision & positioning | superseded |
| [010](010-development-standards.md) | Development, testing, and release standards | accepted |
| [020](020-execution-step-capture.md) | Execution & Step capture — outer correlation + lifecycle primitives | implemented |
| [021](021-replay-metadata.md) | ReplayMetadata envelope — emit-only reconstruction metadata | implemented |
| [022](022-surface-logging.md) | Agent surface logging — MCP inventory, skills, delegation, hooks, file access | implemented |
| [023](023-generic-interaction-capture.md) | Generic interaction capture — universal primitive, baseline, tags, signatures | implemented |
| [025](025-product-planes-and-packaging.md) | Product planes, packaging, and deployment model | superseded |
| [027](027-recorder-v1.md) | Recorder-first OSS release | accepted |
| [028](028-governed-content-capture.md) | Governed content capture and configuration | draft |
| [029](029-content-objects-transcript-contract.md) | Content object and transcript manifest contracts | draft |
| [030](030-auditd-host-connector.md) | auditd host connector | draft |
| [031](031-ebpf-host-emitter.md) | eBPF host emitter | draft |
| [032](032-passive-content-delivery.md) | Passive asynchronous content recording and durable delivery | draft |
| [033](033-content-storage-resolution.md) | Customer content storage and authorized resolution | draft |
| [034](034-eval-interoperability.md) | External evaluation interoperability and qualification | draft |
| [035](035-agent-execution-evidence-profile.md) | Agent Execution Evidence Profile for OpenTelemetry | draft |
| [036](036-evidence-capture-implementation-plan.md) | Bounded agent evidence capture — implementation and conformance plan | draft |
| [037](037-bounded-enterprise-deployment-and-controls.md) | Bounded enterprise evidence deployment and control applicability | draft |
| [038](038-capture-boundary-and-loss-qualification.md) | Capture-boundary and source-loss qualification | draft |
| [039](039-storage-release-and-shadow-pilot.md) | Protected storage, exact-artifact release, and shadow-pilot qualification | draft |
| [040](040-synthetic-agent-evidence-slice.md) | First bounded synthetic model-terminal-artifact evidence slice | draft; NO-GO |
| [041](041-follow-on-evidence-adapter-scopes.md) | Separately scoped SSH, DB, browser/cloud, sandbox and other adapters | draft; no coverage claim |
| [042](042-client-boundary-integration.md) | Opt-in byte-boundary integration for existing Python agents | draft; test-start only |
