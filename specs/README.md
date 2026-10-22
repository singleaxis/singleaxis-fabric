# SingleAxis Fabric — Design of Record

This directory is the **source of truth** for Fabric's product positioning,
architecture, and major design decisions. Every non-trivial change to the
codebase must either implement something here or come with a spec change.

## How specs are numbered

Specs are numbered with a three-digit zero-padded prefix. New specs take
the next unused number. Numbers are never reused. A superseded, withdrawn or
replaced spec keeps its number and moves to [`archive/`](archive/), where
it stays readable for history.

Numbers 013-018 and 024 are reserved. They are intentionally absent here; the
next unused public number is 050.

For the v0.8 release, the current capture contract is spec
[049](049-four-layer-capture-coverage.md) (four-layer coverage; P0-A is
built, P1–P5 are not), building on [047](047-llm-wire-capture-and-reconstruction.md)
(wire capture and reconstruction) and
[048](048-node-content-delivery-and-agent-spool.md) (Node content delivery
and the agent spool). Where they disagree, 049 wins over 048 and 048 over
047. Spec [027](027-recorder-v1.md) remains the product boundary of the
OSS recorder (CAPTURE -> PROTECT -> DELIVER). Specs describing capabilities outside
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
| [010](010-development-standards.md) | Development, testing, and release standards | accepted |
| [020](020-execution-step-capture.md) | Execution & Step capture — outer correlation + lifecycle primitives | implemented |
| [021](021-replay-metadata.md) | ReplayMetadata envelope — emit-only reconstruction metadata | implemented |
| [022](022-surface-logging.md) | Agent surface logging — MCP inventory, skills, delegation, hooks, file access | implemented |
| [023](023-generic-interaction-capture.md) | Generic interaction capture — universal primitive, baseline, tags, signatures | implemented |
| [027](027-recorder-v1.md) | Recorder-first OSS release | accepted |
| [028](028-governed-content-capture.md) | Governed content capture and configuration | draft |
| [029](029-content-objects-transcript-contract.md) | Content object and transcript manifest contracts | draft |
| [030](030-auditd-host-connector.md) | auditd host connector | implemented, not enterprise-qualified |
| [031](031-ebpf-host-emitter.md) | eBPF host emitter | implemented, not enterprise-qualified |
| [032](032-passive-content-delivery.md) | Passive asynchronous content recording and durable delivery | draft |
| [033](033-content-storage-resolution.md) | Customer content storage and authorized resolution | draft |
| [034](034-eval-interoperability.md) | External evaluation interoperability and qualification | draft |
| [035](035-agent-execution-evidence-profile.md) | Agent Execution Evidence Profile for OpenTelemetry | draft |
| [036](036-evidence-capture-implementation-plan.md) | Bounded agent evidence capture — implementation and conformance plan | draft |
| [040](040-synthetic-agent-evidence-slice.md) | First bounded synthetic model-terminal-artifact evidence slice | draft; NO-GO |
| [042](042-client-boundary-integration.md) | Opt-in byte-boundary integration for existing Python agents | draft; test-start only |
| [043](043-custom-agent-call-recording.md) | Linked custom-agent calls, protected bytes and offline comparison | implementation in progress; NO-GO |
| [044](044-production-evidence-closure.md) | Authenticated ingress, source metadata finalization and remaining proof gates | implementation in progress; NO-GO |
| [045](045-independent-evidence-feeds.md) | Authenticated independent operation and byte feeds | draft; no complete-run claim |
| [046](046-qualified-call-run-verification.md) | Qualified offline call-run comparison and exact delivery receipt sets | implementation in progress; NO-GO |
| [047](047-llm-wire-capture-and-reconstruction.md) | LLM wire capture, exchange stitching and run reconstruction (Phase 1) | draft; NO_COVERAGE_CLAIM; partly superseded by 048 |
| [048](048-node-content-delivery-and-agent-spool.md) | Node content delivery, agent durable spool and run scopes | draft; NO_COVERAGE_CLAIM |
| [049](049-four-layer-capture-coverage.md) | Four-layer capture contract: context, structure, content, decisions and effects (field inventory, coverage statuses, projection, phases P0–P5) | final rev 6.3, owner-approved 2026-10-18; P0-A built, P1–P5 not built; NO_COVERAGE_CLAIM |

Specs 036 and 040–046 are the design of record for the explicit evidence
line (`CallRecorder`, byte-boundary adapters, qualified-run mode), which
v0.8 still ships; their NO-GO qualification statements describe the state
when each was written. Spec 049 §2.13 keeps qualified-run mode unchanged.

## Archive

Superseded or replaced specs, kept for history. Their numbers are not
reused.

| # | Title | Why archived |
|---|-------|--------------|
| [001](archive/001-product-vision.md) | Product vision & positioning | superseded by 027 |
| [025](archive/025-product-planes-and-packaging.md) | Product planes, packaging, and deployment model | superseded by 027 |
| [037](archive/037-bounded-enterprise-deployment-and-controls.md) | Bounded enterprise evidence deployment and control applicability | draft enterprise go/no-go plan; replaced by the 049 production profile (enterprise modules removed) |
| [038](archive/038-capture-boundary-and-loss-qualification.md) | Capture-boundary and source-loss qualification | draft qualification contract; replaced by 049 coverage statuses and phase gates |
| [039](archive/039-storage-release-and-shadow-pilot.md) | Protected storage, exact-artifact release, and shadow-pilot qualification | draft storage and shadow-pilot qualification; replaced by 049 §7.8 and its gates |
| [041](archive/041-follow-on-evidence-adapter-scopes.md) | Separately scoped SSH, DB, browser/cloud, sandbox and other adapters | draft follow-on adapter scopes; replaced by 049 P4/P5 |
