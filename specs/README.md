# SingleAxis Fabric — Design of Record

This directory is the **source of truth** for Fabric's product positioning,
architecture, and major design decisions. Every non-trivial change to the
codebase must either implement something here or come with a spec change.

New to the specs? Read the [documentation map](../docs/README.md#map)
first, and keep the [glossary](../docs/glossary.md) open: it defines every
term, rule label and decision code the specs use.

## How specs are numbered

Specs are numbered with a three-digit zero-padded prefix. New specs take
the next unused number. Numbers are never reused. A superseded or replaced
spec that still describes in-scope recorder work keeps its number and either
stays in the index with status `superseded` or moves to
[`archive/`](archive/). A spec that describes capabilities outside the OSS
scope (see [`../AGENTS.md`](../AGENTS.md)) is deleted, not archived; its
history lives in git and its number is retired.

Numbers 013-018 and 024 were never used. The next unused number is 058.

**Current work:** spec [056](056-agent-action-reconstruction.md) —
reconstructing everything an agent did in a run: the model decisions, the
tool calls they asked for, the commands and effects those caused, and
independent host-sensor evidence that corroborates them.

The current capture contract is spec
[049](049-four-layer-capture-coverage.md) (four-layer coverage, rev 6.4; P0 and
P0-A are built in v0.8; P1 waves 0–2 are released in v0.10). Its
phases P1–P5 and the TypeScript wire track are specified by the phase build
specs
[050](050-run-structure-and-records-p1.md) (P1),
[051](051-context-and-lifecycle-p2.md) (P2),
[052](052-decisions-and-effects-p3.md) (P3),
[053](053-execution-channels-p4.md) (P4),
[054](054-specialised-runtimes-p5.md) (P5) and
[055](055-typescript-wire-capture.md) (TS-1). 049 builds on [047](047-llm-wire-capture-and-reconstruction.md)
(wire capture and reconstruction) and
[048](048-node-content-delivery-and-agent-spool.md) (Node content delivery
and the agent spool). Where they disagree, 049 wins over 048 and 048 over
047. Spec [027](027-recorder-v1.md) remains the product boundary of the
OSS recorder (CAPTURE -> PROTECT -> DELIVER). Specs describing capabilities outside
that scope (guardrails, judges, evaluation, red-teaming, policy engines, the
telemetry bridge, the deployment-bundle lifecycle, platform architecture,
regulatory control mappings) were removed when the recorder scope became
authoritative; their history lives in git.

## Status values

Every spec declares a `Status` in its header:

| Status | Meaning |
|--------|---------|
| `draft` | Under discussion; not binding |
| `accepted` | Decided; implementation may begin |
| `implemented` | Behaviour in the code matches the spec |
| `deprecated` | No longer recommended but still supported |
| `implementation_in_progress` | Partly implemented; the spec lists the slices still open |
| `superseded` | Replaced by a newer spec (points to successor) |

Some specs also declare a `qualification` marker, shown after the status in
the index. `NO_GO` means the spec's work has not been qualified for customer
production use. `NO_COVERAGE_CLAIM` means the spec makes no claim that a
verdict covers activity outside the instrumented clients and endpoints it
lists.

A `superseded_in_part_by` field names a later spec that replaces part of an
otherwise current spec.

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
| [028](028-governed-content-capture.md) | Governed content capture and configuration | implemented |
| [029](029-content-objects-transcript-contract.md) | Content object and transcript manifest contracts | implemented |
| [030](030-auditd-host-connector.md) | auditd host connector | implemented; NO_GO |
| [031](031-ebpf-host-emitter.md) | eBPF host emitter | implemented; NO_GO |
| [032](032-passive-content-delivery.md) | Passive asynchronous content recording and durable delivery | implemented; partly superseded by 048 |
| [033](033-content-storage-resolution.md) | Customer content storage and authorized resolution | implemented |
| [034](034-transcript-export-and-qualification.md) | Transcript export and governed-content qualification | implemented |
| [035](035-agent-execution-evidence-profile.md) | Agent Execution Evidence Profile for OpenTelemetry | draft |
| [036](036-evidence-capture-implementation-plan.md) | Bounded agent evidence capture — implementation and conformance plan | superseded by 049 |
| [040](040-synthetic-agent-evidence-slice.md) | First bounded synthetic model-terminal-artifact evidence slice | superseded by 046 and 049; NO_GO |
| [042](042-client-boundary-integration.md) | Opt-in byte-boundary integration for existing Python agents | implemented; NO_GO |
| [043](043-custom-agent-call-recording.md) | Linked custom-agent calls, protected bytes and offline comparison | implemented; NO_GO |
| [044](044-production-evidence-closure.md) | Authenticated ingress, source metadata finalization and remaining proof gates | implementation in progress; NO_GO |
| [045](045-independent-evidence-feeds.md) | Authenticated independent operation and byte feeds | draft; NO_GO; no complete-run claim |
| [046](046-qualified-call-run-verification.md) | Qualified offline call-run comparison and exact delivery receipt sets | implemented (opt-in qualified-run mode); NO_GO |
| [047](047-llm-wire-capture-and-reconstruction.md) | LLM wire capture, exchange stitching and run reconstruction (Phase 1) | implemented; NO_COVERAGE_CLAIM; partly superseded by 048 |
| [048](048-node-content-delivery-and-agent-spool.md) | Node content delivery, agent durable spool and run scopes | implemented; NO_COVERAGE_CLAIM |
| [049](049-four-layer-capture-coverage.md) | Four-layer capture contract: context, structure, content, decisions and effects (field inventory, coverage statuses, projection, phases P0–P5) | accepted (rev 6.4); P0-A implemented (v0.8), P1 implemented (v0.10) except WP-15 and WP-21, P1-A and P2–P5 not built; NO_COVERAGE_CLAIM |
| [050](050-run-structure-and-records-p1.md) | Run structure, records input and model-call projection (049 P1 and P1-A) | draft; P1 implemented (v0.10) except WP-15 and WP-21 ([run record](../docs/run-record.md)), P1-A not built; NO_COVERAGE_CLAIM |
| [051](051-context-and-lifecycle-p2.md) | Run context and lifecycle reporting (049 P2) | draft; NO_COVERAGE_CLAIM |
| [052](052-decisions-and-effects-p3.md) | Decisions and effects records, record-only (049 P3) | draft; NO_COVERAGE_CLAIM |
| [053](053-execution-channels-p4.md) | Execution channels — opt-in observed hooks and production host sources (049 P4) | draft; hooks foundation and subprocess hook implemented for 056 M1 (v0.10); host ingress, production host sensors and the non-model HTTP hook implemented for 056 M2 (v0.11); the rest not built; NO_COVERAGE_CLAIM |
| [054](054-specialised-runtimes-p5.md) | Specialised runtimes and media — provider endpoints, realtime and automation (049 P5) | draft; NO_COVERAGE_CLAIM |
| [055](055-typescript-wire-capture.md) | TypeScript model-call wire capture for Node.js agents (TS-1) | draft; NO_COVERAGE_CLAIM |
| [056](056-agent-action-reconstruction.md) | **Agent action reconstruction** — linking model decisions, tool calls, effects and host evidence (current work) | draft; M1 implemented (v0.10, [action reconstruction](../docs/action-reconstruction.md)); AR-1 passes in CI, hermetic and live (Linux, eBPF); M2, the production profile, implemented (v0.11); AR-1 production passes in CI (replay, live, auditd); NO_COVERAGE_CLAIM |
| [057](057-security-context-recording.md) | Security context recording — permissions, control decisions, hooks and extensions, captured at the boundaries every agent crosses (model wire, tool protocols, process and OS, network, OTLP; record-only; extends 049 D01–D11 and C30–C33) | draft (rev 2); NO_COVERAGE_CLAIM |

Specs 036 and 040–046 are the design of record for the explicit evidence
line (`CallRecorder`, byte-boundary adapters, qualified-run mode), which
v0.8 still ships; their `NO_GO` qualification statements describe the state
when each was written. Spec 049 §2.13 keeps qualified-run mode unchanged.

## Archive

Superseded or replaced specs, kept for history. Their numbers are not
reused.

| # | Title | Why archived |
|---|-------|--------------|
| [038](archive/038-capture-boundary-and-loss-qualification.md) | Capture-boundary and source-loss qualification | draft qualification contract; replaced by 049 coverage statuses and phase gates |
| [039](archive/039-storage-release-and-shadow-pilot.md) | Protected storage, exact-artifact release, and shadow-pilot qualification | draft storage and shadow-pilot qualification; replaced by 049 §7.8 and its gates |
| [041](archive/041-follow-on-evidence-adapter-scopes.md) | Separately scoped SSH, DB, browser/cloud, sandbox and other adapters | draft follow-on adapter scopes; replaced by 049 P4/P5 |

### Retired numbers

Specs 001–009, 011, 012, 019, 025, 026 and 037 described capabilities
outside the OSS scope and were deleted: product vision (001), platform
architecture (002), decision graph (003), telemetry bridge (004), inline
guardrails (005), LLM-as-judge (006), escalation workflow (007), deployment
model (008), compliance mapping (009), roadmap (011), commercialization
(012), policy engine (019), product planes and packaging (025), fabricctl
lifecycle (026) and enterprise deployment and controls (037). Spec 027
supersedes 001 and 025; the spec 049 production profile replaces 037. Their
history lives in git, and their numbers are not reused.

Superseded documentation pages are handled differently from specs: the
former `docs/archive/` pages were deleted rather than archived, because each
had a current replacement under [`../docs/`](../docs/README.md). Their
history lives in git.
