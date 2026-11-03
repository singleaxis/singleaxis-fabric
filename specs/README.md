# SingleAxis Fabric — Design of Record

This directory is the **source of truth** for Fabric's product positioning,
architecture, and major design decisions. Every non-trivial change to the
codebase must either implement something here or come with a spec change.

New to the specs? Read the [documentation map](../docs/README.md#map)
first, and keep the [glossary](../docs/glossary.md) open: it defines every
term, rule label and decision code the specs use.

## Where to start

- Spec [027](027-recorder-v1.md) is the product boundary of the OSS
  recorder: CAPTURE -> PROTECT -> DELIVER, passive, no evaluation or
  enforcement.
- Spec [049](049-four-layer-capture-coverage.md) is the current capture
  contract (four layers, coverage statuses, verdicts, build phases P0–P5).
  It builds on [047](047-llm-wire-capture-and-reconstruction.md) (wire
  capture and reconstruction) and
  [048](048-node-content-delivery-and-agent-spool.md) (Node content delivery
  and the agent spool). Where they disagree, 049 wins over 048 and 048 over
  047.
- Specs [050](050-run-structure-and-records-p1.md)–[055](055-typescript-wire-capture.md)
  are build specs for the phases of 049.
- Spec [056](056-agent-action-reconstruction.md) is the current goal:
  linking model decisions, tool calls, effects and host evidence for one
  run. It selects parts of 050 and 053 and moves them earlier.

Specs describing capabilities outside the recorder scope (guardrails,
judges, policy engines, the telemetry bridge, the deployment-bundle
lifecycle, platform architecture) were removed when the recorder scope
became authoritative; their history lives in git.

## Status values

Every spec declares a status in its header. This index uses four values:

| Status | Meaning |
|--------|---------|
| `draft` | Written and under discussion; not binding. Code may already exist for parts of it: the "Built code" column says so. |
| `accepted` | Decided; implementation may begin or has begun. |
| `implemented` | The code matches the spec. |
| `superseded` | Replaced by a newer spec; kept in [`archive/`](archive/) for history. |

Two headers use older values: `implemented-not-enterprise-qualified` (030,
031) is shown as `implemented`, and `implementation_in_progress` (043, 044)
as `draft`.

Some specs also declare a `qualification` marker, shown in the index.
`NO_GO` means the spec's work had not been qualified for production use
when it was written. `NO_COVERAGE_CLAIM` means the spec claims no coverage
beyond the instrumented clients and endpoints it lists.

"Built code" says what exists. **v0.8.0** is the released code on `main`.
**This branch** is `feat/action-record`, which is not released.

## Index

| # | Plain description | Status | Built code |
|---|---|---|---|
| [000](000-overview.md) | Conventions for writing and numbering specs | accepted | — (process) |
| [010](010-development-standards.md) | Development, testing and release standards | accepted | — (process; enforced by CI) |
| [020](020-execution-step-capture.md) | Execution and step ids that correlate the explicit `decision()` records of one task, with retries | implemented | v0.8.0: `fabric/execution.py`, `decision.py` |
| [021](021-replay-metadata.md) | A `fabric.replay` span event bundling the metadata a downstream replay tool needs; Fabric only emits it | implemented | v0.8.0: `decision.py` (`record_replay_metadata`) |
| [022](022-surface-logging.md) | Explicit records of an agent's surfaces: MCP inventory, skills, delegation, hooks, file access | implemented | v0.8.0: `decision.py`, `integrations/mcp.py` |
| [023](023-generic-interaction-capture.md) | A generic `record_interaction` primitive, approved-hash baselines and taxonomy tags | implemented | v0.8.0: `decision.py`, `baseline.py`, `taxonomy.py` |
| [027](027-recorder-v1.md) | The recorder-first OSS release and its product boundary | accepted | v0.8.0: release boundary enforced by `scripts/tests/test_recorder_release_boundary.py` |
| [028](028-governed-content-capture.md) | Opt-in capture of actual content to customer storage, with references on the telemetry | draft | Partly, explicit line, v0.8.0: `_content.py`, `_content_sink.py`, `content_store/` |
| [029](029-content-objects-transcript-contract.md) | Content-object descriptor, per-decision transcript manifest and exact-byte hashing rules | draft | v0.8.0: contract `contracts/content/v1` (published), `_content.py` |
| [030](030-auditd-host-connector.md) | auditd host sensor in the Node: process, connection and file metadata | implemented (not enterprise-qualified) | v0.8.0: `components/otel-collector-fabric/receiver/auditreceiver`; local profile only |
| [031](031-ebpf-host-emitter.md) | eBPF host sensor as a separate image | implemented (not enterprise-qualified) | v0.8.0: `components/host-emitter`; local profile only |
| [032](032-passive-content-delivery.md) | Moving content to the store without blocking the agent; durability modes and loss windows | draft | Partly, explicit line, v0.8.0: `_content_writer.py`; wire delivery follows 048 |
| [033](033-content-storage-resolution.md) | Customer content stores and authorized, verified reads of stored content | draft | Partly, v0.8.0: `content_store/`, `resolver.py`, `byte_resolver.py` |
| [034](034-eval-interoperability.md) | How an outside evaluator reads recorded content; Fabric ships the format, not an evaluator | draft | Examples only: `examples/offline-transcript`, `examples/governed-content` |
| [035](035-agent-execution-evidence-profile.md) | A vendor-neutral profile of OTLP and W3C Trace Context for agent execution evidence (AEEP) | draft | Draft contract only: `contracts/evidence/v1` |
| [036](036-evidence-capture-implementation-plan.md) | Build plan and acceptance tests for the AEEP profile | draft | — (plan) |
| [040](040-synthetic-agent-evidence-slice.md) | A first synthetic model → terminal → file → model evidence slice; NO_GO | draft | Explicit adapter, v0.8.0: `adapters/synthetic_evidence.py`; `qualification/synthetic-slice` |
| [042](042-client-boundary-integration.md) | Opt-in byte-boundary adapter for agents that expose their final request bytes; NO_GO | draft | v0.8.0: `adapters/byte_boundary.py` |
| [043](043-custom-agent-call-recording.md) | One linked record of a custom agent's model, tool and database calls with protected bytes; NO_GO | draft | Partly, v0.8.0: `call_recorder.py`, `call_reconcile.py` |
| [044](044-production-evidence-closure.md) | Authenticated Node ingress, source metadata and the remaining production proof gates; NO_GO | draft | Partly, v0.8.0: source binding in `fabricguardprocessor`, `evidence_attestation.py` |
| [045](045-independent-evidence-feeds.md) | Independent witness feeds as an offline verification input; NO_GO | draft | v0.8.0: `independent_feed.py`, `independent_store.py` |
| [046](046-qualified-call-run-verification.md) | Qualified-run mode: offline comparison against witnesses and signed receipt sets; NO_GO | accepted | v0.8.0: `qualified_run.py`, `receipt_sets.py` |
| [047](047-llm-wire-capture-and-reconstruction.md) | Zero-code capture of model HTTP calls and the offline verifier; NO_COVERAGE_CLAIM | implemented (partly superseded by 048) | v0.8.0: `wire/`, `reconstruct/` |
| [048](048-node-content-delivery-and-agent-spool.md) | Content delivery through the Node, the durable agent spool and run scopes; NO_COVERAGE_CLAIM | implemented | v0.8.0: `wire/_spool.py`, `wire/_sender.py`, `fabriccontentexporter` |
| [049](049-four-layer-capture-coverage.md) | The four-layer capture contract: field inventory, coverage statuses, projection, verdicts and build phases P0–P5; NO_COVERAGE_CLAIM | accepted | P0 and P0-A in v0.8.0; P1 mostly on this branch; P1-A to P5 not built |
| [050](050-run-structure-and-records-p1.md) | Build spec for P1: shared allocator, records input, segments, seals, manifests, step projection; and P1-A; NO_COVERAGE_CLAIM | draft | Partly, this branch: waves 0–2 except WP-15 and WP-21, plus an end-to-end test; P1-A not built. See [the P1 run record](../docs/run-record.md) |
| [051](051-context-and-lifecycle-p2.md) | Build spec for P2: reporting run context and lifecycle (trigger, inputs, outcome, delegation, checkpoints); NO_COVERAGE_CLAIM | draft | Not built |
| [052](052-decisions-and-effects-p3.md) | Build spec for P3: recording external control decisions, commit state and receipts, record-only; NO_COVERAGE_CLAIM | draft | Not built |
| [053](053-execution-channels-p4.md) | Build spec for P4: opt-in hooks (subprocess, file, database, HTTP, MCP, SSH) and production host-sensor ingress; NO_COVERAGE_CLAIM | draft | Hooks foundation and subprocess hook built on this branch for 056 (WP6-02, WP6-03); the rest not built |
| [054](054-specialised-runtimes-p5.md) | Build spec for P5: images, audio, realtime, batch, files, media and UI automation endpoints; NO_COVERAGE_CLAIM | draft | Not built |
| [055](055-typescript-wire-capture.md) | Build spec for TypeScript wire capture on Node.js (undici, `node:http`); NO_COVERAGE_CLAIM | draft | Not built |
| [056](056-agent-action-reconstruction.md) | Linking model decisions, tool calls, subprocess effects and host evidence for one run; NO_COVERAGE_CLAIM | draft | Milestone M1 in progress on this branch: WP6-01 to WP6-05 and WP6-07 merged; AR-1 harness (WP6-06) not built |

Paths in the "Built code" column without a top-level directory are
relative to `sdk/python/src/fabric/`.

Specs 036 and 040–046 are the design of record for the explicit evidence
line (`CallRecorder`, byte-boundary adapters, qualified-run mode), which
v0.8.0 still ships; their `NO_GO` statements describe the state when each
was written. Spec 049 §2.13 keeps qualified-run mode unchanged.

## How specs are numbered

Specs are numbered with a three-digit zero-padded prefix. New specs take
the next unused number; the next one is 057. Numbers are never reused. A
superseded, withdrawn or replaced spec keeps its number and moves to
[`archive/`](archive/), where it stays readable for history. Numbers that
appear in neither table were removed with the out-of-scope specs (their
history is in git) or are reserved (013–018 and 024).

## How to propose a change

1. Open a pull request that adds a new spec under `specs/` with
   `Status: draft`, or modifies an existing one.
2. Allow 7 calendar days of discussion (lazy consensus; see
   [`../GOVERNANCE.md`](../GOVERNANCE.md)).
3. On acceptance, the PR is merged with `Status: accepted`.
4. When implementation lands, update to `Status: implemented` in a
   follow-up PR.

## Archive

Superseded or replaced specs, kept for history. Their numbers are not
reused. All are `superseded`, whatever their header says.

| # | Title | Why archived |
|---|-------|--------------|
| [001](archive/001-product-vision.md) | Product vision & positioning | superseded by 027 |
| [025](archive/025-product-planes-and-packaging.md) | Product planes, packaging, and deployment model | superseded by 027 |
| [037](archive/037-bounded-enterprise-deployment-and-controls.md) | Bounded enterprise evidence deployment and control applicability | draft enterprise go/no-go plan; replaced by the 049 production profile (enterprise modules removed) |
| [038](archive/038-capture-boundary-and-loss-qualification.md) | Capture-boundary and source-loss qualification | draft qualification contract; replaced by 049 coverage statuses and phase gates |
| [039](archive/039-storage-release-and-shadow-pilot.md) | Protected storage, exact-artifact release, and shadow-pilot qualification | draft storage and shadow-pilot qualification; replaced by 049 §7.8 and its gates |
| [041](archive/041-follow-on-evidence-adapter-scopes.md) | Separately scoped SSH, DB, browser/cloud, sandbox and other adapters | draft follow-on adapter scopes; replaced by 049 P4/P5 |
