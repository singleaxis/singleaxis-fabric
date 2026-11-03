# Fabric documentation

> **Status:** index and map. The map below says, for each part of Fabric,
> whether it is built in the v0.8.0 release, built only on this branch, or
> only specified. Every page in `docs/` starts with its own status line.

## Map

### What Fabric is

Fabric OSS is a customer-controlled, passive recorder for AI agents:

```text
CAPTURE -> PROTECT -> DELIVER
```

It **captures** what an agent sends to its model and what comes back
(exact bytes, with no code change in Python), plus whatever the application
reports through the SDK. It **protects** each record inside the agent
process, before it reaches disk: a privacy mode per content role, keyed
pseudonyms for identifiers, encryption. It **delivers** the record
durably, through the Fabric Node, to a file directory or S3 store and an
OTLP destination the customer owns. An offline verifier,
`python -m fabric.reconstruct`, then states whether each run's record is
complete and unaltered.

Fabric is passive: it never approves, blocks, delays or modifies what the
agent does, and results and exceptions are unchanged. It does not evaluate,
judge or enforce anything; those uses consume the record elsewhere
([AGENTS.md](../AGENTS.md)). It never requires a SingleAxis service.

### The four chains of an agent run

[Spec 056](../specs/056-agent-action-reconstruction.md) states the goal of
the current work: for one production run, say what the agent did, which
model decision caused each action, and what independent evidence confirms
it. That needs four chains of evidence:

| Chain | Question | Source | State |
|---|---|---|---|
| Decisions | What did the model see and return? | Wire capture of model calls | Built (v0.8.0) |
| Actions | Which tools did the model ask for, with which arguments, and what result did the agent feed back? | Parsed offline from the captured model bodies | Pairing by id built (v0.8.0); per-chain verdict built on the branch (056 WP6-04) |
| Effects | What did the agent's process actually run? | Opt-in subprocess hook | Hook and attribution to tool calls built on the branch (056 WP6-03, WP6-04); AR-1 passes in hermetic mode, not yet run in CI |
| Corroboration | What did the operating system see? | Host sensors (auditd, eBPF) | Sensors built for the local profile; the join to effects built on the branch (056 WP6-05), read with `python -m fabric.reconstruct actions --host-records` ([agent action reconstruction](action-reconstruction.md)); AR-1 live mode (a real sensor) not yet run |

### Where things stand

| | What it contains |
|---|---|
| **Released: v0.8.0, on `main`** | Python wire capture (httpx, httpx2, aiohttp); the PROTECT stage, production profile gate, encryption at rest and source authentication (049 phases P0 and P0-A); the agent spool and sender; the Fabric Node; `fabric.reconstruct` with integrity verdicts; the explicit APIs in Python and TypeScript; qualified-run mode; host sensors in the local profile; Helm chart and Compose files. |
| **Built on this branch (`feat/action-record`), not released** | Most of 049 phase P1 ([spec 050](../specs/050-run-structure-and-records-p1.md)): one allocator for both inputs, the records input, random epochs with registration, segments, seals, resume tokens, capture manifests, the segment graph and the step projection. See [the P1 run record](run-record.md). Also most of spec 056 milestone M1: the contracts and rule fixtures (WP6-01), the hooks foundation and `exec.subprocess` hook (WP6-02, WP6-03), effect-to-tool-call attribution, chain verdicts and the `actions` view (WP6-04), the process-tree join of host events and the `--host-records` option (WP6-05, WP6-06), and the AR-1 harness (WP6-06). See [agent action reconstruction](action-reconstruction.md). |
| **In progress on this branch** | Spec 056 milestone M1 acceptance: [AR-1](../qualification/action-record/README.md) passes in hermetic mode (real agent, hook, Node and verifier; recorded host-sensor events), and its live mode with a real eBPF or auditd sensor (CI, Linux) has not run yet. |
| **Specified only** | 050 P1-A and the `decision()` move onto the records input; specs [051](../specs/051-context-and-lifecycle-p2.md) (P2), [052](../specs/052-decisions-and-effects-p3.md) (P3), [053](../specs/053-execution-channels-p4.md) (P4, except the part 056 moves forward), [054](../specs/054-specialised-runtimes-p5.md) (P5), [055](../specs/055-typescript-wire-capture.md) (TypeScript wire capture); spec 056 milestone M2. |

[specs/README.md](../specs/README.md) gives the status of every spec, and
[limitations and roadmap](limitations-and-roadmap.md) what v0.8.0 does not
do.

### Where the code lives

| Path | What it is | State |
|---|---|---|
| [`sdk/python/src/fabric/wire/`](../sdk/python/src/fabric/wire/) | Wire capture: transport tees (`_transport.py`, `_aiohttp.py`), endpoint matching (`_match.py`), the capture worker (`_pipeline.py`), PROTECT (`_protect.py`), the production gate (`_policy.py`), spool and sender (`_spool.py`, `_sender.py`), `install()`, `run()`, resume tokens (`__init__.py`) | Built (v0.8.0); P1 additions on the branch |
| [`sdk/python/src/fabric/reconstruct/`](../sdk/python/src/fabric/reconstruct/) | The offline verifier: span readers (`_inputs.py`), integrity (`_verify.py`, `_report.py`), tool-call and conversation stitching (`_stitch.py`), segment graph (`_graph.py`), step projection (`_project.py`, `_fields_model.py`); effect attribution, chain verdicts and the `actions` view (`_attribute.py`); host-sensor reader and process join (`_host.py`) | Built (v0.8.0); graph, projection, attribution and host join on the branch |
| [`sdk/python/src/fabric/`](../sdk/python/src/fabric/) (top level) | Shared allocator and pseudonyms (`_sequence.py`, `_identity.py`), content roles (`_roles.py`), records input (`_records.py`), segments (`_segments.py`), seals (`_seal.py`), manifests (`_manifest.py`); explicit APIs (`decision.py`, `call_recorder.py`, `byte_evidence.py`, `adapters/`); qualified-run mode (`qualified_run.py`, `receipt_sets.py`, `independent_feed.py`) | Explicit APIs built (v0.8.0); P1 modules on the branch |
| [`sdk/python/src/fabric/hooks/`](../sdk/python/src/fabric/hooks/) | Opt-in hooks: install, status, disable and close, patch ownership and the records-input producer (`__init__.py`, `_config.py`, `_patches.py`, `_guard.py`, `_producer.py`); the `exec.subprocess` observer (`_exec.py`) | Built on the branch (056 WP6-02, WP6-03), not released |
| [`sdk/typescript/src/`](../sdk/typescript/src/) | TypeScript SDK: explicit APIs only (`decision.ts`, `byte-evidence.ts`, `identity.ts`, ...) | Built (v0.8.0); no wire capture |
| [`components/otel-collector-fabric/`](../components/otel-collector-fabric/) | The Fabric Node: `gate/` (`fabric-gate`), `processor/fabricguardprocessor/`, `exporter/fabriccontentexporter/`, `extension/` (`fabricenvelope`, `noredirect`), `receiver/auditreceiver/` (auditd host sensor) | Built (v0.8.0); records class on the branch |
| [`components/host-emitter/`](../components/host-emitter/) | eBPF host sensor (Go and a CO-RE BPF program in `bpf/`) | Built (v0.8.0), local profile only |
| [`contracts/`](../contracts/) | Versioned JSON schemas, registries and fixtures; [`coverage/v1/registry/`](../contracts/coverage/v1/registry/) is the source of truth for field ids, capture points, content roles and vocabularies | Published or draft (see [Public contracts](#public-contracts)) |
| [`scripts/contracts/`](../scripts/contracts/) | Contract validators and reference implementations (`p1_reference.py`, `action_reference.py`) | Built |
| [`scripts/tests/`](../scripts/tests/) | Repository tests: contracts, release boundary, Compose and Node end-to-end | Built |
| [`qualification/action-record/`](../qualification/action-record/README.md) | AR-1, the spec 056 acceptance scenario (hermetic and live) | On the branch; hermetic mode passes |
| [`charts/fabric/`](../charts/fabric/), [`deploy/`](../deploy/README.md) | Helm chart for the Node; Compose files, auditd rules, a host-emitter DaemonSet | Built (v0.8.0) |
| [`tools/fabricctl/`](../tools/fabricctl/README.md) | Local recorder configuration CLI | Built (v0.8.0) |
| [`examples/`](../examples/README.md) | Runnable examples; start with `wire-capture/` | Built |
| [`specs/`](../specs/README.md) | Design of record | See its index |

### Reading order

For a first reading:

1. [Architecture](architecture.md): components and data flow of v0.8.0.
2. [Quickstart](quickstart.md): run the offline example, then break the
   record and watch the verdict change.
3. [Reconstruct and verdicts](reconstruct.md) and
   [privacy and security](privacy-and-security.md): what a verdict means
   and how the record is protected.
4. [Glossary](glossary.md): keep it open while reading the specs.
5. [Spec 049](../specs/049-four-layer-capture-coverage.md) §1–§2 and §6:
   the record model (four layers, coverage statuses, verdicts). Sections 3
   and 4 are reference tables.
6. [The P1 run record](run-record.md) and
   [spec 050](../specs/050-run-structure-and-records-p1.md) §3: what this
   branch adds.
7. [Spec 056](../specs/056-agent-action-reconstruction.md): the current
   goal; it cites the sections of [053](../specs/053-execution-channels-p4.md)
   it builds on.

## Use Fabric

| Page | What it covers | Describes |
|---|---|---|
| [Quickstart](quickstart.md) | Offline example and zero-code capture through a local Node | v0.8.0 |
| [Architecture](architecture.md) | Components, data flow, what ships | v0.8.0 |
| [Deployment](deployment.md) | Compose and Helm, local and production profiles, required keys and policy, upgrade notes | v0.8.0 |
| [Privacy and security](privacy-and-security.md) | Protection modes, pseudonyms, encryption at rest, source authentication, threat model | v0.8.0 |
| [Operations](operations/README.md) | Spool, queues, health, metrics, troubleshooting, upgrades; [recovery runbook](operations/dr.md) | v0.8.0 |
| [Reconstruct and verdicts](reconstruct.md) | The offline verifier, gaps and verdicts | v0.8.0 |
| [The P1 run record](run-record.md) | Shared allocator, records input, segments, seals, manifests, step projection | This branch only |
| [Agent action reconstruction](action-reconstruction.md) | The subprocess hook, a host sensor, effects linked to tool calls and host events, `python -m fabric.reconstruct actions`, what is not covered yet | This branch only |
| [Explicit APIs](explicit-apis.md) | `decision()`/`record_*`, `ByteEvidenceRecorder`, `CallRecorder`, byte-boundary adapters (Python and TypeScript) | v0.8.0 |
| [Qualified-run mode](qualified-run-mode.md) | Opt-in receipt- and witness-backed verification | v0.8.0 |
| [Host sensors](host-sensors.md) | auditd receiver and eBPF host emitter | v0.8.0 |
| [Limitations and roadmap](limitations-and-roadmap.md) | What is not captured, known defects, the roadmap | v0.8.0 and plans |

## Reference

- [Glossary](glossary.md): every term the specs use.
- [GenAI semantic conventions](genai-semantic-conventions.md): span and
  attribute names emitted by the decision API.
- [API stability](api-stability.md): compatibility commitments.
- [Verify a release](verify-release.md): signatures, provenance and release
  qualification.
- SDKs: [Python](../sdk/python/README.md), [TypeScript](../sdk/typescript/README.md);
  [Fabric Node](../components/otel-collector-fabric/README.md);
  [Compose](../deploy/compose/README.md).
- Specifications: [specs/](../specs/README.md). The current capture
  contract is [049](../specs/049-four-layer-capture-coverage.md), with
  [047](../specs/047-llm-wire-capture-and-reconstruction.md) (wire capture
  and reconstruction) and
  [048](../specs/048-node-content-delivery-and-agent-spool.md) (Node
  content delivery and the agent spool).

## Public contracts

Published in the v0.8 contracts archive:
[Activity Envelope v2](../contracts/activity/v2/README.md),
[connector capability v1](../contracts/connect/v1/README.md),
[content objects and transcript manifests v1](../contracts/content/v1/README.md),
[delivery batch and receipt v1](../contracts/delivery/v1/README.md),
[privacy assertion v1](../contracts/privacy/v1/README.md),
[recorder configuration v1](../contracts/recorder/v1/README.md).

In the repository as drafts (used by v0.8 code, not in the published
archive): [capture v1](../contracts/capture/v1/README.md),
[content v2](../contracts/content/v2/README.md),
[coverage v1](../contracts/coverage/v1/README.md),
deployment-policy v1 (`contracts/deployment-policy/v1`),
[evidence v1](../contracts/evidence/v1/README.md),
[redaction v1](../contracts/redaction/v1/README.md).

## Contributors and maintainers

- [Building Fabric](building-fabric.md)
- [Contributing](../CONTRIBUTING.md): environment setup and tests
- [Third-party licenses](licenses/README.md)
- [Historical secret-scan triage](security-history-triage.md)
- [Archive](archive/README.md): superseded documents, kept for history.
