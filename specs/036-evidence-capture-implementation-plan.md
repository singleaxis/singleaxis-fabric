---
title: Bounded agent evidence capture — implementation and conformance plan
status: draft
revision: 1
last_updated: 2026-09-26
owner: product-architecture
depends_on: 027, 028, 029, 030, 031, 032, 033, 035
---

# 036 — Bounded agent evidence capture: build plan

## Decision and current state

Build the [Agent Execution Evidence Profile (AEEP)](035-agent-execution-evidence-profile.md)
as an **optional, passive capture profile** on Fabric OSS's existing
`CAPTURE -> PROTECT -> DELIVER` plane. The profile is a Fabric proposal over
OTLP and W3C Trace Context, not an upstream standard. This spec is the
implementation backlog and acceptance contract; its `draft` status is **not**
permission to market the feature as shipped.

As of this revision, the repository has manual Python/TypeScript governed
content for supported text/JSON roles, versioned content-v1 descriptors and
per-decision manifests, a metadata allowlist in Fabric Node, and host
audit/eBPF prototypes. It does **not** have general terminal/PTY transcripts,
remote SSH-side evidence, DB result capture, HTTP/browser body capture, binary
artifact storage, run-level coverage reconciliation, or durable host-sensor
source queues. In particular, a host process/connection record is not an
agent transcript. The precise gap inventory is in
[agent activity coverage](../docs/agent-activity-coverage.md); the governed
content qualification state is in
[recorder-v1 qualification](../docs/recorder-v1-qualification-status.md).

This spec does not replace recorder v1 or expand it to evaluation, findings,
policy decisions, enforcement, or SingleAxis-managed storage. Dev/offline
evals may record transcripts locally without Fabric. In production, Fabric
can supply a protected record to a customer-selected destination; downstream
content-aware evaluation needs authorized access to the customer's content
objects **inside the permitted boundary**. Metadata-only OTLP is not enough
to grade an agent's actual prompts, results, or context.

## 1. Scope of a reconstruction claim

The only permitted completeness claim is **historical reconstruction of a
specified observable boundary**, not of an unconstrained agent. The customer
deployment declares a run scope before capture begins:

- workload/tenant identity, run ID, environment, source instances, and
  start/stop window;
- supported runtime and connector versions, sandbox/container images,
  namespaces, mounts, network egress paths, and remote hosts/services;
- required operation classes and content role families, plus explicit
  exclusions, redactions, and sampling policy; and
- independent source-of-truth feeds used to reconcile each claimed surface.

A run with an unknown process/remote host, missing source, disabled required
role, unobserved egress path, or unavailable reconciliation feed cannot be
`verified_complete_for_declared_scope`. Even a verified run does not prove
provider-hidden instructions/reasoning, deterministic model replay, unseen
external state, or a total order among concurrent sources. A record of
retrieval output is not proof that those bytes reached the model; provider-
bound request capture is required for that narrower claim. A file `open` is
not proof of bytes read or written. A local SSH socket is not remote command
or file evidence.

Deployment controls that limit tools/network/filesystems may make a bounded
claim testable, but Fabric itself must not enforce those controls or sit on
the monitored request path by default. Where a required source is bypassed,
the recorder emits a gap if it can detect one; undetectable bypass means the
run remains `unverified`, not `complete`.

## 2. Standards and compatibility rules

Use OTel trace spans for operations with duration, OTLP LogRecords with
`EventName` for evidence observations and state changes, W3C `traceparent`
and `tracestate` for supported authenticated propagation, and existing OTel
semantic conventions for GenAI, database, HTTP/RPC, messaging, and process
operations before adding `agent.evidence.*`. The OTel log data model is
stable, but OTel GenAI agent conventions, event conventions, and
`log.record.uid` are Development/opt-in at the researched revision. Pin an
exact semantic-convention release or commit and schema URL in producer
fixtures and manifests; do not follow upstream `main` at runtime. Preserve
unknown input fields only if explicitly allowed by privacy review; do not
rename old semantics silently.

OTel recommends opt-in for sensitive GenAI content and external storage for
production content, but currently leaves the common content-reference format
unspecified. AEEP's content descriptor is therefore **our versioned
interchange extension**. No prompt, response, SQL parameter, environment
value, terminal stream, file byte, or authorization token goes in an OTLP
body/attribute. References on the OTLP wire must be opaque, credential-free,
and tenant-bound. A content digest is not a privacy control for low-entropy
secrets; digest exposure itself is reviewed.

Do not reinterpret OTLP export acknowledgement as durable destination
storage. OTLP supports full/partial acceptance and retryable failures; the
customer-selected destination needs a separate, validated durable receipt
for a storage claim. `log.record.uid` is the OTLP dedupe attribute when
supported, but AEEP also defines an immutable `record_id` in its own
descriptor/manifest so dedupe does not depend on an unstable convention.

References: [OTel logs data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/),
[OTel events](https://opentelemetry.io/docs/specs/semconv/general/events/),
[OTel GenAI content guidance](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md#capturing-instructions-inputs-and-outputs),
[OTel GenAI agent spans](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md),
[OTel DB spans](https://opentelemetry.io/docs/specs/semconv/db/database-spans/),
[OTLP success/failure semantics](https://opentelemetry.io/docs/specs/otlp/),
and [W3C Trace Context](https://www.w3.org/TR/trace-context/)
(checked 2026-09-26). The AEEP namespace, roles, statuses, and run manifest
below are proposed Fabric contracts, **not** OTel/W3C-defined fields.

## 3. Contract package to create first

Create `contracts/evidence/v1/` and `contracts/content/v2/` without mutating
the existing v1 contracts. Their published JSON Schemas use Draft 2020-12,
closed `additionalProperties` at security-sensitive boundaries, versioned
`schema_version`, positive/negative fixtures, a validator, and a compatibility
matrix. Every connector declares its exact contract versions in its
capability manifest; the existing `contracts/connect/v1` remains valid and is
extended only through a new version or a separate evidence-capability
manifest, never by adding unvalidated v1 fields.

### 3.1 Evidence-capability declaration

One signed/pinned declaration per connector build, not per event:

| Field | Required meaning |
| --- | --- |
| `connector_id`, `version`, artifact digest | Identifies exact implementation |
| `protocols`, `runtimes`, `deployment_modes` | Where it can run and observe |
| `boundaries`, `operation_classes`, `roles` | What it can emit and at which side of a call |
| `observation_level` | `content`, `semantic_metadata`, or `host_provenance` per surface |
| `provenance` | `native`, `protocol`, `caller_reported`, or `inferred` |
| `authentication`, `tenant_binding`, `context_propagation` | How source ownership and causal IDs are established |
| `sampling`, `loss_detection`, `spool_guarantee` | Explicit loss windows and counters |
| `bypasses`, `unsupported_media`, `known_blind_spots` | Testable limitations, never empty by assertion |
| `conformance_fixture_ids` | Evidence for each claimed capability |

An SDK-caller-supplied value is `caller_reported` even if emitted from an SDK;
only a hook at the final visible provider boundary may claim `native` bytes.
Kernel and network observation may corroborate a call but cannot promote an
inferred join to native agent causality.

### 3.2 Content-object v2

A v2 descriptor identifies immutable source and stored byte representations:
`object_id`, tenant binding, `role`, `media_type`, `source_byte_length` and
`source_sha256` **only when actually observable**, `stored_byte_length` and
`stored_sha256` when stored, `representation`, `transformations`, `encoding`
when applicable, `source_id`, `source_epoch`, `source_sequence`, `run_id`,
`operation_id`, `attempt_id`, `stream_id`, `chunk_index`, capture/observation
timestamps, provenance, status, and typed causal links. Binary data has no
implicit UTF-8 conversion. The exact source-byte digest and stored-byte
digest are distinct if canonicalized/redacted/truncated; unknown source
length/digest is absent, never fabricated from stored bytes. The full role
vocabulary must cover model request/output, tool definition/arguments/result,
terminal argv/stdin/stdout/stderr, remote request/result/stream, DB
query/parameters/rows/mutation receipt, network request/response/stream,
sandbox config/output, artifact before/after, and service receipt. New roles
need schema revision and privacy review, not free-form pass-through.

Status is `pending`, `stored`, `truncated`, `redacted`, `not_captured`,
`unsupported`, `dropped`, or `failed`; the schema defines which statuses may
carry a ref and digest. V1 content descriptors and transcript manifests stay
unchanged. A v1 object may be linked from a v2 run manifest as legacy evidence
with its v1 representation and provenance; it must not be relabeled byte-exact
source evidence if v1 only recorded canonicalized/caller-reported values.

### 3.3 Observation event and run manifest

Every evidence LogRecord has a stable `record_id`/`log.record.uid`,
`EventName` from spec 035, empty body, authenticated source/tenant binding,
`run_id` when genuinely linked, source epoch and monotonic per-source sequence,
operation/attempt IDs when known, boundary, provenance, role/status, and
optional content ref/digest. An emitter retry reuses the same identity and
sequence. Inference-only host events leave trace/run IDs absent unless
established by authenticated propagation; a post-hoc correlation is stored
as an explicitly inferred link, never as a fabricated parent.

The run manifest records scope snapshot and revision, every expected source
and role, source starts/stops/restarts, sequence high-water marks, known
gaps, overflow/sampling/rate-limit/drop counters, content item statuses,
verification results, accepted/durable delivery receipts, reconciliation
feed results, and excluded/unknown surfaces. It is append/revision-safe:
stable manifest ID, monotonically increasing revision, atomic rewrite or
immutable revisions, digest of each revision, and no stale overwrite. A
reader verifies descriptor/object digests and tenant authorization before
reporting available content. `pending` after its settle deadline is not
`stored`; retention expiry and access denial are distinct resolution states.

The verdict algorithm is deterministic and tested:

1. `partial` if a **known** required item/source interval is missing,
   redacted, truncated, unsupported, dropped, failed, or has observed loss.
2. Otherwise `unverified` if scope/inventory, source health, reconciliation
   feed, content verification, or durable receipt is unavailable. An unknown
   loss counter or a source disappearing without a terminal marker is here.
3. Only otherwise `verified_complete_for_declared_scope` when every required
   source/role/interval reconciles against independent truth, every required
   object resolves and hashes correctly, and required durable receipts exist.

The verdict says nothing about excluded surfaces. Sampling a required source
prevents a verified verdict. Optional roles may be absent only when that
absence is explicit in scope and manifest. Duplicate records do not repair a
sequence gap. Cross-source timestamps never establish a total order.

### 3.4 Delivery receipt semantics

Use the existing public `contracts/delivery/v1` where it fits, but define an
evidence receipt binding to manifest revision/digest and destination object
identity if v1 cannot express that. Expose stages separately: source
observed, source spool fsync acknowledged, Node accepted, destination
accepted, destination durably persisted/verified. Each stage has its own
issuer and authenticated identity. No component may invent a later-stage
receipt on another's behalf. Content object and metadata event may arrive
in either order; reconciliation must tolerate both without falsely closing
the manifest.

## 4. Capture adapter map and first qualification slices

An extensible registry maps **boundary + operation class + source
capability**, not executable/tool names. `ssh`, `psql`, or a new plugin can
move through terminal, API, sandbox, and remote boundaries; each side needs
its own evidence. Each adapter publishes captured, unsupported, and bypass
fixtures. No default auto-hook may change the monitored call's outcome or
block it on content storage.

| Slice | Required capture for the claim | Independent corroboration / limitation |
| --- | --- | --- |
| Provider-bound model/tool | Final visible request, instructions, ordered messages, tool schema, response chunks/outcome, attempt IDs | Compare SDK input vs actual provider-bound bytes; provider-hidden state excluded |
| Terminal/PTY/subprocess | argv/cwd, allowlisted environment, stdin/stdout/stderr chunks and order, exit/signal, process identity | Host exec corroboration; secrets in argv/env require explicit protection; shell scripts can spawn bypass children |
| File/artifact | Exact before/after bytes or versioned snapshots, creation/rename/delete tombstone, content hashes | Filesystem inventory/version truth; open/read metadata alone insufficient |
| Sandbox/container/VM | Image/config/mounts, child identity, process/network coverage, outputs/artifacts, lifecycle | Runtime/control-plane audit; instrument inside each isolated boundary |
| SSH/remote | Client intent/session plus authenticated remote execution, streams, files/effects | Remote endpoint required; encrypted local packets show metadata only |
| DB/warehouse/vector | Query and parameters under opt-in, actual rows returned/consumed, transaction outcome, mutation receipt | DB audit/CDC for committed effects; driver-only capture may miss server transforms |
| HTTP/RPC/WebSocket/browser/cloud | Request/response/stream bodies and status, redirects, artifacts, side-effect receipts | Authorized endpoint/browser/service audit; TLS packet capture alone insufficient |
| Retrieval/memory/queue/object store | Returned/consumed versions and write/read receipts, payload when authorized | Distinguish value fetched from value later sent to model |
| Skills/hooks/plugins/delegation | Definition/version, invocation, before/after transformed values, delegated context and child-run link | Dynamic install/load and direct API bypass fixtures |

Any adapter that cannot access a class of bytes emits an explicit
`unsupported` or `not_captured` status if it knows the action occurred. A
source cannot emit a record for an action it never saw; independent boundary
inventory and reconciliation are therefore required to make absence
meaningful. Secrets, environment snapshots, SQL rows, HTTP headers, and
terminal streams are opt-in by role and protected before any egress.

## 5. Delivery, reliability, and privacy requirements

- Capture is shadow-only and bounded in CPU, memory, disk, and latency.
  Full queues must not block the agent. They produce counted loss and lower
  the run verdict; a dropped-event marker alone cannot be relied upon when
  the same channel is full.
- Source spool persistence/restart recovery and Node queue persistence are
  separate durability boundaries. Test each source under export outage,
  crash, restart, disk-full, permission failure, corruption, overflow,
  clock skew, duplicate delivery, and rolling upgrade. Loss before first
  durable observation cannot be disproved by downstream receipts.
- Required heartbeat/epoch/high-water signals allow a reconciler to detect a
  stopped source. A heartbeat is health evidence, not proof of zero actions.
- Source, Node, and content store authenticate the workload/tenant; tenant
  IDs inside payloads are not authoritative. Object access requires
  tenant-scoped authorization, encryption, retention, and audit logging.
  Refs contain no credentials or signed URLs. Content never enters OTLP,
  collector logs, **telemetry** queue files, error text, or CI artifacts.
  A dedicated customer-controlled content spool may contain raw bytes and
  therefore needs restricted permissions, encryption where required,
  bounded retention, tenant isolation, and deletion/recovery tests.
- Pin collector allowlist additions to exact AEEP event names and reviewed
  scalar keys; deny unknown names/keys and raw bodies. Run privacy canaries
  containing prompt text, bearer tokens, command flags, SQL parameters,
  row data, and binary markers through each adapter and exporter.
- Per-tenant quotas, size limits, backpressure/loss accounting, key rotation,
  multitenant isolation, and reproducible release artifacts are production
  requirements. A scaling claim needs published measured throughput, burst,
  outage, recovery-time, and storage-retention limits, not just passing unit
  tests.

## 6. Work packages in required order

Implementation starts **after this spec/035 review**, and every package
updates the qualification matrix. Dependencies are intentional; later
adapters cannot be marketed as complete before the contract and loss-path
gates pass.

1. **Contract baseline:** publish evidence/v1 and content/v2 schemas,
   positive/negative fixtures, validators, version pins, legacy-v1 mapping,
   field-level privacy classification, and a frozen event/attribute registry.
   Gate: cross-language parse/hash tests and rejection of raw bodies,
   credential-bearing refs, inconsistent statuses, forged completeness.
2. **Core recorder:** implement per-source identity/epoch/sequence, immutable
   record IDs, content-v2 byte store and manifest writer/reconciler in Python
   and TypeScript; keep v1 APIs compatible. Gate: exact byte fixtures
   including binary, Unicode, empty vs absent, chunks, truncation,
   redaction, duplicate/retry, manifest stale-write, and outage/restart.
3. **Node/export path:** admit only reviewed AEEP metadata, preserve native
   trace identity, authenticate source-to-tenant mapping, expose receipt
   stages and loss metrics. Gate: privacy-leak/fuzz tests, OTLP partial
   success and retry tests, queue crash recovery, artifact-content tests.
4. **Provider-bound adapter pilot:** one pinned provider/framework version per
   language, with explicit opt-in and bypass detection. Gate: compare
   provider-bound bytes against independent test endpoint and mark transforms.
5. **Terminal + artifact pilot:** instrument one bounded terminal/sandbox
   API with ordered streams and binary artifacts; reconcile with host/runtime
   source. Gate: direct subprocess/PTY/script child, signal/cancel, rename/
   delete, large/binary output, secrets, and sensor outage fixtures.
6. **Remote and service adapters:** SSH remote endpoint, DB client + server
   audit, HTTP/browser/cloud, retrieval/memory/queue as separately reviewed
   slices. Gate: per-adapter capability/bypass matrix and independent source
   reconciliation; no umbrella `all tools` pass.
7. **Production qualification:** exact-SHA CI, SBOM/provenance/signatures,
   multi-tenant soak/load, security review, customer shadow pilot, measured
   coverage and residual gaps. Promote only the individual qualified
   boundary claims, never universal agent capture.

## 7. Conformance and release evidence

Maintain a machine-readable coverage matrix with one row per
`connector × runtime/version × boundary × operation × role`. Each row lists
claim level, expected bytes/status, bypass cases, test fixture ID, source
truth, privacy policy, release digest, and pass/fail/untested result. A
release gate rejects any marketed capability with an untested row or a
failure. The suite must include:

- positive/negative schema and deterministic verdict fixtures;
- Python/TypeScript identical-byte hashes and object resolution;
- OTel traces/logs with native versus inferred correlation and duplicate
  records; absent trace IDs remain absent;
- source gap/overflow/rate-limit and unreachable-sink tests;
- terminal/SSH/DB/network bypasses, including direct calls outside preferred
  SDK wrappers;
- secret canaries proving no raw content on OTLP, logs, telemetry spools, or
  receipts, and proving dedicated content-spool access controls;
- a shadow pilot comparing independent source truth to captured records; and
- built-artifact inspection excluding evaluation, judge, enforcement, and
  private-platform capabilities from the recorder release.

The first published status is **draft protocol + implementation plan**, not
`implemented` or `enterprise-ready`. Update this status only after the
corresponding contracts, code, fixtures, qualification evidence, and
customer-boundary review exist.

## Implementation ledger (2026-09-26)

This dated ledger is historical, not the current source-support matrix. See
[SDK support](../docs/sdk-support-matrix.md) and
[qualification status](../docs/recorder-v1-qualification-status.md) for later
Python durable byte-spool and audit logfile checkpoint additions.

Work package 1 has a locally tested draft baseline. Closed schemas, exact-byte
pinned fixtures, and a semantic validator live in `contracts/evidence/v1/`,
`contracts/content/v2/`, and
`scripts/contracts/validate_evidence_contracts.py`. The synthetic run
fixture exercises a bounded complete verdict; negative tests reject raw
event bodies, cross-tenant/credential-bearing refs, false exactness, sequence
gaps, loss, absent durable content/event receipts, and unverified source
identity. Repository CI runs the validator. These are **contract tests only**:
they do not prove that any live connector emits the fields, that receipts
are authenticated, or that independent feeds are trustworthy.

Still pending in package 1: a field-level privacy classification and
version-pinned OTel convention registry, full cross-language producer/consumer
fixtures, receipt cryptographic verification, and a signed connector
capability release. Package 2 has begun: Python and TypeScript each have an
explicit opt-in content-v2 byte recorder with exact-byte local tests, but
their queues are process-memory only and there is no AEEP event/run-manifest
producer. The optional host emitter has a locally tested persistent source
spool and counted losses; the audit receiver has bounded in-memory retry but
no restart-durable queue/cursor. Neither is a complete-source proof. Packages
3–7, including provider/terminal/remote adapters, exact-artifact Linux and
customer pilot qualification, remain pending. Do not advertise these draft
contracts or partial runtimes as a complete capture capability.
