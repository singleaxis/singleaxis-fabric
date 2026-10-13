# Recorder v1 qualification status

This document distinguishes implemented runtime behavior from public contracts
and from checks that require the release CI environment. It is a development
status record, not a certification or legal compliance statement.

## Removed from the tree: AEEP drafts and the synthetic evidence slice

The draft Agent Execution Evidence Profile (AEEP, specs 035–041), its
`contracts/evidence/v1` schemas and validator, the synthetic
model → terminal → artifact evidence slice (`qualification/synthetic-slice`,
recorded **NO-GO**), the experimental Python and TypeScript
`ByteEvidenceRecorder`, the Python synthetic-slice modules
(`fabric.byte_evidence`, `fabric.source_spool`, `fabric.synthetic_otlp`,
`fabric.synthetic_reconcile`, `fabric.adapters.synthetic_evidence`) and the
Fabric Node's `evidence` log class (`agent.evidence.*` events) were removed
from the tree. They proposed run-level completeness evidence and enterprise
go/no-go gates that expand the OSS product promise beyond
Capture → Protect → Deliver, and none of them reached a qualified state. They
remain in git history. The Node now drops `event_class=evidence` records like
any other unknown class, and the recorder wheel/sdist qualifier and release
policy forbid the removed modules so they cannot ship again.

What stayed: the byte-content v2 descriptor (`contracts/content/v2`, now
validated by `scripts/contracts/validate_content_v2_contracts.py`) and the
content store's `ByteEvidenceStore.put_bytes_object`, both used by LLM wire
capture.

## LLM wire capture (specs 042–043, draft)

The optional in-process wire tee, agent durable spool, Node content
delivery (`fabriccontent` exporter) and offline `fabric.reconstruct`
verifier are in the SDK and Node source and are exercised by unit,
contract and Docker-backed real-Node tests (local directory and MinIO
stores). They carry **no coverage claim**: a verdict covers only model
calls made through httpx/httpx2 in an instrumented process, and
qualification of the capture boundary and source loss is separate work.
See [Deploying LLM wire capture](wire-capture-deployment.md).

## Isolated Linux CI qualification

Isolated Linux qualification has now started in draft PR
[#164](https://github.com/singleaxis/singleaxis-fabric/pull/164). The first
Ubuntu/kind smoke run on commit `75afeb1` passed Collector install, the
controlled fsync sink, protection/delivery, destination outage and restart
recovery. It did **not** run scoped BPF or target storage/retention
tests. The same commit's security and recorder CI runs failed: dependency scans found
`google.golang.org/grpc` 1.82.1 and AnyIO 4.13.0; the history-wide secret
scan reported seven findings in older commits; clean Python installation
exposed an S3 fake-client test failure; CI typing and repository-test setup
were incomplete. Dependency and test-environment fixes are being qualified
on the PR branch, not yet accepted as a passing release gate. The seven
history findings need security-owner classification before any suppression
or release decision.

The second PR run on commit `334c5b8` passed all released lockfile/dependency
scans, Python SDK tests on 3.11/3.12/3.13, repository contract tests, Node
image scan, and source hygiene. Its recorder CI still failed on one Python
test typing assertion, fixed locally for the next run. The history-wide
secret scan still failed on the same older findings; a separate scan of the
two PR commits (`gitleaks git --log-opts=main..HEAD`) found no new leaks.
Neither result classifies the historical matches or authorizes release.
The next run on commit `3073142` passed Recorder CI, CodeQL, license
compliance, and the Linux/kind smoke, including queue outage/restart recovery.
Recorder security remained red **only** on the same history-wide secret scan;
all current released-dependency scans passed. These CI results establish a
bounded Node smoke on that commit, not target storage qualification or an
enterprise production qualification.

## Implemented in release artifacts

| Area | Implemented behavior |
|---|---|
| Capture | Python and TypeScript SDK surfaces; OTLP trace and log ingestion through Fabric Node |
| Protect | Non-disableable exact metadata allowlist; raw bodies and unapproved native OTLP strings removed before export; named production profile rejects custom allowlist extensions |
| Deliver | OTLP/HTTP export, persistent file queue, no production pre-queue batch window, blocking overflow, restart recovery, and unbounded retry |
| Deployment | Collector-only Helm chart with `shadow-dev` and fail-closed `shadow-production` profiles |
| Setup | Recorder-only `fabricctl` init, validate, digest, help, and version commands |
| Packaging | Explicit release allowlists for SDKs, chart, image, CLI, and public contract families |

Governed content capture (specs 028–034, **draft**) is present in the SDK
source and packages but is **not yet a qualified release capability** — see
its dedicated section below. The recorder claims above are about the
metadata-only pipeline.

The released recorder artifacts do not contain or install judges, red-team
runners, prompt-time PII controls, guardrail engines, policy/tool authorization,
assurance tiers, governance workflows, or management-plane services.

## Public contracts, not automatic runtime evidence yet

Activity Envelope v2, privacy assertions, and delivery batches/receipts define
interoperability shapes and validation rules. Recorder v1 does not yet claim
that Fabric Node materializes Activity Envelope v2 on its OTLP wire path,
automatically emits a signed privacy assertion for every batch, or obtains
durable-persistence proof from arbitrary destinations.

### Governed content (specs 028–034, draft)

Status vocabulary used here: **implemented** (code exists and passes unit
tests), **locally tested** (suite-level evidence in this repository),
**environment-dependent** (requires a live endpoint/cluster), **deferred**
(designed, not built), **unsupported** (explicitly out of scope for v1).

Locally tested in the SDKs today:

- versioned `fabric.content-object/v1` descriptors and
  `fabric.transcript-manifest/v1` / `fabric.transcript-export/v1`
  contracts, with shared byte/hash fixtures passing in both languages;
- local filesystem and S3-compatible governed stores behind a shared
  safe-identifier tenant rule (tenant namespacing, content-addressed
  objects, descriptor sidecars, by-decision manifest aliases);
- bounded writer with `process`/`spooled` durability plus dev-only
  `inline`, `fabric.content-spool/v2` durable records, full recovery
  drain with post-restart manifest-item reconciliation, revision-safe
  manifest rewrites, quarantine, and exact stored/pending/dropped/failed
  accounting — a nonblocking enqueue is never reported as durable;
- passive delivery end to end: refs and `manifest_ref` are deterministic
  and stamped before spans end; objects and manifests travel the bounded
  writer — the monitored path performs no object-store I/O in
  `process`/`spooled`;
- governed capture across `llm_call` (request, output, partial output),
  `tool_call` (arguments, result), retrieval, memory, side-effect,
  context, and interaction surfaces in both SDKs;
- authorized resolution confined to configured stores and tenant
  namespaces; `available` is returned only after descriptor, byte-length,
  and SHA-256 verification, with explicit
  available/pending/missing/denied/corrupted/unverified results.

Environment-dependent, not yet qualified:

- production S3 delivery against a live endpoint (adapter is
  contract-tested with fakes; a skippable live gate exists and must pass
  before S3 is claimed production-ready);
- promotion evidence for governed-content flow through the tagged real
  Fabric Node build. The local Docker E2E gate proves refs cross and raw
  content stays out of exported OTLP, collector logs, and queue files;
  release CI must repeat that proof for the exact promoted commit.

Deferred:

- adapter/framework auto-capture of governed content (manual `llm_call`
  surfaces only — auto-instrumentation content is not wired).

Unsupported in v1:

- binary or multimodal content (mark it `unsupported`; v1 is text/JSON);
- immutable-evidence/retention claims (WORM, object lock, and lifecycle
  are customer bucket/filesystem policies the SDK does not provide);
- hidden provider context or reasoning (Fabric records the observable
  boundary only).

An unsigned privacy assertion records what a processor claims it applied. It is
not independent proof and is not a legal de-identification determination.

### Host-source hardening (not a complete-host claim)

The optional host emitter now has a bounded disk spool with fsync, restart
replay, stable source record IDs, and explicit ring/rate loss summaries. It
defaults to no intentional rate limiting or deduplication. Raw argv and paths
are not spooled or exported; truncated argv/path fields are marked incomplete
rather than mislabeled as full hashes. The guard has exact keys and closed
values for host status metadata and strips raw path keys. The audit receiver
has bounded in-memory retry and known-gap reporting, but **not** a durable
receiver queue or persisted logfile cursor. Neither host path has passed a
target-Linux BPF/kernel loss test or independent host-truth reconciliation.

The host-emitter DaemonSet is a fail-closed qualification template. A static
preflight checks pinned image identity, scoped cgroup, TLS credentials and
persistent spool mounts. It cannot verify encrypted disk, valid credentials,
real cgroup coverage, or lossless live operation.

## Locally qualified

The repository qualification suite covers:

- contract schema, digest, ordering, causality, and receipt invariants;
- guard processor unit, race, and static checks;
- chart schema, package boundary, production ingress/egress, and durable queue
  configuration checks;
- recorder-only CLI build and dependency graph;
- SDK unit, typing, lint, build, and exact package-surface checks;
- installed-artifact runtime smoke for both SDK packages, including local
  governed capture, manifest export, and integrity verification;
- release identity, release policy, workflow syntax, and artifact boundaries.

Exact test counts can change as coverage grows. The release's immutable CI run
is the authority for published counts.

## Required before an enterprise test release is promoted

The tagged commit must pass the required GitHub workflows, including the live
`recorder-ci.yml`, `recorder-license.yml`, `recorder-security.yml`,
`codeql.yml`, and `e2e.yml` runs for that exact commit. The live kind job builds the real Fabric
Node image and proves:

1. accepted telemetry reaches the controlled destination;
2. a forbidden content marker cannot leave Fabric Node;
3. telemetry queued during a destination outage survives a Node restart; and
4. delivery resumes when the destination returns.

Each customer must also qualify its own connectors, certificates, identity
mapping, storage class, egress path, destination acknowledgements, retention,
deduplication, alerting, and operational recovery.

## Known boundaries

- Passive shadow capture can record only activity exposed by SDKs, adapters,
  gateways, vendor APIs, or existing telemetry. Fabric must not infer invisible
  internal reasoning as fact.
- At-least-once delivery can duplicate events; destinations must deduplicate
  using preserved trace/span identity or identities added by an adapter.
- OTLP acceptance is not evidence of durable retention.
- Metadata-only protection reduces export exposure but does not establish legal
  de-identification or prevent PII from reaching the monitored model.
- Historical and experimental source can remain visible in the public Git
  repository during migration; release tests must prove it is absent from the
  recorder binaries, chart, SDK packages, and installer surface.
