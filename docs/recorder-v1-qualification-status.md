# Recorder v1 qualification status

This document distinguishes implemented runtime behavior from public contracts
and from checks that require the release CI environment. It is a development
status record, not a certification or legal compliance statement.

## First synthetic evidence slice — NO-GO

[Spec 040](../specs/040-synthetic-agent-evidence-slice.md) records the phase-1
gap ledger, provisional scope and control/coverage matrix, and documents
phases 2–8 before code changes. The declared test workflow is a non-sensitive
Python 3.11 model → no-shell terminal/tool → file artifact → model flow using
a controlled endpoint and independent fixture/filesystem truth. The scope is
not a signed customer deployment approval. Draft contracts and caller-supplied
byte storage are locally tested. Opt-in loopback HTTP, no-shell terminal and
allowlisted-file adapters now have **source-checkout local** binary-byte
tests. An offline resolver checks tenant-scoped refs and source/stored SHA-256
and length, and a conservative reconciler reports known missing/corrupt
bytes as `partial`. Matching fixture bytes remain `unverified`, never
complete. An optional metadata-only source journal now persists an epoch,
events and outcomes off the action path, with restart recovery and explicit
overflow/corruption tests. Its bounded handoff still has an unverified
pre-fsync crash window. An offline, post-run, loopback-only AEEP metadata
projection now reaches the real Fabric Node. Its closed evidence guard
preserves fixed names and strips bodies/unknown fields; OTLP partial success
is counted without blind retry. This is Node acceptance only: source IDs
remain unauthenticated, with no continuous AEEP publication or durable
destination receipt,
and reachable direct bypasses. The optional host emitter now quarantines
partly accepted OTLP batches without replay, retaining the rejected count
across restart; it remains corroborative and excluded from the complete
source set.
The terminal proxy and synchronous artifact observer are test-harness
adapters, **not** proven non-interfering passive production capture; their
timing/backpressure remains a release gate.

Phase evidence as of 2026-09-27: `sdk/python/.venv/bin/pytest -q -o
addopts= tests/test_synthetic_otlp.py tests/test_synthetic_evidence.py
tests/test_source_spool.py` passed 25/25 locally with an
ephemeral loopback endpoint (the default sandbox denied the bind; the bounded
test was rerun with network permission). Targeted Python Ruff and mypy
passed; `GOCACHE=/private/tmp/fabric-go-cache go test -race ./...` passed
for `components/host-emitter`; the Node guard race suite also passed. The full
Python SDK suite passed 690/690 (85.10% coverage); package-boundary tests passed 21 with one skip because
case-colliding files are unavailable on this filesystem. The
source-checkout synthetic pilot compared twelve byte objects and five outcomes
with independent fixture/endpoint/filesystem values and found zero local
discrepancies; its verdict is still `unverified`. See the
[local discrepancy report](../qualification/synthetic-slice/local-pilot-report.md).
The follow-up fixture projects all twelve reconciled byte events to offline
AEEP metadata and verifies their IDs, roles, statuses and digests; the
focused synthetic suite passed 25/25. This does not constitute live delivery.
With elevated Docker socket permission, uniquely tagged local Node and host
images were built; a disposable Python wheel and chart were packaged. The
latest installed local wheel passed 24/24 focused tests. A pre-resource-hardening
Node image passed 3/3 real-Node governed-content, AEEP privacy/export,
and controlled-sink outage/restart tests in an isolated random Compose
project. A later guard fix clears evidence resource/scope attributes and
passed `go test -race`; its rebuilt image **could not start the persistent
queue** in the shared Docker daemon (`no space left on device`), so its
live privacy probe remains unverified. Exact local digests and commands
are in the [artifact ledger](../qualification/synthetic-slice/local-artifact-ledger.md).
No privileged BPF run or customer deployment was performed. The dirty
worktree has no clean tagged artifact identity, and these tests are not
target-Linux BPF, target-storage or live-customer-destination proofs.
A complete-run or critical-enterprise claim remains **NO-GO**.

Isolated Linux qualification has now started in draft PR
[#164](https://github.com/singleaxis/singleaxis-fabric/pull/164). The first
Ubuntu/kind smoke run on commit `75afeb1` passed Collector install, the
controlled fsync sink, protection/delivery, destination outage and restart
recovery. It did **not** run the synthetic model/terminal/artifact byte
reconciliation, scoped BPF, or target storage/retention tests. The same
commit's security and recorder CI runs failed: dependency scans found
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
bounded Node smoke on that commit, not a synthetic exact-byte pilot, target
storage qualification, or enterprise GO.

The later PR head `c5ca90f` also passed Recorder CI, Linux/kind smoke,
CodeQL and license checks. Recorder security still fails solely on seven
history-wide secret-scan findings in old commits; the current tree and PR
range scans found no new leaks. The smoke still did not run the synthetic
agent. The [installed-artifact pilot plan](../qualification/synthetic-slice/end-to-end-agent-pilot-plan.md)
now defines that missing CI step. A newly built local wheel installed in a
disposable Python 3.11 environment ran a deterministic three-model/two-tool
agent fixture: 25 required byte objects and 10 outcomes reconciled with
fsynced endpoint/tool journals and artifact inventory, with zero discrepancies
in the clean case. A direct provider bypass produced four discrepancies and
a deleted required object produced one; both were `partial`. The clean case
remained `unverified`. The new workflow step will test that same installed
wheel against the isolated Linux/kind Node and controlled sink; its live result
is pending. This fixture is not a customer shadow pilot or passive
non-interference proof.

The local wheel SHA-256 was
`d3ca361f5acb008daf8bb96b392033514393851b5b7f66ce4e127d2797d15561`.
The executable check was
`/private/tmp/fabric-agent-pilot-venv/bin/python scripts/qualification/run_synthetic_agent_pilot.py --report-path /private/tmp/fabric-agent-pilot-report.json`
from the PR worktree, after installing that wheel into the disposable venv.
This local digest is not a clean tagged release identity.

### Decision rule for the first bounded GO

`GO` applies only to the signed synthetic model → terminal → artifact → model
scope, not to every AI tool or compliance regime. All gates below must pass
on the **same clean, tagged, digest-pinned artifact set**; a unit test, OTLP
200, or self-reported manifest cannot substitute for a missing gate.

| Gate | Required evidence | Current blocker |
| --- | --- | --- |
| Approved boundary | Signed route/version/source/role/privacy/capacity record and proof excluded routes are unreachable or explicitly outside the claim | Scope unsigned; direct HTTP/subprocess bypasses are reachable |
| Capture and loss | Exact bytes, outcomes, order, causal IDs and source high-water for every required operation; crash/overflow/partial-success injection always lowers verdict without altering the action | Wrappers not passive-qualified; source pre-fsync blind window and missing authenticated gap chain |
| Identity and receipts | Authenticated tenant/source binding; independently checked source-spooled, Node, destination-accepted and destination-durable stages | IDs caller-supplied; no complete trusted receipt chain |
| Protection and retention | Final image canary-free outbound telemetry/logs/queue/errors/receipts; tenant isolation, encryption, retention, restore and key rotation proved on target stores | Final image live test blocked by shared Docker disk; target controls absent |
| Exact release | Installed SDKs, chart, Node and any shipped host image by digest; security/package/race/E2E gates on isolated target Linux/Kubernetes; scoped BPF if a host route is included, only with approval | Dirty checkout and no isolated target runner; privileged BPF not authorized |
| Independent shadow pilot | Every expected operation and required byte object reconciles against separately authenticated endpoint, terminal and filesystem records; zero unexplained discrepancies; reviewer reproduces verdict | Only local fixture, no authenticated feeds or independent sign-off |

Engineering can close code and fixture gaps in this repository. Customer
platform, security, privacy, records and release owners must supply the
bounded target environment, signed scope and trust roots, storage policies,
destination readback and independent review. No recorder code can honestly
manufacture those proofs. When any gate is unavailable, status remains
`NO-GO` or `unverified`; it is never inferred from a passing schema test.

| Phase | State | Exact missing gate / environment / owner / next action |
| --- | --- | --- |
| 1–2 scope and contract | Documented, provisional | Customer platform/security must sign route, identity, privacy and target limits in an isolated deployment record. |
| 3 boundary adapters | Partly locally tested | Recorder engineering: process crash, partial-stream, backpressure/non-interference and direct-bypass closure in disposable Python 3.11 fixture; replace any intrusive observation before promotion. |
| 4 loss and receipts | Local source journal, host partial success and offline AEEP Node acceptance tested; slice unverified | Crash-before-fsync test proves a blind window; recorder engineering must reconcile it against authenticated independent truth, publish gaps and qualify distinct source/Node/destination/durable receipts. Audit receiver remains excluded. |
| 5 resolver/reconciliation | Local partial/unverified only | Customer verifier: authenticate independent feeds and durable receipt proof before enabling `verified_complete_for_declared_scope`. |
| 6 privacy/storage | Pre-hardening AEEP Node/sink/log/queue canary passed; final resource-attribute guard passed unit/race only | Customer privacy/storage: rerun final image on runner with free disk, then canary across errors/receipts and live encryption, retention, backup/restore, key rotation and disk-full tests for each store. |
| 7 exact artifacts | Local dirty-checkout wheel/chart/images built and partly smoke-tested; final Node image live test blocked by Docker disk exhaustion | Release engineering: isolated runner with free disk, clean tagged SHA and digest-pinned installed SDKs, chart, Node and host images on Linux/Kubernetes; privileged scoped BPF requires explicit approval. |
| 8 shadow pilot | Local installed-wheel synthetic fixture passed; Linux/kind Node linkage and customer pilot not yet run | Customer pilot owner: pre-register authenticated endpoint/terminal/filesystem records, run exact artifacts in target environment, reconcile every operation/object and obtain independent review. |

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

The AEEP profile (specs 035–036) now has **draft, pinned contract fixtures**
for `agent.evidence.*` event projections, source capabilities, a bounded
run manifest, and binary content-object v2. The validator and tests check
schema closure, exact-byte digests, tenant/ref safety, source lifecycle,
loss/sampling, independent-feed and durable-receipt structure, and false
completeness verdicts. The Python and TypeScript SDKs now locally test an
explicit opt-in content-v2 **byte** recorder: it persists caller-supplied
bytes per observation in a tenant-bound local or S3-compatible store. Its
bounded queue is process-memory only; it does not automatically intercept
model/tool/terminal calls, produce run manifests or obtain durable
destination receipts. A separate offline synthetic adapter projects settled
metadata to AEEP OTLP logs for a controlled loopback Node; it is not an
automatic production publisher. The schemas are not an implemented
complete-evidence runtime and are not qualified as a production capture
surface. Proof fields in fixtures are structural, not authenticated proof.
Draft specs [037](../specs/037-bounded-enterprise-deployment-and-controls.md),
[038](../specs/038-capture-boundary-and-loss-qualification.md), and
[039](../specs/039-storage-release-and-shadow-pilot.md) define the
customer-specific control matrix, capture/loss qualification,
protected-storage proof, exact-artifact tests, and shadow-pilot
reconciliation required for a critical-enterprise go decision. No such
go decision or pilot evidence is present in this repository today.

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
