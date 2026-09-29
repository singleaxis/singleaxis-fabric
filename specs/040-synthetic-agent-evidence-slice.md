---
title: Synthetic model-terminal-artifact evidence slice
status: draft
qualification: NO_GO
revision: 1
last_updated: 2026-09-26
owner: recorder-engineering
depends_on: 035, 036, 037, 038, 039
---

# 040 — First bounded agent-evidence slice

This specification is the phase ledger for a **synthetic, non-sensitive**
model → terminal/tool → file artifact → model workflow. It authorizes only
passive `CAPTURE -> PROTECT -> DELIVER` work. It is not a customer scope
approval, production control assessment, or universal tool-capture claim.
The first implementation language is Python 3.11; TypeScript content-v2
remains a separate, locally tested byte API rather than an implicitly
qualified adapter. All statuses below describe this repository at the start
of the slice; evidence must be linked before changing a status.

## Phase 1 — Audit, declared scope, and control/coverage matrix

### Gap ledger

| ID | Required for this slice | Current state | Gate and owner |
| --- | --- | --- | --- |
| G01 | Final visible provider-bound request/response, attempts and context | Locally tested for one opt-in loopback HTTP adapter and distinct retry attempts; direct bypass observed; descriptor provenance remains `caller_reported` | Cancel, route closure, source auth and endpoint proof; recorder engineering |
| G02 | Terminal argv, cwd, approved context, ordered stdin/stdout/stderr, exit/signal | Locally tested for one no-shell subprocess; optional asynchronous metadata journal is fsynced but has a pre-spool blind window; subprocess proxy is not proven non-interfering | Close crash/partial-stream uncertainty, backpressure/non-interference and capacity; recorder engineering |
| G03 | Created/modified artifact before/after bytes | Locally tested for created/modified binary file, absent-before, symlink and oversize gaps; synchronous file observation can delay the fixture and has TOCTOU risk | Non-interference, TOCTOU and independent filesystem inventory; recorder engineering |
| G04 | Authenticated source ID, persisted epoch/sequence, stable event/attempt IDs | Local synthetic metadata journal persists epoch, records and outcomes and detects recovered sequence gaps; append remains asynchronous and source ID unauthenticated | Authenticate source, close pre-fsync uncertainty with independent truth and publish manifest; recorder engineering/platform |
| G05 | Complete-run manifest with independently verified receipts | Draft schema/validator only; no runtime producer or trusted verifier | Authorized resolver, reconciler, destination proof; recorder engineering/customer destination |
| G06 | Source loss and OTLP partial-success accounting | Host spool quarantines a partly accepted batch; synthetic source journal locally tests restart/overflow/quota/corruption but pre-fsync window remains; offline AEEP OTLP exporter accounts for partial success without retry; audit receiver retry is in-memory | Authenticated gap export, complete receipt chain and target outage proofs; exclude audit receiver from complete-source claim; recorder engineering |
| G07 | Privacy and storage qualification | Pre-resource-hardening real-Node AEEP canary passed sink/log/queue; final guard resource/scope hardening passed unit/race only because Docker queue disk exhausted | Rerun final image with free disk, then target permissions, corruption, live store and customer records tests; privacy/storage owners |
| G08 | Exact-artifact Linux/Kubernetes pilot | Dirty-checkout installed wheel and earlier unique Node image tested locally; final Node image live test blocked by Docker disk exhaustion; no clean tagged SHA, target Linux/Kubernetes environment or authorized scoped BPF run | Clean tagged digests, installed-artifact E2E on isolated runner and independent reviewer; release/customer owners |

### Provisional implementation-ready scope record

2026-09-30 implementation delta (not a change to approved scope): spec 044
adds a dedicated credential-bound ingress for G04, an offline signed-statement
verifier foundation for G05, and security remediation for G07/G08. These
additions do not close pre-fsync loss, generate durable receipts, authenticate
fixture witnesses, or approve customer storage. The current control/coverage
status and local versus live evidence are maintained in the
[qualification ledger](../docs/recorder-v1-qualification-status.md#current-closure-work--2026-09-30--no-go).
G01–G03 and excluded routes are unchanged; G04/G05 remain incomplete until
their deployment and full-chain proofs are supplied.

`scope_id=synthetic-model-terminal-artifact-v1`, revision 1. The scope is a
test plan, **not signed approval**. Tenant `synthetic-tenant`; one ephemeral
run ID per execution; one Python 3.11 application process; one controlled
loopback HTTP model endpoint; one explicitly wrapped `subprocess.Popen`
session with `shell=False`; one isolated temporary artifact directory;
local tenant-scoped content store; optional Fabric Node metadata export.
The test endpoint and fixture command are versioned by exact source digest in
the pilot bundle. The target release still needs an exact Python wheel,
Node/chart image/package digests, and a Linux runtime/kernel record; all are
`unverified` until built and tested. No external provider or real customer
data is in scope.

The application source owns run and operation IDs. The model adapter owns
provider request/response observations; the terminal adapter owns the
subprocess boundary; the artifact observer owns only allowlisted paths.
Native trace context is retained only if actually supplied; a PID/time join
does not create a parent. A physical retry has a new attempt ID. Required
content roles are `model.request.messages`, `model.output.messages`,
`terminal.argv`, `terminal.stdin`, `terminal.stdout`, `terminal.stderr`,
`interaction.payload` (approved provider HTTP context and terminal cwd/context), and `artifact.after`;
`artifact.before` is required for a modification and explicitly absent for
a creation. An empty stream is a present zero-byte object; a never-observed
stream is absent and cannot be silently treated as empty.

Independent truth comes from (1) the controlled endpoint's received-body
and response-byte ledger, (2) the fixture harness's expected command,
stdin, stdout/stderr and exit record, and (3) pre/post filesystem inventory
with exact bytes and SHA-256. The pilot compares identities, operation sets,
per-source sequences, chunk order, bytes and statuses—not aggregate counts.
The endpoint ledger and filesystem inventory must be generated outside the
recorder pipeline. A reviewer must inspect their provenance.

Out of scope: hidden provider state/reasoning, PTY semantics, arbitrary
subprocess descendants, direct unwrapped `subprocess` or HTTP calls, SSH,
DB, browser/cloud, sandbox escapes, background jobs and non-allowlisted
files. These exclusions are **not proven unreachable** in a developer shell;
direct-bypass tests therefore must lower the verdict to `unverified` unless
an isolated disposable environment proves reachability restrictions.

Provisional per-run limits: 1 MiB per content object, 64 queued objects,
4,096 descriptors, 4 KiB terminal read chunks, 8 MiB cumulative terminal
output, 64 KiB stdin, 60-second subprocess timeout, and a 60-second maximum
receiver outage. These are test ceilings, **not measured enterprise
capacity**. Exceeding a bound is explicit `truncated`/`dropped`/`failed`
evidence and prevents a complete verdict. Production capacity/outage limits
must be measured and signed before promotion.

Privacy policy: opt in only the roles above for synthetic data; no raw bytes,
argv, cwd, secret headers, filesystem paths or provider bodies on OTLP,
collector logs, telemetry queues, error messages or receipts. Put exact bytes
only in a dedicated customer-controlled tenant store; export opaque refs,
hashes, lengths, status and causal IDs after exact allowlist review. Test a
secret canary in every boundary. Store encryption, retention and deletion
schedule are customer/target-environment controls and remain unverified here.

### Control and coverage matrix for revision 1

| Control | Slice evidence required | Status |
| --- | --- | --- |
| BD-01 | Loopback endpoint, no-shell subprocess, temp artifact root and direct bypass inventory | Unverified: no enforced route inventory |
| ID-01 | Authenticated source→tenant binding; reject forged source/tenant | Unimplemented |
| CA-01 | Exact model/terminal/artifact bytes and causal/attempt IDs | Locally tested for one opt-in synthetic path; not durable or route-complete |
| CA-02 | Gap, overflow, source crash and unsupported role lower verdict | Draft contract locally tested; live source unverified |
| PR-01 | Canary absence from OTLP/logs/telemetry queue/errors/receipts | Earlier image passed AEEP Node/sink/log/queue path; final resource/scope fix not live-tested; error and receipt paths, target environment unverified |
| ST-01/ST-02 | Tenant store integrity, permissions, encryption, retention, restore | Local byte-store tests only; target controls unverified |
| DL-01 | Separate source fsync, Node, destination acceptance and durable receipt | Host and optional synthetic metadata source spools locally tested; complete receipt chain unverified |
| OP-01/RL-01 | Alerts, exact digests, installed artifacts, Linux faults | Local dirty-checkout wheel/Node image tested; target Linux/release unverified |
| EV-01 | Authorized resolver/export without a judge | Local tenant-bound byte resolver and conservative discrepancy report tested; independent feed authentication and complete verdict unavailable |

Coverage rows `provider_bound/request+response`, `terminal/argv+context+
stdin+stdout+stderr+outcome`, and `artifact/create+modify/before+after` are
required for the first slice. `host/audit` is corroborative metadata only;
the audit receiver is explicitly **excluded** from any complete-run source
set until its restart-durable cursor/queue and non-replayable netlink losses
are qualified. Other route classes require separate adapter specs and may
not inherit this slice's status.

## Phase 2 — Event flow and pre-code acceptance contract

1. A source starts with an authenticated tenant/workload identity, a new
   epoch and persisted monotonic source sequence. It records start and
   high-water/health events. Self-reported tenant IDs alone are insufficient.
2. The provider adapter observes the final visible request bytes at its
   send boundary, then the actual response bytes and outcome. It links both
   to one logical operation and physical attempt; retries use fresh attempt
   IDs. The controlled endpoint independently records bytes received.
3. The terminal adapter observes argv bytes and approved cwd/context,
   streams stdin/stdout/stderr in 4 KiB chunks with per-stream chunk indices
   and a single source observation order, then exit/signal/cancel outcome.
   Cross-FD order is the adapter's observed read order, not a claim about
   the kernel's unknowable total write order.
4. The artifact observer reads only configured paths before and after the
   subprocess, distinguishes absent from zero-byte files, and stores exact
   binary bytes with creation/modification status. Unreadable, symlinked,
   deleted or oversized artifacts are explicit gaps.
5. Content descriptors use content-v2 source/stored lengths and SHA-256,
   statuses `stored`, `pending`, `redacted`, `truncated`, `unsupported`,
   `dropped`, or `failed`, and credential-free tenant-bound refs. Metadata
   events use AEEP record IDs and preserve native OTel trace IDs only when
   present. No body carries content.
6. The source spool, Node acceptance, destination acceptance and durable
   destination receipt are distinct. A local store readback is not a
   destination receipt. OTLP partial success reports rejected count as a
   known gap; retrying a partially accepted batch without exact rejected
   identities cannot create completeness.
7. An authorized offline resolver rechecks tenant, namespace, descriptor,
   exact byte length and SHA-256. The reconciler compares specific expected
   operations and objects with independent endpoint/terminal/filesystem
   truth. Known loss or missing required roles means `partial`; unavailable
   identity, health, feed or durable receipt means `unverified`; only all
   required independent proofs permit `verified_complete_for_declared_scope`.

Pre-code tests: exact and empty binary bytes, absent versus empty, chunk
order, two streams, large-output truncation, signal/cancel, retry identity,
direct HTTP/subprocess bypass, source outage/crash/restart, disk full,
corruption, cross-tenant ref, canary leakage, OTLP 200 partial success,
dedupe on replay, false complete fixture, and same-SHA installed-artifact
smoke. Tests that need Linux BPF, Docker, Kubernetes, KMS, or customer
destination are environment gates, never mock substitutions.

## Phase 3 — Minimal adapters, documented before implementation

Implement an opt-in Python controlled-provider HTTP adapter, a bounded
no-shell subprocess adapter, and an allowlisted artifact observer. The
adapters return the underlying response/process result unchanged, never
block on content-store I/O, and never install global monkeypatches. They
use a common source sequencer and the existing content-v2 byte store.
Capture failure changes evidence status only, not the monitored operation.
The initial subprocess proxy and synchronous before/after file observer are
**test-harness implementations**, not qualified passive production capture:
their scheduling, stream drainage and file reads can add latency or
backpressure. A non-interference fault test and a target-specific passive
observation design are required before deployment promotion.
The current shared byte recorder deliberately labels every descriptor
`caller_reported`. The adapter observation point is documented and compared
with independent fixture bytes, but it is **not** upgraded to `protocol` or
`native` provenance until a trusted-source contract is validated. No hidden
post-provider state is claimed.

## Phase 4 — Loss and receipt semantics, documented before implementation

For the first slice, do not rely on the audit receiver for completeness.
Keep host netlink as optional inferred corroboration and mark its unknown
loss `unverified`. A source spool must atomically persist records and
sequence/high-water state, recover after crash, bound disk and expose
overflow/corruption. Passive capture cannot fsync on the monitored call's
critical path; the pre-spool window remains a declared limitation and a
crash there makes the run unverified unless independent truth proves all
expected operations. Partial OTLP acceptance is a terminal rejected-count
gap unless individual rejects are identified by an authenticated receiver.
The optional host emitter now retains a partly accepted batch in a
restart-stable `.partial` quarantine with its rejected count and does not
replay possibly accepted records. This local count is not an authenticated
downstream receipt or exported run gap; host remains outside this slice's
complete-run source set.

### Phase-4 synthetic source-journal implementation contract (before code)

The local Python fixture may opt into a tenant/run-bound, single-writer source
journal on a dedicated owner-only directory. Initialization verifies real
directories and an exclusive process lock, persists a fresh monotonic epoch
before the first monitored action, and refuses identity mismatches or unsafe
entries. Each metadata-only event has a stable record ID, source/epoch/sequence
and initial content status. A bounded in-memory handoff submits it without
fsync on the monitored call path. The worker writes one immutable event to a
temporary owner-only file, fsyncs it, renames it and fsyncs the directory.
Only then is `source_spooled` locally observable. Reopening the same run
increments the epoch and recovers prior committed files; incomplete temp
files, corrupt entries, duplicate positions and identity mismatches fail
closed. Quota, queue overflow and write faults create explicit local gaps.

The journal is **metadata only**; content bytes remain in the separate tenant
store. Its queue and the pre-fsync crash window mean source completeness is
still `unverified` without independent truth reconciliation. A local
`source_spooled` stage is not Node acceptance, destination acceptance or
destination durability. Qualification tests must inject queue overflow,
restart/recovery, truncated/corrupt files, unsafe symlinks, concurrent owner
and disk-full/write failure. Target volume encryption, retention and restore
remain separate phase-6 proofs.

### Phase-4/7 metadata projection to Fabric Node (before code)

The first live bridge is an **offline, post-run synthetic exporter**, not an
on-action network call or a background production source. It maps settled
local byte events to OTLP LogRecords with empty bodies, fixed AEEP EventName,
and a closed `event_class=evidence` attribute set. It exports record,
tenant/run/source/epoch/sequence, operation/attempt, boundary, role, status,
provenance and content object ID/digest only. It deliberately omits absolute
`file://` refs, raw paths, bytes, argv, cwd and free-form outcome values.
The destination is loopback-only for this synthetic profile; production
source authentication, retry/dedupe, durable receipt and gap publication
remain unimplemented. The offline bridge and Node guard now accept this class through a fixed
value-validated allowlist, preserve the five AEEP event names, strip bodies
and unknown keys, and reject arbitrary role/status/ref strings. The real
Node test compares record IDs and expected safe fields in the controlled
sink and probes canaries in log body, log attributes and resource attributes
across sink, logs and queue. A resource group containing evidence records must
not retain caller-supplied free-form resource or scope attributes. OTLP 200 is only Node
acceptance, not destination durability proof.
The local full-flow fixture must also project **every** settled byte event,
compare the exact set of record IDs, roles, statuses and digests against its
resolved ledger, and assert no fixture byte or local path enters the OTLP
payload. This offline check is necessary but does not replace the real-Node
or independently authenticated pilot gate.

## Phase 5 — Resolver and reconciler, documented before implementation

The resolver accepts an authorized store instance and tenant identity, not
an arbitrary telemetry-supplied URI. It rejects URL userinfo, query strings,
remote `file://` authorities, traversal and symlinks. It reports
`available`, `pending`, `missing`, `denied`, `corrupted` or `unverified`;
never substitutes empty bytes for missing content. The deterministic
reconciler emits a discrepancy row per run/source/boundary/operation/role,
including missing, extra, duplicate, corrupt and unsupported observations.
It validates trusted independent-feed provenance before a complete verdict.
This is an offline verifier/export, not an evaluation service.
The initial implementation can emit `partial` for known discrepancies or
`unverified` for a matching fixture, never
`verified_complete_for_declared_scope`: source authentication, durable
continuity, independent-feed authentication and destination durability proof
are absent. A self-supplied fixture cannot confer that trust.

## Phase 6 — Privacy and storage tests, documented before implementation

Run canaries through each adapter and prove they are confined to the
dedicated content store. Test local owner/mode, cross-tenant denial,
descriptor/byte corruption, quota/disk-full and restart behavior. Record
encryption, retention, backup/restore and key-rotation results separately
for content store, source spool and Node queue. A local filesystem unit
test cannot satisfy a target KMS/object-lock/retention gate.

## Phase 7 — Exact-artifact tests, documented before implementation

Build once from a clean tagged SHA; record wheel/sdist, npm tarball,
chart/Node/host image digests and installed config digest. Test installed
packages and digest-pinned images in a disposable isolated environment.
Use unique Docker project/container/volume names and delete only resources
created by that run. The privileged all-host host-emitter smoke script is
**not** authorized for this slice; a scoped Linux BPF run requires separate
explicit approval. Docker/Kubernetes unavailability leaves this phase
`NO_GO`, regardless of local unit tests.
For a locally prebuilt Node image, the disposable Compose gate may accept an
explicit unique image tag and start with `--no-build`; it must verify the
image ID before and after the test and may remove only its random Compose
project. This is not equivalent to a clean tagged release digest or a
target-Kubernetes gate.

## Phase 8 — Synthetic shadow pilot, documented before implementation

Pre-register fixture bytes, operations, roles, attempts, fault seeds,
capacity and independent truth feeds. Reconcile every expected object and
operation; publish a machine-readable discrepancy report, exact artifact
digests, commands, skipped tests, reviewers and residual blind spots.
Acceptance requires zero unexplained discrepancies, every injected loss
lowering the verdict, privacy canaries confined to approved storage, and
independent reproduction from the exact installed artifacts. Until then the
slice and critical-enterprise gate remain `NO_GO`.

Follow-on work needs **separate** bounded specs for SSH remote-side capture,
DB client/server audit and rows, browser/cloud request/effect evidence,
sandbox/container internals and other reachable routes. None is covered by
the first slice.
