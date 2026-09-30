---
title: Bounded production evidence closure
status: implementation_in_progress
qualification: NO_GO
revision: 1
depends_on: 035, 036, 037, 038, 039, 043
---

# 044 — Closing the production evidence gaps

## Scope and acceptance before implementation

Continue the bounded Python custom-agent recorder and existing isolated Linux
qualification. Fabric remains passive CAPTURE -> PROTECT -> DELIVER. Recording
failure must not change an agent operation. The production decision still
requires the named deployment, approved scope, actual storage controls and
independent reviewer required by specs 037–039. Local keys or synthetic fixtures
cannot provide customer approval or make an in-memory handoff crash safe.

### Phase A: security findings

Inspect every reported finding against the exact source and public history.
Repair actual descriptor-cleanup and writable-file close paths. Where type-only
imports create cyclic static dependencies, remove the dependency without
weakening public API types or hiding alerts. Test both import orders and the
failure paths. Do not suppress broad scanner rules, rewrite repository history,
test historical credentials against services, or dismiss alerts merely to turn
CI green. A proven fixture match may be documented with exact commit/path/rule
and literal construction; an actual or ambiguous credential requires its owner
to classify and rotate it. Preserve security sign-off as an external gate.
After source review and owner clarification establish a match is a never-used
example, baseline only its exact commit/path/rule/line fingerprint. Keep default
detectors and full-history scanning enabled. Prove a newly introduced matching
test credential still fails scanning. This classification is not a general
production risk acceptance.

### Phase B: authenticated offline attestations

Add an optional offline verifier for cryptographically signed evidence. Use
Ed25519 from the existing optional signing dependency and a domain-separated,
deterministic JSON payload. The caller supplies a trusted key registry from the
approved deployment; keys embedded in untrusted evidence cannot confer trust.
Each key is pinned to issuer, tenant and permitted statement types. Statements
bind the scope/run and exact subject SHA-256; validity times, key validity and
revocation are checked against an explicit verification time.
Both issuance and verification time must lie inside the key validity interval.
A signer-controlled timestamp cannot prove that an expired key signed before
retirement. Historical verification beyond key expiry requires a separately
trusted timestamp/receipt mechanism and is not implemented here. Pin the exact
expected issuer as well as tenant, scope and subject; another same-tenant
destination authority cannot substitute for the declared destination.

Closed statement types are source binding, independent witness, source-spooled,
Node-accepted, destination-accepted and destination-durable. The issuer of each
stage must have authority for that stage. Acceptance never implies durability.
Verification rejects duplicate JSON keys, unknown fields, malformed/nonfinite
values, wrong domain/algorithm, unknown/revoked/expired keys, wrong tenant,
scope/run/subject, changed payloads and invalid signatures. A valid signature
proves an authorized issuer made the statement; it does not prove the issuer
observed an event or performed fsync. The producer and deployment must still be
qualified independently. Do not add a runtime signing service or judge.

The first phase-B output is a verified/unverified attestation result with a
fixed reason and no raw input/exception text. It must not on its own promote
`reconcile_call_run` to complete. Wiring that decision requires independently
authenticated full operation/byte sets, route closure, source lifecycle and
the four stage receipts, with negative completeness tests.

### Phase C: deployment qualification

Freeze a deployment scope with exact builds, required roles, route exclusions,
capacity/outage bounds, privacy and retention schedules and independent feeds.
Qualify source credential binding, bypass detection, crash-before-fsync gaps,
target storage isolation/encryption/retention/restore/rotation and complete
stage receipts against the existing installed-artifact pilot. One missing
required operation, byte object, source terminal marker, receipt or trusted
witness prevents complete status. Missing approval or target proof keeps the
deployment NO_GO. Host/BPF and remote routes are separate required gates only
when included in the declared reachable scope.

### Phase C1: dedicated authenticated source ingress

The smallest supported identity binding uses one dedicated Node ingress and
one approved bearer credential for one tenant/source. This fits the bounded
initial deployment; it is not shared multi-tenant authentication. Add optional
trusted tenant/source configuration to fabricguard, compare every AEEP record
before accepting the batch, and reject mixed, missing or forged identities with
fixed errors. It must never trust OTLP attributes merely because they exist.

The startup gate must require the dedicated profile to have exactly one OTLP
receiver with bearer authentication on both HTTP and gRPC, a single protected
token file, no other ingress into its guarded pipeline, guard before batching
and the approved export path. TLS remains required by the production profile.
Token material cannot appear in errors or telemetry. Credential ownership and
exclusive provisioning remain deployment proofs. Do not add an authenticated
claim outside this verified profile or infer process identity from an IP.
The pinned bearer extension must itself discard blank token entries on initial
load and every file reload. A supervisor polling a mutable token file cannot
close the interval between an unsafe rotation and its next check. Qualify the
patched module in the exact shipped image; keep the gate's singleton-token
preflight and rotation checks as an additional deployment safeguard. A
Kubernetes projected Secret rotates by atomically replacing its `..data`
symlink, not by writing the token symlink. The extension must reload on that
parent-directory replacement; after the observed reload it must reject the old
credential, accept only the new singleton credential, and fail closed if the
replacement contains malformed material. Filesystem notification and Secret
projection have latency: this does not claim instantaneous revocation at the
moment of update. Exercise this with a real filesystem watcher and atomic
symlink swap, not only by calling the reload function directly.

Acceptance: invalid/missing token on both protocols; forged/missing/mixed
tenant/source; alternate unauthenticated receiver and processor order rejected
by the gate; direct-file and Kubernetes projected-Secret token rotation; no raw token/canary in sink/logs/queue; real Node
installed-artifact test. Rejecting recorder telemetry must not affect an agent
operation. The final complete-run decision still needs source loss accounting,
independent witnesses and distinct receipts.

The live dedicated-ingress probe also requires a non-retryable client-error
response for a syntactically valid request with forged or missing bound
identity: OTLP/HTTP 400 and OTLP/gRPC `INVALID_ARGUMENT`, with a fixed message
that contains no supplied value. Collector v0.150.0 maps a permanent consumer
error without an attached gRPC status to `INTERNAL`/HTTP 500. Therefore the
guard's bound-identity rejection must carry both the permanent marker and an
explicit `INVALID_ARGUMENT` status. A generic 500 is not an acceptable test
outcome, even when the batch was not forwarded. Verify the pinned receiver
mapping and preserve whole-batch rejection before any mutation or delivery.

## Next implementation slice: authenticated complete-run proof (not implemented)

The C1 ingress tests do not close this slice. Preserve `reconcile_call_run` as
the local comparison API and its conservative verdict. Add a separate offline
qualified entry point only after defining these inputs and negative tests:

1. **Approved scope and independent feeds.** Define deterministic scope and
   feed-manifest encodings. Each feed binds its route, complete cursor interval,
   operation/attempt outcomes and required byte role/chunk/length/SHA-256 set.
   Recompute the feed digest from independently resolved bytes, then verify the
   exact route-authorized issuer's `independent_witness` statement. Existing
   `CallByteWitness` and `CallOperationWitness` are comparison data, not trust.
2. **Saved source-end record.** Add an explicit post-run finalization method,
   outside the monitored action. Drain the spool, read back every assigned
   event and fsync an epoch/run seal containing source identity, final assigned
   high-water, exact event-ID/digest set, loss counters and terminal state.
   Pending, failed or dropped records prohibit a clean seal. Recovery must
   verify every epoch's seal; never infer its expected end from the highest
   surviving sequence. Bind the disk-read seal to an authorized source receipt.
3. **Closed routes.** Add a precise public `route_closure` statement contract
   before implementing verification. A platform-authorized issuer must bind
   the reachable-route inventory and deployment controls to the scope hash.
   A `RouteDeclaration` or an agent's own assertion is not independent proof.
4. **Separate receipts.** Source-spooled, Node-accepted, destination-accepted
   and destination-durable statements cover different recomputed sets. Link
   exact IDs/digests across the source journal, approved export and destination
   readback. Source flush or OTLP success never substitutes for another stage.
   The source-seal issuer, Node acceptance emitter, destination acceptance and
   durable-readback issuers are all still missing. Qualify each producer;
   accepting a valid signature alone is insufficient.
5. **Qualified reconciliation.** Ignore caller authentication/receipt flags.
   Require clean local comparison, exact authorized object resolution, all
   source epochs sealed, authenticated complete feed intervals, valid route
   closure and coverage by every required receipt stage. Missing independent
   proof means `unverified`; observed loss or mismatch means `partial`.
   Only the fully proved declared scope can be complete. A positive locally
   signed fixture tests implementation, not customer approval or production GO.

Relevant implementation surfaces: `call_reconcile.py`, `call_recorder.py`,
`source_spool.py`, `byte_evidence.py`, `call_otlp.py` and
`evidence_attestation.py` under `sdk/python/src/fabric/`. Preserve compatibility
and keep all checking offline; do not add a judge or signing management service.

The operation-to-fsync interval remains inherently non-atomic for passive
asynchronous recording. `test_source_spool.py` already demonstrates that a
crash can leave no visible sequence hole. Missing seals and independently
witnessed physical operations must expose that uncertainty. If both are
unavailable, the answer is unknowable, never complete. Persisted terminal
high-water, recovery seals and durable loss counters are engineering work,
not issues that can be delegated to customer approval.

Acceptance before coding: crash after enqueue, before file fsync, before
directory fsync and before seal; deleted journal tail; overflow and counter
loss across restart; missing or forged cursor/operation/byte; wrong signer,
tenant, scope or stage; each missing receipt; acceptance without durable
readback; reachable bypass; clean cryptographic fixture. Every omission must
prevent a complete verdict. Customer storage and named owner sign-off remain
additional gates even after this code exists.

## C2 implementation contract — durable metadata epoch seal

Implement this narrow prerequisite before a qualified reconciler. It is not a
run-completeness receipt and must not change existing verdicts. An explicit
`SyntheticSourceSpool.seal_epoch(expected_high_water, timeout_s=...)` call runs
only after monitored work, stops further metadata admission for that epoch,
waits within the bound for queued writes, securely reads all current-epoch
event files and compares exact source sequence sets against the supplied
assigned high-water map. A caller-supplied map is a consistency assertion,
not independently authenticated truth. Do not obtain expected high-water by
taking the largest surviving sequence during recovery.

The metadata-only seal uses a closed schema with tenant/run/epoch, exact
source high-water map, record count, and SHA-256 over the ordered canonical
event records. Persist it as mode-0600 `seal-<epoch>.json` using file fsync,
atomic replace and directory fsync. Require no pending, failed, dropped or
unretained records and exact match to all records admitted in memory; compare
disk bytes/digests with admission-time expected metadata digests so a validly
rehashed substituted file cannot be silently sealed. Bound seal size/count
and include seals in disk capacity accounting. Journal content status
`pending` records an observation, not a content-store receipt: the seal covers
metadata persistence only. Object availability is always a separate check.

Refuse repeated/conflicting seal writes, undeclared sources, source-position
holes, absent or additional events, corruption, quota/write failures and
unsettled writes. Refusal returns a fixed bounded reason and never a clean
seal. Ordinary `close()` does not create a seal. After seal attempt, further
append attempts fail as recorder evidence without blocking/changing an agent
delegate. A continued run must use a new epoch; this API certifies neither
that no later work occurred nor that all reachable routes were observed.

Recovery exposes verified seal metadata separately from recovered events and
records every prior epoch lacking a seal, including an epoch with **zero**
surviving events. A present seal whose count, identities, sequence bounds or
digest disagrees with disk fails closed, including tail deletion and an event
with a self-consistently rewritten checksum. Legacy unsealed journals remain
readable but explicitly unsealed/unverified; their apparent largest sequence
is only an observed value, never an expected terminal mark.

Acceptance: empty epoch with explicit empty-source high-water `-1`; normal
multi-source seal and restart; missing tail, altered bytes, extra record,
rehashed substitution before/after sealing; invalid/bool/huge high-water;
queue/disk-full/write/fsync failures; crash before event persistence and before
seal persistence; close without seal; late append; seal file permissions and
tenant mismatch; repeated finalization; secret-canary absence. Tests must
distinguish process-crash simulation from actual power-loss qualification.
No automatic signer, destination receipt or complete verdict is added here.

`CallRecorder.seal_source()` is the explicit offline convenience API. It must
refuse while a call/stream is running or partial, content writes are pending,
required observations failed, or recorder/spool losses are known. It passes
the recorder's assigned sequence high-water to the spool; never guesses it
from disk. A later call still executes normally, but cannot enter a sealed
epoch and must create a visible recording gap. Snapshot output distinguishes
the recovered observed maximum from a seal's terminal high-water and includes
compact prior-unsealed epoch ranges, even if no record survived an epoch.
Missing seals preserve uncertainty; matching seals do not clear source trust,
independent-feed or destination proof flags. A seal is explicitly limited to
metadata persistence and never labels pending content as stored.

The installed-wheel custom-agent smoke must explicitly seal its completed
source, reopen it with a tenant-authorized byte resolver and compare each
recovered call and object with the original independent fixture witnesses.
Require an unchanged `unverified` verdict with zero discrepancies, not a
promotion to complete. In a separate disposable copy of the sealed journal,
delete the terminal event and require recovery to fail. Keep the original
journal intact for review; report these metadata tests separately from content
and destination durability. These checks run in the existing isolated Linux
workflow against its installed wheel, without rebuilding that wheel mid-test.

Operational qualification limits: the timeout bounds each queue-drain wait
(zero to 3,600 seconds), not a stalled kernel filesystem operation. Sealing
must remain offline, outside the agent path. Local single-fault tests cover
intent, seal and final directory-fsync failures. If a final fsync or detected
concurrent loss requires restoring the intent and that restoration also
fails, the local store alone cannot prove the failed result across a crash.
Do not qualify that double-failure/power-loss case without an independent
receipt and target-storage tests. A cached seal is never fresh disk readback
and a durable prefix cannot prove that no later activity occurred.

## Evidence ledger

### PR #164 CI closure plan (head `4bf4df9`)

The first Linux CI run exposed three separate gates, not a single recorder
failure. Helm 3.15 rejected the intentionally injected undeclared Secret
field, but the chart test matched Helm 3.19's exact diagnostic wording; keep
the schema rejection and assert a version-neutral diagnostic. The image build
stopped while Go downloaded a pinned gRPC dependency because the module proxy
returned an HTTP/2 stream error, before the patched Collector, image scan or
runtime tests ran. Retry the same source on isolated CI; do not waive the
image scan or claim it passed. Full-history Gitleaks found a new static token
literal in a gate unit-test fixture. Replace the literal with deterministic
runtime-generated test material, prove the committed value's fixture-only
provenance, then add at most that exact already-committed fingerprint to the
historical baseline; retain full-history scanning and a new-commit rejection
probe. Any ambiguous provenance remains an unresolved security finding.

Acceptance: Helm 3.15 and 3.19 both reject the undeclared value; gate tests
still exercise a valid singleton token and malformed rotations; Gitleaks
reports no unclassified findings and the independent probe still detects a
new canary; the exact image build, patch metadata, vulnerability scan and live
tests must pass on CI before qualifying the artifact.

Implementation and test results are recorded in
`docs/recorder-v1-qualification-status.md`. Each phase must state which code and
test environment were exercised. Do not replace failed security or deployment
gates with local simulation results.
