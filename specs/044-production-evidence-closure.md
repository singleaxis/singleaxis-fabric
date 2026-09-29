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

## Evidence ledger

Implementation and test results are recorded in
`docs/recorder-v1-qualification-status.md`. Each phase must state which code and
test environment were exercised. Do not replace failed security or deployment
gates with local simulation results.
