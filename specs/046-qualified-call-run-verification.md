---
title: Qualified offline call-run verification and exact receipt sets
status: draft
qualification: NO_GO
revision: 1
depends_on: 035, 038, 039, 043, 044, 045
---

# 046 — Finish the bounded evidence verification path

## Completion list and order

1. Specify this interface and its negative tests before implementation.
2. Add fresh, authorized source-journal readback, not a cached seal.
3. Add bounded exact-set receipt verification for four separate stages.
4. Connect authenticated independent feeds to original-byte reconciliation.
5. Require authenticated source binding and owner-issued route closure.
6. Exercise the installed wheel with a synthetic signed-evidence fixture,
   including omissions, tampering, unavailable stores and receipt substitution.
7. Run repository tests and the existing exact-artifact Linux qualification.
8. Publish commands, artifact hashes, discrepancies and remaining live gates.

Fabric remains passive CAPTURE -> PROTECT -> DELIVER. All new verification
is optional and offline. No scheduler, judge, enforcement, signing service,
approval service or mandatory vendor connection is introduced. Private keys
exist only in separately controlled fixture apparatus or customer issuers.

## Bounded first interface

Qualify one tenant/run and one explicitly declared source epoch per invocation.
Multiple feeds may partition its route/boundary observations. Multi-epoch and
multi-source deployment qualification require a separately specified aggregate
registry; this interface must reject them rather than silently omit history.
Existing `reconcile_call_run` remains conservative and unchanged.

The caller supplies approved expectations out of band: tenant/run/scope digest,
source identity/epoch, exact route inventory, issuer per proof stage, and every
045 feed expectation including native attempt ledger and terminal cursors.
Do not infer these expectations from captured or submitted records. The owner
must also pin the agent build, provider endpoint, permitted execution/file
paths, required roles, workload/outage bounds, privacy/retention and excluded
routes in the document whose canonical digest is the scope digest. A signature
authenticates an issuer's claim; separate deployment tests establish whether
that issuer and its controls actually observe the declared system.

## Exact receipt-set contract

Add `fabric.receipt_sets` with immutable `EvidenceSetEntry(kind, identifier,
sha256, byte_length)` and `ReceiptSetExpectation(stage, tenant_id, run_id,
scope_sha256, set_id, issuer_id, entries)`. Kinds are `source_record`,
`metadata_record`, `content_object`, `source_seal`. Entries have safe opaque
ASCII identifiers, SHA-256-prefixed lowercase digests, nonboolean nonnegative
lengths; duplicate `(kind,identifier)` entries are forbidden. Bound the set to
4096 entries, 1 MiB canonical manifest, nesting depth 8, object length 16 MiB.
Entries are sorted by `(kind,identifier)`, never count-only comparisons.

`receipt_set_bytes(expectation)` creates the exact closed canonical JSON:
schema_version `fabric.receipt-set/v1`, stage, tenant_id, run_id,
scope_sha256, set_id, issuer_id, entries (kind, identifier, sha256, byte_length).
`verify_receipt_set(manifest_bytes, attestation_bytes, *, expectation,
trusted_keys, verification_time)` recomputes the expected set from caller
readbacks, demands byte-for-byte equality with the submitted canonical
manifest, and verifies the existing Ed25519 statement of type `stage`, subject
kind `evidence_set`, ID `set_id`, digest of the manifest. Missing proof is
`unverified`; contradictory sets or signatures are `invalid`; complete proof
is `verified`. Results contain only fixed reasons and bounded counts.

Four stages remain distinct:

- `source_spooled`: exact fresh sealed journal records, seal and resolved
  original content. Journal hashes use original admission records, not later
  snapshot statuses (a byte observation is initially pending).
- `node_accepted`: exact normalized projected metadata records witnessed at
  the Node boundary; it is not inferred from an HTTP status.
- `destination_accepted`: exact normalized records witnessed at the selected
  destination; Node acceptance is not a substitute.
- `destination_durable`: exact normalized records recovered from durable
  destination readback, plus original content-object readback. The pinned
  issuer must be authorized to attest both metadata and protected storage,
  or this first combined-set interface is unsupported for that deployment.

Metadata normalization removes attribute ordering and OTLP grouping but retains
every projected record attribute and event name. Reject duplicate attributes
or record IDs and unexpected additional record fields. Bind each normalized
record to `record_id`; compare exact normalized sets at each stage. No raw
content, content refs, credentials or arbitrary exception text may enter a
receipt. Do not claim fsync, database commit or retention from an OTLP success.

## Fresh source readback

`SyntheticSourceSpool.readback_sealed_epoch(epoch)` securely re-reads the journal
and seals using the existing ownership/no-symlink/bounded readers and seal
validation, without advancing an epoch or writing anything. Return a deep copy
of the seal and exact records only if the epoch is sealed and no pending seal
intent exists. A removed/corrupt record, changed permissions, unsealed epoch or
invalid epoch must fail with a fixed public error. A cached `current_seal()`
must never stand in for fresh durable readback. This is offline and cannot
delay an agent call. The pre-fsync loss window remains possible: an independent
native operation missing from this journal must force a partial verdict.

## Qualified offline reconciler

Provide an optional `LocalIndependentFeedResolver(root, *, tenant_id, issuer_id,
max_object_bytes=16 MiB)` for deployment-approved local witness storage. The
layout is `root/tenant_id/issuer_id/object_id`. Reads use directory FDs and
`O_NOFOLLOW` on every component, reject hardlinks/nonregular files, require
owner-only namespace and object permissions, and bound reads before allocation.
Validate opaque IDs (never URLs/paths), owner identity and unchanged file stat
before/after reading. Fixed read errors must not leak paths or canaries. It
performs no writes or network calls; supplying its root is explicit authorization
for that single tenant/issuer namespace, not proof of witness independence,
encryption, retention or remote IAM. No fallback to Fabric's captured store.

Add `fabric.qualified_run` with `QualifiedFeedInput` (raw manifest, raw
attestation, 045 expectation, separately authorized byte resolver),
`QualifiedRunExpectation` (scope bindings, routes and source/stage issuers), and
`verify_qualified_call_run`. The verifier accepts raw proof documents, never
caller booleans or precomputed `verified` objects. It must:

1. Validate bounded inputs and exact tenant/run/source/epoch, with no implicit
   recovery-history or undeclared route coverage.
2. Reverify every feed using 045. Materialize comparison bytes only internally
   after authentication, and recheck length/hash on the exact materialized
   bytes to prevent a changing resolver from substituting a second read.
   Deduplicate physical attempt/role keys across feeds; require the exact
   independently expected route and operation/byte sets.
3. Reconcile every original object, attempt, outcome, stream and call graph;
   validate journal-to-snapshot stable identity and lifecycle content. Only
   stored-byte status/descriptor enrichments may differ from admission records.
4. Freshly read the sealed source epoch and require every assigned sequence,
   exact record ID, terminal high-water mark and seal to match. Recovered or
   unsealed history is not silently promoted.
5. Verify `source_binding` with subject kind `source`, source ID and digest of
   canonical `{tenant_id,run_id,source_id,source_epoch}`.
6. Add purpose-specific `route_closure` attestation type, subject kind
   `evidence_set`. Its canonical subject is the independently supplied exact
   route inventory plus tenant/run/scope/source epoch. The issuer attests
   inventory/closure controls for this declared scope; the recorder does not
   install those controls. Reachable unobserved routes force `partial` even
   when the inventory is signed. Missing closure proof prevents completeness.
7. Recompute the four expected receipt sets from source/byte/projection
   readbacks; verify all four independently pinned issuers and signatures.

Result schema `fabric.qualified-call-run/v1` contains a verdict, fixed reason
codes, per-feed and per-stage statuses, bounded counts and digests. It never
contains original bytes, raw arguments, refs, signatures, keys or exception
messages. Known loss, wrong bytes, unexpected operations, changed journal,
wrong signatures/identity or reachable unobserved routes -> `partial`.
Unavailable proofs/readback -> `unverified` unless a known discrepancy already
requires `partial`. Only all exact comparisons and required proofs passing ->
`verified_complete_for_declared_scope`. That verdict authenticates and checks
the submitted bounded evidence under the configured issuer trust model; it
does not itself qualify issuers, prove their independence, establish hidden
provider state, deterministic replay, enterprise approval or universal capture.

## Acceptance tests and evidence producers

Use a non-sensitive custom-agent model -> no-shell tool -> artifact -> model
fixture with a separately populated native operation ledger and byte store.
Test empty/binary bytes, ordered stream chunks, parallel calls, retry attempts,
failure/cancellation and causal links. Fixture signers must be identified as
fixture-only; do not label fixture signatures live provider/storage proof.

Require a positive fully proven offline case, then independently remove each
operation, required role/chunk, byte object, source record, seal, feed, source
binding, closure proof and each stage receipt. No omission may keep complete.
Test same-count substitution, wrong tenant/issuer, key expiry/revocation,
duplicate feed coverage, resolver second-read mutation, content corruption,
metadata mutation, Node-only receipt reuse, acceptance without durable readback,
OTLP partial success, unwrapped operation and reachable unobserved route.
Canary content may appear only in authorized fixture original storage; reports,
OTLP projection, journals, receipt manifests and exceptions must remain clean.

Add an installed-wheel qualification command and artifact-content assertions
for these optional modules. Reuse the isolated Linux workflow for the unchanged
Node/chart/image path and record any unavailable target tests. Real Node and
destination receipt issuance, target KMS/IAM/retention/restore/rotation proofs,
live provider native feeds, route controls and owner sign-off remain explicitly
unqualified until tested on their actual implementations. They are not replaced
by fixture signatures. Keep deployment status NO_GO when such gates cannot run.
