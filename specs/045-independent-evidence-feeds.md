---
title: Authenticated independent operation and byte feeds
status: draft
qualification: NO_GO
revision: 1
depends_on: 035, 037, 038, 039, 043, 044
---

# 045 — Independent evidence-feed contract

## Purpose and boundary

This is a public, optional **offline verification input** for a declared custom
agent run. Fabric remains passive CAPTURE -> PROTECT -> DELIVER. A qualified
provider, terminal, filesystem or database witness may supply its *own* record
of physical operations and exact bytes. This first verifier checks that feed
against separately supplied native-ledger expectations; it does **not yet**
compare the feed with Fabric's captured record. It does not operate an agent,
sign for a customer, run a judge, or turn on continuous evaluation.

`reconcile_call_run` currently accepts `CallByteWitness` and
`CallOperationWitness` as comparison data, but the `witness_source` string does
not authenticate either list. The synthetic smoke builds provider and file
witnesses in fixture delegates and reads SQLite through a separate connection;
this demonstrates matching, not a qualified independent audit feed. This spec
defines the narrow evidence required before those lists may be described as
authenticated. It does **not** make `verified_complete_for_declared_scope`
available. Source lifecycle, closed reachable routes, four delivery receipt
stages, target storage proof and owner approval remain separate gates in 044.

## Trust and feed-production prerequisite

The deployment owner must provision a trusted key registry out of band. Each
key is pinned to one issuer and tenant and permits the existing
`independent_witness` statement type. An approved scope must independently pin
which issuer is authoritative for each `(route_id, route_version, source_id,
boundary, cursor_domain)` tuple. A key included in a feed is never authority.
The verifier must receive the expected route, source, tenant, run, scope digest,
cursor domain and native start/end cursor values from a separately approved
feed registry or native boundary/checkpoint records. It must not derive an
expected terminal cursor from the highest row in the submitted feed or from
Fabric's snapshot.

The issuer must be a separately qualified producer with access to its native
operation ledger and a complete, stable cursor for the declared interval. Its
issuance procedure must enumerate *all* native rows between independently
established start/end checkpoints, including failed and cancelled attempts,
and produce independently retrievable byte objects. A signature authenticates
the issuer's statement; it cannot prove the issuer actually queried all rows,
allocated a cursor before a crash, or could see bypass routes. Those are
deployment qualification and route-closure questions. A provider that offers
only aggregate counts, an incomplete sampled trace, or no native terminal
cursor cannot satisfy this contract, even if it can sign a manifest.

## Closed feed document, version 1

Use a single bounded UTF-8 JSON document with exact top-level keys:

```json
{
  "schema_version": "fabric.independent-feed/v1",
  "feed_id": "opaque-id",
  "tenant_id": "opaque-id",
  "run_id": "opaque-id",
  "scope_sha256": "sha256:<64 lowercase hex>",
  "route_id": "opaque-id",
  "route_version": "opaque-id",
  "source_id": "opaque-id",
  "source_epoch": 0,
  "boundary": "provider_bound",
  "cursor_domain": "opaque-id",
  "cursor_start": 0,
  "cursor_end": 1,
  "records": []
}
```

All IDs use the existing safe ASCII identifier grammar, 1–128 characters.
`source_epoch`, cursors and `chunk_index` are non-boolean bounded integers.
The first verifier limits the manifest to 1 MiB, 4,096 rows, nesting depth
8, each byte object to 16 MiB and aggregate resolved bytes to 64 MiB.
Cursors and epoch are at most 2^53-1; each stream has at most 4,096 chunks.
These limits are checked before allocation/read where possible. `cursor_start` is
nonnegative; `cursor_end >= cursor_start - 1`. An empty interval is represented
only by `cursor_end == cursor_start - 1` and an empty `records` array. A producer
may issue multiple nonoverlapping documents for one route/run only if a higher
level approved registry supplies their exact ordered interval partition; the
first implementation should require one document per route/source epoch.

`records` is ordered by strictly increasing, unique cursor and contains
exactly one row at every integer in the closed `[cursor_start, cursor_end]`
interval. Each row has exact common keys `cursor`, `kind`, `operation_id`,
`attempt_id`. No cursor may be silently skipped, duplicated, inserted or
reordered. There are exactly two `kind` variants:

- `operation`: additionally `outcome`, a closed mapping with required
  `result_status` (`ok`, `error`, `cancelled`) and optional approved scalar
  outcome fields (`http_status`, `returncode`, `signal_number`, `timed_out`,
  `artifact_present`, `artifact_size`, `artifact_phase`,
  `artifact_path_sha256`). Integers are never booleans: HTTP status 100–599,
  return code -255–255, signal null or 1–128, artifact size 0–16 MiB;
  `artifact_phase` is `before`/`after` and path hash is 64 lowercase hex.
  `timed_out` and `artifact_present` are booleans. No other fields or types
  are accepted. Absent and explicit false/zero remain distinct.
  One physical attempt has exactly one terminal outcome row. Its
  `(route, source, epoch, operation_id, attempt_id)` key is unique. Retries
  have distinct attempt IDs and rows; parallel attempts do not collapse.
- `byte`: additionally `role`, `chunk_index`, `byte_length`, `sha256`,
  `byte_object_id`. `chunk_index` is either null for a nonstream object or a
  nonnegative integer. `byte_object_id` is an opaque identifier in the
  independently configured witness store, not a URL or file path supplied
  to a general-purpose fetcher. A byte row's operation/attempt must have an
  operation row in the same document. Its `(operation_id, attempt_id, role,
  chunk_index)` key is unique. Stream chunks for a required role are exactly
  `0..N-1`; empty bytes are `byte_length: 0` plus the SHA-256 of empty bytes,
  never represented by an absent row. A required absent, withheld, redacted,
  truncated or unavailable original is **not** an exact-byte witness.

The approved native-ledger expectation supplies the **exact** set of physical
`(operation_id, attempt_id, outcome)` records and each attempt's required
`(role, chunk shape)` set, independently of this submitted feed. A shape is
either one nonstream object (`chunk_index: null`) or an exact stream count
`N` with indices `0..N-1`; the expected count is not read from the submitted
rows. The verifier must compare the manifest to those expectations, not merely
verify rows that happen to be present. A role may be conditionally required
only when the approved native-ledger expectation supplies that rule/result;
the feed cannot choose to omit it. Additional feed rows or unexpected roles
are discrepancies, not harmless extras. These rows can
carry exact byte lengths and SHA-256 but never raw prompts, responses, tool
bodies or secrets in the manifest or its attestation.

## Canonicalization, byte resolution and authorization

Reject duplicate JSON keys, unknown or missing fields, noncanonical Unicode,
nonfinite values, booleans in integer fields, negative/oversized lengths,
unsafe identifiers, malformed digests, duplicate IDs and out-of-order rows.
The wire document must equal its deterministic serialization: UTF-8 JSON,
sorted object keys, compact separators, ASCII escaping, no insignificant
whitespace and no trailing data. Compute `feed_sha256` from those **exact
canonical document bytes**. Do not hash a normalized subset or an
untrusted supplied `feed_sha256` field. Define a fixed maximum document size
and fail before parsing an oversized input.

For every byte row, an offline `IndependentFeedByteResolver` must read bytes
from the separately approved feed store using its configured tenant/issuer
namespace and opaque object ID. The verifier checks the resolver's pinned
tenant/issuer properties and passes only the opaque ID and size limit. The
custom resolver implementation is trusted deployment code: a Python Protocol
cannot itself prove that it avoided symlinks, a manifest URI, network fetches
or a fallback to Fabric's content store. Qualify its implementation and
permissions separately; the first verifier does not ship a generic remote
fetcher. It must enforce tenant authorization, a per-object size limit, exact length and
SHA-256 before returning bytes. Read errors are unavailable; length,
digest or identity mismatch is invalid. Empty bytes are resolved and hashed
like any other object. Review-only redacted derivatives may be recorded as a
separate privacy view, but cannot satisfy an original-byte role. If policy
forbids storing the original, report that role unavailable for reconstruction
instead of treating a redacted copy as exact evidence.

The manifest signature must be verified **after canonical parsing, identity,
cursor and structural checks but before independent byte reads**, against the
recomputed manifest digest and the deployment-owner's expected issuer. This
preflight prevents unauthorized or malformed documents from provoking store
reads. A `verified` result is returned only after all byte reads and exact
length/digest checks pass. Use the existing
`verify_evidence_attestation` with this exact `EvidenceExpectation`:

```text
statement_type = independent_witness
subject_kind   = evidence_set
subject_id     = feed_id
subject_sha256 = sha256(canonical feed document bytes)
tenant_id      = approved tenant
run_id         = approved run
scope_sha256   = approved scope digest
issuer_id      = issuer pinned to this route/source/cursor domain
```

The attestation's bounded validity, trusted key validity, revocation and
signature checks remain authoritative. The issuer's statement does not make
the feed independent unless the producer, store and cursor semantics were
separately qualified and the approved registry is not built from the
submitted manifest. An agent, Fabric SDK, Node, or fixture signer must not be
mistaken for a provider/file/database witness merely because it can sign the
same JSON.

## Offline API and result semantics

Add a separate module, not a new argument that upgrades
`reconcile_call_run` by caller flag:

```python
verify_independent_feed(
    manifest_bytes: bytes,
    attestation_bytes: bytes,
    *,
    expectation: IndependentFeedExpectation,
    trusted_keys: Mapping[str, EvidenceTrustKey],
    byte_resolver: IndependentFeedByteResolver,
    verification_time: int,
) -> IndependentFeedVerification
```

`IndependentFeedExpectation` is assembled from the approved scope and native
cursor/checkpoint and attempt ledger, not by copying the manifest. It pins
exact tenant, run, scope SHA-256, route/version, source/epoch, boundary,
cursor domain, start/end, feed ID and issuer. It also pins an exact tuple of
`ExpectedAttempt(operation_id, attempt_id, outcome, roles)`, where `roles`
maps each required role to `None` for one nonstream object or to the exact
positive chunk count for a stream. The resolver is constructed for pinned
tenant/issuer and exposes `resolve(byte_object_id, max_bytes) -> bytes`;
the verifier checks that binding before any read. The result contains only a
fixed reason, feed digest and bounded counts. It returns **no raw bytes or
`CallByteWitness` instances**, private exception text, token, key or
arbitrary manifest attributes. A later separately designed authorized API
would be needed to materialize comparison bytes; this first checker does not.

Use four non-overlapping result states:

- `verified`: canonical and complete declared cursor interval, all operation
  and required byte sets exact, every byte independently resolved and
  checked, and the route-pinned statement verified. This means only *this
  feed* is verified, not the Fabric run.
- `incomplete`: a feed is present and its trusted native interval is known,
  but one or more expected cursor rows, physical attempts, required roles or
  chunks are missing, withheld or redacted. The fixed reason identifies the
  missing category without content. A missing *independent expectation* or
  terminal checkpoint makes the feed `unverified`, not `incomplete`.
- `unverified`: manifest or attestation is absent, approved key or native
  interval is not configured, verification dependency is unavailable or the
  independent store cannot be read. An outage is not evidence that a byte
  differs. Existing attestation reasons `unknown_key` and
  `verification_dependency_unavailable` map here.
- `invalid`: contradictory, malformed, duplicated, tampered, cross-tenant,
  wrong-scope, wrong-issuer, bad-signature, wrong-byte or extra/unexpected
  records. Existing attestation reasons `invalid_document`,
  `invalid_signature`, `expected_binding_mismatch`, `issuer_not_authorized`,
  `revoked_key`, `key_not_valid_at_issuance`, `key_not_current` and
  `statement_not_current` map here. None of these states can be silently
  promoted to `verified` by a caller-provided flag.

Only a later qualified reconciler may compare verified feed inputs with the
recorder. An absent record in Fabric with a verified physical-operation row
is a `partial` run discrepancy. A missing or unverified feed prevents a
complete verdict even when local recorder counts match. A feed result alone
never changes `reconcile_call_run`'s current `partial`/`unverified` verdicts.

## Acceptance tests before implementation

1. Canonical clean fixture with an independently configured key, native
   start/end cursors, two attempts (including a retry), parallel ordering,
   binary/empty bytes and ordered stream chunks verifies as a *feed* only;
   local reconciliation remains `unverified`.
2. Delete first, middle or terminal cursor; change the independently expected
   end; duplicate or reorder a cursor; omit a failed/cancelled attempt; add an
   unlisted operation; reuse an attempt ID. Each case must not verify, even
   when operation counts match.
3. Omit, duplicate, reorder or rename a required role/chunk; replace bytes,
   alter length/hash or provide an unreadable object; test empty versus absent
   and a redacted-only object. No original-byte claim may survive.
4. Change tenant, run, scope, route/version, source/epoch, boundary, cursor
   domain, feed ID or pinned issuer; swap another same-tenant issuer; revoke or
   expire its key; mutate the document after signing. All must fail closed.
5. Reject duplicate JSON fields, unknown fields, malformed IDs/digests,
   booleans for integers, deep/oversized documents, unsafe refs, symlinks,
   cross-tenant resolver binding and attacker-controlled exception/canary text
   in reports. Qualify a deployment resolver against symlinks and cross-tenant
   store reads separately; this protocol cannot enforce its implementation.
   No network fetch or write occurs in the verifier itself.
6. Fault-inject independently missing terminal checkpoint, unavailable feed
   store, and a contradictory byte readback; assert `unverified`,
   `unverified`, and `invalid` respectively with fixed reasons. A signer key
   embedded in the input, an unauthenticated `witness_source` label and a
   caller `authenticated=True` flag must never confer trust.

The fixture signer and resolver are test apparatus only. To claim a live
qualified feed, repeat these tests against the actual provider/service audit
export, its native cursor and authorized readback in the declared deployment.
This spec does not authorize creating a customer credential, an external
signature service, or a production-compliance claim.
