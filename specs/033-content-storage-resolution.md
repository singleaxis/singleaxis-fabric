---
title: Customer content storage and authorized resolution
status: draft
revision: 2
last_updated: 2026-09-23
owner: product-architecture
depends_on: 028, 029, 032
related: 034
---

# 033 — Customer content storage and authorized resolution

Defines the write-side store contract and the read-side resolver: where
objects live, how tenants stay isolated, what integrity verification means,
and who may read. Storage remains customer-controlled end to end.

## Goals

- Two store adapters per SDK — local filesystem (dev/shared-PVC) and
  S3-compatible (production) — behind one `ContentStore` contract.
- Tenant-isolated namespaces, atomic writes, exact-byte verification.
- An authorized resolver that returns verified bytes or an explicit status —
  and cannot be pointed at arbitrary hosts/paths by a telemetry URI.
- Honest durability/retention claims: a write ack is a store ack, not a
  proof of immutability or retention.

## Non-goals

- A new identity system, KMS, or signing scheme — adapters use the platform's
  IAM/credentials/encryption settings the customer already runs.
- Immutable-evidence claims (WORM/legal hold is a bucket/filesystem policy
  the customer sets; the SDK neither provides nor asserts it).
- A resolver that executes tools, replays side effects, or fetches arbitrary
  URLs.

## 1. Architecture choice (decided)

**In-SDK store adapters in each language** (Python + TypeScript), not a
shared customer-side writer service.

- A sidecar/daemon writer would become a new mandatory runtime for
  governed users and a new ops surface (HA, spool hand-off, auth);
  metadata-only users must not need it.
- The capture path is already in-process; the async writer (spec 032)
  provides the needed isolation without another deployable.
- Cost: two implementations of one contract — mitigated by the shared
  schema + byte/hash fixtures (spec 029 §2) that both must pass.

## 2. Store layout

```text
<root-or-bucket>/<prefix>/<tenant_id>/<digest>
```

- `digest` is the lowercase SHA-256 hex of the stored bytes (spec 029).
- `tenant_id` is mandatory in the key space — identical content under two
  tenants writes two objects (no cross-tenant dedup leak).
- Descriptors are stored beside objects:
  `<prefix>/<tenant_id>/meta/<digest>.json`.
- Manifests live at `<prefix>/<tenant_id>/manifests/<manifest_id>.json`
  (plus a `<decision_id>.json` alias object containing the manifest URI,
  giving consumers a stable lookup by decision).
- Exposed ref URIs: `file://<abs-path>` and `s3://<bucket>/<key>` — opaque
  to the telemetry consumer; they carry no credentials, no signed query,
  no session material.

### 2.1 The safe-identifier rule (shared, both SDKs)

`tenant_id` — and any other value used as a namespace path or key
component — must satisfy **all** of:

- matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`;
- is **not** exactly `.` or `..` (the regex alone admits them);
- contains no `/`, `\`, NUL, or percent-encoded traversal (the identifier
  is validated *before* any decoding — `%2e%2e`, `..%2f`, double-encoded
  variants all fail the pattern outright);
- on the local adapter, the resolved tenant root (`resolve()`d, symlinks
  expanded) must be strictly inside the resolved configured root — a
  sibling path, the root itself, or an absolute identifier all fail.

The rule lives in one shared helper per SDK (`safe_identifier` /
`assertSafeIdentifier`); the local store, the S3 store, and the client
tenant check all call it — adapters never invent their own regex.

**Client/store agreement.** The governed store's `tenant_id` must equal the
`Fabric` client's `tenant_id` exactly (spec 028). The client fails
construction on mismatch — a store namespaced differently than the
telemetry tenant is a silent cross-tenant leak.

### 2.2 S3 namespace safety

- `prefix` must be a non-empty relative key prefix ending in `/`, never
  starting with `/`, and containing no `..` segments — prefix confusion
  (`fabric/content` vs `fabric/contentx`) is prevented by always joining
  with the trailing separator, never by raw `startswith` on a boundaryless
  string.
- `tenant_id` follows §2.1; the tenant key prefix is
  `<prefix><tenant_id>/` — ownership checks require the full
  `<prefix><tenant_id>/` match, so `acme` and `acme2` never share a
  namespace.
- `endpoint_url`/`region_name` propagate to the client; they never relax
  namespace rules.

### Local adapter

- Root must be an absolute path; the adapter resolves and confines itself
  under it (symlink + `..` rejected outside root).
- Writes are **atomic**: write `<digest>.tmp-<uuid>` in the target shard,
  fsync file + directory, `rename()` onto the final path (POSIX atomic).
- **Pre-existing objects are validated, not trusted:** when the target
  exists, its bytes are re-hashed; a mismatch is a `failed` status
  (`corrupted_preexisting`), never a silent accept and never an overwrite.
- File mode `0600`, directories `0700`, set explicitly — governed content
  is not world-readable by default.
- Local store is for development and single-node/shared-PVC deployments;
  it is not a distributed consistency solution.

### S3 adapter

- Constructor validates: bucket name form, non-empty prefix ending in `/`,
  tenant_id present, region/endpoint coherence; missing credentials surface
  on first write as `failed`, not at construction (lazy client as today).
- Conditional write where the backend supports it (`If-None-Match: *` or
  equivalent) prevents overwrite of an existing object; on backends without
  it, a `HEAD`+digest-check on the descriptor replaces blind trust.
- Server-side encryption and retention are **customer bucket settings**
  (SSE-S3/SSE-KMS, object lock, lifecycle) — the adapter exposes
  `sse_*`/`storage_class` passthrough options, asserts nothing stronger than
  the settings provide, and documents that retention claims live in bucket
  config, not the SDK.
- Optional `endpoint_url` covers S3-compatible stores; the resolver must be
  configured with the same endpoint.

## 3. Resolver — `fabric.resolver`

Authorized read path used by reviewers, auditors, and evaluators.

```python
resolver = ContentResolver(stores=[
    LocalFilesystemContentStore(root="/var/fabric/content", tenant_id="acme"),
    S3ContentStore(bucket="acme-evidence", prefix="fabric/content/",
                   tenant_id="acme"),
])
result = resolver.resolve("s3://acme-evidence/fabric/content/acme/<digest>")
```

Resolution algorithm:

1. Parse URI → scheme. Unconfigured scheme → `denied` (`unknown_scheme`).
2. Match the URI to a configured store's namespace exactly — the
   normalized canonical path inside the resolved tenant root for
   `file://`; `bucket` + `<prefix><tenant_id>/` for `s3://`. No match →
   `denied` (`outside_configured_store`). A telemetry URI can never widen
   the configured set — the allowlist is the configured stores, not the
   URI.
3. Reject traversal (`..`, symlink escape, bucket/prefix mismatch,
   percent-encoded separators) → `denied`.
4. Read the **descriptor** (sidecar, or the manifest-supplied descriptor).
   Missing, unreadable, or invalid → `unverified` — *never* `available`:
   a digest-named path is not proof of integrity.
5. Check descriptor identity: `tenant_id` must equal the store's tenant
   (mismatch → `denied`); `role`, `object_id`, `media_type`, `digest`
   must be internally consistent with what was requested
   (inconsistency → `corrupted`).
6. Read bytes. Absent → `missing` — or `pending` only when a covering
   manifest proves the item is `pending` (manifest-supplied descriptor
   with `status: pending`). Deleted/expired objects resolve `missing`:
   retention is store policy, and the manifest's `stored` history already
   records that the object existed.
7. Verify `byte_length` then `digest` against the descriptor. Mismatch →
   `corrupted`; the bytes are **never returned** for `denied`,
   `corrupted`, or `unverified` results.
8. Only after every check passes: return `available` with bytes +
   descriptor.

`available` therefore means exactly one thing: the object was read inside
an authorized namespace and its byte length and SHA-256 digest verified
against a valid descriptor. There is no weaker form of success.

| Situation | Result |
|---|---|
| URI outside all configured stores / bad scheme | `denied` |
| Traversal or cross-tenant URI | `denied` |
| Descriptor tenant ≠ store tenant | `denied` |
| Descriptor missing / unreadable / wrong shape | `unverified` |
| Descriptor identity inconsistent | `corrupted` |
| Bytes absent, manifest proves `pending` | `pending` |
| Bytes absent otherwise (incl. deleted/expired) | `missing` |
| `byte_length` mismatch | `corrupted` |
| Digest mismatch | `corrupted` |
| All checks pass | `available` + bytes + descriptor |

`resolve_manifest(uri)` does the same for manifest objects (schema-validated
on read). `export_transcript(manifest_uri)` walks items and emits the
spec-034 export.

Security properties:

- **Digests are integrity checks, not authorization.** A correct hash does
  not grant access; the configured-store match does.
- Cross-tenant reads fail at step 2 even with a valid URI/digest — the
  configured `tenant_id` scopes what a store will serve.
- No network egress beyond the configured store endpoints; `file://`
  resolution never leaves the configured root.
- Resolver is a library + `python -m fabric.resolver` / `fabric-content`
  (TS bin) CLI; both are dev/ops tooling shipped in the SDK artifacts —
  they are not recorder runtime components and cannot run inside Fabric
  Node. (Wheel policy forbids console entry points; the Python CLI is
  `python -m fabric.resolver` only.)

## 4. Retention, deletion, expiry

- The SDK **never deletes** objects on its own in v1. Retention is a store
  policy (bucket lifecycle, filesystem jobs) owned by the customer.
- Deleted/expired objects resolve as `missing`/`expired` explicitly;
  manifests keep their `stored` history (the record shows it existed and
  was removed — erasure doesn't forge a gap).
- `forget()` erasure markers (existing SDK primitive) are about *agent
  memory*, orthogonal to governed content; governed-content deletion is a
  customer ops action on the store, documented as such.
- Orphan objects (no manifest reference after `orphan_ttl`, default 24 h)
  are reportable via `resolver.orphans()` (list-only in v1; deletion stays
  a customer action).

## 5. Protection policy (separate from OTLP protection)

- Enabling governed capture is the customer's explicit authorization to
  persist the configured roles; there is no per-field PII redaction in v1.
  Callers may mark an item `redacted` (status) when they transform content
  themselves before capture — the SDK records, does not detect.
- Content protection = storage configuration (encryption, IAM, bucket
  policy, filesystem perms). The SDK enforces the write-side mechanics
  (tenant namespacing, atomicity, perms); the customer owns the policy.
- Error logs, spool diagnostics, and queue stats carry ids/sizes/digests —
  never content bytes.

## 6. Acceptance tests

1. Local write is atomic (no partial files under crash-injection);
   corrupted pre-existing object → `corrupted_preexisting`, no overwrite.
2. S3 conditional write prevents duplicate overwrite; descriptor `HEAD`
   check catches corruption.
3. Identical content in two tenants → two distinct keys.
4. Resolver: valid object → `available` + verified; traversal, cross-tenant,
   unconfigured scheme/host/bucket → `denied`; corrupted bytes → `corrupted`;
   missing → `pending`/`missing` per manifest state.
5. No credentials/URLs with embedded auth ever appear on telemetry refs.
6. Deletion/expiry → explicit resolution status; manifest history intact.
7. CLI export works against local store end-to-end (spec 034 example).

## 7. Rollout

- `ContentStore` protocol gains `read`/`exists`/`read_manifest` methods in
  the same package (backward compatible: old custom stores get a default
  `resolve`-unsupported path rather than breaking).
- Legacy `content_store=` users get the new local/S3 mechanics with no API
  change; `inline` durability keeps their timing semantics.
