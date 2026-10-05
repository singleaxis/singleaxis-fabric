# Authenticated local governed content

The optional Python `fabric.governed_store` module is a customer-local backend for
Capture → Protect → Deliver. It implements the existing `ContentStore` and
`ByteEvidenceStore` protocols, and works with `ByteEvidenceConfig`,
`ByteEvidenceRecorder`, `CallRecorder`, and `PolicyCaptureSession`. It does not
install hooks or alter authorization of a monitored action. Unscoped legacy
`put(text)` is refused because it cannot establish a role-specific content policy.

## Trust and configuration

`LocalCapabilityAuthority(secret, issuer="local-admin")` uses a customer-supplied
signing secret of at least 32 bytes. The caller must generate high-entropy key
material, protect it outside telemetry, and make the same key available when
reopening existing data. There is no embedded key, external account, automatic
credential storage, or network service.

Issue a short-lived grant with:

```python
capability = authority.issue(
    policy=policy,
    subject_id="capture-worker",
    permissions={"write_original", "write_derivative"},
    ttl_seconds=300,
)
original = GovernedLocalContentStore(
    root,
    policy=policy,
    authority=authority,
    capability=capability,
    plane="original",
    encryption_key=customer_key,
)
derivative = GovernedLocalContentStore(
    root,
    policy=policy,
    authority=authority,
    capability=capability,
    plane="derivative",
    encryption_key=customer_key,
)
```

Here `policy` is a validated `DeploymentPolicy`, `authority` is a configured local
trust anchor, and `customer_key` is an explicitly supplied 32-byte AES key. This
example deliberately does not grant read or lifecycle access. Customers may use
separate actual keys and processes for the two planes. Key labels in the policy
are configured expectations, not proof of key custody, isolation, or a KMS call.

Retained objects stay bound to their original policy snapshot. After a policy
revision, use an explicitly authorized store with that older snapshot to read or
manage its retained objects; new-policy listing and purge skip older-policy objects.
The authenticated audit history spans revisions within the tenant/workload/plane.

Capabilities bind issuer, subject, tenant, workload, exact policy digest, policy
ID/version, permissions, issue time, expiry, and a random grant ID. Lifetimes are
1–86,400 seconds. Every operation authenticates its grant; filesystem operations
recheck after acquiring the lock. Unknown, malformed, expired, future-issued,
wrong-policy, cross-tenant, and cross-workload grants are refused. Only the party
holding the administrator key can issue a valid grant. The subject label is a
local administrator assertion, not an externally attested workload identity.

Permissions are independent:

- `write_original`, `write_derivative`: only the named content plane
- `read_original`, `read_derivative`: content, descriptors, and namespace listing
- `lifecycle`: set/release holds, deletion, and expiry purge; no content read
- `audit`: metadata-only local receipts and signed audit history; no content read
- `policy_admin`, `policy_read`: separate capture-configuration registry operations;
  no implied content permissions

All customer application code sharing the Python process, the local administrator
key, or unrestricted OS access is trusted. This library is not an isolation
boundary against a malicious process owner. The authority is a local symmetric
trust anchor, not SSO, an IdP, hardware workload attestation, a revocation service,
or independent approval evidence. Replacing the authority key invalidates existing
grants and object signatures; managed key rotation/migration is not implemented.

## Actual persisted objects

References are `fabric-local://tenant/workload/plane/object_id`. They are opaque
adapter references, not URLs to an HTTP service or direct filesystem locators.
Original and derivative planes have separate directories and resolver namespaces.
Original policy roles require exact bytes; redacted/tokenized roles require their
matching derivative representation, and reject an original fingerprint. Unknown
or omitted roles cannot be written. Privacy transformation correctness still
requires customer testing: a caller who is authorized to write derivatives must
not falsely label raw content as redacted.

One object envelope atomically binds bytes, descriptor, policy, creation/expiry,
legal holds, and lifecycle status. AES-256-GCM uses a fresh random nonce per object
and authenticated identity/descriptor metadata. When AES-GCM is configured, raw
content is ciphertext on disk; metadata remains visible to the authorized OS
owner. Descriptor fields are closed and structurally validated. Opaque IDs must
not contain secrets or personal data. Hashes and pseudonymous identifiers can
still be sensitive and linkable.

When no key is supplied the adapter reports `UNENCRYPTED`; base64 is merely an
encoding. Unencrypted storage is refused for production policies or any policy
requiring encrypted storage. An encrypted local adapter still reports
`production_qualified=false`, `region_verified=false`, and `kms_verified=false`.
The configured region name cannot establish the host's physical region, backup
location, administrative-access country, or legal residency.

Reads authenticate, verify envelope signatures, decrypt if needed, and check
actual byte length and SHA-256. Reads of descriptors verify content too. This is
local content integrity, not an independent receipt that all actions were captured.
The existing `ByteEvidenceResolver` is specific to the older bundled filesystem
format; use this adapter's authenticated `read` and `read_descriptor` methods for
these envelopes. No compatibility with that older resolver is implied.

## Persistence and lifecycle

This POSIX adapter traverses each directory using directory file descriptors and
`O_NOFOLLOW`, rejecting symlink paths, hardlinked files, unsafe file types, broad
file permissions, noncanonical references, and traversal. New directories/files
use 0700/0600. An exclusive file lock coordinates participating threads/processes.
Temporary-file fsync, atomic rename, and parent-directory fsync make each envelope
replacement durable as far as the local filesystem's guarantees permit. Existing
object IDs are immutable: mismatching writes and resurrection after deletion fail.

Signed, hash-linked audit intent is fsynced before a mutation, and completion after
the envelope is durable. Interrupted operations may have intent without completion;
that is an uncertain operation, not a success receipt. A failed write remains an
explicit failure through the asynchronous capture API and does not change a
monitored delegate's result. Reads are also audited. A torn or modified audit chain
fails closed. Audit files are bounded to 32 MiB; rotation/export/recovery operations
are not implemented, and reaching that bound causes explicit operation failures.

The API is:

- `read(uri)`, `read_descriptor(uri)`, `exists(uri)`, `list_object_uris()`
- `read_receipt(uri)`, `audit_events()`, `attestation()`
- `set_hold(uri, hold_id=..., reason_code=...)`
- `release_hold(uri, hold_id=..., reason_code=...)`
- `delete(uri, reason_code="requested")`
- `purge_expired()` returns deletion receipts for expired, unheld objects

Reason and hold identifiers must be opaque case codes, not case descriptions.
Retention begins at successful local object creation. Reads after expiry are
refused unless the object is held. Purging is explicit; there is no background
scheduler in the adapter. Holds remain until an authorized explicit release; they
prevent deletion, including expiry purge. Operational ownership and review of
holds belong to the customer.

Deletion atomically replaces the payload and descriptor with a signed tombstone.
The receipt no longer includes the content hash. A tombstone prevents reuse of the
object ID. This removes the adapter's current accessible copy. It is not secure
physical erasure, backup deletion, disk snapshot deletion, key destruction, or
proof that previously exported copies disappeared. Audit facts and minimal
tombstones have their own customer retention requirements; this implementation
does not silently claim those records have been purged.

## Qualification limits

The adapter is opt-in local implementation evidence. It has no cloud receipts,
remote provider assertions, external time authority, independent audit checkpoint,
or anti-rollback protection against an administrator restoring an earlier valid
filesystem snapshot. HMAC-chain validation detects modification/reordering within
a presented history; it cannot prove that a valid suffix or the entire history
was not removed. Filesystem crashes, full-disk recovery, backups, production IAM,
KMS custody/rotation, independent receipt issuance, customer identity federation,
and multi-host operation require separate qualification. It has not been load or
power-loss qualified and performs bounded full-chain audit verification per
operation. Do not advertise universal capture, production readiness, compliance,
immutability against the OS administrator, or independent durable delivery from
these local receipts.
