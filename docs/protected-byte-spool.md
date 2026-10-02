# Protected durable byte spool (Python)

`fabric.byte_spool.DurableByteSpool` is an optional, customer-local POSIX spool
integrated into the existing `ByteEvidenceRecorder`. The default recorder remains
an in-memory handoff. This feature does not add application authorization or
interception: **CAPTURE → PROTECT → DELIVER** remains passive.

## Configure and recover

```python
from fabric import ByteEvidenceConfig, ByteEvidenceRecorder
from fabric.byte_spool import DurableByteSpool

# Obtain this 32-byte key from the customer's protected key provider. Do not
# put credentials in deployment-policy JSON, source control, or capture output.
spool = DurableByteSpool(
    "/customer/private/fabric-byte-spool",
    tenant_id=store.tenant_id,
    encryption_key=customer_spool_key,
    max_bytes=64 * 1024 * 1024,
    max_records=4096,
    max_attempts=12,
    retry_initial_s=0.25,
    retry_max_s=60,
    retention_s=7 * 86400,
)
recorder = ByteEvidenceRecorder(ByteEvidenceConfig(
    store=store,                      # existing authorized original store
    review_store=review_store,        # existing isolated derivative store
    roles=frozenset(deployment_policy.privacy),
    content_protector=protector,       # existing DeploymentPolicy protection
    durable_spool=spool,
))
```

After restart, reopen the same root with the same tenant/key and fresh authorized
stores. Object IDs, descriptors, protected bytes, routing, retry budgets and
settlement survive restart. Recovered descriptors are available through
`recorder.get(id)`, `recorder.derivatives(id)`, `recorder.drain_settled()` and
`spool.object_ids()`. Binding starts one replay worker. The lifetime POSIX lock
rejects another live owner of that root.

A destination must implement idempotent writes for the same descriptor/object
ID and permitted payload. Existing `GovernedLocalContentStore` does this, using
its capability checks, scoped references, encryption and fsynced atomic writes.
Replay rechecks the destination namespace and rejects changed routing; it never
rewrites the saved object identity to fit a new destination.

## What each state means

- `capture(...)` returns `status="pending"`: only a bounded memory handoff. It
  does not wait for the disk, retry worker or destination.
- `recorder.wait_durable(timeout_s)` waits for background privacy processing and
  local file **and directory** fsync. It does not await the destination. It is an
  explicit caller wait, never an application-call admission gate.
- `recorder.delivery_state(id)["state"] == "durable"` identifies a protected
  object acknowledged by the local spool and awaiting delivery.
- `delivered` identifies a validated successful response from the configured
  byte store, followed by fsynced local settlement. It is **store acknowledgement
  only**, not an independently obtained destination receipt, immutable-retention
  proof, or a complete-run verdict.
- `lost` preserves permanent denial, corrupt data, expiry or exhausted retry
  evidence. The separate `durable` Boolean means an intact locally admitted
  record exists; it does not mean its destination delivery succeeded.
- `unknown` means there is no known durable admission. A crash before asynchronous
  fsync can erase an event without leaving any recoverable record or gap.

`flush(timeout_s)` waits for terminal outcomes, which can include explicit loss.
It is not an all-delivered Boolean. Check states, health and independent source
and destination inventories. `close(timeout_s)` has a shared deadline for
admission drain, delivery drain and thread shutdown. A blocked store or filesystem
call returns false within the bound, leaving a daemon worker and ownership lock
until that call exits or the process dies. Python cannot safely cancel arbitrary
customer I/O. Do not close its underlying store before `health()["worker_stopped"]`.

## Crash consistency, bounds and loss

The spool encrypts each descriptor/payload/retry-state envelope, writes a private
random temporary file, flushes/fsyncs it, atomically replaces the destination
entry, and fsyncs the directory. Delivery attempts have a fsynced intent before
calling the destination. Lost responses or death before local settlement replay
identical IDs and content; such ambiguous attempts consume the bounded budget.
Delivered settlement and payload cleanup share one atomic replacement, so cleanup
cannot remove the only local payload before settlement is committed.

`max_bytes` bounds committed object envelopes. Admission additionally reserves
512 bytes per outstanding object for bounded retry-state growth. Every rewrite
rechecks capacity; high-water accounting includes retries. Atomic replacement
needs extra space for **one envelope**, plus a 64 KiB health reserve. Real volume
quotas must include that overhead. `max_records` includes settled metadata; the
recorder index and its memory queue have their own existing bounds. These finite
limits intentionally reject more work rather than grow without bound.

Transport/timeouts and retryable local I/O use exponential bounded backoff.
Permission/authentication, corrupt-object and invalid/rejected writes become
terminal loss. Unknown adapter exceptions retry only up to the configured
budget. An adapter can raise `PermanentByteDeliveryError` for a fixed permanent
rejection. Arbitrary customer exception text, payloads and URLs are never copied
into failure reasons or health.

`spool.health()` exposes current pending/delivered/lost counts, corruption,
admission-rejection counts, high-water marks, persistence faults, worker state
and the explicit pre-admission unknown boundary. Because terminal envelopes are
never automatically removed, recovery compares the authenticated monotonic
high-water record count with surviving entries. Deleting committed entries
persists `missing_durable_entries` and `recovery_inventory_unverified`; subsequent
restarts and empty expected-set queries cannot hide that uncertainty. Persisted
admission-rejection, persistence-fault and orphaned-temporary counters likewise
keep `wait_durable` false and recovery unverified, even with an empty inventory;
a process restart never erases known rejection or unknown-admission evidence. The count
does not invent missing identities or replace an independent exact-ID inventory. Corrupt entries remain on disk
and do not replay. Wrong tenant/key cannot decrypt entries and does not overwrite
an unreadable health envelope. Uncommitted temporary entries produce a persisted
unknown counter before cleanup. Fsync or disk-full failures can themselves prevent
persisting new failure evidence; `unpersisted_fault` reports this in the live
process. A fresh process cannot recover an unwritten failure report.

No local spool alone detects deletion/rollback of its entire directory or proves
that every physical source event was submitted. Reconcile an independently
witnessed source inventory, including pre-admission drops and unknowns. A local
empty queue, drained snapshot or parent success must not produce `complete`.

## Privacy, custody and retention

Existing `ContentProtector` and `BytePrivacyPolicy` transformations run before
spool persistence. Derivative-only modes spool only permitted derivatives, not
raw values or original hashes. Explicit original-plus-derivative policy keeps the
same separate destination routing. Omitted or failed transformations never spool
the raw object. Raw data may exist in the existing bounded process-memory queue
for asynchronous legacy transforms; this is inside the customer capture boundary.

All spool content **and descriptors/health** use AES-256-GCM with random nonces and
associated data binding schema, tenant and filename. File names expose opaque
object IDs, and filesystem sizes/times remain observable. Directory mode is 0700,
files 0600, with same-owner checks, no-follow opens and regular-file/hardlink
validation reused from governed local storage. OS administrators and customer
code holding the key remain trusted. This is not cloud KMS, hardware attestation,
key rotation, custody certification or residency proof. The customer must protect,
back up, restore and supply the key separately; losing it makes replay impossible.
A single spool uses one key for its admitted original and derivative objects;
do not distribute that key to derivative-only readers. If policy requires
separate spool custody, use separately scoped recorders/spools and keys.

Successful delivery drops payload from the atomically persisted local envelope.
Failed payloads remain until `retention_s`, then the next running worker pass
removes the payload while retaining encrypted loss metadata. An offline process
cannot enforce wall-clock deletion; restart resumes expiry processing. Terminal
metadata remains until customer-managed archival/removal and counts against
capacity. There is no automatic legal-hold or backup lifecycle integration.
Unlink/replacement is not secure erase of SSD blocks, snapshots or backups. Key
retirement, backup expiry, filesystem durability and actual infrastructure failure
semantics require target qualification.

## Executable evidence

```sh
python -m pytest sdk/python/tests/test_byte_spool.py \
  sdk/python/tests/test_byte_evidence.py sdk/python/tests/test_governed_store.py --no-cov
```

Tests use fresh Python subprocesses and real SIGKILL at file/directory fsync,
accepted-but-unacknowledged delivery and cleanup boundaries; an independently
held pending descriptor demonstrates pre-fsync unknowns. They cover restart,
transient outage, permanent rejection, exhausted retry, corrupt ciphertext,
wrong-key recovery, queue/capacity and actual fsync failures, blocked destination
and filesystem writes, retention and canary non-disclosure. Governed-store
integration uses real AES-GCM, capability-authenticated original/derivative
planes, redaction/tokenization/omission and existing idempotent destination writes.
These local tests do not certify power-loss behavior, external cloud KMS/IAM,
network policy, Kubernetes storage or any target infrastructure.
