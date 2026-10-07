---
title: Passive asynchronous content recording and durable delivery
status: draft
revision: 3
last_updated: 2026-09-24
owner: product-architecture
depends_on: 028, 029
related: 033, 034
---

# 032 — Passive asynchronous content recording and durable delivery

Defines how content moves from an instrumented call to the customer's object
store without blocking, altering, or endangering the agent — and exactly
where the durability boundary lies. This spec owns the honest-loss claims:
what can be lost, when, and how a consumer finds out.

## Goals

- Move all object-store I/O off the model/tool execution path.
- Bounded resources: queue, payload size, memory, CPU, enqueue time.
- Explicit durability modes with documented loss windows.
- Solve the two-destination problem: telemetry refs and store objects are
  independently delivered; consumers resolve pending vs. permanently
  unavailable deterministically.

## Non-goals

- Zero-loss guarantees for `inline`/`process` modes.
- Cross-store transactions or atomic ref+object delivery.
- A mandatory always-on daemon; the writer lives inside the SDK process.

## 1. Durability modes

| Mode | Write path | Loss window | Use |
|---|---|---|---|
| `inline` | `store.put()` on the caller's thread before the event is stamped | None for the put itself; store latency is on the agent path (bounded only by store responsiveness) | **Development and tests only** — the legacy `content_store=` behavior |
| `process` | Enqueue to bounded in-process queue; background worker writes | Process death loses every queued, unwritten object | Local eval, throughput-sensitive dev |
| `spooled` | Atomic fsync'd spool entry on enqueue, then background worker uploads and deletes the entry | Only a crash *before* the spool fsync returns (single small write) | **Production default** for governed mode |

`inline` exists for development, debugging, and compatibility — it is
**not** a production durability mode: every byte of store latency
(including network stalls against S3) lands on the monitored model/tool
call. `inline` requires a synchronous store; configuring it is an explicit
acknowledgment that store I/O is on the agent path.

`spooled` requires `spool_dir` on a local filesystem the SDK can fsync
(network filesystems are accepted but degrade the guarantee to whatever the
mount provides — documented, not silently stronger). In `spooled` mode the
fsync'd local handoff **is** the durability acknowledgment: "accepted" is
reported only after the spool write is durable, and a remote object-store
stall can never hold the caller.

## 2. Bounded resources (all required, all configurable within caps)

| Bound | Default | Hard cap | Behavior at limit |
|---|---|---|---|
| `queue_max_items` | 1024 | 65536 | enqueue fails → item status `dropped`, reason `queue_full` |
| `payload_max_bytes` | 1 MiB | 16 MiB | store truncated prefix, `representation: truncated` |
| `enqueue_timeout_ms` | 0 | 100 | enqueue never blocks beyond this; `0` = pure non-blocking |
| `worker_flush_interval_ms` | 250 | — | worker drains on interval or queue pressure |
| `spool_max_bytes` | 1 GiB | — | spool full → `dropped`, reason `spool_full` |
| `retry_max_attempts` | 5 | — | per object, exponential backoff w/ jitter |
| `retry_max_elapsed_s` | 300 | — | terminal → item `failed`, reason recorded |

`queue_max_items` must be a **positive** integer: `0` is rejected at
configuration (it must never silently mean "unbounded" in one SDK and
"drop everything" in another — a bounded queue is the contract).

CPU: hashing + serialization happen at capture call time (bounded by
`payload_max_bytes`); the worker performs store I/O only. No compression in
v1 (keeps byte-exactness trivially verifiable).

## 3. Lifecycle

```text
capture call ─ snapshot bytes + descriptor ─> enqueue ─┐
              (caller path ends here; ref URI          │
               deterministic from digest)              │
                                                       v
                                       ┌─ process mode: queue item
                                       └─ spooled mode: spool file (fsync)
                                              │
                                              v
                              worker: store.put(bytes) → status=stored
                              on retry exhaustion → status=failed

decision close ─ manifest snapshot ─> same bounded writer ─> store
              (manifest_ref stamped BEFORE the span ends;
               the manifest URI is deterministic, no I/O)
```

- **Snapshot at capture.** Mutable inputs (dicts, lists, buffers) are
  serialized to canonical bytes on the caller path at capture time — a later
  caller mutation cannot change what was recorded.
- **Deterministic ref.** The URI is derived from store config + content
  digest, so the span event can carry the final ref before the object lands.
  Pending resolution is a designed-for state (§5).
- **Deterministic manifest ref.** The manifest URI is likewise derived from
  store config + `manifest_id` with **no store I/O** — the decision span can
  carry `fabric.content.manifest_ref` before the manifest exists. The span
  attribute is stamped while the span is still open; an asynchronous
  "stamp after write" can race the span end and silently lose the only
  link between the record and its transcript.
- **Passive manifest delivery.** In `process`/`spooled` modes the manifest
  document is itself submitted through the bounded writer as a manifest
  delivery — the monitored path never performs local or network
  object-store I/O. In `spooled` mode the manifest gets a spool record like
  any object, so a crash between close and upload still reconciles.
  `inline` mode is the documented exception (it is dev-only, §1): the
  manifest write is synchronous there because the caller already accepted
  store I/O on its path.
- **Manifest registration before submission.** A manifest item is
  registered (its `pending` slot exists) *before* the writer can settle it —
  the task submitted to the writer carries manifest/item identity, so a
  store fast enough to settle inline can never outrun registration and
  leave a permanent false `pending`.
- **Settlement is keyed, not global.** Delivery outcomes route to the
  owning manifest through a keyed subscriber mechanism (object id →
  manifest); a decision's subscriber is removed after terminal settlement
  so a shared writer does not accumulate per-decision callbacks forever.
- **`flush(timeout)` / `close()`.** `flush` blocks until the queue + spool
  drain or the timeout expires, returning `FlushResult{stored, pending,
  dropped, failed}` — the opt-in awaitable for tests and graceful shutdown.
  `close()` flushes with the configured shutdown timeout, then marks any
  remainder `failed`/`pending` and stops the worker. `Fabric.close()`/
  context-manager exit calls it; documented that processes exiting without
  it lose `process`-mode queues.

## 4. Failure isolation

- Worker exceptions are contained per item: one poison object retries then
  fails without stalling the queue.
- Store outage, disk full, quota exhaustion, or content rejection produce
  `failed`/`dropped` statuses and counters — never an exception into the
  agent path, never a changed authorization or application result.
- Diagnostics (logs, worker stats) carry object ids, sizes, digests and
  statuses — never content bytes.
- `writer.stats()` exposes `enqueued, stored, dropped, failed, spooled,
  recovered, queue_depth` for health reporting; the decision manifest's
  `completeness` rollup is the per-transcript record.

## 5. Two-destination consistency

Telemetry (ref attributes) and content objects travel independent paths.
Ordering is not guaranteed in either direction; the design makes both orders
resolvable:

- **Ref first, object later:** resolver returns `pending` while the object
  is absent but the manifest still settles (or the object is inside the
  configured settle window). The manifest `pending` status distinguishes
  "on its way" from "gone".
- **Object first, ref later:** an orphan sweep (spec 033) reconciles objects
  not referenced by any manifest after `orphan_ttl` (default 24 h); deletion
  is a customer policy action, never automatic in v1.
- **Ref with object never arriving:** `pending` ages to `failed` at retry
  exhaustion (manifest updated), or stays `pending` when the process died
  mid-flight — the completeness rollup reports it either way.
- No claim of atomic ref+object commit. The manifest is the reconciliation
  point, not a transaction log.

## 6. Crash and recovery semantics

- `process` mode: the queue is volatile. Process death loses it; the
  manifest (if written) marks those items `pending` forever unless the
  decision had already closed — this is the documented loss window.
- `spooled` mode: on startup the writer scans `spool_dir` and delivers
  surviving entries (idempotent — object identity is the digest). A spool
  entry is only deleted after the store confirms the write.
- Distinction tests must prove: in-memory-queue loss produces
  `pending`/absent objects with an honest manifest; spool-acknowledged
  content survives a kill -9 between enqueue and upload.

### 6.1 Spool record — `fabric.content-spool/v2`

Each spool file is one JSON document carrying enough identity to reconcile
its manifest after a restart with no SDK state:

| Field | Meaning |
|---|---|
| `schema_version` | `"fabric.content-spool/v2"` — unknown versions fail closed; numeric legacy-v1 records remain readable for upgrade recovery |
| `kind` | `"object"` or `"manifest"` |
| `tenant_id` | Owning tenant namespace (safe identifier, spec 033) |
| `key` | Object id, or stable `manifest:<manifest_id>` delivery identity |
| `manifest_id` | Owning manifest for either delivery type |
| `manifest_item_sequence` | Object deliveries: exact item slot to reconcile after restart |
| `manifest_revision` | Manifest deliveries: monotonic submitted revision; stale queued revisions may not overwrite or delete the latest durable record |
| `decision_id` | Owning decision (for manifest reconciliation) |
| `descriptor` + `content_b64` | Object deliveries: descriptor and UTF-8/base64 bytes |
| `manifest` | Manifest deliveries: the full manifest document |
| `ref` | The deterministic destination URI stamped on telemetry |
| `attempts`, `first_enqueued` | Retry metadata continued across restarts (Unix seconds for `first_enqueued`) |
| `checksum` | SHA-256 hex of the canonical entry body (all fields except `checksum` itself) — the entry's own integrity check |

### 6.2 Spool filesystem rules

- Spool directory is created `0700` — and **tightened** when it already
  exists more permissively (it will hold raw governed content).
- Spool files are `0600`, written tmp + file fsync + `rename()` +
  directory fsync — the same atomic-write discipline as the store.
- Filenames are `<delivery_id>.json`; tmp files use a dot prefix so a crash
  mid-write never produces a loadable record.

### 6.3 Recovery

- Startup recovery delivers **every** valid spool record — not merely the
  first `queue_max_items`. Recovery entries bypass the live-enqueue bound:
  the bound protects the *agent path* from memory growth, while recovered
  work is already durable and must drain to completion (or terminal
  `failed`) rather than be silently re-dropped.
- A record whose checksum fails, whose JSON is unreadable, or whose
  `schema_version`/`kind` is unknown is **quarantined** by an atomic
  same-directory rename to `*.json.corrupt` and counted/logged —
  an explicit operational outcome, never silent ignore and never an
  infinite re-warn loop.
- Successful delivery deletes the spool entry durably (unlink + directory
  fsync). Delivery is idempotent: re-delivering a record whose object or
  manifest already exists converges without error, so a crash between
  remote write and local delete is safe.
- Recovery republishes manifest records before object records. Recovered
  object deliveries then use `manifest_id` + `manifest_item_sequence`
  (with object-id fallback) to settle the exact item
  `pending -> stored`/`truncated`/`failed` and recompute manifest
  completeness/coverage per spec 029 §4. If reconciliation cannot finish,
  the object write remains idempotent and the spool record remains available
  for a later restart; completeness is never falsely reported.
- Recovered manifest deliveries republish the manifest and its
  by-decision alias.
- Stale tmp files (`*.tmp` older than process start) and quarantined
  entries are retained for operator inspection; the SDK never deletes
  them silently.

## 7. Acceptance tests

1. Enqueue path adds bounded latency (< enqueue_timeout_ms + serialization).
2. Full queue → `dropped` + counter; never blocks past the bound.
3. `flush()` drains and reports exact counts; `close()` is idempotent.
4. `process` mode crash → documented loss; `spooled` mode kill-restart →
   recovered objects stored once (idempotent).
5. Ref-before-object resolves `pending`; terminal failure resolves `failed`.
6. Worker never mutates agent behavior under store outage/disk-full/mocked
   poison object; diagnostics contain no content bytes.
7. Mutable-input snapshot test: caller mutates the message list after the
   capture call; stored bytes unchanged.

## 8. Rollout

- `inline` is the compatibility path (already shipping as `content_store=`).
- `process`/`spooled` are new; `spooled` is the recommended governed-mode
  production setting and is what spec 034's qualification exercises.
