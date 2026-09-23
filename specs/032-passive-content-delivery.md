---
title: Passive asynchronous content recording and durable delivery
status: draft
revision: 1
last_updated: 2026-09-22
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
| `inline` | `store.put()` on the caller's thread before the event is stamped | None for the put itself; store latency is on the agent path (bounded only by store responsiveness) | Dev; the legacy `content_store=` behavior |
| `process` | Enqueue to bounded in-process queue; background worker writes | Process death loses every queued, unwritten object | Local eval, throughput-sensitive dev |
| `spooled` | Atomic fsync'd spool entry on enqueue, then background worker uploads and deletes the entry | Only a crash *before* the spool fsync returns (single small write) | Production default for governed mode |

`inline` remains available for backwards compatibility and tiny deployments.
`spooled` requires `spool_dir` on a local filesystem the SDK can fsync
(network filesystems are accepted but degrade the guarantee to whatever the
mount provides — documented, not silently stronger).

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
                              manifest written/updated at decision close
```

- **Snapshot at capture.** Mutable inputs (dicts, lists, buffers) are
  serialized to canonical bytes on the caller path at capture time — a later
  caller mutation cannot change what was recorded.
- **Deterministic ref.** The URI is derived from store config + content
  digest, so the span event can carry the final ref before the object lands.
  Pending resolution is a designed-for state (§5).
- **Manifest timing.** The manifest is written when the decision closes,
  after in-flight items settle or are marked `pending`/`failed`. When
  `spooled` mode has recovered-but-undelivered entries at close, the
  manifest still publishes and the worker updates item statuses in place
  when they resolve (single-writer, idempotent manifest rewrite).
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
- `spooled` mode: on startup the writer scans `spool_dir`, re-enqueues
  surviving entries (idempotent — object identity is the digest), and marks
  entries whose manifest already closed as resumable orphans. A spool entry
  is only deleted after the store confirms the write.
- Distinction tests must prove: in-memory-queue loss produces
  `pending`/absent objects with an honest manifest; spool-acknowledged
  content survives a kill -9 between enqueue and upload.

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
