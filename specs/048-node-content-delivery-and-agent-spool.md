---
title: Node content delivery, agent durable spool and run scopes
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 4
last_updated: 2026-10-13
owner: recorder-engineering
depends_on: 029, 032, 033, 038, 047
supersedes_in_part: 047 (§3 store activation, §4.5/§4.8 delivery, §6 loss resend and run markers, §7 store writer, §8 model value and boot gate, §9 step 3 run windows)
---

# 048 — Node content delivery, agent durable spool and run scopes

Spec [047](047-llm-wire-capture-and-reconstruction.md) defines what wire
capture records. This spec changes **where content is written, how capture
events survive the agent process, and how explicit runs are scoped**. Where
the two disagree, this spec wins; 047 points here at each superseded part.

Contracts: [`contracts/capture/v1`](../contracts/capture/v1/README.md)
(new: spool record header, content log record, descriptor goldens;
`scope_id` on exchanges, run markers and reconstruction windows).

## Decision record

**2026-10-13 — approved by the product owner.**

Decisions F1–F10:

- **F1 Only the Fabric Node writes content.** Wire capture no longer writes
  to S3 and the agent needs no cloud credentials. `FABRIC_WIRE_STORE`
  accepts `node` (the default when `FABRIC_WIRE_CONTENT_ENDPOINT` is set)
  or `file:///abs/dir` (direct local store for dev, offline and single-host
  use; unchanged). `s3://` is rejected at install. `S3ContentStore` stays
  in the SDK for governed content and for `fabric.reconstruct`.
- **F2 Agent durable spool.** Every capture event is one fsync'd file
  record in `FABRIC_WIRE_SPOOL_DIR` (required in node mode), drained in
  order by one sender thread (content first, then the span), deleted only
  after every part succeeded, replayed after a restart (§2).
- **F3 Content transport.** One OTLP/HTTP protobuf `LogRecord` per stored
  body, posted to `FABRIC_WIRE_CONTENT_ENDPOINT` (§3).
- **F4 Node content path.** Receiver `otlp/content` (port 4319, HTTP only)
  → pipeline `logs/content` → `memory_limiter` → new exporter
  `fabriccontent`, which verifies and writes body + descriptor with exactly
  the SDK store layout to a directory or S3 (§4).
- **F5 Gate.** `fabric-gate` keeps content and telemetry pipelines apart; no
  configuration can route content to the OTLP destination exporter (§5).
- **F6 Run scopes.** Each `fabric.wire.run()` entry has a unique
  `fabric.run.scope_id`; the verifier pairs markers by scope, never by run
  id or parity (§6).
- **F7 Model exposure.** `gen_ai.response.model` is emitted as is only when
  it matches the 047 pattern **and** an allowlist; otherwise as
  `m-` + 16 hex of its SHA-256 (§7).
- **F8 Credential logging.** No Fabric path logs env values, endpoint URLs,
  header values, certificate contents or exporter exception messages (§8).
- **F9 Compose preflight.** A receiver port published beyond loopback needs
  that receiver's TLS genuinely enabled (§9).
- **F10 Reconstruct** reads Node-written content from the same file/S3
  layout, including S3-compatible stores (endpoint, path-style) (§10).

**2026-10-13 — revision 2 (Codex review).** Decisions F11–F13:

- **F11 One tenant per Node by default.** A content record names its own
  tenant and every authenticated agent reaches the same receiver, so a Node
  allowing tenants A and B lets an agent of A write under B. The exporter,
  `fabric-gate`, the Helm chart and the Compose configs allow exactly one
  tenant unless `allow_multiple_tenants: true` is set explicitly; that flag
  trusts every authenticated agent to name its tenant. Use one Node per
  tenant otherwise (§4, §5).
- **F12 S3 encryption is not optional.** The exporter's own configuration
  validation requires `sse: AES256 | aws:kms`, so no launch path (Helm,
  Compose, a hand-written collector config) can write content without
  requested server-side encryption (§4).
- **F13 The window before the spool write is stated, not moved** (§2
  "Window"): the durable write stays off the host's thread; a kill inside
  the window can never yield a complete verdict for an observed scope or an
  unscoped run. (Revision 3, H5: a scope lost whole inside the window
  leaves no record and cannot be detected; the verifier therefore claims
  only observed scopes.)

**2026-10-13 — revision 3 (Sol review of `faac3d2`).** Decisions H1–H5:

- **H1 No redirects.** Every HTTP client Fabric constructs for delivery (the
  content client and the private OTLP trace exporter's session) never
  follows a redirect; any 3xx is a delivery failure, retried later, never a
  success. A body or header is never re-sent to another location (§3).
- **H2 One tenant per Node, across exporters.** All `fabriccontent`
  exporters that share a receiver or pipeline in the effective
  configuration together allow one tenant unless every one of them sets
  `allow_multiple_tenants: true`; `fabric-gate` enforces it on the
  effective configuration, the Helm chart renders a single `fabriccontent`
  exporter (so its one-tenant check is the per-Node check), and the
  exporter-local check stays (§4, §5 rule 7). *Superseded by J3 (revision
  4): the rule spans all `fabriccontent` exporters, shared ingress or not.*
- **H3 Run-id pseudonyms.** A caller-supplied run id never leaves the agent
  in clear: spans, markers, spool records, content descriptors and reports
  carry `r-` + the first 32 hex of `HMAC-SHA256(key, run_id)` when
  `FABRIC_WIRE_ID_KEY` is set (recommended for production; a secret of at
  least 16 bytes, never logged), else of `SHA-256(run_id)`. Generated
  fallback ids (`trace:…`, `source:…`) are unchanged. `fabric.reconstruct
  --run` takes the clear id and computes the pseudonym (§6, §10). Source
  id, tenant id and `service.name` remain operator-chosen labels that must
  be opaque; they are validated by pattern only. *Superseded for source id
  and `service.name` by J1 (revision 4): pseudonymous by default.*
- **H4 Bounded model prefixes.** A `prefix*` allowlist entry matches only
  version-like suffixes; exact entries match exactly (§7).
- **H5 Per-scope claims.** Completeness is claimed per `fabric.wire.run()`
  scope and per unscoped source epoch; a scoped run is at best
  `complete_for_observed_scopes`, because a scope that left no record cannot
  be claimed (§2 "Window", §6).

**2026-10-13 — revision 4 (Sol re-check of `03484d5`).** Decisions J1–J4
and the capture/verifier fixes:

- **J1 Pseudonymous labels by default.** Capture emits `fabric.source_id`
  (exchange spans, run markers, loss and heartbeat records, spool records and
  content descriptors) as `s-` + the first 32 hex of `HMAC-SHA256(key,
  source_id)` and the private provider's `service.name` as `svc-` + 32 hex of
  the same function (`key` = `FABRIC_WIRE_ID_KEY`; SHA-256 without one, as for
  run ids). `FABRIC_WIRE_LABELS=clear` is the documented opt-in that exports
  both unchanged ("operator-chosen labels are exported unchanged; you
  guarantee they contain no personal data"); any value other than
  `pseudonymous`/`clear` fails installation. The reconstruction report shows
  tenant ids as `t-` + 32 hex and source and run ids only in pseudonymous
  form, projecting clear values from older capture (or clear-mode capture)
  through the same function (§10). Tenant ids in storage paths and
  `allowed_tenants` stay clear: they route content. fabricguard validates the
  `s-`/`svc-` forms (clear labels by pattern in clear mode). Vectors:
  `run-id-pseudonym-v1.json` (same hex, prefix `s-`/`svc-`/`t-`).
- **J2 Numeric model suffixes.** Within a `prefix*` match at most two
  numbers of at most 4 digits each; a date (`20YYMMDD`, or `20YY-MM-DD` as
  three tokens) is not a number and may appear once; a decimal `N.N` (1–2
  digits each) is one number (§7). `gpt-4o-123-45-6789` and
  `gpt-4o-919876543210` are hashed.
- **J2b Digits in every token** (Sol re-check of fd84163). Within a
  `prefix*` match no token of any class (number, version token, word) may
  contain a run of more than 4 digits, except a token that is exactly an
  8-digit date; and the whole suffix holds at most 6 digits not counting
  its (single) date. `gpt-4o-v919876543210`, `gpt-4o-919876543210b` and
  `gpt-4o-1234-5678` are hashed; real names such as `gpt-4o-2024-08-06`,
  `claude-3-5-sonnet-20240620`, `llama-3.1-70b-instruct` and
  `gemini-1.5-pro-002` stay clear. Rare real names over the budget
  (`gpt-3.5-turbo-16k-0613`) need an exact allowlist entry.
- **J3 One tenant per Node, whatever the wiring.** `fabric-gate` enforces one
  tenant across **all** `fabriccontent` exporters of the effective
  configuration, regardless of receivers or authenticators, unless every one
  sets `allow_multiple_tenants: true`; a `fabriccontent` exporter whose block
  is not a literal map after the gate's own resolution (e.g. a whole-block
  `${env:…}`) is refused with fixed text (§5 rule 7).
- **J4 The Node never follows a redirect.** The distribution ships a
  `noredirect` HTTP client middleware that turns any `3xx` into a retryable
  failure (the body is closed; nothing is re-sent); `fabric-gate` requires
  every `otlphttp` exporter to list it, and the Helm and Compose configs wire
  it (H1 extended to the Node).
- **Settled outcomes across processes (§2).** A drainer retires another
  process's delivered record by renaming it in place to its receipt
  (`<record>.ack`) and truncating it to zero, so retirement never needs new
  disk space; receipts count against the bound and are bounded by count. A
  writer counts its record delivered only on that receipt, and as a failure
  when it was quarantined (`*.corrupt`) or disappeared without one. `flush()`/
  `close()` run their whole settle, the admission check included, on a
  bounded helper thread, so they return by their deadline even while another
  pump holds the lock during stalled disk I/O.
- **Response evidence and malformed records (047 §9 steps 1 and 5).** An
  `abandoned` exchange, and an `error` one with an HTTP status, received a
  response and need its digest. An exchange span with a valid identity but
  malformed payload keeps its claims and is a `digest_mismatch`
  (`malformed_record`, partial) of every run and scope it names; a malformed
  identity refuses the input (exit 2, fixed text). A run marker naming a
  valid scope with malformed other fields leaves that scope `conflict`
  (`malformed_record`).

**Why.**

1. *Agents need no cloud credentials.* An agent host with write access to
   the evidence bucket is a credential to steal and a write path to audit
   per agent. With F1 the agent holds only an ingress credential for the
   Node.
2. *One reviewed write path and one encryption policy.* Bucket, prefix,
   SSE/KMS and conditional-write behaviour are configured once, on the
   Node, by the operator — not in every agent's environment.
3. *Durable content queue.* The Node already owns an fsync'd
   `file_storage` sending queue for telemetry; content gets its own, so a
   store outage is absorbed by the Node instead of failing in the agent.
4. *The spool closes span-publication loss.* In 047 an exchange span
   evicted from the private `BatchSpanProcessor`, or in memory when the
   process died, was an unexplained gap. With F2 an event is either on disk
   (and eventually delivered) or explicitly counted as a loss.
5. *Run scopes close Codex findings* "false run closure from scope
   collisions", "serial run closure" and "nested-run false completeness":
   047 paired markers by run id and parity, which a reused, serial or nested
   run id could satisfy falsely.

**Trade-offs accepted.** The Node is now sized for content bytes (CPU for
digests, a content queue volume of `queue_size × 64 MiB` worst case, memory
limiter headroom for 64 MiB requests). One more port (4319) needs the same
TLS/auth as 4317/4318. Delivery is at-least-once; the Node and the verifier
deduplicate by `object_id` and `exchange_id`. A spool directory is one more
piece of agent-host state to provision.

**Code size principle.** The spool replaces machinery; it does not sit on
top of it. `LossExporter`, the loss/heartbeat requeue and resend logic, and
the private `BatchSpanProcessor` on the capture path are deleted where the
spool is in use. Capture outside the new spool, sender and content client
(budget ~650 lines together) must get smaller or stay flat.

## Scope check (AGENTS.md)

| Element | Layer | Why it is OSS core |
|---|---|---|
| Agent spool + sender | DELIVER | Durable local buffering, retry and idempotent delivery. Fails open: never blocks, raises into or delays the host. |
| Content log records to the Node | DELIVER | Authenticated ingestion to a customer-run Node. |
| `fabriccontent` exporter | PROTECT / DELIVER | Verifies digests and tenant, writes to a customer-selected destination; no SingleAxis connection. |
| Gate rules | Verify | Configuration checks that refuse unsafe routing. |
| Run scopes, model exposure | PROTECT / Verify | Closed metadata; offline integrity verdict. No evaluation. |

## 1. Activation (supersedes 047 §3 store and SSE bullets)

| Variable | Values | Notes |
|---|---|---|
| `FABRIC_WIRE_STORE` | unset, `node`, `file:///abs/dir` | Unset = `node` when `FABRIC_WIRE_CONTENT_ENDPOINT` is set, else metadata-only. `s3://…` → `ValueError` ("written by the Fabric Node"). `file://` together with a content endpoint → `ValueError`. |
| `FABRIC_WIRE_CONTENT_ENDPOINT` | full URL, e.g. `https://fabric-node:4319/v1/logs` | Used as given (no path appended). User info, query or fragment → `ValueError` whose message never echoes the URL (047 E8). Verified HTTPS, or plain HTTP only to a loopback host (`localhost`, `127.0.0.1`, `::1`), the same rule as metadata delivery; any other scheme or host → `ValueError`. TLS verification cannot be disabled. |
| `FABRIC_TENANT_ID` | safe identifier | Required in `node` and `file` modes. |
| `FABRIC_WIRE_SPOOL_DIR` | absolute directory | Required in `node` mode; optional otherwise (enables spool delivery). |
| `FABRIC_WIRE_SPOOL_MAX_BYTES` | int | Default 1 GiB; minimum `2 × max_body_bytes + 1 MiB`. |
| `FABRIC_WIRE_SPOOL_MAX_RECEIPTS` | int | Delivery receipts kept for other writer processes (§2). Default 4096, 1 – 2^20; never more than `max_bytes / 1024`. |
| `FABRIC_WIRE_MODEL_ALLOWLIST` | comma list | §7. |
| `FABRIC_WIRE_ID_KEY` | secret, ≥ 16 bytes | Keys every label pseudonym (`r-` run ids; `s-`/`svc-` by default). Recommended in production. |
| `FABRIC_WIRE_LABELS` | unset, `pseudonymous`, `clear` | J1. Default pseudonymous `fabric.source_id` and `service.name`; `clear` exports them unchanged (you guarantee they contain no personal data); anything else → `ValueError`. |
| `FABRIC_WIRE_STORE_SSE`, `FABRIC_WIRE_STORE_KMS_KEY_ID` | — | Removed. Set → `ValueError` ("encryption is configured on the Fabric Node"). |
| `OTEL_EXPORTER_OTLP_LOGS_{HEADERS,CERTIFICATE,CLIENT_CERTIFICATE,CLIENT_KEY,TIMEOUT}` | | Content client; each falls back to the `OTEL_EXPORTER_OTLP_*` general variable (§3). |

Node mode also requires: an OTLP traces endpoint (047 §3), the private
tracer (`FABRIC_WIRE_TRACER=global` → `ValueError`), `max_body_bytes ≤ 63
MiB` (one record must fit the Node's 64 MiB request bound), POSIX `fcntl`
(no Windows), and the `[otlp]` extra (`requests`, `opentelemetry-proto`).
Any violation installs nothing; autoload logs one warning naming only the
error class; the host is unaffected. `install(tracer_provider=X)` and
`FABRIC_WIRE_TRACER=global` keep the 047 direct-provider path (no spool,
no requeue machinery) and are refused in node mode.

Programmatic `WireConfig(store=…)` rejects an `S3ContentStore` instance.

## 2. Agent durable spool (F2)

**Directory.** Created `0700` if absent (parents too, like the local store);
an existing directory must be owned by the process uid, not a symlink, and
is tightened to `0700`, else `ValueError`. Lock file `.lock` (`0600`),
`flock(LOCK_EX | LOCK_NB)`. The lock holder is the only **drainer**; any
process can **write**. A process that does not get the lock (a second agent
on the same directory, or a forked worker whose parent holds it) writes
records and retries the lock every 5 s on its sender thread, taking over
when the holder exits.

**Record file.** Name `<source_epoch:020d>-<pid:010d>-<order:012d>.rec`
(`order` = per-process monotonic counter); lexicographic order is drain
order. Written as `.tmp-<name>` (`0600`), `fsync`, `rename`, `fsync(dir)`.
Framing (big-endian):

```text
b"FWSPOOL1" | u32 header_len | header (canonical JSON, UTF-8) | blob | sha256(all preceding bytes) (32 bytes)
```

`header` is a `fabric.wire-spool-record/v1` document
(`contracts/capture/v1/schema/spool-record-v1.schema.json`): `record_kind`
`exchange` (span data + up to two content descriptors with `offset`/`length`
into `blob`), `loss` (one coalesced range) or `marker` (`run_start`,
`run_end`, `final`). Span data is fully resolved at write time — trace id,
span id, parent span id and flags, timestamps, status and the closed 047 §8
attribute map — so a replay re-sends the identical span. Nothing in a header
is content; bodies exist only in `blob`.

**What is spooled.** Every exchange, every loss range and every
`run_start`/`run_end`/`final` marker. **Periodic** heartbeats are not
spooled: the sender exports them best-effort, directly, every 30 s for
active sources and on `flush()`.

**Where it runs.** Never on the host's call path: the capture worker writes
exchange records; loss records are written by the sender thread from the
O(1) in-memory loss table; a marker's `last_sequence` is read on the host
thread under the allocator lock (047 §6) and the record is queued in memory
(bounded, 1,024) for the sender thread to write.

**Window before the spool write.** A record is durable only once its
file is fsync'd. Between a call finishing (the stream is exhausted, closed
or failed) and that point the exchange exists only in the agent's memory:
it waits in the capture worker's queue (bounded by `queue_max_items`,
default 256, and `max_inflight_bytes`, default 256 MiB), then the worker
digests both bodies, builds the record, writes, fsyncs and renames it. With
an idle worker the window is one exchange for the time of one SHA-256 pass
over its bodies plus one `fsync` — typically a few milliseconds, tens of
milliseconds for multi-MiB bodies or slow disks; under a burst it also
covers every exchange queued behind it. Run markers have the same kind of
window (the bounded in-memory marker queue, written by the sender thread).
The write is **not** moved onto the host's thread: disk latency and fsync
stalls on the call path would violate passivity (047 §4 rules 3 and 10).
A process killed inside the window (SIGKILL, OOM kill, power loss) loses
those exchanges with no loss record. Their sequences were allocated when
the calls started, so they remain unexplained gaps, and the verifier can
never report an affected *observed* scope or unscoped run complete:
`partial` when a later sequence or the scope's `run_end` marker was
recorded (a gap inside the window), `unverified` when the end is unproven
(no `run_end`, or no `final` heartbeat for an unscoped run, which a killed
process never writes). `tests/test_wire_spool_window.py` kills an agent
with its worker parked inside the window and checks exactly this.

**A scope lost whole is undetectable (H5).** When *every* record of a
`fabric.wire.run()` entry — its `run_start`, its calls and its `run_end` —
is still in memory at the kill (e.g. a reused run id's second block, entered
and left while the sender or worker was behind), the record holds nothing
that says the scope existed: its allocated sequences show at most as
missing sequences of the source, outside every observed window. The
verifier therefore never claims a run beyond the scopes it observed: a
scoped run is at best `complete_for_observed_scopes`, and each observed
scope has its own verdict. Detecting a scope lost whole needs *durable
admission* — writing the `run_start` (or a scope inventory) to disk on the
host's thread before the block runs — which this spec rejects for the
reason above (§12 Q4).

**Bound.** `spool_bytes` is the total of a per-file ledger: every spool
file the process knows, at its accounted size, plus its own writes in
flight (counted at full size from admission). A directory rescan every 5 s
on the sender thread rebuilds the ledger from disk; every other transition
(write, retirement step, quarantine, receipt consumption or expiry) sets
that file's entry from what is on disk after the step, never by
subtracting a remembered size, so a failed and retried step, or a rescan in
between, never counts anything twice. A rename (record to receipt, record
to `*.corrupt`, a failed write's charge to the temp file it left) moves the
charge to the new name in one step under the admission lock, so no
admission, and no rescan, ever sees the file uncharged; only then is the new
name set from disk. Observation is conservative: when `lstat` fails (any
error but the absence of a name that is not a rename's destination) the
charge stays as it was, and a rescan that cannot observe every spool file
releases nothing (a later complete rescan settles it). The drainer never
takes an own write still in flight. An exchange record is admitted only while `spool_bytes +
size ≤ FABRIC_WIRE_SPOOL_MAX_BYTES`; otherwise it is dropped and recorded as
a `queue_full` loss. Loss and marker records may use a 1 MiB reserve above
the bound; past it, loss ranges stay in the in-memory table (merged per key,
as 047) and are spooled when space frees, and a marker is dropped and
counted (its scope then stays open: `unverified`, never false complete).
With several writer processes the bound is approximate by one rescan
interval. Delivery receipts (`*.ack`, below) count against the same bound
at their size but at least 128 bytes each (an inode and directory entry),
less than any record, so neither the rename nor the truncation of a
retirement grows the accounted total, even when the truncation fails.
Quarantined `*.corrupt` records count against the same bound
(own quarantines immediately, others' at the next rescan) until an operator
removes them: quarantine never deletes evidence and never escapes the
bound, so a spool filled with quarantined records shows as `queue_full`
losses rather than unbounded disk use.

**Sender.** One daemon thread per process. As drainer it takes records in
file-name order. For an exchange: each body is posted to the content
endpoint (§3), then the span is exported with
`SpanExporter.export([ReadableSpan])` — a synchronous export of a span
rebuilt from the header (resource `service.name` from the header, scope
`fabric.wire`), with no `BatchSpanProcessor` on the capture path. Loss and
marker records are exported the same way as `fabric.capture_loss` /
`fabric.capture_heartbeat` spans. A record is retired only after every
part succeeded: an own record is unlinked; another process's becomes its
receipt (below). Retirement allocates nothing. If it fails (`ENOSPC`,
`EIO`, …) the ledger keeps what is on disk, a retry redoes only the
outstanding step, and the drainer marks the record
*delivered-awaiting-retirement*: it is not exported again, and nothing new
is exported until it is retired (retried with the backoff below). A
drainer that stops meanwhile leaves it on disk for the next drainer to
export again: at-least-once, with replay-identical span ids. Failures retry the same
record with capped exponential backoff (0.5 s doubling to 30 s). The sender
may batch up to 64 consecutive ready records per export call.

- *Content result:* 2xx with no `partial_success.rejected_log_records` →
  done. 400, 413, 415, 422 or a rejected record → permanent: counted, logged
  by status code only, the part is skipped and the span is still exported
  unchanged (the verifier then reports `missing_object`). Everything else
  (connection errors, timeouts, 401/403/404, 429, 5xx) → retry.
- *Span result:* every `FAILURE` is retried. A closed-shape metadata span is
  not rejectable by a correctly configured Node, and an authentication
  failure must not discard spooled records.

**Restart and replay.** Records from earlier epochs (a crashed or exited
process, any pid) are drained first; they carry their own source, epoch,
sequences and span ids. A record whose framing or trailer digest fails, or
whose header fails the schema, is renamed `*.corrupt` (kept for the
operator, never retried) and a fixed-text warning is logged (no name, path
or byte). When its header parsed, an `internal_error` loss
is recorded for its sequence; otherwise the sequence stays an unexplained
gap the verifier still detects. Leftover `.tmp-*` files older than one hour
are removed by the drainer.

**flush / close.** `flush(timeout)` waits until every record this process
wrote before the call is *settled* — deleted with a delivery outcome known,
by whichever process drains — then sends a periodic heartbeat; `False` on
timeout. A drainer retires another process's delivered record by renaming
it in place to its receipt `<record>.ack` (atomic; never a moment with
neither name), then truncating it to zero length (file and directory
fsync'd). The writer consumes (deletes) its receipts and counts those
records delivered. A rescan by the drainer finishes a truncation a crash
interrupted. Receipts are bounded by `FABRIC_WIRE_SPOOL_MAX_RECEIPTS`
(default 4096, never more than `max_bytes / 1024`): past it the drainer
expires the oldest first (best effort, retried at the next retirement and
rescan; a receipt that cannot be removed stays counted), and it removes receipts older than one hour (a
writer that exited). A record of this process that was quarantined (by any
drainer) or that disappeared without a receipt (an operator, an older
drainer, or a receipt expired before the writer consumed it) is a failure,
never a delivery: the receipt is the only proof, so a delivery that can no
longer be proven reports `False` (conservative; a running writer consumes
its receipts every 5 s and at every flush, so this needs more than the
receipt bound of other processes' deliveries in that window). The whole
settle — pump, admission check and wait — runs on a helper thread: the
caller waits only until its deadline, even while another pump holds the
lock during stalled disk I/O (047 E9). `close()` drains, seals the epoch,
writes the `final` marker, and waits for delivery within the 047 budget;
whatever is undelivered stays on disk for replay and `close()` returns
`False`. Neither acknowledges a record that never reached the spool:
`flush()` also returns `False` when, since the previous flush, an exchange
was lost before the spool (any recorded loss: `queue_full`, `shutdown`,
`internal_error`, spool full or a failed spool write), a marker was dropped
(queue overflow or a failed write), one of this process's own records was
quarantined or disappeared without a receipt, or a loss range is still only
in memory after the pump;
`close()` returns `False` when any of these happened during the sender's
lifetime. Both still wait for delivery first. The exit handler is bounded
exactly as 047 E9.

**Delivery semantics.** At-least-once. Duplicates are expected after a
crash between "sent" and "deleted": the Node treats an identical object as
success (§4); the verifier deduplicates exchanges by `exchange_id`, losses by
content and heartbeats by logical identity (§6).

**Stats** (`WireStats`, counters only): adds `spooled`, `spool_bytes`,
`spool_full_drops`, `delivered`, `send_retries`, `content_rejected`,
`quarantined`, `markers_dropped`.

## 3. Content transport (F3)

One `ExportLogsServiceRequest` per stored body, protobuf over HTTP POST,
`Content-Type: application/x-protobuf`, to `FABRIC_WIRE_CONTENT_ENDPOINT`,
never following a redirect: a 3xx response is a failed attempt (retried
like a 5xx), and neither the body nor any header is sent to its `Location`
(H1; the private OTLP trace exporter's HTTP session is configured the same
way). Resource: `service.name` only (same rule as 047 D3). Scope: `fabric.wire`.
One `LogRecord`:

- `time_unix_nano` = `captured_at`; `body` = `AnyValue.bytes_value` with the
  exact stored bytes; no trace context, no severity text;
- attributes = the content log-record attribute set
  (`contracts/capture/v1/schema/content-log-record-v1.schema.json`), bare
  descriptor field names, every value typed and closed:

| Key | Type | Value |
|---|---|---|
| `event_class` | string | `content` |
| `schema_version` | string | `fabric.content-object/v2` |
| `object_id` | string | lowercase uuid4 |
| `tenant_id` | string | `^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`, not `.`/`..` |
| `role` | string | `model.exchange.request` \| `model.exchange.response` |
| `media_type` | string | 047 §7 media rule |
| `content_encoding` | string | 047 §7 token-list rule, or `identity`/`unknown` |
| `representation` | string | `exact` \| `partial` (response only) \| `truncated` |
| `transformations` | array of string | `[]` or `["truncate"]` |
| `provenance` | string | `protocol` |
| `boundary` | string | `provider_bound` |
| `status` | string | `stored` \| `truncated` |
| `stored_byte_length` | int | = body length |
| `stored_sha256` | string | `sha256:` + hex of body |
| `source_byte_length` | int | observed length (≥ stored) |
| `source_sha256` | string | present iff not truncated; = `stored_sha256` |
| `source_id`, `run_id`, `operation_id` | string | opaque ids (`operation_id` = exchange id) |
| `source_epoch`, `source_sequence` | int | ≥ 0 |
| `captured_at` | string | RFC 3339 with offset (Python `isoformat()`) |

`truncated` ⇔ `status: truncated` ⇔ `transformations: ["truncate"]` ⇔ no
`source_sha256` ⇔ `source_byte_length > stored_byte_length`. These are the
SDK's content-v2 descriptor fields minus `encoding` and `ref`, which the
writer adds (§4).

TLS, client certificate/key, CA, headers and timeout are resolved like the
trace exporter: `OTEL_EXPORTER_OTLP_LOGS_*` first, then
`OTEL_EXPORTER_OTLP_*`; headers use the OTLP `k=v,k2=v2` percent-decoded
form; an unreadable TLS file fails installation. The client is a
`requests.Session` owned by the sender (the tee patches only httpx/httpx2,
so it cannot capture itself). No URL, header, body or exception message is
ever logged.

## 4. Node content path (F4)

**Receiver.** Instance `otlp/content`, `protocols.http` only (no `grpc`),
`endpoint: 0.0.0.0:4319`, `max_request_body_size: 67108864`, the same
authenticator and TLS as the telemetry receivers, read timeouts sized for
64 MiB.

**Pipeline.** `logs/content: {receivers: [otlp/content], processors:
[memory_limiter], exporters: [fabriccontent]}`. `fabricguard` is not used
here: bodies must pass unchanged, and the exporter enforces the closed
attribute set itself.

**Exporter** `fabriccontent`
(`components/otel-collector-fabric/exporter/fabriccontentexporter`):

1. Accept only records whose attributes are exactly the §3 set (no unknown
   key), every value valid, `event_class = content`, body of type bytes.
2. Recompute SHA-256 and length of the body; mismatch → reject.
3. `tenant_id` must be in `allowed_tenants` → else reject. The tenant is
   the record's claim, not derived from the agent's identity, so the
   exporter configuration must list **exactly one** tenant unless
   `allow_multiple_tenants: true` is set (F11); the flag trusts every
   authenticated agent to name its tenant. Use one Node per tenant
   otherwise. Duplicate entries are refused. The rule holds per Node, not
   per exporter (H2, J3): all `fabriccontent` exporters of the effective
   configuration together allow one tenant, whatever receivers or
   authenticators they sit behind, unless every one of them sets the flag
   (§5 rule 7).
4. Write body to `<prefix><tenant>/evidence/<object_id>`, **then** the
   descriptor to `<prefix><tenant>/evidence/meta/<object_id>.json`.
   Descriptor = the attributes minus `event_class`, plus `"encoding":
   "binary"` and `"ref"` (`file://<abs dir>/<tenant>/evidence/<id>` or
   `s3://<bucket>/<prefix><tenant>/evidence/<id>`), serialized exactly as
   Python `json.dumps(d, ensure_ascii=False, sort_keys=True) + "\n"`
   (keys sorted, `", "` and `": "` separators, integers as integers). The
   goldens in `contracts/capture/v1/fixtures/golden/` pin these bytes.
5. Never overwrite: an existing object or descriptor with identical bytes
   is success (replay); different bytes → reject (`conflict`).

Backends: `file` (`directory`; files `0600`, directories `0700`; a fully
fsync'd temp file is published with `link(2)`, falling back to an atomic
no-replace rename — `renameat2(RENAME_NOREPLACE)` on Linux,
`renamex_np(RENAME_EXCL)` on macOS — then a directory fsync; when the
filesystem offers neither, the write fails retryably, never a
check-then-rename that two processes could race) and `s3` (aws-sdk-go-v2 default credential chain
incl. IRSA; optional `endpoint` and `use_path_style` for MinIO and other
S3-compatible stores; `region`; `sse: AES256 | aws:kms`, **required** —
an empty or missing `sse` fails configuration validation (F12);
`kms_key_id` only with `aws:kms`; `PutObject` with `If-None-Match: *`, on 412 `GetObject` and
byte-compare). A store without conditional-write support is a retryable
error, never an unconditional write.

Durability: exporterhelper `sending_queue` on its own `file_storage`
(fsync, `block_on_overflow: true`) and `retry_on_failure` with
`max_elapsed_time: 0`. Backend I/O errors are retryable (writes are
idempotent). Steps 1–3 and conflicts are permanent per record: the record is
dropped, counted, and logged as `fabriccontent: dropped content record
(reason=<bad_descriptor|digest_mismatch|tenant_not_allowed|conflict>)` —
no tenant, id, path, URL or byte.

Build: add the module to `ocb-config.yaml` (local `path` + `replaces`), the
Dockerfile `COPY`, `EXPOSE 4319`, `tests/test-recorder-manifest.sh`'s pinned
set and the Makefile test dirs. `scripts/license_scan.sh` scans the built
distribution, so the AWS SDK modules are covered without a hand-kept list.

## 5. Gate (F5; extends 047 §8 "Boot gate")

A *content pipeline* is a `logs` pipeline whose name part starts with
`content` (`logs/content`, `logs/content-eu`). A *content receiver* is an
`otlp` receiver whose name starts with `content`. In addition to the 047
rules (`traces`/`logs` only, no `--set`), the gate refuses a configuration
where:

1. a content receiver appears in any non-content pipeline;
2. a `fabriccontent` exporter appears in any non-content pipeline;
3. a content pipeline has a receiver that is not a content receiver, an
   exporter that is not `fabriccontent`, or a processor that is not
   `memory_limiter` (so not `fabricguard`, which would scrub bodies);
4. a non-content (telemetry) pipeline lacks `fabricguard` (047 rule,
   unchanged, including "only `batch`/`memory_limiter` after the guard");
5. a content receiver configures `grpc`;
6. `connectors` is non-empty (a connector could bridge content into a
   telemetry pipeline);
7. a `fabriccontent` exporter lists more than one `allowed_tenants` entry
   without `allow_multiple_tenants: true` (F11; the exporter refuses it
   too), or the `fabriccontent` exporters sharing any receiver or pipeline
   in the effective configuration (transitively) together allow more than
   one tenant while any of them lacks `allow_multiple_tenants: true` (H2;
   the Helm chart renders exactly one `fabriccontent` exporter, whose tenant
   list it checks the same way). Revision 4 (J3): the check spans **all**
   `fabriccontent` exporters of the effective configuration, whatever
   receivers or authenticators they sit behind, and an exporter block that
   is not a literal map after the gate's own resolution is refused with
   fixed text. The diagnostic names exporter ids, never tenant ids.
8. (J4) an `otlphttp` exporter does not list the `noredirect` client
   middleware.

## 6. Run scopes (F6; supersedes 047 §6 run markers and §9 step 3 (a))

**Capture.** `fabric.wire.run(run_id)` validates `run_id` and creates
`RunScope(r, scope_id=uuid4, parent)` per entry, where `r` is the run id's
pseudonym (H3): `r-` + the first 32 hex of `HMAC-SHA256(key, run_id)` with
`key` = `FABRIC_WIRE_ID_KEY` (UTF-8, at least 16 bytes; set it in
production so the pseudonym cannot be confirmed by guessing), else of
`SHA-256(run_id)`. Only `r` is written anywhere (spans, markers, spool,
descriptors, reports); the source id and `service.name` follow the same
function with prefixes `s-` and `svc-` unless `FABRIC_WIRE_LABELS=clear`
(J1); the vectors in
`contracts/capture/v1/fixtures/run-ids/run-id-pseudonym-v1.json` pin it.
fabricguard admits `fabric.run.id` only in the `r-` form or a generated
fallback form (`trace:<32 hex>`, `source:<source_id>:<epoch>`, `h-<40
hex>`). Entry: read `a` = last allocated
sequence under the allocator lock, then set the scope in the context;
spool `run_start{run_id, scope_id, last_sequence=a}`. Exit: under the
allocator lock mark the scope closed and read `b`; reset the context; spool
`run_end{…, last_sequence=b}`. Allocation reads the context's innermost
**open** scope under the same lock: the exchange carries that scope's
`fabric.run.id` and `fabric.run.scope_id`. When no scope is open (e.g. a task
that outlived its block), the 047 run-id fallback applies and no scope id is
set: a run's declared scope is the calls *started* inside its blocks.

New OTLP key: `fabric.run.scope_id` (lowercase uuid4) on `fabric.model_call`
spans inside a scope and on `run_start`/`run_end` heartbeats; never on
`periodic`/`final`. fabricguard admits it in the strict capture profile with
the uuid4 validator.

**Verifier.** Heartbeats deduplicate by `(source_id, epoch, kind, run_id,
scope_id, last_sequence)`. A marker without a valid `scope_id` (047 capture)
is an unclassified heartbeat (counts toward `H` only). Per scope id:

- exactly one distinct `run_start` and one `run_end` `last_sequence` on one
  `(source, epoch)`, the same run id on both, `a ≤ b` → *closed*, window
  `[a+1, b]`; a missing marker → *open* (`tail_unverified`,
  `run_not_closed`); anything else → *conflict* (`tail_unverified`,
  `scope_conflict`);
- every exchange tagged with the scope has its run id and lies in the
  window, else `tail_unverified` (`exchange_outside_run_markers`);
- any missing sequence **inside** the window → `partial` (`loss` when loss
  records cover it, else `sequence_gap`). Missing sequences are never
  attributable to a particular scope, so a concurrent scope's lost call on
  the same source also makes this scope partial (conservative). Sequences
  outside the window are outside the scope: `a` was allocated before entry
  and `b+1` after exit.

- a sequence inside the window that is claimed by conflicting observations
  (one exchange id seen with different values, or several exchange ids on
  one sequence) → `partial` (`digest_mismatch`, `conflicting_claim`):
  whichever run the claims name, the window cannot be proven.

Nested scopes are independent windows (an inner scope's exchanges lie inside
the outer window and count as present there). Serial and concurrent scopes,
and reuse of a run id, are distinct scopes.

**Claims (H5).** Completeness is claimed per scope and per unscoped source
epoch, never for a run as a whole:

- *Scope verdict.* Each scope is `complete_for_declared_scope` only when it
  is closed, has no gap inside its window (above) and every exchange it
  tags verified (bytes, response evidence, stitching); otherwise `partial`
  or `unverified` by the 047 §9 step 7 rule over the scope's own gaps.
- *Run verdict.* A run without scopes keeps 047 rule (b) (`final`
  heartbeat, E2) and its `complete_for_declared_scope` verdict. A run id
  with any scope (marker or scoped exchange) is never better than its worst
  observed scope; its best value is `complete_for_observed_scopes`: it makes
  no claim about a scope that left no record (§2 "Window"). An unscoped
  exchange of such a run is a run-level `tail_unverified`
  (`exchange_outside_run_markers`) that belongs to no scope.
- *Exit code.* `0` iff every reported scope and every unscoped run is
  complete; otherwise `1` (047 §9).

Report: each closed scope with at least one exchange is a window with
`scope_id` and `closed_by: run_markers`; `runs[].scopes[]` lists every scope
(`state` `closed`/`open`/`conflict`, marker sequences, exchange count);
report exchanges carry `scope_id`; the top-level `scopes[]` repeats each
listed scope with its `run_id`, `verdict`, own `gaps` (each also a gap of
its run) and `checks`. The contract validator enforces that a complete run
has only closed scopes and no missing sequence inside a scope window
(adjacency is checked only for windows without a scope), that a scoped
run's best verdict is `complete_for_observed_scopes`, that each scope
verdict follows from its gaps and checks, that a complete scope is closed
with no missing sequence inside its window, and that a run is never better
than its worst scope.

## 7. Model exposure (F7; supersedes 047 E5 for emission)

`fabric/_model_names.py` (shared by capture and `fabric.reconstruct`):

- allowlist = `FABRIC_WIRE_MODEL_ALLOWLIST` (comma-separated exact names or
  `prefix*`; each must match the 047 model pattern without the `*`; a bare
  `*` is refused) plus the built-in prefixes `gpt-*`, `o1*`, `o3*`, `o4*`,
  `chatgpt-*`, `claude-*`, `gemini-*`, `text-embedding-*`, `llama*`,
  `meta-llama/*`, `mistral*`, `mixtral*`, `codestral*`, `command*`,
  `deepseek*`, `qwen*`, `grok*`, `anthropic/*`, `openai/*`, `google/*`
  (case-sensitive);
- matching (H4): an exact entry matches exactly. A `prefix*` entry matches
  only when the value starts with the prefix and the rest, split on
  `[-._:/@]` (empty tokens ignored), consists solely of numbers, dates,
  short version tokens matching `^(v?\d+[a-z]{0,2}|\d+[a-z]\d*|[a-z]\d+)$`
  that are not all digits (`4o`, `o1`, `v2`, `70b`) or words of a fixed
  vocabulary (`mini`, `turbo`, `preview`, `latest`, `instruct`, `sonnet`,
  `flash`, … — the list is pinned by the vectors). J2: a *number* is an
  all-digit token of at most 4 digits, or a decimal `N.N` (two all-digit
  tokens of 1–2 digits joined by exactly `.`); a *date* is an 8-digit token
  matching `^20\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$` or three
  all-digit tokens of 4, 2 and 2 digits joined by exactly `-` that form one;
  tokens are read left to right, a date or decimal taking its tokens first.
  At most two numbers and one date; any longer all-digit token fails.
  J2b: no token of any class may contain a run of more than 4 digits
  (`v919876543210`, `919876543210b` fail), except a token that is exactly
  an 8-digit date, and the suffix holds at most 6 digits not counting its
  date (`gpt-4o-1234-5678` fails; `gpt-3.5-turbo-16k-0613` needs an exact
  entry). Matching is case-sensitive. So `gpt-4o-mini-2024-07-18` and
  `claude-3-5-sonnet-20240620` are kept and `gpt-patient-Jane-Doe-12345`,
  `gpt-4o-123-45-6789` and `gpt-4o-919876543210` are hashed; so are names
  whose suffix is not version-like, such as `openai/gpt-4o`,
  `meta-llama/Llama-3-70b` or `gemini-2.5-flash-preview-05-20` (three
  numbers), which need an exact allowlist entry;
- a non-empty string that matches the pattern, has no `://` and is
  allowlisted is emitted as is; any other string as `m-` + the first 16 hex
  of `sha256(utf-8)`; a non-string is omitted.
- Capture (Python), fabricguard (Go) and `fabric.reconstruct` test against
  the same vectors,
  `contracts/capture/v1/fixtures/model-names/model-exposure-v1.json`.

fabricguard applies the same rule to `gen_ai.response.model` (the `m-`
form passes unchanged; a value that fails the 047 model pattern or contains
`://` is dropped, which a conforming agent never sends). Its
`capture_model_allowlist` option (exact names or `prefix*`, validated like
the environment variable) is the Node counterpart of
`FABRIC_WIRE_MODEL_ALLOWLIST`: deployments that extend the agents' list
pass the same list to fabricguard, or the Node hashes the extra names.
`fabric.reconstruct` applies the same rule to models parsed from bodies and
to span values, keeping span values already of the form `^m-[0-9a-f]{16}$`;
`--model-allowlist` (default `FABRIC_WIRE_MODEL_ALLOWLIST`) extends its list.

## 8. Credential logging (F8)

No Fabric code path logs environment values, endpoint URLs, header values,
TLS file paths or contents, or exception messages from exporter or client
construction and export. Exporter/client construction and every export or
POST are wrapped: only exception class names and HTTP status codes are
logged; errors are re-raised `from None` with fixed text; OTLP exporter log
records emitted during Fabric-owned exports stay reduced (047 §4.9). Test:
set secret-marked values in every `OTEL_*` and `FABRIC_*` variable, force
construction and export failures (traces and content), and assert no marker
appears in captured records at `DEBUG` for the `fabric` and `opentelemetry`
loggers.

## 9. Compose preflight (F9)

When any of 4317, 4318 or 4319 is published on a non-loopback
`FABRIC_BIND_ADDR`, preflight fails unless the receiver instance serving
that port has TLS enabled: an uncommented `tls:` mapping under that
protocol with non-empty `cert_file` and `key_file`. A commented-out stanza,
`tls:` with no children, `tls: {}`, `tls: null`/`~`, or a stanza missing
either file counts as disabled. Fixture tests cover each case.

**Destination URLs (both Compose preflight and the Helm render).**
`FABRIC_EXPORT_ENDPOINT` / `exporter.endpoint` and
`FABRIC_CONTENT_S3_ENDPOINT` / `content.s3.endpoint` must be absolute
`http(s)` URLs with a DNS name, dotted IPv4 or bracketed IPv6 host and a
port of 1–65535; user information (any `@`), a query, a fragment,
whitespace, control characters and backslashes are refused (production
also requires `https`). Credentials belong in Secret-backed headers, never
in a URL. Diagnostics name the variable or value path, never the value;
the Compose reachability probe receives only the parsed host and port.
fabric-gate applies the user-info/query/fragment rule at boot to every
`otlp`/`otlp_grpc`/`otlphttp`/`otlp_http` exporter endpoint and to
`fabriccontent` `s3.endpoint` (env-expanded first).

**NetworkPolicy peers (Helm).** Every peer in `ingressFrom`,
`exporterEgress.to`, `contentEgress.to`, `egressTo` and
`monitoringNamespaceSelector` must restrict its sources or destinations:
a `namespaceSelector` restricts only with `matchLabels` or an `In`/`Exists`
expression (an empty, null or only-`NotIn`/`DoesNotExist` selector needs a
restricting `podSelector`); an empty `podSelector` alone, an `ipBlock` with
prefix length 0, an `ipBlock` combined with a selector and unknown peer
keys are refused in every profile.

## 10. Reconstruct (F10)

`python -m fabric.reconstruct` reads Node-written content through the
unchanged `--store-root` (file backend directory) or `--store-uri
s3://bucket/prefix`, plus new `--s3-endpoint-url URL`, `--s3-region REGION`
and `--s3-path-style` (passed to `S3ContentStore(endpoint_url=…,
region_name=…, addressing_style="path")`). Credentials come from the default
boto3 chain. The e2e qualifies the path agent → Node → MinIO (SSE via
`MINIO_KMS_SECRET_KEY`) → reconstruct.

`--run RUN_ID` takes the id given to `fabric.wire.run()` in the clear (or
its `r-` pseudonym, or a fallback id) and selects the run whose recorded id
is the value or its pseudonym (H3). The key is read from the environment
variable named by `--id-key-env` (default `FABRIC_WIRE_ID_KEY`; when that
default is unset the unkeyed form is used, as capture does; a named
variable that is unset, or a key under 16 bytes, is a usage error). The
key and the clear id are never written to stdout, stderr or the report.

**Report labels (J1).** The same key projects every label the report
shows: the tenant (`--tenant`, clear because it names the store prefix) as
`t-` + 32 hex; every source id not already of the `s-` form as its `s-`
pseudonym (so records of one source from older, clear-label capture and
from current capture are one source); every run id not of the `r-`,
`trace:<32 hex>` or `h-<40 hex>` form as its `r-` pseudonym, except that a
`source:<source_id>:<epoch>` fallback keeps its form with the source id
projected. `--run` values go through the same projection.

## 11. Acceptance

1. Node mode: an agent with no AWS variables captures a three-step ReAct run;
   the Node writes bodies + descriptors to MinIO; reconstruct from the span
   sink and MinIO is complete (`complete_for_declared_scope` for an unscoped
   run, `complete_for_observed_scopes` with every scope complete for a run
   in `fabric.wire.run()` blocks).
2. Kill -9 the agent after the worker spooled N exchanges but before
   delivery; restart; every record is delivered once or more and the run
   verifies with no unexplained gap.
3. Node down for the whole run: the spool holds everything (bounded);
   after the Node returns, delivery completes. Spool full: `queue_full`
   loss, host unaffected.
4. Corrupt a record: it becomes `*.corrupt` and an `internal_error` loss.
5. Two processes on one spool: one drainer, both writers, no record
   delivered zero times.
6. Gate refuses each §5 violation; a digest mismatch, unknown tenant or
   unknown attribute is dropped by the exporter with a content-free log line;
   an identical replay is accepted; a different body under an existing id
   is refused and the stored object is unchanged.
7. Scopes: same run id reused, serial, nested and concurrent scopes each
   verify correctly; dropping an inner exchange makes only scopes whose
   window holds it partial; a missing `run_end` is `unverified`.
8. F7, F8 and F9 tests as stated.
9. 047 §4.10 latency budgets still hold; capture line count outside spool,
   sender and content client does not grow.
10. Revision 2: two tenants without `allow_multiple_tenants` are refused by
    the exporter, the gate and the Helm render; S3 without `sse` is refused
    by the exporter and the Helm render; a SIGKILL inside the spool window
    (scoped or unscoped run) never verifies an observed scope or an
    unscoped run as complete.
11. Revision 3: a 3xx from the content endpoint or the OTLP trace endpoint
    is retried and its `Location` never receives a body or header (H1); two
    `fabriccontent` exporters sharing ingress with different tenants are
    refused by the gate, and the Helm chart renders only one (H2); `fabric.run.id`, markers,
    spool records and descriptors carry only the `r-` pseudonym of a
    caller-supplied run id and `--run <clear id>` selects it (H3); the
    shared model vectors pass in Python and Go (H4); a reused run id whose
    second scope is lost whole while the process is killed reconstructs as
    `complete_for_observed_scopes` with its observed scope complete (exit
    `0`), a scope with a gap makes its own verdict and its run `partial`,
    a `complete`/`closed_early` exchange without response evidence is
    `partial`, and a conflicting duplicate invalidates every run and scope
    it names (H5).
12. Revision 4 (`tests/test_wire_hardening_round4.py`): a writer's record
    quarantined, or removed without a receipt, by another process makes its
    `flush()`/`close()` `False`, and one delivered elsewhere is acknowledged;
    `flush(0.3)`/`close(0.3)` return within a second while another pump
    stalls in a disk write; actual `error` (after a 200) and `abandoned`
    captures without response evidence are `partial`; a malformed duplicate
    claiming another run's scope and sequence makes both runs and scopes
    `partial`, and a malformed identity is exit `2` with fixed text; an
    actual capture with identifying source, service, tenant and run labels
    and the model `gpt-4o-123-45-6789` leaves none of them in telemetry,
    spool records, descriptors or the report (keyed and unkeyed), and
    `FABRIC_WIRE_LABELS=clear` restores clear source/service labels; the
    J2 vectors pass in Python and Go.
13. Revision 4, Node (`gate/gate_node_test.go`,
    `extension/noredirectextension`, `capture_labels_test.go`): two
    `fabriccontent` exporters with different tenants are refused whether or
    not they share a receiver or authenticator, and a whole-block `${env:…}`
    exporter is refused with fixed text (J3); the pinned `otlphttp` exporter
    with the `noredirect` middleware never sends a byte or the
    `Authorization` header to a `3xx` target and never reports a redirect to
    an HTML page as success, an `otlphttp` exporter without the middleware
    is refused by the gate, and the S3 client never follows a redirect, on
    the replay read included (J4); fabricguard drops a clear
    `fabric.source_id`/`service.name` unless `capture_labels: clear` (J1).
14. Revision 5 (`tests/test_wire_hardening_round5.py`): 128 exited writer
    processes under a 512-byte bound leave receipts that stay counted and
    within the bound and the count; retiring a record succeeds when no new
    file can be created; when the rename, truncation or fsync fails with
    `ENOSPC` the record stays pending and is exported once, then retired
    without a second export; an untruncated receipt is truncated by rescan;
    an expired receipt makes its writer's `flush()`/`close()` `False`; the
    J2b vectors (Sol's `gpt-4o-v919876543210`,
    `gpt-4o-a12345678901234567890`, `gpt-4o-919876543210b`) are hashed in
    actual capture telemetry and the report, in Python and Go.
15. Revision 6 (`tests/test_wire_spool_accounting.py`): a failed receipt
    truncation, directory fsync or receipt trim, then a rescan, then the
    retirement retry, then admission until full keeps `spool_bytes` equal
    to the bytes on disk and within the bound (before: 1,172 bytes admitted
    under a 1,100-byte bound); a rescan concurrent with an own write keeps
    it counted once; random interleavings of own and other writers'
    admissions, drains, receipt consumption, corrupt records and rescans,
    with `ENOSPC` injected into truncate, fsync, rename, unlink and
    directory fsync, keep the ledger equal to the disk and within the bound
    after every step; a capture worker admitting concurrently while a
    retirement (with `ENOSPC` on the truncation) or a quarantine is paused
    right after its rename is refused at the bound (before: one record
    past it), `EIO` on `lstat` of the rename's destination keeps it charged
    (before: released until the next rescan), and the random interleavings
    with a concurrent writer and `lstat` failures keep the disk within the
    bound and the ledger at every sampled moment, and equal after a rescan.

## 12. Open questions

1. Whether the Node should also accept governed-content roles (spec 028)
   on `otlp/content`, or stay closed to the two wire roles.
2. Spool encryption at rest (today: `0600`/`0700` and host disk encryption).
3. Whether the Helm chart enables the content path by default.
4. Durable scope admission: writing `run_start` (or a scope inventory) to
   disk before a `fabric.wire.run()` block runs would let the verifier
   detect a scope lost whole (§2 "Window"), at the cost of disk latency on
   the host's thread. Not adopted; reconsider only with a design that keeps
   047 §4 rules 3 and 10.
