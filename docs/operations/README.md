# Operations

Running wire capture and the Fabric Node day to day: the agent spool, the
Node queues, health and metrics, troubleshooting, and upgrades. For backup
and restore of Node volumes see the [recovery runbook](dr.md).

## The agent spool

In node mode every exchange (span data and protected bytes), loss record
and run marker is written to an fsync'd, encrypted file in
`FABRIC_WIRE_SPOOL_DIR` before it is sent (`sdk/python/src/fabric/wire/_spool.py`,
`_sender.py`). The capture worker writes up to 64 queued exchanges (about
8 MiB) at a time as one batch file: one write, one `fsync` and one rename
per batch, and no exchange of a batch counts as spooled before the whole
batch is durable. Loss and marker records are single-record files.

Local file mode (`FABRIC_WIRE_STORE=file://…`) uses the same spool by
default when an OTLP endpoint is set, at `<store>/.fabric-wire-spool/<tenant>`;
`FABRIC_WIRE_SPOOL_DIR=off` turns it off (direct export, not crash-durable).

- **Delivery.** One sender thread posts each body to the Node's content
  endpoint, then exports its span, and deletes the record only after both
  succeeded. It retries with backoff (0.5 s doubling to 30 s) for as long as
  the Node is unreachable. Delivery is at least once; the Node treats an
  identical object as a replay and the verifier deduplicates.
- **Restart.** Records left by an earlier process are delivered first when
  the next agent with the same spool directory, endpoints and credentials
  starts. Nothing drains a spool while no agent runs.
- **Bound.** `FABRIC_WIRE_SPOOL_MAX_BYTES` (default 1 GiB, minimum
  `2 × max_body_bytes + 1 MiB`) bounds the whole directory. When it is full,
  new exchanges are dropped as `queue_full` losses; the application is
  unaffected. Size it for the longest Node outage you want to ride out.
- **Full volume.** Size the volume above `FABRIC_WIRE_SPOOL_MAX_BYTES` plus
  1 MiB. If the volume fills first (`ENOSPC`, `EDQUOT`), new exchanges are
  recorded as `disk_full` losses (`WireStats.disk_full_drops`) and the
  application is unaffected. Loss ranges and run markers that cannot be
  spooled are held in memory and mirrored into the spool's preallocated
  loss ledger (`.ledger`, 260 KiB, written in full when the spool is opened,
  overwritten in place). The next process that drains the spool exports a
  dead process's ledger records (`ledger_recovered`), so a run whose
  exchanges were all lost is still reported (`partial` or `unverified`),
  not missing. On copy-on-write filesystems (btrfs, ZFS) overwriting the
  ledger may itself need free blocks: keep the spool on ext4, xfs or an
  equivalent. A process that opens the spool on an already-full volume
  cannot create the ledger and keeps its losses in memory only.
- **Sharing.** Several processes may share one spool: one drains, all
  write, under a shared admission lock taken only on Fabric's background
  threads. Run the same Fabric version in every process that shares a
  spool. Never point a different kind of spool at the same directory.
- **Durability barrier.** The spool directory is durable only after its
  ancestors are fsync'd; until that walk is recorded (`.barrier`),
  `flush()`/`close()` return `False` and `WireStats.spool_undurable` is 1.
  If an ancestor cannot be opened, set `FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY`
  to a provisioned durable ancestor (a mount point).
- **Quarantine.** A record that fails its checksum or its envelope, or a
  plaintext record when a spool key is set, is renamed `*.corrupt` and
  reported as an `internal_error` loss.
- **The window before the spool.** From the end of a call until its record
  is fsync'd, the exchange exists only in memory (the capture queue, bounded
  by 256 MiB of retained bodies and `FABRIC_WIRE_QUEUE_MAX_ITEMS`, default
  16384 entries). A
  kill inside that window loses those exchanges; their sequence numbers
  make the gap visible (`partial` or `unverified`, never complete).

Files in a spool directory: `.lock`, `.admit`, `.barrier`, `.ledger`,
`*.rec` (one record or a batch), `*.ack` (delivery receipts for other
processes), `.tmp-*`, `*.corrupt`.

### Multiprocessing

Forked and spawned workers capture like any process and share the spool.
End pools with `pool.close(); pool.join()` (or let workers return): each
worker closes capture on its way out and the process draining the spool
delivers every record pending at its close, including exited workers'.
`with Pool():` sends SIGTERM to its workers: what a worker had spooled is
delivered, but a call its capture thread had not yet written is lost. For
forked workers that loss is always visible (the parent records each
worker's last allocated sequence, so its run is `partial` or `unverified`);
a spawned worker killed before it wrote any record leaves no trace.

### Throughput

One capture worker per process writes the spool, and it needs the GIL.
Measured with `scripts/qualification/bench_wire_capture_throughput.py`
(small exchanges, production profile, encrypted spool, loopback fake model
and Node, one Apple-silicon laptop):

| Load | Spooled exchanges/s | Shed (`queue_full`) |
|---|---:|---:|
| 200 threads, 100 ms model latency | 1,732 | 0% |
| 1 CPU-bound thread | 758–835 (keeps up) | 0% |
| 4 CPU-bound threads | 1,643–1,790 | 0% |
| 16 CPU-bound threads | 528–539 | 15–19% |
| 64 CPU-bound threads | 128–132 | 27–34% |

When application threads wait on I/O, as agents waiting on a model do, the
worker keeps up. When many threads spin on the CPU, they hold the GIL and
the worker gets about one turn in N+1: capture sheds load, and every shed
exchange is a recorded `queue_full` loss (the run is `partial`). Run the
benchmark on your own hardware before relying on these numbers.

`fabric.wire.current_handle().stats()` returns counters only (no content):
`matched`, `submitted`, `dropped`, `truncated`, `spooled`, `spool_bytes`,
`spool_full_drops`, `disk_full_drops`, `markers_held`, `ledger_recovered`,
`delivered`, `send_retries`, `content_rejected`, `quarantined`,
`spool_undurable`, `uninstrumented_calls`, `redaction_timeouts`,
`redaction_saturated`, `redaction_failures`, and others.
`handle.status()` reports the profile, whether content capture is enabled
and why not, the policy reference, the pseudonym mode, whether the spool is
encrypted, the state of each wire capture point (`capture_points`:
`wire.py.httpx`, `wire.py.aiohttp`) and `uninstrumented_clients` (clients
seen sending model calls Fabric does not capture, and httpx, httpx2 or
aiohttp loaded but not patched). With `OTEL_SDK_DISABLED=true` it reports
`capture: disabled` (`capture_reason: otel_sdk_disabled`).

## The Node queues

| Queue | Holds | Location (Compose / Helm) |
|---|---|---|
| Telemetry sending queue | protected spans and logs for your OTLP destination | `fabric-queue` volume / queue PVC |
| Content queue | content records waiting for the store; sealed with the Node content key in production | `fabric-content-queue` volume / `<persistence dir>/content-queue` on the queue PVC |

Both are fsync'd `file_storage` queues with `block_on_overflow` and
infinite retry. They bound **items**, not bytes: the content queue can hold
up to `queue_size × 64 MiB`. Size the volumes for your outage window and
alert on disk use. When a queue is full the Node backpressures its senders;
the agent's spool then absorbs the backlog up to its own bound. Never mount
one queue volume into two running Nodes.

The Node's `file` content store shards objects into two levels of
hash-named subdirectories (`<tenant>/evidence/<h0h1>/<h2h3>/<id>`, `h` =
SHA-256 of the id); objects written flat by earlier Nodes are still read.
It holds one file per object and one per descriptor, so alert on the
volume's inode use as well as bytes. At startup the Node sweeps temporary
files across the whole content tree, which takes longer as the store grows.

## Health and metrics

- **Health:** `GET :13133/` (health_check extension).
- **Metrics:** Compose production publishes the Collector's Prometheus
  endpoint on `127.0.0.1:8888`. Useful series:
  `otelcol_exporter_queue_size` against `otelcol_exporter_queue_capacity`,
  `otelcol_exporter_send_failed_spans` / `_log_records`,
  `otelcol_receiver_refused_*`, and the content exporter's
  `fabriccontent_dropped_records` (attribute `reason`) and
  `fabriccontent_written_records`. The Helm chart does not expose a metrics
  port.
- **Content drops.** `fabriccontent` logs `fabriccontent: dropped content
  record` with a reason only: `bad_descriptor`, `digest_mismatch`,
  `tenant_not_allowed`, `conflict`, `source_unbound`. Any non-zero count
  needs review: reconstruct will report those objects missing.
- `fabricguard` keeps its drop counters internal; they are not exported as
  metrics.

## Verify a deployment

After any change to the Node, the store or the agents:

1. **Ingress.** Compose: `make verify-prod` checks that the container runs
   `fabric-gate`, that health answers, and that unauthenticated span,
   content and gRPC requests are refused. Its authenticated-span check posts
   a fixture whose tenant is `harness`; on a source-bound Node that tenant
   does not match the binding, so expect that step to be refused unless
   your tenant is `harness`.
2. **Content canary.** A healthy Node does not prove that content reaches
   the store (bucket policy, IRSA or instance role, KMS grants, egress
   peers). With the production agent settings, make one model call inside
   `fabric.wire.run("fabric-canary-<date>")`, close capture, export the
   spans from your destination and run:

   ```bash
   python -m fabric.reconstruct --spans <export> --trusted-source --profile production \
     --store-uri s3://<bucket>/<prefix> --tenant <tenant> \
     --run fabric-canary-<date> --wait-for-objects 60 --out canary.json
   ```

   Exit code `0` proves the whole path. `missing_object`,
   `source_unauthenticated` or `unverified` names the broken leg without
   exposing content. See [reconstruct](../reconstruct.md).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Spans carry `fabric.wire.store_reason=missing_capture_policy` / `missing_id_key` / `missing_spool_key` | Production profile without that item; content disabled, metadata continues. |
| `store_reason=protection_failed` | A masking mode with no transformation (always the case under autoload) or no redaction service, or the service failed, timed out, answered a non-200 status or was saturated (`redaction_*` counters). |
| `store_reason=privacy_policy` | The policy says `metadata_only` or `omit` for that role. |
| Warning `fabric.wire: autoload failed (...)` or `capture not installed (...)` | Invalid configuration; the class name says which. Capture is off; the application runs. |
| No spans at all | No OTLP endpoint (spans are dropped with a warning), `OTEL_SDK_DISABLED=true` (`status()` says `capture: disabled`), or the autoload directory is not on `PYTHONPATH`. |
| `uninstrumented_client` losses | Model calls sent through `requests` or `urllib3`, which are not captured; move them to httpx, httpx2 or aiohttp. |
| Calls missing from the record | The client is not httpx, httpx2 or aiohttp (`boto3`, gRPC, other processes), `FABRIC_WIRE_AIOHTTP=0`, the host is not matched (add `FABRIC_WIRE_ENDPOINTS`), or the path is not one of the five supported APIs. |
| `queue_full` losses | Burst larger than the capture queue, CPU-bound threads starving the capture worker (see Throughput), or a full spool: raise `FABRIC_WIRE_QUEUE_MAX_ITEMS` or `FABRIC_WIRE_SPOOL_MAX_BYTES`. |
| `disk_full` losses | The spool's volume filled before its bound; grow the volume. |
| Agent batches refused with `INVALID_ARGUMENT` | The agent's tenant or `fabric.source_id` does not match the Node's binding; compare the `s-` value on the agent's spans with the Node's configured source id. |
| `flush()` returns `False` | Something was not delivered in time, the spool barrier is not established, or another process's records were quarantined. |
| Multiprocessing workers' calls missing | The pool was ended by `with Pool():` (SIGTERM); use `close()`/`join()` (see Multiprocessing). |

**Finding a run by its clear id.** Records carry only pseudonyms. Pass the
clear run id to `fabric.reconstruct --run` with the agent's
`FABRIC_WIRE_ID_KEY` in the environment. To compute a pseudonym yourself
(`r-` run, `s-` source, `svc-` service, `t-` tenant) without putting the key
on a command line:

```bash
python3 - s- billing-agent <<'PY'
import hashlib, hmac, os, sys
prefix, value = sys.argv[1], sys.argv[2].encode("utf-8")
key = os.environ.get("FABRIC_WIRE_ID_KEY", "").encode("utf-8")
digest = hmac.new(key, value, hashlib.sha256) if key else hashlib.sha256(value)
print(prefix + digest.hexdigest()[:32])
PY
```

## Upgrade and migration

- Upgrade every process that shares a spool together.
- Upgrading the Node to v0.8 requires the P0-A settings (source id, and
  with content the content key); agents in node mode need a capture policy,
  `FABRIC_WIRE_ID_KEY` and `FABRIC_WIRE_SPOOL_KEY`. See
  [deployment](../deployment.md#upgrading-from-earlier-releases).
- Losing the Node content key loses queued and file-stored content. Rotate
  it only with an empty content queue. Rotating the id key changes every
  pseudonym from that point on.
- Pin the Node image by digest and [verify the release](../verify-release.md)
  before promoting it.
