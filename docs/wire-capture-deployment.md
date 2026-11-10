# Deploying LLM wire capture (moved)

> **Status:** a redirect page. Its redaction-service section describes built
> code, released in v0.8.0:
> [`fabric/redaction.py`](../sdk/python/src/fabric/redaction.py) and the
> reference service in
> [`examples/redaction-service/`](../examples/redaction-service/).

This page moved. Configuration files and scripts in `deploy/compose` still
point here.

- Agent and Node configuration: [deployment](deployment.md); spool disk
  requirements (`fsync` latency, file locks):
  [deployment](deployment.md#what-the-agent-needs) ("Spool disk").
- Content canary and verifying a run (formerly section 5):
  [operations](operations/README.md#verify-a-deployment) and
  [reconstruct](reconstruct.md).
- Encryption and source authentication:
  [privacy and security](privacy-and-security.md).

## Redaction service

The redaction-service setup (`FABRIC_REDACTION_ENDPOINT`,
`FABRIC_REDACTION_TOKEN_FILE`, transformations, bounds and failure
behaviour) is in
[privacy and security](privacy-and-security.md#redaction-service). Error
messages from the SDKs point to this anchor.

## Delivery rate and short-lived workers

Each capturing process delivers its spool on one sender thread. It reads the
pending records, sends their bodies to the Node several to a request
(`FABRIC_WIRE_CONTENT_BATCH_BODIES`, default 32, at most 256 bodies and
about 4 MiB per request) with a few requests in flight
(`FABRIC_WIRE_CONTENT_CONCURRENCY`, default 4, at most 16), then exports the
spans of the records whose bodies were all accepted. A record's span is never
exported before its bodies, and a body the Node accepted is not sent again.
The Node writes the records of one request up to `write_concurrency` at a
time (`fabriccontent` exporter setting, default 8, at most 64).

Measured on one machine with a sealed, fsync'd Node content queue and file
store, and 2 KB to 3 KB bodies. Each figure is model exchanges delivered and
stored per second:

| setup | before (one body per request, serial) | now |
|---|---|---|
| sender alone, 50 ms round trip | 9 per process | 750 per process |
| Node on Linux (Docker), 50 ms round trip, 1 process | 9 | 310 at the agent, 237 stored |
| same, 3 processes | 9 each, 26 stored | 120 each, 231 stored |
| Node on a disk with slow fsync, 3 processes | 4.3 each, 12 stored | 32 each, 64 stored |

The last row matches what the field harness measured against a hosted
Node (4.3 per process, about 13 in total). The Node's storage is then the
limit. Its content queue absorbs bursts, and agents finish delivering long
before the store catches up. A process that captures faster than it
delivers builds a spool backlog. Size the Node's storage for the aggregate
rate, or use the S3 backend.

**At exit**, a process waits only for its exit budget
(`FABRIC_WIRE_SHUTDOWN_TIMEOUT_S`, 2 s by default). Capture never delays the
monitored program beyond that unless you ask it to. Records still in the
spool stay on disk, and the next process that captures to or drains the same
spool delivers them. If no next process comes (a serverless function, a batch
job, an autoscaled worker that is scaled down, a container whose disk is
discarded), the backlog is never delivered. The reader then reports the
missing sequence numbers and the run as `partial`.

Fabric makes that case visible. When a process exits with records left and
no other live process is draining the spool, it writes a note into the spool
directory and logs a diagnostic on Fabric's own logger. Like every Fabric
diagnostic, that log goes to stderr only with `FABRIC_WIRE_DIAGNOSTICS=stderr`.
`python -m fabric.wire status`, run with the agent's environment, reports
`wire.spool.records` (records waiting now) and `wire.spool.left_at_exit`
(how many records the last such exit left, and when), plus a warning that
says what to do. A drainer that empties the spool removes the note.

Choose one of these for workers that do not come back:

- **Drain on exit (opt-in).** `FABRIC_WIRE_DRAIN_ON_EXIT_S=SECONDS` (at most
  3600) lets the process wait up to that much longer at exit, on top of the
  exit budget, until its spool is delivered. It returns as soon as the spool
  is delivered. This delays the program's exit, so set it only where that is
  acceptable, such as a batch job or a serverless function with time left.
- **Drain as the last step.** Run
  `python -m fabric.wire drain --until-empty` after the agent (below).
- **Durable shared spool with a drainer.** Put `FABRIC_WIRE_SPOOL_DIR` on
  storage that outlives the worker (a PersistentVolumeClaim, a shared volume)
  and run the drainer as a sidecar or a separate long-lived process.

## Draining a spool with no agent running

An agent delivers its spool's backlog only while it runs. At exit it waits
only for its exit budget (`FABRIC_WIRE_SHUTDOWN_TIMEOUT_S`, 2 s by default,
plus `FABRIC_WIRE_DRAIN_ON_EXIT_S` if you set it), so after a Node or
destination outage, thousands of records can be left on the spool volume. A
later agent process on the same volume delivers them. If none comes, as with
a one-shot container or a scaled-down job, run the drainer:

```text
python -m fabric.wire drain [--spool DIR] [--until-empty] [--timeout SECONDS]
```

- It reads the agent's own environment (`FABRIC_WIRE_*`,
  `OTEL_EXPORTER_OTLP_*`, the spool key) and delivers as the agent would:
  bodies to the Node, then spans. A record is deleted only after every part
  was accepted. As the spool's lock holder it also exports dead processes'
  loss-ledger slots and declares their orphaned epochs. It installs no
  capture and writes no epoch of its own, even when the environment sets
  `FABRIC_WIRE_AUTOLOAD=1`.
- While a live process holds the spool lock, the drainer waits, and it takes
  over when the lock is released. Two drainers never deliver the same
  record.
- `--until-empty` returns when nothing deliverable is left (exit 0) or at
  `--timeout` with records still on disk (exit 1; they stay for the next
  drainer or agent). Without it the drainer runs until SIGTERM or SIGINT,
  then makes a final drain attempt of up to 10 s. Exit 2 means a usage or
  configuration error. stdout gets one JSON summary line: `drained`,
  `delivered`, `remaining`, `undecryptable` (records sealed under another
  spool key, left on disk), `quarantined` and `seconds`.

Where to run it:

- **One-shot container.** Make it the container's last step, in the same
  container or a second one on the same volume:
  `python agent.py; python -m fabric.wire drain --until-empty --timeout 300`.
  The agent's own exit code is the job's result; the drainer's exit 1 only
  means records wait on the volume.
- **Kubernetes sidecar.** Run `python -m fabric.wire drain` (no
  `--until-empty`) as a native sidecar (an init container with
  `restartPolicy: Always`) that mounts the agent's spool volume and env.
  Kubernetes stops it after the agent container exits, so its final drain
  runs with the spool lock free. Set `terminationGracePeriodSeconds` at least
  15 s above the agent's own shutdown time. The spool must be on a volume
  that outlives the pod (a PersistentVolumeClaim) when a drain can stop
  early, for example when the Node is down. An `emptyDir` spool is deleted
  with the pod.
- **preStop hook.** `python -m fabric.wire drain --until-empty --timeout 20`
  in the agent container's `preStop` delivers the backlog before SIGTERM.
  The agent is still running then and holds the lock, so the hook mostly
  waits for the agent's own sender. Prefer the sidecar.
