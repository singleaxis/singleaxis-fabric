# fabric-host-emitter

Passive CO-RE eBPF host sensor for SingleAxis Fabric (spec `031-ebpf-host-emitter`).

Observes `execve`, `connect`, and (optionally) `openat` inside a configured
cgroup scope and exports them to a Fabric Node. Local mode (the default)
exports `event_class=audit` log records — the same schema the auditd receiver
emits, so downstream consumers see one shape regardless of collection
mechanism. Production mode (`EMIT_PRODUCTION=true`, spec 053 §6.2.9 and spec
056 §7.3.3 (c)) exports host records as traces through the host-records
library; see [Production mode](#production-mode).

It is read-only by construction: tracepoints only. No LSM hooks, no packet
interception, no enforcement — it cannot block or delay the workload.

## Why this exists

The in-process SDKs capture semantic intent (decisions, tool calls). They
cannot see what the agent's runtime actually did on the machine — a
`run_command` tool that SSHs a prod DB or curls an external host is invisible
to the SDK until the syscall layer reports it. This emitter is that layer for
hosts where auditd isn't present or cgroup-scoped filtering is required.
Prefer the auditd connector first on hosts that already run it — it's lower
privilege and already approved.

## Requirements

- Linux kernel >= 5.8 with `CONFIG_DEBUG_INFO_BTF` (CO-RE relocations)
- `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_RESOURCE` + `CAP_DAC_READ_SEARCH`;
  a production `--privileged` fallback is not qualified
- Read-only mounts: `/sys/kernel/btf`, `/sys/kernel/tracing`,
  `/sys/kernel/debug`, `/sys/fs/cgroup`
- `hostPID: true` for cross-container process correlation

## Configuration (env)

| Var | Default | Notes |
|-----|---------|-------|
| `EMIT_ENDPOINT` | `localhost:4317` (local mode) | OTLP/gRPC of the Fabric Node |
| `EMIT_ENDPOINT_FILE` | — | file holding one line `host:port`; an alternative to `EMIT_ENDPOINT` (setting both is refused) |
| `EMIT_CGROUP_PATH` | — | cgroup dir to scope observation to |
| `EMIT_ALL_HOST` | `false` | explicit opt-in to unscoped collection |
| `EMIT_EXEC` | `true` | sched_process_exec tracepoint |
| `EMIT_CONNECT` | `true` | sys_enter_connect tracepoint |
| `EMIT_FILE_ACCESS` | `false` | sys_enter_openat — host-scale volume, keep off unless scoped |
| `EMIT_MAX_EVENTS_PER_SEC` | `0` | optional token-bucket cap; `0` disables deliberate rate loss |
| `EMIT_DEDUPE_WINDOW` | `0s` | optional repeat collapse; `0s` preserves individual observed events |
| `EMIT_SPOOL_DIR` | `/var/lib/fabric-host-emitter` | required pre-existing persistent directory, owned by emitter UID and mode `0700` |
| `EMIT_SPOOL_MAX_BYTES` | `1073741824` | bounded durable queue capacity in bytes; full queue terminates emitter visibly |
| `EMIT_BEARER_TOKEN_FILE` | — | token for the node's bearertokenauth |
| `EMIT_INSECURE` | `false` | explicit plaintext opt-in for local tests only; incompatible with a bearer token |
| `EMIT_TLS_CA_FILE` | system roots | PEM CA bundle for the Node server certificate |
| `EMIT_TLS_CERT_FILE` / `EMIT_TLS_KEY_FILE` | — | client certificate and key for mTLS; must be supplied together |

The default transport is TLS. Production deployments must configure a trusted
Node certificate and, when required by the Node ingress, a client certificate
and key. `EMIT_INSECURE=true` is only for an isolated development receiver.
The sample DaemonSet is not a production-ready install: its image digest and
cgroup scope are deliberately unusable, and its credential Secret must be
provisioned by the operator.

The emitter **refuses to start** with neither `EMIT_CGROUP_PATH` nor
`EMIT_ALL_HOST=true` — silent host-wide collection is a bug, not a default.
It also refuses to start without a safe writable spool directory; there is
no volatile-memory fallback. Production deployments must mount a persistent,
encrypted volume at `EMIT_SPOOL_DIR`, provision mode `0700` and emitter UID
ownership, size it for the longest receiver outage, and alert on emitter exit
and the logged `queued_batches`, `queued_bytes`, and `high_water_bytes` signals.

## Data minimization

- `argv` is read from `mm->arg_start` in-kernel but only its SHA-256 leaves
  the host (`process.command_args_sha256`) when the complete value fits the
  bounded BPF buffer. Longer or unreadable argv produces
  `audit.event=command_args_incomplete` instead of a misleading full-value
  hash; raw command lines never cross.
- Executable and file paths are SHA-256 digests before the local spool or OTLP
  export (`process.executable.path_sha256`, `file.path_sha256`). Raw paths are
  transient inside the sensor but never persist or cross the boundary. Paths
  too long for the BPF buffer or unreadable by the probe are marked
  `audit.event=path_incomplete` (or
  `path_and_command_args_incomplete` when argv is also incomplete), not
  misrepresented as full-value hashes.
- No raw payload or file content is collected — path digests, addresses, ports,
  pids, and argv hash only.
- Optional dedupe collapses repeat bursts into `fabric.event_count` repeat
  counts; it is disabled by default because collapsing destroys per-event
  timing and identity even when the count is retained.
- BPF ring-buffer reservation failures and optional rate-limit omissions emit
  `audit.event=capture_loss` records with a closed reason in `audit.loss_reason` and
  count in `fabric.event_count`. Any such record means capture is incomplete.

## Delivery and completeness limits

The sender persists minimized OTLP batches to disk before export and retries
receiver outages asynchronously. Committed batches are replayed after an
emitter restart. Each committed record receives a stable `log.record.uid` so
downstream systems can deduplicate retries. This is source identity, **not** a
destination durability receipt or proof of a complete run. Delivery is **at
least once**: a receiver may accept a batch just before the emitter crashes,
causing replay and a duplicate. A full or
unwritable spool is a fatal health event, not a silent drop. Unexpected or
incomplete temporary spool files stop startup for operator investigation.
An OTLP `PartialSuccess` response is not retried: the original batch is
durably renamed to a `.partial` quarantine with the rejected-record count,
retained across restart and included in spool capacity/health. The receiver
does not identify which records were rejected, so the quarantined batch
cannot establish per-record delivery or a complete run. Its local count is
not a destination receipt. Operators must investigate and reconcile it; the
emitter never silently deletes or replays it.

Wall time: the kernel stamps events with `CLOCK_MONOTONIC`; the emitter adds
`CLOCK_REALTIME − CLOCK_MONOTONIC`, re-sampled (nanosecond precision) at least
every 250 ms and before translating events, so a wall-clock step (an NTP
step, a VM resync such as Docker Desktop's after the host sleeps, `date -s`)
is followed within one batch. A change of that offset beyond 1 ms plus
500 ppm of the elapsed time is a detected step: it is logged
(`CLOCK_REALTIME step detected step_ms=…`), counted (`clock_steps=` on the
health line), and in production mode the source stages a manifest whose
`clock.uncertainty_ns` is 2 ms plus the largest step, since events captured
just before the step and translated after it may be off by that much. A
verifier then widens the windows of that source's events accordingly.

This does not prove a complete agent transcript. The host sensor sees only its
enabled, scoped tracepoints and metadata, not command output, file contents,
SSH remote actions, database queries, or model context. The kernel loss map
is volatile until a loss record is queued, and activity while the sensor is
down is unobservable. These gaps must be reconciled against independent
sources before any run-level completeness claim.

## Production mode

`EMIT_PRODUCTION=true` turns every observed event into a host record
(`fabric.sensor_event`, 053 §6.2.3) of one host source, staged and sealed by
the host-records library (`components/otel-collector-fabric/hostrecords`)
before it is first sent, and exported as OTLP/gRPC traces to the source's
own ingress group on the Node. Local mode is unchanged.

| Var | Default | Notes |
|-----|---------|-------|
| `EMIT_PRODUCTION` | `false` | `true` or `false`; any other value refuses start |
| `EMIT_TENANT_ID`, `EMIT_SOURCE_LABEL`, `EMIT_HOST_LABEL` | — | required. The source id is the `s-` label pseudonym of the source label (`<node>/ebpf`); the host label is the agents' `FABRIC_HOST_LABEL` |
| `EMIT_ID_KEY_FILE` | — | required; the agents' `FABRIC_WIRE_ID_KEY` bytes exactly (mode 0400/0440, no trailing newline: write it with `printf %s`) |
| `EMIT_STATE_KEY_FILE` | — | required; 32 raw bytes or their base64 (mode 0400/0440); seals `epoch.state` and every staged batch |
| `EMIT_STATE_DIR` | — | required; mode 0700, owned by the emitter, used by no other sensor. `EMIT_SPOOL_DIR` is not used |
| `EMIT_AGENT_CGROUP_ROOTS` | — | comma-separated cgroup v2 directories (at most 8, each existing at start); each and its descendants are scope `agent` |
| `EMIT_AGENT_POD_SELECTOR`, `EMIT_NODE_NAME` | — | Kubernetes: `key=value[,key=value]` and `spec.nodeName`. The emitter lists and watches this node's matching pods over HTTPS with the mounted service-account token (read-only `get`, `list`, `watch` on `pods`) and installs each pod's slice as an agent root when it appears (at most 64). The grant is cluster-wide (RBAC cannot scope a read to one node): the token can read every pod object, inline env values included |
| `EMIT_SANDBOX_CGROUP_ROOTS` | — | comma-separated cgroup v2 directories (at most 8); descendants are scope `sandbox` and carry container and pod ids |
| `EMIT_ALL_HOST` | `false` | every event outside a sandbox root is scope `agent` |
| `EMIT_DIGESTS` | `omitted` | `permitted` emits executable, argv and path digests (the Node's group must permit them too) |
| `EMIT_HEARTBEAT_INTERVAL` | `10s` | 1s to 60s |

Production refuses `EMIT_CGROUP_PATH` (an exact cgroup cannot scope a pod;
use `EMIT_AGENT_CGROUP_ROOTS`), a non-zero `EMIT_DEDUPE_WINDOW` (every event
keeps its own position), `EMIT_INSECURE=true` to a non-loopback endpoint,
and a start with no agent root, no pod selector and no `EMIT_ALL_HOST`.
There is no default endpoint in production.

`fabric-host-emitter print-source-id` prints the `s-` source id of
`EMIT_SOURCE_LABEL` under `EMIT_ID_KEY_FILE` and exits; the operator puts it
in the Node's group as `sourceId`.

**Scope.** The BPF program keeps every root in one map (cgroup id to scope,
at most 256 entries) and walks the task's cgroup ancestors from level 1 down
to its own cgroup; the deepest root that contains it decides the scope.
Events under no root are not emitted. A pod root installed after a container
other than the pod's sandbox container already exists in its slice (or after
the API server lists one of its containers as created) may have missed
events: the next heartbeat reports upstream loss `scope_late` with an
unknown count. API-server errors are retried with backoff and counted in the
health line; they never remove a root already installed.

**Records.** Each record carries the init-namespace `pid` and `ppid` (thread
group ids), the process as numbered in its own pid namespace (`ns_pid`), the
parent's thread-group id in that namespace (`ns_ppid`, 0 when the parent is
outside it, never the spawning thread's id), the namespace inode (`pid_ns`),
the group leader's unrounded `start_boottime` (`process_start_ns`), the
cgroup id and the scope. Sandbox-scope events also carry
`fabric.execution.sandbox_id` and `fabric.sensor.pod_id`, derived from the
kernfs names of the event's cgroup and its parent, which the BPF program
reads at event time, so a container removed right after its exec keeps its
ids. Every id is keyed by the library; no executable name, raw path, argv or
peer address leaves the host. `connect` and `openat` are observed at syscall
entry, so their result is `unknown`.

**Delivery and loss.** Every record and marker (manifest, heartbeat, loss,
final) is a sealed, staged batch until the Node accepts it in full, and is
replayed after a restart with the same positions and event ids. Ring-buffer
and rate-limit drops are upstream loss on the next heartbeat (one heartbeat
span per reason). An OTLP partial success quarantines the batch, still
sealed, and declares its positions `span_dropped`. At shutdown the emitter
stages the final marker and tries for 5 s to deliver what is pending; what
remains is replayed by the next epoch.

## Build

The build context is `components/`, because the emitter links the
host-records library:

```sh
docker build -f components/host-emitter/Dockerfile -t fabric-host-emitter:local components
```

`Dockerfile.dockerignore` limits that context to the emitter's sources and
the library's non-test sources; the library's replay command is not built.

The builder compiles `bpf/emit.bpf.c` with clang via `bpf2go` against the
vendored `bpf/vmlinux.h` (CO-RE), then links the emitter. `vmlinux.h` is
historically described as extracted from a 6.12 linuxkit kernel. The original
source BTF digest, generator version and extraction command are unavailable,
so this provenance is unverified. `bpf/vmlinux.provenance.json` records the
SHA-256 of the unchanged checked-in header, not a source BTF attestation.
CO-RE relocation still requires qualification on each target kernel.

## Test

```sh
go test ./...                       # unit: translation, config, spool, production pipeline, pod watcher
bash e2e-emitter.sh                 # live: loads real BPF objects, cross-container exec/connect
bash e2e-emitter.sh --production    # live, privileged: production scope roots and pid numbering
```

`--production` builds the image's builder stage and runs the `e2e`-tagged Go
tests in a privileged container in the host's pid namespace and cgroup v2
hierarchy: namespace pids against `/proc` (a child spawned from a second
thread), a pod-shaped agent root, and a short-lived sandbox container's id.

The e2e runs the emitter privileged on a Linux-capable Docker engine
(Docker Desktop's VM has BTF), generates a marker exec in a *different*
container, and asserts it surfaces as an audit record at the node.

## Deploy

`deploy/kubernetes/host-emitter-daemonset.yaml` — a DaemonSet with the
minimal cap set, read-only root fs, and no privilege escalation.
