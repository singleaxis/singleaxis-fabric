# fabric-host-emitter

Passive CO-RE eBPF host sensor for SingleAxis Fabric (spec `031-ebpf-host-emitter`).

Observes `execve`, `connect`, and (optionally) `openat` inside a configured
cgroup scope and exports them to a Fabric Node as `event_class=audit` log
records — the same schema the auditd receiver emits, so downstream consumers
see one shape regardless of collection mechanism.

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
| `EMIT_ENDPOINT` | `localhost:4317` | OTLP/gRPC of the Fabric Node |
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

This does not prove a complete agent transcript. The host sensor sees only its
enabled, scoped tracepoints and metadata, not command output, file contents,
SSH remote actions, database queries, or model context. The kernel loss map
is volatile until a loss record is queued, and activity while the sensor is
down is unobservable. These gaps must be reconciled against independent
sources before any run-level completeness claim.

## Build

```sh
docker build -t fabric-host-emitter:local .
```

The builder compiles `bpf/emit.bpf.c` with clang via `bpf2go` against the
vendored `bpf/vmlinux.h` (CO-RE), then links the emitter. `vmlinux.h` is
extracted from a 6.12 linuxkit kernel — CO-RE handles drift across kernels
that ship BTF.

## Test

```sh
go test ./...              # unit: translation, argv-hash, dedupe, config
bash e2e-emitter.sh        # live: loads real BPF objects, cross-container exec/connect
```

The e2e runs the emitter privileged on a Linux-capable Docker engine
(Docker Desktop's VM has BTF), generates a marker exec in a *different*
container, and asserts it surfaces as an audit record at the node.

## Deploy

`deploy/kubernetes/host-emitter-daemonset.yaml` — a DaemonSet with the
minimal cap set, read-only root fs, and no privilege escalation.
