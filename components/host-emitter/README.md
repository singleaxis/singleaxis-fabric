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
- `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_RESOURCE` + `CAP_DAC_READ_SEARCH`,
  or `--privileged`
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
| `EMIT_MAX_EVENTS_PER_SEC` | `500` | token-bucket cap |
| `EMIT_DEDUPE_WINDOW` | `1s` | collapse repeats into `fabric.event_count` |
| `EMIT_BEARER_TOKEN_FILE` | — | token for the node's bearertokenauth |

The emitter **refuses to start** with neither `EMIT_CGROUP_PATH` nor
`EMIT_ALL_HOST=true` — silent host-wide collection is a bug, not a default.

## Data minimization

- `argv` is read from `mm->arg_start` in-kernel but only its SHA-256 leaves
  the host (`process.command_args_sha256`) — raw command lines never cross.
- No raw payload or file content is collected — paths, addrs, ports, pids,
  argv-hash only.
- Dedupe collapses repeat bursts into `fabric.event_count` counts so a
  fork-bomb can't flood the node.

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
