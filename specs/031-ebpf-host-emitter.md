---
title: eBPF Host Emitter (fabric-host-emitter)
status: implemented-not-enterprise-qualified
revision: 2
last_updated: 2026-09-26
owner: project-lead
---

# Spec 031 — eBPF Host Emitter

**Depends on:** spec 030 (auditd host connector — shared attribute schema and
allowlist), spec 027 (recorder-v1 scope), `contracts/connect/v1`.

## Problem

auditd consumption covers the syscall layer only where auditd exists and its
ruleset cooperates. It misses: hosts with no auditd (minimal container
images), container-scoped filtering (auditd rules are host-wide), high event
rates (text-pipeline serialization). The eBPF emitter provides a separate
collection path for the three configured tracepoints below inside an explicit
cgroup scope. It does not cover every syscall, io_uring operation, or other
bypass path, and does not establish complete observation of an agent.

## What we are building

A **separate privileged emitter** (`fabric-host-emitter`) — a small static Go
binary, shipped as its own image + DaemonSet manifest — that loads CO-RE eBPF
tracepoint programs, translates kernel events into the same `event_class=audit`
log-record schema as spec 030, and OTLP-exports them to the Fabric Node.

Separate artifact (unlike spec 030's in-collector receiver) because it carries
a different privilege posture, kernel dependency chain, and release risk —
keeping it out of the collector image keeps the node's attack surface and
image size unchanged for deployments that don't need host monitoring.

```text
kernel tracepoints ──► perf/ringbuf ──► fabric-host-emitter (DaemonSet)
   sched_process_exec, sys_enter_connect, sys_enter_openat
                                              │
                                  cgroup-scoped filter (in-kernel)
                                              │  bounded fsynced source spool
                                              │  OTLP logs (bearer auth)
                                              ▼
                                        Fabric Node → queue → export
```

## Programs (v0.1 — tracepoints only, stable ABI, no enforcement)

| Hook | Captures | Record |
|---|---|---|
| `sched/sched_process_exec` | pid, ppid, filename, comm | exec event |
| `syscalls/sys_enter_connect` | pid, sockaddr (inet host:port) | connect event |
| `syscalls/sys_enter_openat` | pid, filename | file event — **config-gated off by default** |

Deliberately **not** used: LSM hooks, packet drops, kprobe-fiddled paths —
the emitter is read-only by construction (passive promise; smallest blast
radius).

## Attributes (shared schema with spec 030)

`event_class=audit`, `audit.syscall` (exec/connect/openat), `audit.result`
(limited — tracepoints expose args, not always retval), `process.pid`,
`process.parent_pid`, `process.executable.name`,
`process.executable.path_sha256`, `process.command_args_sha256` (argv read
from task memory, hashed at collection — never raw),
`network.peer.address/port`, `file.path_sha256` (openat only),
`audit.source=ebpf`, `log.record.uid`, and `fabric.event_count`.
When BPF buffers cannot hold a complete argv or path, the hash is omitted
and an incomplete-field event is emitted; a prefix is not presented as the
full value.

## The eBPF-only capability: in-kernel cgroup scoping

`EMIT_CGROUP_PATH` takes a cgroup path, resolved to its inode ID; the BPF program calls
`bpf_get_current_cgroup_id()` and drops events outside the target cgroup
**in-kernel**, before they surface. On multi-tenant hosts this is the
difference between an approved deployment and a rejected one — the sensor
matches that exact configured cgroup ID; descendants require separate
qualification. `EMIT_ALL_HOST=true` is an explicit opt-in.

## Safety controls

- Collection-side argv scrub (sha256 only) — same rule as spec 030.
- A bounded mode-0700 disk spool, fsync-before-acknowledgement, asynchronous
  OTLP retry and restart replay. The queue is at-least-once; `log.record.uid`
  is stable across replay for downstream deduplication.
- `max_events_per_sec` and `dedupe_window` default off for per-event fidelity;
  enabling them intentionally reduces completeness. Ring-buffer and rate
  losses emit counted status events after observation, not missing records.
- Graceful degradation: missing BTF, denied caps, or verifier rejection →
  clear startup error listing the exact requirement; never partial-silent
  operation.
- Privilege: scoped `CAP_BPF`+`CAP_PERFMON` (kernel ≥5.8); no production
  `--privileged` fallback is qualified;
  `hostPID: true` for process correlation; read-only mounts for
  `/sys/kernel/btf`, `/sys/fs/cgroup`, `/sys/kernel/debug`.

## Deliverables

- `components/host-emitter/` — Go module: bpf2go CO-RE programs
  (`bpf/emit.bpf.c`), loader, translator, OTLP exporter client, dedupe,
  cgroup resolver; `//go:build linux` for BPF loading, darwin stub for dev
- `components/host-emitter/Dockerfile` — pinned builder compiles the BPF
  object (clang+bpftool in-builder), distroless runtime ships emitter only
- `deploy/kubernetes/host-emitter-daemonset.yaml` — fail-closed qualification
  template with pinned-digest placeholder, scoped cgroup placeholder,
  credential Secret and pre-provisioned persistent spool mount
- `contracts/connect/v1/manifests/` — convert `ebpf-discovery-only.json` from
  illustrative to the real emitter manifest (honest blind spots preserved +
  privilege posture); digest repin
- `scripts/release/release-policy.json` + boundary tests — new artifact
  registered (`fabric-host-emitter` image), with privilege posture declared

## Honest limits (manifest blind spots)

- Kernel ≥ 5.8 with BTF for CO-RE; unsupported kernels are rejected, not
  silently downgraded.
- No semantic/decision layer — same inference caveat as spec 030.
- Encrypted traffic: metadata only (peer and timing) — never content.
- Attribution to a logical "agent" is deployment-dependent (cgroup or PID
  namespace mapping); record the method as provenance.
- An adversarial workload with kernel-level access is outside this threat
  model — the emitter observes the host it runs on.
- The current emitter defaults to TLS and can use client certificates or
  bearer authentication. Local spool/retry/race tests pass, but Linux BPF
  build/live kernel-loss, exact-artifact outage/restart, encrypted-volume,
  workload-scoping and independent host-truth tests have not passed here.
  The sample DaemonSet intentionally cannot deploy unchanged. Neither
  source fsync nor OTLP acceptance is a destination durable receipt, and
  no complete-host-capture claim is qualified.
