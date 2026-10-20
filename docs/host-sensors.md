# Host sensors

Fabric ships two optional Linux host sensors. They record **metadata** about
process starts, network connections and (opt-in) file opens on the machine
where an agent runs. They never record payloads, never block or delay a
workload, and are **corroboration only**: a host record says that something
happened near an agent's activity, not that it belongs to it.

| | auditd receiver | eBPF host emitter |
|---|---|---|
| Ships as | The `audit` receiver compiled into the Fabric Node image (`components/otel-collector-fabric/receiver/auditreceiver`) | A separate image, `ghcr.io/singleaxis/fabric-host-emitter` (`components/host-emitter`) |
| Source | Linux audit subsystem: netlink multicast (live) or `audit.log` (tailed, with a durable cursor) | CO-RE eBPF tracepoints: `sched_process_exec`, `sys_enter_connect`, `sys_enter_openat` |
| Output | `event_class=audit` OTLP log records inside the Node | `event_class=audit` OTLP/gRPC log records sent to a Node, through a local fsync'd disk spool |
| Spec | [030](../specs/030-auditd-host-connector.md), status implemented, not enterprise-qualified | [031](../specs/031-ebpf-host-emitter.md), status implemented, not enterprise-qualified |
| Platform | Linux, native amd64/arm64 syscall numbers (no 32-bit compat ABIs) | Linux ≥ 5.8 with BTF |

Prefer the auditd receiver on hosts that already run auditd; it needs fewer
privileges.

## What a record contains

Both sensors emit the same schema (`translate.go` in the receiver,
`emitter.go` in the emitter):

- `audit.syscall`, `audit.source` (`netlink`, `logfile` or `ebpf`),
  `audit.result` (`success` or `failed:<ERRNO>`);
- `process.pid`, `process.parent_pid`, `process.executable.name`,
  `process.owner` (audit uid);
- `process.executable.path_sha256` and `process.command_args_sha256`:
  the executable path and argv are **hashed, never emitted raw**;
- `network.peer.address` and `network.peer.port` for connections, **in
  clear**;
- `file.path_sha256` for file access (the receiver refuses
  `hash_file_paths: false` together with `file_access`).

Status records report loss and degradation: `rate_limited`,
`delivery_queue_overflow`, `assembly_evicted`, `command_args_incomplete`,
logfile rotation, truncation and source-loss markers (receiver); and
`capture_loss` with `ring_buffer_full` or `rate_limited` (emitter).

Joining a host record to an agent's model calls is investigative (pid, host
and time), not causal.

## auditd receiver

Configure it as a receiver in a Node's collector configuration
([`deploy/auditd/README.md`](../deploy/auditd/README.md) has full examples
and the supplied `fabric.rules`):

```yaml
receivers:
  audit:
    source: netlink          # or: logfile
    rule_key: fabric         # only events tagged -k fabric
    # logfile mode:
    # log_path: /var/log/audit/audit.log
    # state_directory: /var/lib/fabric/audit   # required, persistent, 0700
```

- `netlink` needs `CAP_AUDIT_READ` and is live only: what the Node misses
  while it is down is not replayed.
- `logfile` keeps a durable cursor and a scrubbed replay batch, delivers at
  least once with a stable `fabric.record_id`, and marks rotation,
  truncation and source loss explicitly. Its state is integrity-checked but
  not encrypted.
- `manage_rules: true` (needs `CAP_AUDIT_CONTROL`) installs Fabric's rules
  when no auditd daemon holds the audit socket; it never overrides a live
  daemon.
- Defaults: `exec` and `connect` on, `file_access` off,
  `max_events_per_sec` 200, `dedupe_window` 1 s (netlink only).

## eBPF host emitter

Configured entirely by environment variables
([`components/host-emitter/README.md`](../components/host-emitter/README.md)):
`EMIT_ENDPOINT` (Node OTLP/gRPC, default `localhost:4317`, TLS by default),
`EMIT_CGROUP_PATH` or `EMIT_ALL_HOST=true` (it refuses to start with
neither), `EMIT_EXEC`/`EMIT_CONNECT` (on), `EMIT_FILE_ACCESS` (off),
`EMIT_SPOOL_DIR` and `EMIT_SPOOL_MAX_BYTES` (1 GiB; a full spool stops the
emitter visibly), `EMIT_BEARER_TOKEN_FILE`, and TLS/mTLS file variables.

It runs as root with all capabilities dropped except `BPF`, `PERFMON`,
`SYS_RESOURCE` and `DAC_READ_SEARCH`, with `hostPID: true` and read-only
mounts of BTF, tracefs, debugfs and cgroupfs.
[`deploy/kubernetes/host-emitter-daemonset.yaml`](../deploy/kubernetes/host-emitter-daemonset.yaml)
is a qualification template, not an install: its image digest and cgroup
scope are deliberately unusable until you set them.

## Limits in v0.8

- **Not accepted by a production Node.** `fabric-gate` refuses any receiver
  other than `otlp` and `otlp/content` in the production profile, so the
  `audit` receiver cannot run there; and a source-bound `fabricguard` logs
  pipeline accepts only `event_class=evidence` records, so audit records
  sent by the emitter are refused. Run host sensors against a separate,
  local-profile Node.
- **Not in the Helm chart or Compose.** There are no chart values or Compose
  overlays for either sensor.
- **No run identity.** Host records carry no `fabric.run.*` or source-epoch
  identity that `fabric.reconstruct` reads; reconstruct ignores them. The
  auditd logfile mode carries `audit.source_id` and `audit.source_generation`;
  netlink mode and the emitter carry no source identity.
- **Not enterprise-qualified.** The live kernel, Linux BPF build, outage and
  restart, and host-truth tests listed in specs 030 and 031 have not been
  run as a qualification; CI builds and unit-tests both sensors only.
- `fabric.event_count` on a `dedupe_collapsed` record counts all events in
  the auditd receiver but only the suppressed repeats in the emitter.
