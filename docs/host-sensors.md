# Host sensors

> **Status:** describes built code. Local mode is released in v0.8.0;
> [production mode](#production-mode) (a production Node's host ingress,
> [spec 053](../specs/053-execution-channels-p4.md) §6.2, built for spec 056
> milestone M2) is released in v0.11.0. Implementation:
> [`auditreceiver/`](../components/otel-collector-fabric/receiver/auditreceiver/),
> [`components/host-emitter/`](../components/host-emitter/) and the
> host-records library
> [`hostrecords/`](../components/otel-collector-fabric/hostrecords/). The
> join of host events to agent effects
> ([spec 056](../specs/056-agent-action-reconstruction.md) §4.3) is released
> in v0.10.0, for the local profile
> ([`reconstruct/_host.py`](../sdk/python/src/fabric/reconstruct/_host.py))
> and read with `python -m fabric.reconstruct actions --host-records`; see
> [agent action reconstruction](action-reconstruction.md).

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

## Production mode

[Production setup](production-setup.md) is a complete recipe for the eBPF
emitter in production mode beside an agent and a Node, including its
`docker run` flags and the cgroup scope on either Docker cgroup driver.

Released in v0.11.0 (spec 056 milestone M2). A production-profile Node
admits a host sensor through a dedicated ingress group of its own: one
`host.ebpf` (or `host.auditd`) group per sensor process, each binding one
source id and one token on its own TLS listener, guarded by a
`fabricguard/<group>` with `source_kind` set (spec 053 §6.1, §6.2.6). The
records are spans with their own source identity, positions, heartbeats and
a manifest, and carry the process start time and pid namespace, so the
verifier links effects with rule H1 (`certain`).

The emitter selects it with `EMIT_PRODUCTION=true` and then needs
`EMIT_TENANT_ID`, `EMIT_SOURCE_LABEL`, `EMIT_HOST_LABEL` (the agents'
`FABRIC_HOST_LABEL`), `EMIT_ID_KEY_FILE`, `EMIT_STATE_KEY_FILE` and
`EMIT_STATE_DIR`. Scope is `EMIT_AGENT_CGROUP_ROOTS` (cgroup v2 directories
whose descendants are scope `agent`; `EMIT_CGROUP_PATH` is refused) or, on
Kubernetes, `EMIT_AGENT_POD_SELECTOR` with `EMIT_NODE_NAME`;
`EMIT_SANDBOX_CGROUP_ROOTS` marks agent-started containers as scope
`sandbox`. `EMIT_DEDUPE_WINDOW` must be `0`, and `EMIT_INSECURE=true` is
refused to a non-loopback endpoint. `fabric-host-emitter print-source-id`
prints the `s-` id to bind in the Node's group.

The auditd receiver selects it with `mode: production`. It then runs in a
sensor collector you deploy next to the audit log (never inside a Node),
with tenant, source and host labels, id and state key files and a state
directory, and exports over OTLP/HTTP (TLS unless loopback) to its own `host.auditd`
group; `fabric-gate` checks the collector against its sensor-collector
profile. Its logfile cursor advances only after the Node acknowledges every
staged batch.

- **Compose:** `docker-compose.host-ingress.yml` on the production overlay
  (`make up-prod-groups`): the agent group and the `ebpf` group
  (`FABRIC_EBPF_SOURCE_ID`, `FABRIC_EBPF_TOKEN_FILE`, gRPC 4417); the auditd
  group and the agent's content path are further overlays.
- **Kubernetes:** one group per node (spec 056 §7.3.3 (n)). Each node's
  emitter uses the source label `$(NODE_NAME)/ebpf`, reads its token, state
  key and group endpoint from a per-node hostPath directory
  (`EMIT_ENDPOINT_FILE`), and shares only the id key through a Secret;
  `deploy/kubernetes/host-bindings.py` generates the chart values. The 64
  group default (256 at most) bounds the nodes one Node serves.

[AR-1 production](../qualification/action-record/README.md#ar-1-production-m2)
exercises this path in CI.

Known limits of production mode:

- **The host id is not bound to the ingress group yet.** A group binds one
  source id and one token, but the `hst-` host id in a sensor's records is
  only format-checked, so a sensor holding one group's credentials can
  name another host.
- **The pod-selector scope needs cluster-wide pod read.** The DaemonSet's
  ClusterRole grants `get`, `list` and `watch` on pods; RBAC cannot limit
  that to one node, so every node's emitter can read every pod object,
  inline environment values included, although it uses only its own node's
  pod uids and labels. Use static cgroup roots or a dedicated node pool
  where that is not acceptable.
- **No fork events.** An exec whose parent only forked and produced no event
  of its own (bwrap's default pid-1 reaper) is listed unexplained; run
  bwrap with `--as-pid-1`.
- **One group per node.** A Node serves 64 groups by default and 256 at
  most; a larger cluster deploys one Node per node pool.

## Limits of local mode (since v0.8)

- **Not accepted by a production Node.** Local-mode records (logs) are
  refused by a production Node: `fabric-gate` never runs the `audit`
  receiver inside a Node, and a source-bound `fabricguard` admits host
  records only from a host ingress group. Run local mode against a
  separate, local-profile Node, or use [production mode](#production-mode)
  (v0.11.0).
- **No sensor workload in the Helm chart.** The chart configures a Node's
  host ingress groups but deploys no sensor; the sensors run from the
  DaemonSet and sensor-collector examples in `deploy/kubernetes/` or the
  Compose overlays.
- **No run identity.** Host records carry no `fabric.run.*` or source-epoch
  identity that `fabric.reconstruct` reads; reconstruct ignores them in
  `--spans`. Joining host events to the agent's subprocess effects through
  pid and parent pid is specified in
  [spec 056](../specs/056-agent-action-reconstruction.md) §4.3 and released
  in v0.10.0 for the local profile
  ([`reconstruct/_host.py`](../sdk/python/src/fabric/reconstruct/_host.py)):
  pass the records with `--host-records`
  ([agent action reconstruction](action-reconstruction.md)). The
  auditd logfile mode carries `audit.source_id` and `audit.source_generation`;
  netlink mode and the emitter carry no source identity.
- **Not enterprise-qualified.** The outage and restart and host-truth tests
  listed in specs 030 and 031 have not been run as a qualification. CI builds
  and unit-tests both sensors, and the AR-1 live run
  ([qualification/action-record](../qualification/action-record/README.md))
  loads the eBPF emitter on a CI Linux kernel; the auditd receiver is not run
  against a live kernel in CI.
- `fabric.event_count` on a `dedupe_collapsed` record counts all events in
  the auditd receiver but only the suppressed repeats in the emitter.
