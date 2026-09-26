---
title: auditd Host Connector (auditreceiver)
status: implemented-not-enterprise-qualified
revision: 2
last_updated: 2026-09-26
owner: project-lead
---

# Spec 030 — auditd Host Connector

**Depends on:** spec 027 (recorder-v1 scope), spec 022 (surface logging —
the `audit` event class this connector populates), the connect-capability
contract (`contracts/connect/v1`).

## Problem

SDK instrumentation sees only what flows through instrumented calls. An agent
that spawns a raw subprocess — `ssh`, `curl | sh`, `scp`, any `execve` — leaves
no semantic record. For a "prove the agent never did X" claim, *"nothing was
emitted"* is weaker evidence than *"the kernel audit log shows nothing
happened"*. Regulated hosts already run auditd (CIS/STIG baseline), so
consuming it adds the syscall layer without asking security teams to approve
a new privileged kernel sensor.

## What we are building

A collector **receiver** (`auditreceiver`) compiled into `otelcol-fabric` via
OCB — not a separate daemon or artifact. Audit events become OTLP **log
records** on the existing `logs` pipeline, so they flow through `fabricguard`,
the durable queue, and the exporter unchanged.

```text
auditd rules → kernel emits records → audit netlink (unicast) or audit.log
                                              │
                              auditreceiver (inside otelcol-fabric)
                              assemble → translate → scrub argv
                                              │
                                     logs pipeline → fabricguard → queue → export
```

## Input sources (config `source:`)

1. **`netlink` (default).** Subscribe `AUDIT_NLGRP_READLOG` multicast —
   read-only listener, kernel ≥ 3.16, needs only `CAP_AUDIT_READ` on the
   collector container; coexists with auditd (does not steal the control
   socket). When no host auditd is running and the collector also has
   `CAP_AUDIT_CONTROL`, the receiver may set the configured rules itself
   (`manage_rules: true`) — first writer wins, never overrides an existing
   daemon.
2. **`logfile`**. Tail `/var/log/audit/audit.log` (configurable path) with
   rotation handling and an in-process read position. The position is not
   restart-durable. Needs read access to the audit log
   directory only — the lowest-privilege fallback for hosts where the audit
   subsystem is owned by an existing daemon.

## Event assembly

Audit events arrive as multi-record groups sharing `audit(epoch:serial)`
(SYSCALL 1300, EXECVE 1302, CWD 1303, PATH 1304, PROCTITLE 1307, SOCKADDR 1309,
EOE 1320). The receiver:

- groups records by serial into one event; flush on EOE or a bounded
  assembly timeout (default 500 ms) with eviction stats;
- maps syscall numbers to names on x86_64/arm64: `execve`(59/221),
  `connect`(42/203), `accept`(43/202), `openat`(257/56), `bind`(49/200),
  `socket`(41/198);
- emits one log record per event.

## Log record shape

`event_class=audit`, plus allowlisted attributes only:

| Attribute | From | Notes |
|---|---|---|
| `audit.syscall` | SYSCALL.nr → name | `execve`/`connect`/`openat`/… |
| `audit.result` | SYSCALL success/exit | `success` or `failed:EPERM` |
| `audit.serial` | event serial | dedupe/debug |
| `process.pid` / `process.parent_pid` | SYSCALL pid/ppid | correlation key |
| `process.executable.name` | SYSCALL comm | basename |
| `process.executable.path_sha256` | SYSCALL exe | full-path hash; raw path is not emitted |
| `process.command_args_sha256` | EXECVE argv / PROCTITLE | **hash only — raw argv never emitted** (may carry secrets) |
| `process.owner` | auid | login uid of initiator |
| `network.peer.address` / `network.peer.port` | SOCKADDR | connect/accept targets |
| `file.path_sha256` | PATH | only when `file_access: true`; hashing is required |
| `audit.source` | `netlink`/`logfile` | provenance |
| `fabric.event_count` | dedupe window | >1 when aggregated |

Resource attributes: `host.name`, plus collector's configured resource.

## Safety controls

- **Argv scrubbing at collection** — `process.command_args_sha256` only; raw
  argv never leaves the host boundary. (`fabricguard` is the second layer.)
- **Path minimization at collection** — executable and file paths are hashed;
  `file_access: true` with `hash_file_paths: false` fails configuration
  validation. The export guard drops raw path keys even from other sources.
- **Volume**: `max_events_per_sec` token bucket (default 200) + optional
  `dedupe_window` (default 1s) collapsing identical exec/connect bursts into
  `fabric.event_count`. Drops counted and surfaced via collector telemetry.
- **Syscall classes** are config-gated: `exec: true` (default),
  `connect: true` (default), `file_access: false` (default — high volume).
- **Attribution is inferred provenance**: records carry pid/ppid/host/time;
  they are NOT native span edges. Per `docs/integration-models.md`, joins to
  agent traces are investigative, not causal — the connector must not mint
  trace IDs.

## Fabric guard / gate interplay

- Events land on the `logs` pipeline → existing `fabric-gate` pipeline check
  passes unchanged.
- The `audit` event class has an exact metadata allowlist with closed host
  status values and no raw path or argv keys.
- Deploying this receiver requires `CAP_AUDIT_READ` (netlink) or audit-log
  read access (logfile), and only in the optional host-monitor overlay.

## Deliverables

- `components/otel-collector-fabric/receiver/auditreceiver/` (go module,
  factory + receiver + parser + assembler + tests)
- `ocb-config.yaml` receiver entry + `replaces:` entry; `Makefile` dir list
- `deploy/auditd/fabric.rules` (execve + connect baseline, openat scoped),
  `deploy/auditd/README.md`, host-monitor compose overlay snippet
- `contracts/connect/v1/manifests/auditd-host-connector.json` + digest pin
- allowlist `audit` fields + tests proving argv never crosses

## Honest limits (manifest blind spots)

- Coverage = ruleset quality: auditd only emits what rules request.
- Linux only; kernel ≥ 3.16 for multicast.
- High-volume syscall classes (openat) can exceed queue/emit budgets —
  off by default.
- No semantic/decision context — this layer records *what the OS did*, not
  *why the agent did it*.
- Failed downstream deliveries now enter a bounded in-memory retry queue and
  overflow/rate/assembly gaps are reported when delivery resumes. This queue
  is not restart-durable, logfile mode has no persisted cursor, and multicast
  netlink cannot replay lost kernel events. Source-to-Node loss/restart
  qualification remains required before any complete-host-capture claim.
