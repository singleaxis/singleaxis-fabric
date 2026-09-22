# auditd Host Connector

The `audit` receiver (built into `otelcol-fabric`) consumes Linux audit events
and emits them as `event_class=audit` log records on the logs pipeline —
exec/connect/file-access metadata joins the same `fabricguard` protection,
durable queue, and export path as every other record. See spec 030.

## What it captures

| Audit rule | You see |
|---|---|
| `execve`/`execveat` | every process spawn — `ssh`, `curl`, `scp`, uninstrumented tool escapes |
| `connect`/`accept`/`bind` | every outbound connection with peer address + port |
| `openat` (opt-in) | file access metadata — high volume, scope with `-F dir=` |

Each record carries `process.executable.name`, `process.executable.path`,
`process.pid`, `process.parent_pid`, `audit.result` (including
`failed:EACCES`-style denials), and `process.command_args_sha256` — **raw
command lines are never emitted**; argv is hashed at collection because it
can carry secrets.

## Deployment modes

**netlink (default)** — the collector joins the `AUDIT_NLGRP_READLOG`
multicast group read-only alongside auditd:

```yaml
receivers:
  audit:
    source: netlink
    rule_key: fabric     # consume only -k fabric tagged events
```

Requires `CAP_AUDIT_READ` on the collector container:

```yaml
# compose fragment
collector:
  cap_add: [AUDIT_READ]
```

**logfile** — tail `/var/log/audit/audit.log` for hosts where the audit log
is already collected; needs read access to the log directory only:

```yaml
receivers:
  audit:
    source: logfile
    log_path: /var/log/audit/audit.log
```

**manage_rules (optional)** — when no auditd daemon holds the control socket,
the collector can enable audit and install its own `-k fabric` rules with
`CAP_AUDIT_CONTROL`:

```yaml
receivers:
  audit:
    manage_rules: true
```

On hosts already running auditd, load `fabric.rules` with `auditctl -R` or
`augenrules` instead — the connector never overrides a live daemon.

## Attribution honesty

Audit records are **inferred provenance**, not span edges: they carry
pid/ppid/auid and timestamps. Joining them to SDK traces is investigative
(pid+host+time), not causal. Do not claim an audit record "belongs" to a
trace — claim it was observed near it.

## Volume

`exec` + `connect` on a typical agent host is modest; `file_access` is not —
keep it off unless your rules are path-scoped. `max_events_per_sec` (default
200) and `dedupe_window` (default 1s) bound the stream; rate-limit drops are
counted in collector logs and dedupe repeats surface as
`fabric.event_count` summary records.
