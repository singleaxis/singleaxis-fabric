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

Each record carries `process.executable.name`, `process.executable.path_sha256`,
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
is already collected; requires read-only audit logs and a private persistent
read-write checkpoint volume:

```yaml
receivers:
  audit:
    source: logfile
    log_path: /var/log/audit/audit.log
    state_directory: /var/lib/fabric/audit
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


## Durable logfile migration

Existing `source: logfile` configurations must add `state_directory`; missing
configuration now fails validation rather than silently using volatile state.
Create a dedicated directory owned by the collector user with mode 0700 and
mount it persistently (for example `./audit-state:/var/lib/fabric/audit:rw`).
Keep the audit-log mount read-only. Preserve this state across container restarts.
The supplied E2E script mounts a private temporary state directory; its cleanup
removes test data intentionally, so it is not a production retention setup.

Logfile mode persists a scrubbed replay batch before downstream delivery and
advances the accepted cursor only after acceptance. Ambiguous acceptance can
repeat the same `fabric.record_id`; destinations must deduplicate. It paces
instead of rate-dropping and ignores temporal dedupe. Numeric rename rotations,
truncation, source loss and invalid/oversized input have explicit coverage
markers. Disk-full/corrupt state never silently resets the cursor.

See the [full configuration, boundedness and loss contract](../../components/otel-collector-fabric/receiver/auditreceiver/README.md).
Local temporary-file tests are not live auditd/kernel qualification, and next
consumer acceptance is not a destination durable-delivery receipt.
