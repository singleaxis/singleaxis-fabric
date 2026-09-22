# Components

This directory holds the public, Apache-2.0 Fabric runtime. The recorder
release ships two components:

| Directory | Role | Primary spec |
|-----------|------|--------------|
| [`otel-collector-fabric/`](otel-collector-fabric/) | Fabric Node — the OTel Collector distribution that captures, protects, and delivers recorder telemetry | [027](../specs/027-recorder-v1.md) |
| [`host-emitter/`](host-emitter/) | Fabric Host Emitter — passive CO-RE eBPF DaemonSet that observes exec/connect/openat inside a configured cgroup scope and OTLP-exports them to the Node | [031](../specs/031-ebpf-host-emitter.md) |

Fabric Node is the recorder core: OTLP receivers, the `fabricguard`
metadata-protection processor, the persistent delivery queue, and the
destination exporter. The host emitter is an optional privileged sensor for
environments that need syscall-level observation the in-process SDKs cannot
see — it emits the same `event_class=audit` schema as the auditd receiver
([030](../specs/030-auditd-host-connector.md)), never raw content, and is
read-only by construction (tracepoints only, no LSM or packet control).

Managed platform services and previously-shipped capability sidecars are
out of recorder-v1 scope and no longer ship from this directory; their
history is in git.

## Status

Maturity is declared by each artifact and release manifest. Operators should
qualify the exact released image and chart for their environment.
