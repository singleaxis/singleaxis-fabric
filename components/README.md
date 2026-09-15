# Components

This directory holds the public, Apache-2.0 Fabric runtime. The recorder
release ships exactly one component:

| Directory | Role | Primary spec |
|-----------|------|--------------|
| [`otel-collector-fabric/`](otel-collector-fabric/) | Fabric Node — the OTel Collector distribution that captures, protects, and delivers recorder telemetry | [027](../specs/027-recorder-v1.md) |

Fabric Node is the whole runtime: OTLP receivers, the `fabricguard`
metadata-protection processor, the persistent delivery queue, and the
destination exporter. SDKs and contracts live elsewhere in the repository
(`sdk/`, `contracts/`); this directory is the deployable.

Managed platform services and previously-shipped capability sidecars are
out of recorder-v1 scope and no longer ship from this directory; their
history is in git.

## Status

Maturity is declared by each artifact and release manifest. Operators should
qualify the exact released image and chart for their environment.
