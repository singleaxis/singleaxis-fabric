# Fabric Node Collector distribution

This OpenTelemetry Collector Builder distribution is the recorder-v1 runtime:

```text
CAPTURE -> PROTECT -> DELIVER
```

It accepts OTLP, removes unapproved content with an exact metadata allowlist,
buffers protected telemetry, and exports to any customer-selected OTLP/HTTP
destination. SingleAxis Platform is optional.

## Included components

- `fabricguard` — exact metadata allowlisting and native OTLP text scrubbing;
- upstream OTLP receiver, memory limiter and optional development batch
  processor;
- OTLP/HTTP and local debug exporters;
- health-check and persistent file-storage extensions;
- the bearer-token auth extension is compiled in for non-Kubernetes
  deployments that terminate token-authenticated OTLP ingress without a
  proxy; no shipped config wires it up by default.

The recorder binary does not include policy, Presidio, prompt guard, sampling,
judge, red-team, or management components. Their experimental source modules
may remain elsewhere in the repository but are not compiled into this image.

Recorder configurations MUST NOT define `metrics` or `profiles` service
pipelines: `fabricguard` only protects logs and traces, so any telemetry on
those pipeline types would cross the boundary unfiltered. The shipped image
enforces this at startup: its `fabric-gate` entrypoint parses the collector
config and refuses to boot on non-`traces`/`logs` pipelines, and the
distribution qualification script proves the refusal. Bare `dist/otelcol-fabric`
binary runs carry no gate; the qualification script is their boundary.

`fabric-gate` also rejects `bearertokenauth` extensions whose token material
would mint an empty credential under the pinned extension (v0.150.0 keeps
empty entries after splitting token files on newlines): missing, empty,
blank-line, or newline-terminated token files, and empty inline `tokens`
entries. Operators who override the container entrypoint leave the enforced
path.

## Build and qualify

```bash
go install go.opentelemetry.io/collector/cmd/builder@v0.150.0
make test
make build
make qualify-config
```

The result is `dist/otelcol-fabric`. `qualify-config` proves that the actual
binary accepts mTLS OTLP ingestion, the protection processor, authenticated
OTLP/HTTP export, and a file-backed persistent sending queue. It does not claim
live destination persistence.

For a CI-built image:

```bash
make qualify-image COLLECTOR_IMAGE=fabric-otelcol:pr
```

## Run

The example uses environment-provided endpoint and authorization values:

```bash
export FABRIC_EXPORT_ENDPOINT=https://otlp.example.com
export FABRIC_EXPORT_AUTH='Bearer <token>'
./dist/otelcol-fabric --config examples/config.yaml
```

Mount the file-storage directory on encrypted persistent storage. Production
deployments should use the Helm `shadow-production` profile, which validates
mTLS, authentication, persistence, retry, overflow, sampling, debug, and
network-policy invariants. That profile disables batching before the persistent
exporter queue so acknowledged telemetry does not wait in volatile memory.

## Reliability boundary

Persistent queues provide bounded at-least-once transport. They may replay a
batch after an ambiguous acknowledgement and cannot survive storage loss,
permanent record rejection, or exhausted capacity. The destination must
deduplicate stable identities and provide authoritative retention evidence.

Queue volumes can contain sensitive telemetry. Protect them with encryption,
least privilege, backup, and lifecycle controls appropriate to the deployment.

Apache-2.0.
