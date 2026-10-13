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
- `fabriccontent` — the Node's content writer for LLM wire capture (spec 043):
  it accepts only content log records (the closed content-v2 descriptor
  attribute set, the exact bytes as the body), recomputes their length and
  SHA-256, admits only `allowed_tenants` (exactly one unless
  `allow_multiple_tenants: true`, which trusts every authenticated agent to
  name its tenant; use one Node per tenant otherwise), and writes body then
  descriptor to a directory or an S3(-compatible) bucket (`sse: AES256` or
  `aws:kms` required) with the SDK store layout
  (`<prefix><tenant>/evidence/<id>` and `.../evidence/meta/<id>.json`). It
  never overwrites (S3 `If-None-Match: *`, hard-link creation on disk):
  identical bytes are a successful replay, different bytes a conflict. Refused
  records are dropped, counted and logged by reason only;
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
distribution qualification script proves the refusal for both the image and
the binary artifact. `make build` places `fabric-gate` next to
`otelcol-fabric` in `dist/` — binary deployments should launch the gate,
which resolves and execs the sibling collector itself.

Every `traces` and `logs` pipeline must also list `fabricguard` in its own
`processors` (checked on the merged configuration, so an overlay cannot drop
it), and only `batch` or `memory_limiter` may follow it; a processor after the
guard could re-add values it removed. On the wire-capture spans
(`fabric.model_call`, `fabric.capture_loss`, `fabric.capture_heartbeat`)
`fabricguard` applies a strict profile: only the spec 042 §8 keys, each with a
value validator, everything else dropped. `fabric.run.scope_id` (a lowercase
uuid4, spec 043 §6) survives only on exchange spans and on `run_start` /
`run_end` heartbeats.

Content (spec 043) has its own path: an `otlp/content*` receiver (OTLP/HTTP
only, port 4319) feeds a `logs/content*` pipeline that runs only
`memory_limiter` and exports only to `fabriccontent`. `fabricguard` is not on
that path — bodies must pass unchanged and the exporter enforces the closed
descriptor itself. `fabric-gate` refuses a content receiver or
`fabriccontent` in any other pipeline, any other receiver, processor or
exporter in a content pipeline, gRPC on a content receiver, and any
`connectors`, so content can never reach the OTLP destination exporter.
Give `fabriccontent` its own `file_storage` queue (`block_on_overflow: true`)
and `retry_on_failure.max_elapsed_time: 0`; S3 credentials come from the AWS
default chain (IRSA on EKS), never from the agent.

`fabric-gate` also rejects `bearertokenauth` extensions whose token material
would mint an empty credential under the pinned extension (v0.150.0 keeps
empty entries after splitting token files on newlines): missing, empty,
blank-line, or newline-terminated token files, and empty inline `tokens`
entries. When token files are configured the gate stays resident as a thin
supervisor — the extension re-reads the file via fsnotify, so the gate
re-validates it on a poll interval and stops the collector (SIGTERM, letting
the queue drain) if a rotation reintroduces an unsafe file. Operators who
override the container entrypoint or launch `otelcol-fabric` directly leave
the enforced path; `verify-prod.sh` surfaces a container-level entrypoint
override at verification time.

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
make qualify-content COLLECTOR_IMAGE=fabric-otelcol:pr
```

`qualify-content` posts content log records to a throwaway container and
checks the stored body and descriptor bytes, a refused digest mismatch and an
accepted replay.

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
