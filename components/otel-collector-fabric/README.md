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
- `fabriccontent` — the Node's content writer for LLM wire capture (spec 048):
  it accepts only content log records (the closed content-v2 descriptor
  attribute set, the exact bytes as the body), recomputes their length and
  SHA-256, admits only `allowed_tenants` (exactly one unless
  `allow_multiple_tenants: true`, which trusts every authenticated agent to
  name its tenant; use one Node per tenant otherwise), and writes body then
  descriptor to a directory or an S3(-compatible) bucket (`sse: AES256` or
  `aws:kms` required) with the SDK store layout
  (`<prefix><tenant>/evidence/<id>` and `.../evidence/meta/<id>.json`). It
  never overwrites (S3 `If-None-Match: *`; on disk an fsync'd temp file is
  hard-linked into place, or renamed with an atomic no-replace rename —
  `renameat2(RENAME_NOREPLACE)` on Linux — where the filesystem has no hard
  links; a filesystem offering neither fails the write retryably, never a
  check-then-rename): identical bytes are a successful replay, different
  bytes a conflict. Before its first acknowledgement each process fsyncs
  every directory on the object's path and every ancestor of the content
  root up to the durable boundary (the content root's filesystem root, a
  mount point, or the optional `file.durable_boundary`, which is fsync'd
  but never its parent), even when those directories already exist. The
  walk follows physical directories (symlinked ancestors are resolved
  first). A completed walk is recorded in `<root>/.fabric-root-barrier`
  (a `v2 physical-walk` marker; an older marker demands a fresh walk); only then
  may a later process treat an ancestor that refuses fsync with `EACCES`,
  `EPERM` or `EROFS` as the boundary. Without that record a refusal, like
  any other fsync failure, fails Start or the write retryably (spec 048
  §4, "Content root barrier"). Helm and Compose roots sit on a volume
  mount and need no `durable_boundary`. Refused
  records are dropped, counted and logged by reason only;
- upstream OTLP receiver and optional Linux audit receiver (netlink or durable logfile);
- memory limiter and optional development batch
  processor;
- OTLP/HTTP and local debug exporters;
- `noredirect` — an HTTP client middleware extension that refuses every
  redirect: listed in an OTLP/HTTP exporter's `middlewares`, it turns a
  `3xx` answer into a retryable transport failure before the client can
  follow it, so a body or `Authorization` header is never re-sent to
  another location and a redirect to an HTML page is never acknowledged as
  an export. `fabric-gate` requires it on every OTLP/HTTP exporter
  (`middlewares: [{id: noredirect}]`, with `noredirect: {}` under
  `extensions` and in `service.extensions`). The `fabriccontent` S3 client
  never follows a redirect either;
- health-check and persistent file-storage extensions;
- the bearer-token auth extension is compiled in for non-Kubernetes
  deployments that terminate token-authenticated OTLP ingress without a
  proxy; the compose production overlay wires this extension.

The recorder binary does not include policy, Presidio, prompt guard, sampling,
judge, red-team, or management components. Historical implementations remain in git and are not compiled into this image.

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
`fabricguard` applies a strict profile: only the spec 047 §8 keys, each with a
value validator, everything else dropped. `fabric.run.scope_id` (a lowercase
uuid4, spec 048 §6) survives only on exchange spans and on `run_start` /
`run_end` heartbeats. `fabric.run.id` is admitted only as the SDK's run-id
pseudonym `r-<32 hex>` or a generated fallback (`trace:<32 hex>`,
`source:<source id>:<epoch>`, `h-<40 hex>`), never as a clear caller id.
`gen_ai.response.model` is kept only when allowlisted — built-in prefixes such
as `gpt-*` or `claude-*` admit only version-token suffixes (`gpt-4o-mini`,
`claude-3-5-sonnet-20240620`) with at most two numbers of at most 4 digits
(`N.N` counts as one) and one date, so `gpt-4o-123-45-6789` is hashed; exact
names or `prefix*` entries can be added
with `capture_model_allowlist` (the Node counterpart of the SDK's
`FABRIC_WIRE_MODEL_ALLOWLIST`) — and is otherwise replaced by
`m-` + 16 hex of its SHA-256, the same value the SDK emits; the vectors in
`contracts/capture/v1/fixtures/model-names/` pin the rule for both.
By default (`capture_labels: pseudonymous`) capture spans may carry
`fabric.source_id` only as the SDK's `s-<32 hex>` pseudonym, a source
fallback run id only as `source:s-<32 hex>:<epoch>`, and their resource
`service.name` only as `svc-<32 hex>`; a clear label from an old or
non-conforming agent is dropped. Set `capture_labels: clear` only when the
agents run with `FABRIC_WIRE_LABELS=clear`: operator-chosen labels are then
exported unchanged (checked by pattern), and you guarantee they contain no
personal data. In global-tracer mode the capture spans share the host's
resource, whose clear `service.name` is dropped by default.

Spec 049 (four-layer capture contract) admits each of its new telemetry keys
with the closed check declared in
`contracts/coverage/v1/registry/telemetry-keys-v1.json` (a Go test verifies
`coverage_keys.go` against that file key by key); free text never passes. A
key is admitted on capture spans only on the record classes and heartbeat
kinds the spec places it on: `segment_seal` is a heartbeat kind, and the
segment, predecessor, termination and branch keys stay on their marker kinds.
Under `capture_labels: pseudonymous` a predecessor entry must name its source
in `s-<32 hex>` form. Keys whose validator the spec has not fixed yet
(`check_pending`) are not admitted. `fabric.source.authenticated` is
receiver-owned: it is stripped from every agent-supplied record and cannot be
added through `extra_allowed_*` (stamping at a bound ingress is P0-A).

Content (spec 048) has its own path: an `otlp/content*` receiver (OTLP/HTTP
only, port 4319) feeds a `logs/content*` pipeline that runs only
`memory_limiter` and exports only to `fabriccontent`. `fabricguard` is not on
that path — bodies must pass unchanged and the exporter enforces the closed
descriptor itself. `fabric-gate` refuses a content receiver or
`fabriccontent` in any other pipeline, any other receiver, processor or
exporter in a content pipeline, gRPC on a content receiver, and any
`connectors`, so content can never reach the OTLP destination exporter. The
single-tenant rule is per Node: all `fabriccontent` exporters in the
effective configuration, whatever receivers, pipelines or authenticators
they sit behind (and whether or not a pipeline uses them), together allow
one tenant unless every one of them sets `allow_multiple_tenants: true`. A
`fabriccontent` or OTLP/HTTP exporter block must be a literal map after the
gate's own resolution: a whole block given as `${env:...}`, or any provider
reference other than `${env:...}` inside it, is refused with a fixed
message. Every OTLP/HTTP exporter must list the `noredirect` middleware.
Gate diagnostics name config sources by position (`--config #2`) and never
echo source text, paths, URLs or underlying error text. The gate also refuses an OTLP exporter
endpoint (`endpoint`, `traces_endpoint`, `logs_endpoint`, ...) or a
`fabriccontent` `s3.endpoint` with user info, a query or a fragment; put
destination credentials in Secret-backed headers.
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

The example is for an isolated development environment: OTLP ingress listens
on all interfaces without TLS or authentication. Export endpoint and authorization
come from environment variables. Use the production profile below for protected ingress:

```bash
export FABRIC_EXPORT_ENDPOINT=https://otlp.example.com
export FABRIC_EXPORT_AUTH='Bearer <token>'
./dist/fabric-gate --config examples/config.yaml
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
