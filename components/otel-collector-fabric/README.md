# Fabric Node Collector distribution

This OpenTelemetry Collector Builder distribution (`otelcol-fabric`, v0.8) is the Fabric Node:

```text
CAPTURE -> PROTECT -> DELIVER
```

It accepts OTLP telemetry and wire-capture content from agents, removes
unapproved telemetry fields with an exact metadata allowlist, binds every
batch to one authenticated source in the production profile, buffers both in
persistent queues, and delivers telemetry to a customer-selected OTLP/HTTP
destination and content to a customer-owned directory or S3 bucket. No
SingleAxis service is required. Operator documentation:
[deployment](../../docs/deployment.md),
[privacy and security](../../docs/privacy-and-security.md),
[operations](../../docs/operations/README.md).

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
- `fabricenvelope` — a storage extension that wraps `file_storage` and seals
  every persisted queue value with AES-256-GCM under a Node-side key (see
  the P0-A section);
- the bearer-token auth extension is compiled in for non-Kubernetes
  deployments that terminate token-authenticated OTLP ingress without a
  proxy; the compose production overlay wires this extension.

The binary contains only the components above; release tests check the
build manifest so nothing else is compiled in. Historical implementations remain in git and are not compiled into this image.

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

Spec 049 (four-layer capture contract, rev 6.3) admits every one of its
telemetry keys in P0 with the closed check declared in
`contracts/coverage/v1/registry/telemetry-keys-v1.json`; the validator table in
`coverage_keys.go` is generated from that file and a Go test verifies it key
by key; free text never passes. The tightened validators of existing keys
(`fabric.session_id`, `fabric.delegation.to_agent`) are in force (see
the P0-A section). A key is
admitted on capture spans only on the record classes and heartbeat kinds the
spec places it on: `segment_seal` is a heartbeat kind, and the segment,
predecessor, termination and branch keys stay on their marker kinds. Under
`capture_labels: pseudonymous` a predecessor entry must name its source in
`s-<32 hex>` form and an operator label (`fabric.control.policy_id`,
`fabric.run.agent_policy_id`, `fabric.workflow.node`) must be `lbl-<32 hex>`.
The `fabric.capture_manifest` span is closed to the manifest keys, with
`fabric.schema_version` only as `fabric.capture-manifest/v1`.
`fabric.source.authenticated` is receiver-owned: it is stripped from every
agent-supplied record and cannot be added through `extra_allowed_*`; a
bound ingress stamps it on admitted spans (P0-A section).

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
`fabriccontent` `s3.endpoint` with user info, a query or a fragment (and an
`s3.endpoint` with a path); put
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

## Spec 049 P0-A: production profile

- `fabricguard` `profile: production` requires `evidence_source_binding`
  (`tenant_id`, `source_id` as the records carry them). On a bound ingress
  a span, resource or scope naming another `fabric.source_id` or
  `fabric.tenant_id` refuses the whole batch with `INVALID_ARGUMENT` before
  any mutation. A span naming no source is dropped on its own (an internal
  count and a debug log line `unbound_span`; no exported metric); the rest
  of the batch is admitted, and admitted spans get
  `fabric.source.authenticated=true`. On a bound logs pipeline every log
  record must be `event_class=evidence` with matching `tenant_id` and
  `source_id`; any other record (for example host-sensor `audit` records)
  refuses the whole batch. One production Node binds exactly one agent
  source. `identity_mode: pseudonymous` (the
  default) admits `fabric.session_id` only as `sess-<32 hex>`; `clear`
  keeps its earlier admission. `fabric.delegation.to_agent` is admitted
  only as `agt-<32 hex>`.
- `fabriccontent` follows the role table
  `contracts/coverage/v1/registry/content-roles-v1.json`
  (`roles_generated.go`, rendered by
  `scripts/contracts/generate_p0_contracts.py`), up to `max_body_bytes`
  (default 32 MiB, at most 63 MiB). With `source_binding` it drops other
  tenants or sources (`source_unbound`) and writes `source_authenticated:
  true` into the persisted descriptor. With `file.encryption_key_file`
  every object and descriptor is stored in the AES-256-GCM envelope
  (`contracts/content/v2/fixtures/node-envelope-v1.json`). Its
  `profile: production` requires the binding, a persistent queue on a
  `fabricenvelope` storage extension and, for the file backend, the key.
- `fabricenvelope` (extension) wraps a `file_storage` extension. It seals
  every value the persistent queue persists with the key in `key_file`
  (32 raw bytes or their base64). A value that fails authentication is an
  error and is never read as plaintext.
- `fabric-gate` treats a configuration whose `fabricguard`/`fabriccontent`
  declare `profile: production` as a production Node. It enforces the
  binding; one single-token bearer authenticator (`require_single_token`,
  token from a file) shared by the receivers; no receiver other than `otlp`
  and `otlp/content` (so no `audit` receiver); pipelines named `traces`,
  `logs` and `logs/content*` with fixed processors; exactly one telemetry
  exporter, `otlp_http/fabric`, over `https://` and no debug exporter; the
  same binding on every content exporter; the sealed queue and the
  directory key.

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
mTLS, authentication, persistence, retry, overflow, debug, and
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
