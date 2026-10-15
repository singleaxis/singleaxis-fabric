# Deploying LLM wire capture

This guide is for an operator turning on LLM wire capture
([spec 047](../specs/047-llm-wire-capture-and-reconstruction.md) with the
delivery changes of [spec 048](../specs/048-node-content-delivery-and-agent-spool.md),
both draft) for a Python agent. Capture copies the exact request and
response bytes of each model call and records one metadata-only span per
call. Both go to a Fabric Node you run; the Node writes the bytes to a store
you own and forwards the spans to an OTLP destination you choose.

Capture does not change the agent's requests or responses, and a capture
failure never raises into the agent. On the call path it adds only bounded
in-process work (no disk, store or network I/O; the latency budgets in spec
047 §4.10 are tested), and response chunks reach the client as soon as the
transport yields them. It does wait in three places, all bounded:
`flush()` and `close()` when you call them, and the exit handler, which
holds interpreter exit for at most `shutdown_timeout_s` (default 2 s).

```text
            agent host                                 Fabric Node                         customer-owned
┌─────────────────────────────────────┐   ┌───────────────────────────────────────────┐
│ agent ─► wire tee ─► spool (fsync)  │   │ otlp :4317/:4318 ─► fabricguard ─► queue ─│─► OTLP destination
│                        │ one sender ├──►│                                           │   (spans only)
│                        │ thread     ├──►│ otlp/content :4319 ─► fabriccontent ─► q ─│─► S3 / MinIO / directory
└─────────────────────────────────────┘   │   (descriptor, digest, length, tenant)    │   (bodies + descriptors)
  no cloud credentials, Node ingress only └───────────────────────────────────────────┘
```

**Agents have no store access.** In node mode (the default whenever a
content endpoint is set) the agent never talks to S3 and needs no cloud
credentials: it holds only the Node's ingress credential (client
certificate or bearer token). The Node's identity is the only writer of
content, and encryption, bucket and prefix are configured once, on the
Node.

## 1. Activate capture in the agent

Install the SDK with the OTLP extra (it brings `requests` and
`opentelemetry-proto` for the content client), plus
`opentelemetry-exporter-otlp-proto-grpc` only if you export spans over gRPC:

```bash
pip install "singleaxis-fabric[otlp]"
```

Capture is never enabled by installing the package. Turn it on per process
with the autoload directory and one flag:

```bash
export PYTHONPATH="$(python -m fabric.wire --print-autoload-path)${PYTHONPATH:+:$PYTHONPATH}"
export FABRIC_WIRE_AUTOLOAD=1
```

A node-mode agent needs nothing but Node endpoints, a tenant id and a spool
directory:

```bash
export FABRIC_TENANT_ID=<opaque tenant id>          # must be in the Node's allowed tenants
export FABRIC_WIRE_SPOOL_DIR=/var/lib/my-agent/fabric-spool
export FABRIC_WIRE_CONTENT_ENDPOINT=https://fabric-node:4319/v1/logs
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://fabric-node:4318/v1/traces
# plus the ingress credential: client certificate (Helm) or bearer header (Compose)
```

| Variable | Required | Meaning |
|---|---|---|
| `FABRIC_WIRE_CONTENT_ENDPOINT` | node mode | Full URL of the Node's content receiver, used as given (`https://node:4319/v1/logs`). Setting it selects node mode. A URL with user info, a query or a fragment is rejected without echoing it. Redirects are never followed (below). |
| `FABRIC_WIRE_STORE` | no | Unset: node mode when a content endpoint is set, else metadata only (no bytes stored; runs can only be `unverified`). `node`: node mode explicitly. `file:///absolute/dir`: the agent writes a local store itself (development, offline or single-host; refused together with a content endpoint). `s3://…` is **refused**: S3 is written by the Node. |
| `FABRIC_TENANT_ID` | node and file modes | Tenant id sent with every content record; it must equal the Node's one allowed tenant (one Node per tenant, §2). Objects land at `<prefix><tenant>/evidence/<object-id>`. A path prefix chosen by you, not an access boundary; never personal data (see below). |
| `FABRIC_WIRE_SPOOL_DIR` | node mode | Absolute directory for the durable spool (created `0700`; an existing one must be owned by the agent's uid and not a symlink). Optional in file mode, where it enables the same delivery path. |
| `FABRIC_WIRE_SPOOL_MAX_BYTES` | no | Spool bound, default 1 GiB, minimum `2 × FABRIC_WIRE_MAX_BODY_BYTES + 1 MiB`. When full, new exchanges are dropped and recorded as `queue_full` losses; the host is unaffected. |
| `FABRIC_WIRE_SPOOL_MAX_RECEIPTS` | no | Delivery receipts kept for other processes sharing the spool, default 4096 (at most `max_bytes / 1024`); the oldest expire first. Raise it for large forked worker pools. |
| `FABRIC_WIRE_MODEL_ALLOWLIST` | no | Comma-separated model names emitted as is, in addition to the built-in public families. An exact entry matches only that name; a `prefix*` entry matches only a version-like suffix (§3). Any other model name is emitted as `m-` + a hash. |
| `FABRIC_WIRE_ID_KEY` | recommended in production | Secret key for identifier pseudonyms: a run id passed to `fabric.wire.run(run_id)` is emitted as `r-` + 32 hex of `HMAC-SHA256(key, run_id)`, and (by default, see `FABRIC_WIRE_LABELS`) the source id as `s-` + 32 hex and `service.name` as `svc-` + 32 hex of the same function. Unset, an unkeyed SHA-256 that anyone who can guess the value can recompute. Never logged. See "The id key" below. |
| `FABRIC_WIRE_LABELS` | no | Unset or `pseudonymous` (default): source id and `service.name` leave the agent only as `s-`/`svc-` pseudonyms. `clear`: they are emitted unchanged; **operator-chosen labels are exported unchanged; you guarantee they contain no personal data**. Any other value is a configuration error. Run ids are pseudonymised in both modes. |
| `FABRIC_SOURCE_ID` | no | Id of this capture source, emitted as its `s-` pseudonym (clear only with `FABRIC_WIRE_LABELS=clear`). Default `wire-` + 16 hex derived from host name and `service.name`. |
| `FABRIC_WIRE_ENDPOINTS` | no | JSON array of extra endpoint matchers (vLLM, Ollama, an internal proxy). OpenAI, Anthropic and Azure OpenAI are matched by default. |
| `FABRIC_WIRE_MAX_BODY_BYTES`, `FABRIC_WIRE_QUEUE_MAX_ITEMS` | no | Per-body retention cap (default 8 MiB; at most 63 MiB in node mode so one record fits the Node's 64 MiB request bound) and worker queue length (default 256). |
| `FABRIC_WIRE_TRACER` | no | `private` (default, and required in node mode). `global` sends exchange spans through the agent's own provider without the spool; it is refused in node mode (see "Global mode" below). |
| `FABRIC_WIRE_STORE_SSE`, `FABRIC_WIRE_STORE_KMS_KEY_ID` | — | **Removed.** Setting either is an error: encryption is configured on the Fabric Node. |
| `OTEL_SERVICE_NAME` | no | Source of the capture spans' one resource attribute, `service.name` (must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, else `fabric-wire`), emitted as its `svc-` pseudonym (clear only with `FABRIC_WIRE_LABELS=clear`); `OTEL_RESOURCE_ATTRIBUTES` and resource detectors are ignored. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` | yes | Node span ingress. Over HTTP the traces-specific variable takes the full URL (`https://node:4318/v1/traces`) and the general one gets `/v1/traces` appended; over gRPC use `https://node:4317`. User info, query or fragment is rejected. |
| `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` / `OTEL_EXPORTER_OTLP_PROTOCOL` | no | `http/protobuf` (default, port 4318) or `grpc` (port 4317). The content endpoint is always OTLP/HTTP protobuf. |
| `OTEL_EXPORTER_OTLP_CERTIFICATE` | over TLS | CA bundle that signs the Node's server certificate. |
| `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_KEY` | Helm `shadow-production` | Client certificate and key for mTLS ingress (spans and content). |
| `OTEL_EXPORTER_OTLP_HEADERS` | Helm `shadow-production` (workload authentication) and Compose production | `Authorization=Bearer%20<token>` for bearer ingress. The general variable covers both signals (spans and content); if you set `OTEL_EXPORTER_OTLP_TRACES_HEADERS` or `OTEL_EXPORTER_OTLP_LOGS_HEADERS`, set the same value on both. |

Span settings resolve `OTEL_EXPORTER_OTLP_TRACES_*` before the general
`OTEL_EXPORTER_OTLP_*` variables; the content client resolves
`OTEL_EXPORTER_OTLP_LOGS_{HEADERS,CERTIFICATE,CLIENT_CERTIFICATE,CLIENT_KEY,TIMEOUT}`
before the same general variables, so one set of general variables
configures both. An unreadable TLS file fails installation.

**Redirects are not followed.** The content client and the private OTLP/HTTP
span exporter that Fabric builds for delivery never follow an HTTP redirect.
Any `3xx` answer is a delivery failure: the record stays in the spool and is
retried later, and its body and headers (including the ingress credential)
are never sent to the redirect target. Configure both endpoints with the
Node's final `https://` URL. A proxy or load balancer in front of the Node
that redirects (`http://` to `https://`, a trailing-slash rewrite, a login
page) stalls delivery and grows the spool until the URL is corrected; it
never yields a false success.

Invalid configuration installs nothing and logs one warning naming only the
error class; the agent runs unchanged. Fabric never logs environment
values, endpoint URLs, header values, TLS file contents or exporter
exception messages (spec 048 §8).

**The spool.** Every exchange (span data plus body bytes), loss record and
run marker is one fsync'd file in `FABRIC_WIRE_SPOOL_DIR` before it is
sent. One sender thread posts each body to the content endpoint, then
exports its span, and deletes the record only after both succeeded; it
retries with backoff (0.5 s doubling to 30 s) for as long as the Node is
unreachable. After a crash or restart, leftover records from earlier
processes are delivered first. A record that fails its checksum is kept as
`*.corrupt` and reported as an `internal_error` loss. Delivery is
at-least-once; the Node and the verifier deduplicate. Size the spool for
the longest Node outage you want to ride out. It lives on the agent host
and holds message content (`0600` files, `0700` directory; host disk
encryption is the at-rest protection). Several processes may share one
spool directory: one drains, all write.

*Delivery receipts in a shared spool.* When the draining process has
delivered a record another process wrote, it renames that record in place
to its receipt `<record>.ack` and truncates it to zero, so retiring a
record never needs free disk space; the writer consumes the receipt and
only then counts that record delivered. If the rename or truncation fails
(a full disk), the record stays pending and is not sent again until it is
retired. Receipts count against `FABRIC_WIRE_SPOOL_MAX_BYTES` (their size
plus 128 bytes each) and are capped by `FABRIC_WIRE_SPOOL_MAX_RECEIPTS`
(default 4096), oldest first. A record of a process that was quarantined
(`*.corrupt`) by any drainer, or that disappeared without a receipt, is a
failure for that process's `flush()`/`close()` (`False`), never a delivery.
So removing a pending `*.rec` by hand makes its writer report `False`, and
a drainer from an older Fabric version (which leaves no receipts) makes a
newer writer sharing the spool report `False` too: conservative, not lost
data. Upgrade every process sharing a spool together. The drainer removes
receipts older than one hour (left by writers that exited); a receipt
expired before its writer consumed it makes that writer report `False`,
because the delivery can no longer be proven. `flush()` and
`close()` return by their deadline even while another process's drain is
stalled in disk I/O.

**The in-memory window before the spool.** A call's record is durable only
once its spool file is fsync'd. From the moment the call finishes (the last
response byte reaches the client, or the stream is closed or fails) until
then, the exchange exists only in the agent's memory: it waits in the
capture worker's queue (at most `FABRIC_WIRE_QUEUE_MAX_ITEMS`, default 256
exchanges, and 256 MiB of bodies), and the worker hashes both bodies, then
writes, fsyncs and renames the record. With an idle worker that is one
exchange for a few milliseconds (one SHA-256 pass plus one fsync; longer for
multi-MiB bodies or slow disks); under a burst it is every queued exchange.
Run markers have the same short window. The write deliberately stays off
the agent's thread so capture never adds disk latency to a model call. If
the process is killed inside the window (SIGKILL, OOM kill, power loss),
those exchanges are lost without a loss record, but their sequence numbers
were allocated when the calls started: the run is reported `partial` (a gap
inside a closed run scope, or before a later recorded call) or `unverified`
(its end is not proven), never `complete_for_declared_scope`. An orderly
`close()` or normal exit drains the window before the `final` heartbeat.

**Global mode** (`FABRIC_WIRE_TRACER=global`, or
`fabric.wire.install(tracer_provider=X)`), file or metadata-only modes
only. Exchange spans go through the agent's own tracer provider: its
resource attributes, sampler, span processors, exporter and destination,
none of which Fabric controls, and they bypass the spool. Use it only when
the agent's provider exports through a Fabric Node, and set
`OTEL_SERVICE_NAME` to a value matching
`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` (the OTel default
`unknown_service:python` does not match, so `fabricguard` drops
`service.name` from every resource group holding a capture span). A loss
or heartbeat record the agent's sampler drops makes `flush()` return
`False` and is not retried.

**Identifiers are pseudonymous by default.** An identifier you choose
leaves the agent's telemetry and appears in reports only as a pseudonym
wherever it is not needed to route content: the first 32 hex of
`HMAC-SHA256(FABRIC_WIRE_ID_KEY, value)` (UTF-8 key and value), or of
`SHA-256(value)` when the key is unset, behind a prefix naming its kind:

| Identifier | Emitted as | Where the pseudonym appears |
|---|---|---|
| Run id passed to `fabric.wire.run(run_id)` | `r-` + 32 hex | Spans, run markers, spool records, content descriptors, reconstruction reports |
| Source id (`FABRIC_SOURCE_ID` or the default) | `s-` + 32 hex | `fabric.source_id` on every capture span, run marker, loss and heartbeat record, and in the report |
| `service.name` of the capture spans (`OTEL_SERVICE_NAME`) | `svc-` + 32 hex | The capture spans' resource |
| Tenant id (`FABRIC_TENANT_ID`) | `t-` + 32 hex | The reconstruction report only (see below) |

Generated fallback run ids (`trace:<trace id>`, and `source:<source
id>:<epoch>` with the source id in its emitted form) are not caller-chosen.
The report shows every run id and source id only in pseudonymous form; run
ids recorded in the clear by older agents are projected through the same
function, so old and new records of one run compare equal. The Node (`fabricguard`)
validates `fabric.source_id` and `service.name` as `s-`/`svc-` pseudonyms
and drops any other value (its `capture_labels: pseudonymous` default), or
by the label pattern when it is set to `capture_labels: clear` for agents
running with `FABRIC_WIRE_LABELS=clear`.

An unkeyed pseudonym is only a hash: anyone who can guess the value (a
sequential job number, an order id, a host name) can confirm it, so set the
key in production. One key covers all four kinds; with the same key, equal
values always give equal pseudonyms, so your OTLP destination can still
group spans by source and service.

**The tenant id stays clear where it routes content.** `FABRIC_TENANT_ID`
is deployment routing configuration: it travels with every content record,
must equal the Node's `allowed_tenants` entry, and names the object key
(`<prefix><tenant>/evidence/…`). It is never put on a capture span. Spool
records (agent host) and content descriptors (your store) carry the clear
tenant id and the source id in its emitted form (the `s-` pseudonym by
default). These labels must still be **opaque**: a random UUID, a workload
or job name, or a keyed hash you can resolve on your side; never a patient,
customer, user or account identifier, an email address, a name, or a
secret. Fabric cannot tell a patient number from a job id.

**Clear labels (`FABRIC_WIRE_LABELS=clear`).** For operators who want
readable source and service names in their OTLP backend. Operator-chosen
labels are exported unchanged; you guarantee they contain no personal data.
Source ids and `service.name` then reach every reader of your OTLP
destination as given, so use them only for workload names you would publish
in a dashboard. Give the Node the same choice — Helm:
`--set otel-collector.fabric.guard.captureLabels=clear`; Compose or a
hand-written collector config: `capture_labels: clear` under
`processors.fabricguard` — or it drops the clear `fabric.source_id` and
`service.name`. Run ids stay pseudonymised and the report still shows
pseudonyms. The default source id (`wire-` + 16 hex of host name and
service name) is already opaque.

*The id key (`FABRIC_WIRE_ID_KEY`).* Treat it like any other secret.

- **Generate** 256 random bits, without a trailing newline (the key is the
  variable's exact UTF-8 value, so a stray newline gives a different key):
  `umask 077; openssl rand -hex 32 | tr -d '\n' > id-key`.
- **Store** it in your secret manager and inject it into the agent's
  environment from there: on Kubernetes a Secret
  (`kubectl -n monitored-agents create secret generic fabric-wire-id-key
  --from-file=key=id-key`, then `rm -f id-key`) referenced with
  `valueFrom.secretKeyRef`; on a VM an env file readable only by the agent
  user. Never put it in an image, a Helm values file, a command line or a
  log. Fabric never logs it or writes it to a record or report.
- **Share** one key across every agent whose runs you verify together, and
  give it to whoever runs `fabric.reconstruct --run` or looks up a source
  (§5). It is read when capture is installed; a change takes effect when
  the process restarts.
- **Rotate** between runs, and roll every agent of a deployment together.
  Rotation changes the pseudonym of every run id, source id and service
  name from then on and leaves records already written under their old
  pseudonyms: a run that is open while agents switch keys, or whose
  replicas run with different keys, appears as two unrelated run ids, each
  verified on its own, and a source appears under two `s-` ids in your
  OTLP backend. To look up older records by their clear id, keep the
  retired key (disabled, not destroyed) and pass it with `--id-key-env`.
  Destroying a retired key makes the old pseudonyms permanently unlinkable
  to clear ids, which is a deliberate way to end that linkage. Verdicts
  never need the key: without `--run`, `fabric.reconstruct` reports every
  run by its pseudonym.

## 2. Run a Fabric Node

The Node has two separate paths. Telemetry: `otlp` (4317 gRPC, 4318 HTTP)
→ `memory_limiter` → `fabricguard` → durable queue → your OTLP destination.
Content: `otlp/content` (4319, HTTP only, 64 MiB request bound) →
`memory_limiter` → `fabriccontent` → your store. `fabriccontent` accepts
only records with the closed content descriptor, recomputes each body's
SHA-256 and length, writes only tenants on its allowlist, never overwrites
an object (an identical replay is success, different bytes are refused),
and logs a dropped record as `fabriccontent: dropped content record` with a
reason and nothing else. Content has its own fsync'd queue and is retried
until the store accepts it. `fabric-gate` refuses to start a configuration
that routes content into a telemetry pipeline or to the OTLP destination,
runs anything but `memory_limiter` on the content path, gives the content
receiver gRPC, or uses connectors; every telemetry pipeline must still run
`fabricguard`, every OTLP/HTTP exporter must use the `noredirect`
middleware (below), and `--set` overrides are refused.

**The Node never follows a redirect either.** The upstream OTLP/HTTP
exporter would follow a `3xx` from your destination (or a proxy in front of
it), re-sending the batch and its `Authorization` header to the new
location, including a downgrade from `https://` to `http://`, and a `302`
to a login page would count as a successful export. The Fabric distribution
ships a `noredirect` HTTP client middleware that turns any `3xx` answer into
a retryable failure without following it: the body and headers go only to
the configured URL, the batch stays in the durable queue, and the exporter
retries until the destination answers without a redirect. The Helm chart
and every shipped Compose configuration attach it to each `otlp_http`
exporter, and `fabric-gate` refuses a configuration with an OTLP/HTTP
exporter that does not list it (as with `fabriccontent`, an OTLP/HTTP
exporter block must be a literal map the gate can read; individual fields
may still use `${env:…}`). A hand-written configuration needs both parts:

```yaml
extensions:
  noredirect: {}
exporters:
  otlp_http/fabric:
    endpoint: https://otlp.example.com
    middlewares:
      - id: noredirect
service:
  extensions: [health_check, noredirect]   # plus your storage/auth extensions
```

Configure the destination's final `https://` URL: a redirecting endpoint
stalls delivery (the queue grows, `otelcol_exporter_send_failed_*` rises)
until the URL is corrected; it never yields a false success. The S3
content writer does not use this middleware: a redirect answer from the
store is a failed write there, retried like any other store error.

**One tenant per Node.** A content record names its own tenant, and every
agent that authenticates to the Node reaches the same receiver; the Node
cannot tell which agent belongs to which tenant. So the content exporter
accepts exactly **one** allowed tenant: with two, an agent of tenant A could
write objects under tenant B's prefix. The exporter, `fabric-gate`, the Helm
chart and the shipped Compose configs all refuse more than one unless it is
set explicitly (`allow_multiple_tenants: true`, Helm
`content.allowMultipleTenants=true`). That flag **trusts every
authenticated agent to name its tenant**; use one Node per tenant
otherwise. The rule covers the whole Node, not each exporter or pipeline:
`fabric-gate` takes every `fabriccontent` exporter in the effective
configuration, whatever receivers, pipelines or authenticators it sits
behind, and refuses to start unless together they allow exactly one tenant,
or every one of them sets `allow_multiple_tenants: true`. Separate
receivers or separate client CAs do not make two tenants safe on one Node;
run two Nodes. The gate must be able to read each exporter's settings: a
`fabriccontent` block that is not a literal map after the gate's own
resolution (for example the whole block given as `${env:…}` or `${file:…}`)
is refused with a fixed message, so write the exporter as a map and
substitute individual fields if you need to. The Helm chart renders exactly
one `fabriccontent` exporter. **S3 content is always encrypted:** the exporter refuses an s3
backend without `sse: AES256` or `sse: aws:kms`, whatever the launch path.

| Deployment | Ingress authentication (4317, 4318 and 4319 alike) | Content store | Agent settings |
|---|---|---|---|
| Helm `shadow-production` ([deployment.md](deployment.md)) | TLS with a verified client certificate **and** the workload-scoped bearer token (`receiver.workloadAuthentication`, required by the profile); the chart puts the same `bearertokenauth/workload` authenticator on 4317, 4318 and 4319. NetworkPolicy admits only labelled agent namespaces to all three ports | `otel-collector.content.backend=s3` with `content.s3.sse` (`AES256`, the default, or `aws:kms` + key); the Node writes with its IRSA role. The file backend is refused in this profile, and `content.allowedTenants` must be exactly `[tenant.id]`. | `https://` endpoints, `OTEL_EXPORTER_OTLP_CERTIFICATE`, `..._CLIENT_CERTIFICATE`, `..._CLIENT_KEY`, and `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20<workload token>` for both signals. Neither credential alone is accepted. |
| Compose production overlay ([deploy/compose](../deploy/compose/README.md)) | Bearer token; ports bound to `127.0.0.1` unless every published receiver has TLS (preflight) | `fabric-content` volume by default, or `FABRIC_CONTENT_BACKEND=s3` (bucket, region and SSE on the Node; instance role or a credentials-file secret) | `http://127.0.0.1:4318` and `:4319`, `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20<token>`. Use `https://` and receiver TLS before leaving the host. |
| Compose evaluation + MinIO (`make up-minio`) | None (loopback evaluation only) | Local MinIO bucket with SSE-S3, path-style addressing, Node-only writer keys | `http://127.0.0.1:4318` and `:4319`, `FABRIC_TENANT_ID=evaluation` |

**Helm.** Enable content with `otel-collector.content.enabled=true`,
`content.allowedTenants` (one tenant; in `shadow-production` exactly
`[tenant.id]`), `content.backend` and the backend settings. Content runs on a
content-capable Node only: the chart refuses `content.enabled=true` together
with `receiver.evidenceSourceBinding.enabled=true` ("content path cannot share
the dedicated evidence ingress; deploy a separate Node"), and `fabric-gate`
refuses the same combination in any configuration. The chart refuses to render without allowed tenants or a backend,
with more than one tenant and no `content.allowMultipleTenants=true`, with
an s3 backend lacking a valid bucket or `content.s3.sse` (default
`AES256`), a KMS key without `aws:kms`, an invalid store endpoint (see
below), or a memory limiter at or above the container memory limit.
`shadow-production` also refuses the file backend, an `http://` store
endpoint, and missing
`networkPolicy.contentEgress` peers for the store (S3 endpoint CIDRs or VPC
endpoint, plus STS for IRSA). Put the Node writer role on
`otel-collector.serviceAccount.annotations` (`eks.amazonaws.com/role-arn`);
the pod still mounts no Kubernetes API token (the IRSA webhook projects its
own STS-audience token). For an S3-compatible store without workload
identity, name an operator-created Secret in `content.s3.credentialsSecret`
(values never hold keys). The content queue lives on the queue PVC
(`<persistence.directory>/content-queue`); size the PVC for
`content.queue.queueSize × 64 MiB` on top of the telemetry queue.

*Destination URLs and network peers.* `exporter.endpoint` and
`content.s3.endpoint` must be absolute URLs of the form
`scheme://host[:port][/path]`: the host a DNS name, a dotted IPv4 address
or a bracketed IPv6 address, the port 1–65535, and no user info
(`user:password@`), query or fragment, which would put a credential or a
signed token into the rendered ConfigMap. `shadow-production` also requires
`https://` for both. Credentials belong in `exporter.auth.secret` and, for
the store, in the Node's IRSA role or `content.s3.credentialsSecret`.
Diagnostics name the field, never the value. Every NetworkPolicy peer you
supply (`ingressFrom`, `exporterEgress.to`, `contentEgress.to`, `egressTo`)
must restrict something, in every profile: an empty or exclusion-only
(`NotIn`/`DoesNotExist`) `namespaceSelector` needs a `podSelector` with
`matchLabels` or an `In`/`Exists` expression, an empty `podSelector` alone
(every pod in the Node's namespace) is refused, and an `ipBlock` with prefix
length 0 (`0.0.0.0/0`, `::/0`, `10.0.0.0/0`, …) is refused as equivalent to
no policy. Label values are strings (`matchLabels` is `map<string,string>`
in Kubernetes): pass them with `--set-string`, for example
`--set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'`,
or quote them (`"true"`) in a values file. `--set …=true` makes a boolean
that the API server rejects, so the chart refuses a boolean or numeric
`matchLabels` or `matchExpressions` value at render time.

*Secrets and certificates (Helm).* `shadow-production` expects three
operator-created Secrets in the Node's namespace and verifies every agent's
client certificate. The commands below use the release name `fabric` in
namespace `fabric-system` (Node Service `fabric-otel-collector`) and
self-managed CAs; with your own PKI, issue the same certificates from it.
Keep the CA keys off the cluster.

```bash
NS=fabric-system
NODE=fabric-otel-collector.$NS.svc
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

# CA that signs the Node's server certificate (agents trust it).
openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes \
  -keyout node-ca.key -out node-ca.crt -subj "/CN=fabric-node-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
# CA that signs agent client certificates (the Node trusts it).
openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes \
  -keyout client-ca.key -out client-ca.crt -subj "/CN=fabric-agent-client-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# Node server certificate for the in-cluster Service name.
openssl req -newkey rsa:3072 -sha256 -nodes -keyout node.key -out node.csr -subj "/CN=$NODE"
printf 'subjectAltName=DNS:%s,DNS:%s.cluster.local\nextendedKeyUsage=serverAuth\n' \
  "$NODE" "$NODE" > node.ext
openssl x509 -req -in node.csr -CA node-ca.crt -CAkey node-ca.key -CAcreateserial \
  -days 90 -sha256 -extfile node.ext -out node.crt

# The three Secrets the profile references (names and keys are fixed by it).
kubectl -n "$NS" create secret tls fabric-node-receiver-tls --cert=node.crt --key=node.key
kubectl -n "$NS" create secret generic fabric-node-client-ca --from-file=ca.crt=client-ca.crt
# Workload-scoped ingress token (receiver.workloadAuthentication.tokenSecret):
# one token per approved workload, a single line without a trailing newline,
# never on the command line. The Node checks it on 4317, 4318 and 4319.
umask 077; openssl rand -hex 32 | tr -d '\n' > workload.token
kubectl -n "$NS" create secret generic fabric-node-workload-token --from-file=token=workload.token
# Outbound Authorization value for your OTLP destination, without a trailing
# newline and without putting the token on the command line:
umask 077; read -rs DEST_TOKEN; printf 'Bearer %s' "$DEST_TOKEN" > authorization; unset DEST_TOKEN
kubectl -n "$NS" create secret generic fabric-node-export-auth --from-file=authorization=authorization
rm -f authorization
```

Render with the workload identity the profile requires (the review reference
names your credential-provisioning record):

```bash
helm upgrade --install fabric charts/fabric -n "$NS" \
  --values charts/fabric/profiles/shadow-production.yaml \
  --set tenant.id=<tenant> \
  --set otel-collector.image.digest=sha256:<approved-digest> \
  --set otel-collector.receiver.workloadAuthentication.tenantId=<tenant> \
  --set otel-collector.receiver.workloadAuthentication.workloadId=<workload> \
  --set otel-collector.receiver.workloadAuthentication.identityAttestationRef=<review-ref> \
  --set otel-collector.receiver.workloadAuthentication.tokenSecret.name=fabric-node-workload-token \
  --set otel-collector.content.enabled=true \
  --set 'otel-collector.content.allowedTenants[0]=<tenant>' \
  ...   # content backend, peers and storage as above
```

Give the agent the same token in its own Secret and expose it as
`OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20<token>` (from a
`secretKeyRef`, never a literal in the Pod spec), so both spans and content
present it.

Issue one client certificate per agent workload from the client CA and give
it to the agent together with the Node CA (not the client CA):

```bash
AGENT=billing-agent                 # an opaque workload label, not a person
openssl req -newkey rsa:3072 -sha256 -nodes -keyout "$AGENT.key" -out "$AGENT.csr" \
  -subj "/CN=$AGENT"
printf 'extendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:FALSE\n' > client.ext
openssl x509 -req -in "$AGENT.csr" -CA client-ca.crt -CAkey client-ca.key -CAcreateserial \
  -days 90 -sha256 -extfile client.ext -out "$AGENT.crt"
kubectl -n monitored-agents create secret generic fabric-agent-tls \
  --from-file=tls.crt="$AGENT.crt" --from-file=tls.key="$AGENT.key" \
  --from-file=ca.crt=node-ca.crt
```

Every certificate the client CA signs can write content for the Node's
allowed tenant (see "One tenant per Node"); revoke by rotating the client
CA, or issue short-lived certificates.

*Agent Pod.* Mount the agent's certificate Secret read-only and give the
spool a volume. Point `FABRIC_WIRE_SPOOL_DIR` at a **subdirectory** of the
mount: the agent creates it `0700` under its own uid, whereas the mount
point itself is created by the kubelet and is refused as not owned by the
agent.

```yaml
spec:
  securityContext:
    runAsUser: 10001
    runAsNonRoot: true
    fsGroup: 10001
  containers:
    - name: agent
      image: registry.example.com/billing-agent:1.4.2
      env:
        - {name: FABRIC_WIRE_AUTOLOAD, value: "1"}
        # The directory printed by `python -m fabric.wire --print-autoload-path`
        # in this image, prepended to any PYTHONPATH the image already sets.
        - {name: PYTHONPATH, value: /usr/local/lib/python3.12/site-packages/fabric/_autoload}
        - {name: FABRIC_TENANT_ID, value: tenant-7f3a}        # = content.allowedTenants[0]
        - {name: FABRIC_SOURCE_ID, value: billing-agent}      # optional, opaque
        - name: FABRIC_WIRE_ID_KEY                            # identifier pseudonym key (§1)
          valueFrom: {secretKeyRef: {name: fabric-wire-id-key, key: key}}
        - {name: OTEL_SERVICE_NAME, value: billing-agent}
        - {name: FABRIC_WIRE_SPOOL_DIR, value: /var/lib/fabric/spool}
        - {name: FABRIC_WIRE_CONTENT_ENDPOINT,
           value: "https://fabric-otel-collector.fabric-system.svc:4319/v1/logs"}
        - {name: OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
           value: "https://fabric-otel-collector.fabric-system.svc:4318/v1/traces"}
        - {name: OTEL_EXPORTER_OTLP_CERTIFICATE, value: /etc/fabric-agent-tls/ca.crt}
        - {name: OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE, value: /etc/fabric-agent-tls/tls.crt}
        - {name: OTEL_EXPORTER_OTLP_CLIENT_KEY, value: /etc/fabric-agent-tls/tls.key}
      volumeMounts:
        - {name: fabric-agent-tls, mountPath: /etc/fabric-agent-tls, readOnly: true}
        - {name: fabric-spool, mountPath: /var/lib/fabric}
  volumes:
    - name: fabric-agent-tls
      secret: {secretName: fabric-agent-tls, defaultMode: 0440}  # group-readable via fsGroup
    - name: fabric-spool
      emptyDir: {sizeLimit: 2Gi}   # or a PersistentVolumeClaim, see below
```

The agent's namespace (`monitored-agents` above) must carry the label the
Node's NetworkPolicy admits
(`kubectl label namespace monitored-agents fabric.singleaxis.ai/agent=true`,
matched by the `--set-string` selector shown in [deployment.md](deployment.md)).

*emptyDir or PVC for the spool.* An `emptyDir` lives as long as the Pod: it
survives container restarts (a crashed agent's records are replayed when the
container restarts), but records still on disk when the Pod is deleted,
evicted or rescheduled are lost, and their sequences show as gaps (runs
`partial` or `unverified`, never falsely complete). That is enough when the
Node is normally reachable and Pods are long-lived; set `sizeLimit` at or
above `FABRIC_WIRE_SPOOL_MAX_BYTES` (default 1 GiB) so an outage fills the
spool, not the node's disk. Use a PersistentVolumeClaim (one per Pod, e.g. a
StatefulSet `volumeClaimTemplate`, on an encrypted StorageClass) when
records must also survive Pod deletion and rescheduling, for example
during rolling deploys while the Node is down; a restarted Pod with the
same claim delivers the earlier records first. Several containers or
processes may share one spool directory.

**Compose.** The image runs as uid/gid 65532. Make the token file and any
TLS key owned by the operator who runs `make preflight-prod`, with group
65532 and mode `0440`. Compose publishes 4317, 4318 and 4319 on
`FABRIC_BIND_ADDR`; beyond loopback, preflight requires that every receiver
protocol serving one of them has TLS genuinely enabled (an uncommented
`tls:` mapping with non-empty `cert_file` and `key_file`; a commented,
empty, `{}` or `null` stanza counts as disabled), and it always requires
every receiver to authenticate. It validates `FABRIC_EXPORT_ENDPOINT` and
`FABRIC_CONTENT_S3_ENDPOINT` with the same URL rule as the Helm chart
(`https://`, valid host and port, no user info, query or fragment; the value
is never printed), checks `FABRIC_TENANT_ID` and, for S3, the bucket,
prefix, region and SSE.

## Two capture lines in one process

Wire capture coexists with the explicit evidence line (specs 035–046:
`CallRecorder`, `ByteBoundaryAdapter`, `FinalHTTPAdapter`). See
[Two capture lines](README.md#two-capture-lines) for the full comparison.

- **Explicit wins.** Inside a `CallRecorder` model call (or
  `ByteBoundaryAdapter(kind="model")`) the tee defers: no sequence, no span,
  no content; `WireStats.deferred_to_explicit` counts it. Tool, database and
  agent calls do not suppress wire capture.
- **Protected global provider.** With `FABRIC_WIRE_TRACER=global`, a global
  provider protected by `install_default_provider` never carries wire spans:
  wire switches to its private provider when an OTLP endpoint is set, and
  otherwise does not install (one class-only warning).
  `FABRIC_CAPTURE_LLM_CONTENT` never affects wire.
- **One directory per spool.** `FABRIC_WIRE_SPOOL_DIR` must not be the root
  of a `SyntheticSourceSpool`, `DurableByteSpool` or `JournalMetadataSender`;
  the wire spool refuses a directory holding any file it does not own
  (`.lock`, `*.rec`, `*.ack`, `.tmp-*`, `*.corrupt`) and capture is not
  installed.

## 3. What is streamed and who can read it

| Data | Path | Who can read it | Controlled by |
|---|---|---|---|
| Span metadata: exchange and scope ids (uuid4), source ids (`s-` pseudonyms; clear only with `FABRIC_WIRE_LABELS=clear`), run ids (`r-` pseudonyms of the ids you pass to `fabric.wire.run()`), sequence numbers, heartbeat kinds, body SHA-256 digests, store object ids (uuid4), API, response state, HTTP status, error class name, model name (see below), finish reasons (closed list), token counts; trace id, span id and flags of the agent's current span (its trace state and baggage are not copied); resource `service.name` (`svc-` pseudonym; clear only with `FABRIC_WIRE_LABELS=clear`) | agent spool → OTLP 4317/4318 → Fabric Node (`fabricguard`, queued on disk) → your OTLP destination | Anyone with access to the agent's spool directory, the Node host or queue volume, and every reader of the destination | Node ingress auth (mTLS or bearer), host access, destination ACLs and retention |
| Request and response bytes (prompts, completions, tool arguments and results, anything the provider echoes) and their descriptor JSON | agent spool → OTLP/HTTP 4319 → Fabric Node content queue → your store. Never sent to the OTLP destination | In transit: the agent host's spool directory (`0600`/`0700`) and the Node's content-queue volume. At rest: principals with `s3:GetObject` on the evidence prefix **and** `kms:Decrypt` on the key, or filesystem users who can read the Node's content directory | Agent host access; Node host and volume access; bucket policy, IAM and KMS key policy; filesystem permissions (files `0600`, directories `0700`) |
| Reconstruction report (`python -m fabric.reconstruct`) | written where the operator runs it | Whoever receives the file | File permissions. It holds run ids and source ids (pseudonyms only, whatever `FABRIC_WIRE_LABELS` was), the tenant id as `t-` + 32 hex of the id-key function, scope, exchange and store object ids, digests, counts, model names (same rule as spans) and pseudonyms of provider ids; span files appear only by digest, format and record count. Never message content, input file paths (span files, store root) or the resolved store location of an object |
| Fabric warnings | agent's own logging; Node logs | Agent and Node log readers | Fixed text, exception class names and HTTP status codes only. The Node logs a dropped content record with its reason only (no tenant, id, path, URL or byte) |

Who can touch content:

| Principal | Content access |
|---|---|
| Agent process and agent host | Writes its own records to its spool and posts them to the Node. **No bucket, KMS or store access.** |
| Fabric Node identity (Helm IRSA role on its service account, Compose instance role or writer keys) | The only writer: `s3:PutObject` and `s3:GetObject` (to byte-compare on a conditional-write conflict) on `<prefix><tenant>/evidence/*`, plus `kms:GenerateDataKey` and `kms:Decrypt` for `aws:kms` |
| Reconstruction reader (auditor, verifier job) | `s3:GetObject` on the evidence prefix and `kms:Decrypt` on the key |
| OTLP destination readers | Span metadata only; never content |

Message content never goes to the OTLP destination or into the report. Two
values that come from the provider's response can: the model name on spans
and, in the report only, response, previous-response and tool-call ids (as
`p-` + the first 16 hex of their SHA-256, so equal ids stay equal). The
model name is emitted as is only when it matches
`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`, contains no `://` **and** is
allowlisted: the built-in public families (`gpt-*`, `o1*`, `o3*`, `o4*`,
`chatgpt-*`, `claude-*`, `gemini-*`, `text-embedding-*`, `llama*`,
`meta-llama/*`, `mistral*`, `mixtral*`, `codestral*`, `command*`,
`deepseek*`, `qwen*`, `grok*`, `anthropic/*`, `openai/*`, `google/*`) plus
`FABRIC_WIRE_MODEL_ALLOWLIST`.

An exact allowlist entry (no `*`) matches only that name. A `prefix*`
entry matches a name that starts with the prefix **only when the rest is a
version**: split on `-`, `.`, `_`, `:`, `/` or `@`, every part must be
digits or a date (`4`, `3.5`, `20240620`, `2024-08-06`), a short version
token (`4o`, `o1`, `v2`, `8b`, `70b`), or one of a fixed list of model
words (`mini`, `nano`, `turbo`, `preview`, `latest`, `instruct`, `chat`,
`vision`, `audio`, `realtime`, `pro`, `flash`, `lite`, `sonnet`, `opus`,
`haiku`, `thinking`, `coder`, quantisation tags such as `fp8` or `gguf`,
and similar; the full list and test vectors are in
`contracts/capture/v1/fixtures/model-names/model-exposure-v1.json`).
Digits are bounded so a number cannot hide in a version: no part may
contain more than 4 digits in a row (except one 8-digit date such as
`20240620`), and the whole version may contain at most 6 digits besides
that date. `gpt-4o-v919876543210` and `gpt-4o-1234-5678` are therefore
hashed; a real name over the budget, such as `gpt-3.5-turbo-16k-0613`,
needs an exact entry. So
`gpt-4o-mini-2024-07-18` and `claude-3-5-sonnet-20240620` are emitted as
is, while `gpt-4o-acme-claims-triage` or `llama-3-70b-patient-notes` are
not: a fine-tuned or internal deployment name hiding behind a public prefix
is emitted as `m-` + the first 16 hex of its SHA-256, as is any other
non-allowlisted name. Add an exact entry for a deployment name you want to
see in the clear. The Node (`fabricguard`) and `fabric.reconstruct
--model-allowlist` apply the same rule. When you extend the agents' list,
give the Node the same entries — Helm:
`otel-collector.fabric.guard.captureModelAllowlist`; Compose or a
hand-written collector config: `capture_model_allowlist` under
`processors.fabricguard` — or the Node hashes the extra names again.
Response ids are not emitted on OTLP.

Authorization, cookie and API-key headers are not stored or emitted; they
travel only to the provider, as before. Body bytes can still contain
secrets or personal data the agent itself sent or received; treat the
spool, the Node's content queue and the store as sensitive.

## 4. Minimal IAM

Agents need **no** IAM permissions for content.

Fabric Node writer (Helm: the role on the Node service account via IRSA;
Compose: the instance role, or the user of an S3-compatible store):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject"],
      "Resource": "arn:aws:s3:::<bucket>/<prefix><tenant>/evidence/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
      "Resource": "arn:aws:kms:<region>:<account>:key/<key-id>"
    }
  ]
}
```

Trust condition for that role under IRSA, so only the Node's service
account can assume it:

```json
"Condition": {
  "StringEquals": {
    "oidc.eks.<region>.amazonaws.com/id/<id>:sub": "system:serviceaccount:<namespace>:<release>-otel-collector",
    "oidc.eks.<region>.amazonaws.com/id/<id>:aud": "sts.amazonaws.com"
  }
}
```

Reconstruction reader (offline verification):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::<bucket>/<prefix><tenant>/evidence/*"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:<region>:<account>:key/<key-id>"
    }
  ]
}
```

`<prefix>` is the Node's content prefix (`fabric/content/` by default).
Drop the KMS statements for `AES256` or bucket-default SSE-S3. Neither role
needs list, delete, ACL or tagging permissions. Writes are conditional
(`If-None-Match: *`): a store without conditional-write support is retried,
never written unconditionally. To keep every other principal out, add a
bucket-policy `Deny` on `s3:PutObject` to the evidence prefix for all
principals except the Node writer role.

## 5. Verify a run

Export the capture spans from your destination (OTLP/JSON, or the
collector file exporter's output) and run with the reader credentials in
the default AWS chain:

```bash
python -m fabric.reconstruct --spans spans.json \
  --store-uri s3://<bucket>/<prefix> --tenant <tenant> --out report.json
# S3-compatible store (the MinIO evaluation overlay):
python -m fabric.reconstruct --spans spans.json \
  --store-uri s3://fabric-content/fabric/content/ --tenant <tenant> \
  --s3-endpoint-url http://127.0.0.1:9000 --s3-path-style --s3-region us-east-1
# Node file backend: the Node's content directory
python -m fabric.reconstruct --spans spans.json --store-root <content dir> --tenant <tenant>
```

`--tenant` takes the clear tenant id (it names the store prefix); the
report shows it only as its `t-` pseudonym.

*Looking up a run or a source by its clear id.* The report, the spans in
your OTLP destination and the Node's logs carry only pseudonyms, so you map
a clear id to its pseudonym, never the other way round. To check particular
runs, pass the run id you gave `fabric.wire.run()` in the clear with
`--run` (repeatable). `fabric.reconstruct` computes its pseudonym with the
key in the environment variable named by `--id-key-env` (default
`FABRIC_WIRE_ID_KEY`); use the key the agents ran with, or the run is not
found. An `r-` pseudonym or a `trace:` fallback id is matched as given, and
a `source:<source id>:<epoch>` fallback id may name the source in the clear
(it is projected to its `s-` form). Without `--run` every run is reported
by its pseudonym. The key is read and checked on every invocation, with or
without `--run`: a named variable that is set to fewer than 16 bytes is a
usage error (exit `2`).

To find a source, a service or a tenant in the report or in your OTLP
backend, compute its pseudonym with the same key, read from the environment
so it never appears on a command line:

```bash
# FABRIC_WIRE_ID_KEY in the environment (from your secret manager);
# prefix r- (run id), s- (source id), svc- (service.name) or t- (tenant id).
python3 - s- billing-agent <<'PY'
import hashlib, hmac, os, sys
prefix, value = sys.argv[1], sys.argv[2].encode("utf-8")
key = os.environ.get("FABRIC_WIRE_ID_KEY", "").encode("utf-8")
digest = hmac.new(key, value, hashlib.sha256) if key else hashlib.sha256(value)
print(prefix + digest.hexdigest()[:32])
PY
```

Search the report (`"source_id": "s-…"`) or filter your OTLP backend on
`fabric.source_id` / `service.name` with the printed value. Keep a private
table of the pseudonyms of your sources and services next to the key if
operators need it often; the table is as sensitive as the key.

The report judges each `fabric.wire.run()` entry and each run without
entries on its own. It claims completeness only for what the record proves:

- **Scopes (`scopes[]`).** Every entry into a `fabric.wire.run(run_id)`
  block is its own *scope* with a unique `fabric.run.scope_id`, carried on
  its `run_start` and `run_end` heartbeats and on every call started inside
  it. A scope is `complete_for_declared_scope` when both markers arrived,
  every call tagged with it lies between them, and no sequence inside that
  window is missing; a missing sequence inside it makes the scope
  `partial`, and a missing marker (the process died inside the block, or
  the marker could not be spooled) leaves it `unverified`. Reusing a run
  id, serial blocks, nested blocks and concurrent blocks on one source are
  separate scopes and are never paired with each other's markers.
- **Runs with scopes (`runs[]`).** A run's verdict is the worst of its
  observed scopes, and at best `complete_for_observed_scopes`: every scope
  the record holds is complete, and nothing is claimed about a block whose
  markers and calls all died in the agent's memory before reaching the
  spool, because it left no record. A call recorded under the run id
  outside every scope (for example from a task that outlived its block)
  makes the run `unverified`.
- **Runs without scopes** (trace and source runs). The source's capture
  epoch must end with a `final` heartbeat, written when capture closes
  cleanly (`handle.close()` or normal interpreter exit within the shutdown
  budget), and no sequence may be missing from the run's first recorded
  call up to that heartbeat; then the run is `complete_for_declared_scope`.
  A killed process writes no `final` heartbeat, so its runs are
  `unverified` (its spooled records are still delivered on the next start).
  Use `fabric.wire.run()` when the start must be proven too.

Exit code `0` means every reported scope and every run without scopes is
complete (`complete_for_declared_scope`; a run with scopes is then
`complete_for_observed_scopes`); `1` means at least one is `partial` or
`unverified`, or nothing was found; `2` is a usage error. Without store
access the verdict is at best `unverified`.

Heartbeats are counted by their content (source, epoch, kind, run id,
scope id, last sequence), so a record re-sent after a crash counts once.
Each window in the report names its proof in `closed_by` (`run_markers` or
`final_heartbeat`) and, for run scopes, its `scope_id`; a window without
`closed_by` is not proven.

**Content canary after every deployment change.** A healthy Node and a
passing `make verify-prod` (Compose) or Helm rollout do not prove that an
authenticated content upload reaches the store: `verify-prod` only checks
that unauthenticated content is rejected, and the store path also depends
on the bucket policy, the Node's IRSA trust or instance role, KMS grants,
conditional-write support and the store egress peers. Run one canary with
the production agent settings: make a single model call through an
instrumented process inside `fabric.wire.run("fabric-canary-<date>")`, close
capture (`handle.close()` or a normal exit), export its spans from your
destination and run `python -m fabric.reconstruct --run
fabric-canary-<date>` with the reader credentials. Exit code `0` (the run
`complete_for_observed_scopes` with one complete scope) proves the whole
path; `missing_object` or `unverified` names the broken leg without
exposing content.

## 6. Known limits

- **Python only, httpx and httpx2 only.** Calls through the default
  transports of `httpx` and `httpx2` are captured (OpenAI below 3 and
  Anthropic below 1 use httpx; `openai>=3` and `anthropic>=1` use httpx2).
  `requests`, `aiohttp`, `boto3` (including Bedrock), gRPC clients, other
  languages and other processes are not captured.
- **What the spool does not cover.** An exchange still in the agent's
  in-memory window (§1: finished, not yet fsync'd; typically one exchange
  for a few milliseconds, at most the worker queue) is lost with a kill;
  its sequence number makes the gap visible, so the run is `partial` or
  `unverified`, never complete. A full spool drops
  new exchanges as `queue_full` losses. Records stay on the agent host until
  the Node accepts them; a spool directory that is never drained again
  (host decommissioned, directory deleted) never delivers them.
- **Duplicates.** Delivery is at-least-once: after a crash between "sent"
  and "deleted", content and spans are sent again. The Node accepts an
  identical object as a replay; the verifier deduplicates exchanges,
  losses and heartbeats.
- **Streams closed early.** A client that stops reading at `[DONE]` is
  recorded as `closed_early` with the bytes it read; that is not a gap.
  `openai>=3` does this, so its chat streams are normally `closed_early`.
- **Not covered:** the OpenAI SDK's optional aiohttp client
  (`DefaultAioHttpClient`) and any client built on a custom transport that
  is not wrapped in `fabric.wire.WireTransport`. A wrapper takes the base
  class of the transport it wraps, so the official factories accept it:
  `anthropic.DefaultHttpxClient(transport=fabric.wire.WireTransport(httpx2.HTTPTransport()))`
  (likewise `DefaultAsyncHttpxClient` with `AsyncWireTransport`, and the
  `openai` equivalents).
- **Windows** cannot run node mode (the spool needs POSIX `fcntl`).
- **Identifiers.** Run ids, source ids and `service.name` leave the agent
  only as `r-`/`s-`/`svc-` pseudonyms (source ids and `service.name` in the
  clear only with `FABRIC_WIRE_LABELS=clear`); the report shows tenant ids
  as `t-` pseudonyms. A pseudonym hides a label only as well as its key:
  without `FABRIC_WIRE_ID_KEY` anyone who can guess a label can confirm it.
  The tenant id stays clear in content routing and object keys, so all
  labels must still be opaque (§1). An allowlisted model name is copied as
  is (§3).
- **Redirects** are retried, never followed: from a Node endpoint by the
  agent (§1), and from your OTLP destination by the Node's `noredirect`
  middleware (§2). A redirecting proxy on either leg stalls delivery until
  its URL is corrected.
- **Global mode and `tracer_provider=`** bypass the spool: a span or marker
  the agent's provider samples out or loses is not retried, which leaves a
  gap unexplained or a run `unverified`.
- The Node's durable queues protect records only after the Node accepts
  them; delivery to the destination and the store is at least once.
