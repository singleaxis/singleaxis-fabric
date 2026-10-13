# Deploying LLM wire capture

This guide is for an operator turning on LLM wire capture
([spec 042](../specs/042-llm-wire-capture-and-reconstruction.md) with the
delivery changes of [spec 043](../specs/043-node-content-delivery-and-agent-spool.md),
both draft) for a Python agent. Capture copies the exact request and
response bytes of each model call and records one metadata-only span per
call. Both go to a Fabric Node you run; the Node writes the bytes to a store
you own and forwards the spans to an OTLP destination you choose.

Capture does not change the agent's requests or responses, and a capture
failure never raises into the agent. On the call path it adds only bounded
in-process work (no disk, store or network I/O; the latency budgets in spec
042 §4.10 are tested), and response chunks reach the client as soon as the
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
| `FABRIC_WIRE_CONTENT_ENDPOINT` | node mode | Full URL of the Node's content receiver, used as given (`https://node:4319/v1/logs`). Setting it selects node mode. A URL with user info, a query or a fragment is rejected without echoing it. |
| `FABRIC_WIRE_STORE` | no | Unset: node mode when a content endpoint is set, else metadata only (no bytes stored; runs can only be `unverified`). `node`: node mode explicitly. `file:///absolute/dir`: the agent writes a local store itself (development, offline or single-host; refused together with a content endpoint). `s3://…` is **refused**: S3 is written by the Node. |
| `FABRIC_TENANT_ID` | node and file modes | Tenant id sent with every content record; the Node writes only tenants on its allowlist. Objects land at `<prefix><tenant>/evidence/<object-id>`. A path prefix, not an access boundary. |
| `FABRIC_WIRE_SPOOL_DIR` | node mode | Absolute directory for the durable spool (created `0700`; an existing one must be owned by the agent's uid and not a symlink). Optional in file mode, where it enables the same delivery path. |
| `FABRIC_WIRE_SPOOL_MAX_BYTES` | no | Spool bound, default 1 GiB, minimum `2 × FABRIC_WIRE_MAX_BODY_BYTES + 1 MiB`. When full, new exchanges are dropped and recorded as `queue_full` losses; the host is unaffected. |
| `FABRIC_WIRE_MODEL_ALLOWLIST` | no | Comma-separated exact model names or `prefix*` entries emitted as is, in addition to the built-in public families (§3). |
| `FABRIC_SOURCE_ID` | no | Opaque id of this capture source. Default `wire-` + 16 hex derived from host name and `service.name`. |
| `FABRIC_WIRE_ENDPOINTS` | no | JSON array of extra endpoint matchers (vLLM, Ollama, an internal proxy). OpenAI, Anthropic and Azure OpenAI are matched by default. |
| `FABRIC_WIRE_MAX_BODY_BYTES`, `FABRIC_WIRE_QUEUE_MAX_ITEMS` | no | Per-body retention cap (default 8 MiB; at most 63 MiB in node mode so one record fits the Node's 64 MiB request bound) and worker queue length (default 256). |
| `FABRIC_WIRE_TRACER` | no | `private` (default, and required in node mode). `global` sends exchange spans through the agent's own provider without the spool; it is refused in node mode (see "Global mode" below). |
| `FABRIC_WIRE_STORE_SSE`, `FABRIC_WIRE_STORE_KMS_KEY_ID` | — | **Removed.** Setting either is an error: encryption is configured on the Fabric Node. |
| `OTEL_SERVICE_NAME` | no | The capture spans' one resource attribute (must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, else `fabric-wire`); `OTEL_RESOURCE_ATTRIBUTES` and resource detectors are ignored. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` | yes | Node span ingress. Over HTTP the traces-specific variable takes the full URL (`https://node:4318/v1/traces`) and the general one gets `/v1/traces` appended; over gRPC use `https://node:4317`. User info, query or fragment is rejected. |
| `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` / `OTEL_EXPORTER_OTLP_PROTOCOL` | no | `http/protobuf` (default, port 4318) or `grpc` (port 4317). The content endpoint is always OTLP/HTTP protobuf. |
| `OTEL_EXPORTER_OTLP_CERTIFICATE` | over TLS | CA bundle that signs the Node's server certificate. |
| `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_KEY` | Helm `shadow-production` | Client certificate and key for mTLS ingress (spans and content). |
| `OTEL_EXPORTER_OTLP_HEADERS` | Compose production | `Authorization=Bearer%20<token>` for bearer ingress (spans and content). |

Span settings resolve `OTEL_EXPORTER_OTLP_TRACES_*` before the general
`OTEL_EXPORTER_OTLP_*` variables; the content client resolves
`OTEL_EXPORTER_OTLP_LOGS_{HEADERS,CERTIFICATE,CLIENT_CERTIFICATE,CLIENT_KEY,TIMEOUT}`
before the same general variables, so one set of general variables
configures both. An unreadable TLS file fails installation.

Invalid configuration installs nothing and logs one warning naming only the
error class; the agent runs unchanged. Fabric never logs environment
values, endpoint URLs, header values, TLS file contents or exporter
exception messages (spec 043 §8).

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

**Identifiers must not contain personal data.** Run ids
(`fabric.wire.run(...)`), `FABRIC_SOURCE_ID`, `FABRIC_TENANT_ID` and
`OTEL_SERVICE_NAME` are checked for shape only and are visible to every
reader of the telemetry or the store layout. Use opaque or pseudonymous
values, never patient, customer or user identifiers.

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
`fabricguard`, and `--set` overrides are refused.

| Deployment | Ingress authentication (4317, 4318 and 4319 alike) | Content store | Agent settings |
|---|---|---|---|
| Helm `shadow-production` ([deployment.md](deployment.md)) | TLS with a verified client certificate; NetworkPolicy admits only labelled agent namespaces to all three ports | `otel-collector.content.backend=s3` with `content.s3.sse` (`aws:kms` + key, or `AES256`), required by the profile; the Node writes with its IRSA role. The file backend is refused in this profile. | `https://` endpoints, `OTEL_EXPORTER_OTLP_CERTIFICATE`, `..._CLIENT_CERTIFICATE`, `..._CLIENT_KEY`. A bearer header alone is refused. |
| Compose production overlay ([deploy/compose](../deploy/compose/README.md)) | Bearer token; ports bound to `127.0.0.1` unless every published receiver has TLS (preflight) | `fabric-content` volume by default, or `FABRIC_CONTENT_BACKEND=s3` (bucket, region and SSE on the Node; instance role or a credentials-file secret) | `http://127.0.0.1:4318` and `:4319`, `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20<token>`. Use `https://` and receiver TLS before leaving the host. |
| Compose evaluation + MinIO (`make up-minio`) | None (loopback evaluation only) | Local MinIO bucket with SSE-S3, path-style addressing, Node-only writer keys | `http://127.0.0.1:4318` and `:4319`, `FABRIC_TENANT_ID=evaluation` |

**Helm.** Enable content with `otel-collector.content.enabled=true`,
`content.allowedTenants`, `content.backend` and the backend settings. The
chart refuses to render without allowed tenants or a backend, with an s3
backend lacking a valid bucket, a KMS key without `aws:kms`, an endpoint
with credentials, query or fragment, or a memory limiter at or above the
container memory limit. `shadow-production` also refuses missing SSE, the
file backend, an `http://` store endpoint, and missing
`networkPolicy.contentEgress` peers for the store (S3 endpoint CIDRs or VPC
endpoint, plus STS for IRSA). Put the Node writer role on
`otel-collector.serviceAccount.annotations` (`eks.amazonaws.com/role-arn`);
the pod still mounts no Kubernetes API token (the IRSA webhook projects its
own STS-audience token). For an S3-compatible store without workload
identity, name an operator-created Secret in `content.s3.credentialsSecret`
(values never hold keys). The content queue lives on the queue PVC
(`<persistence.directory>/content-queue`); size the PVC for
`content.queue.queueSize × 64 MiB` on top of the telemetry queue.

**Compose.** The image runs as uid/gid 65532. Make the token file and any
TLS key owned by the operator who runs `make preflight-prod`, with group
65532 and mode `0440`. Compose publishes 4317, 4318 and 4319 on
`FABRIC_BIND_ADDR`; beyond loopback, preflight requires that every receiver
protocol serving one of them has TLS genuinely enabled (an uncommented
`tls:` mapping with non-empty `cert_file` and `key_file`; a commented,
empty, `{}` or `null` stanza counts as disabled), and it always requires
every receiver to authenticate. It also checks `FABRIC_TENANT_ID` and, for
S3, the bucket, prefix, region, an `https://` endpoint without credentials,
and SSE.

## 3. What is streamed and who can read it

| Data | Path | Who can read it | Controlled by |
|---|---|---|---|
| Span metadata: exchange, run, scope and source ids, sequence numbers, heartbeat kinds, body SHA-256 digests, store object ids (uuid4), API, response state, HTTP status, error class name, model name (see below), finish reasons (closed list), token counts; trace id, span id and flags of the agent's current span (its trace state and baggage are not copied); resource `service.name` | agent spool → OTLP 4317/4318 → Fabric Node (`fabricguard`, queued on disk) → your OTLP destination | Anyone with access to the agent's spool directory, the Node host or queue volume, and every reader of the destination | Node ingress auth (mTLS or bearer), host access, destination ACLs and retention |
| Request and response bytes (prompts, completions, tool arguments and results, anything the provider echoes) and their descriptor JSON | agent spool → OTLP/HTTP 4319 → Fabric Node content queue → your store. Never sent to the OTLP destination | In transit: the agent host's spool directory (`0600`/`0700`) and the Node's content-queue volume. At rest: principals with `s3:GetObject` on the evidence prefix **and** `kms:Decrypt` on the key, or filesystem users who can read the Node's content directory | Agent host access; Node host and volume access; bucket policy, IAM and KMS key policy; filesystem permissions (files `0600`, directories `0700`) |
| Reconstruction report (`python -m fabric.reconstruct`) | written where the operator runs it | Whoever receives the file | File permissions. It holds run, scope, source, exchange and store object ids, digests, counts, model names (same rule as spans), pseudonyms of provider ids, the span file paths given on the command line and the tenant id; never message content and never the resolved store location of an object |
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
`FABRIC_WIRE_MODEL_ALLOWLIST`. Any other model string is emitted as `m-` +
the first 16 hex of its SHA-256, so fine-tuned or internal deployment names
stay pseudonymous unless you allowlist them. `fabric.reconstruct
--model-allowlist` applies the same rule. Response ids are not emitted on
OTLP.

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

Exit code `0` means every reported run is `complete_for_declared_scope`;
`1` means at least one run is `partial` or `unverified`, or none was
found; `2` is a usage error. Without store access the verdict is at best
`unverified`.

A run is `complete_for_declared_scope` only when its end is proven and no
sequence is missing in its scope:

- **Runs wrapped in `fabric.wire.run(run_id)`.** Every entry into the block
  is its own *scope* with a unique `fabric.run.scope_id`, carried on its
  `run_start` and `run_end` heartbeats and on every call started inside it.
  A scope is closed when both its markers arrived; its window is the
  sequences between them. The run is complete when every scope is closed,
  every call of the run belongs to one of its scopes, and no sequence
  inside any scope window is missing. Reusing a run id, serial blocks,
  nested blocks and concurrent blocks on one source are separate scopes and
  are never paired with each other's markers. A missing `run_end` (the
  process died inside the block, or the marker could not be spooled) leaves
  the run `unverified`, and so does a call recorded under the run id
  outside every scope (for example from a task that outlived the block).
- **Other runs** (trace and source runs). The source's capture epoch must
  end with a `final` heartbeat, written when capture closes cleanly
  (`handle.close()` or normal interpreter exit within the shutdown budget),
  and no sequence may be missing from the run's first recorded call up to
  that heartbeat. A killed process writes no `final` heartbeat, so its
  runs are `unverified` (its spooled records are still delivered on the
  next start). Use `fabric.wire.run()` when the start must be proven too.

Heartbeats are counted by their content (source, epoch, kind, run id,
scope id, last sequence), so a record re-sent after a crash counts once.
Each window in the report names its proof in `closed_by` (`run_markers` or
`final_heartbeat`) and, for run scopes, its `scope_id`; a window without
`closed_by` is not proven.

## 6. Known limits

- **Python only, httpx and httpx2 only.** Calls through the default
  transports of `httpx` and `httpx2` are captured (OpenAI below 3 and
  Anthropic below 1 use httpx; `openai>=3` and `anthropic>=1` use httpx2).
  `requests`, `aiohttp`, `boto3` (including Bedrock), gRPC clients, other
  languages and other processes are not captured.
- **What the spool does not cover.** An exchange still in the agent's
  in-memory worker queue (not yet spooled) is lost with a crash or kill;
  its sequence number makes the gap visible (`partial`). A full spool drops
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
- **Identifiers are shape-checked only** (see §1). An allowlisted model
  name is copied as is (§3).
- **Global mode and `tracer_provider=`** bypass the spool: a span or marker
  the agent's provider samples out or loses is not retried, which leaves a
  gap unexplained or a run `unverified`.
- The Node's durable queues protect records only after the Node accepts
  them; delivery to the destination and the store is at least once.
