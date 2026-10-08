# Deploying LLM wire capture

This guide is for an operator turning on LLM wire capture
([spec 042](../specs/042-llm-wire-capture-and-reconstruction.md), draft) for
a Python agent. Capture copies the exact request and response bytes of each
model call to a store you own and sends one metadata-only span per call
through a Fabric Node to an OTLP destination you choose.

Capture does not change the agent's requests or responses, and a capture
failure never raises into the agent. On the call path it adds only
bounded in-process work (no store or network I/O; the latency budgets in
spec 042 §4.10 are tested), and response chunks reach the client as soon as
the transport yields them. It does wait in three places, all bounded:
`flush()` and `close()` when you call them, and the exit handler, which
holds interpreter exit for at most `shutdown_timeout_s` (default 2 s) while
it drains and exports. Export never runs on the exiting thread: if a helper
thread cannot be started, the export is skipped and the record's tail stays
unproven instead.

```text
agent process ──(body bytes)──────────────────────────────► your bucket / directory
      │
      └──(metadata spans, OTLP)──► Fabric Node ──► your OTLP destination
```

## 1. Activate capture in the agent

Install the SDK with the OTLP extra into the agent's environment, plus
`boto3` for an S3 store and `opentelemetry-exporter-otlp-proto-grpc` only if
you export over gRPC:

```bash
pip install "singleaxis-fabric[otlp]" boto3
```

Capture is never enabled by installing the package. Turn it on per process
with the autoload directory and one flag:

```bash
export PYTHONPATH="$(python -m fabric.wire --print-autoload-path)${PYTHONPATH:+:$PYTHONPATH}"
export FABRIC_WIRE_AUTOLOAD=1
```

| Variable | Required | Meaning |
|---|---|---|
| `FABRIC_WIRE_STORE` | for body capture | `s3://bucket/prefix` or `file:///absolute/dir`. Unset = metadata only (no bytes stored, runs can only be `unverified`). Without a prefix, S3 uses `fabric/content/`. |
| `FABRIC_TENANT_ID` | with a store | Namespace inside the store: objects land at `<prefix><tenant>/evidence/<object-id>`. A path prefix, not an access boundary. |
| `FABRIC_SOURCE_ID` | no | Opaque id of this capture source. Default `wire-` + 16 hex derived from host name and `service.name`. |
| `FABRIC_WIRE_STORE_SSE` | no | `AES256` or `aws:kms` (S3 only). |
| `FABRIC_WIRE_STORE_KMS_KEY_ID` | no | KMS key for `aws:kms`; any other combination is rejected. |
| `FABRIC_WIRE_ENDPOINTS` | no | JSON array of extra endpoint matchers (vLLM, Ollama, an internal proxy). OpenAI, Anthropic and Azure OpenAI are matched by default. |
| `FABRIC_WIRE_MAX_BODY_BYTES`, `FABRIC_WIRE_QUEUE_MAX_ITEMS` | no | Per-body retention cap (default 8 MiB) and worker queue length (default 256). |
| `FABRIC_WIRE_TRACER` | no | `private` (default): capture spans use their own always-on provider and never touch the agent's OTel setup. `global`: exchange spans use the agent's provider; see "Global mode" below. |
| `OTEL_SERVICE_NAME` | no | Private provider only: its one resource attribute (must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, else `fabric-wire`); `OTEL_RESOURCE_ATTRIBUTES` and resource detectors are ignored. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` | yes | Fabric Node address. Over HTTP the traces-specific variable takes the full URL (`https://node:4318/v1/traces`) and the general one gets `/v1/traces` appended; over gRPC use `https://node:4317`. A URL with user info (`user:pass@`), a query string or a fragment is rejected (capture is not installed; one warning). Without either variable, spans are not exported and a warning is logged. |
| `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` / `OTEL_EXPORTER_OTLP_PROTOCOL` | no | `http/protobuf` (default, port 4318) or `grpc` (port 4317). Any other value disables capture with one warning. |
| `OTEL_EXPORTER_OTLP_CERTIFICATE` | over TLS | CA bundle that signs the Node's server certificate. |
| `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_KEY` | Helm `shadow-production` | Client certificate and key for mTLS ingress. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Compose production | `Authorization=Bearer%20<token>` for bearer ingress. |

Invalid configuration installs nothing and logs one warning naming only the
error class; the agent runs unchanged. Traces-specific
`OTEL_EXPORTER_OTLP_TRACES_*` variables override the general ones; over gRPC
the CA, client certificate and client key are each resolved this way on
their own.

**Global mode** (`FABRIC_WIRE_TRACER=global`). Exchange spans go through
the agent's own tracer provider: its resource attributes, sampler, span
processors, exporter, destination and exporter logging, none of which
Fabric controls. They share that provider's queue with the agent's spans.
Loss and heartbeat records use the private always-on provider when an OTLP
endpoint variable is set; without one they also go through the agent's
provider. `flush()` also force-flushes the agent's provider within the same
deadline and returns `False` when that does not finish in time; `True`
does not confirm that the spans reached a Fabric Node. A loss or heartbeat
record that the agent's sampler drops makes `flush()` return `False` and
logs one warning. Use global mode only when the agent's provider exports
through a Fabric Node. Set `OTEL_SERVICE_NAME` to a value matching
`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`: the OTel default
(`unknown_service:python`) does not match, so `fabricguard` drops
`service.name` from every resource group that holds a capture span, and the
application spans batched with them lose their resource attributes too.

**Identifiers must not contain personal data.** Run ids
(`fabric.wire.run(...)`), `FABRIC_SOURCE_ID`, `FABRIC_TENANT_ID` and
`OTEL_SERVICE_NAME` are checked for shape only and are visible to every
reader of the telemetry or the store layout. Use opaque or pseudonymous
values, never patient, customer or user identifiers.

## 2. Run a Fabric Node

| Deployment | Ingress authentication | Agent settings |
|---|---|---|
| Helm `shadow-production` ([deployment.md](deployment.md)) | TLS with a verified client certificate; NetworkPolicy admits only labelled agent namespaces | `https://` endpoint, `OTEL_EXPORTER_OTLP_CERTIFICATE`, `..._CLIENT_CERTIFICATE`, `..._CLIENT_KEY`. A bearer header alone is refused. |
| Compose production overlay ([deploy/compose](../deploy/compose/README.md)) | Bearer token; OTLP bound to `127.0.0.1` unless you enable receiver TLS | `http://127.0.0.1:4318`, `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20<token>`. Use `https://` and receiver TLS before leaving the host. |

Both run `fabricguard` before the durable queue. On capture spans it admits
only the spec 042 keys, each with a value check, and drops everything else.
When a resource group holds any capture span, the whole group gets the
strict capture policy: its resource keeps only a valid `service.name` and
its scopes keep no attributes, so application spans batched with capture
spans in global mode cannot carry shared metadata past it. `fabric-gate`
refuses to start a traces or logs pipeline that does not run `fabricguard`,
and refuses every `--set` argument (`--set k=v` and `--set=k=v`), because
the collector would apply it after validation; put overrides in an
additional `--config` file, which the gate validates like the others.

The Compose image runs as uid/gid 65532. Make the token file and any TLS
key owned by the operator who runs `make preflight-prod`, with group 65532
and mode `0440` (`sudo chown "$(id -u)":65532 <file> && chmod 0440 <file>`):
preflight can then read and check the token, the container reads it through
the group, and nobody else can. Preflight reports a file it cannot read as a
read failure. Compose publishes both OTLP ports on `FABRIC_BIND_ADDR`, so
beyond loopback preflight requires a `tls:` stanza on every configured
receiver (gRPC and HTTP).

## 3. What is streamed and who can read it

| Data | Path | Who can read it | Controlled by |
|---|---|---|---|
| Span metadata: exchange, run and source ids, sequence numbers, heartbeat kinds, body SHA-256 digests, store object ids (uuid4), API, response state, HTTP status, error class name, model name (see below), finish reasons (closed list), token counts; trace id, span id and flags of the agent's current span (its trace state and baggage are not copied); resource `service.name` (private provider) or the agent's resource (global mode) | agent → OTLP → Fabric Node (filtered, queued on disk) → your OTLP destination | Anyone with access to the Node host or queue volume, and every reader of the destination | Node ingress auth (mTLS or bearer), host access, destination ACLs and retention |
| Request and response bytes (prompts, completions, tool arguments and results, anything the provider echoes) and their descriptor JSON | agent → your store directly; never sent over OTLP or through the Node | Principals with `s3:GetObject` on the evidence prefix **and** `kms:Decrypt` on the key; or filesystem users who can read the directory | Bucket policy and IAM, KMS key policy, filesystem permissions (new local files `0600`, evidence directories `0700`) |
| Reconstruction report (`python -m fabric.reconstruct`) | written where the operator runs it | Whoever receives the file | File permissions. It holds run, source, exchange and store object ids, digests, counts, model names (same rule as spans), pseudonyms of provider ids, the span file paths given on the command line and the tenant id; never message content and never the resolved store location of an object |
| Fabric warnings | agent's own logging | Agent log readers | Fabric's own messages: fixed text and exception class names. Log records the OTLP exporter writes during Fabric's private-provider exports are reduced to status codes and exception class names. In global mode the agent's exporter logs as the agent configured it |

Message content (prompts, completions, tool arguments and results) never
goes on OTLP or into the report. Two values that come from the provider's
response can: the model name, kept only when it matches
`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` and contains no `://` (so no `@`, no
URL, no credentials; otherwise omitted); and, in the report only, response,
previous-response and tool-call ids, as `p-` + the first 16 hex of their
SHA-256 (equal ids stay equal, so correlation survives). A model name that
matches the pattern is copied as is, so a provider that returns sensitive
text shaped like a model name would expose it. Response ids are not
emitted on OTLP.

Authorization, cookie and API-key headers are not stored or emitted; they
travel only to the provider, as before. Body bytes can still contain
secrets or personal data the agent itself sent or received; treat the store
as sensitive.

## 4. Minimal IAM

Agent (writes bodies; reads back only to verify an existing object):

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

`<prefix>` is the path in `FABRIC_WIRE_STORE` with a trailing slash
(`fabric/content/` by default). Drop the KMS statement for `AES256` or
bucket-default SSE-S3. Neither role needs list, delete, ACL or tagging
permissions. boto3 uses its standard credential chain and region
(`AWS_REGION`, instance or workload identity).

## 5. Verify a run

Export the capture spans from your destination (OTLP/JSON, or the
collector file exporter's output) and run:

```bash
python -m fabric.reconstruct --spans spans.json \
  --store-uri s3://<bucket>/<prefix> --tenant <tenant> --out report.json
```

Exit code `0` means every reported run is `complete_for_declared_scope`;
`1` means at least one run is `partial` or `unverified`, or none was
found; `2` is a usage error. Without store access the verdict is at best
`unverified`.

A run is `complete_for_declared_scope` only when its end is proven and no
sequence is missing in its scope:

- **Runs wrapped in `fabric.wire.run(run_id)`.** The block writes a
  `run_start` heartbeat on entry and a `run_end` heartbeat on exit. The run
  is complete when, on each source it used, every `run_start` has its
  `run_end` and no sequence between them is missing (lost, with or without a
  loss record). A missing `run_end` (the process died inside the block)
  leaves the run `unverified`, and so does a call recorded under the run id
  before its first `run_start` or after its last `run_end` (for example
  from a task that outlived the block).
- **Other runs** (trace and source runs). The source's capture epoch must
  end with a `final` heartbeat, written when capture closes cleanly
  (`handle.close()` or normal interpreter exit within the shutdown budget),
  and no sequence may be missing from the run's first recorded call up to
  that heartbeat. A killed process writes no `final` heartbeat, so its
  runs are `unverified`. Such a run's scope starts at its first recorded
  call: a lost earlier call that is not adjacent to it shows in the
  report's `sources[].missing_sequences` and in the runs around it, not in
  this run. Use `fabric.wire.run()` when the start must be proven too.

Heartbeats are counted by their content (source, epoch, kind, run id, last
sequence), so a heartbeat re-sent after a failed export counts once.
Periodic heartbeats reveal missing sequences but never prove an end. Each
window in the report names its proof in `closed_by` (`run_markers` or
`final_heartbeat`); a window without `closed_by` is not proven.

## 6. Known limits

- **Python only, httpx and httpx2 only.** Calls through the default
  transports of `httpx` and `httpx2` are captured (OpenAI below 3 and
  Anthropic below 1 use httpx; `openai>=3` and `anthropic>=1` use httpx2).
  `requests`, `aiohttp`, `boto3` (including Bedrock), gRPC clients, other
  languages and other processes are not captured.
- **In-memory buffering.** Exchanges wait in memory for the store write
  and span export. A crash, kill or exit past the shutdown deadline
  (default 2 s; programmatic `shutdown_timeout_s` only, no environment
  variable) loses what is in flight, and then no `final` heartbeat is
  written. Every call has a sequence number, so a lost call inside a run's
  scope makes it `partial`, and a run whose end is unproven is `unverified`
  (§5). Loss records explain a gap's cause when one could be emitted; an
  exchange span evicted from a full export batch queue gets none and stays
  an unexplained gap.
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
- **Identifiers are shape-checked only** (see §1). The model name is
  pattern-checked, not proven free of sensitive text (§3).
- **Explicit `tracer_provider=`.** `fabric.wire.install(tracer_provider=X)`
  sends exchange, loss and heartbeat spans through `X`. If `X` samples out
  a loss or heartbeat record, `flush()` returns `False` and one warning is
  logged. The record is not retried: a sampled-out loss record leaves its
  gap unexplained, and a sampled-out `final` or `run_end` heartbeat leaves
  the run `unverified`.
- The Node's durable queue protects records only after the Node accepts
  them; delivery to the destination is at least once.
