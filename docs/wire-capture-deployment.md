# Deploying LLM wire capture

This guide is for an operator turning on LLM wire capture
([spec 042](../specs/042-llm-wire-capture-and-reconstruction.md), draft) for
a Python agent. Capture copies the exact request and response bytes of each
model call to a store you own and sends one metadata-only span per call
through a Fabric Node to an OTLP destination you choose. It never alters,
blocks or delays the agent's calls, and a capture failure never raises into
the agent.

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
| `FABRIC_WIRE_TRACER` | no | `private` (default): capture spans use their own always-on provider and never touch the agent's OTel setup. `global`: exchange spans use the agent's provider and sampler; loss and heartbeat records still use the private path, so also set the OTLP endpoint below. |
| `OTEL_SERVICE_NAME` | no | The only resource attribute on capture spans (must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, else `fabric-wire`). `OTEL_RESOURCE_ATTRIBUTES` is ignored. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` | yes | Fabric Node address. Over HTTP the traces-specific variable takes the full URL (`https://node:4318/v1/traces`) and the general one gets `/v1/traces` appended; over gRPC use `https://node:4317`. Without either, spans are not exported and a warning is logged. |
| `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` / `OTEL_EXPORTER_OTLP_PROTOCOL` | no | `http/protobuf` (default, port 4318) or `grpc` (port 4317). Any other value disables capture with one warning. |
| `OTEL_EXPORTER_OTLP_CERTIFICATE` | over TLS | CA bundle that signs the Node's server certificate. |
| `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_KEY` | Helm `shadow-production` | Client certificate and key for mTLS ingress. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Compose production | `Authorization=Bearer%20<token>` for bearer ingress. |

Invalid configuration installs nothing and logs one warning; the agent runs
unchanged. Traces-specific `OTEL_EXPORTER_OTLP_TRACES_*` variables override
the general ones.

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
only the spec 042 keys, each with a value check, and drops everything else;
`fabric-gate` refuses to start a pipeline that does not run `fabricguard`.
The Compose image runs as uid/gid 65532: make the token file and any TLS
key readable by it (`chown root:65532`, `chmod 0440`); `make preflight-prod`
checks this.

## 3. What is streamed and who can read it

| Data | Path | Who can read it | Controlled by |
|---|---|---|---|
| Span metadata: exchange, run and source ids, sequence numbers, body SHA-256 digests, store object ids (uuid4), API, response state, HTTP status, error class name, model name, finish reasons (closed list), token counts, `service.name` | agent → OTLP → Fabric Node (filtered, queued on disk) → your OTLP destination | Anyone with access to the Node host or queue volume, and every reader of the destination | Node ingress auth (mTLS or bearer), host access, destination ACLs and retention |
| Request and response bytes (prompts, completions, tool arguments and results, anything the provider echoes) and their descriptor JSON | agent → your store directly; never sent over OTLP or through the Node | Principals with `s3:GetObject` on the evidence prefix **and** `kms:Decrypt` on the key; or filesystem users who can read the directory | Bucket policy and IAM, KMS key policy, filesystem permissions (new local files `0600`, evidence directories `0700`) |
| Reconstruction report (`python -m fabric.reconstruct`) | written where the operator runs it | Whoever receives the file | File permissions. It holds ids, digests, model names and resolved store locations, never message content |
| Fabric warnings | agent's own logging | Agent log readers | Fixed text and exception class names only |

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

## 6. Known limits

- **Python only, httpx and httpx2 only.** Calls through the default
  transports of `httpx` and `httpx2` are captured (OpenAI below 3 and
  Anthropic below 1 use httpx; `openai>=3` and `anthropic>=1` use httpx2).
  `requests`, `aiohttp`, `boto3` (including Bedrock), gRPC clients, other
  languages and other processes are not captured.
- **In-memory buffering.** Exchanges wait in memory for the store write
  and span export. A crash, kill or exit past the shutdown deadline
  (default 2 s) loses what is in flight. Losses are never silent: every
  call has a sequence number, so a lost call shows as a sequence or tail
  gap and the run is `partial` or `unverified`, never complete. Loss
  records explain a gap's cause when one could be emitted.
- **Streams closed early.** A client that stops reading at `[DONE]` is
  recorded as `closed_early` with the bytes it read; that is not a gap.
  `openai>=3` does this, so its chat streams are normally `closed_early`.
- **Not covered:** the OpenAI SDK's optional aiohttp client
  (`DefaultAioHttpClient`) and any client built on a custom transport that
  is not wrapped in `fabric.wire.WireTransport`.
- **Identifiers are shape-checked only** (see §1).
- The Node's durable queue protects records only after the Node accepts
  them; delivery to the destination is at least once.
