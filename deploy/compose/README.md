# Fabric Node evaluation harness

This is a small, explicitly non-production setup for trying the Fabric OSS
recorder:

```text
OTLP spans   (4317/4318) -> Fabric Node -> default-deny allowlist -> durable queue -> test sink
wire content (4319)      -> Fabric Node -> fabriccontent (digest, tenant) -> durable queue -> content store
```

It contains only two services:

- `fabric-node`: the current Collector-based recorder implementation;
- `test-sink`: a controlled OTLP/HTTP destination that stores requests on a
  durable Docker volume and returns success only after fsync.

There are no guardrails, prompt-time PII sidecars, judges, red-team runners,
management services, or observability UI.

## LLM wire capture content (spec 048)

Agents in wire-capture node mode POST each stored request/response body to
the separate `otlp/content` receiver on port 4319 (OTLP/HTTP only). The
`logs/content` pipeline runs only `memory_limiter` and the `fabriccontent`
exporter, which checks the closed descriptor, recomputes digest and length,
accepts only `FABRIC_TENANT_ID` (default `evaluation` here) and writes the body
and its descriptor in the SDK store layout. The Node is the only content writer;
agents need no store credentials. `fabric-gate` refuses any config that
routes content into a telemetry pipeline or to the OTLP destination.

| Where content goes | How |
|---|---|
| `fabric-content` volume (`/var/lib/fabric-node/content`) | evaluation default (`make up`); read it with `fabric.reconstruct --store-root` |
| local S3-compatible store (SeaweedFS), SSE-S3, path-style | `make up-s3-eval` (evaluation only, `docker-compose.s3-eval.yml`) |
| S3 / S3-compatible store, server-side encrypted | production: `FABRIC_CONTENT_BACKEND=s3` in `.env` (`docker-compose.content.yml` + `docker-compose.content-s3.yml`, merging `collector-config/collector-content.yaml` + `collector-content-s3.yaml`) |
| `fabric-content` volume in production | `FABRIC_CONTENT_BACKEND=file` plus `FABRIC_CONTENT_REQUIRE_SSE=false` (no server-side encryption; preflight refuses it otherwise, as the Helm shadow-production profile does) |

The production content path is opt-in: without `FABRIC_CONTENT_BACKEND` the
production overlay is telemetry only and starts unchanged with an existing
`.env` (no `FABRIC_TENANT_ID`, no port 4319).

`make up-s3-eval` starts an S3-compatible evaluation store (SeaweedFS,
Apache-2.0, pinned by digest; an SSE-S3 key from `FABRIC_S3_EVAL_SSE_KEK`;
S3 published on `127.0.0.1:9000` only) with three static identities: an
admin used only by the one-shot `s3-eval-init` job, a writer for the Node
(GetObject + PutObject on `fabric-content/fabric/content/*`) and a
GetObject-only reader on the same prefix for reconstruction. `s3-eval-init`
creates the bucket with default SSE-S3 encryption and a bucket policy that
denies `s3:DeleteObject` to everyone. The Node is pointed at
`http://s3-eval:8333` with `use_path_style` and `sse: AES256`. Only the
`fabric-node` service receives the writer keys.

End to end, from a fresh stack to a verdict:

```bash
cd deploy/compose
make up-s3-eval                       # prints the commands below with your ports
# ... run the agent with capture on (docs/wire-capture-deployment.md §1) ...
make export-spans OUT=/tmp/fabric-spans   # the sink's span requests, traces-*.otlp
pip install "singleaxis-fabric[s3]"   # reader only: boto3; agents never need it
AWS_ACCESS_KEY_ID=fabric-reader AWS_SECRET_ACCESS_KEY=fabric-reader-secret \
python -m fabric.reconstruct --spans /tmp/fabric-spans --tenant evaluation \
  --store-uri s3://fabric-content/fabric/content/ \
  --s3-endpoint-url http://127.0.0.1:9000 --s3-path-style --s3-region us-east-1 \
  --wait-for-objects 30 --out report.json
```

`make export-spans` copies the controlled sink's stored span requests (raw
OTLP protobuf, one `traces-<id>.otlp` file per request) out of the
`test-sink` container into `OUT` (default `./fabric-spans`), replacing the
`traces-*.otlp` files already there; `fabric.reconstruct --spans` reads such
a directory directly. Content is delivered to the store separately from the
spans, so an object can still be in flight just after a run:
`--wait-for-objects 30` re-reads absent objects for up to 30 seconds before
reporting them missing.

All store credentials and the SSE key have evaluation-only defaults (see
`.env.example`).

This overlay used MinIO until October 2026. MinIO no longer publishes
community images and the pinned image stopped being pullable, so it was
replaced; the Node only needs S3 with `If-None-Match` writes and SSE, and
any S3-compatible store that has both can stand in. The S3 end-to-end test
(`scripts/tests/test_wire_capture_s3_eval_e2e.py`) runs against this overlay.
It verifies SSE as the store reports it (`ServerSideEncryption: AES256`) and
that the bytes kept below its S3 gateway are not the plaintext; it does not
verify AWS KMS (`aws:kms`) or bucket-key behaviour, which need real S3.

## Start and inspect

```bash
cd deploy/compose
make up
make status
make smoke
```

Evaluation ports are always published on `127.0.0.1`, including the sink's
telemetry-search endpoint. `FABRIC_BIND_ADDR` applies only to the separate VM
overlay; it cannot expose the unauthenticated evaluation harness.

Send OTLP/HTTP to `http://localhost:4318`. The controlled sink exposes:

- `GET http://localhost:8080/health`
- `GET http://localhost:8080/count`

Run the restart/outage qualification:

```bash
make qualify
```

It checks this configuration using fresh exported request markers:

1. accepts a known trace;
2. strips a non-allowlisted marker before export;
3. queues a trace while the destination is unavailable;
4. survives a Fabric Node restart;
5. delivers the queued request after the sink returns.

## Client VM deployment

`docker-compose.production.yml` is an overlay that turns the harness into a
single-node deployment for a plain Linux VM (Docker Engine, no Kubernetes).
The same `fabric-node` image receives authenticated OTLP from agents on the
host, applies the default-deny allowlist, buffers to a durable volume, and
delivers to the customer's OTLP/HTTP backend over HTTPS.

### Prerequisites

- Docker Engine >= 24 with the Compose plugin (`docker compose`) v2.24+
  (the overlay uses `!reset` / `!override` merge tags).
- An OTLP/HTTP `https://` destination operated by the client. Fabric delivers
  records to it; it does not include a monitoring UI. Point the destination
  at whatever backend the client already uses to monitor agentic workflows.

### Quick start

```bash
cd deploy/compose
cp .env.example .env && chmod 0600 .env
# Edit .env:
#   FABRIC_EXPORT_ENDPOINT    = https://<your-otlp-backend>
#   FABRIC_EXPORT_AUTH_HEADER = "Bearer <egress credential>"
#   FABRIC_INGRESS_TOKEN_FILE = ./secrets/ingress.token
#   FABRIC_TENANT_ID          = <tenant id your agents send>
#   FABRIC_SOURCE_ID          = <the agents' source id as it travels: s-<32 hex>>
# Optional content path (spec 048):
#   FABRIC_CONTENT_BACKEND    = s3 (or file with FABRIC_CONTENT_REQUIRE_SSE=false)
#   FABRIC_CONTENT_KEY_FILE   = ./secrets/content.key
printf %s "$(openssl rand -hex 32)" > secrets/ingress.token
sudo chown "$(id -u)":65532 secrets/ingress.token && chmod 0440 secrets/ingress.token
# With the content path:
openssl rand -base64 32 > secrets/content.key
sudo chown "$(id -u)":65532 secrets/content.key && chmod 0440 secrets/content.key
make preflight-prod # validates env, secrets, TLS posture, tooling before deploy
make up-prod        # docker compose -f docker-compose.yml -f docker-compose.production.yml [content overlays] up -d --wait
make verify-prod    # proves health, 401 unauthenticated (spans, and content when enabled), 200 authenticated spans (queue metrics warn-only)
make logs-prod
```

> **File ownership matters.** The image runs as distroless `nonroot`
> (uid/gid 65532) and Compose bind-mounts the token secret and the TLS
> directory with their host owner and mode. A token file owned by your
> login user with mode `0600` is unreadable inside the container and
> `fabric-gate` refuses to start. Make each secret (token, `server.key`)
> owned by the operator who runs `make preflight-prod`, with group 65532
> and mode `0440`: the operator can read it so preflight can check its
> format, the container reads it through the group, and nobody else can.
> Certificates and CA bundles only need to be readable (`0444`).
> `make preflight-prod` checks each mounted file it uses, and reports a
> file it cannot read as a read failure rather than guessing at its
> content. With a layout the operator cannot read (for example owner
> 65532 and `0400`), run the preflight as a user that can.

Use `make up-prod` for startup: it always runs the preflight first. Invoking
the expanded `docker compose ... up` command directly skips the TLS,
bind-address, and disk-headroom checks — though the image's `fabric-gate`
entrypoint still refuses an unsafe token file or a non-traces/logs pipeline
at container start.

Agents on the same host send OTLP to `127.0.0.1:4317` (gRPC) or
`127.0.0.1:4318` (HTTP), and, with the content path enabled, wire-capture
content to `http://127.0.0.1:4319/v1/logs`, with `Authorization: Bearer
<contents of secrets/ingress.token>`. Requests without a valid token are
rejected on every port; there is no unauthenticated fallback. With the
content path, set `FABRIC_TENANT_ID` in `.env` to the tenant id your agents
send (required; the content exporter writes no other tenant, and the shipped
configs allow exactly one: run one Node per tenant).

**Production profile (spec 049 P0-A).** The production configuration is a
production-profile Node. Every agent batch is bound to one tenant and one
source, `FABRIC_TENANT_ID` and `FABRIC_SOURCE_ID`, and the ingress token is
that source's single credential. `fabricguard` refuses a span batch that
names another tenant or source with `INVALID_ARGUMENT` and stamps
`fabric.source.authenticated=true` on every span it admits.
`fabriccontent` drops a content record of another tenant or source and writes
`source_authenticated: true` into every descriptor it stores.

`FABRIC_SOURCE_ID` is the source id as the agents send it. Under their
default pseudonymous labels that is `s-` plus the first 32 hex of
HMAC-SHA256(`FABRIC_WIRE_ID_KEY`, agent `FABRIC_SOURCE_ID`), the `s-`
value on their capture spans. A span that names no source, such as an
application span exported to the same ingress, is dropped on its own; the
capture records next to it are admitted. **Limit:** a production Node binds
exactly one agent source, so agents with different `FABRIC_SOURCE_ID`
values need one Node each.

With the content path, the persistent content queue and the file store are
sealed with the Node key `FABRIC_CONTENT_KEY_FILE`: 32 bytes or their
base64, mounted as a Compose secret, AES-256-GCM. S3 keeps its server-side
encryption.

The Compose stack refuses to start without these settings, and preflight
and `fabric-gate` fail on them too. **Upgrading a Node configured before
P0-A therefore stops at preflight until they are set; the agents are never
affected.**

Agents in node mode now need a capture policy (`FABRIC_CAPTURE_POLICY`) and
`FABRIC_WIRE_ID_KEY` to record content (spec 049 §7.3, superseding spec 048
§1). Without them they record metadata only and report why on every exchange
span.

**Content store.** The production content path is S3 with server-side
encryption: set `FABRIC_CONTENT_BACKEND=s3`, `FABRIC_CONTENT_S3_BUCKET`,
`FABRIC_CONTENT_S3_REGION` and optionally `FABRIC_CONTENT_S3_PREFIX`,
`FABRIC_CONTENT_S3_SSE` (`aws:kms` by default, or `AES256`) and
`FABRIC_CONTENT_S3_KMS_KEY_ID`; `make up-prod` then adds
`docker-compose.content.yml` and `docker-compose.content-s3.yml`.
`FABRIC_CONTENT_BACKEND=file` keeps content on the `fabric-content` volume
(back it up with `fabric-queue`) without server-side encryption; preflight
refuses it unless `FABRIC_CONTENT_REQUIRE_SSE=false` records that the host
disk's encryption is accepted instead, matching the Helm chart's
`content.requireServerSideEncryption` (pinned on in shadow-production). The Node writes with the EC2 instance role
(containers reach IMDSv2 only with a metadata hop limit of 2), or, for an
S3-compatible store, with keys from a credentials file you mount as a
Compose secret and point `AWS_SHARED_CREDENTIALS_FILE` at in a further
override. Never put keys in `.env`. Preflight checks the bucket name,
prefix, region and SSE, and validates `FABRIC_CONTENT_S3_ENDPOINT` like
`FABRIC_EXPORT_ENDPOINT`: an `https://` URL with a valid host and port and
no user info, query or fragment (the value is never printed).
`make verify-prod` checks that unauthenticated content is rejected, not that
an authenticated upload reaches the store; after each deployment change run
the content canary in
[`docs/wire-capture-deployment.md`](../../docs/wire-capture-deployment.md#5-verify-a-run). See
[`docs/wire-capture-deployment.md`](../../docs/wire-capture-deployment.md)
for the minimal Node-writer and reader IAM.

> **Token file format matters.** Write one token with `printf %s` and no
> trailing newline. The shipped patched bearer authenticator rejects malformed
> or multiple entries on startup/reload; the unsafe empty-entry behavior of the
> upstream extension is not the shipped contract. `make preflight-prod` and
> `fabric-gate` also reject unsafe token files. The gate keeps watching during
> execution; an unsafe rotation stops the recorder.

To run the signed release image instead of building locally, verify the
cosign signature per [`docs/verify-release.md`](../../docs/verify-release.md), then set
`FABRIC_NODE_IMAGE=ghcr.io/singleaxis/fabric-otelcol@sha256:<approved-64-hex-digest>` and
`FABRIC_NODE_PULL_POLICY=always` in `.env`.

### Firewall and exposure

OTLP, health (`13133`), and metrics (`8888`) publish on `127.0.0.1` only.
Setting `FABRIC_BIND_ADDR` to a LAN address is an explicit operator choice:
first uncomment the `tls:` stanzas in
`collector-config/collector-production.yaml` (and, with the content path,
the one in `collector-config/collector-content.yaml`), drop `server.crt`/`server.key`
into `./tls` (or set `FABRIC_INGRESS_TLS_DIR`; `server.key` operator-owned,
group 65532, mode `0440`), and open only ports
4317/4318 (and 4319 with the content path) in the host firewall. These ports
publish on `FABRIC_BIND_ADDR`, so `make preflight-prod` fails unless **every**
receiver protocol serving one of them (gRPC, HTTP and the content receiver)
has TLS genuinely enabled (and `fabric-gate` refuses a content receiver
weaker than the telemetry receivers): an uncommented `tls:` mapping with non-empty
`cert_file` and `key_file`. A commented stanza, a bare `tls:`, `tls: {}`,
`tls: null`/`~`, or a stanza missing either file counts as disabled
(fixtures: `fixtures/preflight-tls/`). Preflight also requires every
receiver to authenticate. Bearer tokens over plaintext must stay on
loopback.

### Secure defaults and honest limitations

This VM overlay is a technical example, not the Helm `shadow-production`
contract or a production approval. It does not implement Helm's workload
identity/review metadata or require an image digest and storage-encryption
attestation. Those controls and independent live qualification remain the
operator's responsibility. The local build is useful for evaluation, not a
verified release identity. Static Compose checks are not Docker execution.

- Ingress requires a bearer token (file-backed Compose secret); receiver TLS
  is optional-but-supported and required on every receiver before binding
  beyond loopback.
- Egress requires HTTPS with certificate verification and an Authorization
  header; `insecure_skip_verify` exists only for throwaway dev destinations.
  For a destination with a private CA, put the bundle in `./tls`, uncomment
  `ca_file` in `collector-config/collector-production.yaml` and set
  `FABRIC_EXPORT_CA_FILE=/run/fabric-node/tls/<bundle>`; preflight checks
  that the file exists and is readable by the container user.
- Egress never follows an HTTP redirect: every shipped config attaches the
  distribution's `noredirect` middleware to its OTLP/HTTP exporter, so a
  `3xx` from the destination (or a proxy in front of it) is a retried
  failure; the batch and its Authorization header are never re-sent to the
  redirect target, and a redirect to a login page is never a successful
  export. `fabric-gate` refuses an OTLP/HTTP exporter without it. Configure
  the destination's final `https://` URL; a redirecting URL stalls delivery
  (watch `otelcol_exporter_send_failed_*`). See
  [wire-capture-deployment.md §2](../../docs/wire-capture-deployment.md).
- The collector runs as nonroot with a read-only root filesystem, all
  capabilities dropped, and `no-new-privileges`.
- This deployment configures a durable queue and retry to a client-selected
  destination. `make verify-prod` checks ingress health/authentication and
  available queue metrics; it does not read back destination records or prove
  privacy protection, durable destination persistence, or exactly-once delivery.
  `make qualify` separately exercises the local evaluation sink using fresh
  request markers; it does not qualify the production destination.
- For plaintext development, keep using the evaluation profile (`make up`) on
  a trusted host instead of weakening the production overlay.

### Boot persistence

`restart: unless-stopped` plus an enabled Docker daemon covers reboots:

```bash
sudo systemctl enable docker
```

Sizing, backup/restore of the `fabric-queue` volume, and alerting are covered
in [`docs/operations/dr.md`](../../docs/operations/dr.md).

### Agent-side capture reliability

The recorder's queue is durable, but an agent's OTel SDK has its own in-process
buffer: the default BatchSpanProcessor holds up to 2048 spans and **drops on
overflow**, silently losing telemetry before it reaches Fabric Node. For
audit-grade capture on a bursty agent host, raise the buffer via standard
env vars and always flush on shutdown:

```bash
OTEL_BSP_MAX_QUEUE_SIZE=8192        # default 2048
OTEL_BSP_MAX_EXPORT_BATCH_SIZE=512  # default 512
OTEL_BSP_SCHEDULE_DELAY=2000        # ms; default 5000
```

The Python OTel SDK provider registers a best-effort shutdown handler by
default. Explicitly call `force_flush`/`shutdown` during orderly shutdown
(`examples/reference-agent` shows the pattern), inspect their outcomes, and
allow bounded time to finish. Neither an exit handler nor a flush proves
destination durability; hard termination can lose buffered spans. Inspect
source SDK/exporter diagnostics and any counters that the configured SDK
actually exposes. `otelcol_*` metrics belong to the Collector, not the Python
agent: monitor `otelcol_receiver_refused_spans` on the Node for admission
pressure. A healthy Node cannot detect spans lost before they reach it.

## Honest limitations

This harness is plaintext and unauthenticated. It is for local evaluation
only. Use the client-VM overlay above or the Helm `shadow-production` profile
across a trust boundary.

The test sink's `200` response has a deliberately strong, test-specific
meaning: that request was fsynced to its Docker volume. Fabric cannot infer
the same meaning from an arbitrary OTLP destination. In production,
distinguish Collector acceptance, local queueing, destination
acknowledgement, and destination durable persistence.

The queue is at least once, not exactly once. Duplicate delivery remains
possible after ambiguous acknowledgements, and the queue is not an
authoritative evidence store.

## Remove evaluation data

```bash
make down        # keeps queue and sink volumes
make reset       # deletes this Compose project's evaluation volumes
```

The S3 evaluation overlay has its own pair, which also covers the store
volume (`s3-eval-data`) that the base project does not declare:

```bash
make down-s3-eval    # stops it, keeping the store, queue, content and sink volumes
make reset-s3-eval   # deletes them all, including every stored object
```

Use the same `COMPOSE` (for example a `-p` project name) as for
`make up-s3-eval`. `make down` and `make reset` read only the base file:
they do not know the overlay's store service or its `s3-eval-data` volume.
