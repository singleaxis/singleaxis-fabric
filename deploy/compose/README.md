# Fabric Node evaluation harness

This is a small, explicitly non-production setup for trying the Fabric OSS
recorder:

```text
OTLP -> Fabric Node -> default-deny allowlist -> durable queue -> test sink
```

It contains only two services:

- `fabric-node`: the current Collector-based recorder implementation;
- `test-sink`: a controlled OTLP/HTTP destination that stores requests on a
  durable Docker volume and returns success only after fsync.

There are no guardrails, prompt-time PII sidecars, judges, red-team runners,
management services, or observability UI.

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
printf %s "$(openssl rand -hex 32)" > secrets/ingress.token && chmod 0600 secrets/ingress.token
make preflight-prod # validates env, secrets, TLS posture, tooling before deploy
make up-prod        # docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --wait
make verify-prod    # proves health, 401 unauthenticated, 200 authenticated (queue metrics warn-only)
make logs-prod
```

Use `make up-prod` for startup: it always runs the preflight first. Invoking
the expanded `docker compose ... up` command directly skips the TLS,
bind-address, and disk-headroom checks — though the image's `fabric-gate`
entrypoint still refuses an unsafe token file or a non-traces/logs pipeline
at container start.

Agents on the same host send OTLP to `127.0.0.1:4317` (gRPC) or
`127.0.0.1:4318` (HTTP) with `Authorization: Bearer <contents of
secrets/ingress.token>`. Requests without a valid token are rejected; there is
no unauthenticated fallback.

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
`collector-config/collector-production.yaml`, drop `server.crt`/`server.key`
into `./tls` (or set `FABRIC_INGRESS_TLS_DIR`), and open only ports
4317/4318 in the host firewall. Bearer tokens over plaintext must stay on
loopback.

### Secure defaults and honest limitations

This VM overlay is a technical example, not the Helm `shadow-production`
contract or a production approval. It does not implement Helm's workload
identity/review metadata or require an image digest and storage-encryption
attestation. Those controls and independent live qualification remain the
operator's responsibility. The local build is useful for evaluation, not a
verified release identity. Static Compose checks are not Docker execution.

- Ingress requires a bearer token (file-backed Compose secret); receiver TLS
  is optional-but-supported and required before binding beyond loopback.
- Egress requires HTTPS with certificate verification and an Authorization
  header; `insecure_skip_verify` exists only for throwaway dev destinations.
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
