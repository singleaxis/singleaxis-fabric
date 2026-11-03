# deploy/

Deployment material for Fabric OSS, the customer-controlled recording data
plane:

```text
CAPTURE -> PROTECT -> DELIVER
```

## What exists today

### `compose/` — Docker Compose paths (no Kubernetes)

- **Local harness** (`compose/docker-compose.yml`): `fabric-node` plus a
  controlled fsync test sink. `make up` / `make qualify` prove protected
  capture, durable local queueing, and at-least-once delivery through a
  destination outage and a recorder restart. Plaintext and unauthenticated —
  local trial only.
- **Client-VM technical overlay** (`compose/docker-compose.production.yml`,
  config `compose/collector-config/collector-production.yaml`): the same recorder
  image deployed on a single Linux VM with bearer-token-authenticated OTLP
  ingress bound to one tenant and source (the production profile; receiver
  TLS is configurable and required beyond loopback), a durable file-backed
  exporter queue, an optional content path with an encrypted content queue,
  and authenticated HTTPS egress to a customer-selected OTLP backend. It is
  not a production approval: your storage controls, retention and declared
  capture scope still need your own qualification. See
  [`../docs/deployment.md`](../docs/deployment.md),
  `compose/README.md` ("Client VM deployment") and
  [`../docs/operations/dr.md`](../docs/operations/dr.md) for queue sizing,
  backup, and alerting.
- **Production-profile CI fixtures** (`kind/production-e2e/`): kind values
  and sink manifests for the production-profile E2E workflow.
- **Host sensors** (`auditd/`, `kubernetes/host-emitter-daemonset.yaml`):
  development and qualification material for the auditd receiver and the
  eBPF host emitter; see [`../docs/host-sensors.md`](../docs/host-sensors.md).

## Kubernetes

Kubernetes deployment uses the Helm chart under `charts/fabric` (see the
`shadow-production` values profile).

## Authoritative specs

[`../specs/027-recorder-v1.md`](../specs/027-recorder-v1.md) (product
boundary) and [`../specs/049-four-layer-capture-coverage.md`](../specs/049-four-layer-capture-coverage.md)
(current capture contract). [`../specs/056-agent-action-reconstruction.md`](../specs/056-agent-action-reconstruction.md)
is the current direction: reconstructing what an agent did in a run, including
the host-sensor evidence above.
