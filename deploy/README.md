# deploy/

Deployment material for Fabric OSS, the customer-controlled recording data
plane:

```text
CAPTURE -> PROTECT -> DELIVER
```

## What exists today

### `compose/` — Docker Compose paths (no Kubernetes)

- **Evaluation harness** (`compose/docker-compose.yml`): `fabric-node` plus a
  controlled fsync test sink. `make up` / `make qualify` prove protected
  capture, durable local queueing, and at-least-once delivery through a
  destination outage and a recorder restart. Plaintext and unauthenticated —
  local evaluation only.
- **Client-VM production overlay** (`compose/docker-compose.production.yml`,
  config `compose/collector-config/collector-production.yaml`): the same recorder
  image deployed on a single Linux VM with bearer-token-authenticated OTLP
  ingress (optional receiver TLS), a durable file-backed exporter queue, and
  authenticated HTTPS egress to a customer-selected OTLP backend. See
  `compose/README.md` ("Client VM deployment") for the quick start and
  `../docs/operations/dr.md` for queue sizing, backup, and alerting.

## What does not exist here yet

Kubernetes deployment uses the Helm chart under `charts/fabric` (see the
`shadow-production` values profile). There is no Terraform/Crossplane
module set in this tree today.

## Authoritative spec

[`../specs/027-recorder-v1.md`](../specs/027-recorder-v1.md)
