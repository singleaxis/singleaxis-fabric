# presidio-sidecar subchart

Presidio PII redaction sidecar. Spec:
[`specs/005-guardrails-inline.md`](../../../../specs/005-guardrails-inline.md).

## What this ships

A FastAPI sidecar that redacts PII from payloads using Microsoft
Presidio (analyzer + spaCy NER) and a tenant-keyed HMAC:

- `GET  /healthz`
- `POST /v1/redact` — returns the payload with PII spans redacted

## Required: tenant HMAC key

The sidecar **refuses to start** without a real tenant HMAC key, so
HMACs are not reversible across deployments. The chart **fails to
render** unless `tenantKey.existingSecret` names an existing Secret.

Create the Secret first:

```sh
kubectl create secret generic fabric-presidio-tenant-key \
  --from-literal=tenant.key="$(openssl rand -base64 32)"
```

Then install with:

```sh
helm install presidio charts/fabric/charts/presidio-sidecar \
  --set tenantKey.existingSecret=fabric-presidio-tenant-key
```

The Secret is mounted read-only at `/etc/fabric/tenant/` and passed to
the sidecar via `--tenant-key-file`.

## Phase 1 scope

- Shared `Deployment` + `Service` mode (TCP) for smoke tests and dev
  clusters. Production should inject the container as a per-agent-pod
  sidecar over a Unix domain socket for <5ms redaction — the
  sidecar-injection webhook lands in Phase 2.

## Redaction mode

`redactionMode` selects how detected PII spans are rewritten:

- `hmac` (default) — each span is replaced with a stable, tenant-keyed
  HMAC token, correlatable across requests for the same tenant.
- `tag` — each span is replaced with a generic entity tag (e.g.
  `<PERSON>`), discarding correlatability.

## Key values

| Key | Default | Purpose |
|-----|---------|---------|
| `tenantKey.existingSecret` | `""` | **Required.** Name of an existing Secret holding the tenant HMAC key. Empty → render fails. |
| `tenantKey.secretKey` | `tenant.key` | Key within the Secret; also the mounted filename under `/etc/fabric/tenant/`. |
| `redactionMode` | `hmac` | Redaction strategy (`hmac` or `tag`); passed via `--redaction-mode`. |
| `allowPassthrough` | `false` | Dev only. Passes `--allow-passthrough` so the sidecar starts with the no-op analyzer when the `[presidio]` extra is absent. |
| `service.port` | `8080` | Container + Service TCP port. |

## Latency posture (published budget)

| Route | P99 target |
|-------|------------|
| `POST /v1/redact` | <5ms (Presidio analyze + HMAC/tag redaction) |

Budgets apply to the sidecar process itself — colocated UDS calls
skip the TCP stack. The shared-Deployment mode shipped here is for
smoke-tests and dev clusters only.
