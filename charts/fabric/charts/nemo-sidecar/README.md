# nemo-sidecar subchart

NeMo Colang guardrails sidecar. Spec:
[`specs/005-guardrails-inline.md`](../../../../specs/005-guardrails-inline.md).

## What this ships

A FastAPI sidecar that evaluates prompts and outputs against a Colang
rails configuration:

- `GET  /healthz`
- `POST /v1/check` — returns `{allow, reasons, rails_fired}`

## Phase 1 scope

- Shared `Deployment` + `Service` mode (TCP) for smoke tests and dev
  clusters. Production should inject the container as a per-agent-pod
  sidecar over a Unix domain socket for <100ms P99 — the
  sidecar-injection webhook lands in Phase 2.
- Passthrough engine (fail-open) when `railsConfigMap.name` is unset.
  Production profiles must supply a Colang rails ConfigMap.

## Key values

| Key | Default | Purpose |
|-----|---------|---------|
| `railsConfigMap.name` | `""` | ConfigMap containing the Colang rails. Unset → passthrough. |
| `railsConfigMap.mountPath` | `/etc/fabric/rails` | Where the rails are mounted; passed via `--rails-config`. |
| `service.port` | `8080` | Container + Service TCP port. |

## Latency posture (published budget)

| Route | P99 target |
|-------|------------|
| `POST /v1/check` | <100ms (passthrough or Colang rails) |

Budgets apply to the sidecar process itself — colocated UDS calls
skip the TCP stack. The shared-Deployment mode shipped here is for
smoke-tests and dev clusters only.
