# fabric umbrella chart

The deployable unit for SingleAxis Fabric. Installs the Layer 5/6
evaluation stack into a tenant's Kubernetes cluster under one
`helm install`. Regulatory Profiles in [`profiles/`](./profiles)
preset each subchart for the target regulation.

Authoritative shape: [`specs/008-deployment-model.md`](../../specs/008-deployment-model.md).

## Phase 1 scope

- [x] Umbrella `Chart.yaml` with conditional subchart dependencies
- [x] Default `values.yaml` documenting subchart toggles
- [x] Two profiles: `permissive-dev`, `eu-ai-act-high-risk`
- [x] Cross-cutting namespace + NetworkPolicy + NOTES templates
- [x] Fabric-authored Layer 1 subcharts:
  - [`otel-collector/`](./charts/otel-collector) — telemetry processors
  - [`nemo-sidecar/`](./charts/nemo-sidecar) — NeMo Colang guardrails
  - [`langfuse/`](./charts/langfuse) — local observability UI
  - [`redteam-runner/`](./charts/redteam-runner) — scheduled adversarial probes
  - [`update-agent/`](./charts/update-agent) — GitOps signed-manifest pull
- [ ] Layer 2 subcharts (`judge-workers/`, `escalation-service/`) live
      in a separate SingleAxis-internal repo during Phase 1; not part
      of the public OSS distribution.
- [ ] Context Graph subchart (Phase 2 — awaiting Postgres migration story)
- [ ] Telemetry Bridge subchart (Phase 2)
- [ ] Signed manifest channel + Update Agent (Phase 2)
- [ ] `values.schema.json` (Phase 2 — after subchart shape stabilizes)
- [ ] Production profiles beyond EU AI Act: NIST RMF, ISO-42001,
      SR-11-7, HIPAA (profile-by-profile as rubrics land)

## Install

```bash
cd charts/fabric
helm dependency update         # regenerates Chart.lock + charts/ tarballs
helm dependency build          # pulls subchart tarballs from charts/

# dev cluster:
helm install fabric . \
    --namespace fabric-system --create-namespace \
    --values profiles/permissive-dev.yaml

# production (EU AI Act high-risk):
helm install fabric . \
    --namespace fabric-system --create-namespace \
    --values profiles/eu-ai-act-high-risk.yaml \
    --set tenant.id=<uuid>
```

### Contributor note on `Chart.lock`

The repo intentionally does not check in `Chart.lock`. Subchart
versions are pinned in `Chart.yaml`; operators regenerate the lock
locally with `helm dependency update`. This avoids stale digests
diverging across branches when contributors bump a subchart.

## Latency posture (cross-cutting)

Every component is gated on a per-operation latency budget. The
agent's request path is *never* synchronous on a Fabric HTTP call:

| Layer | Operation | Budget (P99) |
|-------|-----------|--------------|
| SDK | span emit + local decision update | <1ms |
| L5 guardrails | UDS sidecar check | <100ms |
| L6 judges (fast) | score async | <500ms |
| L7 escalation | publish to bus | <5ms |
| L7 escalation | SDK resume poll | <5ms |

Published budgets are enforced in each subchart's readiness probe
and documented in the component README. A subchart that can't meet
its budget must flip its readiness probe to `NotReady` so HPAs /
service meshes drain it before it hurts the tenant.

## Chart structure

```
charts/fabric/
├── Chart.yaml
├── values.yaml
├── templates/
│   ├── _helpers.tpl
│   ├── namespace.yaml
│   ├── networkpolicy.yaml
│   └── NOTES.txt
├── charts/
│   ├── otel-collector/      (Layer 1, shipped)
│   ├── nemo-sidecar/        (Layer 1, shipped)
│   ├── langfuse/            (Layer 1, shipped)
│   ├── redteam-runner/      (Layer 1, shipped)
│   └── update-agent/        (Layer 1, shipped)
└── profiles/
    ├── permissive-dev.yaml
    └── eu-ai-act-high-risk.yaml
```

## Release signing (Phase 2)

Charts are signed with `cosign` and published with a `.prov`
provenance file. Phase 1 publishes unsigned from-source tarballs;
the signing pipeline lands with the Update Agent channel.

## Testing

```bash
helm lint charts/fabric
helm template test charts/fabric --values charts/fabric/profiles/permissive-dev.yaml > /dev/null
helm template test charts/fabric --values charts/fabric/profiles/eu-ai-act-high-risk.yaml > /dev/null
```
