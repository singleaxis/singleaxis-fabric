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
- [ ] Decision Graph subchart (Phase 2 — awaiting Postgres migration story)
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

The numbers above are design budgets per spec 005, not measured P99s
on the current release. Today's readiness probes are simple HTTP
`/healthz` checks (process up). A latency-aware readiness gate that
flips `NotReady` on budget breach is roadmap; the benchmark suite
that would inform it lands as a follow-up release. Documented in
each component README.

## Chart structure

`fabric/` is the **only published unit** — the release pipeline packages
and pushes this umbrella chart as a single OCI artifact. The subcharts
below are bundled inside it; they are not released or installed on their
own. First-party (Fabric-authored) subcharts have their `appVersion`
bumped to the Fabric release version on each release; `langfuse` is a
third-party dependency pinned independently to its upstream version.

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
│   ├── otel-collector/      (Layer 1, first-party)
│   ├── nemo-sidecar/        (Layer 1, first-party)
│   ├── presidio-sidecar/    (Layer 1, first-party)
│   ├── langfuse/            (Layer 1, third-party — pinned to upstream Langfuse)
│   ├── redteam-runner/      (Layer 1, first-party)
│   └── update-agent/        (Layer 1, first-party)
└── profiles/
    ├── permissive-dev.yaml
    └── eu-ai-act-high-risk.yaml
```

### Langfuse versioning

The `langfuse` subchart's `appVersion` tracks the **upstream Langfuse**
release and is intentionally NOT bumped with Fabric releases. The one
piece that does carry the Fabric version is the Fabric-built
`langfuse-bootstrap` image (curated-bundle seeding tool): the umbrella
propagates `global.fabric.version` so the bootstrap Job tags that image
at the Fabric release version the pipeline actually publishes it at,
while the Langfuse application container keeps its upstream tag.

## Release signing

The `fabric` umbrella chart is published as a signed OCI artifact —
signed keylessly with [cosign](https://www.sigstore.dev/) via Fulcio
(see the `publish-chart` job in `.github/workflows/release.yml`).
Verification instructions ship with each release — see
[`SECURITY.md`](../../SECURITY.md) §Release signing.

## Testing

```bash
helm lint charts/fabric
helm template test charts/fabric --values charts/fabric/profiles/permissive-dev.yaml > /dev/null
helm template test charts/fabric --values charts/fabric/profiles/eu-ai-act-high-risk.yaml > /dev/null
```
