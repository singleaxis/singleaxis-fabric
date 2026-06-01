# charts/

Helm charts for deploying Fabric **Layer 1** (public, Apache-2.0). The
top-level umbrella chart is `fabric/`; subcharts for each Layer 1
component live under `fabric/charts/`.

**Only the `fabric/` umbrella chart is published** (as a single OCI
artifact). The subcharts under `fabric/charts/` are packaged inside it —
they are not released or installed independently.

Components not in this repository are maintained by SingleAxis
internally and are not part of this distribution.

## First-party subcharts vs. the Langfuse dependency

The subcharts split into two categories with different versioning rules:

- **First-party (Fabric-authored):** `otel-collector`, `nemo-sidecar`,
  `presidio-sidecar`, `redteam-runner`, `update-agent`. Their
  `appVersion` (and thus their image tags) is bumped to the Fabric
  release version on every release, in lockstep with the umbrella.
- **Third-party (`langfuse`):** pinned independently. Its `appVersion`
  tracks the **upstream Langfuse** version (e.g. `2.93.0`) and is **not**
  bumped with Fabric releases. The one exception is the Fabric-built
  `langfuse-bootstrap` image, which is Fabric tooling and therefore
  carries the Fabric release version (propagated via
  `global.fabric.version`), not Langfuse's appVersion.

## Authoritative spec

[`../specs/008-deployment-model.md`](../specs/008-deployment-model.md)

## Status

Pre-alpha — umbrella ships the following Layer 1 subcharts. First-party
(Fabric-authored) subcharts are version-locked to the Fabric release;
`langfuse` is a third-party dependency pinned independently.

First-party:

- [`fabric/charts/otel-collector/`](./fabric/charts/otel-collector) — telemetry processors
- [`fabric/charts/nemo-sidecar/`](./fabric/charts/nemo-sidecar) — NeMo Colang inline guardrails
- [`fabric/charts/presidio-sidecar/`](./fabric/charts/presidio-sidecar) — Presidio PII redaction
- [`fabric/charts/redteam-runner/`](./fabric/charts/redteam-runner) — scheduled adversarial probes
- [`fabric/charts/update-agent/`](./fabric/charts/update-agent) — GitOps signed-manifest pull

Third-party dependency:

- [`fabric/charts/langfuse/`](./fabric/charts/langfuse) — local observability UI (pinned to upstream Langfuse)

Two profiles ship: [`permissive-dev`](./fabric/profiles/permissive-dev.yaml)
(dev clusters only) and [`eu-ai-act-high-risk`](./fabric/profiles/eu-ai-act-high-risk.yaml).

## Usage (once released)

```bash
helm repo add singleaxis https://charts.singleaxis.com
helm install fabric singleaxis/fabric \
    --namespace fabric-system --create-namespace \
    --values singleaxis/profiles/eu-ai-act-high-risk.yaml \
    --set tenant.id=<uuid> \
    --set tenant.vault.address=<url> \
    --set tenant.kms.keyArn=<arn>
```

## Chart structure

See [`../specs/008-deployment-model.md`](../specs/008-deployment-model.md)
for the planned layout and profile system.

## Release signing

Charts are signed with `cosign` and a `.prov` provenance file.
Verification instructions ship with each release.
