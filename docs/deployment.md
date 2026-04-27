# Deployment

Fabric's deployable unit is the umbrella Helm chart at
[`charts/fabric/`](../charts/fabric/). The authoritative spec for the
deployment model is
[`specs/008-deployment-model.md`](../specs/008-deployment-model.md);
this page is a pointer and a posture statement.

## Chart + profiles

```bash
cd charts/fabric
helm dependency build

# Dev / evaluation cluster:
helm install fabric . \
    --namespace fabric-system --create-namespace \
    --values profiles/permissive-dev.yaml

# Regulated workloads (EU AI Act high-risk):
#   - REPLACE the trustedKey publicKey with the real release Ed25519
#     public key (base64). The chart fails-closed otherwise.
#   - DEPLOY the Presidio sidecar separately (the umbrella does not
#     bundle it yet) and set redact.existingSocketProvider to its
#     resource name.
helm install fabric . \
    --namespace fabric-system --create-namespace \
    --values profiles/eu-ai-act-high-risk.yaml \
    --set tenant.id=<uuid> \
    --set update-agent.config.trustedKeys[0].publicKey=<real-base64-Ed25519-key> \
    --set otel-collector.fabric.redact.existingSocketProvider=<presidio-sidecar-name>
```

### Inspecting the rendered manifests (template / lint only)

For pre-install review (`helm template`, `helm lint`, compliance audit
of the rendered manifests), bypass the install-time checks:

```bash
helm template fabric . \
    --values profiles/eu-ai-act-high-risk.yaml \
    --set update-agent.config.allowPlaceholderKey=true \
    --set otel-collector.fabric.redact.acceptMissingProvider=true
```

Both flags **only affect template rendering**. The deployed binaries
re-validate at startup and refuse to run with a placeholder key or a
missing redact socket — a real `helm install` cannot bypass either
check even if the renderer was told to.

Two regulatory profiles ship in Phase 1:

- `permissive-dev` — local / evaluation / non-regulated. Loose
  sampling, judges off, no retention constraints.
- `eu-ai-act-high-risk` — EU AI Act high-risk systems. Full retention,
  judges on, escalation workflow on, tightened guardrail chain.

Other profiles (NIST AI RMF, ISO 42001, SR 11-7, HIPAA) land
profile-by-profile as rubric content does. See the chart
[`README.md`](../charts/fabric/README.md) for current subchart
inventory (shipped vs. Phase 2).

## Compose (local smoke only)

[`deploy/compose/`](../deploy/compose/) provides a docker-compose
topology for local smoke testing the SDK + sidecars + OTel Collector
chain without a cluster. It is **not** a supported production
topology. Use Helm for anything that touches real traffic.

## What "audit-ready" means in Phase 1a

Fabric is positioned as *audit-ready*, not *certified*. Those are
different claims and the difference matters to regulators.

- **Fabric does not issue certifications.** No SOC 2 report, no
  ISO 42001 certificate, no EU AI Act conformity marking comes out
  of the box.
- **Fabric produces the evidence trail a certification audit
  requires.** Signed decision spans, signed guardrail outcomes,
  judge scores over time, escalation records, tenant-scoped
  retention — these are the artifacts an external auditor asks
  for. Fabric's job is to make collecting them automatic.
- **Certification remains the tenant's process.** The tenant's
  compliance function takes the evidence bundle to an auditor; the
  auditor issues the attestation. Fabric is the substrate, not the
  auditor.

In Phase 1a, the evidence surface is deliberately narrow: decision
spans, guardrail events, and escalation records. Context Graph
queries, signed bundle exports, and the SingleAxis attestation
network are roadmap items maintained by SingleAxis internally.

## Operational posture

| Concern | Phase 1a state | Pointer |
|---------|----------------|---------|
| Disaster recovery | Stateless components recoverable from Git; stateful services (Postgres, NATS) follow standard backup practice | [`operations/dr.md`](operations/dr.md) |
| Upgrade channel | Manual `helm upgrade` in Phase 1a; signed manifest channel + Update Agent in Phase 2 | Chart [`README`](../charts/fabric/README.md) |
| High availability | `profile.availability: ha` opt-in (3-node NATS, replicated Postgres, ≥2 worker replicas) | [`specs/008-deployment-model.md`](../specs/008-deployment-model.md) |
| Image signing | Cosign (keyless via Fulcio), SLSA build provenance, SBOM shipped from `0.1.0`; Helm `.prov` on roadmap | [`SECURITY.md`](../SECURITY.md) §Release signing |

## Roadmap / not yet shipping

Helm `.prov` provenance files (cosign signing of OCI charts is the
current path); NIST RMF / ISO 42001 / SR 11-7 / HIPAA profiles;
Context Graph and Telemetry Bridge subcharts; umbrella-chart OCI
publishing. See the chart README and spec 008 for current Phase 2
scope.
