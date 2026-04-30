---
title: Deployment Model & Helm Chart
status: draft
revision: 2
last_updated: 2026-04-20
owner: project-lead
---

# 008 — Deployment Model & Helm Chart

## Summary

Fabric deploys as a single umbrella Helm chart into a dedicated
Kubernetes namespace (`fabric-system`) inside the tenant VPC. A
**Regulatory Profile** (named `values.yaml` preset) configures the
chart for a target regulation. Updates to policies, rubrics, and the
chart itself flow via a **GitOps pull channel** backed by signed
manifests — the tenant's cluster pulls; SingleAxis never pushes into
the tenant.

This spec defines the chart structure, profile system, the pull
channel, and the day-0 operator experience.

## Goals

1. Make day-0 short: a prepared cluster should reach a working
   deployment in under 30 minutes with `helm install`.
2. Provide Regulatory Profiles as the primary configuration
   interface; most tenants should never touch raw `values.yaml`
   values.
3. Make the update channel pull-based, signed, and fully
   auditable — every remote change appears as a Git commit the
   tenant's security team can review.
4. Support the major Kubernetes distributions (EKS, GKE, AKS,
   vanilla + OpenShift) with Terraform modules for the non-
   Kubernetes dependencies (Vault, KMS, networking).
5. Keep the chart modular enough that tenants can swap individual
   components (alternate L3, alternate vector DB) without forking.

## Non-goals

- Shipping our own Kubernetes distribution or installer. Tenants
  bring a cluster; Fabric deploys on it.
- Managing cloud infrastructure provisioning beyond documented
  Terraform modules. A tenant may choose to use Crossplane or a
  different IaC tool; the Terraform modules are a reference.
- Non-Kubernetes deployment. Docker Compose is a dev fixture, not
  a supported runtime.

## Chart structure

Subcharts split across what's in this repository and what's
maintained by SingleAxis internally:

- **This repository (public umbrella, Apache-2.0):** OTel Collector
  distribution, guardrail sidecars, local observability.
- **Maintained internally by SingleAxis (overlay chart):** judges, escalation
  service, Context Graph, Telemetry Bridge, and the infrastructure
  (NATS, Postgres) they require. Installed on top of the Layer 1
  umbrella during a services engagement.

```
charts/
└── fabric/                          # Layer 1 umbrella (public)
    ├── Chart.yaml
    ├── values.yaml                  # documented defaults
    ├── values.schema.json           # schema-validated
    ├── templates/
    │   ├── _helpers.tpl
    │   ├── namespace.yaml
    │   ├── rbac/
    │   ├── networkpolicies/
    │   └── NOTES.txt
    ├── charts/                      # Layer 1 subcharts
    │   ├── langfuse/
    │   ├── otel-collector/          # Fabric-authored
    │   ├── nemo-sidecar/            # Fabric-authored
    │   ├── presidio-sidecar/        # Fabric-authored
    │   ├── redteam-runner/          # Fabric-authored
    │   └── update-agent/            # ArgoCD bundle
    └── profiles/
        ├── eu-ai-act-high-risk.yaml      # SHIPPED in 0.1.x
        ├── permissive-dev.yaml           # SHIPPED in 0.1.x; not for production
        ├── eu-ai-act-limited-risk.yaml   # PHASE 2 — not yet shipped
        ├── nist-ai-rmf.yaml              # PHASE 2
        ├── iso-42001.yaml                # PHASE 2
        ├── sr-11-7.yaml                  # PHASE 2
        └── hipaa.yaml                    # PHASE 2

                                     # (SingleAxis-internal overlay charts
                                     # — judges, escalation service,
                                     # context graph, telemetry bridge —
                                     # are maintained internally and not
                                     # part of this distribution.)
```

Each subchart is independently versioned but released together under
the umbrella chart's version.

## Day-0 experience

```bash
# 1. Add Fabric Helm repo
helm repo add singleaxis https://charts.singleaxis.com
helm repo update

# 2. Verify chart signature (cosign)
cosign verify-blob \
    --certificate singleaxis-fabric-cert.pem \
    --signature singleaxis-fabric-<ver>.tgz.sig \
    singleaxis-fabric-<ver>.tgz

# 3. Install, selecting a regulatory profile
helm install fabric singleaxis/fabric \
    --namespace fabric-system \
    --create-namespace \
    --values singleaxis/profiles/eu-ai-act-high-risk.yaml \
    --set tenant.id=<tenant-uuid> \
    --set tenant.vault.address=https://vault.internal \
    --set tenant.kms.keyArn=arn:aws:kms:eu-west-1:...
```

Only two pieces of per-tenant config are mandatory on the CLI:

- `tenant.id` — UUID assigned at tenant registration
- Tenant's secret manager and KMS key references

Everything else is either in the profile (regulatory controls) or
discovered (cluster capabilities).

### Post-install verification

```bash
# Wait for pods
kubectl -n fabric-system wait --for=condition=ready pod --all --timeout=10m

# Run built-in smoke test
helm test fabric -n fabric-system

# Check Admin UI
kubectl -n fabric-system port-forward svc/fabric-admin-ui 8080:80
# Visit http://localhost:8080
```

## Regulatory Profiles

A profile is a `values.yaml` that declares:

- Which L5 guardrail rails load, with what thresholds
- Which L6 rubrics are enabled
- Tiering policies (sample rates, escalation thresholds)
- Content storage policy (hash-only / redacted / full)
- Retention durations
- Escalation behaviour (sync / async, fail-closed / fail-open)
- Bridge settings (enabled by default, dry-run toggle, sampling)
- Required tenant infrastructure (Vault, KMS, sandbox)

Profile selection is the primary configuration lever. A profile
named in `tenant.profile` (set by the `--values` file) supplies
defaults; the tenant's additional `values.yaml` may override within
the profile's allowed bounds.

Some profile fields are **locked** — they cannot be overridden by
tenant config. A tenant wanting different behaviour for a locked
field must switch to a less strict profile.

### Example: EU AI Act high-risk

```yaml
# profiles/eu-ai-act-high-risk.yaml
fabric:
  profile:
    name: eu-ai-act-high-risk
    regulations: [eu_ai_act_high_risk]
    locked_fields:
      - telemetryBridge.redaction.presidio.enabled
      - telemetryBridge.manifest.signed
      - contextGraph.retention.minDays
      - guardrails.piiRedaction.enforced
      - escalation.fallback

guardrails:
  presidio:
    enabled: true
    recognizers: [default, medical, financial]
    action:
      pii_any: redact
  nemo:
    enabled: true
    rails:
      - off_topic
      - jailbreak_defence
      - refusal_policy
      - tool_permission_enforcement
  piiRedaction:
    enforced: true

judges:
  rubrics:
    - sasf.factuality
    - sasf.faithfulness
    - sasf.pii_leak
    - sasf.bias_demographic
    - sasf.tool_safety
    - sasf.instruction_following
  tiers:
    fast:
      sampleRate: 1.0
      model: tenant.default_small_model
    deep:
      sampleRate: 0.1
      model: tenant.default_large_model

contextGraph:
  contentStorage: redacted
  retention:
    minDays: 365
    evidenceBundles: forever

telemetryBridge:
  enabled: true
  mode: dry-run            # tenant flips to 'active' after review
  redaction:
    presidio:
      enabled: true
  manifest:
    signed: true

escalation:
  mode: async
  fallback: fail-closed
  slaHours: 4

redteam:
  suites: [garak_full, pyrit_prompt_injection]
  schedule: "weekly"
```

### Profiles ship as part of the release

Profile changes follow the spec process. A profile is considered
**load-bearing** — changing what an existing profile does in a
non-backward-compatible way requires a Fabric major version bump.

## The update channel (GitOps pull)

Fabric bundles an **Update Agent** (ArgoCD or Flux) that pulls from a
public signed manifest repository at
`github.com/singleaxis/fabric-manifests` (or a self-hosted mirror).

### What the channel delivers

- Policy updates (Presidio custom recognizers, NeMo Colang rails)
- Rubric library updates (new rubrics, rubric version bumps)
- Chart updates (point releases)
- Trust bundle updates (SingleAxis signing keys, SaaS SPIFFE identity)
- Profile updates (correlated with regulation changes)

### How it flows

1. SingleAxis publishes a signed commit to
   `fabric-manifests/tenants/<tenant_id>/`. The commit is signed
   with SingleAxis's release key.
2. The tenant's Update Agent pulls on its schedule (default: every
   30 minutes).
3. Before applying, the Update Agent verifies:
   - Commit signature against pinned release key
   - Manifest content against schema
   - Version compatibility with installed Fabric version
4. If verification passes, the manifest is applied. Each apply
   creates a Kubernetes event visible to the tenant.
5. If the tenant has enabled **manual approval mode**, the Update
   Agent stages the change and waits for an operator to approve
   via the Admin UI.

### Why pull, not push

- Tenants' security teams can audit the manifest repo as a Git
  diff before applying (especially in manual-approval mode).
- No inbound connection from SingleAxis is required; firewall
  posture stays simple.
- Rollback is `git revert` — standard tooling.
- No tenant-specific credentials held by SingleAxis beyond the
  published signing keys.

### Incident access (break-glass)

If SingleAxis support needs live access to debug an incident, the
tenant grants time-boxed access via a Kubernetes RBAC binding that
expires automatically. The access is scoped to `fabric-system`
only (not the app namespace), logged, and surfaces in the Admin
UI. This is the only way a SingleAxis operator ever touches a live
tenant deployment.

## Cluster prerequisites

- Kubernetes 1.29+
- A storage class supporting RWO PVCs (for Postgres, NATS)
- A loadbalancer or Ingress controller (for Admin UI, optional
  public endpoints)
- NetworkPolicy-capable CNI (Calico, Cilium, etc.) — mandatory
- Cert-manager or equivalent (for internal mTLS)
- Either:
  - HashiCorp Vault reachable from `fabric-system`, or
  - Cloud-native secret manager (AWS Secrets Manager, GCP Secret
    Manager, Azure Key Vault) with Workload Identity configured

## Terraform reference modules

Under `deploy/terraform/` (to be scaffolded), reference modules for:

- `aws/eks-fabric-prerequisites` — VPC endpoints, KMS key, Vault
  cluster or Secrets Manager + Workload Identity, IAM roles
- `gcp/gke-fabric-prerequisites` — analogous
- `azure/aks-fabric-prerequisites` — analogous

These are reference, not required. Tenants using their own IaC
patterns are welcome.

## Non-K8s services integrated but not bundled

Fabric integrates with but does **not** run these:

| Service | Role | Tenant provides |
|---------|------|------------------|
| HashiCorp Vault / Secret Manager | Secrets | ✅ required |
| KMS | Envelope encryption keys | ✅ required |
| Object storage (S3 / GCS / ABS) | Content store, backups | ✅ required |
| LLM endpoint (Bedrock / Azure OpenAI / vLLM / ...) | Models for agent and judges | ✅ required |

## Security considerations

- **Network isolation.** Default `NetworkPolicy` denies all egress
  from `fabric-system` except from the Telemetry Bridge pod, and
  only to the configured SaaS endpoints.
- **Pod security.** All pods run with `runAsNonRoot`, seccomp
  `RuntimeDefault`, drop all capabilities, read-only root FS.
  Enforced via Kyverno / OPA Gatekeeper policies shipped with the
  chart.
- **RBAC.** Each component has its own ServiceAccount with the
  minimum permissions needed. No `cluster-admin` roles.
- **Signed releases.** Chart is signed (`.prov` file + cosign).
  Container images are signed. SBOM published per release (SPDX +
  CycloneDX).
- **Supply chain.** SLSA Level 3 build attestation targeted by
  0.3.0. Until then, reproducible build scripts are published so
  tenants can verify independently.

## Operational considerations

- **HA mode.** Profile `.availability: ha` deploys 3-node NATS,
  streaming-replicated Postgres, 2+ replicas of workers. Resource
  footprint triples; availability improves accordingly.
- **Disaster recovery.** Postgres WAL archived to tenant object
  storage; NATS streams snapshotted on the same schedule. DR
  posture and recovery outline live in
  [`docs/operations/dr.md`](../docs/operations/dr.md); detailed
  runbooks are a Phase 2 deliverable.
- **Upgrade cadence.** Minor releases monthly; patch releases as
  needed. Tenants can pin a minor for up to 6 months.

## Open questions

- **Q1.** OpenShift support — first-class (shipped routes,
  SecurityContextConstraints) or community-maintained overlay?
  *Resolver: platform maintainer. Deadline: before 0.2.0.*
- **Q2.** Flux vs ArgoCD as the default Update Agent — both work;
  pick one to document first-class? *Resolver: platform maintainer.
  Deadline: before 0.1.0.*
- **Q3.** How do we handle tenants running multi-cluster (e.g.
  per-region agent deployments sharing a single Control Plane)?
  Future spec. *Resolver: platform maintainer. Deadline: 0.3.0
  scope.*

## References

- Spec 002 — Architecture
- Spec 004 — Telemetry Bridge
- [Helm 3 best practices](https://helm.sh/docs/chart_best_practices/)
- [ArgoCD](https://argo-cd.readthedocs.io/)
- [SLSA framework](https://slsa.dev/)
- [Kyverno](https://kyverno.io/)
