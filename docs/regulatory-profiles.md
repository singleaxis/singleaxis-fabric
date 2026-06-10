# Regulatory profiles

Fabric ships two named umbrella-chart profiles. They are *opinionated*
default-value bundles for the umbrella `charts/fabric` chart — same
components, different posture.

> Profiles set defaults; every value remains overridable. They exist so
> you don't have to derive a regulated posture from scratch.

| | `permissive-dev` | `eu-ai-act-high-risk` |
|---|---|---|
| **Intended for** | local development, CI smoke tests, demos | production deployments under EU AI Act Annex III (high-risk) |
| **Production safe?** | **No** | Yes (with your signing keys + KMS) |
| **Presidio redaction** | ON (HMAC) | ON (HMAC, real recognizer set, fail-loud on missing key) |
| **NeMo guardrails** | optional | ON, output rails enforced |
| **OPA policy at 4 points** | optional | Required at all 4 points |
| **Egress allowlist (`fabricguard`)** | warn-only | enforce |
| **Sampling (`fabricsampler`)** | 100% | HMAC-keyed tail sampling per event class |
| **Tail-sample of denials/blocks** | retain | retain (regulator wants the bad cases) |
| **Network policies** | none | strict — sidecars cannot egress to public internet |
| **PodDisruptionBudgets** | none | yes |
| **Resource requests/limits** | minimal | production-sized |
| **Update-agent signing key** | placeholder allowed | real key required (chart fails to install otherwise) |
| **Exporter endpoint** | optional | required (chart fails to install otherwise) |
| **Tenant HMAC key** | dev placeholder | real Secret required |
| **Locked fields** | none | `presidio.mode`, `nemo.enabled`, policy enforcement points |

## Install

```bash
# permissive-dev — the kind-quickstart default
helm upgrade --install fabric oci://ghcr.io/singleaxis/charts/fabric \
  --values profiles/permissive-dev.yaml

# eu-ai-act-high-risk — production posture
helm upgrade --install fabric oci://ghcr.io/singleaxis/charts/fabric \
  --values profiles/eu-ai-act-high-risk.yaml \
  --set tenant.id=acme-corp \
  --set update-agent.config.signingKeySecret=acme-update-agent-key \
  --set presidio-sidecar.tenantKeySecret=acme-tenant-hmac \
  --set otel-collector.exporter.endpoint=https://otel.acme.example
```

## Fail-loud guards

The `eu-ai-act-high-risk` profile uses Helm `fail` templates rather than
hidden defaults. Missing-on-purpose to force a conscious deployer choice:

| Guard | Override (only for dry-render / kind) |
|---|---|
| `tenant.id` is set | `--set tenant.id=...` |
| Real update-agent signing key | `--set update-agent.config.allowPlaceholderKey=true` |
| Presidio redact-socket provider | `--set otel-collector.fabric.redact.acceptMissingProvider=true` |
| Exporter endpoint set | `--set otel-collector.exporter.acceptUnsetEndpoint=true` |

If a guard fires, the failure message tells you exactly which field and
why. Don't bypass guards in production.

## Deriving a custom profile

Profiles are just YAML files under `charts/fabric/profiles/`. Copy one
and edit:

```bash
cp charts/fabric/profiles/eu-ai-act-high-risk.yaml profiles/acme-finance.yaml
# edit profile.name, profile.regulations, lockedFields, and any value overrides
helm upgrade fabric oci://ghcr.io/singleaxis/charts/fabric \
  --values profiles/acme-finance.yaml
```

A few good practices:

- **Lock fields you don't want operators to change** with the
  `profile.lockedFields` list — the chart will refuse a `helm upgrade`
  that overrides them.
- **Set `profile.regulations`** so the `fabricsampler` retains the
  right event classes (e.g. anything tagged `eu-ai-act` keeps 100%
  sampling).
- **Always set the exporter endpoint**, even if your backend is in-cluster
  — `accept` flags are for `helm template` only.

## What the profile does *not* do

- It does not provision your IdP, KMS, or HSM. Those stay in your control.
- It does not enable the Commercial plane. To ship sanitized evidence to
  SingleAxis-hosted services, set `commercial.enabled=true` and provide a
  license key.
- It does not authorize tool calls — that's wired by your application
  via the `ToolAuthorizer` protocol. The profile only enforces *that
  the call happens*.
