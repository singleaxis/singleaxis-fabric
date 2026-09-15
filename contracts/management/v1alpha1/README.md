# Fabric Management contracts v1alpha1

> **Legacy build tag only.** The `fabricctl` commands described in this
> document (`init --legacy-management`, `deployment validate|digest|plan`,
> `bundle build`, and `doctor`) compile only with the explicit `legacy` Go
> build tag and are **absent from the recorder release binary**. The released
> CLI surface is `init`, `recorder validate`, `recorder digest`, `version`,
> and `help` — see `contracts/recorder/v1` for the shipped configuration
> contract. These management contracts remain as published interoperability
> artifacts and migration source; nothing here is installed or advertised by
> the recorder release.

This directory defines the public resources and derived machine artifacts for
Offline Install Bundle v1. The bundle is reviewable without a SingleAxis
account and does not grant authority to mutate a cluster.

## `FabricDeployment`

`FabricDeployment` is the public, vendor-neutral desired-state envelope for one
agent deployment. It lets an operator describe identity, integration mode,
assurance posture, reference-only controls, observation posture, assurance
plan, and rollout approval in a single reviewable file.

This contract is intentionally local and declarative. It does **not** apply a
deployment, resolve a reference, fetch a secret, or require a SingleAxis
account. The v1alpha1 schema is strict: unknown fields fail validation, raw
content is not a supported content mode, and secrets, tokens, credentials, and
environment dumps cannot be expressed inline.

## Resource shape

```yaml
apiVersion: fabric.singleaxis.dev/v1alpha1
kind: FabricDeployment
metadata:
  name: payments-agent-prod
spec:
  assuranceLevel: A3
  connection:
    mode: gateway
    tenantIdFrom: tenant-identity
    workloadIdentityRef: payments-spiffe-binding-v2
  controls:
    profileRef: payments-agent-controls-v4
  observe:
    contentMode: hash-only
    relayRef: regulated-relay-eu-west
  assurance:
    planRef: payments-release-gate-v7
  rollout:
    approvalRef: change-1842
```

All `*Ref` and `*From` values are identifiers or approved external-reference
URIs—not credential values. Their authorization,
integrity, type, existence, and effective configuration are controller
concerns. An operator may point them at customer-owned systems; no identifier
has product-specific resolution semantics in this contract.

`hash-only` is a data-minimization mode, not anonymization: hashes may remain
linkable or guessable. Likewise, `controls.piiRef` identifies runtime
input-path PII handling and is distinct from Observe/export redaction.

## Assurance requirements

- A0 requires identity, connection, and an Observe content mode.
- A1 additionally requires `observe.relayRef`.
- A2 and A3 additionally require `controls.profileRef`,
  `assurance.planRef`, and `rollout.approvalRef`.
- A3 additionally requires `connection.workloadIdentityRef`; local validation
  proves only that the opaque reference is present, not that it is resolved,
  authorized, or bound at ingress.

These structural requirements do not certify the referenced resources or make
a compliance claim. A future Site Controller must verify signatures and
approval authority, resolve references, enforce segregation of duties, render
component configuration, reconcile rollout, publish status, and record the
effective digest. Those apply/reconcile semantics are explicitly outside
v1alpha1 and outside the current `fabricctl` implementation.

## Local operator workflow

For a guided human workflow, the canonical Go CLI creates the complete
six-file Offline Install Bundle v1:

```bash
mkdir payments-agent
cd payments-agent
fabricctl init
```

The wizard writes the two canonical resources and four derived artifacts only
after explicit confirmation from an interactive terminal. Redirected or piped
stdin is rejected. It is offline and non-mutating, and it collects opaque
identifiers, public verification material, and non-secret target metadata
rather than secret values. It does not download or verify a chart, run Helm,
or install Fabric. The current directory is the default; `--output-dir DIR`
selects another location. `A0` selects `permissive-dev`; `A2` and `A3` select
`eu-ai-act-high-risk`. `A1` fails without writing because this release has no
truthful public production-standard profile for that level. `init` never
replaces an existing artifact and is not the CI/CD interface.

```bash
fabricctl deployment validate singleaxis.yaml
fabricctl deployment digest singleaxis.yaml
fabricctl deployment plan singleaxis.yaml
fabricctl bundle build \
  --deployment singleaxis.yaml \
  --target install-target.yaml \
  --output-dir ./bundle
fabricctl doctor --offline --bundle ./bundle --output json
```

All three commands are offline. Validation fails closed with stable diagnostic
IDs. Digest first validates, then hashes canonical UTF-8 JSON of the complete
input document. No declared field is defaulted, resolved, or excluded. This
makes a digest a precise review identity, not proof that referenced
configuration was approved or deployed.

`deployment plan` validates the same document and produces a deterministic,
offline installation/readiness plan. It names only the OSS roles selected by
the resource (connection artifact, Collector, and any selected Control, Relay,
or Assurance Runner), lists opaque references without resolving them, and
emits operator prerequisites with stable IDs. A plan is not a readiness
attestation: prerequisites have status `required`, not `verified`. The JSON
plan identifies the resource and includes the canonical digest of the complete
decoded desired-state document; readiness remains explicitly `unverified`.

Planning and bundle verification do not read environment variables or secret stores, contact a
network, cluster, or platform, render Helm, verify an approval, or apply or
reconcile desired state. It does not add Governance, a Site Controller, or a
SingleAxis destination unless a future contract explicitly selects such a
component. YAML anchors and aliases are rejected; this small desired-state
contract does not need them, and rejecting them prevents alias-expansion
attacks before object composition.

## `FabricInstallTarget`

[`FabricInstallTarget`](schema/fabric-install-target.schema.json) is a second
canonical resource. It binds the canonical digest of one `FabricDeployment`
to a digest-pinned distribution, a digest-pinned public profile, and a concrete
Kubernetes Helm destination. It is kept separate so promoting the same agent
posture between environments does not change the reviewed agent definition.

```yaml
apiVersion: fabric.singleaxis.dev/v1alpha1
kind: FabricInstallTarget
metadata:
  name: payments-agent-eu-target
spec:
  deploymentRef:
    name: payments-agent-prod
    digest: sha256:3333333333333333333333333333333333333333333333333333333333333333
  distribution:
    artifactRef: oci://registry.example.com/singleaxis/fabric
    version: 1.2.3
    digest: sha256:4444444444444444444444444444444444444444444444444444444444444444
  profile:
    name: eu-ai-act-high-risk
    digest: sha256:5555555555555555555555555555555555555555555555555555555555555555
  backend:
    type: helm
    helm:
      context: eu-production
      namespace: singleaxis-fabric
      releaseName: payments-fabric
      createNamespace: false
  bindings:
    tenantId: tenant-eu-payments
    exporter:
      endpoint: https://telemetry.customer.example/v1/traces
      egress:
        cidrs: [192.0.2.0/24]
        ports:
          - protocol: TCP
            port: 443
    updateTrust:
      keyId: singleaxis-release-2026-01
      publicKey: ed25519:<base64url-encoded-32-byte-public-key>
```

The v1alpha1 target supports only `backend.type: helm`. Docker Compose and
local backends are intentionally deferred. Distribution, deployment, and
profile digests use lowercase `sha256:` plus exactly 64 hexadecimal
characters; a version or mutable OCI tag is not a substitute for a digest.
`distribution.artifactRef` must use `oci://`.

Only `permissive-dev` and `eu-ai-act-high-risk` are public profiles in this
revision. The high-risk profile structurally requires `bindings.tenantId`, an
HTTPS exporter with an explicit egress allowlist, and an Ed25519 update-trust
public key. This is a secure configuration requirement, not a certification or
claim of legal compliance.

The contract cannot contain arbitrary Helm values, passwords, tokens, private
keys, or secret data. `context`, tenant, and key identifiers are opaque,
non-secret references. `updateTrust.publicKey` is public verification
material. A later installer must still verify that:

- `deploymentRef.digest` equals the canonical digest of `singleaxis.yaml`;
- artifact and profile bytes match their declared digests and signatures;
- CIDRs are canonical networks with valid IPv4 or IPv6 prefix lengths;
- the exporter destination and resolved network path comply with the declared
  egress allowlist; and
- the selected Kubernetes context and namespace are the operator-approved
  target.

The JSON Schema deliberately handles the bounded structural checks. These
cross-resource and environment-dependent checks remain fail-closed installer
semantics; offline schema validation does not claim that they passed.

## Offline Install Bundle v1

A complete bundle contains exactly six files:

| File | Class | Contract |
|---|---|---|
| `singleaxis.yaml` | canonical | `FabricDeployment` |
| `install-target.yaml` | canonical | `FabricInstallTarget` |
| `fabric-values.yaml` | derived | deterministic values from the public profile; no arbitrary override map |
| `secrets-required.yaml` | derived | [`FabricSecretRequirements`](schema/fabric-secret-requirements.schema.json) |
| `installation-plan.json` | derived | [`fabricctl.installation-plan/v1`](schema/fabric-installation-plan.schema.json) |
| `bundle-manifest.json` | derived | [`fabricctl.bundle-manifest/v1`](schema/fabric-bundle-manifest.schema.json) |

`FabricSecretRequirements` contains only unresolved secret metadata: name,
namespace, required key names, purpose, and consumer. Its `status` is always
`unresolved`; generation never inspects a secret store or claims a secret is
present. The schema has no field capable of carrying a secret value.

The installation plan binds the exact deployment and target digests and
copies the target's pinned distribution, profile, and Helm backend. Its
actions and prerequisites are ordered deterministically. In v1 it is an
offline description only: `operation.network` and `operation.mutating` are
both `false`, and `readiness` is always `unverified`. Action and prerequisite
`order` values must be unique, contiguous, and agree with array order; that
deterministic semantic is enforced by the generator/validator because JSON
Schema cannot express it cleanly.

`deployment_obligations` preserves the selected Connect, Control, Observe,
and Assurance roles, every opaque deployment reference, and the unresolved
assurance-level prerequisites. These obligations are intentionally not mapped
into Helm values: a later authorized installer or management plane must
resolve and verify them without silently dropping policy, identity, approval,
PII, guardrail, escalation, relay, assurance, or recovery requirements.

The bundle manifest lists exact byte SHA-256 values for the other five files
and explicitly excludes itself. It contains generator name, version, and
source commit, but no wall-clock timestamp. Receipts—not deterministic desired
state—record installation, verification, upgrade, and rollback times.

The five `files` entries are serialized in lexicographic path order. This
ordering is part of the canonical manifest schema; consumers must reject a
permutation even though the digest algorithm also sorts defensively.

To compute `bundle_digest`, sort the five manifest entries lexicographically
by `path`. For each entry, append the UTF-8 path, one NUL byte, the lowercase
64-character `sha256`, and one LF byte. SHA-256 hash the concatenated bytes and
prefix the lowercase result with `sha256:`. A consumer must recompute all five
file hashes and this digest before consuming the bundle. A matching unsigned
manifest proves deterministic internal consistency, not publisher identity or
authorization; release and installation authenticity require the signature
and receipt work defined for later lifecycle slices.

The fixtures are separated by artifact so `FabricDeployment` conformance
runners do not misclassify them:

- `install-target/{valid,invalid}` for canonical targets; and
- `derived/<artifact>/{valid,invalid}` for derived machine outputs.

The stable automation envelopes are also public contracts:

- [`fabricctl.bundle-build/v1`](schema/fabric-bundle-build-result.schema.json)
  covers both success and value-free failure results; and
- [`fabricctl.bundle-verification-report/v1`](schema/fabric-bundle-verification-report.schema.json)
  covers strict offline bundle verification and can never claim readiness or
  network or target activity.

The digest-pinned [`manifest.json`](manifest.json) is the complete contract
index. Consumers must verify it before using any schema or fixture in
qualification.
