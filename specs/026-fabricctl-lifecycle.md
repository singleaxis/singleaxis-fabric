---
title: fabricctl lifecycle and deployment bundle
status: accepted
revision: 3
last_updated: 2026-08-28
owner: product-architecture
---

# 026 — `fabricctl` lifecycle and deployment bundle

> **Scope note (partially superseded):** this document describes the full
> lifecycle and management target for `fabricctl`. For the recorder v1
> release, [spec 027](027-recorder-v1.md) narrows the shipped CLI surface to
> `init`, `recorder validate`, `recorder digest`, `version`, and `help`; the
> lifecycle and management contracts cited below are `legacy` build-tag only
> and are not the recorder-v1 `fabricctl` surface. Where this document and
> 027 disagree about recorder scope, 027 controls.

## Summary

`fabricctl` is the public operator interface for configuring, installing, and
verifying SingleAxis Fabric. It must give a human operator, a GitOps pipeline,
and the SingleAxis Management service equally capable ways to produce and
apply the same reviewed desired state.

The canonical CLI is the standalone Go binary released for supported operating
systems and architectures. It must not require Python, Node.js, or a SingleAxis
account. The Python and TypeScript packages remain language SDKs distributed
through PyPI and npm; they are not alternative implementations of the
deployment CLI.

This specification defines the lifecycle target and records implementation
status by slice. It does not claim that install or reconciliation exists where
the current-state section says it is deferred.

The recommended ownership boundary is a public, provider-neutral lifecycle
engine in `tools/fabricctl/pkg/lifecycle` with environment-specific execution
backends behind the CLI. The SingleAxis Platform consumes those contracts and
owns fleet state, approval workflows, rollout orchestration, and operator UI.
`singleaxis-fabric-internal` may supply private engines, workers, connectors,
bundles, and deployment overlays, but it is not a second management plane.

## Problem

Fabric historically exposed two commands named `fabricctl`. The Go binary now
owns `version`, `doctor`, guided `init`, and offline `FabricDeployment`
validation, digest, and planning. A legacy Python console entry point still
exists during migration and must not become a second lifecycle implementation.

Two independently implemented operator interfaces cannot provide stable
automation, support, or evidence in a regulated deployment. They may disagree
about exit codes, validation, profiles, security defaults, and effective
configuration. The product also lacks one complete lifecycle from guided
configuration through installation, verification, upgrade, and rollback.

## Product decisions

1. The Go binary under `tools/fabricctl` becomes the only canonical
   `fabricctl` executable.
2. The public `FabricDeployment` contract remains the canonical user-authored
   desired state. CLI behavior must be derived from public, versioned
   contracts rather than private platform models.
3. Interactive terminal setup, declarative Git configuration, and Management
   service bundle generation are three front ends to the same bundle and plan
   engine. None may have capabilities or defaults unavailable to the others.
4. Kubernetes is the first production deployment backend. Docker Compose and
   local development are later backends behind the same interface; the CLI
   must not present an unimplemented backend as installable.
5. Planning is offline and non-mutating. Mutation begins only at an explicit
   `install`, `upgrade`, or `rollback` command.
6. No generated file contains credentials, tokens, private keys, raw prompts,
   or other secret values. Secret requirements are references and metadata.
7. A dashboard-generated bundle is not privileged. The CLI validates its
   contracts, signatures, target, and approvals before use exactly as it does
   for a Git-authored bundle.

## Distribution ownership

| Artifact | Distribution | Responsibility |
|---|---|---|
| `fabricctl` | signed standalone binaries and release archives | operator lifecycle and deployment backends |
| Python SDK | PyPI package `singleaxis-fabric` | Python instrumentation, adapters, and reusable SDK APIs |
| TypeScript SDK | npm package `@singleaxis/fabric` | TypeScript instrumentation and adapters |
| Helm chart | OCI/chart release | Kubernetes resources rendered by the Kubernetes backend |

During migration, the Python console entry point may remain for one documented
deprecation window. It must delegate to the canonical binary or retain only
compatibility commands with an explicit warning. New lifecycle behavior must
not be implemented twice. Reusable schema fixtures and conformance tests move
to language-neutral public contracts; Go and Python consumers must produce the
same canonical digest and diagnostics for those fixtures.

The PyPI and npm SDKs are separate release lanes. A Fabric source release may
publish both, but publishing either SDK is not how the standalone CLI is
installed. Release policy must state explicitly whether a missing optional
language SDK blocks a CLI/chart release.

## Operator experiences

### Interactive terminal

Running `fabricctl init` on a terminal starts a guided, local wizard:

```text
Welcome to SingleAxis Fabric

Where will Fabric run?
> Kubernetes
  Docker Compose (not yet available)
  Local development (not yet available)

Where should telemetry go?
> SingleAxis Platform
  Customer OTLP endpoint
  Local observability backend
  Configure later

Select a deployment profile:
> Regulated enterprise
  Production standard
  Development

Capture sensitive content?
> No — metadata and governed references only
  Redacted content
  Custom data policy

Enable runtime controls?
[x] PII detection
[x] Tool authorization
[ ] Guardrails
[ ] Human escalation

Review configuration -> Validate -> Write bundle
```

The wizard explains consequences and required dependencies; it does not imply
that every component is mandatory. A profile may lock required settings. The
regulated profile must fail closed when a required answer or reference is
absent.

### Declarative automation

Every operation supports non-interactive execution with stable machine output:

```sh
fabricctl plan --config singleaxis.yaml --output json
fabricctl install --config singleaxis.yaml --non-interactive
fabricctl verify --config singleaxis.yaml --output json
```

Non-interactive mode never prompts, guesses, or accepts an approval on behalf
of the caller. Missing required input fails with a stable diagnostic and no
mutation. The same input and artifact set must yield the same plan digest.

### SingleAxis Management service

The private Management service may provide a web form, profiles, approval
workflow, and signed bundle download. It must call or conform to the same
public contracts and plan semantics. A customer can export the bundle, review
it, store it in Git, install it without platform connectivity, and compare the
local effective digest with the approved digest.

The platform implementation, fleet database, SSO/RBAC, approvals UI, and
rollout orchestration remain outside this OSS repository.

## Canonical configuration and generated bundle

`singleaxis.yaml` is the canonical agent desired state and contains one
`FabricDeployment`. `install-target.yaml` is a separate canonical
`FabricInstallTarget`; it binds the deployment digest to one exact
distribution, public profile, and Kubernetes Helm target. Keeping these
resources separate allows the same reviewed agent posture to be targeted at a
different environment without changing or re-signing the agent definition.

Offline Install Bundle v1 contains exactly six files:

`fabricctl init --output-dir <directory>` writes a reviewable bundle:

| File | Authority | Contents |
|---|---|---|
| `singleaxis.yaml` | canonical input | deployment identity, assurance level, connection mode, references, selected controls, Observe posture, and rollout reference |
| `install-target.yaml` | canonical input | deployment digest binding, pinned OCI distribution and profile, Kubernetes context, namespace, release name, and non-secret environment bindings |
| `fabric-values.yaml` | derived | deterministic Helm values rendered from the canonical input and selected public profile |
| `secrets-required.yaml` | derived | required secret names, types, scopes, and provisioning instructions; never secret values |
| `installation-plan.json` | derived | resource digests, pinned chart/profile, target, offline actions, effects, and unresolved prerequisites |
| `bundle-manifest.json` | derived | byte digests for the other five files, deterministic bundle digest, and generator name/version/commit |

The authoritative bundle manifest contains no wall-clock timestamp. Time is
an observation made by an installer or verifier and belongs in a signed
receipt, not in deterministic desired state. The manifest excludes itself and
computes `bundle_digest` by sorting its five entries by path, concatenating
each UTF-8 path, one NUL byte, its lowercase 64-character SHA-256, and one LF
byte, then hashing the resulting bytes with SHA-256.

Files are created only after the operator confirms the write. Existing files
are never replaced, each new file uses restrictive permissions and is synced,
and newly created files are rolled back if the six-file commit cannot finish.
The same generation engine is callable non-interactively by CI. The manifest
covers every non-manifest file byte-for-byte and excludes itself through an
explicit rule. Bundle signing is not implemented in Slice 1; Slice 2 must use
a detached signature or a separately defined signature envelope so
deterministic desired-state bytes do not self-reference.

Offline Install Bundle v1 supports Kubernetes Helm only. Docker Compose and
local development remain deferred backends and do not appear as valid
`FabricInstallTarget` values. The target has no arbitrary Helm-values map and
cannot contain secret values; profile-driven rendering is the sole source of
`fabric-values.yaml`.

The current offline plan includes:

- deployment and install-target digests;
- selected Helm backend, expected cluster context, namespace, and release;
- exact chart OCI reference/version/digest and profile digest;
- ordered validate, render, and verify actions;
- unresolved prerequisites with stable identifiers; and
- explicit offline, non-mutating, readiness-unverified posture.

The mutation plan introduced in Slice 2 must additionally identify resolved
image and binary digests, create/update/replace/delete effects, approval scope,
rollback revision, compatibility constraints, and stable target identity.

Planning must not read secret values, contact a secret store, contact
SingleAxis, or mutate a cluster. An opt-in `--refresh` operation may resolve
remote artifact metadata in a later contract, but its network effects must be
explicit and its result pinned in the bundle.

## Command contract

| Command | Mutation | Purpose | Required evidence output |
|---|---|---|---|
| `init` | local files | guided or template-based configuration and bundle generation | validation result and bundle digest |
| `plan` | none | validate desired state and show exact intended effects | deterministic installation plan |
| `doctor` | none | check local, backend, identity, and destination prerequisites | stable diagnostic report |
| `install` | target environment | apply an approved plan to a new installation | install receipt and effective digest |
| `verify` | synthetic test traffic only | prove component health, identity propagation, privacy behavior, and end-to-end delivery | verification report with coverage and limitations |
| `status` | none | show desired/effective revision, component readiness, queue/delivery health, and drift | status snapshot |
| `connect` | local/platform registration | pair an installation with an approved SaaS, private, or customer endpoint | connection receipt without credentials |
| `upgrade` | target environment | plan and apply a signed compatible release | upgrade plan and receipt |
| `rollback` | target environment | restore a retained approved revision | rollback receipt and resulting digest |
| `support` | local output | create a sanitized diagnostic bundle | redaction report and support-bundle digest |

All commands support `--help`, `--output human|json`, and stable process exit
semantics. Mutating commands also support `--non-interactive`, `--plan-digest`,
and a dry-run mode. JSON output has a versioned schema and contains no ANSI
control characters. Human output may change for clarity; automation must use
JSON.

`install`, `upgrade`, and `rollback` must refuse to proceed when the current
target differs from the planned target, the input digest changed, an immutable
artifact cannot be verified, a required approval is missing or invalid, or a
regulated profile cannot establish its required failure posture.

## Backend boundary

The lifecycle engine owns contracts, validation, planning, receipts, locking,
and output. A deployment backend owns target-specific discovery, rendering,
diffing, application, health, and rollback.

The initial Kubernetes backend:

- uses the released Fabric Helm chart and pinned container digests;
- shows and records the exact Kubernetes context and namespace;
- uses server-side or Helm validation without leaking rendered Secrets;
- serializes concurrent mutations with a target-scoped lock;
- records the previous and effective release revision; and
- verifies more than pod readiness: ingress identity, trace correlation,
  privacy transformations, Relay delivery, and declared control posture.

Backend APIs are internal Go interfaces in the first release. A public plugin
protocol is deferred until at least two production backends establish a stable
boundary. Shelling out to arbitrary customer plugins is not part of the first
build.

## Platform connection

`fabricctl connect` must support:

- SingleAxis SaaS;
- a customer-hosted SingleAxis endpoint;
- a customer-owned OTLP destination; and
- a disconnected installation.

Interactive pairing may use a short-lived browser/device flow. Workloads use
customer-approved workload identity or secret-manager references after
pairing. Static access tokens are never written to `singleaxis.yaml`, generated
values, plan output, shell history recommendations, or support bundles.

Connection is not a prerequisite for offline `init`, `plan`, `doctor`, local
`verify`, or customer-owned export. Management availability must not enter the
agent request path. A connected installation continues under its last
verified approved configuration during a management outage.

## Security and regulated-operation requirements

- Raw content capture is off by default. The wizard must describe metadata,
  redacted-content, and governed-reference modes without presenting hashes as
  anonymization.
- PII detection is a selectable Control capability, while Collector redaction
  and allowlisting remain Observe export protections. The UI must not merge
  these distinct positions or imply that post-capture redaction protects the
  model input path.
- Every network operation identifies its destination before execution and
  uses server-authenticated TLS. Regulated profiles reject insecure transport.
- Every fetched release artifact is signature- and digest-verified before use.
- Logs and errors use structured redaction and never echo environment dumps,
  tokens, rendered Secret values, raw prompts, or raw tool payloads.
- Installation and upgrade receipts include actor/workload identity when
  available, time, source and target revisions, plan and bundle digests,
  approval reference, outcome, and verification summary.
- A3 profiles require separation between configuration author, approver, and
  deployment actor where the target identity system can prove it. The CLI
  cannot self-attest separation of duties.
- `support` starts from an allowlist, reports every included class of data, and
  supports local inspection before export. It never uploads automatically.
- Interrupted mutations are recoverable and leave an explicit incomplete
  operation record. Retrying is idempotent against the plan digest.

## Implementation slices

### Slice 0 — one CLI and one contract engine (complete)

- Port `FabricDeployment` validation, canonicalization, digest, and offline
  plan behavior to the Go CLI against shared contract fixtures.
- Define stable validation, plan identity, and exit semantics.
- Establish the Go binary as the canonical CLI while keeping Python behavior
  limited to a documented compatibility window.
- Add cross-language conformance coverage for accepted/rejected
  `FabricDeployment` fixtures and canonical digests.

Exit criterion: one canonical binary can reproduce every current Python
deployment validation and plan result without network or mutation.

### Slice 1 — guided bundle generation (complete)

- Implement `init`, profile explanations, secret-reference collection, safe
  review, and no-clobber bundle writes.
- Implement non-interactive `bundle build` using the same engine while
  retaining current `deployment validate|digest|plan` inspection commands.
- Generate and validate all six Offline Install Bundle v1 files.
- Validate the separate `FabricInstallTarget`, derived secret-requirements,
  installation-plan, and bundle-manifest schemas.
- Re-verify canonical inputs and every derived artifact through
  `doctor --offline --bundle`, including re-hashed stale content.
- Support Kubernetes only; label other backends unavailable.

Exit criterion: interactive and non-interactive inputs produce equivalent,
deterministic bundles whose schemas and security properties pass fixtures.

### Slice 2 — Kubernetes install and proof

- Implement target discovery, diff/dry-run, explicit confirmation, install,
  install receipts, enhanced `verify`, and `status`.
- Pin and verify chart/image artifacts.
- Prove an end-to-end synthetic decision traverses the configured ingress,
  Collector/processors, Relay, and selected destination without exposing its
  synthetic content.

Exit criterion: a clean supported cluster can be planned, installed, verified,
and inspected from a pinned release with no SingleAxis account.

### Slice 3 — optional Management connection

- Implement secure pairing and workload-identity registration.
- Accept and verify platform-generated bundles and approval envelopes.
- Report effective digest, rollout status, and receipts through public APIs.

Exit criterion: Git, CLI wizard, and dashboard-generated desired state converge
to the same effective digest and evidence record.

### Slice 4 — lifecycle safety

- Implement signed upgrade planning, compatibility checks, rollback,
  operation locking, drift reporting, and sanitized support bundles.
- Qualify interrupted operations and N-1 rollback.

Exit criterion: upgrades and rollback are deterministic, auditable, and tested
under component, network, and management-service failure.

### Slice 5 — additional backends

- Add local development and Docker Compose backends after Kubernetes behavior
  is stable.
- Evaluate a public backend plugin protocol only after the second production
  backend is complete.

## Acceptance criteria for every slice

1. Public schemas, valid and invalid fixtures, and compatibility rules exist
   before implementation is considered complete.
2. Human and JSON outputs are tested; JSON schemas are versioned.
3. Interactive and non-interactive paths exercise the same validation and plan
   code.
4. Tests cover corrupted bundles, stale plans, target mismatch, missing
   approvals, signature failure, interrupted writes, secret leakage, and
   malicious YAML/JSON inputs.
5. The released archive and binary, not only source tests, pass installation
   and behavior qualification on every supported platform.
6. Documentation states network calls, mutations, collected metadata, failure
   posture, recovery, and rollback for each command.
7. No command makes a legal compliance or deterministic-reproduction claim.
8. Deferred backends and private platform capabilities are visibly deferred;
   placeholders do not masquerade as functional controls.

## Non-goals

- Implementing the private SingleAxis dashboard, fleet service, Decision Graph,
  evidence store, regulatory mappings, or enterprise identity integrations in
  this repository.
- Acting as a general-purpose secrets manager, Kubernetes manager, policy
  authoring environment, or agent framework.
- Installing every optional Control or Assurance component for every customer.
- Reconstructing internal model reasoning or guaranteeing identical replay of
  nondeterministic models and external systems.
- Treating installation success as proof of regulatory compliance.

## Current state and migration

At this revision:

- Slice 0 is complete: the Go CLI owns offline `FabricDeployment` validate,
  digest, and plan behavior;
- Slice 1 is complete: guided `init` and non-interactive `bundle build`
  generate the exact six-file bundle, and offline doctor reconstructs and
  verifies it without target access;
- the shared public Go API and `contracts/lifecycle/v1` define bundle,
  artifact-lock, plan, approval, receipt, status, verification, pairing, and
  support semantics for CLI, GitOps, customer controllers, and platform
  consumers;
- Slice 2 is implemented through mutation-ready planning, exact digest-locked
  Helm install, target Lease, atomic failure recovery, receipts, status,
  receipt-bound drift detection, and metadata-only Collector ingress proof;
  a clean Kind cluster has exercised those paths successfully from current
  source;
- Slice 2 is not release-qualified: destination persistence acknowledgement,
  signed release/archive qualification, A3 cluster qualification, and the
  full interruption/failure matrix remain open;
- the OSS portion of Slice 3 provides an HTTPS-only, provider-neutral pairing
  client with ephemeral device credentials and signed connection receipts;
  the fleet APIs, bundle service, rollout state, and UI belong in
  `singleaxis-eval-platform` and are not implemented by this repository;
- Slice 4 provides operation locking, drift reporting, hash-chained receipts,
  purpose-separated approval trust, atomic install recovery, and local
  allowlisted support bundles. Upgrade and rollback remain deliberately
  unavailable on the public CLI until current-state binding and N-1 recovery
  qualification are complete;
- Slice 5 remains gated. Local and Docker Compose backends must not duplicate
  or weaken lifecycle behavior before Kubernetes destination proof and
  lifecycle-safety exit criteria stabilize;
- the Python/PyPI console script is compatibility surface, not an alternative
  place to add lifecycle features;
- no command uploads support data automatically, and no command represents
  Collector acceptance as destination persistence or legal compliance; and
- the private Management service does not yet generate and reconcile the
  complete public bundle.

## References

- [Spec 008 — Deployment model](008-deployment-model.md)
- [Spec 010 — Development and release standards](010-development-standards.md)
- [Spec 012 — Public distribution architecture](012-oss-commercialization-strategy.md)
- [Spec 025 — Product planes and packaging](025-product-planes-and-packaging.md)
- [`FabricDeployment` v1alpha1 contract](../contracts/management/v1alpha1/README.md)
- [Current Go `fabricctl`](../tools/fabricctl/README.md)
