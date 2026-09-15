# Fabric documentation

Fabric OSS is the customer-controlled recorder:

```text
CAPTURE -> PROTECT -> DELIVER
```

The accepted scope and release gates are in
[spec 027](../specs/027-recorder-v1.md). When an older document conflicts with
that specification, 027 controls the recorder release.

## Start here

- [Quickstart](quickstart.md) — record one agent operation and send it through
  a local Fabric Node.
- [Architecture](architecture.md) — how the system works end to end: pipeline
  diagrams, the protection gate, delivery lifecycle, and deployment
  topologies.
- [Deployment](deployment.md) — `shadow-dev` and fail-closed
  `shadow-production` installation.
- [Integration models](integration-models.md) — SDK, existing OTLP pipeline,
  framework adapter, gateway, and vendor integration choices.
- [Capturing interactions](capturing-interactions.md) — model, tool, retrieval,
  memory, delegation, side-effect, failure, and retry activity.
- [Exporting to your backend](exporting-to-your-observability-backend.md) —
  customer-owned and SingleAxis destinations.
- [Install a pinned release](install.md) and
  [verify a release](verify-release.md) — artifact integrity and promotion.
- [Qualification status](recorder-v1-qualification-status.md) — implemented
  behavior, contract-only surfaces, required CI, and known boundaries.
- [API stability](api-stability.md) — compatibility commitments.

## Public contracts

- [Activity Envelope v2](../contracts/activity/v2/README.md)
- [Connector capability contract](../contracts/connect/v1/README.md)
- [Recorder configuration](../contracts/recorder/v1/README.md)
- [Privacy assertion](../contracts/privacy/v1/README.md)
- [Delivery batch and receipt](../contracts/delivery/v1/README.md)

Contract links may appear before a release is published while the release
candidate is being qualified.

The schema `$id` authorities differ across contract families for historical
reasons and are stable published identities, not resolvable URLs:
`schemas.singleaxis.dev` (activity v2, privacy, delivery), `singleaxis.ai`
(connect, assurance), `singleaxis.dev` (recorder), `fabric.singleaxis.dev`
(lifecycle, management), and a `github.com` repository address (activity v1).
They are intentionally not renumbered.

## Historical and optional capability documents

Documents about judges, red teams, prompt-time guardrails, policy enforcement,
assurance findings, Decision Graph, regulatory profiles, or enterprise
governance are not the recorder-v1 product guide. They remain in the repository
as historical design records or optional integration references until they are
migrated or removed. None of those systems is installed by the recorder default.

## Status

Recorder v1 is being qualified for enterprise testing. Production claims are
limited to behavior proven by the qualification evidence published with a
release.
