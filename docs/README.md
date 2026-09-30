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
- [Agent activity coverage](agent-activity-coverage.md) — terminal, SSH,
  sandbox, database, network, file, and artifact evidence levels, blind spots,
  and production qualification gates.
- [Agent Execution Evidence Profile](../specs/035-agent-execution-evidence-profile.md)
  — draft OTLP/W3C protocol for interoperable operations, evidence references,
  and run-level completeness.
- [Evidence capture build plan](../specs/036-evidence-capture-implementation-plan.md)
  — draft contracts, adapter sequence, conformance gates, and honest coverage
  claims; not a shipped capture capability.
- [Enterprise go/no-go qualification](../specs/037-bounded-enterprise-deployment-and-controls.md)
  — draft bounded deployment and control matrix, with
  [capture/loss gates](../specs/038-capture-boundary-and-loss-qualification.md)
  and [storage/release/shadow-pilot gates](../specs/039-storage-release-and-shadow-pilot.md).
- [Capturing interactions](capturing-interactions.md) — model, tool, retrieval,
  memory, delegation, side-effect, failure, and retry activity.
- [Recording a custom agent](custom-agent-recording.md) — wrap an existing
  dispatcher, retain actual permitted bytes and reconstruct linked calls;
  [privacy choices](custom-agent-recording-privacy.md) distinguish exact
  originals from omitted or masked content.
- [Offline evidence statements](evidence-attestation-verification.md) —
  verify approved issuer signatures without claiming that a signature alone
  proves a complete run; [independent feed contract](../specs/045-independent-evidence-feeds.md)
  specifies the separate operation and byte records required from witnesses.
- [Qualified bounded call-run testing](qualified-call-run-testing.md) —
  combine signed witness feeds, exact original data, fresh source readback and
  four distinct receipt sets; reproduce the installed-package loss tests.
- [Exporting to your backend](exporting-to-your-observability-backend.md) —
  customer-owned and SingleAxis destinations.
- [Install a pinned release](install.md) and
  [verify a release](verify-release.md) — artifact integrity and promotion.
- [Qualification status](recorder-v1-qualification-status.md) — implemented
  behavior, contract-only surfaces, required CI, and known boundaries.
- [Governed content](governed-content.md) — opt-in capture of actual
  content to customer-controlled storage: postures, stores, durability,
  resolution/export, coverage limits, and migration from `capture_content`.
- [Historical governed-content gap assessment](governed-content-gap-assessment.md)
  — the dated September 22 baseline for specs 028–034, not current capability
  status. Use the qualification status above for current test evidence.
- [API stability](api-stability.md) — compatibility commitments.

## Public contracts

- [Activity Envelope v2](../contracts/activity/v2/README.md)
- [Connector capability contract](../contracts/connect/v1/README.md)
- [Content objects and transcript manifests](../contracts/content/v1/README.md)
- [Draft AEEP evidence contract](../contracts/evidence/v1/README.md) and
  [draft byte-content v2 contract](../contracts/content/v2/README.md) —
  schemas and conformance fixtures only; recorder v1 does not emit them.
- [Recorder configuration](../contracts/recorder/v1/README.md)
- [Privacy assertion](../contracts/privacy/v1/README.md)
- [Delivery batch and receipt](../contracts/delivery/v1/README.md)

Contract links may appear before a release is published while the release
candidate is being qualified.

The schema `$id` authorities differ across contract families for historical
reasons and are stable published identities, not resolvable URLs:
`schemas.singleaxis.dev` (activity v2, privacy, delivery), `singleaxis.ai`
(connect), `singleaxis.dev` (recorder), and a `github.com` repository address
(activity v1). They are intentionally not renumbered.

## Removed capability surfaces

This repository carries recorder-v1 scope only. Judges, red-team runners,
prompt-time guardrails, policy enforcement, assurance findings, Decision
Graph, and enterprise governance sources were removed when the recorder scope
became authoritative; their design history lives in git history. The release
boundary tests prove none of them can reach an artifact.

## Status

Recorder v1 is being qualified for enterprise testing. Production claims are
limited to behavior proven by the qualification evidence published with a
release.
