# Fabric documentation

Fabric OSS is a customer-controlled, passive recorder for AI systems:

```text
CAPTURE -> PROTECT -> DELIVER
```

These pages describe what the v0.8 release provides. A capability that is
not described here is not built; see
[limitations and roadmap](limitations-and-roadmap.md).

## Use Fabric

| Page | What it covers |
|---|---|
| [Quickstart](quickstart.md) | Offline example and zero-code capture through a local Node |
| [Architecture](architecture.md) | Components, data flow, what ships |
| [Deployment](deployment.md) | Compose and Helm, local and production profiles, required keys and policy, upgrade notes |
| [Privacy and security](privacy-and-security.md) | Protection modes, pseudonyms, encryption at rest, source authentication, threat model |
| [Operations](operations/README.md) | Spool, queues, health, metrics, troubleshooting, upgrades; [recovery runbook](operations/dr.md) |
| [Reconstruct and verdicts](reconstruct.md) | The offline verifier, gaps and verdicts |
| [Explicit APIs](explicit-apis.md) | `decision()`/`record_*`, `ByteEvidenceRecorder`, `CallRecorder`, byte-boundary adapters (Python and TypeScript) |
| [Qualified-run mode](qualified-run-mode.md) | Opt-in receipt- and witness-backed verification |
| [Host sensors](host-sensors.md) | auditd receiver and eBPF host emitter |
| [Limitations and roadmap](limitations-and-roadmap.md) | What is not captured, known defects, phases P1–P5 |

## Reference

- [GenAI semantic conventions](genai-semantic-conventions.md): span and
  attribute names emitted by the decision API.
- [API stability](api-stability.md): compatibility commitments.
- [Verify a release](verify-release.md): signatures, provenance and release
  qualification.
- SDKs: [Python](../sdk/python/README.md), [TypeScript](../sdk/typescript/README.md);
  [Fabric Node](../components/otel-collector-fabric/README.md);
  [Compose](../deploy/compose/README.md).
- Specifications: [specs/](../specs/README.md). The current capture
  contract is [049](../specs/049-four-layer-capture-coverage.md), with
  [047](../specs/047-llm-wire-capture-and-reconstruction.md) (wire capture
  and reconstruction) and
  [048](../specs/048-node-content-delivery-and-agent-spool.md) (Node
  content delivery and the agent spool).

## Public contracts

Published in the v0.8 contracts archive:
[Activity Envelope v2](../contracts/activity/v2/README.md),
[connector capability v1](../contracts/connect/v1/README.md),
[content objects and transcript manifests v1](../contracts/content/v1/README.md),
[delivery batch and receipt v1](../contracts/delivery/v1/README.md),
[privacy assertion v1](../contracts/privacy/v1/README.md),
[recorder configuration v1](../contracts/recorder/v1/README.md).

In the repository as drafts (used by v0.8 code, not in the published
archive): [capture v1](../contracts/capture/v1/README.md),
[content v2](../contracts/content/v2/README.md),
[coverage v1](../contracts/coverage/v1/README.md),
deployment-policy v1 (`contracts/deployment-policy/v1`),
[evidence v1](../contracts/evidence/v1/README.md),
[redaction v1](../contracts/redaction/v1/README.md).

## Contributors and maintainers

- [Building Fabric](building-fabric.md)
- [Third-party licenses](licenses/README.md)
- [Recorder cleanup audit](maintainers/recorder-cleanup-audit.md)
- [Historical secret-scan triage](security-history-triage.md)
- [Archive](archive/README.md): superseded documents, kept for history.
