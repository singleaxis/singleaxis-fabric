---
title: Recorder-first OSS release
status: accepted
revision: 1
last_updated: 2026-08-31
owner: product-architecture
supersedes: 025
---

# 027 — Recorder-first OSS release

## Product promise

SingleAxis Fabric OSS is a customer-controlled recording data plane. Its first
stable release does three things:

```text
CAPTURE -> PROTECT -> DELIVER
```

It passively shadows observable AI activity, removes data that is not approved
for export, and reliably sends the resulting record to a destination selected
by the customer. A SingleAxis account is not required.

`Connect` describes how activity enters Fabric. `Verify` is a property of every
stage. Neither is a separate deployed layer.

## Stable release artifacts

| Artifact | Responsibility |
|---|---|
| Fabric SDKs | Optional in-process instrumentation and framework adapters |
| Fabric Node | OTLP ingestion, metadata categorization, export protection, buffering and delivery |
| `fabricctl` | Local recorder configuration creation, validation, digest, help and version reporting |

Fabric Node is the existing Fabric OpenTelemetry Collector distribution. The
separate Relay implementation is retained as experimental source, but is not a
second required hop or a recorder-v1 release artifact.

## Required behavior

### Capture

- accept OTLP from SDKs, framework adapters and customer telemetry pipelines;
- preserve source time, sequence and causal identity when supplied;
- distinguish observed facts from reported or inferred information;
- preserve the qualified metadata needed for a destination to map model, tool,
  retrieval, delegation, side-effect, retry, failure and cancellation activity
  into the common Activity Envelope v2 contract;
- never sample the audit stream.

### Protect

- default to metadata-only export;
- deny raw prompts, responses, tool arguments, tool results, headers,
  credentials and tokens unless a later explicit governed mode is configured;
- apply the export allowlist before data crosses the customer boundary;
- support a privacy assertion contract that binds the claimed input, protected
  output, policy, and processor build without treating an unsigned assertion as
  independent proof;
- make no claim that metadata-only export alone provides legal de-identification.

Prompt-time PII redaction, guardrails and tool authorization are runtime
enforcement. They are not part of the passive recorder default.

### Deliver

- hand acknowledged production telemetry directly to the persistent exporter
  queue before export; volatile pre-queue batching is disabled in that posture;
- use bounded queues with explicit overflow behavior;
- retry transient failures without a finite retry deadline in the production
  profile;
- support authenticated TLS delivery to a customer or SingleAxis destination;
- publish an interoperability contract that keeps queued, transmitted,
  destination-accepted and durably-persisted states distinct;
- preserve trace, span and upstream event identities for destination
  deduplication of at-least-once delivery.

An exporter HTTP success is not proof of durable destination persistence unless
the destination returns evidence for that state.

Fabric Node does not automatically emit delivery-receipt or signed privacy
assertion documents in recorder v1. Those public contracts allow a destination
adapter to add such evidence without changing the capture wire path.

## Deployment profiles

### `shadow-dev`

For local evaluation only. It may use non-durable debug output and relaxed
network settings. The CLI and chart must label it as unsuitable for production.

### `shadow-production`

For passive enterprise monitoring. It requires:

- authenticated TLS ingestion;
- authenticated HTTPS export;
- metadata-only protection enabled;
- custom allowlist extensions disabled;
- persistent, fsync-backed queue storage;
- no audit sampling;
- block-on-overflow behavior;
- indefinite retry for retryable delivery failures;
- debug export disabled;
- deny-by-default network policy with explicit ingress and egress.

The chart must fail validation when a required secret, endpoint, storage or
network decision is absent. It must not generate production credentials.

## Explicit non-goals

Recorder v1 does not ship or enable:

- judges, evaluation findings or continuous evaluation workers;
- red-team campaign runners;
- prompt-time PII, NeMo or prompt-injection sidecars;
- policy decisions, advisory controls or runtime enforcement;
- assurance tiers, regulatory mappings or legal compliance profiles;
- Decision Graph analytics, incident workflows, replay orchestration or
  evidence bundles;
- enterprise agent registry, approvals, rollout control or management UI.

Those capabilities may consume the open activity record in SingleAxis Platform
or customer systems. Their historical or experimental source may remain visible
in this public repository and its automatic source snapshots during migration,
but it is not compiled into recorder binaries, bundled into the recorder chart,
advertised as a recorder capability, installed, or published as a recorder
runtime artifact.

## Release gates

A recorder-v1 release must prove:

1. compatible SDK and direct OTLP inputs preserve the qualified identity,
   correlation and activity metadata required for reconstruction;
2. raw content placed in unapproved fields or native content channels cannot
   leave under the default protection policy;
3. audit traffic cannot be sampled;
4. traffic acknowledged into the durable production pipeline survives a Node
   restart when persistent storage is used;
5. retry and overflow behavior match the selected profile;
6. duplicate delivery retains the upstream trace/span identity and the public
   delivery contract validates explicit event/batch identities when used;
7. production configuration fails closed when TLS, authentication, storage or
   destination policy is incomplete;
8. only the Fabric Node, SDKs, CLI and public recorder contracts are published;
9. release artifacts have checksums, provenance and independently visible
   versions.

Fabric Node transports protected OTLP in recorder v1. Activity Envelope v2 is
the public downstream normalization and interchange contract; Fabric Node does
not claim to materialize that JSON envelope on its OTLP wire path.

## Commercial boundary

```text
Fabric OSS                 SingleAxis Platform          Optional later runtime
CAPTURE -> PROTECT ->      MONITOR -> EVALUATE ->       ENFORCE
DELIVER                    GOVERN
```

The trust boundary, activity contracts, privacy enforcement and delivery
verification remain open and locally auditable. SingleAxis monetizes fleet
orchestration, scalable monitoring, calibrated evaluation, investigations,
enterprise workflows and regulatory content.
