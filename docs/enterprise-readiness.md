# Enterprise readiness

This page describes recorder v1 only. Fabric OSS is a customer-controlled,
passive data plane:

```text
CAPTURE -> PROTECT -> DELIVER
```

It does not install SingleAxis evaluation, governance, management, or inline
enforcement services. A release candidate is suitable for enterprise testing
only after the tagged commit passes the published release gates. It is not a
certification or a claim that a particular customer deployment is compliant.

## Trust boundary

- Fabric Node runs in customer-controlled infrastructure.
- The customer selects the OTLP destination. A SingleAxis account is optional.
- Raw prompts, responses, tool payloads, headers, credentials, and tokens are
  outside the default export allowlist.
- Metadata values can still be sensitive. Use opaque identifiers and perform
  customer-specific data classification before production use.
- Fabric does not receive hidden model reasoning and cannot capture behavior
  that an SDK, adapter, gateway, or existing telemetry source does not expose.

The allowlist is an export-minimization control, not semantic PII detection and
not a legal de-identification determination. Prompt-time PII blocking is a
separate optional enforcement capability and is not shipped in recorder v1.

## Production deployment posture

The `shadow-production` Helm profile is passive: it does not block, transform,
or delay the monitored application. It fails to render unless the operator
provides:

- a non-empty customer-controlled tenant identifier;
- TLS server identity and client-certificate verification for OTLP ingress;
- an explicit NetworkPolicy ingress peer for monitored workloads;
- an authenticated HTTPS exporter endpoint;
- explicit exporter egress peers and ports;
- a persistent, fsync-enabled sending queue with blocking overflow behavior;
- no volatile batching before that persistent queue;
- indefinite retry for transient export failures; and
- no debug exporter or customer extension to the production allowlist.

Queue PVCs are retained on deletion and scale-down. At-least-once export can
produce duplicates, so the destination must deduplicate preserved trace/span
identities. An OTLP or HTTP success means destination acceptance; it does not
prove durable persistence unless the destination separately provides that
evidence.

## Release and supply-chain controls

Recorder release policy permits only these public artifacts:

- the Python and TypeScript capture SDKs;
- the Fabric Node Collector image and Collector-only Helm chart;
- the recorder-only `fabricctl` binary; and
- activity, connection, recorder, privacy, and delivery contracts.

The release workflow verifies the exact tagged commit, required workflow
evidence, coordinated versions, package contents, artifact digests, SBOMs,
provenance, and signatures before creating a draft release. Registry
publication uses short-lived trusted identity where the registry supports it.

## Enterprise qualification responsibilities

Before promotion, the customer and SingleAxis must qualify the exact deployment
for:

1. connector coverage and known blind spots;
2. workload identity, certificate issuance, rotation, and revocation;
3. opaque identifier policy and metadata classification;
4. encrypted storage, capacity, retention, backup, and restore;
5. queue saturation, destination outage, and restart recovery;
6. destination deduplication and durable-acceptance semantics;
7. NetworkPolicy and external firewall enforcement;
8. operational alerting, runbooks, access review, and change approval; and
9. applicable legal, privacy, residency, and records-management obligations.

See [deployment](deployment.md), [auditor checklist](auditor-checklist.md), and
[qualification status](recorder-v1-qualification-status.md).
