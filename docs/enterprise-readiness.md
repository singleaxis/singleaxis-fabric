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

The optional host-emitter DaemonSet is a **qualification template**, not a
production-ready install. Its zero image digest and empty workload cgroup are
intentional stop conditions. Pin the exact tested image digest, select the
approved workload cgroup and nodes, provision the credential Secret, and
pre-provision `/var/lib/fabric-host-emitter` as a mode-0700 directory owned by
the emitter UID on
customer-approved encrypted persistent storage. The mounted source spool is
distinct from the Node queue and governed-content store. Size it for the
measured maximum outage and alert on backlog, corruption, quota exhaustion,
kernel loss and fatal exit. Do not enable source rate limiting for a
complete-source claim.

Run the static rendered-manifest gate with the independently approved image
identity:

```sh
python scripts/qualification/check_host_emitter_manifest.py \
  deploy/kubernetes/host-emitter-daemonset.yaml \
  --expected-image 'ghcr.io/singleaxis/fabric-host-emitter@sha256:<approved-64-hex-digest>'
```

The shipped template must fail this gate until filled. A passing static gate
does **not** prove Secret validity, disk encryption, cgroup coverage, kernel
compatibility, delivery, or loss accounting; those need target-cluster tests
and independent source reconciliation under specs 038–039.

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
[qualification status](recorder-v1-qualification-status.md). For terminal,
SSH, sandbox, database, and artifact capture claims, also use the
[agent-activity coverage and production gates](agent-activity-coverage.md).
The proposed critical-enterprise evidence qualification is specified by
[bounded deployment and control applicability](../specs/037-bounded-enterprise-deployment-and-controls.md),
[capture and source-loss tests](../specs/038-capture-boundary-and-loss-qualification.md),
and [storage, exact-artifact and shadow-pilot gates](../specs/039-storage-release-and-shadow-pilot.md).
These specs are draft; they do not constitute a current go decision.
