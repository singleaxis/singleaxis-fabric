# Fabric Node Collector

The Collector is the current implementation of the Fabric OSS recorder:

```text
OTLP receive -> default-deny allowlist -> queue -> OTLP/HTTP destination
```

The chart exposes only recorder concerns:

- OTLP/gRPC and OTLP/HTTP ingestion;
- optional receiver mTLS;
- optional workload-scoped bearer authentication for ordinary traces/logs;
- optional dedicated evidence ingress with one Secret-backed bearer token
  bound to one declared tenant/source identity;
- the `fabricguard` export allowlist on logs and traces;
- secret-backed authenticated HTTPS export;
- persistent file-storage queue, retry and at-least-once delivery;
- no volatile pre-queue batching when the durable contract is enabled;
- health, resource, pod-security and NetworkPolicy settings;
- optional wire-capture content delivery (`content.*`, spec 048).

## Content delivery (`content.*`)

Disabled by default. When enabled the chart adds a dedicated receiver
`otlp/content` (port `service.ports.otlpContent`, 4319; HTTP only; 64 MiB
per request; the same server certificate and client CA as 4317/4318), a
`logs/content` pipeline running only `memory_limiter`, and the
`fabriccontent` exporter, which verifies digest, length and tenant and
writes bodies + descriptors to `backend: s3` (bucket, prefix, region,
optional endpoint and path-style for S3-compatible stores, required `sse`
`AES256` (default) or `aws:kms`, `kmsKeyId`) or `backend: file` (single
replica, inside the queue PVC). `allowedTenants` holds exactly one tenant
unless `allowMultipleTenants=true`, which trusts every authenticated agent
to name its tenant (a content record names its own); use one Node per tenant
otherwise. Content is never routed to `exporter.endpoint` and never
passes `fabricguard` (bodies must pass unchanged). The Node is the only
writer: give its ServiceAccount the writer role (IRSA via
`serviceAccount.annotations`); `content.s3.credentialsSecret` references
operator-created static keys for stores without workload identity. Values
never contain keys. The content queue lives at
`<persistence.directory>/content-queue` on the queue PVC (memory-only
without persistence). `networkPolicy.contentEgress` names the store (and
STS) peers, and is required whenever `networkPolicy.enabled=true` with an
s3 backend (the policy would otherwise block every content write);
NetworkPolicy ingress opens 4319 to the same `ingressFrom` peers. The
memory guard reads `resources.limits.memory` in any Kubernetes quantity
form (bytes, `M`/`G`, `Mi`/`Gi`, decimals). Render fails without `allowedTenants` or a backend, on more than one
tenant without `allowMultipleTenants`, on an s3 backend without `sse`, on an
invalid bucket, prefix or endpoint, on `kmsKeyId` without `aws:kms`, and with
`requireServerSideEncryption=true` (pinned by `shadow-production`) on
missing SSE or the file backend. `tests/test-content-delivery.sh` is the
render contract.

It does not expose runtime policy, prompt-time PII processing, Presidio,
sampling, judges, red teaming, or governance. Those concerns are not part of
the Fabric Node v1 deployment path.

Use the umbrella chart's `shadow-dev` or `shadow-production` profile rather
than installing this dependency directly. The production profile enforces the
secure transport, persistent queue and deny-default network posture as a
single render-time contract.

The durable posture hands acknowledged OTLP directly to the persistent exporter
queue. The queue protects transient delivery; it is not an evidence database
and does not establish exactly-once delivery or prove that an arbitrary
destination durably persisted an acknowledged request.

For the bounded evidence profile in spec 044, set
`receiver.evidenceSourceBinding.enabled=true` with `tenantId`, `sourceId`, and
`tokenSecret.name` (plus an optional `tokenSecret.key`, default `token`). The
Secret must already exist in the Collector namespace and contain a single
operator-approved token with no trailing newline. Configure receiver TLS and
an HTTPS export destination as well. Helm references the Secret by name/key;
the token value never enters values or the ConfigMap. Both OTLP protocols use
the same bearer authenticator, and `fabricguard` checks the declared identity
on every evidence batch. The shipped patched bearer extension also rejects
empty or multiple token entries immediately on startup and reload. A missing
Secret prevents the pod from starting. The
Secret's sole use by the declared source, its rotation and the source's route
closure require deployment proof; this chart setting alone does not establish
complete capture or a production GO.

## Ordinary workload authentication

`receiver.workloadAuthentication` requires mTLS and a separate workload-scoped
Secret token on both OTLP protocols. Configure `enabled`, `tenantId`,
`workloadId`, `identityAttestationRef`, and `tokenSecret.name`/`key`. A token is
32–4096 printable ASCII bytes with no spaces or newlines; the shipped singleton
authenticator rejects malformed values on startup and reload. The Secret must
already exist; its contents are never Helm values or ConfigMap data. This mode
requires verified HTTPS egress and disables debug export. It is separate from
`evidenceSourceBinding` and does not reject ordinary traces.

The identity review must cover token custody, certificate issuance and rotation
for that one workload. The receiver authenticates credential possession, not
arbitrary tenant/source strings supplied in telemetry. It does not compare a
client certificate SAN to `workloadId`. The identity fields and optional paired
`policyVersion`/`policyDigest` are deployment-owned Pod annotations, not a policy
engine or per-record evidence. Full production requirements and migration
arguments are in the [umbrella chart README](../../README.md).

The persistent queue's `encryptionAttestationRef` identifies a customer review of
the chosen StorageClass or existing PVC. It neither enables nor verifies disk
encryption. The production umbrella requires explicit storage selection plus
this reference. Real credentials, KMS state, wrong-identity rejection and durable
readback must be independently qualified before production approval.
