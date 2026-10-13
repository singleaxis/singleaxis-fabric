# Fabric Node Collector

The Collector is the current implementation of the Fabric OSS recorder:

```text
OTLP receive -> default-deny allowlist -> queue -> OTLP/HTTP destination
```

The chart exposes only recorder concerns:

- OTLP/gRPC and OTLP/HTTP ingestion;
- optional receiver mTLS;
- the `fabricguard` export allowlist on logs and traces;
- secret-backed authenticated HTTPS export;
- persistent file-storage queue, retry and at-least-once delivery;
- no volatile pre-queue batching when the durable contract is enabled;
- health, resource, pod-security and NetworkPolicy settings;
- optional wire-capture content delivery (`content.*`, spec 043).

### Content delivery (`content.*`)

Disabled by default. When enabled the chart adds a dedicated receiver
`otlp/content` (port `service.ports.otlpContent`, 4319; HTTP only; 64 MiB
per request; the same server certificate and client CA as 4317/4318), a
`logs/content` pipeline running only `memory_limiter`, and the
`fabriccontent` exporter, which verifies digest, length and tenant and
writes bodies + descriptors to `backend: s3` (bucket, prefix, region,
optional endpoint and path-style for S3-compatible stores, `sse`
`aws:kms`/`AES256`, `kmsKeyId`) or `backend: file` (single replica, inside
the queue PVC). Content is never routed to `exporter.endpoint` and never
passes `fabricguard` (bodies must pass unchanged). The Node is the only
writer: give its ServiceAccount the writer role (IRSA via
`serviceAccount.annotations`); `content.s3.credentialsSecret` references
operator-created static keys for stores without workload identity. Values
never contain keys. The content queue lives at
`<persistence.directory>/content-queue` on the queue PVC (memory-only
without persistence). `networkPolicy.contentEgress` names the store (and
STS) peers; NetworkPolicy ingress opens 4319 to the same `ingressFrom`
peers. Render fails without `allowedTenants` or a backend, on an invalid
bucket, prefix or endpoint, on `kmsKeyId` without `aws:kms`, and with
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
