# Fabric Node Collector

The Collector is the current implementation of the Fabric OSS recorder:

```text
OTLP receive -> default-deny allowlist -> queue -> OTLP/HTTP destination
```

The chart exposes only recorder concerns:

- OTLP/gRPC and OTLP/HTTP ingestion;
- optional receiver mTLS;
- optional dedicated evidence ingress with one Secret-backed bearer token
  bound to one declared tenant/source identity;
- the `fabricguard` export allowlist on logs and traces;
- secret-backed authenticated HTTPS export;
- persistent file-storage queue, retry and at-least-once delivery;
- no volatile pre-queue batching when the durable contract is enabled;
- health, resource, pod-security and NetworkPolicy settings.

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
