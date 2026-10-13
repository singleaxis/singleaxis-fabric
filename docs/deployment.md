# Deployment

The supported recorder-v1 Kubernetes unit is the Fabric umbrella chart. It
packages only Fabric Node.

## Choose a profile

| Profile | Use | Posture |
|---|---|---|
| `shadow-dev` | Local evaluation | Plaintext input and debug output are allowed; no durability claim |
| `shadow-production` | Passive enterprise monitoring | Fail-closed configuration, mTLS input, authenticated HTTPS output, persistent queue, no sampling |

These profiles are operating postures, not regulatory certifications.

## Local evaluation

```bash
helm dependency build charts/fabric
helm upgrade --install fabric charts/fabric \
  --namespace fabric-system \
  --create-namespace \
  --values charts/fabric/profiles/shadow-dev.yaml
```

With no destination, `shadow-dev` writes protected metadata to the Collector
debug exporter. Pod logs are neither durable storage nor an audit trail.

## Production shadow deployment

The production profile deliberately cannot invent credentials, storage, or an
approved egress route. Before installation, create these Secrets in the target
namespace:

| Secret | Keys | Purpose |
|---|---|---|
| `fabric-node-receiver-tls` | `tls.crt`, `tls.key` | Fabric Node OTLP server identity |
| `fabric-node-client-ca` | `ca.crt` | CA used to authenticate OTLP clients |
| `fabric-node-export-auth` | `authorization` | Complete outbound authorization value |

Select an encrypted StorageClass or a customer-owned persistent volume. Then
label or select the monitored workload namespace, then install with a real
tenant identity, HTTPS destination, and explicit ingress and egress peers. This
example CIDR is documentation-only:

```bash
kubectl label namespace monitored-agents fabric.singleaxis.ai/agent=true

helm dependency build charts/fabric
helm upgrade --install fabric charts/fabric \
  --namespace fabric-system \
  --create-namespace \
  --values charts/fabric/profiles/shadow-production.yaml \
  --set tenant.id=TENANT_UUID \
  --set otel-collector.exporter.endpoint=https://otlp.example.com \
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true' \
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
```

Set the persistent volume StorageClass through the Collector subchart values
described in the chart README. Kubernetes NetworkPolicy cannot match a DNS name
or prove that a CIDR belongs to the configured URL; route through an approved
egress gateway when that is the organization's control point.

Operational notes:

- **Dedicated namespace.** Install into a namespace used only by the
  recorder. `networkPolicy.denyDefault` selects every pod in the release
  namespace, so co-located workloads lose pod-to-pod traffic unless a
  subchart policy opens it. When `namespace.create=true`,
  `namespace.name` must equal the release namespace (`--namespace`) —
  resources are always rendered into the release namespace.
- **Pinned image.** `shadow-production` rejects the `latest` tag and the
  empty-tag appVersion fallback. Prefer
  `--set otel-collector.image.digest=sha256:<64-hex>`; an explicit
  non-latest `otel-collector.image.tag` is accepted.
- **Peer rules.** Every NetworkPolicy peer you supply in `ingressFrom`,
  `exporterEgress.to`, `contentEgress.to` and `egressTo` must restrict
  something, in every profile; anything equivalent to no policy is
  rejected at render time: an empty peer; a `namespaceSelector` that is
  empty, null or exclusion-only (`NotIn`/`DoesNotExist`) without a
  `podSelector` that narrows it; an empty `podSelector` alone (every pod in
  the namespace); an `ipBlock` with prefix length 0 (`0.0.0.0/0`, `::/0`,
  `10.0.0.0/0`, …); an `ipBlock` combined with a selector. A selector
  restricts when it has `matchLabels` or an `In`/`Exists` expression. An
  empty `ingressFrom` keeps the development default (any namespace) and is
  refused by `shadow-production`. The health extension is not exposed by
  NetworkPolicy by default — kubelet probes are node traffic. To let a
  monitoring stack scrape it, set
  `otel-collector.networkPolicy.monitoringNamespaceSelector` (the same
  restriction rule applies).
- **Destination URLs.** `exporter.endpoint` (and `content.s3.endpoint`
  when set) must be `scheme://host[:port][/path]` with a DNS name, dotted
  IPv4 address or bracketed IPv6 address and a port 1–65535, and must not
  carry user info, a query or a fragment: a credential pasted into the URL
  would land in the rendered ConfigMap. Put the destination credential in
  the `fabric-node-export-auth` Secret. `shadow-production` requires
  `https://`. Render errors name the field and never echo the value.
- **Pull secrets.** Set `otel-collector.imagePullSecrets`; there is no
  parent-level `imagePullSecrets` key.
- **`helm test` is dev-only.** The bundled test pod matches no ingress
  peer under `shadow-production`; run it under `shadow-dev` only.

## Content delivery for LLM wire capture (optional)

Wire capture (spec 043) sends stored request/response bodies to a separate
content receiver on the Node (`otlp/content`, port 4319, OTLP/HTTP only,
64 MiB per request). The `fabriccontent` exporter verifies each record's
descriptor, digest, length and tenant and writes it to the customer store.
The Node is the only content writer; agents hold no cloud credentials.
Content never enters the telemetry pipelines and never reaches
`exporter.endpoint`. It is off by default. To enable it in
`shadow-production`, create the Node writer role (see
[wire-capture-deployment.md](wire-capture-deployment.md#4-minimal-iam)) and
add:

```bash
  --set otel-collector.content.enabled=true \
  --set 'otel-collector.content.allowedTenants[0]=TENANT_ID_USED_BY_AGENTS' \
  --set otel-collector.content.backend=s3 \
  --set otel-collector.content.s3.bucket=customer-evidence \
  --set otel-collector.content.s3.region=eu-west-1 \
  --set otel-collector.content.s3.sse=aws:kms \
  --set otel-collector.content.s3.kmsKeyId=arn:aws:kms:eu-west-1:111122223333:key/KEY_ID \
  --set 'otel-collector.serviceAccount.annotations.eks\.amazonaws\.com/role-arn=arn:aws:iam::111122223333:role/fabric-node-writer' \
  --set 'otel-collector.networkPolicy.contentEgress.to[0].ipBlock.cidr=198.51.100.0/24' \
  --set 'otel-collector.networkPolicy.contentEgress.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.contentEgress.ports[0].port=443'
```

`allowedTenants` takes exactly one tenant: a content record names its own
tenant, so a Node allowing several would let any authenticated agent write
under another tenant's prefix. Run one Node per tenant; only
`otel-collector.content.allowMultipleTenants=true` permits more, and it
trusts every authenticated agent to name its tenant. The rule is per Node:
the chart renders one `fabriccontent` exporter, and `fabric-gate` refuses a
hand-written or overlaid configuration whose `fabriccontent` exporters share
a receiver or pipeline but do not all allow the same single tenant (unless
every one of them sets `allow_multiple_tenants: true`). `content.s3.sse` is
required for the s3 backend (`AES256` by default, or `aws:kms`).

The content receiver uses the same server certificate, client CA and
NetworkPolicy ingress peers as 4317/4318. The content queue shares the
queue PVC (`<persistence.directory>/content-queue`, fsync); size the PVC for
`content.queue.queueSize` × 64 MiB in addition to the telemetry queue, and
raise `resources.limits.memory` above `content.memoryLimiterMiB`. The chart
refuses to render content without allowed tenants, a backend and a valid
bucket; in `shadow-production` it also requires SSE, an `https://` store
endpoint (when one is set, for S3-compatible stores), store egress peers,
and refuses the file backend. For an S3-compatible store without workload
identity, reference an operator-created Secret with
`otel-collector.content.s3.credentialsSecret.name`; keys never go in values.

A successful rollout does not prove that content reaches the store (bucket
policy, IRSA trust, KMS grants and store egress are only exercised by a real
upload). After each deployment change run the content canary described in
[wire-capture-deployment.md](wire-capture-deployment.md#5-verify-a-run).

## Production invariants

`shadow-production` must render only when all of these are true:

- OTLP receivers require TLS and a verified client certificate;
- the export endpoint is an HTTPS URL with a valid host and port, no user
  info, query or fragment, and is authenticated through a Secret;
- metadata-only protection is enabled;
- custom allowlist extensions are empty in the named production profile;
- at least one operator-supplied workload ingress peer is present;
- the sending queue uses persistent file storage with fsync;
- volatile batching before the persistent exporter queue is disabled;
- overflow blocks intake instead of silently discarding accepted audit data;
- retry has no finite maximum elapsed time for retryable failures;
- the debug exporter is disabled;
- the audit path is not sampled;
- the Collector Service is ClusterIP (no NodePort/LoadBalancer exposure);
- the Collector image is pinned by digest or explicit non-latest tag;
- the pod runs as non-root and cannot escalate privileges;
- every declared network peer restricts its sources or destinations (no
  empty, unrestricted-selector or prefix-length-0 peer);
- when content delivery is enabled: allowed tenants, an s3 backend with
  server-side encryption, the same mTLS on port 4319, a persistent content
  queue and explicit store egress;
- default-deny network policy and explicit workload ingress and destination
  egress are enabled.

Helm validation proves configuration shape and required references. Pod
readiness proves that referenced Secrets and storage are actually available.

Independently of the chart, the Node's `fabric-gate` entrypoint refuses to
boot any configuration (Helm, Compose or hand-written, overlays included)
in which a `traces` or `logs` pipeline does not run `fabricguard`, or runs a
processor other than `batch` or `memory_limiter` after it, or in which
content could leave its own path (a content receiver or the `fabriccontent`
exporter outside `logs/content`, any other processor or exporter on that
pipeline, gRPC on the content receiver, or connectors). For LLM wire
capture see [wire-capture-deployment.md](wire-capture-deployment.md).

## Delivery semantics

Fabric Node uses at-least-once delivery. Destinations must deduplicate using
preserved trace/span identity or an event/batch identity supplied by an upstream
or destination adapter. A restart or retry can produce a duplicate; losing an
accepted audit record to avoid duplication would be the wrong tradeoff.

Delivery states remain distinct:

```text
accepted by Node -> queued -> transmitted -> destination accepted
                                           -> durably persisted (only with destination proof)
```

An OTLP success response establishes destination acceptance, not arbitrary
backend retention or WORM persistence.

The production pipeline hands acknowledged OTLP directly to the persistent
exporter queue. It disables the optional in-memory batch processor because a
pod failure during that pre-queue batching window could otherwise lose recently
acknowledged telemetry. This favors audit reliability over maximum throughput.

Recorder v1 defines the delivery receipt contract but Fabric Node does not
automatically emit a receipt document for each exported OTLP batch.

## Other deployment models

- **Existing collector:** add Fabric Node as a protected OTLP destination or
  route compatible telemetry through its processor chain.
- **Customer backend:** export to an OTLP service operated entirely by the
  customer.
- **Private SingleAxis:** export to SingleAxis Platform deployed inside the
  customer's environment.
- **SingleAxis SaaS:** export only protected records over the approved endpoint.

All models use the same public contracts. No management-plane connection is
required to start or continue local capture.

## Not deployed

The recorder chart does not package Relay, Presidio, NeMo, Prompt Guard,
Langfuse, red-team runners, judge workers, update agents, assurance profiles,
or enterprise management services. Their older source directories are not
Helm dependencies or recorder release images.
