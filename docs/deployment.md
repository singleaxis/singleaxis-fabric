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
- **Peer rules.** Every NetworkPolicy peer in `ingressFrom`,
  `exporterEgress.to`, and `egressTo` must be non-empty and must not use a
  world CIDR (`0.0.0.0/0`, `::/0`); such entries are equivalent to no
  policy and are rejected at render time. The health extension is not
  exposed by NetworkPolicy by default — kubelet probes are node traffic.
  To let a monitoring stack scrape it, set
  `otel-collector.networkPolicy.monitoringNamespaceSelector`.
- **Pull secrets.** Set `otel-collector.imagePullSecrets`; there is no
  parent-level `imagePullSecrets` key.
- **`helm test` is dev-only.** The bundled test pod matches no ingress
  peer under `shadow-production`; run it under `shadow-dev` only.

## Production invariants

`shadow-production` must render only when all of these are true:

- OTLP receivers require TLS and a verified client certificate;
- the export endpoint is HTTPS and authenticated;
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
- every declared network peer is non-empty and non-world;
- default-deny network policy and explicit workload ingress and destination
  egress are enabled.

Helm validation proves configuration shape and required references. Pod
readiness proves that referenced Secrets and storage are actually available.

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
