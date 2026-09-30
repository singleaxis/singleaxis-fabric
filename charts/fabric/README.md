# Fabric Node Helm chart

Fabric Node is the customer-controlled OSS recorder for passive shadow
monitoring:

```text
CAPTURE -> PROTECT -> DELIVER
```

This chart intentionally installs one runtime: the Fabric OpenTelemetry
Collector. It receives OTLP activity, applies the deny-by-default export
allowlist, buffers records locally, and sends them to a destination selected by
the customer. It does not install judges, red-team runners, guardrails,
prompt-time PII controls, governance services, or a SingleAxis-only backend.

Fabric Node is asynchronous to the monitored AI system. A Collector or
destination outage must not become a production request-path dependency.

## Profiles

### `shadow-dev`

For local evaluation and CI only. Receiver traffic is plaintext and
unauthenticated. Without an endpoint, records are printed to Collector stdout,
which is neither durable nor an audit trail.

```bash
helm upgrade --install fabric-node charts/fabric \
  --namespace fabric-system --create-namespace \
  --values charts/fabric/profiles/shadow-dev.yaml
```

### `shadow-production`

Fails closed at render time unless the recorder has:

- receiver TLS with required client certificates;
- an HTTPS destination and secret-backed authentication;
- deny-by-default export allowlisting;
- an fsync-enabled persistent queue that blocks on overflow;
- no volatile batch processor before the persistent queue;
- indefinite retry for transient destination failures;
- no debug exporter and no sampler;
- a ClusterIP-only Collector Service — NodePort/LoadBalancer is rejected;
- a pinned Collector image (sha256 digest recommended; `latest` and empty
  tags are rejected);
- a non-root pod that cannot escalate privileges or mount an API token;
- namespace deny-default and explicit Collector ingress/egress policy,
  where every peer must be non-empty and non-world (`{}` and
  `0.0.0.0/0`/`::/0` are rejected).

The customer must create the referenced Secrets and identify the exact egress
peer/port. Example render/install arguments:

```bash
helm upgrade --install fabric-node charts/fabric \
  --namespace fabric-system --create-namespace \
  --values charts/fabric/profiles/shadow-production.yaml \
  --set tenant.id=customer-production \
  --set otel-collector.exporter.endpoint=https://telemetry.customer.example \
  --set 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true' \
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP' \
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
```

Label the monitored workload namespace with `fabric.singleaxis.ai/agent=true` or
replace the ingress selector with an operator-approved peer. The documentation
CIDR is not a working destination. Replace it with the
customer's approved backend or egress gateway. Provision these Secrets first:

| Secret | Required keys | Purpose |
|---|---|---|
| `fabric-node-receiver-tls` | `tls.crt`, `tls.key` | OTLP server identity |
| `fabric-node-client-ca` | `ca.crt` | verify telemetry clients |
| `fabric-node-export-auth` | `authorization` | destination auth header |

The production profile has no implicit ingress peer. Supply an explicit
`otel-collector.networkPolicy.ingressFrom` selector for each monitored workload
namespace; do not broaden it to the whole cluster.

Select a customer-approved encrypted StorageClass with
`otel-collector.exporter.sendingQueue.persistence.storageClass`, or supply a
customer-owned existing claim for a single replica.

## Namespace and operations notes

- Install into a **dedicated namespace**. `networkPolicy.denyDefault`
  selects all pods in the release namespace; unrelated workloads placed
  there lose pod-to-pod traffic. When `namespace.create=true`,
  `namespace.name` must equal the release namespace passed to
  `--namespace`, because all resources render into the release namespace.
- `helm test` is dev-only: the bundled connection-test pod matches no
  ingress peer under `shadow-production`. Run it under `shadow-dev`.
- The health extension (default port 13133) is not opened by
  NetworkPolicy. kubelet probes are node traffic and need no from-rule on
  most CNIs; to allow an in-cluster monitoring stack, set
  `otel-collector.networkPolicy.monitoringNamespaceSelector` to a
  LabelSelector naming that namespace.
- Pull secrets belong under `otel-collector.imagePullSecrets`. There is no
  parent-level `imagePullSecrets` value; a top-level key would not reach
  the Collector pod.
- The bundled `otel-collector` dependency is vendored. Do not run
  `helm dependency update` on this chart.

## Reliability semantics

The persistent sending queue and indefinite retry provide restart-tolerant,
at-least-once delivery for transient failures. They do **not** provide:

- exactly-once delivery (destinations must deduplicate stable event IDs);
- infinite capacity or protection from disk/storage loss;
- recovery from permanently invalid records;
- proof that an arbitrary destination durably persisted an acknowledged batch;
- an authoritative evidence store inside the queue.

Treat Collector acceptance, queued delivery, destination acknowledgement, and
destination durable persistence as distinct states.

## Protection semantics

`fabricguard` is enabled with unknown event classes dropped and trace
attributes restricted to exact approved metadata keys. This is a default-deny export
allowlist. It is not prompt-time PII redaction and it cannot determine that a
value inside an allowed field is safe. Keep raw prompt, response, and tool
payload fields out of the exported envelope unless the customer explicitly
governs them.

## Verify the chart

```bash
charts/fabric/tests/test-values-schema.sh
charts/fabric/tests/schema-validation.sh
helm lint charts/fabric
helm template fabric-node charts/fabric \
  --values charts/fabric/profiles/shadow-dev.yaml
```

The Compose evaluation harness at `deploy/compose` exercises the same
Collector-only path with a controlled test sink and durable local volumes.
