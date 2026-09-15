# Delivering protected records

Fabric Node has one qualified OTLP/HTTP destination. That destination may be a
customer-owned OpenTelemetry Collector or backend, a private SingleAxis
deployment, or SingleAxis Platform.

```text
agent telemetry -> Fabric Node -> one approved OTLP/HTTP destination
                   protect       persistent queue + retry
```

Using one destination keeps credentials, retry semantics, and delivery status
reviewable. For fan-out, send Fabric to a customer-owned Collector or gateway
and configure multiple exporters there.

## Local evaluation

With `shadow-dev`, an empty endpoint uses the debug exporter:

```bash
helm upgrade --install fabric charts/fabric \
  --namespace fabric-system --create-namespace \
  --values charts/fabric/profiles/shadow-dev.yaml
```

Pod output is useful for a smoke test. It is not durable storage or an audit
record and must not be used across a production trust boundary.

To test against a local OTLP/HTTP destination:

```bash
helm upgrade --install fabric charts/fabric \
  --namespace fabric-system --create-namespace \
  --values charts/fabric/profiles/shadow-dev.yaml \
  --set otel-collector.exporter.endpoint=http://customer-otel:4318 \
  --set otel-collector.debugExporter.enabled=false
```

## Production delivery

`shadow-production` requires all of the following:

- an HTTPS destination;
- an operator-created Secret containing the complete outbound authorization
  value;
- persistent file storage with fsync for the sending queue;
- blocking overflow behavior and indefinite retry for retryable failures;
- default-deny networking with an explicit destination peer and port;
- no debug exporter and no audit sampling.

The default Secret reference is `fabric-node-export-auth` with key
`authorization`. Create it without putting credentials in Helm values:

```bash
kubectl --namespace fabric-system create secret generic fabric-node-export-auth \
  --from-file=authorization=/secure/path/authorization-header-value
```

Install with an approved endpoint and egress route as described in
[Deployment](deployment.md). If a backend requires a vendor-specific header,
set `otel-collector.exporter.auth.headerName` and retain that reviewed value in
the deployment record.

## Destination choices

| Destination | Recommended connection |
|---|---|
| Customer observability platform | Customer OTLP gateway or Collector |
| Vendor backend | Customer egress gateway or vendor OTLP endpoint |
| Private SingleAxis | Private OTLP ingestion endpoint |
| SingleAxis Platform | Tenant-scoped approved OTLP endpoint |

Fabric recorder v1 does not install Langfuse or any other observability
backend. The customer chooses and operates the destination unless a separate
SingleAxis Platform service has been contracted.

## Delivery meaning

Fabric uses at-least-once delivery. Retries and restarts can create duplicates,
so destinations must deduplicate by preserved trace/span identity or identities
added by an upstream or destination adapter.

```text
accepted by Fabric Node
        -> queued
        -> transmitted
        -> destination accepted
        -> durably persisted, only when the destination supplies such evidence
```

An OTLP success response proves protocol acceptance. It does not prove the
backend retained the record, wrote it to WORM storage, or will expose it for a
specified retention period. Record the destination's actual acknowledgement
and retention semantics during qualification.

The public delivery contract can represent explicit batch receipts, but Fabric
Node does not automatically emit such a receipt document in recorder v1.

## What leaves the customer boundary

Fabric Node applies an exact metadata allowlist to traces and logs before the
exporter. Raw span names, log bodies, prompts, responses, tool arguments,
results, headers, credentials, and tokens are denied by default. Unknown or
structured values are not allowed through merely because a key resembles an
approved namespace.

This is export protection, not prompt-time PII prevention and not a legal
de-identification claim. If PII must be prevented from reaching a model, that
requires a separately governed inline control before the provider call.

## Network policy limitations

Kubernetes NetworkPolicy matches peers and ports, not DNS ownership. For a SaaS
destination with changing addresses, route through a stable customer-controlled
egress gateway. NetworkPolicy enforcement also depends on the cluster CNI.
