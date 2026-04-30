# Exporting to your observability backend

Fabric is OTLP-native. Once the SDK and collector are running, every
agent decision produces an OpenTelemetry span (with `gen_ai.*`
semantic conventions on LLM calls from v0.2.0 onward) that can land
in any backend that speaks OTLP/HTTP.

This page shows the wire-up for the most common backends. The
collector's exporter endpoint is the single setting that determines
where spans actually go.

## Where the setting lives

`charts/fabric/charts/otel-collector/values.yaml`:

```yaml
exporter:
  endpoint: ""        # required at install time; empty fails render
  insecure: true      # set false for TLS-fronted backends
```

Override at install via `helm install` or a profile YAML:

```bash
helm install fabric ./charts/fabric \
  --set otel-collector.exporter.endpoint=<URL>
```

Render-time validator: if `exporter.endpoint` is empty AND
`exporter.acceptUnsetEndpoint=false` (the default), the chart
fails install with a clear message. The escape hatch
`acceptUnsetEndpoint=true` exists for CI smoke renders only.

## Bundled Langfuse (recommended starter)

The Helm chart ships a Langfuse subchart. When `langfuse.enabled:
true` (the chart default), Langfuse + Postgres + the
`langfuse-bootstrap` Job all run inside `fabric-system`.

```bash
helm install fabric ./charts/fabric \
  --set otel-collector.exporter.endpoint=http://langfuse:3000 \
  --set langfuse.enabled=true
```

`langfuse-bootstrap` configures the Langfuse instance with Fabric's
curated score configs, prompt presets, and saved-view URLs (idempotent
— rerun safe). Open `http://langfuse:3000` (or your Ingress) and
your spans appear immediately.

## Arize Phoenix

```bash
helm install fabric ./charts/fabric \
  --set otel-collector.exporter.endpoint=http://phoenix:6006/v1/traces
```

Phoenix's "LLM" view keys off `gen_ai.*` attributes, which Fabric
emits from v0.2.0. Earlier versions appear as generic spans —
upgrade to v0.2.x for full LLM dashboard coverage.

## Datadog (OTLP intake)

```bash
helm install fabric ./charts/fabric \
  --set otel-collector.exporter.endpoint=https://otlp.datadoghq.com:443 \
  --set otel-collector.exporter.insecure=false \
  --set-string otel-collector.exporter.headers.dd-api-key=$DD_API_KEY
```

(Replace `datadoghq.com` with your region domain.)

## Honeycomb

```bash
helm install fabric ./charts/fabric \
  --set otel-collector.exporter.endpoint=https://api.honeycomb.io:443 \
  --set otel-collector.exporter.insecure=false \
  --set-string otel-collector.exporter.headers.x-honeycomb-team=$HONEYCOMB_API_KEY
```

## Grafana Tempo / Cloud (via OTLP gateway)

```bash
helm install fabric ./charts/fabric \
  --set otel-collector.exporter.endpoint=https://otlp-gateway-prod-<region>.grafana.net:443 \
  --set otel-collector.exporter.insecure=false
```

Add Basic auth headers per Grafana Cloud's OTLP configuration page.

## Your own collector chain

Operators running their own OTel collector (e.g., as part of an
existing observability platform) point Fabric at it:

```bash
helm install fabric ./charts/fabric \
  --set otel-collector.exporter.endpoint=http://my-otel-collector.observability.svc:4318
```

From there, the operator's collector applies the rest of their
processor chain (sampling, retention routing, vendor-specific
exporters).

## Multiple destinations (fan-out)

The chart ships a single OTLP/HTTP exporter by default. To fan out
to multiple backends, edit the collector's pipeline config — the
`fabricredact`, `fabricguard`, `fabricsampler` chain is independent
of the exporter list, so adding additional exporters does not change
the privacy/policy enforcement applied to spans.

For most operators, the simpler pattern is: send to one OTLP
endpoint (your own collector), and let that collector fan out.

## NetworkPolicy considerations

The `eu-ai-act-high-risk` profile enables `denyDefault: true` plus
per-subchart NetworkPolicies. The collector's `egressTo` defaults to
the `fabric-system` namespace only, so external destinations
(Datadog, Honeycomb, anywhere outside the cluster) require operator
overrides:

```yaml
otel-collector:
  networkPolicy:
    egressTo:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: fabric-system
      - ipBlock:
          cidr: 0.0.0.0/0   # external — tighten as needed
        ports:
          - protocol: TCP
            port: 443
```

For tighter setups, replace `0.0.0.0/0` with the egress
NAT/proxy CIDR your cluster uses.

## What's in the span

Until v0.2.0, Fabric emits one `fabric.decision` span per agent turn
with identity tags (`fabric.tenant_id`, `fabric.agent_id`, `…`),
guardrail/escalation/retrieval/memory events, and any custom
attributes the application attaches via `decision.set_attribute`.

From v0.2.0, `Decision.llm_call` and `Decision.tool_call` add child
spans with `gen_ai.*` standard attributes (model, tokens, finish
reason, tool name, etc.). Auto-instrument extras (`pip install
"singleaxis-fabric[openai]"`, etc.) wire the upstream
`opentelemetry-instrumentation-*` packages so LLM SDK calls light up
without manual wrapping.

## Verifying the wire

After install, the simplest verification:

```bash
kubectl -n fabric-system port-forward svc/fabric-otel-collector 4318:4318 &
curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://localhost:4318/v1/traces \
  -H "Content-Type: application/json" \
  -d '{"resourceSpans": []}'
# expect 200
```

Then run the reference agent (or your own instrumented agent) and
check the backend's UI for the `fabric.decision` span.

## See also

- [`charts/fabric/charts/otel-collector/values.yaml`](../charts/fabric/charts/otel-collector/values.yaml)
  for the full exporter config surface.
- [`docs/quickstart.md`](quickstart.md) for the SDK-side wire-up.
- [`docs/architecture.md`](architecture.md) for what the collector
  actually does to spans before egress.
