# Fabric integration harness

Self-contained docker-compose stack that runs the full Layer 1 Fabric
audit path — OTel Collector (Fabric distribution) plus the two UDS
guardrail sidecars plus Langfuse + Postgres — so an external agent can
be pointed at it and every decision it makes is redacted, schema-
gated, and landed as a Langfuse trace.

This is the harness we recommend for today's integration test: an
existing product imports the Fabric SDK (or just speaks OTLP), points
at the endpoints below, and you watch decisions light up in Langfuse.

## What you get

| Surface | Where | Purpose |
|---|---|---|
| Langfuse UI | http://localhost:3000 | Decision traces, scores, filters |
| OTLP/gRPC | localhost:4317 | Agent telemetry ingest |
| OTLP/HTTP | localhost:4318 | Same, for HTTP-only clients |
| Presidio UDS | `./run/presidio.sock` | PII redaction for SDK users |
| NeMo rails UDS | `./run/nemo.sock` | Input/output guardrails for SDK users |

Default Langfuse login: `admin@fabric.local` / `fabric-admin`.

## Start

```bash
cd deploy/compose
cp .env.example .env            # (optional) override defaults
make up                         # builds + starts everything
```

First start builds the three Fabric images locally (~2–4 min). Later
`make up` reuses the built images unless code changes.

Wait ~30s for Langfuse to finish its Prisma migrations, then open the
UI and the project `fabric-harness` will be pre-created with the
bootstrap keys.

### Optional: apply curated Fabric dashboards

```bash
make up-bootstrap
```

Runs the `langfuse-bootstrap` Job once against the running Langfuse,
provisioning Fabric rubric→score mappings, saved filters, and
per-profile dashboards. Pick a different profile with:

```bash
FABRIC_PROFILE=eu-ai-act-high-risk make up-bootstrap
```

## Pointing an external agent at the harness

### Option 1 — Fabric SDK (Python, recommended)

```python
# pip install singleaxis-fabric
from fabric import FabricClient, DecisionContext

client = FabricClient(
    tenant_id="harness",
    agent_id="my-product",
    otlp_endpoint="http://localhost:4318",  # OTLP/HTTP exporter
    presidio_socket="./run/presidio.sock",
    nemo_socket="./run/nemo.sock",
)

with client.decision("answer_user_question") as d:
    d.record_input(user_msg)
    d.check_input_guardrails()      # → nemo-sidecar over UDS
    response = llm.complete(user_msg)
    d.record_output(response)
    d.check_output_guardrails()     # → nemo-sidecar over UDS
```

Adjust paths if you aren't running the agent from `deploy/compose/`.

### Option 2 — vanilla OTLP

If your product already emits OpenTelemetry traces, just set the
exporter:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_SERVICE_NAME=my-product
# Fabric allowlist needs event_class on each span/record.
# See specs/004-telemetry-bridge.md §A.4.
```

Anything without `event_class = decision_summary` (or another allowed
class) is dropped by the `fabricguard` processor. This is intentional:
the collector is the schema contract.

### Option 3 — curl smoke test

```bash
curl -X POST http://localhost:4318/v1/traces \
  -H 'Content-Type: application/json' \
  -d @fixtures/decision-summary.json
```

## Troubleshooting

- **`make up` fails on first run with `permission denied` on `./run/*.sock`**:
  the sidecar images run as UID 1000. If your host UID differs and you
  bind-mount `./run/`, either `chown -R 1000 run/` or delete `run/`
  and let the sidecars recreate the sockets on next start.
- **Langfuse never becomes healthy**: the Postgres container usually
  needs ~15s. Check `make logs ARGS=langfuse-db` — Prisma migrations
  run on first boot and can take up to a minute.
- **`fabricredact` drops everything**: confirm both sidecar and
  collector see the same UDS path (`./run/presidio.sock` on the host,
  `/run/fabric/presidio.sock` inside the containers).
- **Traces don't land in Langfuse**: verify the collector's
  `otlphttp/langfuse` exporter credential — the default base64 matches
  `pk-lf-harness:sk-lf-harness`. Rotating one without the other fails
  silently with a 401 on the exporter.

## Relationship to the Helm chart

This harness mirrors `charts/fabric` one-to-one for Layer 1 subcharts
(otel-collector, nemo-sidecar, presidio-sidecar, langfuse). The
`permissive-dev` profile values are the compose defaults. For anything
past a local test — multi-tenant, production Langfuse with external
Postgres, KMS-backed keys — use the Helm chart.

See `specs/008-deployment-model.md` for the authoritative deployment
shape and `specs/012-oss-commercialization-strategy.md` for the
Layer 1/2/3 split.
