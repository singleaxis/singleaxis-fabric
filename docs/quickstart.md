# Quickstart

Get a Fabric-instrumented agent running in ~5 minutes. No cluster, no
API keys, no signup. Exercises the in-process SDK surface end-to-end;
guardrail sidecars and real judges are optional layers you add later.

## Prerequisites

- Python 3.12+ (the SDK also supports 3.11; other repo components
  require 3.12)
- `pip` or `uv`

## 1. Install the SDK

```bash
pip install singleaxis-fabric
# Extras are opt-in (core stays framework-neutral):
pip install "singleaxis-fabric[otlp]"             # OTLP/HTTP exporter
pip install "singleaxis-fabric[langgraph]"        # LangGraph adapter
pip install "singleaxis-fabric[agent-framework]"  # MS Agent Framework
pip install "singleaxis-fabric[crewai]"           # CrewAI adapter
```

## 2. Wrap one agent turn

The minimum viable wrapping: construct a `Fabric` client, open a
`Decision` context per agent call, let the SDK tag the OTel span.

```python
from fabric import Fabric, FabricConfig

fabric = Fabric(FabricConfig(tenant_id="tenant-demo", agent_id="support-bot"))

with fabric.decision(
    session_id="sess-1",
    request_id="req-1",
    user_id="user-42",
) as decision:
    # Your agent logic goes inside the decision context.
    # The SDK records the span; on exit it records success/failure.
    response = my_llm.complete(prompt="Hello")
    decision.set_attribute("llm.model", "claude-opus-4-7")
```

That's the minimum. `decision` also exposes `guard_input`,
`guard_output_final`, `record_retrieval`, `remember`, and
`request_escalation` — see the
[reference agent](../examples/reference-agent/) for each surface in
one place.

## 3. Run the reference agent

The canonical runnable example. Calls every SDK surface in one turn
against a simulated LLM + judge, so it works offline.

```bash
git clone https://github.com/ai5labs/singleaxis-fabric.git
cd singleaxis-fabric/examples/reference-agent
uv sync
uv run fabric-reference-agent --prompt "Hello"
uv run fabric-reference-agent --prompt "Hello" --low-score  # escalation path
```

Expected output shape: `{"response": "...", "escalated": bool,
"blocked": bool, "trace_id": "<32-hex>"}`.

## 4. What you should see in telemetry

By default the SDK installs a no-op tracer. For an OTel Collector
(what the Fabric chart ships, pre-configured):

```python
import os
from fabric import install_default_provider
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

install_default_provider(
    service_name="support-bot",
    exporter=OTLPSpanExporter(endpoint=os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"]),
)
```

You should see one span per decision, named `fabric.decision`, tagged
with `fabric.tenant_id`, `fabric.agent_id`, `fabric.session_id`,
`fabric.request_id`, plus any `fabric.retrieval` / `fabric.guardrail`
/ `fabric.escalation` span events the turn recorded. Spans land in
whatever your Collector fans out to — Langfuse, Tempo, Jaeger,
Honeycomb. With the chart's curated-Langfuse bootstrap, they appear
in the Langfuse project created by the init Job. For pure-local
debugging, swap `OTLPSpanExporter` for `ConsoleSpanExporter`.

## 5. What's next

- Wire the Presidio / NeMo sidecars: set `FABRIC_PRESIDIO_UNIX_SOCKET`
  and `FABRIC_NEMO_UNIX_SOCKET`; `guard_input` / `guard_output_*`
  start applying the rails. See the
  [SDK README](../sdk/python/README.md) for environment variables.
- Deploy the control-plane components via Helm: see
  [`deployment.md`](deployment.md).
- Map decisions to regulations: see
  [`compliance/mappings/`](compliance/mappings/).

## Troubleshooting

- `GuardrailNotConfiguredError` on `guard_input` / `guard_output_*`
  is intentional fail-loud behavior; either wire a sidecar or catch
  the exception (the reference agent does the latter).
- No spans visible — the default provider is a no-op. Install a real
  one (step 4).
