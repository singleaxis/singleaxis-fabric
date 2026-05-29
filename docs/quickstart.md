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
    response = "..."  # call your LLM here, e.g. anthropic.messages.create(...)
    decision.set_attribute("llm.model", "claude-opus-4-7")
```

That's the minimum. `decision` also exposes `guard_input`,
`guard_output_final`, `record_retrieval`, `remember`, and
`request_escalation` — see the
[reference agent](../examples/reference-agent/) for each surface in
one place.

Open one `Decision` per agent turn: it is single-use and not safe to
share across threads or asyncio tasks (the `Fabric` client is
shareable). Genuinely concurrent use of one instance raises
`ConcurrentDecisionUseError`.

### Async

`Decision`, `llm_call`, and `tool_call` also work as `async with`, and
the blocking guardrail / policy / judge methods have non-blocking
`a`-prefixed variants (`aguard_input`, `aguard_output_final`,
`aevaluate_policy`, `aauthorize_tool_call`, `aqueue_judge`) that offload
the blocking call off the event loop. Pure-CPU recording methods
(`record_retrieval`, `remember`, `checkpoint`, …) stay sync. The emitted
span is identical to the sync path.

```python
async with fabric.decision(session_id="sess-1", request_id="req-1") as decision:
    safe_input = await decision.aguard_input(user_message)
    async with decision.llm_call(system="anthropic", model="claude-opus-4-7") as call:
        answer = await my_async_llm.complete(safe_input)
        call.set_usage(input_tokens=42, output_tokens=210, finish_reason="stop")
    safe_answer = await decision.aguard_output_final(answer)
```

## 3. Run the reference agent

The canonical runnable example. Calls every SDK surface in one turn
against a simulated LLM + judge, so it works offline.

```bash
git clone https://github.com/singleaxis/singleaxis-fabric.git
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

You should see one `fabric.decision` span per decision, tagged with
`fabric.tenant_id`, `fabric.agent_id`, `fabric.session_id`,
`fabric.request_id`, plus any `fabric.retrieval` / `fabric.guardrail`
/ `fabric.escalation` span events the turn recorded.

Per-call detail: wrap the LLM API call in `Decision.llm_call(...)` and
each tool / function call in `Decision.tool_call(...)` to capture
child spans with the OpenTelemetry GenAI semantic conventions
(`gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`,
`gen_ai.usage.output_tokens`, `gen_ai.response.finish_reasons`) plus
Fabric `fabric.llm.*` / `fabric.tool.*` mirrors:

```python
with decision.llm_call(system="anthropic", model="claude-opus-4-7") as call:
    response = anthropic_client.messages.create(...)
    call.set_usage(
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
        finish_reason=response.stop_reason,
    )
```

Phoenix's LLM view, Langfuse cost dashboards, and any backend keyed
on either namespace render Fabric traces natively from this release
onward.

Spans land in whatever your Collector fans out to — Langfuse, Tempo,
Jaeger, Honeycomb. With the chart's curated-Langfuse bootstrap, they
appear in the Langfuse project created by the init Job. For pure-local
debugging, swap `OTLPSpanExporter` for `ConsoleSpanExporter`.

## 5. What's next

- Wire the Presidio / NeMo sidecars: set `FABRIC_PRESIDIO_UNIX_SOCKET`
  and `FABRIC_NEMO_UNIX_SOCKET`; `guard_input` / `guard_output_*`
  start applying the rails. See the
  [SDK README](../sdk/python/README.md) for environment variables.
- Deploy the control-plane components via Helm: see
  [`deployment.md`](deployment.md).
- Compliance mapping is roadmap. The design lives in
  [`specs/009-compliance-mapping.md`](../specs/009-compliance-mapping.md);
  per-regulation mapping documents (EU AI Act, NIST AI RMF, ISO/IEC 42001,
  SR 11-7, HIPAA) ship alongside the SingleAxis commercial control plane.

## v0.4 primitives at a glance

```python
from fabric import (
    Fabric, FabricConfig, JudgeContext, LocalQueueTransport, MemoryKind,
    SimpleLLMJudge,
)
from fabric.policy_adapters import HTTPPolicyAdapter

fabric = Fabric(FabricConfig(
    tenant_id="acme",
    agent_id="my-agent",
    workflow_id="complaint-resolution-v2",  # new in v0.4
    execution_id="run-001",                  # new in v0.4
))

transport = LocalQueueTransport()
policy = HTTPPolicyAdapter(endpoint="https://policies.internal/eval")

with fabric.decision(session_id="s", request_id="r") as d:
    safe_input = d.guard_input(user_message)

    # Memory: read + write (read is new in v0.4)
    d.recall(kind=MemoryKind.EPISODIC, key="last_turn", content="prior content")
    d.remember(kind=MemoryKind.EPISODIC, key="this_turn", content=user_message)

    # Save point for replay (new in v0.4)
    d.checkpoint("after-input")

    # Policy enforcement (new in v0.4)
    verdict = d.evaluate_policy(policy, policy_id="region.eu", input={...})

    response = my_llm.complete(safe_input)
    safe_response = d.guard_output_final(response)

    # Sync eval (new in v0.4)
    d.record_eval(rubric_id="tone-v1", score=0.9, dimension="tone",
                  evaluator_name="rule_based")

    # Async judge with full context (new in v0.4)
    ctx = d.snapshot_context()
    ctx = JudgeContext(**{**ctx.__dict__, "user_input": user_message,
                          "agent_response": safe_response})
    d.queue_judge(rubric_id="faithfulness-v1", dimensions=("faithfulness",),
                  context=ctx, transport=transport)
```

The full reference agent at `examples/reference-agent` demonstrates
every v0.4 primitive end-to-end including the in-process judge
worker. Run it with:

```bash
uv run fabric-reference-agent --prompt Hello --enable-v04-primitives
```

## Troubleshooting

- `GuardrailNotConfiguredError` on `guard_input` / `guard_output_*`
  is intentional fail-loud behavior; either wire a sidecar or catch
  the exception (the reference agent does the latter).
- No spans visible — the default provider is a no-op. Install a real
  one (step 4).
