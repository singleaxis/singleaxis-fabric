# singleaxis-fabric (Python SDK)

Native Python SDK that tenant agents import in-process. Provides the
decision-span contract, guardrail/escalation types, OTel plumbing,
and optional adapters for LangGraph, Microsoft Agent Framework, and
CrewAI (installed via extras — the core SDK stays framework-neutral).

## Authoritative specs

- [`../../specs/002-architecture.md`](../../specs/002-architecture.md)
- [`../../specs/005-guardrails-inline.md`](../../specs/005-guardrails-inline.md)
- [`../../specs/003-context-graph.md`](../../specs/003-context-graph.md) (retrieval audit)
- [`../../specs/007-escalation-workflow.md`](../../specs/007-escalation-workflow.md) (pause primitive)

## Status

Beta — **Phase 1a shipping.**

### Shipping now

- `Fabric` client (`Fabric.from_env`, `FabricConfig`, `close()`)
- `Decision` context manager — opens an OTel span per agent call and
  tags it with the Fabric-standard attributes:
  - `fabric.tenant_id`, `fabric.agent_id`, `fabric.profile`
  - `fabric.session_id`, `fabric.request_id`, `fabric.user_id`
  - `fabric.blocked`, `fabric.blocked.policies` (on block)
- Guardrail types: `GuardrailResult`, `EntitySummary`,
  `GuardrailBlocked`, `GuardrailNotConfiguredError`
- Presidio rail via UDS sidecar: `UDSPresidioClient`,
  `RedactionResult`, `RedactionError`. `Decision.guard_input`,
  `guard_output_chunk`, and `guard_output_final` route through the
  chain and emit `fabric.guardrail` span events (phase, latency_ms,
  blocked, entities, policies).
- NeMo Colang rail via UDS sidecar: `UDSNemoClient`, `NemoResult`,
  `NemoError`. Wired into the same chain; runs **after** Presidio so
  the Colang / LLM checks never see raw PII. May block
  (`action == "block"`), with the canned response surfaced on the
  `GuardrailResult`.
- LLM-call instrumentation: `Decision.llm_call(system=..., model=...)`
  opens a `fabric.llm_call` child span (kind=CLIENT) populated with
  the OpenTelemetry GenAI semantic conventions
  (`gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`,
  `gen_ai.usage.output_tokens`, `gen_ai.response.finish_reasons`)
  alongside `fabric.llm.*` mirrors. Phoenix LLM views, Langfuse cost
  dashboards, and any backend keying off either namespace render
  Fabric traces natively. The returned context manager exposes
  `set_usage(...)`, `set_response_model(...)`, and `set_attribute(...)`
  for attaching response data on exit.
- Tool-call instrumentation: `Decision.tool_call(name, call_id=...)`
  follows the same pattern with `gen_ai.tool.*` + `fabric.tool.*`
  conventions. Helpful for instrumenting function/tool invocations
  that happen inside an agent turn.
- OTel helpers: `get_tracer`, `install_default_provider`
- Decision-level block recording (`record_block`, `raise_for_block`)
- Retrieval recording: `RetrievalSource`, `RetrievalRecord`,
  `Decision.record_retrieval(source, query=..., result_count=..., ...)`.
  Hashes the query with SHA-256 locally (raw text never hits the
  span), emits a `fabric.retrieval` span event with allowlisted
  attributes, and maintains rolling `fabric.retrieval_count` and
  `fabric.retrieval_sources` on the decision span so the Telemetry
  Bridge can fold them into the `DecisionSummary` wire event. Maps
  onto the Context Graph's `Retrieval` node (spec 003).
- Escalation pause primitive: `EscalationSummary`, `EscalationRequested`,
  `Decision.request_escalation`, `Decision.raise_for_escalation`.
  Records `fabric.escalated`, `fabric.escalation.reason/rubric_id/
  mode/triggering_score` on the span and emits a `fabric.escalation`
  span event. `EscalationSummary.to_payload()` returns the
  framework-agnostic dict tenants hand to whatever interrupt
  primitive their orchestrator exposes (LangGraph `interrupt()`,
  Agent Framework checkpoints, a bespoke queue). The SDK owns the
  *local* signal only; the downstream SASF review + signed-verdict
  resume lives in the escalation service (spec 007).
- Memory write recording: `MemoryKind`, `MemoryRecord`,
  `Decision.remember(kind=..., content=..., key=..., tags=...,
  ttl_seconds=...)`. Tenants perform the actual write against their
  own memory store; the SDK SHA-256s the content locally (raw text
  never hits the span) and emits a `fabric.memory` span event with
  the allowlisted metadata, plus rolling `fabric.memory_write_count`
  and `fabric.memory_kinds` attributes the Telemetry Bridge folds
  into the `DecisionSummary` wire event. Symmetric to
  `record_retrieval` — the Context Graph materializes the write as
  a `Retrieval` node with `source=memory` tied to the owning
  `Decision`.

  ```python
  from fabric import MemoryKind

  with fabric.decision(session_id=sess, request_id=req) as decision:
      answer = my_agent.run(user_input)
      my_memory_store.write(key="last_answer", value=answer)
      decision.remember(
          kind=MemoryKind.EPISODIC,
          key="last_answer",
          content=answer,
          tags=("turn", "assistant"),
      )
  ```

When no rails are configured, `guard_input` / `guard_output_*` raise
`GuardrailNotConfiguredError`. This is a deliberate fail-loud
posture — a silently passing guardrail is a compliance footgun.

### Framework adapters (optional)

The core SDK is framework-neutral. Adapters live under
`fabric.adapters.*` and are each gated behind an install extra so the
core install does not pull in any orchestration package.

- `fabric.adapters.langgraph.escalate(decision, summary)` — records
  the Fabric escalation on the decision span and calls
  `langgraph.types.interrupt(payload)`. Returns whatever the host
  resumes the graph with (typically the signed verdict).
- `fabric.adapters.agent_framework.request_escalation(ctx, decision,
  summary, *, response_type=...)` — records on span, then
  `await ctx.request_info(request_data=..., response_type=...)`. The
  resumed response is routed to a MAF `@response_handler` method
  (dispatch-based, per MAF design).
- `fabric.adapters.crewai.attach_callbacks(decision)` returns
  `CrewCallbacks` (step + task callbacks that record CrewAI
  lifecycle events on the decision span).
  `fabric.adapters.crewai.request_escalation(decision, summary)`
  records on span and returns the canonical payload — the tenant
  pairs it with their chosen CrewAI HITL channel (`@human_feedback`
  Flow, `Task(human_input=True)`, or enterprise `/resume`).

## Install

```bash
pip install singleaxis-fabric                         # core
pip install "singleaxis-fabric[otlp]"                 # + OTLP/HTTP exporter
pip install "singleaxis-fabric[langgraph]"            # + LangGraph adapter
pip install "singleaxis-fabric[agent-framework]"      # + MAF adapter
pip install "singleaxis-fabric[crewai]"               # + CrewAI adapter
```

## Quick start

```python
import os
from fabric import Fabric, install_default_provider
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

# Host chooses how to export — typically an OTLP endpoint pointing at
# the Fabric OTel Collector. install_default_provider is a convenience
# for small agents; production hosts wire the provider themselves.
install_default_provider(
    service_name="support-bot",
    exporter=OTLPSpanExporter(endpoint=os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"]),
)

fabric = Fabric.from_env()

with fabric.decision(
    session_id=session.id,
    request_id=req.id,
    user_id=user.id,
) as decision:
    # real work happens here; the decision span wraps it all
    safe_input = decision.guard_input(req.body)
    output = llm.complete(prompt=safe_input)
    final = decision.guard_output_final(output)
    decision.set_attribute("llm.model", "claude-opus-4-7")
```

`guard_input` / `guard_output_*` are no-ops that raise
`GuardrailNotConfiguredError` unless `FABRIC_PRESIDIO_UNIX_SOCKET` is
set (or a `PresidioClient` is passed to `Fabric(...)` directly).

## Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `FABRIC_TENANT_ID` | yes | Tenant scope for all emitted events. |
| `FABRIC_AGENT_ID` | yes | Which agent in the tenant is running. |
| `FABRIC_PROFILE` | no | Regulatory profile (default `permissive-dev`). |
| `FABRIC_PRESIDIO_UNIX_SOCKET` | no | Unix socket path to the Presidio sidecar (`/v1/redact`). If unset, the Presidio rail is not installed. |
| `FABRIC_PRESIDIO_TIMEOUT_SECONDS` | no | Per-call timeout for the sidecar (float, default `0.5`). |
| `FABRIC_NEMO_UNIX_SOCKET` | no | Unix socket path to the NeMo Colang sidecar (`/v1/check`). If unset, the NeMo rail is not installed. |
| `FABRIC_NEMO_TIMEOUT_SECONDS` | no | Per-call timeout for the NeMo sidecar (float, default `1.0`). |

## Module layout

```
sdk/python/
├── pyproject.toml
├── src/fabric/
│   ├── __init__.py
│   ├── client.py          # Fabric, FabricConfig, from_env
│   ├── decision.py        # Decision context manager
│   ├── guardrails.py      # result + error types
│   ├── escalation.py      # EscalationSummary + EscalationRequested
│   ├── presidio.py        # PresidioClient protocol + UDS impl
│   ├── nemo.py            # NemoClient protocol + UDS impl
│   ├── retrieval.py       # RetrievalSource + RetrievalRecord
│   ├── memory.py          # MemoryKind + MemoryRecord
│   ├── _chain.py          # GuardrailChain (internal)
│   ├── _uds.py            # HTTP-over-unix-socket transport
│   ├── _version.py        # version sourced from git tag (hatch-vcs)
│   ├── tracing.py         # OTel helpers
│   ├── adapters/          # framework adapters (extras-gated)
│   │   ├── langgraph.py
│   │   ├── agent_framework.py
│   │   └── crewai.py
│   └── py.typed
└── tests/
    ├── conftest.py
    ├── _fake_sidecar.py
    ├── test_client.py
    ├── test_decision.py
    ├── test_guardrail_chain.py
    ├── test_escalation.py
    ├── test_nemo.py
    ├── test_presidio.py
    ├── test_retrieval.py
    └── test_tracing.py
```

## Tests

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Coverage threshold is 85% at the pyproject level. Current baseline is
~98% because the Phase 1a surface is narrow; as guardrails and memory
land, keep the 85% floor honest rather than moving it.

## Versioning

Independent of the Fabric umbrella version pre-1.0.0. Tenant agents
pin the SDK; the Control Plane advertises compatibility ranges.

## License

Apache-2.0. See `LICENSE`.
