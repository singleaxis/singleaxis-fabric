# singleaxis-fabric (Python SDK)

Native Python SDK that tenant agents import in-process. Provides the
decision-span contract, guardrail/escalation types, OTel plumbing,
and optional adapters for LangGraph, Microsoft Agent Framework, and
CrewAI (installed via extras — the core SDK stays framework-neutral).

## Authoritative specs

- [`../../specs/002-architecture.md`](../../specs/002-architecture.md)
- [`../../specs/005-guardrails-inline.md`](../../specs/005-guardrails-inline.md)
- [`../../specs/003-decision-graph.md`](../../specs/003-decision-graph.md) (retrieval audit)
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
  onto the Decision Graph's `Retrieval` node (spec 003).
- Escalation pause primitive: `EscalationSummary`, `EscalationRequested`,
  `Decision.request_escalation`, `Decision.raise_for_escalation`.
  `request_escalation` **records** the escalation — it tags the span
  (`fabric.escalated`, `fabric.escalation.reason/rubric_id/mode/triggering_score`)
  and emits a `fabric.escalation` span event, but does **not** raise.
  Pair it with `raise_for_escalation()` for an exception-driven flow
  that raises `EscalationRequested`. `EscalationSummary.to_payload()`
  returns the framework-agnostic dict tenants hand to whatever interrupt
  primitive their orchestrator exposes (LangGraph `interrupt()`,
  Agent Framework checkpoints, a bespoke queue). OSS emits the
  *local* signal only; the durable escalation service (SASF reviewer),
  signed-verdict resume, and pause/resume orchestration are commercial
  (spec 007).
- Memory write recording: `MemoryKind`, `MemoryRecord`,
  `Decision.remember(kind=..., content=..., key=..., tags=...,
  ttl_seconds=...)`. Tenants perform the actual write against their
  own memory store; the SDK SHA-256s the content locally (raw text
  never hits the span) and emits a `fabric.memory` span event with
  the allowlisted metadata, plus rolling `fabric.memory_write_count`
  and `fabric.memory_kinds` attributes the Telemetry Bridge folds
  into the `DecisionSummary` wire event. Symmetric to
  `record_retrieval` — the Decision Graph materializes the write as
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

- Side-effect recording: `SideEffectType`, `ReplayBehavior`,
  `SideEffectRecord`, `Decision.record_side_effect(...)`. Use this for
  tool calls that mutate external state, such as CRM updates, ticket
  creation, email sends, file writes, database writes, or payments. The
  SDK hashes raw request/result payloads locally, emits a
  `fabric.side_effect` span event, and keeps rolling
  `fabric.side_effect_count`, `fabric.side_effect_types`, and
  `fabric.side_effect_systems` attributes for Decision Graph projection
  and replay suppression.

  ```python
  with fabric.decision(session_id=sess, request_id=req) as decision:
      ticket = zendesk.create_ticket(summary=final)
      decision.record_side_effect(
          "ticket_create",
          target_system="zendesk",
          operation="ticket.create",
          request_payload=final,
          result_payload=ticket.id,
          idempotency_key=f"ticket:{req}",
          replay_behavior="suppress",
      )
  ```

- Eval + judge primitives: `Decision.record_eval` (`EvalRecord`)
  attaches a synchronous score to the span; `Decision.queue_judge`
  (`JudgeRequest`, `JudgeContext`) forwards an async judge request
  through a `QueueTransport`. OSS ships these
  recording/queueing primitives, the transport protocol, and a
  local/reference judge harness — `JudgeRunner` (drains a transport and
  scores out-of-band), `SimpleLLMJudge` (a minimal reference worker, not
  commercial quality), and `LocalQueueTransport` (in-process). The
  production judge *worker* fleet, rubric corpus, calibration, and
  drift/longitudinal analysis are **commercial**; OSS does not run
  managed scoring or persist results (the default result sink is a no-op).

When no rails are configured, `guard_input` / `guard_output_*` raise
`GuardrailNotConfiguredError`. This is a deliberate fail-loud
posture — a silently passing guardrail is a compliance footgun.

### Async API

`Decision`, `LLMCall`, and `ToolCall` work as `async with` as well as
the sync `with` — a single instance is usable as one **or** the other,
not both at once. Opening and closing a span is pure-CPU, so the async
entry/exit reuse the sync logic; the emitted span is byte-identical
whichever call style you use.

The methods that perform blocking sidecar / adapter I/O have
non-blocking `a`-prefixed variants that offload the blocking call to a
worker thread via `asyncio.to_thread`, so the event loop is never
blocked:

- `aguard_input`, `aguard_output_chunk`, `aguard_output_final` —
  guardrail-chain sidecar I/O.
- `aevaluate_policy` — pluggable `PolicyEngine` (OPA / HTTP adapters do
  network I/O).
- `aauthorize_tool_call` — pluggable `ToolAuthorizer`.
- `aqueue_judge` — pluggable `QueueTransport` (SQS / NATS / Redis
  transports do network I/O).

The pure-CPU recording methods (`record_retrieval`, `remember`,
`recall`, `record_side_effect`, `record_eval`, `checkpoint`,
`snapshot_context`, `set_attribute`) are microsecond-fast and have **no**
async variant — call them directly inside an `async with` block. The
LangGraph and Agent Framework adapters use this async surface.

```python
async with fabric.decision(session_id=sess, request_id=req) as decision:
    safe_input = await decision.aguard_input(req.body)

    async with decision.llm_call(system="anthropic", model="claude-opus-4-7") as call:
        output = await my_async_llm.complete(safe_input)
        call.set_usage(input_tokens=42, output_tokens=210, finish_reason="stop")

    decision.record_retrieval("rag", query="q", result_count=3)  # sync, pure-CPU
    safe_output = await decision.aguard_output_final(output)
```

### Concurrency contract

A `Decision` represents a single agent turn and is **not** safe to share
across threads or asyncio tasks — open one `Decision` per turn. The
`Fabric` client itself is shareable. Genuinely overlapping mutating
calls on the same `Decision` (for example two coroutines fired with
`asyncio.gather` on one instance) raise `ConcurrentDecisionUseError`
rather than silently racing the internal record lists and rolling
span-counter attributes. Sequential calls — including each awaited
`a`-variant, which completes before the next begins — never trip it.
Re-entering an already-entered or already-closed `Decision` raises
`RuntimeError`.

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

The SDK lives under `src/fabric/`. Grouped by role (accuracy over a
flat dump — read the module docstrings for detail):

**Core**

- `client.py` — `Fabric`, `FabricConfig`, `from_env`
- `decision.py` — `Decision` context manager (the agent-turn span)
- `execution.py` — optional outer `execution()` correlation span
- `guardrails.py` — guardrail result + error types
- `escalation.py` — `EscalationSummary`, `EscalationRequested`
- `retrieval.py` — `RetrievalSource`, `RetrievalRecord`
- `memory.py` — `MemoryKind`, `MemoryRecord`
- `side_effect.py` — `SideEffectType`, `SideEffectRecord`
- `eval.py` — `EvalRecord` (synchronous score record)
- `judge.py` — `JudgeContext`, `JudgeRequest`, `JudgeWorker` +
  `QueueTransport` protocol
- `judge_runner.py` — `JudgeRunner` (local/reference judge loop)
- `policy.py` — `PolicyDecision`, `PolicyEngine` protocol
- `tool_auth.py` — pre-execution `ToolAuthorizer` protocol + gate
- `checkpoint.py` — `CheckpointEvent` schema (replay breadcrumb; replay
  engine is commercial)
- `stream.py` — `StreamRedactor` (boundary-safe streaming redaction)
- `propagation.py` — W3C `tracestate` cross-service context carrier
- `presidio.py`, `nemo.py` — PII / Colang sidecar clients
- `tracing.py` — OTel helpers (`get_tracer`, `install_default_provider`)
- `auto_instrument.py` — opt-in `opentelemetry-instrumentation-*` hookup
- internal leaf modules: `_attributes.py`, `_calls.py`, `_chain.py`,
  `_id_validators.py`, `_uds.py`, `_version.py`

**Adapters & extensions** (each extras-gated)

- `adapters/` — framework adapters (`langgraph`, `agent_framework`,
  `crewai`)
- `guardrail_adapters/` — `http`, `lakera`
- `judge_adapters/` — `simple` (`SimpleLLMJudge`), `deepeval`, `ragas`
- `policy_adapters/` — `opa`, `cedar`, `http`
- `queue_transports/` — `local` (`LocalQueueTransport`), `sqs`, `nats`,
  `redis`
- `content_store/` — `ContentStore` protocol + `local`, `s3` backends

**Integrations**

- `integrations/mcp.py` — MCP `call_tool` instrumentation

Tests, conformance suites, benchmarks, and soak harness live alongside
under `tests/`, `benchmarks/`, and `soak/`.

## Tests

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Coverage threshold is 85% at the pyproject level (`--cov-fail-under=85`).

Beyond unit tests, the SDK ships:

- a **schema conformance suite** (`tests/conformance/`) that freezes the
  emitted `fabric.*` / `gen_ai.*` span and span-event contract against
  golden fixtures and a JSON Schema at `SCHEMA_VERSION` 1.0, so silent
  wire-shape drift fails CI;
- a **reusable adapter-conformance kit** (`tests/conformance/adapters/`)
  that any implementer of a Fabric extension Protocol (`GuardrailChecker`,
  `PolicyEngine`, `QueueTransport`, `ToolAuthorizer`, …) can subclass to
  prove their adapter satisfies the behavioral contract;
- an opt-in **micro-benchmark suite** (`benchmarks/`) and **soak harness**
  (`soak/`), both outside `tests/` so they never gate or flake CI. They
  are informational and machine-dependent — no pass/fail timing
  threshold.

## Versioning

Independent of the Fabric umbrella version pre-1.0.0. Tenant agents
pin the SDK; the Control Plane advertises compatibility ranges.

## License

Apache-2.0. See `LICENSE`.
