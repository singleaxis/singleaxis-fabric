---
title: Execution & Step capture — outer correlation + lifecycle primitives
status: draft
revision: 2
last_updated: 2026-06-02
owner: project-lead
---

# 020 — Execution & Step capture

> **Scope split.** This spec covers two capture primitives that the OSS
> SDK *emits* and the commercial layer *interprets*. The OSS boundary is
> strict: the SDK emits canonical `fabric.execution` / `fabric.step.*`
> spans and attributes; it never schedules, orchestrates, materializes
> lineage, or reconstructs runs. Those belong to the commercial
> operational-intelligence layer (Decision Graph, replay orchestration).
> See [012](012-oss-commercialization-strategy.md) for the full
> OSS↔commercial split.

## Summary

Fabric already captures the *inner* unit of agent work — the
[`Decision`](../sdk/python/src/fabric/decision.py) (`fabric.decision`
span). Production runs, however, are usually a *sequence* of related
decisions: a multi-turn task, a retried job, a multi-step workflow. There
is no canonical, OSS-emitted way to say "these N decisions belong to one
run" without the host hand-threading an id through `FabricConfig` on
every call.

This spec introduces two **optional, emit-only** capture primitives:

1. **Execution** (this PR) — an *outer correlation + lifecycle* span,
   `fabric.execution`, that demarcates and correlates a run of related
   decisions. It does **not** drive decisions; it brackets them.
2. **Step** (implemented) — a per-operation taxonomy, `fabric.step.*`,
   stamped on the existing child spans (`fabric.llm_call`,
   `fabric.tool_call`). A *step* is one operation inside an execution (an
   LLM call, a tool call); the taxonomy names its canonical kind and
   carries opt-in step-level identity + retry metadata.

Both are additive and backward compatible. A `Decision` opened outside an
execution behaves exactly as it did before, and the only child-span
change is the always-on `fabric.step.type` (a deterministic constant per
call kind) — the rest of the existing wire contract is byte-identical.

## Non-goals (the OSS↔commercial boundary)

The OSS SDK **emits** the spans and attributes below. It explicitly does
**not**, in OSS:

- **schedule or drive** decisions — Execution is not a workflow engine.
  It opens a span and correlates whatever the host runs inside it.
- **orchestrate retries / branches** — `fabric.execution.status` is a
  recorded outcome, not a control signal.
- **materialize lineage or reconstruct** a run from the emitted spans —
  joining executions → decisions → steps into a graph, replaying, and
  signing audit bundles is the commercial Decision Graph
  ([003](003-decision-graph.md)) and replay orchestration
  ([012](012-oss-commercialization-strategy.md)).

This keeps the emit/act boundary clean: OSS produces honest, canonical
telemetry; the commercial layer turns it into operational intelligence.

## Execution primitive (this PR)

### Shape

`Fabric.execution(*, execution_id=None, workflow_id=None,
attributes=None)` returns an
[`Execution`](../sdk/python/src/fabric/execution.py) context manager,
usable as **either** a synchronous `with` **or** an asynchronous
`async with` (mirroring `Decision`'s dual-mode; the emitted span bytes
are identical across call styles).

On **enter** it opens one span:

| Field | Value |
|-------|-------|
| name  | `fabric.execution` |
| kind  | `INTERNAL` |

and stamps these attributes:

| Attribute | Source | Required |
|-----------|--------|----------|
| `fabric.schema_version` | const `"1.0"` | yes |
| `fabric.tenant_id` | client config | yes |
| `fabric.agent_id` | client config | yes |
| `fabric.profile` | client config | yes |
| `fabric.execution_id` | supplied `execution_id`, else a minted uuid4 | yes |
| `fabric.workflow_id` | supplied `workflow_id` | only when provided |
| *(host extras)* | `attributes` mapping | as supplied |

On **exit** it stamps the lifecycle outcome:

| Attribute | Value |
|-----------|-------|
| `fabric.execution.status` | `"completed"` normally; `"failed"` if the block raised |

On failure the exception is recorded on the span
(`span.record_exception`) and the OTel status is set to `ERROR` with the
exception type as the description — matching `Decision`'s exception
handling. The exception is **not** swallowed (it propagates).

### Decision inheritance

While an `Execution` is open, its `(execution_id, workflow_id)` pair is
published on a process-global `contextvars.ContextVar`
(`fabric.execution._ACTIVE_EXECUTION`), set on enter and reset
(token-based) on exit. The contextvar is async-safe and nested /
sequential executions never leak into one another.

When a `Decision` is opened, it resolves `execution_id` and
`workflow_id` independently with this **precedence**:

```
explicit kwarg  >  active Execution (contextvar)  >  FabricConfig
```

- A decision opened **inside** `fabric.execution(...)` inherits the
  execution's ids (unless the caller passes an explicit
  `decision(..., execution_id=...)` / `workflow_id=...`, which wins).
- A decision opened **outside** any execution sees no active execution
  and falls back to `FabricConfig` — **exactly today's behavior**. This
  is the back-compat guarantee that keeps every existing golden
  byte-identical.

### Usage

```python
fabric = Fabric.from_env()

with fabric.execution(execution_id="run-42", workflow_id="refunds") as ex:
    with fabric.decision(session_id="s", request_id="r1") as d:
        ...  # d.execution_id == "run-42", d.workflow_id == "refunds"

# async, id minted automatically
async with fabric.execution() as ex:
    ...  # ex.execution_id is a uuid4, inherited by inner decisions
```

## Step taxonomy (implemented)

A **Step** is one operation inside an execution — an LLM call, a tool
call, a named phase. Rather than introduce a new span, the taxonomy is
stamped onto the **existing child spans** that already bracket each
operation:
[`fabric.llm_call`](../sdk/python/src/fabric/_calls.py) (kind `CLIENT`)
and `fabric.tool_call` (kind `INTERNAL`). It mirrors the Execution
attempt/retry model, but at the per-operation grain. Like Execution it is
**emit-only**: the SDK stamps the attributes; it does not schedule,
sequence, or retry the operation.

### Shape

`Decision.llm_call(...)` / `Decision.tool_call(...)` accept these
additional, all-optional parameters (forwarded verbatim to the
underlying `LLMCall` / `ToolCall`):

```
step_id, step_type,
step_attempt_id, step_attempt,
step_retry_reason, step_retry_previous_attempt_id
```

The child span then carries:

| Attribute | Source | Required |
|-----------|--------|----------|
| `fabric.step.type` | supplied `step_type`, else the kind default (`"llm_call"` for `llm_call`, `"tool_call"` for `tool_call`) | **always** (deterministic) |
| `fabric.step.id` | supplied `step_id` | only when provided |
| `fabric.step.attempt_id` | supplied `step_attempt_id` | only when provided |
| `fabric.step.attempt` | supplied `step_attempt` (integer ≥ 1) | only when provided |
| `fabric.step.retry.reason` | supplied `step_retry_reason` | only when provided |
| `fabric.step.retry.previous_attempt_id` | supplied `step_retry_previous_attempt_id` | only when provided |

### Canonical step type

`fabric.step.type` is the canonical step kind and is **auto-stamped on
every child span** — `"llm_call"` on the LLM-call span, `"tool_call"` on
the tool-call span. It is deterministic (no uuid, no clock) and
host-overridable: pass `step_type="plan"` / `"act"` / etc. to relabel the
operation's phase. This is the one always-on addition to the child-span
contract.

### Opt-in step identity and step-level retry

`fabric.step.id` is a **stable, logical** step id: the same value across
retries of the *same* operation. It is **opt-in** — stamped only when the
host supplies `step_id=`. The SDK does **not** auto-mint it, which keeps
the existing goldens byte-identical and the id deterministic.

The step retry fields mirror Execution's attempt/retry, but describe a
**concrete attempt of one step** and are entirely **independent** of the
enclosing execution's attempt/retry:

- `fabric.step.attempt_id` — unique id for *this* concrete step attempt.
- `fabric.step.attempt` — one-based step attempt number (integer ≥ 1).
- `fabric.step.retry.reason` — why this step attempt exists.
- `fabric.step.retry.previous_attempt_id` — prior step attempt id, if any.

All four are opt-in and stamped only when supplied. A child span carries
`fabric.step.*` (per-operation) while the decision/execution spans carry
`fabric.execution.*` (per-run); the two never collide.

### Usage

```python
with fabric.decision(session_id="s", request_id="r") as d:
    # canonical type auto-stamped: fabric.step.type="tool_call"
    with d.tool_call("vector_search") as tool:
        ...

    # a retried tool step with explicit step-level retry metadata
    with d.tool_call(
        "vector_search",
        step_id="step-0001",                       # stable across retries
        step_attempt_id="step-attempt-0002",
        step_attempt=2,
        step_retry_reason="tool_timeout",
        step_retry_previous_attempt_id="step-attempt-0001",
    ) as tool:
        ...

    # host-relabelled phase
    with d.llm_call(system="anthropic", model="claude", step_type="plan"):
        ...
```

The commercial Decision Graph consumes execution → decision → step
attributes to materialize the run hierarchy, correlate step retries, and
build lineage. The OSS SDK only emits them.

## Conformance

- A new `execution` scenario
  ([scenarios.py](../sdk/python/tests/conformance/scenarios.py)) opens
  `fabric.execution(execution_id="execution-0001",
  workflow_id="workflow-0001")` with a bare decision inside, producing
  `goldens/execution.json`. The inner decision span carries the inherited
  `fabric.execution_id="execution-0001"` and
  `fabric.workflow_id="workflow-0001"`.
- The conformance schema
  ([fabric-decision-v1.schema.json](../sdk/python/tests/conformance/schema/fabric-decision-v1.schema.json))
  gains an **optional** top-level `execution_span` object (sibling to
  `decision_span` / `events` / `child_spans`). The root still **requires**
  only the existing three, so non-execution scenarios validate unchanged;
  `execution_span` is an allowed but non-required property.
- The schema-enforcement test validates any emitted `fabric.execution`
  span against `execution_span`.
- The `llm_call` / `tool_call` scenarios now emit the deterministic
  `fabric.step.type` (`"llm_call"` / `"tool_call"`) on their child span,
  so `goldens/llm_call.json` and `goldens/tool_call.json` each gain
  exactly that one attribute. A new `step_retry` scenario opens a
  `tool_call` carrying fixed step retry metadata
  (`step_id="step-0001"`, `step_attempt_id="step-attempt-0002"`,
  `step_attempt=2`, `step_retry_reason="tool_timeout"`,
  `step_retry_previous_attempt_id="step-attempt-0001"`), producing
  `goldens/step_retry.json`. The ids are fixed and deterministic, so they
  are not normalized away.
- The conformance schema adds the `fabric.step.*` fields to both
  `child_spans.fabric.llm_call` and `child_spans.fabric.tool_call`
  (`fabric.step.type` / `id` / `attempt_id` / `retry.*` as strings,
  `fabric.step.attempt` as integer ≥ 1). They are kept **optional** in
  `required` to stay lenient for older consumers — even `fabric.step.type`,
  which the SDK now always emits and the enforcement test validates on
  live spans.

## Compatibility

Additive and emit-only. Neither primitive introduces a breaking change.
Decisions outside an execution are byte-identical to the prior release;
the schema additions are optional; `SCHEMA_VERSION` remains `1.0`. The
only child-span change is the always-on, deterministic
`fabric.step.type`, so among the existing conformance goldens only
`llm_call.json` and `tool_call.json` move (gaining `fabric.step.type`),
plus one new `step_retry.json`; the others are unchanged.
