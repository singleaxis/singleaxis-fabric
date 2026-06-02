---
title: Execution & Step capture — outer correlation + lifecycle primitives
status: draft
revision: 1
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
2. **Step** (planned, follow-up PR) — a *child* span taxonomy,
   `fabric.step.*`, that names the phases inside an execution (e.g.
   `plan`, `act`, `observe`). Documented here for contract stability;
   not implemented in this PR.

Both are additive and backward compatible. A `Decision` opened outside an
execution behaves exactly as it did before — the entire existing wire
contract (all 18 conformance goldens) is byte-identical.

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

## Step taxonomy (planned — follow-up PR)

> **Not implemented in this PR.** Documented here so the child-span
> contract is stable before code lands. A follow-up PR will implement
> Step as an emit-only child span under the active decision / execution.

A **Step** names a phase of work inside an execution — the agent loop's
`plan` / `act` / `observe`, or named pipeline stages. It is a **child
span**, `fabric.step.<name>` (kind `INTERNAL`), emitted under the current
decision/execution span. Like Execution it is emit-only: it demarcates a
phase; it does not schedule it.

Planned child-span tags (subject to refinement when implemented):

| Attribute | Meaning |
|-----------|---------|
| `fabric.schema_version` | const `"1.0"` |
| `fabric.step.name` | phase label, e.g. `plan` / `act` / `observe` |
| `fabric.step.kind` | optional coarse category (`reasoning`, `tool`, `io`) |
| `fabric.step.index` | optional 0-based ordinal within the execution |
| `fabric.step.execution_id` | inherited correlation id (as for decisions) |
| `fabric.step.status` | `completed` / `failed`, set on exit |

The commercial Decision Graph consumes execution → step → decision spans
to materialize the run hierarchy and lineage. The OSS SDK only emits
them.

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

## Compatibility

Additive and emit-only. The Execution primitive introduces no breaking
change: decisions outside an execution are byte-identical to the prior
release, the schema additions are optional, and the existing 18
conformance goldens are unchanged (one new `execution.json` is added).
`SCHEMA_VERSION` remains `1.0`.
