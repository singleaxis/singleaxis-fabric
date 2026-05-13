---
title: Modern Agent Primitives (MCP, async tasks, rich tools, memory reads, evals)
status: draft
revision: 1
last_updated: 2026-05-13
owner: project-lead
---

# 018 — Modern Agent Primitives

## 1. Problem

Fabric's SDK surface was designed in early 2024 and predates several
ecosystem developments that are now becoming standard:

| Primitive | When it landed | Fabric's current support |
|---|---|---|
| **MCP** (Model Context Protocol) | late 2024 | none |
| **A2A** (Agent-to-Agent) | early 2025 | none |
| **Long-running / async tasks** above the request-response model | ongoing | none |
| **Memory READS** (mem0, Letta, Zep) | maturing 2024-2025 | only `remember()` (writes) |
| **Rich tool call telemetry** (params, results, errors, retries) | always needed; never adequate | name + result_count only |
| **Async LLM judge** as standard pattern | 2024-2025 | partial (SPEC 015 ships the hook) |
| **Subagent delegation** as a first-class concept | 2024-2025 | only adapter shims |

The result: a customer building a modern agent (multi-turn, MCP-using,
multi-agent, with mem0 for long-term memory) cannot use Fabric's
primitives to fully instrument their agent. They either fall back to
raw OTel (losing Fabric's attribution) or add custom attributes
ad-hoc (losing semantic standardization).

This spec collects the modern-agent primitives the L1 OSS needs in v0.4
to stay relevant. It's deliberately a larger spec than 012-017 because
the scope is broader; expect it to ship in pieces across v0.4 and v0.5.

## 2. Goals

- An agent using **MCP** to call tools can `from fabric.mcp import
  instrument_mcp; instrument_mcp()` and get standardized spans for every
  MCP `connect`, `list_tools`, `call_tool`, `read_resource` interaction.
- An agent calling subagents via LangGraph / CrewAI / A2A protocol can
  emit `fabric.delegate` spans linking parent agent → child agent
  decisions across trace boundaries.
- A long-running agent task (Claude Code-style, runs 30+ minutes) can
  use `fabric.task` as a workflow abstraction above `fabric.decision`,
  with checkpoint/resume semantics.
- An agent using mem0 / Letta / Zep for memory can instrument READS as
  well as WRITES with standardized `fabric.memory.*` attributes.
- A tool call can carry full request/response telemetry (params, result,
  errors, retries, latency breakdown) without dropping to raw OTel.
- All of the above use OTel semantic conventions where possible —
  contribute upstream rather than maintain Fabric-only labels.

## 3. Non-goals

- We do not invent new wire protocols for MCP / A2A / memory. We
  instrument existing ones.
- We do not maintain MCP server registries, A2A directories, or memory
  store catalogs — those are platforms, not telemetry.
- We do not require all of these primitives to land in v0.4. Ship as
  ready. MCP and rich tool tracking are the highest-priority subset.

## 4. Design

### 4.1 MCP instrumentation

Two paths:

**Path A — upstream OTel instrumentor.** Propose an
`opentelemetry-instrumentation-mcp` package to the OTel GenAI semantic
conventions working group. Once it lands upstream, Fabric just lights
up via the wildcard auto-instrumentation detection (SPEC 016 §4.2).

**Path B — Fabric adapter in the interim.** Until OTel ships an
upstream package, ship `fabric.mcp` ourselves:

```python
from fabric.mcp import instrument_mcp_client

# In agent setup:
instrument_mcp_client()  # monkeypatches mcp.client.session.ClientSession
```

Spans emitted per MCP operation:

```
fabric.mcp.connect
  attributes:
    mcp.server.name = "github-mcp"
    mcp.server.version = "0.3.1"
    mcp.transport = "stdio" | "sse" | "websocket"
    mcp.connect.duration_ms = 124

fabric.mcp.list_tools
  attributes:
    mcp.server.name = "github-mcp"
    mcp.tools.count = 12

fabric.mcp.call_tool
  attributes:
    mcp.server.name = "github-mcp"
    mcp.tool.name = "search_issues"
    mcp.tool.params_hash = "<sha256>"   # params not stored; hash for correlation
    mcp.tool.result_size_bytes = 2453
    mcp.tool.duration_ms = 287
    mcp.tool.error = null | "ServerError: ..."

fabric.mcp.read_resource
  attributes:
    mcp.server.name = "github-mcp"
    mcp.resource.uri = "repo://owner/repo"   # hash optional
    mcp.resource.size_bytes = 8421
```

When path A lands upstream, the Fabric adapter is deprecated in favor.

### 4.2 Rich tool tracking

Current `decision.tool_call(name, call_id)` is too thin. Replace with:

```python
with decision.tool_call(
    name="search_orders",
    call_id="t-1",
    kind="function",  # function | mcp | rest_api | subagent | shell
) as t:
    t.set_params({"query": "refund status", "user_id": "X"})
    try:
        result = search_orders(...)
        t.set_result(result, size_hint=len(json.dumps(result)))
        t.set_result_count(len(result))
    except Exception as e:
        t.set_error(type(e).__name__, str(e))
        raise
    finally:
        # latency captured from span duration automatically
        pass
```

Backward-compat: existing calls without new methods continue to work.
New methods optional.

Span attributes added:

```
fabric.tool.kind                = function | mcp | ...
fabric.tool.params_hash         = sha256 of params (not the raw params)
fabric.tool.params              = JSON (only if capture_content=True)
fabric.tool.result_hash         = sha256 of result
fabric.tool.result              = JSON (only if capture_content=True)
fabric.tool.result_size_bytes   = 2453
fabric.tool.error.type          = "RateLimitError"
fabric.tool.error.message       = "429 Too Many Requests"
fabric.tool.retries             = 0  # caller sets if applicable
```

### 4.3 `fabric.task` — workflow above decision

For long-running multi-decision agents:

```python
with fabric.task(
    task_id="01HJZ...",        # opaque
    task_name="generate-pr-from-issue",
    parent_task_id=None,        # for subtasks
) as task:
    task.set_attribute("issue.number", 42)
    
    # Each iteration becomes a fabric.decision under this task
    while not task.complete:
        with task.decision(session_id=...) as d:
            # ... normal decision flow ...
            if some_condition:
                task.checkpoint()  # persist progress, can resume later
            if other_condition:
                task.complete_with(status="success", summary="...")
```

`task` is a span with kind=INTERNAL that spans the entire task duration.
Each decision is a child span. The task span stays open for the lifetime
of the task — for tasks longer than ~30 minutes (where backend timeout
becomes a concern), `checkpoint()` closes the current task span and
opens a fresh one linked via `fabric.task.parent_task_id`.

The lineage attribute is what threads them: a SQL-style `WHERE
task_id = X` query returns all decisions in the entire task lineage.

### 4.4 Memory reads

Symmetric to existing `decision.remember()`:

```python
class Decision:
    def recall(
        self,
        *,
        kind: MemoryKind | str,
        query: str,          # what the agent was searching for
        results: int,        # how many memories were retrieved
        backend: str,        # "mem0" | "letta" | "zep" | "custom"
        hit_ids: list[str] = (),  # opaque ids of retrieved memories
    ) -> MemoryRecallRecord:
        """Record that this decision read from long-term memory."""
```

Emits `fabric.memory.recall` event with:

```
fabric.memory.kind     = "semantic" | "episodic" | "scratch"
fabric.memory.query_hash = sha256
fabric.memory.results  = 3
fabric.memory.backend  = "mem0"
fabric.memory.hit_ids  = ("mem-1", "mem-7", "mem-22")
```

The L2 Commercial Context Graph uses these hit_ids to link recall →
write events across decisions.

For mem0 / Letta / Zep specifically: ship `fabric.memory.adapters`
package with auto-instrumentation extras (`pip install
singleaxis-fabric[mem0]`, etc.). Customer doesn't manually call
`recall()` — the adapter does it via library hooks.

### 4.5 Subagent delegation

When agent A invokes agent B via LangGraph node, CrewAI handoff, or
A2A protocol call:

```python
with decision.delegate(
    target_agent_id="research-agent",
    target_agent_kind="subagent",       # subagent | a2a_protocol | langchain_chain
    propagate_trace_context=True,
) as sub:
    response = research_agent.invoke(sub.propagated_context, ...)
    sub.set_response_summary(response.summary)
```

Emits `fabric.delegate` span — kind=CLIENT — with attributes:

```
fabric.delegate.target_agent_id = "research-agent"
fabric.delegate.target_kind = "subagent"
fabric.delegate.context_propagated = true
fabric.delegate.response_summary_hash = "<sha256>"
```

The propagated context includes the OTel `traceparent` header, so when
the target agent uses Fabric, its decisions become children of this
delegate span — full cross-agent trace lineage out of the box.

### 4.6 Async judge — extends SPEC 015

The judge primitive is fully specified in SPEC 015 (queue_judge,
record_eval). No new design here; this spec just enumerates it as part
of the modern-primitives bundle.

## 5. Work breakdown

Each row is sized as a single PR. They're independent enough to
parallelize.

| # | PR | Effort | Depends on |
|---|---|---|---|
| 1 | `fabric.mcp` adapter — basic MCP client instrumentation | 1-2 weeks | none |
| 2 | OTel GenAI working group proposal for upstream MCP semantic conventions | ~3 days (write-up) + ongoing |  external review |
| 3 | Rich tool tracking — extend `decision.tool_call` API + tests | 1 week | none |
| 4 | `fabric.task` workflow abstraction + checkpoint/resume | 1-2 weeks | none |
| 5 | `Decision.recall()` primitive | 3-5 days | none |
| 6 | `fabric.memory.adapters` extras for mem0 / Letta / Zep | 1-2 weeks (one per backend) | #5 |
| 7 | `Decision.delegate()` primitive | 1 week | none |
| 8 | Update OpenTelemetry instrumentation wildcards to pick up MCP / memory instrumentors | 2-3 days | #1, #6 |
| 9 | Documentation: "instrumenting a modern agent with Fabric" cookbook | 1 week | most |
| 10 | Integration tests covering each new primitive | 1-2 weeks | each |

**Total: ~8-12 weeks. Span across v0.4 and v0.5.**

Suggested split:

**v0.4 (rough order):**
- #3 Rich tool tracking
- #1 MCP basic adapter (Fabric-side, before OTel upstream lands)
- #5 Recall primitive
- #2 OTel proposal
- #9 Documentation for v0.4-shipped pieces

**v0.5:**
- #4 fabric.task
- #6 Memory adapters
- #7 Delegate
- #8 Wildcard pickup
- #9 Updated docs
- #10 Full test coverage

## 6. Acceptance criteria

- An agent using `mcp` package + `fabric.mcp.instrument_mcp_client()`
  emits `fabric.mcp.*` spans for each operation, visible in Phoenix.
- An agent using rich tool tracking shows in the trace: params hash,
  result size, error info — all as standard `fabric.tool.*` attributes.
- A 30-min task using `fabric.task` with three checkpoints produces
  three linked task spans (via `fabric.task.parent_task_id`) plus all
  child decision spans, queryable as one lineage.
- An agent using `decision.recall(...)` emits `fabric.memory.recall`
  events. An adapter-installed mem0 client emits them automatically
  without manual calls.
- A LangGraph multi-agent workflow with `decision.delegate(...)`
  produces a single connected trace across agents, where the child
  agent's spans appear as descendants of the parent's delegate span.
- OTel GenAI working group has at least acknowledged the MCP semantic
  conventions proposal (acceptance is bonus).

## 7. Open questions

1. **Path A vs Path B for MCP.** Upstream OTel may take months. Ship
   Path B in v0.4 as the interim, transition to Path A whenever
   upstream lands. Confirmed.
2. **`fabric.task` parent linkage** — span links (OTel API) or
   attribute-based (`parent_task_id`)? Span links are more correct but
   not all backends visualize them. I lean attribute-based for
   visibility, span links additionally for correctness — both. The
   primary lookup is by attribute.
3. **Memory adapter auto-installation** — does `singleaxis-fabric[mem0]`
   monkeypatch on import, or require explicit `instrument_memory()`?
   I lean explicit, opt-in. Auto-monkeypatch surprises people.
4. **`delegate` for A2A protocol.** A2A is a draft spec from Google.
   What it looks like over the wire is still moving. Ship `delegate`
   with `kind="subagent"` working first, `kind="a2a_protocol"` when A2A
   stabilizes.

## 8. Related work

- SPEC 002 (architecture) — references this for the modern-agent surface
- SPEC 005 (guardrails) — tool-call authorization from SPEC 013
  composes with rich tool tracking from this spec
- SPEC 015 (judge hooks) — async judge primitives
- OpenTelemetry GenAI semantic conventions working group (external)
