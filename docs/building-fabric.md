# Building Fabric

This document is the engineering compass for rebuilding Fabric around
the new positioning: **operational infrastructure for autonomous
systems**.

## Product spine

Every feature should strengthen at least one of these pillars:

1. **Execution telemetry** — what happened?
2. **Causality lineage** — what caused it?
3. **Replay metadata** — can we reconstruct or safely replay it?
4. **Governance** — which policy, human, or system allowed it?
5. **Side-effect control** — what external state changed?
6. **Runtime evaluation** — was it good, safe, and compliant over time?

If a feature does not map to one of these, it probably belongs outside
Fabric.

## Architecture rules

- Fabric is not an agent framework.
- Fabric is not a model gateway.
- Fabric is not a prompt-management system.
- Fabric should integrate with workflow engines rather than replace
  them.
- Fabric should use OpenTelemetry and public schemas on the capture
  path.
- Fabric should keep raw content off by default.
- Fabric should make side effects first-class.
- Fabric should treat replay as reconstruction-first, orchestration
  later.

## v1 rebuild sequence

Build in this order:

1. **Canonical schemas**
   - `Execution`
   - `Decision`
   - `Step`
   - `ToolCall`
   - `MemoryRead`
   - `MemoryWrite`
   - `PolicyDecision`
   - `SideEffect`
   - `Intervention`
   - `Checkpoint`

2. **Python SDK hardening**
   - Keep `Fabric` and `Decision`.
   - Add execution/workflow correlation.
   - Add side-effect recording.
   - Add checkpoint metadata.
   - Add stricter conformance tests.

3. **Collector contract**
   - Normalize `fabric.*` events.
   - Preserve OpenTelemetry GenAI compatibility.
   - Redact and allowlist attributes.
   - Emit dropped-field diagnostics.

4. **TypeScript SDK**
   - Match Python schema.
   - Support OpenAI Agents SDK, LangGraph JS where applicable, and
     custom runtimes.

5. **Framework adapters**
   - LangGraph
   - CrewAI
   - OpenAI Agents SDK
   - Microsoft Agent Framework
   - Temporal / Restate hooks for workflow correlation

6. **Local debugging flow**
   - first trace in less than 10 minutes
   - local collector
   - local observability backend
   - conformance check command

7. **Commercial Decision Graph**
   - materializer in private repo
   - replay indexes
   - side-effect queries
   - retention and erasure workflows

## Feature quality bar

Every production feature needs:

- schema contract
- SDK emission path
- collector handling
- conformance fixture
- docs
- tests
- privacy posture
- failure mode
- migration story

## Replay standards

Never claim exact deterministic replay unless all dependencies are
deterministic and side effects are controlled.

Allowed terms:

- reconstruction metadata
- replay-safe metadata
- side-effect suppression
- workflow replay where supported
- deterministic replay for deterministic runtimes

Avoid broad claims like:

- "replay any agent"
- "reproduce every output"
- "deterministic LLM replay"

## Side-effect standards

Any tool call that mutates external state should emit a `SideEffect`.

At minimum capture:

- target system
- operation name
- idempotency key, if any
- request hash
- result hash
- commit status
- rollback support
- approval requirement
- replay behavior

## Documentation standard

Docs should always state:

- what ships in OSS today
- what is commercial
- what is roadmap
- what is an architectural contract
- what is measured versus only budgeted

This keeps the project credible with platform engineers, CISOs, and
auditors.
