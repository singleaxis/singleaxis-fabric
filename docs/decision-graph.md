# Decision Graph

The **Decision Graph** is Fabric's commercial system of record for
autonomous-system operations. It materializes the open telemetry emitted
by the OSS SDK and collector into a causal graph of executions,
decisions, steps, tools, memory, policies, humans, evaluations, and side
effects.

The public repo owns the contract. The commercial repo owns the
production engine.

## Why Decision Graph

Agent traces alone are not enough. Production incidents usually ask:

- Which workflow or agent caused this external change?
- What did the agent retrieve before it acted?
- Which policy allowed, warned, or blocked the action?
- Did a human approve it?
- Which memory records influenced the answer?
- Which side effects were committed?
- Can this execution be reconstructed or safely replayed?

Decision Graph is the layer that answers those questions.

## Core primitives

| Primitive | Meaning |
|---|---|
| `Execution` | A full workflow, run, job, or long-lived autonomous task |
| `Decision` | A governance-relevant choice point |
| `Step` | LLM call, tool call, memory event, policy check, evaluator action |
| `SideEffect` | External state mutation or irreversible operation |
| `Intervention` | Human, policy, or system override |
| `Checkpoint` | State boundary for reconstruction or replay |

## OSS contract

The OSS repo should contain:

- canonical primitive names and required fields
- OpenTelemetry span and event mappings
- conformance fixtures
- reference SDK emission paths
- local examples that prove reconstruction metadata is emitted

The OSS repo should not contain:

- production graph builder
- graph storage migrations
- enterprise query APIs
- replay orchestration
- evidence bundle jobs
- commercial analytics

## Commercial engine

The commercial Decision Graph engine should provide:

- idempotent event materialization
- cross-decision lineage
- hot decision reads
- replay indexes
- side-effect queries
- retention and erasure workflows
- evaluation and risk trend joins
- evidence export inputs

## Replay language

Use **reconstruction-first** language.

Fabric v1 must not promise exact deterministic replay of arbitrary LLM
outputs or external APIs. It should promise that enough metadata is
captured to reconstruct what happened and to enable replay-safe workflows
when the runtime supports checkpoints and side-effect suppression.

## Related specs

- [Spec 003 — Decision Graph](../specs/003-decision-graph.md)
- [Spec 012 — Operational Infrastructure PRD](../specs/012-oss-commercialization-strategy.md)
