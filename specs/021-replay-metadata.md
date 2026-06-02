---
title: ReplayMetadata envelope — emit-only reconstruction metadata
status: draft
revision: 1
last_updated: 2026-06-02
owner: project-lead
---

# 021 — ReplayMetadata envelope

> **Scope split.** This spec covers a single emit-only capture
> primitive: a versioned `fabric.replay` span event that bundles the
> metadata a replay engine needs to reconstruct a decision. The OSS
> boundary is strict — the SDK *emits* this envelope; it never
> reconstructs, orchestrates, or replays a decision. Reconstruction and
> replay orchestration belong to the commercial operational-intelligence
> layer (Decision Graph, replay orchestration). See
> [012](012-oss-commercialization-strategy.md) and
> [003](003-decision-graph.md) for the full OSS↔commercial split.

## Summary

Fabric already emits the breadcrumbs a replay needs as they happen —
`fabric.checkpoint` save-points and `fabric.side_effect` records (each
carrying a `replay_behavior`). What was missing is a single, versioned
*envelope* that says, at one point on the decision timeline, "here is
the bundle of metadata required to reconstruct this decision."

This spec introduces an **optional, emit-only** capture primitive: the
**ReplayMetadata envelope**, a single `fabric.replay` span event emitted
on demand via a new `Decision.record_replay_metadata(...)` method. The
envelope carries its own `metadata_version`, independent of
`SCHEMA_VERSION`, so the envelope's field set can evolve without a
wire-schema bump.

The primitive is additive and backward compatible. A decision that never
calls `record_replay_metadata` emits a byte-identical wire contract to
before. `SCHEMA_VERSION` remains `1.0`.

## The envelope

`Decision.record_replay_metadata(*, state_hash=None, tool_result_hashes=None)`
emits one `fabric.replay` span event. Most of the envelope is assembled
**automatically** from the decision's accumulated state; two fields are
**host-supplied** because the decision cannot derive them itself.

| Attribute | Source | Required | Notes |
|-----------|--------|----------|-------|
| `fabric.schema_version` | const | yes | `"1.0"` |
| `fabric.replay.metadata_version` | const | yes | `"1"` — the envelope's own version, independent of `schema_version` |
| `fabric.replay.decision_id` | auto | yes | the decision's canonical `decision_id` |
| `fabric.replay.execution_id` | auto | no | the decision's resolved execution id; omitted when the decision is not inside an execution |
| `fabric.replay.checkpoint_ids` | auto | no | ids of every checkpoint recorded on this decision; omitted when none |
| `fabric.replay.suppressed_side_effect_ids` | auto | no | ids of side effects recorded with `replay_behavior == "suppress"` (the mutations a replay must NOT re-execute); omitted when none |
| `fabric.replay.state_hash` | host | no | optional host-supplied state fingerprint |
| `fabric.replay.tool_result_hashes` | host | no | optional host-supplied tool-result hashes; the decision does not track child tool spans, so the host passes these |

Auto vs host-supplied is the load-bearing distinction. The SDK already
holds the decision id, the resolved execution id, the accumulated
checkpoints, and the accumulated side effects (with their per-effect
`replay_behavior`), so it derives those four fields with no host input.
The `state_hash` and `tool_result_hashes` are knowledge the SDK does not
have — agent-state fingerprinting and child tool-result hashing are the
host's responsibility — so they are passed in.

The arrays are omitted entirely when empty, matching the rest of the
event contract (an absent key, never an empty array).

## Non-goals (the OSS↔commercial boundary)

The OSS SDK **emits** the `fabric.replay` envelope. It explicitly does
**not**, in OSS:

- **reconstruct** a decision from the envelope — rebuilding the decision
  state, re-running the agent, or re-deriving outputs is the commercial
  replay layer ([012](012-oss-commercialization-strategy.md)).
- **orchestrate or drive** a replay — suppressing side effects, mocking
  tool results, and stepping a reconstruction forward are commercial
  concerns. `replay_behavior == "suppress"` is a *recorded intent*, not
  an enforced control signal.
- **materialize lineage** — joining the envelope with checkpoints, side
  effects, and child spans into a replayable graph and signing audit
  bundles is the commercial Decision Graph
  ([003](003-decision-graph.md)).

The envelope is metadata about how a decision *could* be reconstructed;
the act of reconstruction stays behind the commercial boundary.

## Conformance

A `replay_metadata` conformance scenario opens a decision, records a
checkpoint and a suppress-behavior side effect (both with fixed ids),
then emits the envelope with a host-supplied `state_hash` and
`tool_result_hashes`. The conformance schema gains a `fabric.replay`
event under `events` (`additionalProperties: false`, required:
`schema_version` / `metadata_version` / `decision_id`). Among existing
goldens nothing changes; one new `replay_metadata.json` is added.
