---
title: Inline Guardrails & Latency Budget
status: draft
revision: 1
last_updated: 2026-04-18
owner: project-lead
---

# 005 — Inline Guardrails

## Summary

Fabric's Layer 5 (Guardrails) runs **inline and in-process** with the
agent — as imported libraries, not as a network service — because it
is the only layer other than the LLM call that sits on the user's
critical path. This spec fixes the latency budget, the default
implementation stack, the integration contract, and the fallback path
for non-Python agents.

## Goals

1. Impose a hard latency budget on Layer 5: total inline overhead
   **< 200 ms p99** on the agent's critical path.
2. Specify the default guardrail stack (Presidio + NeMo Guardrails)
   and the integration contract the Fabric SDK enforces.
3. Define input, output, and streaming-output filters consistently.
4. Provide a fallback for agents that cannot import Python libraries
   in-process (Go, Node, compiled languages).
5. Emit every guardrail action as a structured event consumed by
   the Decision Graph.

## Non-goals

- Inventing new policy languages. We use NeMo Guardrails' Colang
  and OPA Rego for policy; we do not ship a Fabric-proprietary
  policy DSL.
- Replacing LLM-based content moderation (Llama Guard et al.). Those
  are pluggable as a slower second-pass filter, not the default
  inline filter.
- Per-token streaming moderation with human latency-level control
  (e.g. blocking mid-token). That is a future feature.

## Why inline, not sidecar

Every network hop on the request path costs ~1–5 ms p50 and 10–50 ms
p99 inside a cluster, 50+ ms across AZs. For a guardrail that must
check input *and* output, a sidecar adds ~40–200 ms of round-trip
latency p99 — 20–100% of the entire latency budget.

In-process Python import:

- Zero network hop
- Latency dominated by Presidio / NeMo themselves
- Measurable: 30–150 ms p99 on typical inputs (short to medium)
- Shared process memory for the model (recognizer pipelines load
  once)

In-process is non-negotiable for Python agents. Sidecar is a
documented fallback for non-Python runtimes only, with an explicit
latency budget relaxation.

## Latency budget

Targets apply on the agent's critical path, per turn:

| Phase | p50 budget | p99 budget |
|-------|-----------:|-----------:|
| Input guardrail (L5 in) | 30 ms | 150 ms |
| Output guardrail (streaming, per chunk) | 5 ms | 20 ms |
| Context read (L8 cached) | 20 ms | 100 ms |
| Auth check (L7 cached) | 5 ms | 20 ms |
| OTel span emit (L2) | 1 ms | 5 ms |
| **Total Fabric inline overhead** | **< 60 ms** | **< 200 ms** |

The LLM call itself is not in this budget (tenant's model, tenant's
network); Fabric must not add to it.

### Enforcement

- Every Fabric SDK release ships with a benchmark suite that
  exercises the inline path on representative inputs.
- CI runs the benchmark on each PR; PRs that regress any phase's
  p99 by > 10% are blocked unless the maintainer explicitly signs
  off with a rationale.
- The Fabric Admin UI plots the inline phase latencies per-tenant so
  regressions in production are visible.

## The default stack

### Presidio (PII detection + redaction)

- **Role:** detect and redact PII in input and output strings.
- **Mode:** runs on every input and every complete output. For
  streaming output, runs at chunk boundaries defined by the
  orchestrator.
- **Categories:** default PII recognizers (names, emails, phones,
  SSNs, credit cards, addresses, medical IDs) plus tenant-
  configured custom recognizers.
- **Action on detection:** per-policy; defaults:
  - Input: redact and proceed (agent sees `<REDACTED:EMAIL>`)
  - Output: redact and proceed; emit guardrail event

### NeMo Guardrails (content policy + dialog control)

- **Role:** enforce dialog rules (off-topic, refusal, tool-use
  restrictions) and content policy (toxicity, jailbreak detection).
- **Mode:** runs on input before LLM call; on output before
  return. Colang rails define the policy.
- **Action on detection:** per-rail; typical:
  - Refuse with a canned response
  - Redirect to a safer rail
  - Block and return a policy-violation error to the caller
- **Jailbreak detection:** NeMo's input rails cover common patterns;
  tenants may layer Llama Guard or equivalent as a slower
  second-pass filter (off the critical path).

### Llama Guard (optional second pass)

- **Role:** LLM-based content classification for cases where
  rule-based filters are insufficient.
- **Mode:** runs **async** via the event bus, not inline. If Llama
  Guard disagrees with the inline verdict and the disagreement is
  severe enough, triggers an escalation.
- **Rationale:** Llama Guard is accurate but too slow for inline
  (100–500 ms for a small model, seconds for larger). It earns its
  keep as a post-hoc second opinion.

## The integration contract

The Fabric SDK binds guardrail checks to the active `Decision`
context manager, not to a free-standing `Guardrails` object. The
profile and rail set are configured on the `Fabric` client at
construction time; the `Decision` methods delegate to the
internally-managed chain.

```python
# Example — normative API defined in sdk/python/src/fabric/decision.py
# and sdk/python/src/fabric/guardrails.py.
from fabric import Fabric, FabricConfig, UDSNemoClient, UDSPresidioClient

fabric = Fabric(
    FabricConfig(tenant_id="t", agent_id="a", profile="eu-ai-act-high-risk"),
    presidio=UDSPresidioClient("/run/fabric/presidio.sock"),
    nemo=UDSNemoClient("/run/fabric/nemo.sock"),
)

with fabric.decision(
    session_id=session.id,
    request_id=req.id,
    user_id=user.id,
) as decision:
    # Input path. guard_input returns the redacted/rewritten text.
    # It does not raise on a block; hosts that want exception-style
    # flow run the chain directly and call record_block + raise_for_block.
    prompt_for_llm = decision.guard_input(user_input)

    # Output path (streaming). Each chunk is redacted in place.
    for chunk in llm_stream:
        yield decision.guard_output_chunk(chunk)

    # Final pass on complete output (for checks that need the full text).
    final = decision.guard_output_final(complete_output)

    # Exception-style block handling (opt-in):
    result = fabric.guardrail_chain.check(
        phase="input", path="input", value=user_input,
    )
    if result.blocked:
        decision.record_block(result)
        decision.raise_for_block()   # raises GuardrailBlocked
```

If no rails are configured on the `Fabric` client, each
`guard_*` method raises `GuardrailNotConfiguredError`. Silent
pass-through would be a compliance footgun; the SDK fails loud.

Every check returns a `GuardrailResult` with:

- `event_id: UUID` — correlates the decision span event with the
  `DecisionSummary` wire event the Telemetry Bridge emits.
- `blocked: bool`
- `block_response: str | None` — the canned response if blocked.
- `redacted_content: str` — content with redactions applied (also
  what `guard_input` / `guard_output_*` return to the caller).
- `entities_detected: list[EntitySummary]` — category + count; no
  raw values.
- `policies_fired: list[str]` — policy identifiers
  (e.g. `presidio:EMAIL`, `nemo:jailbreak_defence`).
- `latency_ms: float`

The `guard_*` methods **emit a `fabric.guardrail` span event
automatically** with phase, latency, blocked flag, and the
allowlisted policy / entity attributes. Agents do not separately
log guardrail actions. Downstream, the Telemetry Bridge folds those
span events into the Decision Graph.

## Streaming output filter

Streaming moderation is hard: you cannot check the complete output
until it exists, but waiting for the complete output defeats the
point of streaming.

Fabric's approach:

1. **Chunk-level redaction:** as each chunk arrives, run Presidio
   on the chunk; replace detected PII before emitting to the user.
   Cheap (<5 ms per chunk).
2. **Sliding-window content check:** maintain a rolling window
   (default 256 tokens) over recent output. NeMo Guardrails checks
   the window for policy violations as it grows. A violation
   terminates the stream, emits the block response, and escalates.
3. **Final pass:** once the stream completes, run a final full-text
   check for anything the windowed check might have missed. This is
   post-stream; it does not affect latency observed by the user
   but can still trigger an escalation if the complete text
   violates policy.

This is a pragmatic tradeoff. It is not a guarantee that no bad
token reaches the user — that is only achievable by non-streaming
inference. For streaming, this is the best compromise.

## Per-profile configuration

Regulatory profiles (spec 009) configure guardrails. A profile sets:

- Which Presidio recognizers are active (and with what thresholds)
- Which NeMo Colang rails load
- Default actions (redact vs block) per category
- Whether Llama Guard second-pass is enabled
- Streaming behaviour (chunk size, window size, terminate vs warn)
- Which custom recognizers the tenant has defined

Tenants may override within bounds. A profile may declare certain
rails as **mandatory** (cannot be disabled by tenant config);
disabling a mandatory rail requires dropping to a less-strict
profile.

## Non-Python runtimes

Some agents run in Go, TypeScript, Rust, or other languages where
in-process Python is not an option. Fabric supports them via a
**local gRPC sidecar**:

- Sidecar deploys as a second container in the agent's pod
- Shares a Unix domain socket (no network hop)
- Exposes the same `check_input` / `check_output_*` methods via gRPC
- Latency budget relaxation: < 300 ms p99 (vs 200 ms for in-process)

The sidecar is not preferred — the latency cost is real — but it is
the honest option for non-Python stacks. The Fabric SDK ships
client bindings for Go, TypeScript, and Rust that talk to the
sidecar with the same API shape.

## Event emission

Every `guard_*` call emits a `fabric.guardrail` span event on the
active decision span with allowlisted attributes only. No raw
content is ever placed on the span. The in-memory
`GuardrailResult` shape (see the integration contract above) is
the ground truth the Telemetry Bridge serializes onto the wire.

The span event attributes are:

| Attribute | Type | Notes |
|---|---|---|
| `fabric.guardrail.phase` | `input` \| `output_stream` \| `output_final` | |
| `fabric.guardrail.latency_ms` | float | End-to-end chain latency. |
| `fabric.guardrail.blocked` | bool | Presidio only redacts; the NeMo rail and any pluggable `GuardrailChecker` tier (`extra_checkers`) may block. |
| `fabric.guardrail.policies` | tuple[str, ...] | e.g. `("presidio:EMAIL", "nemo:jailbreak_defence")`. Omitted if no policy fired. |
| `fabric.guardrail.entities` | tuple[str, ...] | `category:count` pairs. Omitted if none. |

Events flow to:

- **OTel** — as a `fabric.guardrail` span event on the decision
  span, alongside `fabric.blocked` / `fabric.blocked.policies`
  attributes when a block was recorded.
- **Telemetry Bridge + Decision Graph** — the bridge folds the
  decision span's guardrail events into the `DecisionSummary` wire
  event; the graph builder materializes the guardrail provenance
  from there.

Events never contain raw content.

## Security considerations

- **Guardrail bypass.** The SDK's API is the contract; agents that
  call the LLM without passing input/output through the guardrail
  API bypass Fabric's guarantees. This is out of scope for the SDK
  to prevent; tenants enforce via code review and (for paranoid
  profiles) by routing LLM traffic through a Fabric-owned proxy
  that enforces the checks.
- **Policy update TOCTOU.** Colang rails and Presidio recognizers
  are loaded at SDK init and reloaded on a signed manifest update.
  Between reloads the policy is fixed; a rollout that requires
  new policy + new code version must happen in that order.
- **Dependency trust.** Presidio and NeMo Guardrails are the
  standard tooling; version pinning and SBOM tracking are
  mandatory. Breaking changes in either require a Fabric minor
  bump.
- **PII recognizer false negatives.** No PII detector is perfect.
  The profile's default action should be redact (not block) for
  PII so false negatives degrade gracefully; combined with the
  Telemetry Bridge's second-pass check (spec 004), a false
  negative inline still does not leak.

## Operational considerations

- **Memory footprint.** Presidio pipelines load spaCy models; ~200–
  500 MB per agent process depending on language support. NeMo
  adds ~50–100 MB. Budget 1 GB of memory minimum per agent pod.
- **Cold start.** Initial load of recognizers is 3–8 seconds;
  agents should preload at startup, not on first request.
- **Custom recognizer deployment.** Tenant-defined Presidio
  recognizers deploy via the signed manifest channel (spec 008),
  not via agent code, so updates do not require redeploy of the
  agent.

## Open questions

- **Q1.** Do we standardize on spaCy's large English model or ship
  a smaller default and let profiles upgrade? *Resolver: SDK
  maintainer + compliance. Deadline: before 0.1.0.*
- **Q2.** For output streaming, what is the correct user experience
  when we block mid-stream? Revoke the partial response, or let it
  stand with an inline warning? *Resolver: SDK maintainer + UX
  review. Deadline: before 0.2.0.*
- **Q3.** Should Llama Guard (second-pass) results be allowed to
  rewrite the Decision Graph verdict after the fact, or only append
  a flag? Integrity concerns on retroactive modification.
  *Resolver: graph maintainer. Deadline: before 0.2.0.*

## References

- Spec 002 — Architecture
- Spec 003 — Decision Graph (consumer of guardrail events)
- Spec 009 — Compliance mapping (profile definitions)
- [Microsoft Presidio](https://microsoft.github.io/presidio/)
- [NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)
- [Llama Guard](https://huggingface.co/meta-llama/LlamaGuard-7b)
