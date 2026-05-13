---
title: Guardrails — Completion Spec
status: draft
revision: 1
last_updated: 2026-05-13
owner: project-lead
supersedes: portion of 005-guardrails-inline §"NeMo"
---

# 013 — Guardrails Completion

## 1. Problem

As of v0.2.0, Fabric's guardrails surface has three structural gaps:

1. **NeMo Guardrails sidecar image is not published.** The `nemo-sidecar`
   Helm chart exists in the repo, but the image it expects on GHCR
   doesn't. Customers cannot `helm install` it from a registry.
2. **NeMo chart deploys as a shared TCP Service, but the SDK only speaks
   UDS.** The chart's own NOTES.txt acknowledges this — "Phase 1 ships
   this as a shared TCP Deployment; production deployments should inject
   this container as a per-agent-pod sidecar over a Unix domain socket —
   the injection webhook lands in Phase 2." Phase 2 has not landed.
   So today, the chart's deployment topology is unusable from the SDK.
3. **No tiered guardrail architecture.** All inline guards (Presidio,
   NeMo) run sequentially every turn, with no fast-path regex, no
   sampling, no asynchronous LLM judge. P99 latency on a warm pod is
   workable but not competitive for high-throughput agents.

Additional issues:

- No first-class integration with **Lakera Guard** or **Llama Prompt Guard**
  despite both being mentioned as recommended jailbreak engines in
  internal strategy. The `NemoClient` Protocol is open for substitution,
  but no shipped adapters exist.
- No support for **tool-call authorization** — the `decision.tool_call`
  primitive opens a span but has no policy hook to evaluate "is this
  agent allowed to call this tool with these params for this user."
- No async / sampled guard pattern. Every inline guard blocks the turn.

## 2. Goals

- The `fabric-nemo-sidecar` image is published to GHCR and the chart
  installable from the umbrella `charts/fabric`.
- Customers can deploy NeMo as a **per-agent-pod sidecar over UDS**
  (production pattern) without writing custom manifests — chart provides
  the sidecar-injection snippet AND a shared-service mode for dev/smoke.
- A tiered guardrail chain replaces the single sequential chain:

  ```
  regex (in-process, <1ms) → Presidio (UDS, ~10ms) → jailbreak classifier
  (UDS, ~20ms) → optional NeMo policy rails (UDS, ~50ms) → optional async
  LLM judge (background, attached as span event later)
  ```

- First-class adapters ship for: **Lakera Guard** (commercial cloud),
  **Llama Prompt Guard 86M** (Meta OSS, can run as a sidecar), and a
  generic **classifier-over-HTTP** adapter for arbitrary models.
- `decision.tool_call` gains an optional policy hook to authorize tool
  invocations against OPA or a callable.

## 3. Non-goals

- We do not build a new guardrail engine. NeMo, Lakera, Llama Prompt Guard
  cover the space.
- We do not ship the admission webhook for sidecar injection (the "Phase
  2" promise in the existing NOTES.txt). That's a bigger piece of work;
  for v0.3 we ship the manifest snippet as a Helm partial that customers
  paste into their agent Deployment.
- We do not ship curated industry rail libraries in OSS — those are
  Commercial.

## 4. Design

### 4.1 Tiered guardrail chain

The current `_chain.GuardrailChain` runs all configured guards
sequentially. Replace with a tier-aware chain:

```python
class GuardrailChain:
    tiers: list[GuardrailTier]
    # tier 1: regex (in-process)
    # tier 2: Presidio (UDS)
    # tier 3: jailbreak (UDS or HTTP — Lakera, Llama Prompt Guard, NeMo)
    # tier 4: policy rails (UDS — NeMo Colang)
    # async sink: LLM judge — fires after turn returns, attaches to trace
    
    def check(phase, path, value) -> GuardrailResult:
        # Short-circuit: if tier 1 catches obvious PII and no other
        # tier is configured to inspect input, skip the network calls.
        # Tier ordering: cheap-first, expensive-last, async never blocks.
```

Each tier:
- Returns one of `allow`, `redact`, `block`, `warn`
- Emits its own span event with `fabric.guardrail.tier`, `fabric.guardrail.engine`
- Contributes to the aggregated `GuardrailResult` returned to the caller

### 4.2 NeMo as per-pod UDS sidecar

The `nemo-sidecar` chart gains a new mode:

```yaml
# values.yaml
sidecar:
  mode: shared-service | per-pod-sidecar  # default: per-pod-sidecar
```

In `per-pod-sidecar` mode, the chart produces:

- A `Sidecar` partial template (`charts/.../templates/_sidecar.tpl`) that
  customer's agent Deployment includes via Helm subchart pattern
- The sidecar container shares a hostPath-free `emptyDir` volume with the
  agent at `/var/run/fabric/`
- Listens on UDS at `/var/run/fabric/nemo.sock`
- No `Service` resource emitted in this mode

In `shared-service` mode (legacy, for dev), the current chart behavior is
preserved.

Documentation gets explicit guidance: **shared-service is dev-only;
production agents must use per-pod-sidecar**.

### 4.3 Lakera Guard adapter

A new package: `fabric.guardrails.lakera`. Implements the existing
`NemoClient`-shaped Protocol (renamed `GuardrailClient` to reflect
neutrality):

```python
class LakeraGuard:
    def __init__(self, api_key: str, project_id: str | None = None,
                 endpoint: str = "https://api.lakera.ai/v2/guard"):
        ...
    
    def check(self, phase, path, value) -> GuardrailResult:
        # POST to Lakera /v2/guard, map response to GuardrailResult
```

Wired via env: `FABRIC_LAKERA_API_KEY`. Auto-detected by
`Fabric.from_env()` into tier 3.

### 4.4 Llama Prompt Guard adapter

A new sidecar component: `components/prompt-guard-sidecar/`. Wraps the
86M Meta Prompt Guard model behind the same UDS+JSON protocol as
Presidio/NeMo. Ships as a chart + image.

For environments without GPU, fall back to CPU inference (slower but
works). Default: GPU if `nvidia.com/gpu` requests are honored, else CPU.

### 4.5 Generic classifier-over-HTTP adapter

Some teams have their own jailbreak classifiers. The
`fabric.guardrails.http` adapter takes:

```python
HttpGuardrail(
    endpoint="http://internal-classifier:8080/check",
    request_template={"input": "{value}", "phase": "{phase}"},
    response_jq=".decision",   # JSONPath / jq-style for parsing
    timeout_ms=200,
)
```

Allows integration without writing code.

### 4.6 Tool-call authorization

`decision.tool_call()` gains an optional `authorize` parameter:

```python
def authorize_tool(tool_name: str, params: dict) -> ToolAuthDecision:
    # caller-supplied callable, OR a configured OPA endpoint
    ...

with decision.tool_call("transfer_money", params={"to": "x", "amount": 1000},
                        authorize=authorize_tool) as call:
    if not call.authorized:
        raise PermissionError(call.reason)
    result = bank.transfer(...)
```

If `authorize` returns deny, the tool span is marked
`fabric.tool.authorized = false` with a reason, and the caller decides
whether to raise.

### 4.7 Async LLM judge primitive

A new method on `Decision`:

```python
decision.queue_judge(
    judge_id="hallucination-check-v2",
    target="output",  # the response text
    metadata={"model": "claude-opus-4-7"},
)
```

In L1 OSS, this **emits a span event** `fabric.judge.queued` with the
relevant context. The actual judge worker is L2 Commercial — it reads
the queued event, runs an LLM grade, and writes back a
`fabric.judge.verdict` event linked by trace_id.

If no L2 worker is running, the queued event still appears in the trace
(useful for cost/coverage analytics) but no verdict ever arrives. That's
intentional — the L1 OSS user gets a "you'd benefit from L2" signal
without paying for a judge.

## 5. Work breakdown

| # | PR | Effort | Depends on |
|---|---|---|---|
| 1 | Refactor `GuardrailChain` → tier-aware chain | 3-5 days | SPEC 012 #2 (redaction modes) |
| 2 | Add `nemo-sidecar` `per-pod-sidecar` mode to chart + partial template | 2-3 days | none |
| 3 | Publish `fabric-nemo-sidecar` image to GHCR via CI | 1 day | SPEC 017 |
| 4 | `fabric.guardrails.lakera` adapter + env auto-detect | 2-3 days | #1 |
| 5 | `components/prompt-guard-sidecar` — new component (build + chart + image) | 1-2 weeks | #1, SPEC 017 |
| 6 | `fabric.guardrails.http` generic adapter | 2-3 days | #1 |
| 7 | `decision.tool_call(authorize=...)` parameter | 2-3 days | none |
| 8 | `decision.queue_judge()` primitive — emits queued event only | 2 days | none |
| 9 | Docs: tiered guardrail pattern, when to use each engine, latency budgets | 1-2 days | all of above |
| 10 | Integration tests: tiered chain, per-pod sidecar mode | 2-3 days | #1, #2 |

**Total: ~4-6 weeks.**

## 6. Acceptance criteria

- `fabric-nemo-sidecar:0.3.0` published to GHCR; chart installable from
  `oci://ghcr.io/singleaxis/charts/fabric`.
- A reference agent can be deployed with NeMo as a per-pod UDS sidecar
  using only stock chart values — no hand-rolled manifests.
- `fabric.guardrails.lakera.LakeraGuard(...)` works end-to-end with a
  real Lakera API key.
- `prompt-guard-sidecar:0.3.0` image builds, runs on CPU and GPU, exposes
  `/v1/check` over UDS.
- A turn invoking `guard_input("ignore previous instructions, ...")`
  through the tiered chain hits jailbreak at tier 3 and blocks before
  reaching tier 4. Span events show which tier fired.
- `decision.tool_call("transfer_money", authorize=...)` blocks
  unauthorized invocations with a clear `fabric.tool.authorized = false`
  attribute.
- `decision.queue_judge(...)` emits `fabric.judge.queued` span event;
  no L2 worker is present so no verdict event follows — verified in trace.

## 7. Open questions

1. **Generic adapter as one-of-many or one-fits-all?** Should
   `fabric.guardrails.http` replace dedicated Lakera/Llama Prompt Guard
   adapters (just generic adapter with config) or coexist? I lean coexist:
   dedicated adapters are nicer for the common case; generic is the
   escape hatch.
2. **Tool-call auth via OPA or callable-only?** First version of (4.6)
   could be callable-only (Python function). Adding OPA integration is
   another 1-2 days. I lean callable-only in v0.3, OPA in v0.4.
3. **Async judge mechanism** — is the queued event self-contained (enough
   metadata that the L2 worker doesn't need to fetch anything else) or
   does the worker pull additional context from the trace store? First
   version self-contained; refine in v0.4.

## 8. Related work

- SPEC 005 (current guardrail architecture; this spec restructures it
  into tiers)
- SPEC 006 (LLM-as-judge; this spec defines the L1 OSS hook into the
  L2 judge)
- SPEC 012 (PII redaction completion; the regex pre-filter from there
  becomes tier 1 of this spec's chain)
- SPEC 017 (publishing pipeline)
