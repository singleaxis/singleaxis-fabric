---
title: Judge Hooks — L1 OSS Primitives
status: draft
revision: 1
last_updated: 2026-05-13
owner: project-lead
relates_to: 006-llm-as-judge
---

# 015 — Judge Hooks (L1 OSS Primitives Only)

## 1. Problem

The L1 OSS does not, and should not, ship a production LLM-as-judge
worker. That capability is part of L2 Commercial — running judge models
reliably is operational work with ongoing costs (judge LLM API spend,
queue management, model selection per use case).

But the L1 OSS **must** ship the **hooks** that let an L2 worker
(commercial, or customer-built) hang off the L1 trace pipeline. Without
those hooks, L1 and L2 cannot interoperate.

As of v0.2.0 there are two relevant primitives, both incomplete:

1. **`Decision.request_escalation(summary)`** — records an escalation
   request. But the semantics of what an L2 worker should do with it are
   undocumented. There's no schema for "what should the judge actually
   evaluate."
2. **No `Decision.record_eval(...)` primitive** — there's no way for
   any caller (L2 worker, in-process judge, post-hoc evaluator) to write
   a score back onto a decision after the fact.

Customers who want even basic eval (sample 1% of traffic, judge with
gpt-4o-mini, attach score to the trace) have to wire raw OTel themselves
— and lose the standardized `fabric.*` attribution.

## 2. Goals

- A clean, documented contract between L1 OSS (emits judge work items)
  and any judge worker (L2 Commercial, customer-built, or open-source
  shim) that consumes them and writes verdicts back.
- A `Decision.record_eval(...)` primitive that lets any caller attach a
  judge score, model used, latency, and reason to a decision's trace,
  by trace_id.
- A `Decision.queue_judge(...)` primitive that emits a structured "this
  decision should be judged" event for downstream workers to pick up.
- An optional in-OSS reference judge shim — `fabric.judge.simple` —
  that runs a judge LLM call inline (slow, blocking) or in a small async
  pool. Not production-grade; for demos and minimal local setups.

## 3. Non-goals

- We do NOT ship a production queue, worker pool, retry logic, or judge
  model orchestration in OSS. Those are L2.
- We do NOT ship judge prompts or rubric libraries in OSS. Those are
  Commercial L2 (the curated content library).
- We do NOT prescribe which LLM is "the judge." The L2 worker picks
  per tenant / per use-case.

## 4. Design

### 4.1 Event format — what L1 emits, what L2 consumes

When a decision wants to be judged, the SDK emits a span event:

```
event name: fabric.judge.queued
attributes:
  fabric.judge.id              = "hallucination-grounding-v2"   # caller-defined
  fabric.judge.target          = "output_final"                  # input | output_stream | output_final | retrieval
  fabric.judge.target_hash     = "<sha256 of the target text>"
  fabric.judge.target_size     = 1247                            # bytes
  fabric.judge.priority        = 5                               # 0-9
  fabric.judge.requested_by    = "agent" | "policy" | "sampler"
  fabric.judge.rubric_ref      = "fabric://rubrics/hallucination-v2"  # URI; L2 resolves
  # NOT the target content itself (PII concerns); worker fetches via
  # trace_id + the customer's trace backend if it needs full content
```

When a worker (L2, custom, or OSS shim) completes the judgement, it
writes back via the SDK's `record_eval`:

```
event name: fabric.judge.verdict
attributes:
  fabric.judge.id              = "hallucination-grounding-v2"   # echoes queued
  fabric.judge.score           = 0.78                            # float 0..1
  fabric.judge.passed          = true | false
  fabric.judge.reason          = "<short text>"                  # opt
  fabric.judge.confidence      = 0.91                            # opt, float 0..1
  fabric.judge.model           = "claude-haiku-4-5-20251001"
  fabric.judge.latency_ms      = 412
  fabric.judge.worker_id       = "l2-judge-pool-3"               # opt
```

The worker writes back into the **same trace** by re-opening the span
context using the trace_id+span_id propagated alongside the queued
event. OTel makes this possible via the standard `trace.use_span(...)`
API with a derived `SpanContext`.

### 4.2 `Decision.queue_judge()` — the L1 OSS write side

```python
class Decision:
    def queue_judge(
        self,
        *,
        judge_id: str,
        target: Literal["input", "output_stream", "output_final", "retrieval"],
        target_value: str,
        rubric_ref: str | None = None,
        priority: int = 5,
        requested_by: Literal["agent", "policy", "sampler"] = "agent",
    ) -> JudgeQueuedRecord:
        """Mark this decision as needing judgement.

        Emits a fabric.judge.queued event on this decision's span.
        Does NOT block — the actual judging happens out-of-band by a
        worker (L2 Commercial, customer-built, or fabric.judge.simple).

        target_value is hashed; the hash and metadata land on the span.
        The raw value is not stored on the span. Workers that need the
        raw value either receive it via a queue payload (worker design's
        choice) or fetch it from the trace backend via the trace_id +
        the customer's `capture_content` setting.
        """
```

### 4.3 `Decision.record_eval()` — the L1 OSS read-back side

```python
class Decision:
    def record_eval(
        self,
        *,
        judge_id: str,
        score: float,
        passed: bool,
        reason: str | None = None,
        confidence: float | None = None,
        model: str | None = None,
        latency_ms: int | None = None,
        worker_id: str | None = None,
    ) -> JudgeVerdictRecord:
        """Write a judge verdict back onto this decision's trace.

        Typically called by a worker process, NOT by the original
        agent. The worker connects to the SDK using the trace_id
        propagated alongside the original queued event and creates
        a Decision with that trace context.

        Score is float [0.0, 1.0]; passed is a boolean independent of
        score so workers can implement non-linear thresholds.
        """
```

### 4.4 `fabric.judge.simple` — the OSS reference shim

A minimal, blocking, in-process judge for demos and local development.
Not production-grade but useful for showing "this is how L2 works at
its simplest":

```python
from fabric.judge.simple import SimpleJudge
import anthropic

judge = SimpleJudge(
    llm=anthropic.Anthropic(),
    model="claude-haiku-4-5-20251001",
    rubric="""You are evaluating whether an AI agent's output is
              grounded in retrieved context. Score 0.0 if hallucinated,
              1.0 if fully grounded. Reply with JSON: {score, passed, reason}.""",
)

# Subscribe to a Decision context to auto-judge on exit:
with fabric.decision(...) as d:
    d.set_judge(judge)  # judges output_final on context exit
    ...

# Or judge synchronously inline (blocking):
verdict = judge.evaluate(target_value=response.text, decision=d)
```

This is OSS-only-utility. L2 Commercial customers will replace
`SimpleJudge` with the hosted worker — same interface.

### 4.5 Trace context propagation for out-of-process workers

A worker needs to know which decision to attach its verdict to, and
needs the ability to write a span event onto that already-finished
decision's trace. Two practical mechanisms — both honest about the
constraint that **OTel spans are immutable after `end()`**:

- **In-flight workers** (worker runs while the decision span is still
  open, e.g., async inside the same Python process or short-lived
  workers that subscribe to a queue and complete in seconds): the
  worker holds a reference to the still-open span and writes a verdict
  event directly. Standard OTel API.

- **Post-hoc workers** (worker runs after the original decision span
  has closed, e.g., a separate process picks up queued events from
  the trace backend's API): the worker emits a **new span** that
  carries the same trace_id (via `SpanContext` with `is_remote=True`)
  AND a `fabric.judge.target_decision_id` attribute pointing at the
  original decision's span_id. The two spans share a trace_id so any
  backend's trace view groups them; the explicit link attribute lets
  customers query "find verdicts for this decision."

The L1 OSS provides `fabric.judge.attach_to_trace(trace_id, span_id)`
helper that yields a properly-configured `Decision`-like context for
out-of-process workers. Implementation uses OTel's
`NonRecordingSpan` + a real child span pattern.

Optional Pub/Sub fan-out (the collector republishing queued events to
Kafka / SQS / Pub/Sub) is **L2 Commercial** infrastructure; the L1 OSS
ships only the event schema and the helper.

### 4.6 Sampling integration

`fabricsampler` should always keep `event_class=decision_summary` events
for decisions with a `fabric.judge.queued` or `fabric.judge.verdict`
event attached. Update default rates accordingly.

## 5. Work breakdown

| # | PR | Effort | Depends on |
|---|---|---|---|
| 1 | `Decision.queue_judge()` + `JudgeQueuedRecord` + tests | 2-3 days | none |
| 2 | `Decision.record_eval()` + `JudgeVerdictRecord` + tests | 2 days | #1 |
| 3 | Trace-context propagation utility for workers (open a Decision from an existing trace_id) | 2-3 days | #1 |
| 4 | `fabric.judge.simple.SimpleJudge` reference implementation | 3-5 days | #1, #2 |
| 5 | Documentation: L1 OSS → L2 worker contract, custom worker recipe, simple-judge tutorial | 2 days | all |
| 6 | Update `fabricsampler` defaults to retain judge-related events | 1 day | #1, #2 |
| 7 | Integration test: queue_judge → simple-judge in-process worker → record_eval → verify both events in trace | 2 days | #4 |

**Total: ~2-3 weeks.**

## 6. Acceptance criteria

- A decision instrumented with `decision.queue_judge(...)` emits a
  `fabric.judge.queued` event on its span with the full attribute set.
- An external process holding the queued event's trace_id can call
  `fabric.judge.attach_to_trace(trace_id).record_eval(...)` and the
  verdict appears as a `fabric.judge.verdict` event on the same span.
- `SimpleJudge` runs end-to-end: queue → judge → verdict → both events
  visible in Phoenix.
- L2 Commercial design partners (when they exist) can implement their
  worker against this contract without needing changes to L1.
- Spec 006 (LLM-as-Judge) updated to reference this as the L1 OSS hook
  layer.

## 7. Open questions

1. **Synchronous vs asynchronous SimpleJudge default.** Sync is simpler;
   async lets the turn return before judgement completes. I lean
   async-by-default with a `blocking=True` opt-in for tests.
2. **Should `SimpleJudge` ship with prompt rubrics or just take them as
   strings?** Strings only in OSS. Rubric library is Commercial content.
3. **Worker authentication.** When L2 Commercial workers write back to
   a customer's trace backend, do we use the customer's OTel credentials
   or a separate writer identity? This is more an L2 design decision but
   affects the L1 event schema slightly. Defer to L2 spec.
4. **Backpressure.** If queued events outpace worker capacity, what
   happens? In L1 OSS: nothing — events are emitted, workers may drop.
   L2 Commercial handles backpressure. Document this.

## 8. Related work

- SPEC 006 (LLM-as-Judge) — this spec is the L1 OSS hook layer; SPEC 006
  describes the L2 Commercial judge architecture
- SPEC 007 (escalation) — `request_escalation` is the human-in-the-loop
  cousin of `queue_judge` (a human reviews vs an LLM judges)
- SPEC 013 §"Async LLM judge primitive" — references this spec for the
  primitive contract
