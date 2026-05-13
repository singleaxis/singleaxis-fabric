# OSS Implementation Plan — v0.3 / v0.4 / v0.5

**Status:** draft, working doc
**Last updated:** 2026-05-13
**Audience:** anyone executing on Fabric OSS

This document sequences specs 012–018 into a release plan. Each spec
has its own design; this doc only answers "what ships in which release,
in what order, with what dependencies."

## v0.3.0 — "claims match reality" (target: 4-6 weeks)

The shipping goal: a customer can `helm install fabric` from GHCR and
get a working Level 1 audit stack. Every bug from the 2026-05-12
validation is fixed. Every artifact the umbrella chart references is
published.

### What ships in v0.3.0

| Spec | What lands |
|---|---|
| [012](012-pii-redaction.md) — PII | Real PresidioAnalyzer wired (§4.2), tag-mode default (§4.1), regex pre-filter (§4.3), recognizer config (§4.4), cold-start fix (§4.5), Helm chart (§4.6) |
| [013](013-guardrails.md) — Guardrails | NeMo image published, per-pod-sidecar mode (§4.2). Lakera/PromptGuard adapters defer to v0.4. |
| [014](014-red-teaming.md) — Red-team | Dockerfile fixed (§4.1), image published, OTel span emission (§4.2), CronJob chart (§4.3) |
| [015](015-judge-hooks.md) — Judge hooks | `queue_judge()` + `record_eval()` primitives (§4.2, §4.3). SimpleJudge defers to v0.4. |
| [016](016-foundational-fixes.md) — Foundational fixes | All six defects fixed |
| [017](017-publishing-pipeline.md) — Publishing | All 5 sidecar images + umbrella chart published. E2E CI workflow runs on every PR. |

### v0.3.0 critical path

```
Week 1: SPEC 016 foundational fixes land in parallel (six small PRs)
        SPEC 012 #1 Presidio analyzer wire
        SPEC 014 #1 Redteam Dockerfile fix
        SPEC 017 #1 Begin extending release.yml for sidecar matrix

Week 2: SPEC 012 #2-#5 (tag mode, regex pre-filter, recognizer config, warmup)
        SPEC 013 #2 NeMo per-pod-sidecar chart mode
        SPEC 015 #1-#2 queue_judge + record_eval primitives
        SPEC 017 #3 E2E scripts authored

Week 3: SPEC 012 #6-#8 (chart + docs + tests)
        SPEC 014 #2-#3 (OTel span emission + chart updates)
        SPEC 017 #2 Umbrella chart publish
        SPEC 017 #4 E2E workflow wired

Week 4: SPEC 017 #6 Tag v0.3.0-rc.1, verify everything publishes
        Burn-in: 3-5 days running E2E against rc.1
        Documentation: README, quickstart, CHANGELOG honest about scope

Week 5: Tag v0.3.0
        Re-validate end-to-end against published artifacts (not local)
        Honest blog post / release notes
```

Total: ~5 weeks at solo founder pace (60% allocation). Compresses to
2-3 weeks with help.

## v0.4.0 — "competitive parity" (target: 6-8 weeks after v0.3)

Goal: a senior engineer evaluating Fabric prefers it over wiring
Phoenix + Presidio + NeMo + garak themselves. Latency competitive,
ergonomics smooth, integrations rich.

### What ships in v0.4.0

| Spec | What lands |
|---|---|
| 012 — PII | (already shipped in v0.3) |
| [013](013-guardrails.md) — Guardrails | Tiered chain (§4.1), Lakera adapter (§4.3), Llama Prompt Guard sidecar (§4.4), generic HTTP adapter (§4.5), tool-call authorization (§4.6) |
| [015](015-judge-hooks.md) — Judge hooks | SimpleJudge reference (§4.4), trace-context propagation utility (§4.5) |
| [018](018-modern-agent-primitives.md) — Modern primitives | Rich tool tracking (§4.2), Fabric MCP adapter (§4.1 Path B), recall primitive (§4.4) |

### Strategic v0.4 decisions

Before v0.4 work starts:

1. **Default `score_threshold` for Presidio** (open in 012 §7.1).
   Recommendation: 0.4.
2. **`Fabric(FabricConfig(...))` env-var detection** (open in 016 §7.1).
   Recommendation: warn-only, don't break existing callers.
3. **Generic vs dedicated adapters in 013** (open in 013 §7.1).
   Recommendation: coexist.
4. **OTel GenAI working group proposal for MCP** (018 §4.1 Path A).
   Recommendation: write it up in v0.3 timeframe, ship Fabric adapter in
   v0.4 regardless of upstream pace.

## v0.5.0 — "modern agent" (target: 8-12 weeks after v0.4)

Goal: Fabric is the obvious choice for instrumenting an agent using MCP,
multi-agent delegation, long-running tasks, and modern memory backends.

### What ships in v0.5.0

| Spec | What lands |
|---|---|
| [018](018-modern-agent-primitives.md) — Modern primitives | `fabric.task` workflow (§4.3), memory adapters for mem0/Letta/Zep (§4.4), `decision.delegate()` (§4.5), upstream OTel MCP if it landed (§4.1 Path A) |

### v0.5 is more uncertain than v0.3 / v0.4

By the time we get here:

- OTel GenAI conventions for MCP may or may not have landed upstream.
  Either way, ship Fabric's version and align later.
- A2A protocol may have stabilized; if so, add `kind="a2a_protocol"`
  to `decision.delegate()`. If not, skip that mode.
- Memory backends are consolidating fast. Pick the top 2-3 by adoption
  at the time, don't try to cover everything.

This release is the right place to also re-evaluate:

- Whether to keep the Fabric-specific MCP adapter (if OTel upstream now
  covers it, deprecate Fabric's)
- Whether `traceloop-sdk` should be a supported alternative SDK
  alongside Fabric (interop, not competition)
- Whether v1.0 is the right next call after v0.5

## Cross-release coordination

### Dependencies between specs

```
SPEC 016 (foundational fixes)
    ↓ unblocks
SPEC 012 (PII), SPEC 013 (guardrails), SPEC 014 (redteam)
    ↓ all feed
SPEC 017 (publishing) — needs the artifacts to publish
    ↓ enables
v0.3.0 release

SPEC 012 #2 (tag mode)
    ↓ unblocks
SPEC 013 §4.1 (tiered chain) — uses tag-mode as tier 1

SPEC 015 (judge hooks)
    ↓ contract for
SPEC 013 §4.7 (async judge primitive) — same contract
L2 Commercial Judge Worker — implements the worker side
```

### Decisions only the founder can make

A summary of all "open questions" across specs that need a product call
before implementation:

- **012 §7.1** Default Presidio score_threshold (0.4 / 0.5 / 0.6)
- **012 §7.2** Backward-compat mode for v0.3 SDK → v0.2 sidecar (error / silent fallback / warn-and-fallback)
- **012 §7.3** Regex pre-filter — fixed vs configurable in v0.3
- **012 §7.4** Sidecar warmup blocks readiness or fires async
- **013 §7.1** Dedicated adapters or generic-only
- **013 §7.2** Tool-call auth via OPA or callable-only in v0.3
- **014 §7.1** Single-image vs separate-image redteam
- **014 §7.2** Default redteam suite scope
- **014 §7.4** Finding snippets vs hashes by default
- **015 §7.1** SimpleJudge sync vs async default
- **016 §7.1** Constructor env-detection warn or fail-loud
- **016 §7.2** PII warnings on `*_name` fields or only `*_id`
- **017 §7.1** Self-hosted runner vs hosted with secret
- **017 §7.3** E2E on every PR or only on main + tags
- **018 §7.3** Memory adapter auto-monkeypatch or explicit opt-in

Each is a small call individually. Collectively they shape the v0.3 / v0.4
experience for customers. Better to decide upfront than to relitigate
mid-implementation.

## What this plan deliberately drops

Things you might expect to see here but won't:

- **A v1.0 plan.** Not yet. Get v0.3-v0.5 right; the path to v1.0
  becomes clearer after.
- **JS / Go SDK plans.** Defer until customer demand is clear.
- **Multi-modal (image / audio / video) instrumentation.** OTel GenAI
  conventions for multi-modal are still moving upstream; revisit in
  v0.5+.
- **A separate "performance optimization" track.** Performance is
  rolled into each spec (regex pre-filter, warmup, tiered chain).
  No dedicated perf release.
- **Anything Commercial-side.** This document is OSS-only. See the
  internal product-strategy doc for the Commercial roadmap.

## Working agreements while executing this plan

Recommended (these are working agreements, not strict rules):

- **One spec per release.** Don't try to land partial work across two
  specs in the same release; ship complete spec implementations.
- **Small PRs.** Each spec's work-breakdown rows are sized to be one
  PR each. Resist bundling.
- **Tag often, ship often.** v0.3.0-rc.1, rc.2, rc.3 if needed before
  v0.3.0. Catch issues in rc burn-in, not after release.
- **Tests in the same PR as the change.** No "tests follow."
- **Update the spec status when implementation lands** — draft →
  accepted → implemented. Catches drift between spec and code.

## Tracking progress

Each spec is a GitHub Project board column. Each PR closes a row of
the spec's work-breakdown. When all rows of a spec are closed:

1. Update the spec's `status` from `draft` (or `accepted`) to
   `implemented`
2. Cross-reference the PRs in the spec's "Implementation notes"
   section (add one if not present)
3. Move the spec card to the "Done" column on the project board

This makes spec-status the single source of truth for what's done.
