---
title: Generic Interaction Capture
status: draft
revision: 1
last_updated: 2026-06-10
owner: project-lead
---

# Spec 023 — Generic Interaction Capture

**Status:** proposed (v0.7 target, builds on spec 022)
**Goal:** make the OSS layer the **best generic product on the market for
capturing *every* interaction an agentic system has** — not a fixed list of
known surfaces, but a universal, extensible capture model with generic
baseline / tagging / signature primitives that apply to *any* interaction,
plus a coverage loop that tells you what you're not yet capturing.

## Design principle: generic, not particular

The mistake to avoid: MCP-specific baseline, OWASP-only tagging, skill-only
signatures. Everything here is **cross-cutting and surface-agnostic**:

- One universal capture primitive (`record_interaction`) logs *any* interaction
  type — including ones we never anticipated.
- The specific primitives (llm_call, tool_call, mcp, skill, delegation, hook,
  file…) are **specializations** of the same shape.
- Baseline, tagging, and signature verification are **generic capabilities**
  usable on *any* interaction, supplied as data/parameters — never hardcoded to
  one surface or one taxonomy.

Invariant (unchanged from spec 002 / 022): **metadata + hashes on the span,
never raw data.** All additions are **additive** — the 31 + 5 conformance
goldens must stay byte-identical; add new goldens for new behavior.

## 1. Universal interaction primitive

```python
d.record_interaction(
    kind,                  # free-form namespaced str: "http.request", "db.query",
                           #   "queue.publish", "shell.exec", "browser.navigate", ...
    target,                # what it touched: URL / host / table / path / topic
    *,
    direction=None,        # "inbound" | "outbound" | "internal" | None
    payload_hash=None,     # hash of the payload (raw payload NEVER on span)
    metadata=None,         # dict of allowlisted scalar metadata (hashed if sensitive)
    tags=None,             # see §3 — generic taxonomy tags
    baseline=None,         # see §2 — generic baseline check name
    signature=None,        # see §4 — generic signature verification input
)
```

- Emits `fabric.interaction` event with `fabric.interaction.kind`, `.target`,
  `.direction`, `.payload_hash`, plus tags/baseline/signature results (below).
- Rolling `fabric.interaction_count` + `fabric.interaction_kinds` (tuple) on the
  decision span.
- This is the **completeness guarantee**: any interaction a host can name is
  capturable today, without waiting for a first-class method.

## 2. Generic baseline comparison (any hashed thing)

A surface-agnostic "is this what we approved?" mechanism — works for MCP tool
sets, skill manifests, allowed endpoints, file paths, prompt templates, *or
anything else you can hash*.

```python
bl = fabric.Baseline.load(path_or_dict)   # name -> approved_hash (signed file ok)
status = bl.check(name, observed_hash)    # "match" | "deviation" | "unknown"
```

- When `baseline=` is passed to any `record_*` / `record_interaction`, the event
  carries `fabric.baseline.name`, `fabric.baseline.status`
  (`match`/`deviation`/`unknown`).
- Distinct from spec-022 *drift* (session-to-session change): baseline is
  *deviation from an approved set*. Both are useful; baseline is the one the
  security best-practice literature asks for.

## 3. Generic taxonomy tagging (any framework, extensible)

Tags are **data, not hardcoded logic**. Any event can carry namespaced tags;
reference taxonomies ship as loadable data, never special-cased.

```python
tags = ["atlas:AML.T0051", "owasp-llm:LLM01", "myco:risk-high"]   # arbitrary
```

- Captured as `fabric.tags` (tuple[str]). Format `namespace:code`.
- Ship reference taxonomy *data* files (`taxonomies/mitre-atlas.json`,
  `taxonomies/owasp-llm.json`) + a generic `fabric.taxonomy` helper that
  validates/looks-up a tag against any loaded taxonomy — but **arbitrary tags
  are always allowed** (open vocabulary). Adding a new framework = drop in a
  JSON file, zero code change.

## 4. Generic signature verification (any artifact)

Surface-agnostic verification — verify a signature over *any* artifact hash
(tool manifest, skill bundle, policy bundle, MCP server identity, anything).

```python
result = fabric.verify_signature(artifact_hash, signature, public_key, scheme="ed25519")
```

- Schemes: `ed25519` (default), `hmac-sha256`, extensible.
- When `signature=` is passed to a `record_*`, the event carries
  `fabric.signature.verified` (bool), `fabric.signature.scheme`,
  `fabric.signature.key_id`. Verification is done locally; keys are caller-supplied.

## 5. The improvement loop (coverage signal)

The product self-reports what it is *not* yet capturing first-class, so coverage
converges toward "everything":

- Fabric tracks the set of `kind`s seen via the generic `record_interaction`
  path (i.e. NOT one of the first-class specializations). The first time a new
  generic `kind` appears in a process, emit a one-shot `fabric.coverage` event:
  `fabric.coverage.kind`, `fabric.coverage.suggestion="generic"` — a signal that
  "interaction type X is being captured generically; consider first-class
  support / a baseline / tags."
- Also surface, as the same low-rate signal: a `kind` seen with
  `baseline.status="deviation"` and no tags (an unclassified anomaly).
- This is a *signal*, not analysis/ML. The analysis (clustering, risk scoring,
  auto-baselining) is Commercial.

## Relationship to existing primitives

- `llm_call` / `tool_call` / `record_retrieval` / `remember` / `record_side_effect`
  / `record_skill` / `delegate` / `record_hook` / `record_file_access` / MCP
  inventory all **gain optional `tags=` / `baseline=` / `signature=`** kwargs
  (cross-cutting), and conceptually emit the universal shape. Existing calls
  without these kwargs stay byte-identical (additive).

## Out of scope (Commercial / later)

- Content scanning for poison patterns; risk scoring; auto-baseline learning;
  enforcement/blocking; cross-decision correlation; the threat dashboards.
- These consume the generic OSS signals. OSS = generic capture; Commercial =
  analysis + enforcement.

## Acceptance

- `record_interaction` + generic Baseline + generic tags + generic
  `verify_signature` + coverage signal, all surface-agnostic.
- Cross-cutting `tags/baseline/signature` kwargs on existing primitives.
- 31 + 5 existing goldens byte-identical; new goldens for the generic events.
- mypy strict, ruff, full suite green, ≥85% coverage.
- Verified end-to-end with a real LLM + real MCP, exercising the generic path
  on a never-before-seen interaction kind (e.g. `http.request`).
