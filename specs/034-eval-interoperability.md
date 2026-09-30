---
title: External evaluation interoperability and qualification
status: draft
revision: 2
last_updated: 2026-09-23
owner: product-architecture
depends_on: 028, 029, 032, 033
related: 027
---

# 034 — External evaluation interoperability and qualification

Defines how an outside evaluator consumes governed content — the transcript
export format, the runnable examples, and the qualification gates that keep
this honest. Fabric ships *interoperability*, not an evaluation service:
the boundary from `AGENTS.md` and spec 027 is unchanged.

## Positioning

```text
CAPTURE -> PROTECT -> DELIVER          (Fabric OSS — unchanged)
governed content -> customer storage   (this feature — still customer-side)
transcript export -> your evaluator    (interop contract — not a service)
```

- A recording plane is necessary for reliable production review when
  equivalent recording doesn't already exist — it is not sufficient for
  evaluation, and Fabric itself remains optional (a customer's existing
  system may supply any of this).
- Development and offline evaluation need no Fabric: a harness can record
  and read its own local transcripts directly, without a Node, queue, or
  production posture. Offline datasets still carry their own privacy,
  access, and retention duties — local does not mean uncontrolled.
- Metadata-only export supports structural review; governed content enables
  content-level judgment *only where the content is authorized to be read*.
  Verifiability and content visibility coexist via governed references —
  they were never mutually exclusive; they were never the same channel.

## Goals

- A versioned, self-describing JSON/JSONL transcript export that any tool
  can consume without SingleAxis Platform or a Fabric service.
- Runnable examples proving the two sanctioned consumption paths.
- Qualification gates mapped 1:1 onto the brief's release acceptance list.

## Non-goals

- Graders, judges, scores, rubrics, pass@k metrics, replay, red-teaming.
- Deterministic replay claims — the export records what happened; the
  resolver never re-executes tools or side effects.
- A proprietary consumption path. If a consumer can't parse the export with
  `jq` + an HTTP client + filesystem, the contract failed.

## 1. Transcript export — `fabric.transcript-export/v1`

`resolver.export_transcript(manifest_uri)` (and `python -m fabric.resolver
export` / `fabric-content export`) produces:

```json
{
  "schema_version": "fabric.transcript-export/v1",
  "manifest": {"manifest_id": "…", "decision_id": "…", "trace_id": "…",
               "tenant_id": "…", "agent_id": "…", "producer": {"…": "…"},
               "started_at": "…", "closed_at": "…"},
  "steps": [
    {"sequence": 0, "kind": "llm_call", "span_id": "s-llm1",
     "entries": [
       {"sequence": 0, "role": "model.request.instructions",
        "status": "available", "ref": "s3://…", "digest": "sha256:…",
        "text": "You are a support agent…"},
       {"sequence": 1, "role": "model.request.messages",
        "status": "available", "…": "…"},
       {"sequence": 4, "role": "model.output.messages",
        "status": "available", "…": "…"}
     ]},
    {"sequence": 1, "kind": "tool_call", "span_id": "s-tool1",
     "tool_call_id": "call_9",
     "entries": [
       {"sequence": 2, "role": "tool.call.arguments",
        "status": "available", "…": "…"},
       {"sequence": 3, "role": "tool.call.result",
        "status": "available", "…": "…"}
     ]}
  ],
  "completeness": {"stored": 7, "pending": 0, "dropped": 0, "failed": 0},
  "integrity": {"verified": true, "objects_checked": 7, "failures": []}
}
```

Rules:

- **`entries` is an ordered array, not a role-keyed object.** Every
  manifest item appears exactly once, in manifest `sequence` order,
  carrying its own `role`, `sequence`, and `status`. A role-keyed object
  silently overwrites repeated roles — multiple `model.output.messages`
  chunks, retried tool attempts, repeated retrieval or context items —
  and is forbidden.
- Role filtering stays convenient: consumers select `entries` by `role`
  (e.g. `jq '.steps[].entries[] | select(.role=="tool.call.result")'`);
  multiplicity and order survive the filter.
- Items resolve through the configured resolver (spec 033). Unresolved or
  `denied` items appear with their status — never silently dropped from
  the export and never replaced with empty text.
- `integrity.verified` is the conjunction of per-object digest checks;
  failures are enumerated. An export with `verified: false` is still
  produced and marked — consumers decide policy.
- Text objects inline as `text` (JSON objects inline as parsed JSON under
  `text` when the consumer asks for materialized form, or stay as refs
  with `--refs-only`). Size bounds apply to materialization
  (`export_max_bytes`, default 64 MiB, refused beyond).
- Ordering follows manifest `sequence`; the export never invents causal
  order from timestamps. `status_reason` (including `partial*` reasons)
  is preserved verbatim on each entry.

## 2. Required examples (outside recorder artifacts)

| Example | Path | Proves |
|---|---|---|
| Governed content end-to-end | `examples/governed-content/` | SDK → local store → manifest → resolve → export → a deterministic consumer assertion (e.g. "the model's second request contained the tool result"); no Fabric Node required for the content path |
| Offline harness transcript | `examples/offline-transcript/` | A harness records + reads its own transcript via SDK + local store only — no collector, queue, or production posture; documents that offline datasets still need privacy/retention controls |
| Collector integration | `deploy/compose` governed overlay / test | Same flow through the real Fabric Node: refs + manifest_ref cross, raw values absent from OTLP, collector logs, and the queue |

The deterministic consumer is deliberately small (stdlib JSON + the
resolver): it demonstrates *access and integrity*, not grading. The docs
state plainly that content enables richer evaluation but establishes no
correctness — rubrics, expected outcomes, and evaluator design remain the
customer's.

## 3. Collector integration

- One new allowlist key: `fabric.content.manifest_ref` (decision span).
  Traces/logs pipelines otherwise unchanged; raw content still cannot
  cross (the sensitive-name cascade is untouched).
- Qualification test additions: a fixture trace carrying governed refs +
  manifest_ref passes through the compose harness with refs intact and no
  content-shaped bytes in the exported OTLP, collector logs, or queue
  storage.

## 4. Packaging and boundary gates

- `qualify_recorder_wheel.py`: new modules ship (`fabric.content.*`,
  `fabric.resolver`, `fabric._content_writer`, …); no console entry point
  (Python CLI is `python -m fabric.resolver`); forbidden lists unchanged.
- `npm run package:qualified` (TS): equivalent shipped-API check for the
  TS content store/resolver surface.
- Examples stay outside `dist/`, chart, and image; a packaging test asserts
  no eval/judge/enforcement strings or modules appear in artifacts.
- Optional deps stay optional: `boto3` (Python) and `@aws-sdk/client-s3`
  (TS) are extras/peer-optional; metadata-only installs carry no cloud SDK.

## 5. Qualification matrix (brief gate → evidence)

| # | Gate | Evidence |
|---|---|---|
| 1 | Metadata-only writes no objects | SDK unit test + compose diff |
| 2 | Model→tool→model: authorized consumer retrieves instructions/messages/output/tool args+result, byte-verified, attempt-linked | `examples/governed-content` assertion test |
| 3 | Same flow through real Node: refs cross; raw absent from OTLP/logs/queue | compose qualification script |
| 4 | Py + TS pass shared byte/hash fixtures (Unicode, structured output, retries, empty, partial streams) | `contracts/content/v1/fixtures/bytes` tests in both repos |
| 5 | Every capture surface demonstrated or marked unsupported | coverage-matrix doc test |
| 6 | Mutation-after-capture unchanged; concurrent calls distinguishable | snapshot test + concurrent-decision manifest test |
| 7 | Outage/crash/restart/queue-full/disk-full/shutdown → documented statuses; crash tests distinguish in-memory loss vs durable ack | writer + spool test suite |
| 8 | Ref-before-object → pending; failure/deletion → explicit; dup writes + corrupted pre-existing tested | resolver + local-store tests |
| 9 | Unauthorized/cross-tenant/malicious refs fail; corrupted bytes fail; retention/deletion demonstrable | resolver negative tests |
| 10 | External consumer evaluates export without proprietary service; offline harness without Fabric | example consumer tests |
| 11 | Artifacts pass boundary + governed-content qualification; production S3 tested separately from mocks; env-dependent gates listed | packaging + integration results table |
| 12 | Docs state overhead, durability limits, adapters, security duties; no overclaim | docs review + scope test |

## 6. Honest-capability documentation

`docs/governed-content.md` must state: per-call serialization + hashing CPU
cost and the enqueue bound; the `process`-mode loss window and the spool
guarantee boundary; which adapters are wired (coverage matrix); that
storage encryption/retention/IAM are customer settings; that content
capture does not prove correctness; that no hidden reasoning or unseen
provider context is captured; and that "immutable evidence" requires
customer-side object-lock/WORM the SDK does not provide.

## 7. Rollout

- Drafts → lazy consensus → implementation on `feat/governed-content`.
- Feature lands disabled by default; a release marks it only after the
  matrix above is green and `docs/recorder-v1-qualification-status.md` is
  updated to reflect governed-content gates.
