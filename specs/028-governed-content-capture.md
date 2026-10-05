---
title: Governed content capture and configuration
status: draft
revision: 2
last_updated: 2026-09-23
owner: product-architecture
depends_on: 027
related: 029, 032, 033, 034
---

# 028 — Governed content capture and configuration

## Product promise

Recorder v1 exports metadata only (spec 027). This spec defines the explicit,
opt-in extension anticipated there: when a customer configures it, the SDK
also writes the **actual observable content** — model inputs and outputs,
tool payloads, retrieval results, supplied context — to **customer-controlled
storage**, and stamps resolvable references on the trace stream.

The pipeline is unchanged:

```text
CAPTURE -> PROTECT -> DELIVER
        + governed content -> customer storage (off-wire)
```

- Content objects never enter OTLP, never cross the customer boundary as
  telemetry, and never reach a SingleAxis service through Fabric.
- The trace stream carries references and digests only; the collector
  allowlist is unchanged in kind.
- Nothing here is an evaluation service, judge, policy engine, or runtime
  control. Resolution and export (spec 033/034) are read-side libraries a
  customer or evaluator runs where content is authorized to be read.

## Goals

- Let a customer capture real inputs/outputs/context into storage they own,
  with references an authorized reviewer can resolve and verify.
- Keep metadata-only the zero-configuration default; governed mode requires
  explicit configuration that fails closed when incomplete.
- Define which content roles are captured, at which API surfaces, and what
  is explicitly out of scope.
- Preserve observed-fact discipline: capture what crossed an observable
  boundary; never reconstruct hidden context or reasoning.

## Non-goals

- Prompt-time redaction, PII classification, guardrails, tool authorization,
  or any decision about what the agent *may* do.
- Evaluation, grading, findings, judges, or replay orchestration.
- Binary/multimodal content (images, audio, arbitrary bytes) in v1 — recorded
  as `unsupported`, not silently skipped or mis-stored.
- Universal framework/provider coverage. Only surfaces listed in §4 that the
  caller or adapter actually exposes are captured; absence is a status, not
  a silent gap.

## Capture modes

`spec.content.mode` in the recorder contract (v1) already spells the three
values; this spec gives them runtime semantics:

| Mode | Meaning | Content objects written |
|---|---|---|
| `metadata` | Zero-configuration default. Metadata + hashes + (optionally configured) governed references on legacy surfaces. | None, except the legacy inline refs in §6.2 |
| `hash` | Reserved contract value; identical observable behavior to `metadata` in this release. Alias kept for contract compatibility. | None |
| `governed-reference` | Governed mode. Content objects are written to customer storage; references + manifest are stamped on the record. | Yes, per capture policy |

Configuring `governed-reference` requires all of:

1. a **store**: a configured `ContentStore` (local filesystem or S3-compatible;
   spec 033), including its tenant namespace;
2. a **capture policy**: the set of content roles to capture (`roles`), or
   `all` minus exclusions; and
3. a **durability mode** (spec 032): `inline`, `process`, or `spooled`.

Missing any of these fails configuration — governed mode does not degrade to
a partial capture silently; the operator sees an explicit error at client
construction (SDK) or config validation (contract).

### Contract declaration vs. executable configuration

`spec.content.mode` in the recorder contract is a **declaration**: it tells
the Fabric Node to expect `fabric.content.*` reference attributes on
telemetry from governed SDKs in this deployment. It does not, and cannot,
configure the SDK — store endpoints, spool paths, and durability bounds are
executable settings that live in `ContentCaptureConfig` (Python) /
`contentCapture` (TypeScript) at client construction. A recorder YAML that
says `mode: governed-reference` while no SDK configures governed capture
produces metadata-only telemetry; the declaration never *enables* capture
by itself.

Environment variables follow the same rule in the stricter direction:
`FABRIC_CONTENT_MODE` may only *restrict* (`metadata` force-disables a
configured governed capture); no environment variable can enable governed
mode. Activation is always explicit code.

### Tenant identity

The governed store's `tenant_id`/`tenantId` must **exactly equal** the
`Fabric`/`FabricConfig` client tenant — mismatched store and client tenants
fail at construction, because refs stamped under one tenant resolving into
another namespace is a silent cross-tenant leak. Tenant identifiers must be
safe namespace components per spec 033 §2 (the shared safe-identifier rule);
store adapters validate them at construction.

## Content roles (v1)

Each role names one class of content object. The SDK binds every object to
trace/span, decision, execution, step, attempt, and tool-call identity where
the surface supplies it (binding schema: spec 029).

| Role | Content | Captured at (Python API; TS mirrors) |
|---|---|---|
| `model.request.instructions` | System/developer instructions **as supplied by the caller** | `llm_call(system_instructions=…)` |
| `model.request.messages` | Ordered input messages — the effective request the caller passed | `llm_call(input_messages=…)` |
| `model.request.tool_definitions` | Tool/function definitions offered to the model | `llm_call(tool_definitions=…)` |
| `model.request.parameters` | Scalar request parameters (temperature, top_p/k, max_tokens, stream, output_type, seed if supplied) | `llm_call(...)` |
| `model.output.messages` | Structured output incl. model-issued tool calls; assembled streamed output; partial output on error/cancel | `LLMCall.set_response(output_messages=…)`, `record_partial_output` |
| `tool.call.arguments` | Serialized tool arguments | `ToolCall.set_arguments(payload)` |
| `tool.call.result` | Serialized tool result | `ToolCall.set_result(payload)` |
| `retrieval.query` | The retrieval query text | `record_retrieval(query=…)` |
| `retrieval.results` | Supplied result content, ordered, with document ids/rank where given | `record_retrieval(results=…)` (new param) |
| `memory.write.content` | Memory write content | `remember(content=…)` |
| `memory.read.content` | Memory read content | `recall(content=…)` |
| `side_effect.request` | Side-effect request payload | `record_side_effect(request_payload=…)` |
| `side_effect.result` | Side-effect result payload | `record_side_effect(result_payload=…)` |
| `context.file` | Explicitly supplied file/context (text or JSON in v1) | `Decision.record_context(...)` (new API) |
| `interaction.payload` | Generic interaction payload when the caller supplies raw bytes | `record_interaction(payload=…)` (new optional param) |

Explicit rules:

- **Effective-request evidence only.** `model.request.*` captures what the
  caller supplied to the SDK method. If the provider or framework merges
  hidden system prompts, tools, or context the caller cannot see, that
  hidden context is *not* captured and *not* claimed. The recorded request
  is evidence of what the instrumentation observed, nothing more.
- **Retrieval is not receipt.** A recorded `retrieval.results` object proves
  the caller received and supplied those results. Whether the model actually
  consumed them is evidenced by `model.request.messages` of a later call —
  never inferred.
- **Streaming assembly.** Adapters capturing streamed model output record
  the assembled output, plus `representation: assembled` on the descriptor;
  a failed/cancelled stream produces a `partial` object with the assembled
  prefix, marked `truncated`/`partial` per spec 029 statuses.
- **Payload limits.** Each role has a `payload_max_bytes` bound (default
  1 MiB per object, configurable, hard-capped at 16 MiB). Oversized content
  is stored truncated with `representation: truncated` and the original
  byte length recorded — or marked `dropped` when the role policy says
  `drop`. Truncation never verifies against the full-content digest
  (spec 029).

## Compatibility with `capture_content` / `captureContent`

The existing raw-span flags remain, unchanged in behavior: they place raw
text on `gen_ai.*` span attributes for backends that are *not* behind Fabric
Node protection, and Fabric Node strips them as today. They are **not**
governed evidence storage and are documented as such.

- Governed mode does not imply `capture_content=True`, and vice versa.
- The original proposal allowed both paths together. Current Python governed
  capture instead rejects conflicting raw-span flags and raw-content
  auto-instrumentation environment settings. TypeScript legacy behavior is a
  separate capability boundary; do not infer Python parity or privacy from it.
- Migration note (docs): customers who want *verifiable* content should use
  governed mode; raw span flags remain a dev/debug convenience.

## Consent and configuration scope

- Enabling governed mode is a **deployment-time, per-process decision** —
  `ContentCaptureConfig` on the `Fabric` client (Python/TS), or equivalent
  adapter configuration. There is no remote or per-request enablement and no
  environment-variable shortcut that flips content on accidentally; the only
  env var defined is `FABRIC_CONTENT_MODE` which may *restrict* to
  `metadata` (fail-safe direction) but never enables governed mode on its own.
- The capture policy `roles` set is closed under the table above; unknown
  role names fail configuration.
- Enabling governed mode never widens the OTLP allowlist. It only adds
  reference attributes that are already admitted (`fabric.content.*_ref`)
  plus the new `fabric.content.manifest_ref` (spec 029/034).

## Coverage matrix

Published in `docs/governed-content.md` and enforced by a doc test that walks
the matrix rows:

| Surface | Python manual API | TS manual API | Auto-instrumentation | Adapters |
|---|---|---|---|---|
| `model.request.*` / `model.output.*` | ✔ v1 | ✔ v1 | deferred — adapters see provider spans without caller-supplied payloads; marked `unsupported` until wired | MCP integration: tool args/results ✔ |
| tool.call.* | ✔ | ✔ | — | MCP ✔ |
| retrieval.* | ✔ | ✔ | — | — |
| memory.* | ✔ | ✔ | — | — |
| side_effect.* | ✔ | ✔ | — | — |
| context.file / interaction.payload | ✔ | ✔ | — | — |

Anything not marked ✔ is a documented `unsupported`/`missing` state, never a
silent claim. Auto-instrumentation content capture is **deferred** (it emits
raw `gen_ai.*` attributes, which the governed path does not consume in v1).

## Failure semantics

- Store/write failure never raises into the agent path and never changes
  agent behavior or authorization — capture is passive (spec 032).
- Every failure lands as an explicit manifest status (`failed`, `dropped`,
  `pending`) — a missing object can never masquerade as an empty input or a
  complete transcript.
- Configuration errors (governed mode without store/roles/durability) fail
  closed at construction.

## Acceptance tests

1. Default client emits no content objects, no manifest, byte-identical spans.
2. Governed mode without store/roles/durability → configuration error.
3. Each role in §4 demonstrably produces a bound, verified object, or is
   documented `unsupported`.
4. Python governed capture rejects conflicting raw-span flags; TypeScript
   legacy behavior is qualified separately. Neither widens Node protection.
5. Unknown role names rejected; env var cannot enable governed mode.
6. Coverage matrix doc test passes against implemented surface.

## Rollout

- Specs 028–034 land as `draft`; acceptance per `GOVERNANCE.md` lazy
  consensus. Implementation lands behind the new config on a feature branch;
  no release marks the feature stable until qualification gates in spec 034
  pass.
- Existing users: zero behavior change without `ContentCaptureConfig`.
  `content_store=` keeps working as `inline` + legacy roles (§6.2).
