# Governed content capture — gap assessment and requirements matrix

Evidence basis: checkout at `d397fc2` (branch `feat/governed-content`),
verified 2026-09-22 against the implementation brief
[`governed-content-implementation-brief.md`](governed-content-implementation-brief.md).

This document is the Phase 1 gap assessment required by the brief. It maps
every existing foundation to its file/function evidence, states the gap, and
cross-references the specification that closes it (specs 028, 029, 032–034;
numbers 030/031 are the auditd/eBPF host specs). Every claim below names a
file and, where useful, a function or line range.

## Numbering

The next unused spec numbers are 028 and 029 (013–018 and 024 are reserved;
030 and 031 are the host-observation specs). The five governed-content specs
take **028, 029, 032, 033, 034**. All are `Status: draft` — acceptance follows
the 7-day lazy-consensus rule in `GOVERNANCE.md`; nothing in this change marks
a proposal accepted.

## A. Verified current state vs. required state

| Area | Existing foundation (evidence) | Gap | Spec |
|---|---|---|---|
| Trace capture | `sdk/python/src/fabric/decision.py` — `Decision.llm_call` (L1848), `tool_call` (L1972), `record_retrieval` (L793), `remember`/`recall` (L877/972), `record_side_effect` (L1119), `record_interaction` (L1365); `_calls.py` — `LLMCall`/`ToolCall` child spans | Content objects are not bound to operation/attempt/role anywhere except memory/side-effect; model I/O, retrieval results, tool args/results, context files have no governed path | 028, 029 |
| Protection | `components/.../fabricguardprocessor/allowlist.go` — `TraceAllowedFields` admits `fabric.content.ref`, `fabric.content.request_ref`, `fabric.content.result_ref` (L94); `sensitiveAttributeKey` (L200) denies content-shaped keys | `fabric.content.manifest_ref` is not admitted; no allowlist key carries the per-decision manifest locator | 029, 034 |
| Python content storage | `content_store/base.py` (`ContentStore` protocol, `ContentRef`, `content_hash`), `local.py`, `s3.py` | `put` is synchronous and on the caller path; no tenant namespace, no atomicity, no pre-existing-object validation, no overwrite/corruption checks, no storage policy | 032, 033 |
| Python content wiring | `Decision._store_content_ref` (decision.py L769) — called by `remember` (L916), `recall` (L1001), `record_side_effect` (L1166-1169) | Model request/response, tool call arguments/results, retrieval query/results, explicit context files are not wired; failures only warn and drop the ref with no completeness marker | 028, 032 |
| Raw content options | `capture_content` on `llm_call`/`tool_call`/`remember`/`recall`/`record_retrieval` writes raw values onto `gen_ai.*` span attributes (`_calls.py` L456-466, L988/L1002; `decision.py` L862-872, L965-969, L1042-1047); `FABRIC_CAPTURE_LLM_CONTENT` env (`auto_instrument.py`) | Raw span emission is stripped by Fabric Node and is not governed evidence; compatibility with governed mode is undefined | 028 |
| TypeScript | `sdk/typescript/src/{client,decision,calls}.ts` — `captureContent` flags, `remember`/`recall`/`recordSideEffect` hash-only | No `ContentStore`, no governed storage, no writer lifecycle, no resolver — entire surface missing | 028, 032, 033 |
| Store behavior | `ContentStore.put` synchronous; `LocalFilesystemContentStore.put` writes `{root}/{hash[:2]}/{hash}` (local.py L24-37); failure path warns and omits ref (`decision.py` L783-789) | No bounded async path, no durability boundary statement, no retry, no spool, no gap reporting — an agent call blocks on object-store latency today | 032 |
| Local/S3 adapters | `local.py` (write-once, `exists()` skip), `s3.py` (`put_object` to `{prefix}{digest}`) | Local write is not atomic (no tmp+rename), pre-existing objects are trusted by name, no mode/perm enforcement; S3 has no tenant namespace, no conditional write, no read-back verification | 033 |
| Consumer access | Ref URIs admitted by the collector allowlist; nothing resolves them | No resolver, no integrity verification on read, no namespace/authorization enforcement, no transcript reconstruction or export | 033, 034 |
| Contracts/config | `contracts/recorder/v1/schema.json` — `spec.content.mode` enum already spells `metadata`, `hash`, `governed-reference` (L45); `contracts/activity/v1` goldens include `content_ref_stamped.json` | `governed-reference` has no runtime semantics behind it; no content-object or manifest schemas exist | 028, 029 |
| Packaging gates | `sdk/python/scripts/qualify_recorder_wheel.py` (forbidden members/symbols/extras; no console entry points); `sdk/typescript` `npm run package:qualified`; `scripts/tests/test_recorder_release_boundary.py` | New modules must not trip forbidden lists; new APIs need explicit shipped-proof additions; governed-content examples must stay outside recorder artifacts | 034 |

## B. Design decisions taken in the specs

| Decision | Choice | Rationale |
|---|---|---|
| Writer architecture | In-SDK per-language writer (no new runtime) | A customer-side writer service would be a new mandatory deployable for metadata-only users; the SDK is already inside the trust boundary |
| Config spelling | `governed` content mode = `spec.content.mode: governed-reference` (existing contract vocabulary) | Aligns with `contracts/recorder/v1/schema.json` instead of inventing a new spelling |
| Legacy `content_store=` | Preserved as `durability=inline` + the legacy role set (memory, side-effect) | Byte-identical behavior for existing users; no silent semantic change |
| Ref URI form | Store-native URIs (`file://`, `s3://`) inside configured namespaces; never credentials/signed URLs on telemetry | Keeps the existing admitted attribute shape; resolver constrains to configured stores |
| Completeness | Per-decision manifest object in the store + `fabric.content.manifest_ref` on the decision span | One resolvable index of expected vs. actual objects; missing content can never look like empty input |
| Binary/multimodal | `unsupported` marker in v1; text/JSON only | Explicit deferral per brief §A |

## C. Requirements-to-test matrix

| Requirement (spec §) | Test evidence target |
|---|---|
| Metadata-only default writes no objects (028 §Modes) | `tests/test_governed_content.py`: default client produces no refs/manifest; span bytes unchanged |
| Governed mode requires store + policy (028) | config validation tests: governed without store fails |
| Role coverage: model req/resp, tool args/results, retrieval, memory, side-effect, context, interaction (028) | per-role capture tests + coverage-matrix doc test |
| Inline/process/spooled durability semantics (032) | writer unit tests; crash-recovery test re-scanning spool dir; enqueue-full → `dropped` status test |
| Bounded resources (032) | queue-capacity test; payload-max truncation test; enqueue-time bound test |
| Exact-byte hashing parity (029) | shared fixture files hashed in both languages (`tests/fixtures/content-bytes/*`) |
| Empty vs absent, Unicode, streaming assembly (029) | fixture + unit tests in both SDKs |
| Manifest ordered refs + statuses (029) | manifest schema validation against `contracts/content/v1` schema; incomplete-transcript golden |
| Two-destination consistency (032) | ref-before-object resolves `pending`; manifest statuses settle |
| Local atomic write + pre-existing validation (033) | corrupted pre-existing object test; crash-during-write test |
| Tenant isolation, traversal, unapproved host (033) | resolver negative tests |
| Digest verify on read (033) | corrupted-bytes test fails verification |
| Retention/deletion semantics (033) | expired ref resolves explicit status |
| Export consumable without proprietary service (034) | `examples/governed-content/` consumer runs deterministic assertion |
| Offline harness path without Fabric Node (034) | `examples/offline-transcript/` runs with local store only |
| Real collector end-to-end (034) | compose harness test: refs cross, raw values absent from OTLP/logs/queue |
| No eval/control code in artifacts (034) | extended `qualify_recorder_wheel.py` + `package:qualified` checks |
| Store outage/crash/restart/disk-full behavior (032) | documented-status tests; no silent drop while claiming complete |

## D. Product-boundary reconciliation

- `AGENTS.md` scope is **CAPTURE -> PROTECT -> DELIVER**. Governed content
  capture extends *capture*: the SDK writes content objects to
  customer-controlled storage and stamps references; nothing content-shaped
  enters OTLP or crosses the boundary. The recorder does not evaluate, judge,
  or enforce — spec 034 keeps external-evaluator support at the
  contract/export layer.
- Spec 027 `Protect` already anticipates this: "deny raw prompts ... **unless
  a later explicit governed mode is configured**" (027 §Protect). These specs
  define that mode without changing the default.
- The internal product-direction document was located:
  `docs/governed-content-implementation-brief.md` (this task's brief). No
  unresolved product conflict remains; the three-mode positioning
  (metadata-only default, governed content, harness-owned offline
  transcripts) is adopted verbatim in spec 028 and
  `docs/capturing-interactions.md`.
