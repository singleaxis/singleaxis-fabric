---
title: Content object and transcript manifest contracts
status: draft
revision: 2
last_updated: 2026-09-23
owner: product-architecture
depends_on: 028
related: 032, 033, 034
---

# 029 — Content object and transcript manifest contracts

This spec defines the versioned schemas every governed-content implementation
serializes identically: the content-object descriptor, the per-decision
transcript manifest, and the exact-byte hashing rules. Canonical schemas live
under `contracts/content/v1/`; this spec is the design of record.

## Goals

- One immutable descriptor per stored content object, self-describing enough
  for an offline auditor.
- A per-decision manifest that orders references and marks every expected
  item's state — so missing content can never look like empty input or a
  complete transcript.
- Byte-exact, cross-language hashing: identical input yields identical bytes
  and digest in Python and TypeScript.

## Non-goals

- A generic object-store format for arbitrary binary payloads (v1 is text /
  JSON only; spec 028 §roles).
- Semantic understanding of content (roles label *where* content came from,
  not what it means).
- Cross-store atomicity claims (spec 032 defines the actual guarantee).

## 1. Content object descriptor — `fabric.content-object/v1`

Every stored object has a JSON descriptor with these fields (canonical schema
`contracts/content/v1/schema/content-object-v1.schema.json`):

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | `"fabric.content-object/v1"` | Schema id |
| `object_id` | string (uuid4) | Opaque object identity; unique per object, never the digest |
| `tenant_id` | string | Owning tenant namespace (storage isolation scope) |
| `role` | enum | One of the spec-028 roles |
| `media_type` | string | `application/json` or `text/plain` in v1 |
| `encoding` | `"utf-8"` | Byte encoding of stored content |
| `byte_length` | int | Bytes actually stored |
| `digest` | `sha256:<hex>` | SHA-256 over **stored** bytes |
| `captured_at` | RFC 3339 UTC | Source-side capture time (not storage ack) |
| `representation` | enum: `captured`, `canonicalized`, `assembled`, `truncated` | How stored bytes relate to source |
| `original_byte_length` | int, optional | Source size when `representation=truncated` |
| `source` | enum: `caller`, `adapter` | Provenance: supplied by caller vs observed by adapter |
| `status` | enum, see §4 | Lifecycle/completeness state |
| `status_reason` | string, optional | Free text for `failed`/`dropped`/`unsupported` |
| `bindings` | object | Correlation ids, all optional except where noted |

`bindings` fields (each present only when the surface supplies it):
`trace_id`, `span_id`, `decision_id`, `execution_id`, `session_id`,
`request_id`, `step_type`, `step_id`, `step_attempt_id`, `step_attempt`,
`tool_call_id`, `parent_tool_call_id`, `related_object_ids` (e.g. output
messages listing the tool-call object ids the model requested).

Objects are immutable once `status` reaches `stored`. A descriptor's digest
covers only the stored byte sequence; descriptors travel inside the manifest
and inside the store alongside objects (layout: spec 033).

## 2. Exact bytes and hashing

- **Text content** (`text/plain`): stored bytes are the caller-supplied
  string encoded UTF-8 exactly, no normalization. Surrogates/lone
  characters are encoded with `surrogatepass` semantics where the language
  permits, matching the existing `_sha256_hex` convention; TS encodes
  UTF-8 the same way for all valid strings (invalid input is a caller
  error, not silently munged).
- **Structured content** (`application/json`): stored bytes are the
  **canonical JSON** of the supplied value — UTF-8, no insignificant
  whitespace (`{"a":1,"b":[2]}`, separators `,`/`:`), object keys sorted
  recursively, non-ASCII emitted as literal UTF-8 (no `\uXXXX` escapes),
  numbers serialized by the language's shortest round-trip form.
- The digest always covers the **stored** bytes. When content is
  transformed (canonicalization, truncation), the descriptor's
  `representation` says which bytes the digest covers; a consumer never
  verifies redacted/truncated bytes against an original-content digest.
- **Empty vs absent:** an empty string / `[]` / `{}` is a stored object with
  its true byte length (`0`, `2`, `2`). An absent value produces **no**
  object and a `not_captured` manifest entry — never an empty object.
- **Streaming assembly:** assembled output is stored as the canonical JSON
  of the assembled structure with `representation: assembled`; a partial
  stream stores the assembled prefix with `status` reflecting partiality.
- Fixtures: `contracts/content/v1/fixtures/bytes/*` holds shared byte+hash
  pairs (ASCII, multi-byte UTF-8, emoji/surrogate pairs, nested JSON,
  `""`, `[]`, large-text). Both SDK test suites hash the fixture bytes and
  must produce the fixture digest.

## 3. Transcript manifest — `fabric.transcript-manifest/v1`

One manifest per decision (or per explicitly-scoped transcript). Written to
the same store as a JSON object; the decision span carries
`fabric.content.manifest_ref` pointing at it.

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | `"fabric.transcript-manifest/v1"` | Schema id |
| `manifest_id` | string (uuid4) | Manifest identity |
| `tenant_id`, `agent_id` | string | Producer identity (asserted, not independently verified) |
| `decision_id` | string | Owning decision (required) |
| `trace_id`, `span_id` | string, optional | Owning decision span |
| `execution_id`, `session_id`, `request_id`, `workflow_id` | string, optional | Correlation |
| `started_at`, `closed_at` | RFC 3339 UTC | Decision window |
| `producer` | `{name, version, language}` | SDK identity/version |
| `items` | array of items, **ordered** | See below |
| `completeness` | object | Rollup: counts per status, `dropped_count`, `pending_count`, `failed_count` |
| `coverage` | object | Roles the capture policy enabled vs. actually observed |

Each `items[]` entry:

| Field | Meaning |
|---|---|
| `sequence` | Monotonic emission index on the decision (0-based); **the** ordering guarantee — never timestamp-sorted |
| `role` | Spec-028 role |
| `status` | §4 status |
| `descriptor` | The content-object descriptor — **only** when `status` is `pending`, `stored`, or `truncated` |
| `ref` | Resolution URI — **only** when `status` is `pending`, `stored`, or `truncated` |
| `status_reason` | Optional detail |
| `links` | `{span_id, step_id, step_attempt, tool_call_id, related_object_ids}` |

**Descriptor/ref rule.** An item carries `descriptor` and `ref` exactly when
a resolvable object exists or may still arrive: `pending`, `stored`,
`truncated`. Every other status — `failed`, `dropped`, `not_captured`,
`unsupported`, `redacted` — carries **neither** field: a `failed` or
`dropped` object was never durably written, so a ref would point at
nothing (and would resolve `missing`, misrepresenting a delivery failure
as a retention gap). The item's `role`, `status`, `status_reason`, and
`links` still identify what was attempted. Emitters must strip
`descriptor`/`ref` when an item settles to a non-descriptor status;
validators reject manifests that carry them.

Ordering rules: `sequence` reflects SDK emission order within the decision.
Cross-decision and concurrent-call ordering is *not* flattened: consumers
use `trace_id`/parent links; the manifest preserves `related_object_ids`
edges (model-issued tool call → tool arguments/result objects). Uncorrelated
concurrent events keep independent sequences — no false causal order.

## 4. Status vocabulary and item state machine

**Manifest item statuses** — the closed set the contract validates:

| Status | Kind | Meaning |
|---|---|---|
| `pending` | lifecycle | Reference published; object not yet confirmed stored |
| `stored` | lifecycle | Object durably written per the store's own guarantee (spec 033) |
| `not_captured` | completeness | Role/surface produced nothing, or the capture policy filtered it (e.g. no instructions supplied; role outside policy) |
| `unsupported` | completeness | Role or media type outside v1 scope (e.g. binary input) |
| `truncated` | completeness | Stored prefix only; `original_byte_length` set |
| `dropped` | completeness | Queue/bound shed the item (resource limit) |
| `failed` | lifecycle | Store/retry exhausted (spec 032) |
| `redacted` | completeness | Transformation applied before storage (v1: only via caller marking) |

**Resolution results** — a separate vocabulary returned by the resolver
(spec 033 §3), never written into manifest items: `available`, `pending`,
`missing`, `denied`, `corrupted`, `unverified`. Deleted or expired objects
resolve `missing` (retention is store policy — spec 033 §4); an object that
fails descriptor or digest verification resolves `corrupted`/`unverified`,
never `available`.

**Valid item transitions.** An item is registered once, in emission order,
and settles exactly once:

```text
pending -> stored | truncated | failed
stored | truncated | failed | dropped | not_captured | unsupported | redacted  = terminal
```

`dropped`/`not_captured`/`unsupported`/`redacted` are terminal at capture.
Only `pending` may transition, and only to a terminal lifecycle status.
A settlement that arrives for an unregistered or already-terminal item is
an SDK defect — it must be surfaced (logged/counted), never silently
absorbed.

**Partial and cancelled output.** An interrupted model output is recorded
as `model.output.messages` with `representation: assembled` and a
`status_reason` beginning with `partial` (e.g. `partial_output`,
`partial_output_cancelled`). Stored partial bytes are real evidence —
`status` stays `stored`/`truncated` — but consumers must treat a
`partial*` reason as *not* a complete output: a transcript whose only
output item is partial is an **incomplete interaction**, not a successful
model→tool→model exchange. Emitters must not drop the `status_reason`;
consumers and the export must preserve it verbatim.

**Manifest revision and reconciliation.** `manifest_id` and the manifest
URI are stable for the life of the decision. The manifest may be rewritten
after initial publication — idempotently, same `manifest_id`, same path —
exactly when an item settles after close (`pending -> stored`/`failed`)
or when a recovered spool delivery lands after process restart. Rewrites
are serialized per manifest (single-writer or equivalent ordering) so a
stale snapshot can never overwrite a newer one; the write itself is the
store's atomic write (spec 033), so a torn manifest never appears.
A terminal manifest — every item settled, decision closed — must validate
against the published schema; there is no "failed manifest" escape hatch.

## 5. Span attributes (allowlist additions)

- `fabric.content.manifest_ref` — decision span attribute carrying the
  manifest URI. **New allowlist key** (spec 034).
- Existing `fabric.content.ref`, `fabric.content.request_ref`,
  `fabric.content.result_ref` continue to carry per-item refs on events.
- Item refs on child spans/events: `fabric.content.ref` where a single ref
  applies; multi-ref items (e.g. retrieval results) keep per-item refs inside
  the manifest only — telemetry stays a flat scalar channel.

## 6. Examples

### 6.1 Complete model → tool → model transcript (excerpt)

```json
{
  "schema_version": "fabric.transcript-manifest/v1",
  "manifest_id": "m-01",
  "tenant_id": "acme", "agent_id": "support-bot",
  "decision_id": "d-7", "trace_id": "4bf92f…", "span_id": "00f067…",
  "items": [
    {"sequence": 0, "role": "model.request.instructions", "status": "stored",
     "descriptor": {"object_id": "o-1", "role": "model.request.instructions",
       "media_type": "text/plain", "byte_length": 212, "digest": "sha256:aa…",
       "representation": "captured", "source": "caller",
       "bindings": {"span_id": "s-llm1", "step_type": "llm_call"}},
     "ref": "s3://acme-evidence/fabric/content/acme/aa…"},
    {"sequence": 1, "role": "model.request.messages", "status": "stored",
     "descriptor": {"object_id": "o-2", "role": "model.request.messages",
       "media_type": "application/json", "byte_length": 1410,
       "digest": "sha256:bb…", "representation": "canonicalized",
       "source": "caller", "bindings": {"span_id": "s-llm1"}},
     "ref": "s3://acme-evidence/fabric/content/acme/bb…"},
    {"sequence": 2, "role": "model.output.messages", "status": "stored",
     "descriptor": {"object_id": "o-3", "role": "model.output.messages",
       "media_type": "application/json", "byte_length": 388,
       "digest": "sha256:cc…", "representation": "captured",
       "source": "caller", "bindings": {"span_id": "s-llm1",
         "related_object_ids": ["o-4"]}},
     "ref": "s3://…/cc…"},
    {"sequence": 3, "role": "tool.call.arguments", "status": "stored",
     "descriptor": {"object_id": "o-4", "bindings": {"span_id": "s-tool1",
       "tool_call_id": "call_9", "step_type": "tool_call"}, "…": "…"},
     "ref": "s3://…/dd…"},
    {"sequence": 4, "role": "tool.call.result", "status": "stored",
     "descriptor": {"object_id": "o-5", "bindings": {"span_id": "s-tool1",
       "tool_call_id": "call_9"}, "…": "…"},
     "ref": "s3://…/ee…"},
    {"sequence": 5, "role": "model.request.messages", "status": "stored",
     "descriptor": {"object_id": "o-6", "bindings": {"span_id": "s-llm2"},
       "…": "…"}, "ref": "s3://…/ff…"},
    {"sequence": 6, "role": "model.output.messages", "status": "stored",
     "descriptor": {"object_id": "o-7", "bindings": {"span_id": "s-llm2"},
       "…": "…"}, "ref": "s3://…/00…"}
  ],
  "completeness": {"stored": 7, "pending": 0, "dropped": 0, "failed": 0,
                   "not_captured": 0, "unsupported": 0}
}
```

### 6.2 Incomplete transcript (excerpt)

```json
{"schema_version": "fabric.transcript-manifest/v1", "decision_id": "d-9",
 "items": [
   {"sequence": 0, "role": "model.request.messages", "status": "stored", "…": "…"},
   {"sequence": 1, "role": "tool.call.arguments", "status": "stored", "…": "…"},
   {"sequence": 2, "role": "tool.call.result", "status": "dropped",
    "status_reason": "queue_full", "links": {"tool_call_id": "call_9"}},
   {"sequence": 3, "role": "retrieval.results", "status": "unsupported",
    "status_reason": "binary result content (media_type image/png)"},
   {"sequence": 4, "role": "model.output.messages", "status": "pending",
    "descriptor": {"object_id": "o-8", "…": "…"}, "ref": "s3://…/11…"}
 ],
 "completeness": {"stored": 2, "pending": 1, "dropped": 1, "failed": 0,
                  "not_captured": 0, "unsupported": 1}}
```

A consumer reading 6.2 knows exactly what exists, what is missing, and why —
no item silently absent.

## 7. Compatibility

- New schemas are additive; nothing in Activity v1/v2 or recorder v1 changes.
- `fabric.content.manifest_ref` is the only new telemetry key.
- Manifests older than this revision are out of scope (none exist).
