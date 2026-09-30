# Governed content capture

Fabric's default is **metadata-only**: spans and events carry calls,
timing, usage, retries, relationships, and hashes — never prompt or
payload bytes. That supports operational and structural review. It
cannot support content-level judgments (correctness, grounding,
instruction following, leakage, tool appropriateness) because the
content itself was never captured.

**Governed content** is the explicit opt-in extension: when the caller
configures it, the SDK writes the *actual* observable content — the
effective model request, outputs, tool arguments and results, retrieval
query and supplied results, memory content, side-effect payloads,
explicitly supplied context, and interaction payloads — to
**customer-controlled storage**, and stamps only references and hashes
on telemetry:

```text
CAPTURE -> PROTECT -> DELIVER
        + governed content -> customer storage (off-wire)
```

Raw content never enters OTLP. The collector allowlist admits only
`fabric.content.{ref,request_ref,result_ref,manifest_ref}` — resolution
URIs and a manifest pointer, nothing content-shaped.

This extends the recorder; it does not add evaluation. Fabric ships no
judge, grader, or finding generator. External evaluators run where the
content is authorized to be read, using the resolver/export contract.

## What this enables for evaluation

| Available record | What can be evaluated | What remains impossible |
|---|---|---|
| Metadata only (default) | call structure, latency, token/cost fields, retries, tool names, hashes, relationships, reported outcomes | semantic correctness, grounding, instruction following, leakage, payload safety, or whether a tool's arguments/result were appropriate |
| Governed content + metadata | all of the above, plus content-level review of captured prompts/messages, outputs, tool arguments/results, retrieval inputs/results, memory, side effects, explicit context and interaction payloads | hidden provider context/reasoning, content not exposed to an instrumented boundary, and correctness without an external rubric/expected outcome |
| Harness-owned offline transcript | content-level development evaluation without Fabric Node or production durability infrastructure | production audit durability/authentication unless the harness separately supplies them |

The output of this feature is therefore an **evaluation-ready, verified
record**, not an evaluation result. A grader consumes
`fabric.transcript-export/v1`, applies its own rubric, and stores its score or
finding outside Fabric OSS. Metadata and governed content are deliberately
separate channels: OTLP remains metadata-only while an authorized evaluator
resolves content from customer storage.

## The three postures

| Posture | Content | Infrastructure | Use |
|---|---|---|---|
| `metadata` (default) | none | any | operations, structure, cost |
| `governed-reference` | customer store | store + optional Node | deep review, external eval |
| harness-owned | local store | none | development, offline eval |

A development harness can record and read its own local transcripts
directly — see
[examples/offline-transcript](../examples/offline-transcript/README.md).
Offline datasets still carry privacy, access, and retention
responsibilities: the store enforces tenant namespacing and `0600`
file modes, but retention and deletion are the operator's storage
policy, not an SDK claim.

## Configuration

Governed mode requires all of: a governed store, a role policy, and a
durability mode. Anything missing fails closed at client construction.
Environment variables can only *restrict* capture
(`FABRIC_CONTENT_MODE=metadata` force-disables it) — they can never
enable it.

```python
from fabric import (
    ContentCaptureConfig, Fabric, FabricConfig,
    LocalFilesystemContentStore,
)

fabric = Fabric(
    FabricConfig(tenant_id="acme", agent_id="agent"),
    content_capture=ContentCaptureConfig(
        store=LocalFilesystemContentStore("/var/lib/fabric/content", tenant_id="acme"),
        roles="all",                # or an explicit subset of content roles
        durability="spooled",       # inline | process | spooled
        spool_dir="/var/lib/fabric/spool",
    ),
)
```

```typescript
const fabric = new Fabric({
  tenantId: "acme",
  agentId: "agent",
  contentCapture: {
    store: new LocalFilesystemContentStore("/var/lib/fabric/content", "acme"),
    roles: "all",
    durability: "spooled",
    spoolDir: "/var/lib/fabric/spool",
  },
});
```

### Stores

- **Local filesystem** — synchronous, atomic `tmp + fsync + rename`
  under `<root>/<tenant>/<digest>`; descriptor sidecars under `meta/`,
  manifests under `manifests/` with a `by-decision/` alias. File mode
  `0600`, directories `0700`. Pre-existing objects are verified against
  their digest, never trusted by name. Reads are confined to the
  configured tenant namespace.
- **S3-compatible** — `s3://<bucket>/<prefix>/<tenant>/<digest>`;
  conditional writes (`IfNoneMatch: "*"`) with digest verification of
  pre-existing objects; lazy optional dependency (`boto3` /
  `@aws-sdk/client-s3` — never required for metadata-only installs).
  Encryption, bucket policy, IAM, and retention are the customer's
  storage controls; the SDK does not claim to provide them.

Refs are `file://`/`s3://` URIs — never credentials, signed URLs, or
session material.

**Tenant rules.** The store's `tenant_id` must exactly equal the `Fabric`
client tenant — a mismatch fails construction. Tenant identifiers follow
one shared safe-identifier rule (spec 033 §2.1): they must match
`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`, not be `.`/`..`, and contain no
separators or encoded traversal; the local adapter additionally verifies
the resolved tenant root stays inside the configured root. Identical
content under two tenants writes two objects — no cross-tenant dedup.

### Durability modes

- **`inline`** — synchronous store write on the capture path.
  **Development and tests only**: every byte of store latency lands on
  the monitored call, and it requires a synchronous store (local only).
  It is never the recommended production mode.
- **`process`** — bounded in-memory queue drained on the event loop /
  worker thread. **A nonblocking enqueue is not a durable
  acknowledgment**: there is an interval in which process failure can
  lose buffered content. The manifest reports those items `pending` /
  `dropped` — an honest gap, never claimed delivered.
- **`spooled`** — fsync'd local handoff before the item is accepted as
  durable; recovered on restart with idempotent re-delivery. **This is
  the production path.** In spooled mode the durable local handoff
  completes before acceptance — a remote object-store stall never holds
  the monitored call.

All modes bound queue depth (`queue_max_items`, a required positive
integer), payload size (`payload_max_bytes`, UTF-8-safe truncation marked
`truncated` with the original length), retry attempts, and retry
wall-clock. `flush_content(timeout_s)` / `flushContent(timeoutS)` is an
opt-in awaitable flush for tests and graceful shutdown; `close()` drains
within the shutdown timeout. Store outages never change application
behavior — failures land as explicit manifest statuses (`failed`,
`dropped`, `unsupported`, `not_captured`), not exceptions into the
monitored path and not silent omissions.

The monitored call still pays for canonical serialization, UTF-8
truncation, SHA-256 hashing, descriptor construction, and the bounded local
handoff. Those costs are linear in the accepted payload size. `process`
limits the handoff to a bounded in-memory enqueue; `spooled` additionally
pays for a local file fsync + rename + directory fsync. Remote destination
I/O and retries stay off the monitored path in both modes.

**Passive delivery end to end.** In `process`/`spooled` modes no
object-store I/O — local *or* network — happens on the monitored path,
including the transcript manifest: `fabric.content.manifest_ref` is a
deterministic URI computed without I/O and stamped while the decision
span is still open; the manifest document is then delivered through the
same bounded writer (spooled, in spooled mode) and reconciled as items
settle (`pending → stored`/`failed`, idempotent rewrite, stable
`manifest_id`). Object delivery outcomes reach the owning manifest
through a keyed subscriber while the process is alive. Durable spool
records also carry the owning manifest id and item sequence, so restart
recovery performs the same transition without relying on a process-local
callback.

### Durable spooling

In `spooled` mode each pending delivery — content objects *and* the
transcript manifest — is a `fabric.content-spool/v2` record: schema
version, tenant, delivery type, object/manifest and decision identity,
the payload (descriptor + bytes, or the manifest document), the
deterministic destination ref, retry metadata, and a record checksum.
Object records include `manifest_id` + `manifest_item_sequence` for
post-restart reconciliation. Manifest records carry a monotonic revision;
older queued revisions cannot overwrite the newest document or delete its
stable spool file.
The spool directory is `0700` (tightened if it already exists more
permissively), records `0600`, written atomically with file + directory
fsync.

On restart, recovery processes **every** valid record — not just the
first queue-capacity batch. It republishes recovered manifests first,
then idempotently delivers objects and reconciles their exact manifest
items. Unreadable, checksum-failed, or unknown-version records are renamed
to `*.json.corrupt` and counted — an explicit operational outcome, never
silent loss. Successful delivery unlinks the record and fsyncs the spool
directory; a crash between remote write and local delete is safe because
re-delivery converges. Numeric legacy-v1 records remain readable for
upgrade recovery, but new writes use v2.

## What telemetry carries

- `fabric.content.request_ref` — the effective request (LLM input
  messages, retrieval query, side-effect request).
- `fabric.content.result_ref` — outputs and results.
- `fabric.content.ref` — single-ref surfaces (memory, interaction
  payload, context).
- `fabric.content.manifest_ref` — the per-decision transcript manifest
  written at decision close.

A ref can arrive before its object (two destinations, no atomic
delivery claim): it resolves as `pending` until stored, and manifest
statuses keep `pending`/`failed`/`dropped` distinct from `stored` —
missing content never looks like an empty input or a complete capture.

## Resolution and export

`ContentResolver` reads only through explicitly configured stores and
tenant namespaces — a telemetry-provided URI can never grant arbitrary
filesystem or network access, and ownership checks run on normalized
canonical paths/keys.

**`available` means verified.** Content returns `available` only after
a valid descriptor is found, its tenant/identity checks pass, and the
object's byte length and SHA-256 digest verify. A digest-named path is
never treated as proof of integrity, and bytes are never returned for
`denied`, `corrupted`, or `unverified` results:

| Situation | Result |
|---|---|
| URI outside configured stores / bad scheme / traversal | `denied` |
| Descriptor tenant ≠ store tenant | `denied` |
| Descriptor missing, unreadable, or wrong shape | `unverified` |
| Descriptor identity inconsistent; byte-length or digest mismatch | `corrupted` |
| Bytes absent, manifest proves `pending` | `pending` |
| Bytes absent otherwise (incl. deleted/expired) | `missing` |
| All checks pass | `available` |

`export_transcript` produces `fabric.transcript-export/v1`: ordered
steps, each carrying an `entries` **array** — every manifest item exactly
once, in sequence order, with its role, status, refs, and materialized
or reference-only content. Repeated roles (multiple output chunks,
retried tool attempts, repeated retrieval/context) are preserved, never
overwritten. Completeness counts and per-object integrity results are
included. The resolver does not execute tools, replay side effects, or
fetch arbitrary URIs.

## Coverage and limits

Supported today: text and JSON content roles (the closed set in spec
028), manual `llm_call`/`tool_call`/`record_*` surfaces in both SDKs,
local + S3 stores, inline/process/spooled delivery, manifest +
export + resolution.

Not supported / not claimed:

- **Binary/multimodal content** — mark it `unsupported` rather than
  storing; v1 is text/JSON.
- **Hidden provider context or reasoning** — Fabric records what
  crossed the observable boundary; it does not reconstruct system
  prompts the caller never saw or claim access to hidden reasoning.
- **Model-consumed proof** — a recorded retrieval result proves the
  caller received it, not that the model consumed it; the recorded
  effective request is the evidence where visible.
- **Zero overhead / zero loss** — buffering has real CPU/memory cost
  and the process-mode crash window is documented above.
- **Auto-everything capture** — adapter/framework auto-capture is
  per-integration; check the coverage matrix in
  [recorder-v1-qualification-status.md](recorder-v1-qualification-status.md).

## Migrating from `capture_content`

`capture_content` / `captureContent` emitted raw model/tool payloads
onto spans — stripped by the Fabric Node's allowlist and never a
governed evidence path. Governed mode does not reinterpret that flag:
raw span emission stays opt-in and is still stripped at the collector;
governed storage is configured independently via `contentCapture`.
Existing metadata-only users see no behavior change.
