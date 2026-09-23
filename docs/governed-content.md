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

## The three postures

| Posture | Content | Infrastructure | Use |
|---|---|---|---|
| `metadata` (default) | none | any | operations, structure, cost |
| `governed-reference` | customer store | store + optional Node | deep review, external eval |
| harness-owned | local store | none | development, offline eval |

A development harness can record and read its own local transcripts
directly — see [examples/governed-content](../examples/governed-content/README.md).
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

### Durability modes

- **`inline`** — synchronous store write on the capture path. Simplest;
  requires a synchronous store (local only).
- **`process`** — bounded in-memory queue drained on the event loop /
  worker thread. **A nonblocking enqueue is not a durable
  acknowledgment**: there is an interval in which process failure can
  lose buffered content. The manifest reports those items `pending` /
  `dropped` — an honest gap, never claimed delivered.
- **`spooled`** — fsync'd local handoff before enqueue; recovered on
  restart with idempotent re-delivery. This is the production path when
  crash loss is unacceptable.

All modes bound queue depth, payload size (`payload_max_bytes`,
UTF-8-safe truncation marked `truncated` with the original length),
retry attempts, and retry wall-clock. `flush_content(timeout_s)` /
`flushContent(timeoutS)` is an opt-in awaitable flush for tests and
graceful shutdown; `close()` drains within the shutdown timeout.
Store outages never change application behavior — failures land as
explicit manifest statuses (`failed`, `dropped`, `unsupported`,
`not_captured`), not exceptions into the monitored path and not silent
omissions.

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
filesystem or network access. Every resolved object is verified against
its descriptor's byte length and SHA-256 digest before content is
returned; states are explicit (`available`, `pending`, `missing`,
`denied`, `corrupted`). Digests are integrity checks, not authorization
and not proof of source truth.

`export_transcript` produces `fabric.transcript-export/v1`: ordered
steps (grouped by child span, preserving emission order — not
timestamp-sorted inference), materialized or reference-only content,
completeness counts, and per-object integrity results. The resolver
does not execute tools, replay side effects, or fetch arbitrary URIs.

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
