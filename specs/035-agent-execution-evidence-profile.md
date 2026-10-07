---
title: Agent Execution Evidence Profile for OpenTelemetry
status: draft
revision: 2
last_updated: 2026-09-26
owner: product-architecture
depends_on: 027, 028, 029, 030, 031, 032, 033, 034
---

# 035 — Agent Execution Evidence Profile for OpenTelemetry

## Decision

Define a **public, vendor-neutral profile of existing standards**, not a new
trace transport. The profile uses:

1. **OTLP traces** for operations with duration and causal parent/links;
2. **OTLP LogRecords with EventName** for point-in-time observations, stream
   chunks, artifact changes, source health, and capture gaps;
3. **W3C Trace Context** across instrumented process and network boundaries;
4. **OpenTelemetry semantic conventions** for GenAI agent/model/tool, DB,
   HTTP/RPC, messaging, process and other operations where applicable; and
5. **customer-controlled content objects and manifests** for exact bytes,
   with only opaque references, digests and statuses on the OTLP wire.

This is the **Agent Execution Evidence Profile (AEEP) v0.1**, a Fabric
proposal, **not an existing OpenTelemetry or W3C standard**. The GenAI
agent/tool conventions are currently Development status; implementations
MUST pin the convention version/schema URL they emit, and compatibility
adapters MUST not silently reinterpret older records. The profile should be
proposed upstream once at least two independent implementations and their
conformance fixtures exist. Until then, `agent.evidence.*` is a proposed
extension namespace, never an assertion that OpenTelemetry has standardized
these keys.

Standard references (checked 2026-09-26):

- [OTel log/event data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
  and [event conventions](https://opentelemetry.io/docs/specs/semconv/general/events/);
- [OTel GenAI agent/tool spans](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md)
  and [content upload guidance](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md#uploading-content-to-external-storage);
- [OTel database client spans](https://opentelemetry.io/docs/specs/semconv/db/database-spans/)
  and [process attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/process/);
- [W3C Trace Context](https://www.w3.org/TR/trace-context/).

OpenTelemetry explicitly leaves a common external-content reference format
to future work. AEEP defines that missing interoperability piece by extending
Fabric's public content contract; it does not claim that the extension is
already standardized upstream.

The sequenced build plan, contract definitions to create, coverage gates,
and current-state inventory are in
[spec 036](036-evidence-capture-implementation-plan.md). `log.record.uid` is
currently an **opt-in Development** semantic-convention attribute, not a
stable OTel identity guarantee; AEEP must also carry its own immutable
`record_id` in its versioned evidence event/run-manifest contract. The exact OTel
semantic-convention revision must be pinned before implementation.

## Product boundary and guarantees

AEEP is **CAPTURE -> PROTECT -> DELIVER** only. It supplies records for
downstream evaluation, investigation, or customer audit, but contains no
judge, score, finding, policy decision, or enforcement action. Passive
capture MUST NOT block or alter the monitored agent. When source-side loss
is possible, the record MUST expose the gap instead of claiming completeness.

The strongest valid claim is **byte-exact historical reconstruction of the
declared and verified observable boundary**. The profile does not promise
deterministic model re-execution, hidden provider context/reasoning, a global
order for concurrent events, or visibility into an uninstrumented remote
machine. Hash verification proves stored-byte integrity, not capture
completeness or semantic truth.

## 1. Identity, ordering and provenance

The following fields are required when the source can establish them. When
it cannot, the source capability manifest must declare that limitation and
the run manifest must not claim native end-to-end correlation:

| Field | Meaning |
| --- | --- |
| OTel `TraceId`, `SpanId` | Native trace position when available; never synthesized from host metadata |
| `agent.evidence.run_id` | Opaque run identity minted at the agent boundary and propagated to authorized adapters; omitted by unlinked host sources |
| `agent.evidence.source_id` | Unique emitter instance within a run; includes restart epoch |
| `agent.evidence.source_sequence` | Monotonic, gap-detectable sequence **per source**, not a global order |
| OTel `log.record.uid` | Opt-in Development dedupe attribute; retry MUST keep it, with AEEP `record_id` as the contract-owned stable identity |
| `agent.evidence.operation_id`, `agent.evidence.attempt_id` | Logical operation and physical attempt, when applicable |
| `agent.evidence.boundary` | `caller`, `provider_bound`, `tool`, `terminal`, `sandbox`, `remote`, `host`, `service` |
| `agent.evidence.provenance` | `native`, `protocol`, `caller_reported`, or `inferred` |

W3C `traceparent`/`tracestate` MUST be propagated where the instrumented
protocol supports them. Cross-process operations that have an authenticated
carrier use parent/child spans or span links. Kernel audit records lacking a
carrier MUST remain separate provenance events; PID/time/IP joins MUST be
labelled `inferred` and MUST NOT invent a trace parent. Concurrent sources
retain independent sequences and causal links; wall-clock timestamps are
investigation aids, not ordering proof. Every source reports its start,
stop/restart epoch, sequence high-water mark, and observed loss counters.

Identity is accepted only after the customer deployment authenticates and
binds the emitter to a tenant/workload. A self-reported tenant or run ID
alone is not proof of ownership.

## 2. OTLP mapping

Use the closest applicable **existing** OTel semantic convention first.
Only add `agent.evidence.*` fields for evidence semantics with no existing
OTel key. Do not overload standard keys with a different meaning.

| Activity | Operation span | Point-in-time evidence / governed bytes |
| --- | --- | --- |
| Agent/workflow/model/tool/MCP | Current OTel GenAI `invoke_agent`, `invoke_workflow`, inference, `execute_tool`, MCP conventions where supported | Actual provider-bound request/output and tool definition/arguments/result as content objects; model/tool IDs bind objects to spans |
| Terminal/PTY/subprocess | Tool span; a child process execution span using process/resource attributes where supported | `stdin`, `stdout`, `stderr` ordered chunks, argv, cwd and approved environment snapshot; exit/signal event; host `exec` corroboration stays provenance-only |
| SSH/remote execution | Client call span and remote span **only** with authenticated context propagation | Local command/session metadata; remote command streams, file changes and results from an instrumented remote endpoint; encrypted-transport metadata alone is insufficient |
| Database/warehouse/vector store | OTel DB client span; keep standard sanitized query metadata | Exact query + bound parameters, returned rows or approved snapshot, transaction/commit receipt in governed storage; server audit/CDC can corroborate mutations |
| HTTP/RPC/WebSocket/browser/cloud API | Existing OTel HTTP/RPC spans | Request/response bodies and stream chunks in governed storage; redirects, browser-visible artifacts, server/cloud receipts where supported |
| Sandbox/container/VM/Kubernetes | Agent/tool spans plus runtime/control-plane spans where available | Image digest/config, mounts, process/network inventory, output artifacts, control-plane audit ID, start/stop and loss markers |
| File/artifact/object store | Tool/object-store spans where applicable | Exact created/read bytes, prior/new object version or tombstone, media type, digest and provenance; metadata-only file opens do not count as artifact content |
| Retrieval/memory/messaging | Existing OTel GenAI retrieval/memory and messaging spans where applicable | Exact returned/consumed values and version/receipt; distinguish result *received by caller* from context actually sent to the model |

Spans describe operations with duration; LogRecords with `EventName` describe
observations that can repeat within a span. The proposed names are
`agent.evidence.content`, `agent.evidence.artifact`,
`agent.evidence.coverage`, `agent.evidence.loss`, and
`agent.evidence.receipt`. Their OTLP body MUST be empty; sensitive bytes
MUST NOT be placed on span/log attributes. The metadata-only Collector
allowlist MUST explicitly admit only reviewed keys; this draft does not
authorize new keys in the current Fabric Node.

## 3. Governed content extension

Content v1 remains unchanged. AEEP requires a separately versioned
**content v2** contract rather than adding roles/media types to v1's closed
schema. Its descriptor/manifest MUST specify:

- exact source byte length and `sha256` of **source bytes** when accessible;
- stored byte length and `sha256` of **stored bytes**; media type, encoding,
  representation (`exact`, `canonicalized`, `assembled`, `partial`,
  `truncated`, `redacted`), and transformation provenance;
- tenant-bound, credential-free reference and access-controlled store;
- content role, capture boundary, source/operation/attempt/stream identity,
  per-source sequence, capture and observed timestamps;
- explicit status: `pending`, `stored`, `truncated`, `redacted`,
  `not_captured`, `unsupported`, `dropped`, or `failed`; and
- typed causal links to other evidence objects and any external receipt.

New role families include `terminal.{argv,stdin,stdout,stderr}`,
`remote.{request,result,stream}`, `database.{query,parameters,rows,mutation}`,
`network.{request,response,stream}`, `sandbox.{config,output}`,
`artifact.{before,after}`, and `service.receipt`. A role is not a claim that
its bytes were captured: each expected role has an item/status in the
manifest. Binary and multimodal artifacts require bytes-capable v2 stores;
v1's text/JSON-only limit MUST NOT be silently bypassed.

Store-side authorization, encryption, retention and audit logging are
customer responsibilities. Raw command lines, environment values, SQL
parameters, headers and rows may contain secrets; the default is
metadata-only, with role-scoped content opt-in and explicit redaction.
Never export credentials, signed URLs, or raw content in OTLP refs. Hashing
small secrets is not a substitute for content classification.

For streaming, emit chunk order and terminal status (`complete`, `partial`,
`cancelled`) with source sequence; an assembled object may be added for
convenience but MUST NOT replace chunk evidence when exact timing/order is
claimed. A captured file *open* is not a captured file *read*, and a recorded
retrieval result is not proof that the model consumed it.

## 4. Completeness and delivery

The run-level evidence manifest MUST declare the approved boundary set,
connector capability manifest IDs/versions, expected role families,
producer versions, source epochs and high-water marks, observed sequence
gaps, sampled/rate-limited/dropped counts, item statuses, and destination
receipts. Its verdict is one of:

| Verdict | Meaning |
| --- | --- |
| `verified_complete_for_declared_scope` | Every required source/role in a **bounded declared scope** reconciles, all required objects resolve and verify, and no unknown loss is reported |
| `partial` | A known missing, redacted, truncated, unsupported, failed, or lost item/interval |
| `unverified` | Source health, boundary inventory, receipt, or reconciliation is unavailable |

No universal `complete` verdict exists for an unconstrained agent. A
connector's absence of records cannot prove that the agent did nothing.
Independent source truth (e.g. database audit, Kubernetes audit, sandbox
artifact inventory) is needed to qualify a completeness claim. Exporters
MUST distinguish accepted by source spool, accepted by Node, accepted by
destination, and durably persisted; OTLP success alone proves neither
source completeness nor durable destination storage.

At-least-once delivery may duplicate LogRecords and spans. Consumers dedupe
by AEEP `record_id` (also exported as `log.record.uid` when supported), or
preserved span identity plus attempt, never by timestamp or payload hash. A
passive recorder may lose data under catastrophic source
failure; that loss must be visible, not silently normalized away.

## 5. Minimal interoperable example (illustrative, not current wire output)

```text
OTLP Span: gen_ai.operation.name=execute_tool, gen_ai.tool.name=run_command
  TraceId=... SpanId=... parent=agent span

OTLP LogRecord: EventName=agent.evidence.content, Body=<empty>
  TraceId=... SpanId=...
  agent.evidence.run_id=run-42
  agent.evidence.source_id=terminal-adapter-1:epoch-3
  agent.evidence.source_sequence=17
  log.record.uid=evt-17
  agent.evidence.boundary=terminal
  agent.evidence.provenance=native
  agent.evidence.role=terminal.stdout
  agent.evidence.status=stored
  fabric.content.ref=s3://customer-bucket/tenant/.../object
  agent.evidence.content_digest=sha256:...

Customer store: exact stdout chunk bytes + v2 descriptor
Run manifest: expected terminal.stdout item #17 -> stored/verified
```

The current Fabric Node does **not** admit all example attributes or emit
this event. The example is a proposed compatibility target, not a claim of
implementation. The actual v2 schema must define exact field types and
privacy bounds before any producer ships it.

## 6. Conformance and staged implementation

1. Publish this draft for review; pin the OTel GenAI convention revision and
   map every existing `fabric.*` field/role to this profile. Preserve the v1
   wire and content contracts.
2. Define public v2 content-object and run-manifest schemas, valid/invalid
   fixtures, exact-byte cross-language tests, status transitions, and a
   parser/validator. Treat new attributes/event names as deny-by-default
   until Fabric Node allowlist and privacy-leak tests pass.
3. Build adapters in risk order: provider-bound model/tool; terminal/PTY and
   file artifacts; sandbox and remote SSH; DB and HTTP/browser/cloud. Each
   adapter publishes a versioned capability/bypass manifest and tests both
   captured and unsupported paths. No universal auto-capture claim.
4. Qualify source-side durability/retry/loss accounting **before** declaring
   source completeness; test outage, restart, disk-full, overflow, duplicate,
   rate-limit and clock-skew cases. Keep the monitored path passive.
5. Run a multi-implementation conformance suite and a customer-controlled
   pilot that reconciles independent source truth. Publish measured coverage
   and gaps. Consider an upstream OTel semantic-convention proposal only
   after the profile and extension names have implementation evidence.

Acceptance for this draft is **a reviewable protocol design**, not production
qualification. Recorder release artifacts MUST NOT advertise AEEP v0.1 as
implemented until all relevant code and artifact-content tests exist.
