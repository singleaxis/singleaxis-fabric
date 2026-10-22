# Explicit (app-reported) APIs

Wire capture records what crosses the model HTTP boundary without code
changes. Everything else Fabric records, the application reports itself
through the SDK: decisions, tool calls, retrieval, memory, side effects,
delegation, and exact bytes at boundaries the application chooses. These
records are `caller_reported`: they say what the application told Fabric,
and Fabric cannot detect a call the application did not report.

| API | Python | TypeScript |
|---|---|---|
| `decision()` and `record_*` activity spans | yes | yes (`decision`, `record*` in camelCase) |
| Exact bytes with privacy modes (`ByteEvidenceRecorder`, `ContentProtector`, `DeploymentPolicy`) | yes | yes |
| `CallRecorder` (call, attempt and stream timeline with exact bytes) | yes | no |
| Byte-boundary adapters (`ByteBoundaryAdapter`, `FinalHTTPAdapter`, synthetic adapters) | yes | no |
| Encrypted durable byte spool (`DurableByteSpool`) | yes | no |
| Metadata-only managed span export (`install_default_provider`) | yes | no (registers the provider you pass) |
| Qualified-run mode | yes ([qualified-run mode](qualified-run-mode.md)) | no |
| Wire capture | yes | **no** |

None of these APIs blocks, changes or delays the call it records. A
recording failure is caught and becomes an evidence gap; the application's
result, exception and cancellation are its own.

## Decision API

`decision()` opens one OpenTelemetry span per agent decision; the methods on
it emit child spans and span events that carry metadata and SHA-256 hashes,
never raw payloads (unless you opt in to content, below).

```python
from fabric import Fabric, FabricConfig, install_default_provider

install_default_provider(service_name="my-agent")  # exporter from OTEL_EXPORTER_OTLP_ENDPOINT

fabric = Fabric(FabricConfig(tenant_id="demo", agent_id="my-agent"))

with fabric.decision(session_id="session-1", request_id="request-1") as decision:
    with decision.llm_call(provider="openai", model="gpt-4o-mini") as call:
        answer = ...  # call your model here
        call.set_usage(input_tokens=5, output_tokens=6, finish_reason="stop")
    with decision.tool_call("lookup_order", call_id="tool-1") as tool:
        tool.set_arguments('{"order_id": "order-123"}')
        tool.set_result('{"status": "shipped"}')
```

Configure a tracer provider **before** opening a decision. Without one, the
SDK warns once and the spans are dropped. `install_default_provider` wires a
`TracerProvider` whose exporter is metadata-only: it removes content, event
payloads and status text, hashes free-form strings and keeps trace identity
and timing. `fabric.tracing.trace_export_protection_status()` reports which
routes are protected. An existing host provider is never modified; its
exporters remain the host's responsibility.

`Decision` methods (Python; `sdk/python/src/fabric/decision.py`):
`llm_call`, `embeddings`, `tool_call`, `record_retrieval`, `remember`,
`recall`, `forget`, `record_side_effect`, `checkpoint`,
`record_replay_metadata`, `record_interaction`, `record_context`,
`record_skill`, `delegate`/`adelegate`, `record_hook`, `record_file_access`,
`set_attribute`. `Fabric.execution(...)` correlates several decisions.
Recording never raises into the application: a failing tracer, span or
store is caught and counted (`capture_health` `partial`), the application's
own exception always propagates unchanged, and no recording call waits on
storage (the legacy `content_store` is written by a bounded background queue;
governed `inline` durability waits at most 50 ms in Python and never in
TypeScript, where `flush()` is the durability point). When one `Decision` is
used from several threads or tasks, the overlapping call is recorded without
serialisation and counted (`Decision.concurrent_use_count`,
`capture_health["status"] == "partial"`); `FABRIC_RECORDS_STRICT=1` raises
`ConcurrentDecisionUseError` instead, for tests.
`fabric.integrations.mcp` wraps an MCP client session (`traced_call_tool`,
`InstrumentedMCPSession`, `record_mcp_inventory`); arguments and results are
hashed under the digest rule below. `InstrumentedMCPSession` records the
`list_tools()` (and `list_resources()`, `list_prompts()`) results the
application receives through it and never makes a request of its own. The
emitted span names and GenAI attributes are listed in
[GenAI semantic conventions](genai-semantic-conventions.md).

TypeScript (`@singleaxis/fabric`) uses callbacks:
`fabric.decision(ids, async (decision) => { await decision.llmCall(...); })`
and `toolCall`, `recordRetrieval`, `remember`, `recall`, `forget`,
`recordSideEffect`, `checkpoint`, `recordReplayMetadata`,
`recordMcpInventory`, `recordSkill`, `delegate`, `recordHook`,
`recordFileAccess`, `recordInteraction`, `recordContext`. Register a provider
and an `AsyncLocalStorageContextManager` first (see the
[TypeScript SDK README](../sdk/typescript/README.md)).

### Identifiers (pseudonym v2)

By default (`FABRIC_IDENTITY_MODE=pseudonymous`), caller-supplied ids are
emitted only as keyed pseudonyms: `prefix-` + 32 hex of an HMAC-SHA256 keyed
by `FABRIC_WIRE_ID_KEY` (at least 16 bytes) with a per-type subkey. Prefixes
include `sess-` (session), `usr-` (user), `conv-`, `mkey-` (memory key),
`agt-` (delegation target) and `tgt-` (interaction target).

- **Without `FABRIC_WIRE_ID_KEY`, session, user and other caller-supplied
  ids are omitted** (one warning per process). Set the key in every
  environment where you need to correlate by these ids.
- `FABRIC_IDENTITY_MODE=clear` emits the ids unchanged. Use it only with
  ids that are not personal data. A Node in its default pseudonymous
  identity mode drops a `fabric.session_id` that is not a `sess-` value.
- The configured `agent_id` is emitted as given; use an opaque value. From
  v0.8.1 `request_id` is a caller id like the others (`lbl-`, omitted
  without the key).
- Other caller data on decision-line keys (v0.8.1): with the key,
  `gen_ai.memory.store.id` is `mst-`; idempotency keys
  (`fabric.side_effect.idempotency_key`, `fabric.tool.idempotency_key`) and
  `fabric.retrieval.source_document_ids` entries are `lbl-` (their types have
  no v2 prefix yet); checkpoint step names, MCP tool names
  (`fabric.mcp.tools`), tool names on tool spans, side-effect target systems
  and operations, and tags are operator labels, `lbl-`, or as given with
  `FABRIC_WIRE_LABELS=clear`. Provider ids (response, previous response, tool
  call, parent tool call) are the keyed `p-` form. Without the key they are
  omitted. Host spans record only the exception class, never its message or
  stack trace.

With the id key, `ByteEvidenceRecorder`, `CallRecorder` and
`SyntheticCaptureSession` emit the run id as `r-`, the source id as `s-`,
the agent id as `agt-` and any other caller id (operation, attempt, stream,
parent call) as `lbl-`. **Every caller-supplied id is pseudonymised**, even
one already shaped like `r-`, `s-`, `lbl-` or a UUID. Only ids a recorder
returned pass through unchanged: they are typed `EmittedId` values (Python
`fabric._sequence.EmittedId`, a `str` subclass; TypeScript `EmittedId`),
recognised by type and issuer, never by shape, so a `parent_call_id` joins
its parent's `call_id`. An emitted id written out as text and read back is
a plain string again and is mapped. For continuity across processes and
hosts, pass the **same clear id** under the same key (the mapping is
deterministic), never an emitted value. `emitted_run_id(run_id)` and
`emitted_source_id(source_id)` (TypeScript `emittedRunId`, `emittedSourceId`) return
the emitted form; a source spool is keyed by the emitted run id.

### Content with the decision API

By default the decision API records metadata, not content. A `*_hash`
digest of a payload (query, memory content, side-effect request and result,
tool arguments and result, interaction payload) is emitted only when the
payload's content role retains the original: a role in the governed content
capture below or, in Python without one, the memory and side-effect payloads
written to a legacy `content_store`. `FABRIC_IDENTITY_MODE=clear` keeps the
v0.8.0 digests. Two opt-ins exist:

- `Fabric(content_capture=ContentCaptureConfig(...))` writes the content
  that recorder methods receive to a tenant-scoped governed store and stamps
  references on the spans, with a content-v1 transcript manifest per
  decision (specs 028, 029, 032, 033).
- `FABRIC_CAPTURE_LLM_CONTENT=true` (or `capture_content=True` on
  `install_default_provider`) puts content on spans and bypasses the
  metadata-only export. Do not use it across a trust boundary.

## Exact bytes: `ByteEvidenceRecorder`

`ByteEvidenceRecorder` stores bytes the caller passes, per content role
(`model.request.messages`, `tool.call.result`, `terminal.stdout`, ...), as
content-v2 objects in a tenant-scoped store, through a bounded background
queue. Privacy is chosen per role, before anything is persisted:

- `BytePrivacyPolicy(mode=...)` per role: `original`, `omit`,
  `masked_only`, `original_plus_masked`; or
- a `DeploymentPolicy` (deployment-policy/v1) with the seven modes
  `omit`, `metadata_only`, `redact`, `tokenize`, `masked_only`,
  `original_plus_masked`, `retain_original`, applied by a `ContentProtector`.
  Roles the policy does not name are omitted.

Masking modes (`redact`, `masked_only`, and the review copy of
`original_plus_masked`) are performed by a **redaction service you run**
beside the application; Fabric ships no PII detector and never runs your
code. Name the transformation by id and version
(`BytePrivacyPolicy(mode="masked_only", transformation_id="example-mask", transformation_version="1")`,
or `ContentProtector(policy, transformations={role: Transformation("example-mask", "1")})`;
TypeScript `new ContentProtector(policy, { transformations: { role: { id: "example-mask", version: "1" } } })`)
and point the recorder at the service (`redaction=RedactionService(...)` /
`redaction: { endpoint }`, else `FABRIC_REDACTION_ENDPOINT`). The service is
called only on the recorder's worker, with a 5 s timeout and at most two
calls in flight; any failure **withholds** the object (`not_captured`,
`protection_failed`), never stores raw bytes, and is counted in
`redaction_stats()`. A masking role without a transformation or a service
raises at construction, and module references or functions are refused.
Details: [redaction service](privacy-and-security.md#redaction-service).

In the production profile (`deployment.profile: production` in the policy)
content capture also needs `FABRIC_WIRE_ID_KEY`; without it every object is
`not_captured` with `missing_id_key`.

Python only: `DurableByteSpool` adds an AES-256-GCM encrypted, fsync'd local
spool under the recorder (customer-supplied 32-byte key; POSIX;
`cryptography` required). TypeScript's handoff is in memory only; a crash
loses pending content.

## `CallRecorder` (Python)

`CallRecorder` wraps your dispatcher's final model and tool send/receive
points. Each call gets an operation and attempt id, causal parent links
(propagated across asyncio tasks; pass `parent_call_id` across threads;
across processes see the emitted-id rule under Identifiers) and its input and output bytes through a `ByteEvidenceRecorder`.

```python
from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, CallRecorder, LocalFilesystemContentStore

recorder = ByteEvidenceRecorder(ByteEvidenceConfig(
    store=LocalFilesystemContentStore(root="./evidence", tenant_id="demo"),
    roles=frozenset({"model.request.messages", "model.output.messages",
                     "tool.call.arguments", "tool.call.result"}),
))
calls = CallRecorder(recorder, run_id="run-1", agent_id="support-agent", source_id="host-a")

reply = calls.call(request_bytes, send_to_model, kind="model")   # send_to_model(bytes) -> bytes
result = calls.call(args_bytes, lookup_order, kind="tool")
snapshot = calls.snapshot()   # offline, local; makes no completeness claim
recorder.close()
```

- `call`/`acall` record one request and response; `stream`/`astream`
  return pull-through iterators that record ordered chunks and never
  prefetch. Close a stream you stop early; an unclosed stream stays
  incomplete.
- `kind` is `model`, `tool`, `database` or `agent`. `record_data()` attaches
  extra bytes (file, terminal, DB) to the active call.
- An optional source journal (`source_spool=SyntheticSourceSpool(...)`,
  then `seal_source()` after the work) is the basis of
  [qualified-run mode](qualified-run-mode.md).
- In the production profile without an id key, generated ids replace your
  run, source and agent ids, and the source journal is not used.

## Byte-boundary adapters (Python)

- `fabric.adapters.byte_boundary.ByteBoundaryAdapter(session, kind="model"|"tool", source_id=...)`:
  a synchronous `call()` for an existing agent whose final transport takes
  and returns bytes.
- `fabric.http_dispatch.FinalHTTPAdapter`: the final HTTP/1.1 request and
  response body for one declared URL (stdlib HTTP only).
- `fabric.adapters.synthetic_evidence`: a no-shell subprocess adapter
  (argv, stdin, stdout, stderr, exit), a before/after file-bytes observer
  and a loopback HTTP model adapter, used by the bounded test slices of
  spec 040.

These record exactly what passes through them; they do not discover other
routes. The offline reconcilers for this line (`call_reconcile`,
`synthetic_reconcile`) return `partial` or `unverified`, never complete.

## Using the explicit APIs with wire capture

Both can run in one process. Inside a live `CallRecorder` or
`ByteBoundaryAdapter` call with `kind="model"` the wire tee defers: the
call is recorded once, by the explicit recorder. A response that outlives
the explicit call is wire-captured. Tool, database and agent calls do not
suppress wire capture. Work handed to `ThreadPoolExecutor.submit` or
`loop.run_in_executor` does not inherit the scope; wrap the function in
`fabric.bind_capture_context(...)`. Give every spool its own directory.

`fabric.reconstruct` does not read explicit-line records; see
[reconstruct](reconstruct.md#scope-of-the-verifier).
