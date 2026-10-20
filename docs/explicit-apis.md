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
`fabric.integrations.mcp` wraps an MCP client session (`traced_call_tool`,
`InstrumentedMCPSession`, `record_mcp_inventory`); arguments and results are
hashed. The emitted span names and GenAI attributes are listed in
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
- `request_id` and the configured `agent_id` are emitted as given; use
  opaque values.

### Content with the decision API

By default the decision API records hashes, not content. Two opt-ins exist:

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

Masking modes need a **customer transformation, named by module
reference** (`"package.module:function"`, bytes in, bytes out). Fabric ships
no PII detector. Python runs the function in a separate `python -I` child
process; TypeScript runs a module (`{ module: "/abs/path/redactor.mjs",
exportName: "redact" }`) in a `worker_threads` Worker. Passing a function
raises (Python) or throws (TypeScript). Each call has a timeout (default 5 s);
an error, timeout or oversized result **withholds** the object
(`not_captured`, `protection_failed`); there is no fallback to raw bytes. At
most two calls per transformation run at once; beyond that content is
withheld (`transform_saturated`). See [privacy and security](privacy-and-security.md).

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
(propagated across asyncio tasks; pass `parent_call_id` across threads and
processes) and its input and output bytes through a `ByteEvidenceRecorder`.

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
