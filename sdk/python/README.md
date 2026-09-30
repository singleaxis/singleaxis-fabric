# SingleAxis Fabric recorder SDK for Python

The Python SDK adds passive OpenTelemetry activity capture to an AI agent. It
records enough identity and causal context to reconstruct model calls, tool
calls, retrieval, memory activity, side effects, delegation, retries and
failures. It does not block or alter the agent.

```text
CAPTURE -> PROTECT -> DELIVER
   ^
   |
Python SDK (optional instrumentation)
```

Protection and delivery happen in the customer-controlled Fabric Node. Raw LLM
content capture is disabled by default.

## Install

```bash
pip install singleaxis-fabric
```

Add OTLP export and only the integrations you use:

```bash
pip install "singleaxis-fabric[otlp,openai]"
```

## Capture one agent decision

```python
from fabric import Fabric, FabricConfig

fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="support-agent"))

with fabric.decision(session_id="session-42", request_id="request-7") as decision:
    with decision.llm_call(provider="provider-example", model="model-example") as call:
        # Invoke the customer's model client here.
        call.set_response(model="model-example")

    with decision.tool_call("lookup_order", call_id="tool-1") as tool:
        tool.set_arguments('{"order_id":"order-123"}')
        # Invoke the customer's tool here.
        tool.set_result('{"status":"shipped"}')
```

The SDK hashes tool payloads locally. It does not send telemetry by itself;
configure the OpenTelemetry provider/exporter used by the host application to
send to Fabric Node. For tests and small agents,
`fabric.install_default_provider(...)` wires a `TracerProvider` for you — pass
an exporter, or set `OTEL_EXPORTER_OTLP_ENDPOINT` with the `[otlp]` extra
installed and an OTLP exporter is constructed from the environment. Calling it
with neither produces spans that go nowhere (the SDK warns loudly rather than
dropping them silently).

`gen_ai.client.*` metrics (token usage, operation duration, time-to-first-token,
time-per-chunk, tool duration) are recorded on the global OpenTelemetry metrics
API. Without a `MeterProvider` installed they silently no-op — install an SDK
`MeterProvider` (for example one wired to an OTLP metric exporter) at process
level, pass `meter_provider=` to `install_default_provider`, or inject a `Meter`
via `Fabric(..., meter=...)`.

Use `Fabric.execution(...)` to correlate multiple decisions and the retrieval,
memory, side-effect, checkpoint, delegation and generic-interaction methods on
`Decision` to capture consequential activity beyond LLM and tool calls.

When a `ContentStore` (for example `LocalFilesystemContentStore` or
`S3ContentStore`) is passed to `Fabric`, recorder paths that receive raw
content — `remember`, `recall` and `record_side_effect` payloads — write it to
the tenant-controlled store and stamp the returned `fabric.content.*_ref` URI on
the emitted event. The trace stream then carries a governed reference an
auditor resolves out-of-band, never the raw bytes.

### Experimental explicit byte evidence (content v2)

For custom dispatchers, `CallRecorder` joins a call timeline to these protected
byte objects. It supports sync/async calls and pull-through streams, nested
calls and parallel agent identities. Install the wheel containing spec 043
before using this experimental API:

```python
from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, CallRecorder
from fabric import LocalFilesystemContentStore

store = LocalFilesystemContentStore("./protected-data", tenant_id="tenant-1")
writer = ByteEvidenceRecorder(ByteEvidenceConfig(
    store=store,
    roles=frozenset({"tool.call.arguments", "tool.call.result"}),
))
calls = CallRecorder(writer, run_id="run-1", agent_id="agent-1", source_id="dispatcher-1")
result = calls.call(
    b"exact-input", existing_tool_function,
    kind="tool", operation_id="lookup-1", attempt_id="try-1",
)
# Offline, after the monitored work: snapshot waits for local storage settlement.
record = calls.snapshot()
writer.close()
```

Configure your OpenTelemetry tracer as above to retain real trace IDs. Use
`acall` for async delegates, `stream` for iterators and `astream` for async
iterators. Close a stream explicitly when stopping early. Within a delegate,
`calls.record_data(bytes, role="artifact.after")` attaches approved file bytes
to that call; this helper does not independently observe filesystem changes.

`BytePrivacyPolicy` configures role-specific omission or a customer-supplied
masking callback. Original and masked review copies require separate store
namespaces; target access permissions still need deployment verification.
Masking occurs in the bounded background worker. A failing callback withholds
content and never falls back to raw export. It is not a built-in PII detector.

The offline `fabric.call_reconcile.reconcile_call_run` compares specific calls
and bytes against independent witness inputs. Matching local fixtures remain
`unverified`; missing or corrupt evidence becomes `partial`. The API has no
authenticated source or durable delivery receipt chain and its in-memory
timeline is not crash-durable. See [custom-agent recording](../../../docs/custom-agent-recording.md)
and [spec 043](../../../specs/043-custom-agent-call-recording.md).

The optional `fabric.qualified_run.verify_qualified_call_run` path is separate:
it checks signed independent feeds, exact original bytes, fresh sealed source
readback, source binding, route closure and four exact receipt sets. It can
verify a bounded submitted package for one source epoch under owner-provided
issuer authority. It does not supply production issuers or live storage
qualification. See [installed-package qualified tests](../../../docs/qualified-call-run-testing.md)
and [spec 046](../../../specs/046-qualified-call-run-verification.md).

The separate `ByteEvidenceRecorder` API captures bytes the caller explicitly
supplies. It does not intercept terminal, SSH, database or sandbox operations.

For a byte-oriented Python agent that already exposes its final model
transport or tool-call function, the optional
`fabric.adapters.byte_boundary.ByteBoundaryAdapter` provides a test-start
integration without replacing the delegate:

```python
from fabric.adapters.byte_boundary import ByteBoundaryAdapter

# Configure ByteEvidenceRecorder and SyntheticCaptureSession as in the
# bounded reference pilot; keep the protected store customer-controlled.
model = ByteBoundaryAdapter(session, kind="model", source_id="model-client-1")
response = model.call(
    final_request_bytes,
    existing_send_function,
    operation_id="model-call-1",
    attempt_id="attempt-1",
    context=approved_context_bytes,
)
```

`existing_send_function` receives the same byte object once; its result or
exception passes through unchanged. Instrument *after* the framework's last
serialization step. If that function or a lower client changes the request,
this is caller-side evidence, not proof of provider-bound bytes. Streaming,
async calls, unwrapped routes and external side effects are not captured by
this adapter. Reconcile against an independent endpoint/tool witness before
claiming coverage. The current session/source identity and receipt chain are
not production-qualified; see [spec 042](../../../specs/042-client-boundary-integration.md).

This is not a substitute for the terminal/artifact adapter or an installer
that discovers every route in a client's agent. A customer must declare and
test each reachable route separately.

An example observation is:

```python
from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, LocalFilesystemContentStore

store = LocalFilesystemContentStore("/private/fabric-content", tenant_id="acme")
recorder = ByteEvidenceRecorder(ByteEvidenceConfig(
    store=store,
    roles=frozenset({"artifact.after"}),
))
initial = recorder.capture(
    artifact_bytes,
    role="artifact.after",
    boundary="sandbox",
    source_id="sandbox-1",
    source_epoch=0,
    source_sequence=7,
    run_id="run-42",
)
recorder.flush()
settled = recorder.get(initial["object_id"])
recorder.close()
```

The store receives exact binary bytes and a per-observation v2 descriptor;
the descriptor uses `caller_reported` provenance. `pending` is only a
process-memory handoff, not durable storage. Only `stored` after `flush()`
confirms local store settlement. A bounded queue, payload cap and record
index report `dropped` rather than pretending coverage. Callers must publish
and reconcile settled descriptors independently; this experimental API does
not yet emit correlated OTLP events, delivery receipts or run-level coverage
manifests. It is not a compliance-grade complete-capture path.

## Stable recorder-v1 surface

The `fabric` package root exports capture, activity-correlation, governed
content-reference and integrity primitives only. Framework and provider
instrumentation remain optional extras.

It does not export or install judges, evaluation workers, guardrail engines,
prompt-time PII/NeMo controls, policy engines, tool authorization, escalation
enforcement or management-plane commands.

Recorder-v1 artifacts do not contain the former runtime-control, judge,
evaluation, policy, authorization or escalation modules. Their former
`Decision` methods and `Fabric` constructor parameters have also been removed;
this is an intentional breaking boundary so installing the recorder cannot put
enforcement behavior in an agent's request path.

See the
[SDK scope](https://github.com/singleaxis/singleaxis-fabric/blob/main/sdk/python/SCOPE.md)
and [recorder-v1 spec](https://github.com/singleaxis/singleaxis-fabric/blob/main/specs/027-recorder-v1.md)
for the authoritative boundary.

## Development

```bash
uv sync --all-extras --dev
uv run pytest
uv run ruff check src tests
uv run mypy src
```
