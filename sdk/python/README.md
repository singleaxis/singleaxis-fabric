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

The separate `ByteEvidenceRecorder` API captures bytes the caller explicitly
supplies. It does not intercept terminal, SSH, database or sandbox operations.
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
