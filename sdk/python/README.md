# SingleAxis Fabric SDK for Python

`singleaxis-fabric` records what a Python AI agent does, protects the record
inside the process before it reaches disk, and delivers it to storage you
own. It never blocks, alters or delays the agent.

```text
CAPTURE -> PROTECT -> DELIVER
```

It provides:

- **Zero-code wire capture** (`fabric.wire`): the exact request and response
  bytes of every model call sent through `httpx`, `httpx2` or `aiohttp`,
  which covers the official `openai` and `anthropic` SDKs, LiteLLM, DSPy
  and frameworks built on them.
- **Explicit APIs**: `Fabric.decision()` and its `record_*` methods,
  `ByteEvidenceRecorder`, `CallRecorder` and byte-boundary adapters, for
  activity the application reports itself.
- **`python -m fabric.reconstruct`**: an offline verifier that states
  whether each run's record is complete and unaltered.
- **Qualified-run mode** (`fabric.qualified_run`): opt-in, receipt- and
  witness-backed verification for the `CallRecorder` line.

Requires Python 3.11+. Linux and macOS; node mode (the production profile)
needs POSIX.

## Install

```bash
pip install "singleaxis-fabric[otlp]"
```

Extras: `otlp` (OTLP exporter and spool encryption; needed for node mode),
`s3` (boto3, for reading an S3 store with `fabric.reconstruct`; agents never
need it), `mcp` (MCP client instrumentation), `signing` (Ed25519 for
qualified-run mode). Wire capture uses whichever of `httpx`, `httpx2` and
`aiohttp` your application already installs.

## Zero-code wire capture

Installing the package enables nothing. Turn capture on per process:

```bash
export PYTHONPATH="$(python -m fabric.wire --print-autoload-path)${PYTHONPATH:+:$PYTHONPATH}"
export FABRIC_WIRE_AUTOLOAD=1
```

then choose where records go:

- **Local profile** (development): `FABRIC_WIRE_STORE=file:///abs/dir`,
  `FABRIC_TENANT_ID`, and an OTLP endpoint for the spans
  (`OTEL_EXPORTER_OTLP_ENDPOINT`).
- **Production profile** (node mode): `FABRIC_WIRE_CONTENT_ENDPOINT`,
  `FABRIC_WIRE_SPOOL_DIR`, `FABRIC_TENANT_ID`, `FABRIC_SOURCE_ID`, the Node's
  OTLP endpoint and credentials, plus `FABRIC_CAPTURE_POLICY`,
  `FABRIC_WIRE_ID_KEY` and `FABRIC_WIRE_SPOOL_KEY`. Without the policy and
  keys content capture is disabled (metadata continues) and every span says
  why.

Or install from code:

```python
from fabric import wire

wire.install_from_env()           # what the autoload does; None (one warning) if invalid
with wire.run("order-1234"):      # optional run scope, emitted as an r- pseudonym
    ...                           # model calls here are captured
wire.flush()                      # optional; capture also drains at exit
```

`wire.install(...)` takes the same settings as keyword arguments (`store=`,
`content_endpoint=`, `transformations=`, ...) and raises on an invalid
configuration.

Matched by default: `api.openai.com`, `api.anthropic.com`,
`*.openai.azure.com`; add other hosts with `FABRIC_WIRE_ENDPOINTS`. Matched
APIs: chat completions, responses, completions, embeddings, messages.
`aiohttp` calls are captured too (`FABRIC_WIRE_AIOHTTP=0` turns that off).
A model call through `requests` or `urllib3` is not captured; it is
recorded as an `uninstrumented_client` loss, so its run is `partial`.

Verify offline:

```bash
python -m fabric.reconstruct --spans <span files> --store-root <store> --tenant <tenant>
```

See the [quickstart](../../docs/quickstart.md),
[deployment](../../docs/deployment.md) and
[reconstruct](../../docs/reconstruct.md).

## Explicit APIs

```python
from fabric import Fabric, FabricConfig, install_default_provider

install_default_provider(service_name="my-agent")  # metadata-only exporter from OTEL_EXPORTER_OTLP_ENDPOINT

fabric = Fabric(FabricConfig(tenant_id="demo", agent_id="my-agent"))

with fabric.decision(session_id="session-1", request_id="request-1") as decision:
    with decision.llm_call(provider="openai", model="gpt-4o-mini") as call:
        call.set_usage(input_tokens=5, output_tokens=6, finish_reason="stop")
    with decision.tool_call("lookup_order", call_id="tool-1") as tool:
        tool.set_arguments('{"order_id": "order-123"}')
        tool.set_result('{"status": "shipped"}')
```

Payloads are hashed, not recorded. Session, user and similar ids are
emitted as keyed pseudonyms and omitted without `FABRIC_WIRE_ID_KEY`
(`FABRIC_IDENTITY_MODE=clear` emits them unchanged).

`CallRecorder` records exact bytes at your dispatcher's final model and
tool boundaries, with call, attempt and stream identity:

```python
from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, CallRecorder, LocalFilesystemContentStore

recorder = ByteEvidenceRecorder(ByteEvidenceConfig(
    store=LocalFilesystemContentStore(root="./evidence", tenant_id="demo"),
    roles=frozenset({"model.request.messages", "model.output.messages"}),
))
calls = CallRecorder(recorder, run_id="run-1", agent_id="support-agent", source_id="host-a")
reply = calls.call(request_bytes, send_to_model, kind="model")
recorder.close()
```

Privacy is set per content role (`BytePrivacyPolicy`, or a
`DeploymentPolicy` with `ContentProtector`). Masking is done by a
redaction service you run beside the application
(`FABRIC_REDACTION_ENDPOINT`, a Unix socket or loopback port; protocol
`contracts/redaction/v1`); you name the transformation by id and version.
Fabric runs no customer code, and a failure withholds the content.

Full reference: [explicit APIs](../../docs/explicit-apis.md),
[privacy and security](../../docs/privacy-and-security.md),
[qualified-run mode](../../docs/qualified-run-mode.md).

## Not in this package

Framework adapters and auto-instrumentation extras were removed in v0.8;
wire capture replaces them. The package contains no evaluation, scoring or
control code, and nothing in it can block or change an agent's request. See
[limitations](../../docs/limitations-and-roadmap.md) and the
[changelog](../../CHANGELOG.md).

## Development

```bash
uv sync --all-extras --dev
uv run pytest
uv run ruff check src tests
uv run mypy src
```
