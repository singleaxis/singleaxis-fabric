# Python auto capture: protected setup and limits

Install a supported upstream hook, then configure protection before registering
it. Upstream `capture_content=False` switches alone are not a privacy boundary:
a real OpenAI error in the local SDK benchmark still placed the synthetic
private canary in an exception event/status description. Fabric's managed
export route suppresses that raw content before the exporter sees it.

```sh
python -m pip install 'singleaxis-fabric[openai,otlp]' 'openai==3.24.0'
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
# Choose sampling explicitly. Use always_on when measuring attempt coverage.
export OTEL_TRACES_SAMPLER=always_on
```

```python
from fabric import install_default_provider
from fabric.auto_instrument import enable_auto_instrumentation_with_manifest
from fabric.tracing import trace_export_protection_status

# Must run before the application installs another global TracerProvider.
provider = install_default_provider(capture_content=False)
manifest = enable_auto_instrumentation_with_manifest(
    required=["openai"], only=["openai"], capture_content=False,
)
print(manifest.to_dict())

# Invoke the application's normal OpenAI client here.
# Flush at an appropriate shutdown boundary, not after every model request.
provider.force_flush()
print(trace_export_protection_status())
provider.shutdown()
```

An explicit `exporter=` can replace the environment-configured OTLP destination.
No configured exporter means `NO_EXPORTER` and a warning, not successful capture.
The managed provider uses `BatchSpanProcessor`; its in-memory queue is not the
source journal, durable delivery or a receipt. Sampling and SDK queue loss remain
separate coverage limits.

## What the managed span route retains

- Trace, span, parent and linked-span numeric IDs, trace flags, span kind,
  start/end times and status codes survive. Tracestate does not.
- An exact key allowlist admits finite numeric/signed-int64 and boolean metadata
  only under its expected type. Numeric token usage survives.
- A small fixed semantic vocabulary, such as `gen_ai.operation.name=chat` and
  `gen_ai.provider.name=openai`, stays readable. Other allowed string values and
  string-array elements become deterministic `sha256:` values. This includes
  service/model/tool identifiers and content references.
- Span and instrumentation-scope names are fixed. Their original names have
  hash attributes. Scope attributes/versions/schema URLs, span events (including
  exception details), status descriptions, unknown attributes and resource
  schema URLs do not pass through.
- String-array metadata is limited to 32 entries and each hash input to 4,096
  characters. Oversize attributes are dropped; oversize span/scope names have
  no original-name hash. Both cases have explicit counters. This is not an
  aggregate OTLP batch-byte limit; standard SDK queue/link/attribute bounds
  remain relevant.
- Source spans are not mutated. A malformed span is dropped without raw fallback
  or exception text in Fabric's diagnostic. Exporter failures are reported with
  fixed diagnostics and failure counters.

Hashes are pseudonymous, correlatable and potentially guessable. This is raw
content suppression, not anonymization, PII detection, credential discovery or
an information-flow guarantee. A trace `fabric.content.*ref` becomes a hash and
is no longer a usable content-resolver pointer. The separate byte/journal and
metadata-delivery paths are unaffected; do not enable raw trace content just to
recover resolver references.

## Inspect the actual boundary

`trace_export_protection_status()` and
`manifest.to_dict()["trace_export_protection"]` report:

- `PROTECTED_METADATA_ONLY`: the inspected routes all use Fabric's projection
- `CONTENT_OPT_IN`: a managed route explicitly bypasses the projection
- `UNPROTECTED_HOST_ROUTES`: at least one processor/exporter belongs to the host
- `NO_EXPORTER`: the SDK provider has no export route
- `UNKNOWN`: the current provider cannot be inspected

The report names its `basis` as `current_process`, counts protected, content-opt-in
and host routes, and includes projection/drop/hash/failure counters. Exported
spans also carry `fabric.protection.*` counts. Projection counts are attempted
projections, not destination acceptance or delivery receipts.

A fresh CLI doctor process cannot inspect the application's live provider. Its
unknown/unconfigured trace route does not prove the separate byte pipeline is
broken, and its local readiness does not attest that another process's trace
exporters are protected. Run this helper in the application and exercise a
canary through its real exporter to establish that route's behavior.

Existing SDK providers are returned unchanged with a warning when
`install_default_provider()` is called late. An already installed non-SDK host
provider raises a fixed setup error; a rejected global installation is also
detected. The helper cannot return an unused provider that misleadingly appears
protected. Initialize before starting request producers. Fabric does not wrap, replace or
silently modify their exporters. A host processor added later is likewise outside
the managed route. Other logs, metrics, instrumentation and network paths require
their own protection. In particular, this helper does not install a protected
OTel log or metric exporter.

## Explicit content opt-in

The default is metadata-only. `capture_content=True` on
`install_default_provider()` bypasses its projection and may export prompts,
credentials and raw exception text. The omitted argument reads
`FABRIC_CAPTURE_LLM_CONTENT`; an explicit `False` overrides that environment
flag. Only actual booleans are accepted, so the string `"false"` cannot become a
truthy privacy bypass.

The separate `enable_auto_instrumentation(capture_content=True)` call enables
upstream content capture. It does not change an already installed managed
exporter's privacy mode. Both controls must intentionally allow content for
prompt/completion content to pass that route. Fabric's upstream content setting
overrides stale upstream environment values on each registration call.

## Verified dependency combination

The Python `[openai]` extra pins `opentelemetry-instrumentation-openai-v2==2.4b0`
and `opentelemetry-util-genai==0.4b0`, and supplies `httpx>=0.28.1,<1`.
The real loopback fixture used OpenAI `3.24.0`, HTTPX `0.28.1` and OTel `1.45.0`.
The provider SDK is installed separately. This combination was also installed
into a new isolated environment with no dependency conflicts.

Why these constraints: instrumentor `2.4b0` imports
`opentelemetry.util.genai.instruments`, absent from util-genai `1.2b0`, and imports
`httpx` even when the OpenAI SDK uses `httpx2`. An unconstrained upstream install
failed before activation. These are scoped dependency findings, not claims about
all earlier/later versions or other provider families. Updating the pin requires
rerunning actual-provider success, error, streaming and privacy probes.

The local managed fixture exported all four expected provider attempts, retained
the error status and numeric usage, and exported no synthetic raw canary. Its
host-owned-exporter variant still exposed the upstream error canary, documenting
the ownership boundary. These local fixtures are not production qualification
or universal capture evidence.

The tuple API reports only an explicit upstream active flag. The manifest keeps
missing packages, installed-but-broken dependencies, no-op registration and
unobservable activation distinct. `ACTIVE` means reported hook activation, not
proof that the application's request route is captured.
