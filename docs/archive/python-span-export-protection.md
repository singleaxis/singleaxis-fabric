# Python managed span export: protection and limits

`fabric.install_default_provider()` installs a Fabric-managed
`TracerProvider` whose export route is metadata-only by default. Upstream
`capture_content=False` switches in other instrumentation are not a privacy
boundary: a real OpenAI error in an earlier local SDK benchmark still placed
the synthetic private canary in an exception event/status description.
Fabric's managed export route suppresses that raw content before the
exporter sees it.

```sh
python -m pip install 'singleaxis-fabric[otlp]'
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
# Choose sampling explicitly. Use always_on when measuring attempt coverage.
export OTEL_TRACES_SAMPLER=always_on
```

```python
from fabric import install_default_provider
from fabric.tracing import trace_export_protection_status

# Must run before the application installs another global TracerProvider.
provider = install_default_provider(capture_content=False)

# Run the application here.
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

`trace_export_protection_status()` reports:

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

`FABRIC_CAPTURE_LLM_CONTENT` never affects LLM wire capture
([spec 047](../specs/047-llm-wire-capture-and-reconstruction.md)): wire stores
exact bytes off telemetry in the customer store and its spans carry only
digests and references, whatever this flag says. Installing wire while the
flag is set logs one warning saying so. A global provider protected by
`install_default_provider` never carries wire spans; see
[Two capture lines](README.md#two-capture-lines).
