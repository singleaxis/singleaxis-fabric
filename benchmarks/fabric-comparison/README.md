# Matched local instrumentation comparison

This is an executable SDK-level comparison, not a vendor scorecard or proof that
Fabric is better than the market. It runs actual installed open-source packages.
It does not run Phoenix, Langfuse, Datadog, any hosted backend, a collector, native
host instrumentation, or a production application. No accounts or real API keys
are used. All provider traffic is loopback and all content is synthetic.

## Reproduce

From repository root, with Python 3.12:

```sh
python3 -m venv /tmp/fabric-comparison
/tmp/fabric-comparison/bin/pip install -r benchmarks/fabric-comparison/requirements.lock.txt
PYTHONPATH="$PWD/sdk/python/src" /tmp/fabric-comparison/bin/python benchmarks/fabric-comparison/run.py --samples 11 --output /tmp/fabric-comparison-results
PYTHONPATH="$PWD/sdk/python/src" /tmp/fabric-comparison/bin/python -m pytest -q benchmarks/fabric-comparison/test_benchmark.py
```

The harness and dependencies live outside the product runtime. A clean output
directory is required. Install only from the official package registry. The lock
file freezes the actual tested dependency set; it does not claim these are the
only supported versions. Fabric is loaded from source so its exact file hashes
are recorded in metrics.json, alongside package versions, Python/platform,
benchmark source hashes, randomization seed and individual samples.

## Fair comparison boundaries

- `none`: identical application and independent witness, no instrumentation.
- `otel-explicit` versus `fabric-explicit`: same manually wrapped final dispatch
  and same caller-supplied operation/attempt IDs. OTel emits metadata-only spans;
  Fabric CallRecorder additionally maintains its bounded in-memory timeline and
  policy-withheld byte descriptors. Both suppress raw exception text. Neither
  configures durable telemetry delivery or content persistence.
- `fabric-auto` versus `openinference-auto`: provider SDK auto-instrumentation,
  no modified dispatch call sites. Fabric uses its supported OpenAI extra and
  enable_auto_instrumentation helper. OpenInference uses OpenAIInstrumentor with
  hide_inputs=True and hide_outputs=True. These are provider-scope integrations;
  they do not claim arbitrary filesystem/process interception.

Both auto rows use the same provider and sink as explicit rows. Every provider
uses ALWAYS_ON sampling, not the host environment's inherited sampler. Application
latency includes local synchronous export for *every* nonempty mode. All runs use
the same sink observer and local JSON-lines serialization. There is no network
export latency, remote ACK, cost, or backend ingestion measurement. Randomized
mode order and independent interpreters prevent cross-instrumentor monkey-patch
contamination. One untimed model request warms each normal worker. Setup/import
cost is reported separately; process startup is outside the workload timer.

## Workload and independently observed truth

Each sample makes one successful provider call, a 503 physical attempt and its
successful explicit retry, a wrapped file write/read, a wrapped real subprocess,
a background-thread provider call and one deliberately unwired file write.
The OpenAI SDK uses max_retries=0 so retry counts cannot be confused with logical
calls. A loopback HTTP server records physical requests independently of the
instrumentation adapter. File bytes are read back and child stdout/exit checked.
There are seven observed actions, six explicitly wrapped or four provider calls.
The bypass is outside the declared wrappers, not a secret missing action counted
against the provider instrumentor's scope. The external inventory is necessary
to notice it. This is independent application-level observation, not an OS audit
or hostile-process-resistant witness.

Normal runs report actual spans, local Fabric records, statuses, model/token
attributes, operation identities, and inventory misses. Raw per-run spans,
Fabric snapshots, HTTP/file/process truth, and stderr are kept in output. No
percentage based on raw span count is described as all-activity completeness.
Fabric snapshots and trace exports are distinguished: snapshot IDs do not imply
that identical IDs appeared as exported span attributes.

The privacy canary is placed in prompt, completion and the provider's 503 error
message. Input/output hiding alone is not assumed to cover exceptions, invocation
parameters or arbitrary user metadata. The explicit adapters intentionally don't
record exception text. Any auto exception leak is attributed to that tested
configuration, never generalized to the hosted product or compared as equivalent
to an explicit wrapper's exception policy.

## Fault and performance limits

`export-first-failure` returns FAILURE from the common sink on its first export;
observed local spans and received sink records are counted separately. There is
no custom retry added to favor any adapter. `crash-before-flush` uses the same
BatchSpanProcessor for every instrumented row, a long delay, and os._exit(23)
after truth is persisted. It measures loss before in-memory batch flush, not
replay after a configured durable journal restart. Durable Fabric pipelines and
collector-backed competitor pipelines need a separate matched tier.

Latency samples include the workload's child-process launch and local HTTP work
and are noisy; the harness's worker-interpreter startup is excluded. The
unpaired bootstrap interval is descriptive for this one machine/run; it is not a
production SLA or statistically controlled market-wide speed ranking. Do not
choose a winner from small median differences or negative measured overhead.
Neither setup source lines nor command counts establish human onboarding time.

## Sources checked

- https://arize-ai.github.io/openinference/spec/configuration.html
- https://arize-ai.github.io/openinference/python/
- https://opentelemetry.io/docs/languages/python/exporters/
- https://opentelemetry.io/docs/languages/python/instrumentation/
- Fabric sdk/python/src/fabric/auto_instrument.py and call_recorder.py

## Deliberately blocked or not tested

Hosted/backend retention/search, distributed causal closure, independently
attested native host inventories, privileged eBPF/audit, service receipts, fleet
setup, real providers, durable restart replay and production throughput are not
covered. They require their own adapters, host permissions, deployment and where
applicable authorized credentials. Adding an adapter must preserve the same
workload/witness and declare boundaries, privacy, sampling and delivery tier.

## Protected-route probes

These are functional privacy probes, separately labeled because the managed
Fabric route owns a BatchSpanProcessor while the host-provider baseline uses a
SimpleSpanProcessor. They are not added to the matched latency ranking.

```sh
PYTHONPATH="$PWD/sdk/python/src" /tmp/fabric-comparison/bin/python benchmarks/fabric-comparison/run.py --worker --mode fabric-auto --managed-provider --work /tmp/fabric-managed-probe
PYTHONPATH="$PWD/sdk/python/src" /tmp/fabric-comparison/bin/python benchmarks/fabric-comparison/run.py --worker --mode openinference-auto --redact-exceptions --work /tmp/openinference-protected-probe
```

The first uses Fabric's actual managed default exporter protection. The second
uses an application-owned ordinary OTel SpanExporter wrapper in
exception_redaction.py; it removes exception events/status descriptions before
the sink. It is not presented as an OpenInference built-in setting or a full PII
filter. Both can make the tested error-message canary safe. The managed Fabric
policy additionally hashes many textual fields, sacrificing readable model/span
names. Existing host exporters remain outside Fabric's ownership/protection.

`integration-cost.json` includes actual setup commands and counted source
fragments from adapters.py. The runtime's first auto-extra install failed with
OpenAI3.24.0 because httpx was absent (the new SDK brought httpx2). Adding httpx
revealed incompatible latest opentelemetry-util-genai1.2b0 with
opentelemetry-instrumentation-openai-v2 2.4b0. Pinning util-genai0.4b0 restored real
instrumentation. These findings prompted Fabric's extra to include the verified
compatible dependencies. Neither auto adapter needed individual provider-call
edits. This does not prove Fabric is easier than OpenInference.

Unmatched action IDs mean the exported/local records could not be joined using
the available opaque IDs; this is not automatically proof the action was
uncaptured. In particular, Fabric's provider auto spans preserve provider
semantics but do not carry this fixture's caller-supplied attempt IDs. OTel's
explicit adapter and Fabric's local CallRecorder timeline carry those IDs. The
provider auto rows' physical-attempt counts are checked separately.
