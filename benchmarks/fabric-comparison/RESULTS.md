# Executed results: 2026-10-02

## Bottom line

Fabric matched the tested open-source capture scopes. This benchmark does **not**
establish market-wide superiority or easier onboarding. Both auto integrations
needed one startup registration and zero edits at individual provider call sites.
Both captured all four provider attempts. Explicit Fabric and OTel each captured
all six wrapped attempts, including real file/process actions. None captured the
unwrapped seventh action, which the separate witness exposed.

The benchmark found and helped fix a concrete Fabric setup/privacy problem:
its provider auto extra needed compatible dependency pins, and input/output
hiding alone did not protect exception text on a host-owned exporter. Fabric's
new managed exporter passed the actual error-canary test. A custom standard OTel
exception-redacting exporter also made OpenInference pass. The difference is
safe defaults and configuration ownership, not that baseline protection is
impossible.

## Recorded runs

- 11 randomized warmed samples per mode: 55 normal subprocess runs
- Four first-export failure runs and four abrupt-exit-before-flush runs
- 15 separate real subprocess regression tests passed
- Identical independently witnessed workload in every normal sample
- No Fabric source changes during the final timed run
- All benchmark Python file hashes matched after the run
- Tested Fabric Python source-tree hash: `6c30a07e663971306b71cdadaa2f648017736e49be20c04696c2532a29252c5a`

The full package versions, source-file hashes, individual measurements,
randomization seed and uncertainty summaries are in `evidence/metrics.json`.
Representative raw spans, local snapshots and independent truth are in
`evidence/representative/`; all 63 final run directories are in `evidence/raw-final/`.
All content is synthetic. Final source identity was rechecked after the 15
regressions and both protected-route probes passed again; see
`evidence/representative/protected-provenance.json`.

## Matched capture and latency

| Mode | Captured / declared boundary attempts | Median workload ms | Range ms |
|---|---:|---:|---:|
| Uninstrumented | 0 / 0 | 25.594 | 18.820–35.348 |
| OTel explicit wrapper | 6 / 6 | 27.875 | 21.488–36.828 |
| Fabric explicit CallRecorder | 6 / 6 | 33.625 | 21.318–43.644 |
| Fabric provider auto, host-owned exporter | 4 / 4 | 25.386 | 19.853–38.784 |
| OpenInference provider auto | 4 / 4 | 36.170 | 28.304–47.762 |

**No established repeatable speed winner.** In this final run, the estimated
Fabric-minus-OTel explicit median difference was +5.751 ms, with an unpaired
bootstrap 95% interval of [0.027, 10.182] ms. Fabric-auto minus OpenInference-auto
was -10.784 ms, interval [-15.499, -1.073] ms. Thus this run favored OTel explicit
and Fabric auto. Two earlier source revisions had much smaller differences and
both matched intervals crossed zero; their complete metrics are preserved in
`evidence/prior-runs/`. They are historical observations, not measurements of the
final source. Repeated local runs therefore did not establish a stable advantage.

These small HTTP-dominated workloads ran in a shared build container. Concurrent
build/test activity and scheduler noise were not controlled in this final run;
its bootstrap intervals do not account for that confounding. These are neither
throughput nor production latency qualification results. We publish the latest
exact-source measurements rather than select the most favorable trial.

Both auto rows exported model/token semantics; the explicit generic dispatch
wrappers do not infer those provider-specific semantics. Both explicit adapters
exposed the opaque operation/attempt IDs in their records. Fabric's local
snapshot IDs are not automatically identical to exported span attributes.

## Privacy and safe defaults

The prompt, successful completion and 503 error message contain the same
synthetic canary. All measured host-provider auto runs kept that canary out of
normal input/output attributes but exported it from error telemetry. This
happened in **both** Fabric-auto and OpenInference-auto. OpenInference's documented
hide-input/output flags do not promise to redact exception events/descriptions;
this is a configuration boundary, not a vendor-wide vulnerability finding.

Separate functional probes (not folded into the latency comparison):

- Fabric's managed provider: 4/4 exported, error status retained, no raw canary.
  Model/span/resource text is hashed or withheld by its broader managed policy.
- OpenInference plus `exception_redaction.py`: 4/4 exported, error status
  retained, no raw canary. This standard OTel exporter extension strips exception
  events and status descriptions. It preserves readable model metadata, but is
  an application-owned narrow redactor, not a general sensitive-data detector.

Fabric deliberately does not replace or silently sanitize an existing host's
exporters. Those exporters require their own protection configuration.

## Failure and restart boundaries

Every instrumented matched mode observed its expected local records, but a
first-export FAILURE left one fewer sink record (5/6 explicit; 3/4 auto). The
external sink witness exposed this. A local CallRecorder snapshot is not proof
that trace delivery succeeded; Fabric's local recording gap count stayed zero.

All four matched modes lost their unflushed batch on abrupt process exit: seven
witnessed actions, zero exported spans. This tier has no durable journal or
collector configured. We did **not** run a durable recovery/replay comparison,
and this result is not attributed to configured durable Fabric or competitor
pipelines. No automatic completeness claim was inferred from silence.

## Actual setup friction and integration cost

Fresh registry resolution installed OpenAI3.24.0 and OpenAI instrumentor2.4b0.
Fabric auto startup first failed because `httpx` was missing (OpenAI used
`httpx2`), then because util-genai1.2b0 lacked a module imported by the instrumentor.
Adding httpx0.28.1 and pinning util-genai0.4b0 restored the real integration.
`pip check` passed. Fabric's OpenAI extra was updated with the compatible set.

`integration-cost.json` gives actual executed installation commands and counted
code fragments. In this fixture, OpenInference's startup adapter is 7 physical
nonblank lines and Fabric's is 11 including its enable-result check. Both have
zero changed provider dispatch sites. Explicit Fabric has 32 startup lines and
a 3-line dispatch call; the OTel wrapper uses the common tracer plus 19 wrapper
lines. These are this fixture's physical source lines, including formatting and
imports. They are not minimum possible integration sizes or human onboarding
measurements. Exporter setup is common and separately disclosed.

The tested versions are OpenInference OpenAI0.1.63, OTel SDK1.45.0, OpenAI3.24.0,
OpenAI-v2 instrumentor2.4b0, util-genai0.4b0 and httpx0.28.1. The lock contains the
complete dependency set; none of these rows evaluates a hosted vendor backend.

## Iterations and remaining work

An early trial inherited the container's 1% OTel sampler; that invalid trial is
excluded. The final harness forces ALWAYS_ON everywhere. We added warmed runs,
local-observer versus received-export counts, source fingerprints, error-canary
coverage, independent operation joins, explicit dependency checks, both real
auto paths, and equivalent configurable exception protection, then reran.

Still untested: production providers/backends, long streams, high-volume
throughput, durable restart recovery, native privileged host capture, fleet
installation, and end-to-end service receipts. No Langfuse, Datadog, Phoenix
backend or AgentSight kernel deployment was run. These require separate matched
adapters/deployments; the SDK comparison cannot establish a market-wide claim.
