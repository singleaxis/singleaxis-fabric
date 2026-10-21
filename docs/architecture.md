# Architecture

Fabric is a passive recorder for AI systems that runs entirely in your
infrastructure:

```text
CAPTURE  ->  PROTECT  ->  DELIVER
```

It records observable AI activity, protects the record before it leaves the
process and before it reaches disk, and delivers it to a store and an OTLP
destination you choose. It never blocks or alters the monitored system:
results and exceptions are unchanged, protection and export I/O stay off the
monitored call path, and instrumentation adds a small, measured overhead
(about 0.2 ms per call in our tests) plus a bounded drain at shutdown. It
does not evaluate, judge, score or control the system.

## Components

```text
┌──────────────────────── agent process (Python) ────────────────────────┐
│ app ─► httpx / httpx2 / aiohttp ─► model provider                      │
│          │ tee (bytes copied, never changed)                           │
│          ▼                                                             │
│   capture worker: match ─► extract parts ─► PROTECT ─► digest          │
│          ▼                                                             │
│   durable spool (fsync, AES-256-GCM) ─► sender thread ───────────────┐ │
│                                                                      │ │
│ app ─► explicit APIs: decision()/record_*, CallRecorder, adapters ──┐│ │
└─────────────────────────────────────────────────────────────────────┼┼─┘
                                                     spans (OTLP) ◄───┘│ content (OTLP logs)
┌──────────────────────────── Fabric Node ───────────────────────────────▼──┐
│ fabric-gate (refuses unsafe config) ─► otelcol-fabric                     │
│  otlp :4317/:4318 ─► fabricguard (allowlist, source binding) ─► queue ─►  ├─► OTLP destination
│  otlp/content :4319 ─► fabriccontent (descriptor checks, binding) ─► q ─► ├─► file dir or S3 (SSE)
│                        queue sealed by fabricenvelope                     │
└───────────────────────────────────────────────────────────────────────────┘
offline:  python -m fabric.reconstruct  (spans + store ─► integrity verdict)
```

### Capture

Two inputs exist in the Python SDK:

- **Wire capture** (`fabric.wire`, Python only). Enabled per process by
  `fabric.wire.install()` or by the autoload (`FABRIC_WIRE_AUTOLOAD=1` with
  the autoload directory on `PYTHONPATH`); installing the package enables
  nothing. It patches the default transports of `httpx` and `httpx2` and
  `aiohttp.ClientSession` requests, so it covers any client built on them:
  the official `openai` SDK (httpx in 1.x/2.x, httpx2 from 3.x, and its
  optional aiohttp client) and `anthropic` SDK (httpx2 from 1.x), LiteLLM
  and DSPy (aiohttp by default), and the frameworks that use them. A model
  call through `requests` or `urllib3` is not captured but is recorded as
  an `uninstrumented_client` loss. A request is matched by host and path (chat completions,
  responses, completions, embeddings, messages); its exact request and
  response bytes are copied on the transport and handed to a background
  worker. Nothing is parsed at capture time. Each call gets a source
  sequence number, so a missing record is detectable; losses are recorded
  as `fabric.capture_loss` and the end of a process as a `final` heartbeat.
  `fabric.wire.run(run_id)` brackets a run scope with start/end markers.
- **Explicit records**: what the application reports through the SDK
  (Python and TypeScript): `decision()` and its `record_*` methods, and in
  Python `CallRecorder` and the byte-boundary adapters, which record exact
  bytes the application passes. See [explicit APIs](explicit-apis.md).

Inside a live explicit model call the wire tee defers, so a call is
recorded once.

Optional Linux [host sensors](host-sensors.md) (auditd receiver, eBPF host
emitter) record process, connection and file metadata as corroboration.

### Protect

Protection happens in the agent, on the capture worker, **before** the spool:

- each object gets the privacy mode of its content role from the capture
  policy (`omit`, `metadata_only`, `redact`, `tokenize`, `masked_only`,
  `original_plus_masked`, `retain_original`); customer redaction is done by
  a redaction service you run beside the agent (Unix socket or loopback),
  never by code Fabric runs; a failure withholds the object;
- large JSON requests are split into a skeleton and extracted media parts,
  each protected separately;
- identifiers leave as keyed pseudonyms; telemetry carries ids, digests and
  allowlisted metadata only;
- the spool is encrypted with a customer key.

The production profile refuses to record content without a policy and
keys. The Node then enforces an exact-key allowlist (`fabricguard`), binds
every batch to one authenticated source, and seals its content queue and
file store. Details: [privacy and security](privacy-and-security.md).

### Deliver

- **Agent → Node.** A single sender thread drains the spool: it posts each
  body to the Node's content receiver, then exports its span, and deletes the
  record only when both were accepted. It retries until the Node accepts;
  records survive agent restarts.
- **Node → destinations.** Telemetry goes through a persistent, fsync'd
  queue to one OTLP/HTTP destination, with infinite retry and no redirects.
  Content goes through its own persistent queue to a directory or an
  S3/S3-compatible bucket with server-side encryption; objects are written
  once (`If-None-Match: *`) under `<prefix><tenant>/evidence/<object-id>`
  with a JSON descriptor beside each (a Node directory store shards these
  into hash-named subdirectories).
- Delivery is at least once; destinations deduplicate.

### Verify

Verification is a property of the record, not a runtime service:

- `python -m fabric.reconstruct` checks sequences, losses, heartbeats and
  run markers, re-reads every object and its digest, rebuilds runs from the
  stored bytes and states `complete_for_declared_scope`,
  `complete_for_observed_scopes`, `partial` or `unverified`. In the
  production profile it requires the Node's source-authentication stamp on
  trusted readback. See [reconstruct](reconstruct.md).
- [Qualified-run mode](qualified-run-mode.md) (opt-in, explicit line) adds
  independent witnesses and four signed receipt stages and is the only path
  to `verified_complete_for_declared_scope`.

## Profiles

`local` (development; `file://` store or an unauthenticated loopback Node)
and `production` (node mode; capture policy, id key and spool key required;
authenticated, single-source Node). See [deployment](deployment.md).

## What ships

| Artifact | Contents |
|---|---|
| Python SDK `singleaxis-fabric` | wire capture, explicit APIs, `fabric.reconstruct`, qualified-run verifier; extras `otlp`, `s3`, `mcp`, `signing` |
| TypeScript SDK `@singleaxis/fabric` | explicit APIs only (no wire capture); Node.js ≥ 20.6 |
| Fabric Node image `ghcr.io/singleaxis/fabric-otelcol` | `otelcol-fabric` with `fabric-gate`; components: `otlp` and `audit` receivers; `fabricguard`, `batch`, `memory_limiter` processors; `fabriccontent`, `otlphttp`, `debug` exporters; `health_check`, `file_storage`, patched `bearertokenauth`, `noredirect`, `fabricenvelope` extensions |
| Host emitter image `ghcr.io/singleaxis/fabric-host-emitter` | eBPF host sensor |
| Helm chart `fabric` | the Node, profiles `shadow-dev` and `shadow-production` |
| `fabricctl` | `init`, `recorder validate`, `recorder digest`, `version`, `help` for a local recorder configuration file |
| Public contracts | activity v2, connect v1, content v1, delivery v1, privacy v1, recorder v1 (published archive); capture v1, content v2, coverage v1, deployment-policy v1, evidence v1 and redaction v1 are in the repository as drafts |

Compose files for the Node are in `deploy/compose` (not a separate
artifact).

## What Fabric is not

Fabric OSS does not include evaluation, judges, guardrails, red-teaming,
escalation, policy engines, approval workflows, enforcement, analytics or a
management UI, and it never requires a SingleAxis service. Those consume
the record elsewhere ([AGENTS.md](../AGENTS.md)). Release artifact tests
keep removed capabilities out of every package and image.
