# Limitations and roadmap

This page lists what Fabric v0.8 does not do, the known defects found by
testing, and the work planned in
[spec 049](../specs/049-four-layer-capture-coverage.md) §8. If a capability
is not described in the other pages of this documentation set, assume it is
not built.

## What v0.8 does not capture

| Not captured | Why | What the record shows |
|---|---|---|
| TypeScript model calls at the wire | TypeScript wire capture (`undici`) is not built (spec 049 TS-1). TypeScript has only the explicit, app-reported APIs. | Nothing. Use the [explicit APIs](explicit-apis.md). |
| Python model calls through `aiohttp`, `requests`, `boto3` (including Bedrock), gRPC or raw sockets, or the OpenAI SDK's optional `DefaultAioHttpClient` | Only `httpx` and `httpx2` transports are teed. A client built on a custom transport is captured only if that transport is wrapped in `fabric.wire.WireTransport` / `AsyncWireTransport`. | Nothing. The call is invisible, and a run can still be `complete_for_declared_scope` for the calls that went through httpx (see below). |
| Endpoints other than chat completions, responses, completions, embeddings and messages | The endpoint matcher (`fabric/wire/_match.py`) recognises only those five APIs. Images, audio, moderations, rerank, fine-tuning, files, provider batch and realtime are not matched. | Nothing. |
| Model hosts you have not listed | Only `api.openai.com`, `api.anthropic.com` and `*.openai.azure.com` are matched by default. | Nothing, until you add the host with `FABRIC_WIRE_ENDPOINTS`. |
| HTTP headers, environment values, credentials | Privacy rule: never captured. | Nothing. |
| Hidden reasoning, local variables, provider-held state | Never crosses an observable boundary; Fabric never fetches provider-side state. | Only what appears in the request and response bytes. |
| Tool execution, subprocesses, databases, files, MCP servers, browsers | No capture point in v0.8 except what the application reports through the explicit APIs, and the optional [host sensors](host-sensors.md) (metadata only). | Only what the application reports, or host metadata. |

LiteLLM uses `aiohttp` by default, and so DSPy does too. Set LiteLLM's
`DISABLE_AIOHTTP_TRANSPORT=True` to move it onto httpx; the agent-matrix test
then captured every call.

**A `complete` verdict is scoped to instrumented clients.** In a test that
sent one call each through the OpenAI SDK (httpx), `requests` and `aiohttp`,
reconstruct reported `complete_for_declared_scope`: the httpx call was
captured and the other two left no record. Nothing in the record says that
uncaptured traffic happened. Read every verdict as "complete for the calls
that went through httpx/httpx2 to a matched endpoint".

## Known defects

These were found by the real-framework test matrix (18 single-process
framework rows, 152 local cases, 23 Node cases, 58 loss probes) run against
the release stack. In every case where calls were lost through an
instrumented client, reconstruct reported `partial`, `unverified` or no
run; it never reported `complete`.

| Defect | Effect | Status |
|---|---|---|
| **Multiprocessing worker pools lose calls.** Capture flushes from `atexit`; fork workers exit through `os._exit()` and a `with Pool()` block terminates workers before they export. | Fork pools lost all calls in local mode and 58–67% in node mode; spawn pools with `with Pool()` also lost calls. Only spawn with `pool.close(); pool.join()` passed. Reconstruct reports `unverified` (`tail_unverified`) for workers it can see and nothing for workers whose records never left. | Fix in progress. |
| **macOS fork with capture on can hang.** Fabric's background threads start at install; a `fork()` on macOS while they resolve system proxy settings aborts the child, and `Pool.map` then waits forever. Not observed when `HTTP(S)_PROXY` is set. | Breaks the passivity rule for fork-based pools on macOS. | Open; tracked with the multiprocessing fix. |
| **Large fan-out overflows the capture queue.** One worker thread protects and writes each side; the queue holds 256 items by default (`FABRIC_WIRE_QUEUE_MAX_ITEMS`). | 408 calls in about one second over loopback: 34% lost in local mode, 6% in node mode. Every loss is recorded as `fabric.capture_loss` (`queue_full`) and reconstruct reports `partial`. | Accounted for, not fixed. Raise `FABRIC_WIRE_QUEUE_MAX_ITEMS` for bursty workloads. |
| **A torn non-streamed response is `unverified`.** When the connection drops mid-body, the torn bytes are stored, but reconstruct classifies the side `unparsed_exchange` (`not_json`). A torn SSE stream is reported complete. | Conservative verdict; nothing is lost. | Open. |
| **Local file mode is not crash-durable.** Without a spool, spans leave through the batch exporter; a SIGKILL loses everything not yet exported. | Reconstruct reports no run (exit 2). | By design: use node mode with a spool for durability. |
| **`OTEL_SDK_DISABLED=true` disables capture silently.** | No span, no loss record. | Open. |

## Deployment limits

- **One agent source per production Node.** A production Node binds one
  tenant, one `fabric.source_id` and one ingress token. Agents with
  different source ids need one Node each; pods that share a Node must run
  with the same `FABRIC_SOURCE_ID`. A shared DaemonSet Node serving many
  independently identified pods cannot be a production Node in v0.8.
- **Zero-code capture cannot redact.** `redact`, `masked_only` and the
  review copy of `original_plus_masked` need a customer transformation,
  which is configured only through `fabric.wire.install(transformations=...)`.
  Under autoload those modes withhold the content (`protection_failed`).
  `tokenize`, `metadata_only`, `omit` and `retain_original` work zero-code.
- **`tokenize`, `metadata_only` and `omit` reconstruct as `unverified`.**
  The verifier cannot parse or digest-check an original it was not given.
- **POSIX only for production.** Node mode needs a POSIX spool (`fcntl`),
  so it does not run on Windows; there, every customer transformation also
  withholds its content.
- **`make verify-prod` authenticated check.** It posts a fixture trace whose
  tenant is `harness`; a source-bound production Node refuses it unless
  your tenant is `harness`. Its unauthenticated-refusal checks are valid.
  (Found by reading the code; not yet confirmed on a running Node.)
- **Host sensors cannot feed a production Node** (see
  [host sensors](host-sensors.md)).
- **Delivery is at least once.** Destinations must deduplicate. Fabric does
  not prove that a destination durably persisted a record.
- **Host sensors are corroboration only** and are not enterprise-qualified
  ([host sensors](host-sensors.md)).

## Production qualification

Fabric v0.8 has been tested on a developer workstation and in CI (unit,
installed-package, Compose and kind tests). No customer production
deployment has been qualified. Before production, run the tests in
[deployment](deployment.md) against your own Node, store and agents, and
read [privacy and security](privacy-and-security.md).

## Roadmap (spec 049 §8)

Spec 049 describes the record in four layers: context, structure, content,
and decisions and effects. v0.8 delivers phase **P0-A** (the content path
and privacy gate) on top of the 047/048 wire line. The rest is not built.

| Phase | What it adds | Status |
|---|---|---|
| P0 | Coverage contract freeze (`contracts/coverage/v1`) | Contracts published; no run-level coverage report yet |
| P0-A | PROTECT stage, production profile gate, encryption at rest, source authentication, typed extraction, pseudonym v2 | **Built in v0.8** |
| P1 | One allocator and spool for both inputs, `event_id`, segment chaining and resume tokens, the step projection (`fabric.step-projection/v1`) and per-layer verdicts | Not built |
| P1-A | Mixed explicit + wire capture qualification, passivity harness | Not built |
| P2 | Run context and lifecycle reporting (`record_trigger`, `record_input`, `record_run_context`, `record_outcome`, ...) | Not built |
| P3 | Decision and effect records: observations of controls run by other systems, commit state, receipts. Record-only: Fabric never approves, blocks or waits | Not built |
| P4 | Opt-in hooks for MCP clients, subprocesses, DB-API, non-model HTTP, file audit | Not built |
| P5 | Realtime/websocket, provider batch and files, media, UI automation | Not built |
| TS-1 | TypeScript wire capture on `undici` (Node.js 24+) | Not built |

Out of scope for Fabric OSS at every phase: evaluation, judging, scoring,
guardrails, escalation, blocking or modifying agent actions, policy engines
and approval orchestration ([AGENTS.md](../AGENTS.md)).
