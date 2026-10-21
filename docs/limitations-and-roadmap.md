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
| Python model calls through `requests` or `urllib3` | Only `httpx`, `httpx2` and `aiohttp` are teed. | An `uninstrumented_client` loss per matched call (method and URL only are read): the run is `partial`, and `WireHandle.status()` lists the client under `uninstrumented_clients`. |
| Python model calls through `boto3` (including Bedrock), gRPC or raw sockets, an httpx client on a custom transport not wrapped in `fabric.wire.WireTransport` / `AsyncWireTransport`, or any client with `FABRIC_WIRE_AIOHTTP=0` (aiohttp) | Not teed. `boto3` sends through urllib3, but Bedrock hosts are not matched by default. | Nothing. The call is invisible, and a run can still be complete for the calls that were captured (see below). |
| Endpoints other than chat completions, responses, completions, embeddings and messages | The endpoint matcher (`fabric/wire/_match.py`) recognises only those five APIs. Images, audio, moderations, rerank, fine-tuning, files, provider batch and realtime are not matched. | Nothing. |
| Model hosts you have not listed | Only `api.openai.com`, `api.anthropic.com` and `*.openai.azure.com` are matched by default. | Nothing, until you add the host with `FABRIC_WIRE_ENDPOINTS`. |
| HTTP headers, environment values, credentials | Privacy rule: never captured. | Nothing. |
| Hidden reasoning, local variables, provider-held state | Never crosses an observable boundary; Fabric never fetches provider-side state. | Only what appears in the request and response bytes. |
| Tool execution, subprocesses, databases, files, MCP servers, browsers | No capture point in v0.8 except what the application reports through the explicit APIs, and the optional [host sensors](host-sensors.md) (metadata only). | Only what the application reports, or host metadata. |

LiteLLM and DSPy send through `aiohttp` by default; that path is captured
(capture point `wire.py.aiohttp`, on whenever wire capture is installed;
`FABRIC_WIRE_AIOHTTP=0` turns it off). In the agent-matrix test DSPy's
default path was then captured, locally and through a Node.

**A `complete` verdict is scoped to instrumented clients.** In a test that
sent one call each through the OpenAI SDK (httpx), `aiohttp`, `requests` and
raw `urllib3`, the httpx and aiohttp calls were captured, the other two
became `uninstrumented_client` losses and reconstruct reported `partial`.
Clients that are neither teed nor detected (`boto3`, gRPC, other
processes) still leave no record. Read every verdict as "complete for the
calls that went through httpx, httpx2 or aiohttp to a matched endpoint".

## Known defects

The real-framework test matrix (18 single-process framework rows, local and
Node cases, and loss probes) was rerun after the multiprocessing, aiohttp
and capture-queue fixes listed below; the disk-full, throughput and
reconstruct fixes were tested by their own suites and benchmark. Wherever calls were lost through an instrumented client,
reconstruct reported `partial`, `unverified` or no run; it never reported
`complete`.

| Defect | Effect | Status |
|---|---|---|
| **`with Pool()` loses calls.** `Pool.__exit__` sends SIGTERM to its workers; no exit hook runs, and a call a worker's capture thread had not yet written dies with it. | Under a sub-millisecond fake model, up to 364 of 408 calls were lost. Forked workers' losses are always visible (the parent records each worker's last sequence), so no run is `complete`; a spawned worker killed before its first record write leaves no trace. | Accounted, not lossless. End pools with `pool.close(); pool.join()`: fork and spawn pools then delivered every call and reconstructed complete, locally and through a Node. Making `with Pool()` lossless would need I/O on the call path or a SIGTERM handler, both excluded by spec 049 §7.1. |
| **Capture throughput is bound by the GIL under heavy CPU contention.** One capture worker per process writes the spool and needs the GIL; CPU-bound application threads starve it. | With 16 CPU-bound threads about 530 exchanges/s were spooled and 15–19% shed; with 64, about 130/s and 27–34% shed. With I/O-bound threads (agents waiting on a model) or up to 4 CPU-bound threads, capture kept up (1,600–1,800/s, nothing shed). Every shed exchange is a `queue_full` loss and the run is `partial`. Numbers: [operations](operations/README.md#throughput). | Open. Going further needs work off the GIL (a native writer or a helper process). |
| **A full disk can still lose loss records.** A process that opens the spool on an already-full volume cannot create the loss ledger, and losses recorded after the sender's last pass before a SIGKILL stay in memory. On copy-on-write filesystems (btrfs, ZFS) writing the ledger may need free blocks. | Those sequences are unexplained gaps: the run is `partial`, never complete. | Open. The `disk_full` path was exercised on a real volume on macOS and by fault injection; not on a real ext4 or xfs volume. |
| **Host sensors have no production ingress.** | See below. | Planned for P4. |

Fixed in v0.8 (found by the same matrix): fork pools on macOS crashing or
hanging with capture on (a forked child now answers system proxy lookups
from a snapshot taken at install; a system proxy change after install
reaches such children only through proxy variables); bursts overflowing the
256-entry capture queue (the queue is now bounded by bytes, with a 16,384
entry cap, and the worker writes batches); local file mode losing records
on SIGKILL (it now spools by default when an OTLP endpoint is set); `OTEL_SDK_DISABLED=true` disabling
capture silently (now one warning and `status()` reports it); a response
cut off mid-body being graded complete (a stream) or `unverified` (JSON):
a response whose bytes do not prove their own end is now a `truncated` gap
(`stream_closed_early` or `transport_incomplete`), so `partial`; a spool on a
full volume losing the record of its losses (`disk_full` and the loss
ledger); and `fabric.reconstruct` exhausting memory under heavy loss
(bounded per-run gap lists).

## Deployment limits

- **One agent source per production Node.** A production Node binds one
  tenant, one `fabric.source_id` and one ingress token. Agents with
  different source ids need one Node each; pods that share a Node must run
  with the same `FABRIC_SOURCE_ID`. A shared DaemonSet Node serving many
  independently identified pods cannot be a production Node in v0.8.
- **Redaction needs a service you run, and zero-code capture cannot
  redact.** `redact`, `masked_only` and the review copy of
  `original_plus_masked` are performed by your
  [redaction service](privacy-and-security.md#redaction-service) (Unix
  socket or loopback only), with the transformation named in code at
  `fabric.wire.install()`. Under autoload those modes withhold the content
  (`protection_failed`), as does any service failure, timeout (5 s) or
  saturation (two calls in flight). Fabric ships no PII detector.
  `tokenize`, `metadata_only`, `omit` and `retain_original` work zero-code.
- **`tokenize`, `metadata_only` and `omit` reconstruct as `unverified`.**
  The verifier cannot parse or digest-check an original it was not given.
- **POSIX only for production.** Node mode needs a POSIX spool (`fcntl`),
  so it does not run on Windows. Local file mode on Windows has no spool
  and exports directly.
- **`make verify-prod` authenticated check.** It posts a fixture trace whose
  tenant is `harness`; a source-bound production Node refuses it unless
  your tenant is `harness`. Its unauthenticated-refusal checks are valid.
  (Found by reading the code; not yet confirmed on a running Node.)
- **Host sensors are local-profile only.** A production Node refuses
  them; a production ingress for host sensors is planned for P4 (see
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
| P4 | Opt-in hooks for MCP clients, subprocesses, DB-API, non-model HTTP, file audit; host sensors on a production Node | Not built |
| P5 | Realtime/websocket, provider batch and files, media, UI automation | Not built |
| TS-1 | TypeScript wire capture on `undici` (Node.js 24+) | Not built |

Out of scope for Fabric OSS at every phase: evaluation, judging, scoring,
guardrails, escalation, blocking or modifying agent actions, policy engines
and approval orchestration ([AGENTS.md](../AGENTS.md)).
