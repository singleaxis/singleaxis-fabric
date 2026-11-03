# Python SDK scope

The recorder SDK has one job: instrument observable agent activity and preserve
its identity, timing and causal relationships so a Fabric Node can protect and
deliver the record.

## Supported

- decision and execution correlation;
- model and tool call spans, including retries and failures;
- retrieval and memory events using hashes instead of raw content;
- side effects, checkpoints, delegation, MCP inventory, skills, hooks, file
  access and generic interactions;
- zero-code capture of model calls at the httpx, httpx2 and aiohttp clients
  (`fabric.wire`), the PROTECT stage before the durable spool, and delivery
  to a Fabric Node;
- exact-byte recording at caller-chosen boundaries (`ByteEvidenceRecorder`,
  `CallRecorder`, byte-boundary adapters);
- the offline verifiers `fabric.reconstruct` and qualified-run mode;
- OpenTelemetry propagation;
- customer-controlled content references and integrity metadata.

Framework adapters and provider auto-instrumentation are not part of the
package.

## Outside the package

Everything outside CAPTURE -> PROTECT -> DELIVER is out of scope; see
[AGENTS.md](../../AGENTS.md) and
[architecture](../../docs/architecture.md#what-fabric-is-not). Other systems
may consume the delivered record; installing this package enables none of
them.

## Artifact boundary

The wheel and source distribution contain only recorder code. Runtime-control,
judge, evaluation, policy, authorization, escalation and management modules,
extras and console commands are absent rather than hidden behind package-root
exports. Exact-archive qualification enforces this boundary before release.
