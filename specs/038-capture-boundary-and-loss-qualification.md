---
title: Capture-boundary and source-loss qualification
status: draft
revision: 1
last_updated: 2026-09-26
owner: product-architecture
depends_on: 035, 036, 037
related: 039
---

# 038 — Capture-boundary and source-loss qualification

## Decision

Qualify **each reachable boundary** in the signed
[deployment scope](037-bounded-enterprise-deployment-and-controls.md), not a
list of tool names or an entire agent by assertion. Use AEEP's native OTel
identity, content-v2 objects and run manifest. This spec is an acceptance
contract for future implementation; current recorder v1 does not satisfy it.
The OSS core remains passive. Tests MUST NOT require an inline block,
modification, or delay to the monitored agent as a way to improve capture.

## 1. Qualification inventory

Every claimed adapter/version needs one row for
`runtime × boundary × operation × role × media type × failure mode`, with
capability manifest ID/digest, owner, fixture, expected record, independent
source truth, privacy posture, bypass route and result. The inventory also
contains **negative reachability proof** for an excluded class: egress
policy, service account permissions, mount inventory and a direct-call
attempt. Merely not observing a call is not exclusion proof.

| Boundary / action | Required evidence if reachable | Independent truth and bypass test |
| --- | --- | --- |
| Provider-bound model calls and streaming | Exact final visible instructions, ordered messages, tool definitions, parameters, request/response chunks, attempt/finish/error; distinguish caller-supplied from post-transform bytes | Controlled provider endpoint captures received bytes; bypass direct SDK HTTP and retry/cancel paths |
| Tool/MCP/plugin/skill/hook/delegation | Definition/version, invocation, arguments, result/error, before/after hook values, child-run identity and context link | Framework/tool fixture and direct plugin call; dynamic load/child process bypass |
| Terminal, subprocess and PTY | argv, cwd, approved environment snapshot, stdin/stdout/stderr ordered bytes, exit/signal, process tree and attempt | Known-output PTY fixture plus host exec; direct `subprocess`, shell script, detached child and large binary stream |
| File and object artifacts | Exact before/after bytes or version, create/modify/rename/delete tombstone, digest and provenance | Filesystem/object-store snapshots; direct write, rename, atomic replace, symlink and deleted-before-read cases |
| Sandbox/container/VM | Image/config/mounts, nested processes, network flows, output artifacts and lifecycle | Runtime/Kubernetes audit and independent inventory; nested container/sidecar/exec bypass |
| SSH/SCP/SFTP/remote execution | Local intent/session **and** authenticated remote command, streams, files and effects | Remote-side audit and fixture; encrypted local packet-only source must report unsupported |
| DB/warehouse/vector access | Query and bound parameters where approved, rows actually returned, transaction commit/rollback, mutation receipt and attempt | DB server audit/CDC and test table state; direct driver, CLI, pool/retry and stored-procedure bypass |
| HTTP/RPC/WebSocket/browser/cloud API | Request/response/stream bytes where approved, status, redirects, artifacts and side-effect receipt | Fixture server/cloud audit; direct `curl`, browser, cloud CLI and redirected request |
| Retrieval/memory/queue | Exact returned/consumed item version, write/read receipts, relation to later model-bound context | Store/queue truth and provider-bound input; fetched-but-not-sent distinction |

The table is not a promise to capture every tool automatically. Any newly
reachable class requires a new inventory row and tests before a complete
verdict. If customer controls cannot prove a bypass is unreachable, the
source is `unverified`. Host audit/eBPF records are corroborating process,
socket or file **metadata**; they do not reveal TLS, SSH or DB content and
must not be upgraded to native agent causality through PID/time joins.

## 2. Event and content acceptance

For each positive fixture:

1. The native source emits a stable record ID, authenticated tenant/source
   and source epoch/sequence, operation/attempt IDs, accurate boundary and
   provenance, and trace context only when actually propagated.
2. Required input, output and context roles are present as exact-byte
   content-v2 objects in a customer store, or have explicit
   `pending/truncated/redacted/not_captured/unsupported/dropped/failed`
   status. Binary and multimodal bytes are never coerced to text.
3. Source and stored lengths/digests are independently recomputed from
   fixture bytes. Chunk order and terminal stream state are testable.
   Empty content and absent content remain distinct.
4. The ref/descriptor/event/run-manifest links resolve to the same
   tenant, run, operation, attempt and object. A retry preserves identity
   for duplicates; a new physical attempt gets a new attempt ID.
5. The Fabric Node exports only allowlisted metadata. Raw bytes, credentials,
   command flags, SQL values, URLs with tokens, headers and canary strings
   are absent from OTLP, telemetry spools, logs, error messages and receipts.
   Dedicated governed-content spools are protected and tested separately.
6. An authorized offline consumer reconstructs the declared ordered
   record without executing tools or side effects; it reports missing and
   uncertain causal links rather than inventing a global order.

For a negative fixture, the manifest MUST report the exact unsupported,
redacted, partial or missing role and lower the verdict. A hash of an
uncaptured secret or a metadata-only file-open is not content evidence.
Hidden provider instructions/reasoning and uninstrumented remote state are
never claimed.

## 3. Source-loss and delivery fault matrix

Every source type (SDK, provider adapter, terminal, host sensor, remote
agent, DB/API connector) MUST pass the following fault injections at the
target kernel/runtime and maximum approved rate:

| Fault | Required observation and acceptance |
| --- | --- |
| Destination outage / OTLP 5xx / timeout | Stable retry identities; source spool or explicit pre-spool loss boundary; no silent batch clear |
| OTLP partial success / non-retryable 4xx | Exact rejected count and explicit gap; never treat HTTP 200 partial success as full delivery |
| Source crash / kill -9 / restart | Persisted epoch/high-water and queued records recover; unknown pre-fsync window is `unverified` |
| Node crash / queue replay | No accepted record silently lost; duplicate records dedupe by stable ID; content and metadata can arrive in either order |
| Disk full / permission denial / corrupt spool | Agent call remains unchanged; loss counter, alert and `partial` or `unverified` verdict |
| Ring buffer overflow / rate limit / sampling | Measured drop count, source-health event and no complete verdict; absence of events never means zero activity |
| Clock skew / concurrent sources | Per-source sequence and causal links retained; no timestamp-only total order |
| Certificate expiry / revocation / identity spoof | Ingress rejects unauthenticated source; outage/gap visible and tenant attribution not fabricated |
| Large/multimodal/partial stream and cancellation | Bounded resource use; exact supported bytes or explicit truncation/unsupported; terminal status correct |
| Connector disabled/uninstalled or new egress route | Independent inventory detects mismatch and blocks complete verdict |

The event channel can itself fail. Loss counters therefore need a separately
testable durable high-water/health path and independent source truth; a
best-effort `loss` event alone is insufficient. Passive capture may still
lose data under catastrophic source failure. The allowed claim is **no
silent loss within the tested bound**, not unconditional zero loss.

The audit receiver now retains failed downstream deliveries in a bounded
in-memory retry queue and reports overflow/rate/assembly gaps after recovery
([source](../components/otel-collector-fabric/receiver/auditreceiver/receiver.go)).
This repairs a silent-error path, but the queue and logfile cursor are not
restart-durable, and netlink events cannot be replayed. Collector crash and
kernel-loss tests therefore still block a complete host-audit claim. The
host emitter's durable-spool work requires separate qualification; its source-side
fsync acknowledgement must not be conflated with destination persistence.

## 4. Deterministic verdict and pass thresholds

Pre-register the target peak and burst rates, maximum outage, spool size,
retention and recovery objectives in the signed scope; never choose
thresholds after seeing results. The minimum conformance suite includes
100% of declared `boundary × operation × role` rows, every listed fault,
and both a direct-bypass and an unsupported fixture for every connector.
No privacy canary may escape into a disallowed surface. For the pilot's
declared scope, independent truth must reconcile **every** expected
operation and required content object; any unexplained discrepancy is
`NO_GO`. A known loss yields `partial`, while unavailable health,
identity, receipt or feed yields `unverified`—neither qualifies as
complete. Zero observed discrepancies in a finite test is not a
probabilistic guarantee for all future runs.

The test output includes source versions/digests, exact commands and
fixtures, expected/observed counts, byte digests, before/after spool
state, destination receipts, run verdict, variance and reviewer. Repeat
on every relevant SDK/adapter/Node upgrade, kernel/runtime change, scope
revision and deployment topology change.

## 5. Implementation order

1. Freeze content-v2, event/capability/run-manifest semantics and a pinned
   OTel convention revision; add cross-language byte fixtures and parsers.
2. Build provider/tool then terminal/artifact adapters, with source
   identity, sequence, bounded protected spool, health and loss paths.
3. Add remote, DB and network connectors only as separately testable
   capability slices; keep unsupported roles explicit.
4. Preserve reviewed metadata through the Node allowlist; test protected
   delivery and receipt stages. Never open a raw-content OTLP bypass.
5. Run this matrix in CI against exact artifacts and in the customer
   shadow pilot. Do not mark this spec `implemented` until the required
   rows pass and release artifacts include only recorder capabilities.

OTLP's [partial-success and retry semantics](https://opentelemetry.io/docs/specs/otlp/)
are the transport baseline; a successful OTLP response is acceptance,
not independent proof of durable destination storage.
