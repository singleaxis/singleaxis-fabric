---
title: Custom-agent call recording and protected reconstruction
status: implementation_in_progress
qualification: NO_GO
revision: 1
depends_on: 035, 036, 037, 038, 039, 040, 041, 042
---

# 043 — One linked record for a custom agent

## Scope and implementation phases (specified before code)

Fabric remains passive CAPTURE → PROTECT → DELIVER. Extend the existing
Python tracing and byte-content facilities with a general call recorder for
custom dispatchers. Do not install global interceptors or add evaluation,
enforcement, or management services. Preserve existing public APIs.

The first integration is Python 3.11+ and one local synthetic custom agent,
using a controlled model endpoint, explicitly wrapped tools, parallel child
calls, approved files and a disposable SQLite database. SQLite state readback
is an independent fixture observation, not authenticated enterprise DB audit.
Caller-supplied source identity and bytes remain caller-reported. SSH,
browser/cloud, sandbox internals, hidden provider state, arbitrary direct
calls, and deterministic replay remain excluded under spec 041.

### A. Identity and privacy consistency

Every call carries run, agent, source, operation and physical attempt identity,
parent call where present, and trace correlation when available. Content
objects bind to the same operation and attempt as their timeline. Protected
content configuration must reject raw-span capture before content can enter
an upstream exporter. Fix missing model-output/tool attempt bindings.
Acceptance: canaries absent from exported spans; requests/results share the
intended attempt; legacy APIs remain compatible when protected mode is absent.

### B. Consolidated call surface

Reuse the existing byte recorder/store and tracing infrastructure. Provide
one framework-independent API for synchronous and asynchronous calls and
streams, with exact bytes supplied at the final visible call boundary.
Record start, input/context, ordered chunks, outcome and parent/child links.
Parallel calls keep context-local parents and independent attempts. Do not
serialize arbitrary objects and call them exact wire bytes. Empty bytes,
absent content, unsupported values and capture failures remain distinct.

Delegate invocation is exactly once. Results/exceptions and cancellation are
preserved. Streams do not prefetch; early close/exception/cancel must not
become success. No network/store/fsync wait is added to monitored calls;
in-process recording has measurable overhead and a pre-persistence loss
window. Full queues and recording faults affect evidence, not the action.

Acceptance: nested and concurrent calls, binary/empty data, separate retry
attempts, sync/async streams, partial close/cancel, delegate errors and
recording failures; independently resolve and compare every expected byte.

### C. Customer privacy choices

Define explicit role policies: original, masked-only, original plus masked
review copy, or omitted. A customer-provided versioned transformation is an
optional mechanism, not a built-in infallible PII detector. Transformation
must happen off the monitored action path; raw queued memory is inside the
approved boundary. Masked-only never durably stores originals. Failure must
withhold the affected content with a fixed reason and never fall back to raw
export. Original/review objects retain separate references and provenance;
deployments must separately authorize review/original store access.
Acceptance: secret canaries, failing transformations, omitted roles, bounded
queues, exact original versus derivative distinction and honest reporting.

### D. Independent records and run report

Add an offline read-only witness input and deterministic report matching
specific run/operation/attempt/role objects and outcomes against provider,
filesystem and controlled DB observations. Verify authorized resolution,
byte length and SHA-256. Detect missing/extra/duplicate/corrupt objects,
incomplete streams, absent outcomes, and known bypasses. A mere equality of
counts is insufficient. A caller-provided trust flag cannot authenticate a
witness or a delivery receipt.

The local implementation emits partial for known discrepancies and unverified
when matching but source authentication, route closure, independent-feed
authentication or durable receipts are absent. No local fixture confers a
verified-complete or production GO verdict. Source persistence, Node
acceptance, destination acceptance and destination durable readback remain
separate stages; unsupported stages are explicitly unavailable.

### E. Installable example and coverage check

Package the new API in the ordinary SDK wheel. Provide a runnable custom
dispatcher example and offline coverage check with versioned route inventory,
provider/file/SQLite witnesses, deliberate direct bypass and loss cases,
protected actual data and a machine-readable discrepancy report. Test the
installed wheel (without source imports), record its digest and publish exact
commands. Follow-on routes require individual specs and tests.

## Qualification limits

This first implementation does not qualify source-to-tenant authentication,
the pre-fsync crash window, complete destination receipts, customer IAM/KMS,
retention/restore/key rotation, target cluster policies or customer-owner
approval. Keep docs/recorder-v1-qualification-status.md at NO_GO and report
local tests separately from exact-artifact/target-environment proofs.

## Implementation ledger — 2026-09-30

### Second build phase — specified before implementation

F. Reuse the closed, metadata-only OTLP projector for custom-call snapshots,
including safe call/agent/parent identity, byte chunk order and operation
outcomes. Add only reviewed fields to the Node guard. Never project local
paths, refs, byte bodies, transformations or exception text. Test the exact
projected event set through Node and controlled sink; accepted OTLP remains
distinct from durable storage readback. Projection stays an offline action.

The phase F projection retains existing `agent.evidence.content` and
`agent.evidence.artifact` records and adds `agent.evidence.call` for actual
source start/outcome records. Calls use `status=observed`,
`call_phase=start|outcome`, `call_kind=model|tool|database|agent`; outcomes
require `result_status=ok|error|cancelled|deferred`. All custom-call records
carry opaque `call_id`, `agent_id`, optional `parent_call_id`, plus existing
tenant/run/source/epoch/sequence/operation/attempt/record identity. Stream
objects retain the paired `stream_id` and nonnegative `chunk_index`. Only
nonnegative signed-64-bit integers and bounded opaque identifiers are allowed.
Export each source record once; reject duplicate record IDs, malformed fields
and batches above 4096 records. A lifecycle summary is never invented as a
source event. Historical recovered records require an explicit separate
projection; the live-run export includes `starts`, `events`, and `operations`.
The loopback HTTP or verified mTLS test bridge posts once, accounts for OTLP
partial rejection, and marks the response non-retryable. No automatic retry
or destination durability receipt is inferred from that response.

G. Allow CallRecorder to use the existing asynchronous metadata source journal.
Persist call identity, starts, observations and terminal outcomes with restart
epoch and sequence/high-water evidence. Initialization/fsync recovery occurs
before monitored calls. append does not wait for fsync; retain explicit
pre-fsync uncertainty. Recovered metadata must link to protected descriptor
readback or expose missing bytes; it must not fabricate a completed run.
Acceptance covers restart, pending-to-settled metadata, overflow, corruption,
source journal outage and unchanged delegate results.

H. Add an authorized local content-v2 resolver for exact originals and masked
review objects. It receives explicit store/tenant configuration, verifies
descriptor identity, length, hash and allowed transformation/representation,
and never follows telemetry-controlled arbitrary locations. Separate original
and review store permissions remain a deployment proof. The report verifies
review bytes separately and cannot satisfy an original requirement with them.

I. Extend the installed-wheel custom-agent pilot with Node publication and
controlled sink comparison by record ID and safe fields, plus source journal
and privacy faults. Pin the wheel and Node image used. Use only unique
disposable resources; do not alter existing user deployments or volumes.
If Docker/Linux is unavailable, retain exact commands and mark that gate
unrun. This phase cannot manufacture source authentication, enterprise audit
feeds, customer IAM/KMS or signed target acceptance.

Phases A–E have a locally tested Python surface and installed-wheel fixture.
Phase F now has an offline metadata-only projection, Node guard coverage and
controlled-sink exact-record readback. Phase G journals call metadata and
recovers persisted entries, but deliberately does not claim to close the
pre-fsync window or recover raw queued content. Phase H resolves both original
and masked review objects through explicit local tenant/store configuration.
Phase I ran the exact installed wheel and pinned local Node image through a
disposable sink outage/restart pilot. These are local fixture proofs, not a
signed customer deployment. Authenticated source/witness identity, trusted
four-stage receipts, actual target storage controls and route closure remain
unimplemented or unverified. A clean fixture remains `unverified` by
construction. See the qualification record for exact commands, hashes and
remaining gates.
