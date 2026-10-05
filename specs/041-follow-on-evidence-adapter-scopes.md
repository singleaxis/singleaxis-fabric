---
title: Follow-on bounded evidence adapter scopes
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 1
last_updated: 2026-09-26
depends_on: 035, 036, 037, 038, 039, 040
---

# 041 — Separately scoped observable routes

The first synthetic slice in spec 040 covers none of the routes below.
Each adapter needs its own approved deployment record, protocol/version
matrix, identity binding, capacity ceiling, privacy policy, independent
truth feed and fault-tested source-to-destination receipts before its row can
become a required source in a complete-run manifest. No adapter may install
a global interceptor or alter, block or delay the monitored action by default.
All remain Fabric OSS `CAPTURE -> PROTECT -> DELIVER`; evaluation is external.

| Proposed slice | Observable capture boundary and required bytes | Independent truth / hard loss case | Explicit exclusion until proved |
| --- | --- | --- | --- |
| Reachable SSH | Opt-in client wrapper: target identity, host-key verification result, command or subsystem request, stdin/stdout/stderr channel bytes with observed order, exit status/signal and transfer artifact digests; server-side adapter if remote process/file effects are required | Controlled SSH server transcript plus remote audit and filesystem inventory; reconnect, rekey, multiplexed channels, dropped session and remote restart | Direct `ssh`/`scp`, unwrapped libraries, agent forwarding, remote descendants and files not covered merely by a client transcript |
| Database | Named driver/proxy boundary: endpoint identity, transaction/session ID, query and parameter bytes under role policy, bounded row/result bytes, mutation result and commit/rollback outcome | Server audit/WAL/transaction ledger plus controlled fixture rows; pooled connections, retries, prepared statements, truncation and server-side procedures | Direct alternate drivers, console access, internal server effects and full database state are not inferred from a client query |
| Browser and cloud API | Opt-in browser automation or HTTP/cloud SDK boundary: request body and approved headers, response body/status, navigation/tool action, downloads/uploads and credential-free object refs | Controlled browser/HTTP server ledger, cloud audit trail and object inventory; redirects, streaming, pagination, retries and asynchronous jobs | Human browser tabs, direct network sockets, provider-internal transformations and eventual remote effects are not covered without separate source proof |
| Sandbox/container | Runtime-specific process/exec/file/network adapter with authenticated container identity, namespace/cgroup linkage, ordered stdio, mounted-file inventory and lifecycle outcome | Sandbox runtime events, isolated filesystem snapshot and scoped kernel telemetry; restart, escape, detached jobs, overlay filesystems and non-replayable ring loss | Host-wide capture, privileged all-host BPF, descendants outside the declared namespace and hidden in-container state are excluded |
| Other reachable tools | Inventory each MCP server, code interpreter, queue, object store, shell/PTY and plugin route; define the final visible request/result and side-effect boundary per version | Service-side receipt or controlled fixture ledger; timeout, partial success, async completion and replay/dedupe | Generic “tool call captured” does not establish content, side-effect or remote-state completeness |

For every row, implementers must prove both the positive route and at least
one direct bypass in an isolated disposable environment. A reachable bypass
that is not instrumented is a declared coverage gap. Each adapter must emit
stable source/operation/attempt identity, explicit byte availability state,
source epoch/sequence/high-water and separate source, Node, destination
acceptance and destination durability stages. Content may appear only in an
authorized tenant store, never OTLP/logs/queues/errors/receipts. Acceptance
requires exact-byte reconciliation with independent records and injected
loss preventing a complete verdict. No row inherits qualification from the
synthetic Python adapter, host emitter or audit receiver.
