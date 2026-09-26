# Agent activity coverage and production qualification

Status: gap assessment, not a certification or a claim of complete capture.

The proposed interoperable logging/capture contract is
[spec 035 — Agent Execution Evidence Profile](../specs/035-agent-execution-evidence-profile.md).
The sequenced contracts, adapter work, and release gates are specified in
[spec 036 — Bounded agent evidence capture](../specs/036-evidence-capture-implementation-plan.md).

Fabric OSS remains a passive **CAPTURE -> PROTECT -> DELIVER** recorder. A
finite list of tool names cannot establish completeness: an agent can invoke
new programs, protocols, plugins, remote machines, or APIs at runtime. Coverage
must be defined by **execution boundary and data flow**, then tested for each
supported runtime and deployment. Host metadata is not a transcript.

## Evidence levels

| Level | Meaning | Example |
| --- | --- | --- |
| Content evidence | Exact bytes observed at an instrumented boundary, with role, order, identity, verified storage, and an explicit completeness status | A model-bound request or tool result in a governed content object |
| Semantic metadata | A named action and outcome, but not enough bytes to reconstruct it | SDK tool span or file-access hash |
| Host provenance | Process, socket, or file metadata inferred to be related to an agent | auditd/eBPF `execve`, `connect`, `openat` record |
| No evidence | Not observed, filtered, lost, unsupported, or outside the deployment | SSH commands on an uninstrumented remote host |

Never promote a lower level to a higher one by joining on time, PID, IP, or
session name. Such joins are investigative hints, not proven causal links.
`stored` and a matching SHA-256 prove integrity of the **stored bytes**, not
that every action was captured. A run is reconstructable only for the declared
coverage boundary when every required item is present, complete, and verified.

## Boundary inventory and required mapping

The examples below are classes, not an exhaustive list of products or tools.
Every new connector needs a versioned capability manifest, bypass tests, and a
declared content/metadata/unsupported posture.

For a near-complete claim, the customer must first define a bounded execution
environment: known sandbox images, filesystem mounts, network exits, remote
hosts, identity propagation, and service accounts. Those boundaries can be
enforced by the customer's sandbox/network platform; Fabric itself stays
passive and records evidence or an explicit gap. An unconstrained agent that
can install code or reach uninstrumented hosts has no universal one-to-one
capture guarantee.

| Agent action / examples | Evidence needed for one-to-one historical reconstruction | Current Fabric evidence | Additional capture boundary needed |
| --- | --- | --- | --- |
| Model calls, function calling, streaming, embeddings | Final provider-bound request, ordered instructions/messages/tool schemas/parameters, response or partial stream, attempts and model identity | Manual Python/TypeScript governed `llm_call`; auto content capture deferred | Versioned provider/framework adapters at the last visible request boundary; record transformations and bypasses |
| Tools, MCP, plugins, skills, hooks, subagents | Definition/version, exact arguments and result/error, tool-call identity, delegation/context propagation, hook before/after values when material | Manual tool/MCP content for supported calls; skill/hook/delegation metadata or hashes | Wrapper/adapter at each invocation; capture actual definitions and modified values in governed storage when authorized |
| Terminal, shell, PTY, subprocess (`ssh`, `psql`, `curl`, scripts) | Command input/argv, cwd, environment *allowlist*, stdin, stdout/stderr, exit/signal, process tree and attempt identity | auditd/eBPF can show configured exec/connect/file metadata; argv is hash-only; no PTY transcript | Instrument the terminal/exec API or session boundary; record streams as governed content, excluding credentials; host sensor reconciles bypasses |
| SSH, SCP, SFTP, remote exec | Local invocation and encrypted session metadata **plus remote command, stream, file and mutation records** | Local host can show `ssh` process and connection only | Instrument SSH client/session and the remote endpoint (or approved remote audit/export); carry authenticated run identity across hosts; encrypted packets alone cannot reveal actions |
| Sandboxes, containers, VMs, CI runners, Kubernetes jobs | Sandbox identity/image digest/config, parent run, processes, mounts, network, resource access, files before/after and exit state | Host sensors only if installed and correctly scoped; SDK only if included inside | Instrument inside each sandbox or its control-plane/API boundary; propagate run identity and reconcile host/runtime audit data |
| Files and generated artifacts (text, binary, images, patches) | Exact created/modified bytes, path or opaque locator, before/after version, operation and content hash; deletion/tombstone | `record_file_access` and host sensor: path hash/size or open metadata; `context.file`: explicit text/JSON; opt-in content-v2 records caller-supplied binary bytes but does not discover file operations | Governed artifact object contract and filesystem/tool wrapper; binary/multimodal source adapters; avoid following unrelated/sensitive paths |
| Databases, warehouses, vector stores (`psql`, drivers, SQL APIs) | Query/parameters, transaction ID and commit/rollback, returned rows or approved result snapshot, schema/version, mutation receipt | SDK can record a manually supplied tool request/result; host sensor sees process/connection, not SQL or rows | Driver/proxy/tool integration at DB protocol boundary; DB audit/CDC for committed effects; credential-safe content policy |
| HTTP/gRPC/WebSocket, browsers, cloud APIs | Request method/URL/body, response/status/body, stream messages, redirects and side-effect receipt; browser-visible input/DOM/artifacts if relevant | Manual side-effect/tool/interactions; host connection metadata | Client/gateway/browser adapter with governed payload capture; server/cloud audit for effects; TLS payloads require an authorized endpoint, not packet metadata |
| Kubernetes, container runtime, and cloud control-plane calls (`kubectl`, Docker, cloud CLIs) | Authenticated caller, requested operation/object, request/result body where permitted, resulting object version and audit ID | Host sensor may see a CLI process and connection; no complete control-plane audit import | Client/API instrumentation plus customer control-plane audit export and versioned object evidence; audit policy determines body coverage |
| Retrieval, memory, queues, object stores, email/chat, source control | Exact item returned/consumed, version, write/read receipt and downstream mutation identity | Manual retrieval/memory/side-effect roles and hashes | Per-service adapters or tool wrappers; source-system version/receipt and later model-bound context; remote state snapshots where needed |
| Secrets, environment, clocks, random state, installed packages | Provenance/version and a safe representation of values that affected execution | Not comprehensively captured | Explicit allowlisted environment/config snapshot; never indiscriminately record secret values; hash/opaque reference where bytes cannot be retained |

Content must remain in customer-controlled storage, off the OTLP wire, behind
tenant authorization, encryption, retention, and audit logging. Record
`not_captured`, `unsupported`, `truncated`, `dropped`, `failed`, and `pending`
honestly; absence of a record is not evidence that an action did not occur.

## Current blockers to a complete-agent claim

1. Governed content is opt-in and manual. Framework/provider auto-capture is
   deferred; `model.request.*` records caller-supplied SDK values, not
   necessarily a request after later provider transformations.
2. No general terminal/PTY content, SSH remote-side, database protocol,
   browser, or arbitrary HTTP body capture exists. An explicit byte-recorder
   API can store bytes supplied by a caller, including binary bytes; it does
   not discover created files or reconstruct missing file operations. File
   access metadata cannot regenerate a created file.
3. The host sensors emit metadata only and cannot prove causal attribution to
   an SDK run. Audit rules, cgroup scope, syscall selection, rate limits,
   ring-buffer loss, and encrypted traffic bound coverage.
4. `fabric-host-emitter` now has a bounded persistent source spool, restart
   replay, stable dedupe IDs, and counted kernel/rate losses; rate limiting
   and deduplication default off. This is locally unit/race tested, **not**
   Linux BPF or exact-image E2E qualified. The sample DaemonSet intentionally
   cannot deploy unchanged: its image digest is a placeholder and its cgroup
   path is empty. Source fsync and OTLP acceptance do not prove destination
   retention or complete host observation.
5. The audit receiver now retries failed downstream delivery in a bounded
   **in-memory** queue and reports known gaps. Collector crash can still lose
   records, logfile cursor is not persisted, and netlink cannot replay.
   Fabric Node's durable queue begins only after Node accepts telemetry.
6. Production S3 governed-content delivery and the exact tagged Node path
   still require live qualification. A destination OTLP success is not a
   durable-storage receipt.

## Release and deployment gates

Do not publish a complete-agent or enterprise-ready capture claim until all
applicable gates pass on the exact release commit and target environment:

1. **Coverage contract:** declare supported runtimes, protocols, tool APIs,
   syscall classes, sandbox types and bypass paths. Exercise a fixture for
   each claimed surface, including direct calls that bypass the preferred SDK.
2. **Transcript/artifacts:** capture exact input/output/context and generated
   artifact bytes where authorized; preserve causal IDs and attempts; verify
   complete, partial, missing, redacted and unsupported exports. Never claim
   hidden provider context or model reasoning.
3. **Sensor reliability:** verify authenticated TLS/mTLS emitter egress,
   add durable bounded spool/retry/recovery, explicit loss counters/alerts,
   startup checks for scope and rules, and a controlled sink-outage/restart/
   overflow test. Qualify the audit receiver under downstream backpressure
   and audit-log rotation. No source may report completeness after loss.
4. **Privacy/security:** enforce tenant-bound authorization and least privilege
   for content storage; test secrets in argv/stdin/headers/database rows;
   ensure raw content never enters OTLP, logs, crash dumps, or CI artifacts.
   Pin production images by digest and validate credentials/cert rotation.
5. **Scale:** establish measured rates and limits per source and tenant;
   run multi-tenant soak, burst, outage, restart, disk-full, replay/dedupe,
   upgrade/rollback, and recovery-time tests with explicit pass thresholds.
6. **Release evidence:** scan every shipped module and image, run artifact
   boundary tests, obtain exact-SHA CI evidence, SBOM/provenance/signatures,
   and perform a customer-specific ingress/egress/storage/retention review.
7. **Pilot:** deploy in shadow mode to a named, isolated customer environment;
   compare independent source truth (terminal history, DB/cloud audit,
   filesystem artifacts, sandbox logs) against the exported record. Publish
   the measured coverage and residual gaps before widening the rollout.

The OSS recorder may implement these capture and verification contracts, but
it must not bundle evaluation, judgment, enforcement, or fleet governance.
