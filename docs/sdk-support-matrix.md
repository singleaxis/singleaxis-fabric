# SDK support matrix

This is a source-support matrix for the enterprise capture build. “Implemented”
means an implementation exists, not that an arbitrary target deployment is
qualified. Local reference services and contract-only interfaces are named
separately. Test commands and actual run evidence belong with the delivered
build's qualification results.

| Capability | Python | TypeScript |
| --- | --- | --- |
| Versioned deployment-policy validation and canonical digest | Implemented, `deployment_policy.DeploymentPolicy` | Implemented, `DeploymentPolicy` |
| Pre-persistence privacy protection | Implemented in `ByteEvidenceRecorder` | Implemented in `ByteEvidenceRecorder` |
| Fabric-managed metadata-only span export | Implemented; `install_default_provider` protects its own export route and `trace_export_protection_status` reports it | Not implemented; external provider/exporter configuration is separate |
| Byte evidence capture | Implemented | Implemented; bounded in-process queue, no crash-durable spool parity |
| Explicit call/attempt/stream capture | Implemented, `CallRecorder` | No `CallRecorder` parity |
| Durable source metadata journal | Implemented, `source_spool.SyntheticSourceSpool` | Not implemented |
| Encrypted durable byte spool/replay | Implemented, `byte_spool.DurableByteSpool`, `ByteEvidenceConfig.durable_spool` | Not implemented |
| Restartable metadata delivery/ack ledger | Implemented, `metadata_delivery.JournalMetadataSender`, `HTTPMetadataTransport` | Not implemented |
| Authenticated AES-GCM local governed store | Implemented, `GovernedLocalContentStore` | Not implemented; ordinary stores are not an equivalent |
| External control observations | Metadata only, `ControlObservation` | Not implemented |
| Registered multi-source/recovered-epoch closure | Local reference, `distributed_closure` | Not implemented |
| Client portal UI, SSO/fleet rollout service | Not implemented | Not implemented |
| Action enforcement | Not implemented | Not implemented |
| Production IAM/KMS, residency, network or native BPF attestation | External target qualification required | External target qualification required |

The connector capability manifests in
[`contracts/connect/v1/manifests`](../contracts/connect/v1/manifests) are the
machine-readable declarations for each released SDK and connector. Do not use
this static matrix as a workload readback or infer that installed features are
enabled.

## Durability and privacy limits

- Python's durable paths are opt-in. Passive queue admission is pending until
  durable acknowledgement; pre-fsync observations can remain unknown after a
  crash. Node acceptance is not destination durability. Missing, rejected,
  corrupted or unjoined records withhold completeness.
- TypeScript's current privacy/byte implementation is supported and tested in
  its declared scope. It does not inherit Python's journal, durable spool,
  delivery ledger, governed encryption backend, closure or qualification APIs.
- Deployment policy protects the explicit ByteEvidenceRecorder path. It does
  not retrofit arbitrary OTel exporters, provider logs, diagnostics or traffic
  that was never submitted to Fabric.
- A configured policy or static capability declaration does not prove live
  hooks, encryption custody, retention deletion, destination readback
  or complete coverage of physical attempts.

## Runtime and effect boundaries

“Capture a tool call” and “independently observe everything the tool changed”
are different supported claims. These rows do not require three separate
application integrations: existing OTel/framework output can supply semantic
context, optional host sensors can be deployed centrally, and destination
readback can be added only for effects that need stronger evidence.

| Surface | Available implementation/evidence | Boundary of the claim |
| --- | --- | --- |
| Existing framework/OTel traces | Node preserves supported supplied identity/correlation; lightweight framework hooks can emit compatible spans | Sampling, absent hooks and bypasses remain unknown; imported spans are not independent completeness proof |
| Explicit model/tool dispatch | Python `CallRecorder`; real `FinalHTTPAdapter` HTTP/1.1 body tests | Named wrapped calls and physical requests only; no automatic arbitrary framework/SDK interception |
| Zero-code LLM wire capture (opt-in) | Python httpx/httpx2 tee, agent spool and Node content path (specs 047/048); offline `python -m fabric.reconstruct`; TypeScript not implemented | Only model calls through httpx/httpx2 to listed endpoints in an instrumented process; defers inside explicit model calls ([Two capture lines](README.md#two-capture-lines)); record-integrity verdicts, not run qualification |
| Bounded local CLI subprocess | `BoundedTerminalAdapter` in the synthetic adapter module; local subprocess return/stdout/stderr and failure tests | Explicit controlled child only; not a universal shell/PTY/session recorder, not qualified for arbitrary descendants |
| Interactive terminal / PTY | No general qualified PTY adapter | Terminal resize, input timing, interactive sessions and arbitrary nested commands are unsupported/unverified |
| Shell descendants / detached children | Explicit parent propagation, expected-child closure; optional host exec/connect metadata | Parent success cannot prove unknown children complete; live host correlation requires target evidence |
| auditd logfile | Durable receiver checkpoint/replay extension with temporary-log restart/rotation/fault tests | Native audit-rule coverage and kernel source completeness are separate target gates; metadata does not reveal encrypted application content |
| eBPF host sensing | Existing passive host emitter and portable spool/metadata tests | Native BPF object, kernel, privileges and workload scope not qualified in this environment; no TLS plaintext capture |
| Local files / SQLite effects | Allowlisted artifact observer and orchestration fixture readback | Only explicitly named files/operations; fixture success does not attest arbitrary databases/filesystems |
| Browser / remote sandbox / remote VM | Ordinary supplied telemetry or explicit custom adapter/context propagation | No universal guest/remote instrumentation or session reconstruction; instrumentation/provider evidence must exist inside the relevant boundary |
| SSH / remote CLI / encrypted traffic | Explicit approved application observations and host connection metadata where configured | Host network metadata does not reconstruct SSH/TLS payloads or remote committed effects |
| External writes/payments/cloud effects | Caller-supplied effect references and selected destination readback adapters | A successful tool return is not independent proof the external effect committed; authoritative provider readback required |
| Destination content and metadata | Exact receipt sets and attestations checked offline (`receipt_sets`, `evidence_attestation`); destination readback | Receipts are checked, not issued: the SDK ships no receipt service, and a receipt is not a cloud storage SLA, IAM/KMS or replication attestation |

No row establishes “captures everything.” Missing routes, absent sensors,
unknown child sources and unverified effect readbacks must remain explicit.

## Managed metadata-only tracing

The Python convenience provider now defaults to a protected exporter projection.
It preserves causal trace/span IDs and valid numeric token metadata, removes raw
exception events/status text, and hashes free-form metadata strings. Hashes are
pseudonymous/correlatable and may be guessable; they are not de-identification.
Content/manifest references in this trace projection are also hashed, so they
are not resolver pointers. The separate byte/journal delivery path retains its
explicitly governed evidence contract.

`fabric.tracing.trace_export_protection_status()` reports protected managed
routes, explicit content opt-in, unprotected host routes, unavailable inspection
or no exporter, plus projection/drop/failure counters. Its basis is the current
process. An installed capability is not an active-hook or backend-delivery proof,
and a fresh doctor process cannot inspect another application's live exporters.
Fabric never silently rewrites an existing host provider; an upstream content
flag alone does not suppress all exception telemetry.
