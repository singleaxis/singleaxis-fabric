# Enterprise capture reference build

Status: implementation contract, 2026-10-02. Product boundary: CAPTURE → PROTECT → DELIVER. No portal, enforcement, governance runtime, or unconditional loss-free promise.

## Scope and durability contract

Deliver a runnable customer-controlled Python reference deployment with a finite declared final HTTP dispatch boundary, existing privacy policy, encrypted local byte spool, existing fsynced metadata journal, restartable journal sender, independently persisted local Node/destination receipt services, fresh destination readback, and registered multi-source/recovered-epoch closure accounting. Preserve TypeScript's existing supported privacy/byte subset and explicitly document missing durable/call parity. External cloud KMS/IAM, Kubernetes/network controls and native BPF attestation remain target qualification gates, never simulated as production proof.

Passive admission returns pending, not durable. Background work must never change application return values, exceptions or cancellation. Acknowledged durable records must survive process restart and replay with stable identities. Pre-fsync events may be unknown; independently witnessed source truth is necessary to detect that gap. Any missing, rejected, corrupted, unregistered, unjoined, or unresolved event withholds complete.

## Workstreams and interfaces

1. **Protected byte durability (byte owner):** add durable spool/replay integrated with ByteRecorder without replacing existing store/privacy behavior. Privacy protection occurs before encrypted disk admission; stable descriptor/object IDs; atomic fsync settlement; bounded capacity; classified retry/backoff; durable terminal loss and health. Public API must expose pending versus durable versus delivered and bounded shutdown. Use existing governed-store encryption facilities where applicable. Tests cover restart, lost acknowledgement, corruption, capacity, transient/permanent failure and canary non-disclosure.
2. **Metadata delivery (sender owner):** add a restartable consumer of SourceJournal's durable event inventory and existing call OTLP batch projection. Persist immutable batch payload/identity and per-batch acknowledgement ledger atomically. Node acceptance is not destination durability. OTLP partial success is explicitly rejected/uncertain and never full acknowledgement; lost responses replay identical batches. Retry transient HTTP/transport failures; retain permanent rejection evidence. Tests cover >4,096 records, boundaries between sends and cursor writes, restart and partial success.
3. **Independent reference receipts and boundary adapters (receipt owner):** implement real runnable local HTTP acceptance/destination services whose inventories/receipts are derived from their persisted ingress, not recorder lists. Scoped tenant/run/stage identities and explicit key trust/revocation. Fresh readback recomputes exact record/object identity. Add a genuine final HTTP dispatch adapter and independent receiver truth, including retries and bypass evidence. Existing receipt fixture contracts are reused where useful, but synthetic signatures must never be relabeled live proof.
4. **Closure, integration and qualification (build lead):** authenticated source registration and expected-child/joined closure inventory across epochs, conservative verdicts, executable reference orchestration, cross-cutting outage/process-termination/privacy regression suite, SDK support matrix and final test evidence. Integrate worker APIs rather than duplicate their persistence implementations.

## Required acceptance

- Fresh-process recovery of durable byte and metadata records retains identity, permitted content and exact record set; replay after accepted-but-unacknowledged sends is idempotent.
- All privacy canaries stay absent from metadata, exception text, and derivative-only disk surfaces. Encrypted local storage has explicit key custody, retention and deletion limitations.
- Transient outage eventually drains after restart/recovery. Permanent denial, disk quota/full, corruption, partial rejection and blocked writes stay visible; no false complete.
- Every declared physical HTTP request, retry, stream terminal and bypass is independently reconciled. Undeclared routes remain unverified.
- Multi-source closure requires all expected registered children, valid source/epoch sequences, settled joins and independent truth. Parent completion or clock ordering alone cannot complete a run.
- Runnable local reference campaign emits machine-readable evidence distinguishing implemented/passed, implemented/untested and excluded target gates. Actual cloud infrastructure is not claimed qualified by local tests.
- Regression: Python full suite, TypeScript typecheck/tests/build, repository contract tests and relevant static checks; unavailable Docker/S3/native infrastructure explicitly reported.

## Integration ownership

Workers own new implementation/test modules in their domain and coordinate shared ByteRecorder/exports edits before writing. Build lead owns orchestration, closure, support documentation and aggregate evidence. Existing uncommitted release work must remain intact. Publication is separately owned; no worker pushes or rewrites git history.

## Future client-portal control compatibility

The user's direction is a strong capture layer that can eventually support a separately enabled control layer configured through the client SingleAxis portal. Reuse versioned deployment policy, authenticated authority interfaces and local desired/approved/applied lifecycle. Extend only missing machine-readable capabilities, authenticated workload/operator binding, readback/drift and action/decision/policy/outcome correlation contracts. A final-boundary external-controller protocol is opt-in and separate; the recorder never interprets an observation as authorization. Portal UI, remote fleet rollout and action enforcement implementation are excluded from this capture build.

## Auditd receiver durability extension

The capture build also closes the existing auditd logfile cursor/retry gap.
A dedicated Go workstream owns durable cursor/backlog storage, restart replay,
explicit loss/corruption accounting and temporary-log rotation/truncation/crash
regressions. Cursor advancement must follow downstream acknowledgement and
remain crash-consistent with pending delivery. At-least-once replay and its
stable identity/deduplication boundary must be explicit. Native auditd/eBPF
sensor execution, privileges and target-kernel qualification remain excluded
from local Go-test claims; metadata never implies access to encrypted payloads.

The implemented auditd logfile interface requires an absolute private
`state_directory`; defaults are 16 MiB state, 4 MiB batch, 1 MiB record and
4,096 records per batch. A staged scrubbed OTLP batch and accepted cursor share
one atomic fsynced checkpoint. Cursor advancement follows downstream acceptance;
ambiguous acceptance replays the same 64-hex `fabric.record_id`. Dedicated
persistent-volume migration is mandatory for logfile mode. Netlink behavior
remains separately bounded/in-memory and explicitly non-replayable.
