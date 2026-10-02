# Agent developer integration practices

Start with the smallest useful integration. Existing supported framework or
OpenTelemetry spans can provide application context without a Fabric-specific
wrapper everywhere. Use the [runnable onboarding example](../examples/enterprise-reference/integrate.py)
and [installation/doctor commands](enterprise-testing-quickstart.md), rather than
copying a large reference deployment into the application.

## Choose the evidence level

- **Minimum tracing:** preserve useful existing spans, trace/parent identity,
  model/token metadata and explicit coverage limits. Missing hooks, sampling and
  raw provider diagnostics remain separate concerns. Telemetry is not proof of
  every physical request or committed effect.
- **Durable verified recording:** explicitly protect permitted bytes, enable the
  byte spool and source journal, deliver through the durable sender, reconcile
  independent destination readback and registered source closure. This adds
  operational configuration; it is not mandatory merely to start tracing.
- **Host/effect evidence:** add optional centrally deployed sensors and targeted
  authoritative readback when those claims matter. Host metadata does not reveal
  TLS/SSH payloads, and a tool success does not prove a remote write committed.

## Ten implementation habits

1. **Centralize final dispatch.** Keep shared model/tool execution functions.
   Hook the final serialized request and response, after application transforms.
   The example's `AppCapture.dispatch` delegates to the real
   `PolicyCaptureSession.calls.call`; `FinalHTTPAdapter` owns a finite HTTP/1.1
   transport boundary. Do not wrap every helper or double-count one attempt.

2. **Keep stable logical identity, distinct attempts.** Reuse `run_id` for the
   logical run and `operation_id` for one logical action; create a new
   `attempt_id` for each physical retry. Let the journal own restart epochs and
   the recorder own source sequences. Do not reset counters and reuse a source
   epoch after restart. Map tenant/workload identity through an authenticated
   boundary; a caller-supplied string is not authentication.

3. **Carry context before background handoff.** Obtain
   `capture.session.calls.current_call_id` while the parent call is active and
   pass it as `parent_call_id` to the child wrapper. The runnable example covers
   a joined thread. For another process, sandbox or VM, propagate run/source/
   parent context through the existing queue and initialize that source there.
   Use authenticated registration/context verification and an expected-child
   join barrier for a distributed completion claim. A timestamp or parent ID
   alone does not prove causality, identity or child completion.

4. **Make retries observable.** Route every retry through the final boundary
   with its own attempt ID. An outer provider-SDK call cannot observe hidden
   internal attempts. Configure explicit retry hooks when supported, or declare
   that route unverified. Capture must not invent a physical-attempt count from
   the number of logical calls.

5. **Protect before persistence and logging.** Validate the deployment policy
   before startup. Configure transforms and a separately authorized derivative
   store for redaction/tokenization; never fall back to raw bytes if a transform
   fails. Do not place prompts, credentials, raw exception messages, stack
   traces or request/response bodies in application logs or span names. In
   metadata-only mode raw exception text is not allowed. Upstream
   `capture_content=False` flags alone are not a privacy boundary: use the
   protected [Fabric-managed provider/export path](python-auto-capture-privacy.md).
   Inspect `fabric.tracing.trace_export_protection_status()` inside the application;
   its hashed string metadata remains correlatable, and content-ref hashes are
   no longer resolver pointers.
   Existing/custom providers and their exporters remain the application's
   responsibility; Fabric does not silently patch them.

6. **Preserve errors and cancellation.** Use `calls.call` / `acall` without
   replacing the application's return value or exception. Use `stream` /
   `astream` for streaming work and explicitly close partially consumed streams.
   Record a terminal outcome; cancellation and incomplete streams must not look
   complete. Arbitrary response objects are preserved but may be unsupported
   for exact-byte capture; do not rely on `repr` as an original transcript.

7. **Make external effects idempotent.** Supply the same application-level
   idempotency key when retrying one logical write, while retaining distinct
   attempt IDs. Read back the authoritative outcome and retain an opaque
   outcome/effect reference where supported. A receipt authenticates its issuer's
   claim at a named stage; Node acceptance is not destination persistence.
   Fabric observes these decisions and does not authorize or enforce them.

8. **Bound capture resources and shutdown.** Choose queue, record, byte, retry,
   retention and outage bounds for the workload. Stop producers and join
   background work before `capture.close(timeout_s=...)`. False means unresolved
   evidence. `wait_durable` acknowledges local admission; `flush` may settle into
   explicit loss, so check states/health as well. Do not close a store underneath
   a blocked writer or delete its ownership lock to force a restart.

9. **Treat health as part of the record.** Preserve failed/dropped/unknown,
   partial rejection, corrupt inventory and missing-child evidence across
   restart. Freeze independently expected identities before injecting faults;
   never redefine the expected set from the survivors. Refresh destination
   readback before declaring delivery. A canary route and installed instrumentor
   status are useful checks, not proof that all real traffic uses the route.

10. **Declare what is unsupported, then test it.** Record exact runtime,
    provider/adapter version, routes, privacy modes and source scope. Exercise
    deliberate bypass, hidden retry, unavailable storage, process termination,
    stream cancellation and detached-child cases against independent truth.
    Remote VM, PTY, shell descendants, host sensors and external effects need
    their own scoped evidence; see the [support matrix](sdk-support-matrix.md).
    Keep unknown coverage explicit. Do not claim every action was captured.

## Small adoption checklist

1. Reuse existing tracing, or add one initialization and one shared dispatch hook.
2. Select and validate privacy policy; verify the actual protected exporter path.
3. Run the existing onboarding example and its doctor, then one real workload
   canary through the application's declared route.
4. Add context at existing background/sandbox handoffs and join expected work.
5. Enable stronger durability/receipts only where the required evidence warrants it.
6. Run the [fault campaign](enterprise-reference-validation.md) for the selected
   tier and production target before making a stronger completeness claim.

The local doctor intentionally distinguishes `LOCAL_READY` from production
`NO_GO`. These practices improve an integration; they are not evidence of
market superiority or a substitute for a matched workload benchmark.
