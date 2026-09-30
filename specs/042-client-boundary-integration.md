---
title: Bounded client boundary integration
status: draft
qualification: NO_GO
revision: 1
owner: recorder-engineering
depends_on: 035, 036, 040
---

# 042 — Existing-agent byte boundary integration

This specification defines a small opt-in Python integration for an agent
whose final model transport and tool invocation expose byte-oriented call
sites. It does not auto-discover a framework, intercept arbitrary subprocesses,
or qualify an unrestricted agent. Fabric remains passive CAPTURE → PROTECT →
DELIVER. The integration is a test-start surface, not a production-completeness
claim.

## Required observation and non-claims

An application supplies the exact final request bytes, approved context bytes,
and a delegate callable that performs the original action once. The adapter
observes those supplied bytes, the delegate's exact byte response, and an
explicit outcome. Physical retries use separate attempt IDs. Exceptions are
re-raised unchanged; recording faults only lower evidence status. An application
must instrument *after* its own prompt assembly and serialization. If the
delegate or a lower client transforms the bytes, this adapter cannot claim
provider-bound fidelity. A direct bypass is outside its observation and must
be found by an independent witness or made unreachable by deployment controls.

This adapter may run on the action path and has no proven timing
non-interference. Only nonblocking recorder handoff is allowed; source fsync,
Node export, and content-store I/O remain off the path. The pre-fsync crash
window, unauthenticated source identity, and missing durable destination
receipt keep the complete-run verdict unavailable. No raw bytes enter OTLP.

## Acceptance before implementation

1. An existing byte-oriented caller can add the adapter without replacing its
   transport implementation; the delegate receives the identical byte object
   once and returns the identical object to the caller.
2. Exact binary request, context, response, and zero-byte response resolve
   from the protected store with matching length and SHA-256.
3. The adapter records separate attempt identities and an operation outcome.
   Delegate errors and capture failures do not change caller-visible results.
4. A non-byte response is returned unchanged but marked unsupported; a direct
   bypass appears as a discrepancy against independent endpoint truth.
5. Package-content tests confirm the adapter ships in the installed wheel.

The reference agent may use this adapter to begin integration testing, but
client deployment still requires a versioned capability manifest, bounded
route inventory, target storage qualification, exact-artifact pilot, and
independent owner review under specs 037–039.
