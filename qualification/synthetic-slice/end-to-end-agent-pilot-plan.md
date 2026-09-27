# Installed-artifact synthetic agent pilot plan

Status: test design, not a production-completeness claim. This extends the
bounded scope in spec 040; it does not add SSH, database, browser, cloud, or
universal host capture.

## Declared workflow and independent truth

The deterministic controller makes three model calls to a loopback fixture
endpoint. The first response requests a no-shell terminal tool which creates
a binary file. The second requests a different terminal tool which modifies
that file and emits both stdout and stderr. The third observes the final
artifact and returns a final response. The controller passes exact prior
response, terminal result, and artifact bytes as subsequent model context.
One model attempt is retried, with a distinct attempt ID. The fixture endpoint
records each received request and emitted response independently of Fabric.
The terminal fixture writes a separate, fsynced execution journal; the pilot
also inventories artifact bytes before and after each tool. These records are
the comparison oracle, not Fabric's own events or aggregate counts.

## Required checks

1. Build a wheel, install it in a clean virtual environment, and verify the
   imported `fabric` module comes from that environment, not the checkout.
2. Run the fixture with no real provider credentials or customer data. Assert
   exact request/response bodies, context, argv, cwd, stdin/stdout/stderr,
   exit status, artifact before/after bytes, attempts, source sequence, and
   causal controller order against the independent records. Verify each
   governed object by tenant, byte length, and SHA-256.
3. Project the settled metadata to AEEP OTLP after the action finishes. Send
   it to the installed Fabric Node in isolated kind. Check the projected
   per-event role/status/digest mapping before export, and require every
   record ID and digest to appear in the controlled fsync sink's stored
   payloads. This is byte-presence verification, not a parsed destination
   receipt binding each attribute to its record. Confirm secret canaries and
   local refs are absent from exported bytes.
4. Inject a direct provider bypass and a required-object loss in separate
   runs. Each must produce a discrepancy and `partial`, never a complete
   verdict. A clean match remains `unverified` because source authentication,
   the pre-fsync window, and durable destination receipts are not solved by
   this fixture.

## Limits and release decision

The no-shell terminal proxy and synchronous file observer can perturb the
agent; this pilot tests reconstruction, not passive non-interference. The
controlled sink's fsync readback proves only that test sink's bytes, not a
general destination receipt. A missing independent feed, package mismatch,
sink record, canary containment, or gap downgrade fails this pilot. Passing
the pilot does not change the recorder's NO-GO status in the absence of the
remaining spec-039 target-environment and sign-off gates.
