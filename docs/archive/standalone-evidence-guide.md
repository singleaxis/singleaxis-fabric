# Standalone evidence: capture, protect, deliver and read back

Fabric records observable AI activity into customer-controlled destinations.
No SingleAxis service, portal or action-enforcement service is required. Existing
OpenTelemetry is the smallest integration; explicit Python final-dispatch
wrappers add permitted bytes and physical-attempt identity where needed.

```text
Application / existing OTel / explicit adapter
  -> bounded SDK admission -> source journal + optional protected byte spool
  -> Fabric Node metadata allowlist -> durable queue -> customer OTLP destination
Customer-authorized content store -> separate authorized consumer readback
Independent operation/effect witness -> offline reconciliation
```

These are distinct evidence paths. Node protects metadata and does not store
model/tool payloads as OTLP bodies. Original or derived content uses a separately
configured store. Destination acceptance does not prove durable content or
metadata readback. The default product is passive CAPTURE -> PROTECT -> DELIVER.

## Start with the existing application boundary

Initialize capture once, wrap the existing shared final model/tool dispatch,
propagate parent context at background handoffs, join producers, then close
capture. No framework rewrite is required. For model calls made through httpx,
the [wire-capture example](../examples/wire-capture/README.md) records the exact
bytes with no wrapper at all. An outer provider wrapper
cannot expose retries hidden inside a provider SDK. Supply the actual serialized
request/response bytes; unsupported objects remain unsupported evidence while
the application result is preserved.

The Python `CallRecorder` supports synchronous/asynchronous calls and streams.
Explicitly close an interrupted stream. A returned root result, successful flush,
or empty queue cannot establish that all producers stopped. Independently track
expected producers, their final epochs and joins. The optional host
sensors observe scoped process/network metadata, not TLS plaintext or universal
shell/PTY sessions. [TypeScript support](sdk-support-matrix.md) is narrower: its
byte recorder does not have Python's call recorder, durable source journal,
encrypted spool, delivery ledger or closure parity.

## Choose privacy and customer storage before real content

Use a validated `DeploymentPolicy` and explicit per-role policy. Its
`ByteEvidenceRecorder` path applies Fabric's own protections (tokenize, omit,
metadata only) before queue admission; customer redaction (`redact`, `masked_only`)
and the separate `BytePrivacyPolicy` masked modes run behind the queue, in a
transformation child process: raw input can exist in process memory before that
transformation. Do not confuse that worker-side masking with pre-queue protection. Neither mechanism
rewrites arbitrary host exporters, diagnostics or provider logs.

Use [authenticated local governed storage](governed-local-storage.md) for the
implemented Python customer-local backend, or qualify your own adapter. Supply
stable customer-held authority and encryption keys, private directories, grants
and the original policy snapshot. Separate write, original-read, derivative-read
and lifecycle permissions. Opaque references are not bearer grants. Output
encrypted with ephemeral demo keys cannot be reopened after exit, and fixture
key files are not a production KMS.

The local backend verifies envelopes, decrypts and checks lengths/digests. Its
fsync and signed audit chain do not provide cloud IAM/KMS, anti-rollback, backup
erasure or independent service evidence. Retention/purge is explicit. Configure
stable key custody and authorized readback for a real consumer, then test restart
with those same keys. Do not generate replacement keys and call old data lost
without investigating the actual custody failure.

## Read back without trusting the recorder's live memory

Retrieve metadata from the selected destination, then resolve permitted content
using an independently initialized consumer and customer-authorized store.
Verify reference identity, tenant, workload, representation, length and digest;
retain explicit missing, denied, pending, corrupted and unverified results.
Original and masked/derived views are different evidence. A matching original
can establish exact captured bytes; a derivative cannot reconstruct an original.
For flat byte-event attributes recovered from the destination, use:

```python
from fabric.governed_reconstruction import GovernedEvidenceResolver

# Reopen GovernedLocalContentStore with its original policy and customer keys;
# issue a fresh read_original or read_derivative grant for the selected plane.
resolver = GovernedEvidenceResolver(authorized_store)
result = resolver.resolve(destination_event_attributes)
if result.status == "available":
    consume_authorized_bytes(result.data, representation=result.representation)
else:
    record_unresolved(result.status, result.reason)
```

The snippet's consumer functions and store setup are application-owned. The
resolver checks object and deployment bindings using the store's fixed namespace;
telemetry cannot choose a filesystem path. It does not invoke the original tool,
rewrite historical `pending` admission status, or prove producer closure.
Older events without the required workload/policy/privacy bindings resolve as
`unverified` (`metadata_binding_invalid`); the consumer does not infer a past
policy or rewrite a journal. Exact originals additionally require digest and
length bindings. Derivatives retain their redacted/tokenized representation.
The store's authenticated `read` and `read_descriptor` APIs are documented in
[storage](governed-local-storage.md); the legacy filesystem resolver is not
compatible with governed envelopes.

For stronger offline claims, [qualified call-run verification](qualified-call-run-testing.md)
checks supplied independent feeds, fresh source readback and distinct
`source_spooled`, `node_accepted`, `destination_accepted` and
`destination_durable` receipt sets. Fixture issuers demonstrate the interface;
they are not live provider or customer infrastructure witnesses.

That verifier currently requires its legacy original-byte resolver and settled
snapshot shape. The governed journal journey retains historical pending
observations; its receipt identities are different. Successful governed object
readback therefore does not establish `verified_complete` through that verifier.
Older journals also lack the new policy and privacy bindings: strict governed
reconstruction returns unverified for them instead of inventing those bindings.
The authorized store API remains available for separately verified legacy IDs.

Record remote effects as `requested`, `acknowledged`, `committed` or `unknown`
according to available evidence. A request was attempted; a successful response
acknowledged it; only authoritative independent state/readback supports committed.
Record existing permission decisions as attempted, granted and exercised facts
with their observers. Fabric does not grant permission or enforce those decisions.

## Demonstrate the bounded local path

Run the [wire-capture example](../examples/wire-capture/README.md) for an
offline capture and `python -m fabric.reconstruct` verdict, and the
[qualified call-run tests](qualified-call-run-testing.md) for the explicit
evidence line. For the Compose path, use the [quickstart](quickstart.md) and
`make qualify`. These are local fixtures: production remains `NO_GO` until the
declared customer scope, independent truth, storage controls and exact
artifacts are qualified.

An empty legacy transcript accumulator means no content observations were
recorded. Both SDKs leave its URI absent and publish no transcript; attempting
to serialize that empty accumulator fails explicitly. Capturing an empty string
produces a stored zero-byte content observation. Neither a closed transcript
snapshot nor a normal root return proves that detached producers have finished.
