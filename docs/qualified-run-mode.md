# Qualified-run mode

Qualified-run mode is an **opt-in**, Python-only, offline verification path
for runs recorded with the explicit `CallRecorder` line
([spec 049](../specs/049-four-layer-capture-coverage.md) §2.13, specs
[045](../specs/045-independent-evidence-feeds.md) and
[046](../specs/046-qualified-call-run-verification.md)). It is the only path
in Fabric that can return `verified_complete_for_declared_scope`: a
complete-run statement backed by independent evidence and signed receipts,
not only by the recorder's own output.

Default capture (wire capture and `fabric.reconstruct`) never reaches that
verdict; its strongest result is `complete_for_declared_scope` /
`complete_for_observed_scopes`, an integrity statement about what the
recorder captured.

Qualified-run mode is a library, not a service: no signing service, key,
network call or receipt issuer comes with it, and there is no CLI. It does
not judge the agent.

## What it compares

`fabric.qualified_run.verify_qualified_call_run(...)` takes:

| Input | What it is |
|---|---|
| `snapshot` | The `CallRecorder.snapshot()` (`fabric.call-recording/v1`) |
| `source_spool` | The `SyntheticSourceSpool` journal the recorder wrote, sealed with `CallRecorder.seal_source()` after the work |
| original-byte resolver | A `ByteEvidenceResolver` over the original (not masked) objects |
| independent feeds | One `QualifiedFeedInput` per witness (provider, tool, caller): a signed operation and byte ledger produced outside Fabric, read through `fabric.independent_store.LocalIndependentFeedResolver` |
| `source_binding_attestation`, `route_closure_attestation` | Signed statements that the source is who it claims and that every reachable route was declared |
| `receipts` | Four separately signed exact receipt sets: `source_spooled`, `node_accepted`, `destination_accepted`, `destination_durable` |
| `trusted_keys` | `EvidenceTrustKey` entries (Ed25519 public key, issuer, tenant, permitted statement types, validity, revocation), supplied out of band by the deployment owner |
| expectation | `QualifiedRunExpectation`: tenant, run, scope digest, source id and epoch, declared routes, feed and issuer expectations |

It checks every operation, attempt, outcome, required original object and
ordered chunk against the independent feeds; re-reads the sealed journal
(exact record set and terminal sequence); verifies every signature against
the trusted registry; and requires all four receipt stages. A missing proof
cannot be replaced by a caller flag, another stage's receipt, a count, a
masked copy or an OTLP success response.

## Verdicts

Schema `fabric.qualified-call-run/v1`:

| Verdict | Meaning |
|---|---|
| `verified_complete_for_declared_scope` | Every required proof and exact comparison passed under the supplied trust registry and scope. |
| `partial` | A known omission, contradiction or loss was detected. |
| `unverified` | Required authority or evidence could not be established. |

The result also lists reason codes, per-feed status and per-stage receipt
status.

## How to opt in

1. Record with `CallRecorder(recorder, ..., source_spool=SyntheticSourceSpool(root, tenant_id=..., run_id=...))`.
2. After the monitored work ends (never on the call path), call
   `calls.seal_source()`.
3. Collect the independent feeds, attestations and the four receipt sets
   from issuers you operate and trust.
4. Run `verify_qualified_call_run` offline with an explicit verification
   time.

Building blocks you can use on their own: `fabric.evidence_attestation`
(`attestation_signing_bytes`, `verify_evidence_attestation`; Ed25519,
envelope `fabric.evidence-attestation/v1`), `fabric.receipt_sets` and
`fabric.independent_feed.verify_independent_feed`. Install the `signing`
extra (`cryptography`).

## Reproduce the bounded test

From a repository checkout, with the SDK installed from a built wheel (the
script refuses source-tree imports):

```bash
pip install "./sdk/python[otlp,signing]"
python scripts/qualification/run_qualified_call_pilot.py --fixture-only --evidence-dir /new/empty/dir
```

It drives a loopback model endpoint, a no-shell subprocess, a binary file
artifact and a second model call, then verifies 4 operations and 15
original objects and runs 24 negative tests (each omission or substitution
must lose the complete verdict). The positive result is
`verified_complete_for_declared_scope` with `production_status: NO_GO`.

## Limits

- One source, epoch 0, one tenant and run per verification. Multiple
  sources or epochs are not supported.
- The pilot's signatures are **test fixtures**. Fabric does not issue live
  Node or destination receipts; a real deployment needs issuers for all four
  stages, an independent native ledger per declared route and owner-supplied
  keys.
- A signature authenticates an issuer's assertion; it does not prove the
  issuer observed every action.
- Wire capture records are not inputs; qualified-run mode covers the
  explicit `CallRecorder` line only. Not available in TypeScript.
