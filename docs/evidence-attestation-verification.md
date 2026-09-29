# Authenticating offline evidence statements

The optional Python verifier in spec 044 checks who signed an evidence
statement and exactly which scope, run and byte digest that statement covers.
Install the SDK's `signing` extra. No signing service, private key, network
request or production approval is supplied by this feature.

Use `fabric.evidence_attestation.EvidenceTrustKey` for each public key approved
by the deployment owner. Pin its issuer, tenant, permitted statement types,
signing validity interval and revocation state. A key offered inside the
evidence is rejected; the trusted registry must arrive through a separate
administrative path. The deployment owner must restrict each issuer to its
approved stages and separately establish witness independence. The verifier
enforces that registry; it cannot make overbroad grants safe.

The envelope has exactly `schema_version`, `algorithm`, `key_id`, `payload`,
and `signature`. Version is `fabric.evidence-attestation/v1`; algorithm is
`Ed25519`; signature is canonical base64. The closed payload contains:

| Field | Required meaning |
| --- | --- |
| `statement_type` | `source_binding`, `independent_witness`, `source_spooled`, `node_accepted`, `destination_accepted`, or `destination_durable` |
| `issuer_id`, `tenant_id` | Identifies the approved authority and its tenant |
| `run_id`, `scope_sha256` | Names the run and exact approved scope bytes |
| `subject_kind`, `subject_id`, `subject_sha256` | Identifies the exact source, evidence set, event or content object covered |
| `issued_at`, `expires_at` | Integer UTC Unix seconds defining statement validity |

`attestation_signing_bytes(payload, key_id=...)` supplies the external issuer
with the deterministic bytes to sign. Those bytes begin with
`singleaxis.fabric.evidence-attestation/v1` and a zero byte, followed by compact
ASCII JSON with sorted keys for the version, algorithm, key ID and payload.
All identifiers are bounded ASCII, digests are lowercase SHA-256 and timestamps
are bounded integers. There is no floating-point or arbitrary Unicode
canonicalization. Producers must use this exact profile.

An offline consumer independently computes the subject and scope digests and
constructs `EvidenceExpectation`. It calls `verify_evidence_attestation` with
that expectation, the approved key registry and an explicit verification time.
The result is `verified` only for an authorized signature matching every
expected field. All evidence failures return `unverified` with fixed reasons;
input content and exception messages are not copied into diagnostics.

Key validity is checked at both issuance and verification time. An expired or
revoked key cannot authorize a current verification: its holder could otherwise
backdate a new statement. Historical validation beyond key expiry requires a
separately trusted timestamp or durable receipt of the original signature;
that mechanism is not supplied here. The expectation pins the exact issuer,
so a different same-tenant destination cannot substitute a receipt. Customer
key custody, rotation, revocation distribution and independent-feed
authorization remain deployment controls.

A valid signature authenticates an issuer's assertion. It cannot prove that
the issuer actually observed every action or completed a durable write.
Those producer behaviors and independent truth feeds need their own tests.
The custom-agent reconciler still reports matching local fixtures as
`unverified`; this verifier alone never enables a complete-run or production
GO verdict. The next required integration binds independently observed full
operation/byte sets, route closure, source lifecycle and four receipt stages to
the same frozen run and artifact bundle.

Run the tampering and authority tests:

```sh
sdk/python/.venv/bin/python -m pytest -q -o addopts= -p no:cacheprovider sdk/python/tests/test_evidence_attestation.py
```
