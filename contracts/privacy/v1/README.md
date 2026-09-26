# Fabric export privacy assertion v1

This contract records a processor's assertion about which customer-approved
export policy it applied to one delivery batch. An unsigned assertion is not
independent proof, is not a prompt-time PII control, and does not claim that data
is legally de-identified.

The assertion binds the input digest, protected output digest, policy digest,
component build and workload identity to a batch ID. `verification.status`
states whether an external issuer verified it. Current fixtures honestly use
`unverified`; signed verification is represented only when issuer, key, subject
digest, algorithm, and signature are all present. The v1 export contract permits
metadata, hashes, and governed references; it cannot claim raw content export.

All SHA-256 values cover the exact bytes of the named pinned UTF-8 file. JSON
reserialization changes the digest; RFC 8785 canonicalization is not claimed.
`manifest.json` pins the schema and every JSON fixture; Markdown
documentation, including this README, is not a pinned artifact.
