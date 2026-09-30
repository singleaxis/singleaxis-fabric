# Fabric delivery evidence contract v1

This contract keeps Fabric Node delivery states separate. `queued`,
`transmitted`, `destination.accepted`, and
`destination.durably_persisted` are different facts and must never collapse into
one ambiguous success value.

A durable-persistence claim requires a proof issued by the configured
destination and bound to the batch payload digest. The contract records a
detached signature and key identifier, but cryptographic signature verification
requires the destination trust material and is deliberately outside fixture
validation.

Payload and privacy-assertion SHA-256 values cover the exact bytes of their pinned UTF-8
JSON files (`digest_scope: exact_file_bytes`). RFC 8785 canonicalization is not claimed.
`manifest.json` pins the schema and every JSON fixture; Markdown documentation,
including this README, is not a pinned artifact.
