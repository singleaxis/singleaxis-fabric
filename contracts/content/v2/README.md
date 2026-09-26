# Governed byte evidence contract v2 (draft)

This contract is a proposed extension of [content v1](../v1/README.md),
specified by [AEEP](../../../specs/035-agent-execution-evidence-profile.md)
and its [build plan](../../../specs/036-evidence-capture-implementation-plan.md).
It is not emitted by recorder v1. Content v1 remains unchanged.

The descriptor records the relationship between *source bytes* and *stored
bytes*. A source digest is present only when those bytes were actually
observed. A stored digest covers exactly the stored bytes, including when
they were redacted or truncated. Binary content is supported without
coercion to UTF-8. `pending` may name a prospective object; `stored`,
`truncated`, and `redacted` require a resolvable, credential-free
reference. Missing/failed/dropped/unsupported items have no reference or
stored-byte digest. `unavailable` is the representation for
`not_captured`, `unsupported`, `dropped`, or `failed` objects; source-byte
length and digest may still be present when the source actually observed
them and policy permits fingerprints.

References must be credential-free and contain the exact tenant ID as a
path segment, without query parameters, fragments, encoded/traversal
segments, or remote authority on `file://` refs. This syntax check does not
authorize a store access or prove tenant isolation; the resolver must enforce
those checks with customer-controlled identity and storage policy.

The JSON fixture under `fixtures/bytes/` uses base64 only to make the
contract test portable. It is **not** a prescription to place encoded content
in OTLP; the bytes belong in the customer-controlled content store.
