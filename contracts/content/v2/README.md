# Byte-content contract v2 (draft)

This contract extends [content v1](../v1/README.md) to exact binary bytes.
LLM wire capture ([spec 042](../../../specs/042-llm-wire-capture-and-reconstruction.md),
[spec 043](../../../specs/043-node-content-delivery-and-agent-spool.md))
writes `model.exchange.*` objects with this descriptor. It is not part of
the released recorder v1 contract set, and content v1 remains unchanged.
The role vocabulary is wider than the roles any runtime emits today; a role
in the schema is not a capture claim.

`scripts/contracts/validate_content_v2_contracts.py` validates the pinned
schema and fixtures.

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

## Model-exchange roles (spec 042, draft)

`model.exchange.request` and `model.exchange.response` hold the complete
HTTP body of one model API call exactly as transmitted/received by the
in-process wire tee (`provenance: protocol`, `representation: exact`,
`partial` or `truncated`). Both roles use `boundary: provider_bound`,
`operation_id` = the exchange id, and the exchange's `run_id` and
`source_*` position, so the store is self-describing.

`content_encoding` is the HTTP `Content-Encoding` of the stored bytes,
lowercased with whitespace removed (`identity` when the header was absent,
`unknown` when it was not a valid token list). Wire bytes are stored as
received and never decompressed at capture; a reader decodes them. The
narrower `model.request.*` / `model.output.messages` roles are unchanged
and are not emitted by the wire tee.
