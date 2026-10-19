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

## Model-exchange roles (spec 047, draft)

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

## Producer-specific source position

`source_id`, `source_epoch` and `source_sequence` are schema-compatible
across producers, but `source_epoch` semantics are producer-specific. The
wire tee (spec 047/048) sets it to `time_ns` at allocator creation (about
1.8e18), so a restart is a new epoch. The explicit evidence line
(specs 043–046) uses a persisted small counter and caps epochs and cursors
at 2^53-1. Wire records are not inputs to spec 045 feeds or spec 046
qualified verification; admitting them there needs a separate 050-series
spec.

## Role and descriptor widening (spec 049, manifest 2.1.0)

[Spec 049](../../../specs/049-four-layer-capture-coverage.md) §4.3 widens
this draft contract; `contracts/coverage/v1/registry/content-roles-v1.json`
is the single role table, and the coverage validator fails unless `role`
lists every row of it, existing roles first. Version 2.1.0 adds:

- the new roles of the role table (`model.exchange.part`, `actor.identity`,
  `run.*`, `mcp.*`, `control.*`, `artifact.locator`, ...);
- `representation: split` and `transformations: extract_parts` for a side
  stored as a skeleton plus extracted parts (§7.4-§7.5). A split skeleton is
  stored whole and carries the `source_sha256` of the original body;
- `links.relation: part_of`, with an optional `byte_range` allowed only on
  `part_of`: the half-open `[start, end)` offsets of the part in the original
  body. `valid/split-reassembly-retain-original.json` pins reassembly: every
  part inserted at its range into the skeleton reproduces `source_sha256`;
- the receiver-owned `source_authenticated` boolean (§4.3 rule 6, §7.9). Only
  the `fabriccontent` exporter writes it into the persisted descriptor; an
  agent-supplied value is rejected by the exporter's closed parser.

Version 2.2.0 (spec 049 P0-A) adds:

- the privacy modes `masked_only` (only a masked copy is stored, outcome
  `redacted`) and `original_plus_masked` (the original, outcome `retained`,
  plus a masked review copy, outcome `redacted`, that names the original
  with a `derived_from` link and keeps no digest or length of it);
- withholding on a failed transformation in any byte-storing mode:
  `not_captured`, `protection_status: withheld`, `status_reason:
  protection_failed`, no original-body digest (§7.7);
- `fixtures/node-envelope-v1.json`: the Node directory backend's AES-256-GCM
  customer-key envelope (§7.8), pinned for every reader.

The `fabriccontent` exporter enforces the role table and these rules on the
content path (capture/v1 `content-log-record-v1`); nothing in this directory
changes what recorder v1 emits.
