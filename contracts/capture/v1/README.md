# LLM wire-capture contract v1 (draft)

Specified by [spec 042](../../../specs/042-llm-wire-capture-and-reconstruction.md)
(revision 5: store-only stitching, object-id refs, closed metadata values,
heartbeat kinds, proven-end verdicts, pseudonymised report ids) and
[spec 043](../../../specs/043-node-content-delivery-and-agent-spool.md)
(Node content delivery, agent durable spool, run scopes, model exposure;
revision 3: run-id pseudonyms, bounded model prefixes, per-scope verdicts).
Not emitted by recorder v1 and not part of the published contracts archive
until those specs are accepted.

| Schema | Document | Produced by |
|---|---|---|
| `schema/llm-exchange-v1.schema.json` | `fabric.llm-exchange/v1` — the JSON form of one `fabric.model_call` span: exchange id, source position, run, body digests and store object ids, closed-shape response metadata | wire tee (as an OTLP span); normalized by the verifier |
| `schema/loss-record-v1.schema.json` | `fabric.loss-record/v1` — `loss` (a range of exchange sequences that will never produce a span) or `heartbeat` (the source's last allocated sequence, with `heartbeat_kind` `periodic`, `run_start`, `run_end` or `final`) | the capture loss emitter (as `fabric.capture_loss` / `fabric.capture_heartbeat` spans) |
| `schema/run-reconstruction-v1.schema.json` | `fabric.run-reconstruction/v1` — per-run exchanges, threads, gaps and integrity verdict, plus one verdict per `fabric.wire.run()` scope (`scopes[]`) | `python -m fabric.reconstruct` |
| `schema/spool-record-v1.schema.json` | `fabric.wire-spool-record/v1` — the header of one agent spool record (spec 043 §2): an `exchange` (fully resolved `fabric.model_call` span + up to two content descriptors addressing the record's byte blob), a `loss` range, or a `run_start`/`run_end`/`final` marker | the agent's capture worker and sender (on disk, never on the wire) |
| `schema/content-log-record-v1.schema.json` | `fabric.content-log-record/v1` — the JSON form of one OTLP `LogRecord` on the content path: body length and digest, and the exact closed attribute set (`event_class: content` + content-v2 descriptor fields) | agent sender → Fabric Node `otlp/content` → `fabriccontent` exporter |

Every document is metadata only. Request and response bytes live in
customer-controlled content-v2 objects (`model.exchange.request`,
`model.exchange.response`) whose descriptors carry the exchange id, run id,
source position, media type and `content_encoding`. OTLP carries no
message hashes, no tool-call ids and no response ids: all stitching is
derived offline by `fabric.reconstruct` from the stored bytes, so stitching
requires read access to the store.

A stored body is named on OTLP only by its opaque object id (a lowercase
uuid4), never by a path, URI or bucket name; a reader resolves it through
the store it is configured with. A model name is kept only when it matches
`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$` and contains no `://` (no `@`, no
URL, no credentials; otherwise it is omitted), and finish reasons use a
closed vocabulary (anything else is `other`). A model name that matches the
pattern is copied as is: the pattern limits its shape, it does not prove it
free of sensitive text.

Digests in these JSON documents use the `sha256:<hex>` form. The OTLP
projection uses bare 64-hex values because the Node's hash-key rule
(`*_hash`, `*_hashes`, `*_sha256`) admits only bare lowercase hex.

`fixtures/digests/stitch-v1-messages.json` pins the `fabric.stitch/v1`
per-message projection that `fabric.reconstruct` applies to stored bytes:
for each case, `projected` is what an implementation must derive from
`raw`, `canonical` is its spec-029 canonical JSON and `sha256` the digest
of those UTF-8 bytes. Cases marked `same_digest_as` prove that a message
hashes identically when returned in a response and when re-sent in the next
request. These digests never leave the verifier.

Completeness rests on per-source sequence numbers, heartbeats and the
offline verifier: a lost exchange always shows as a sequence gap. Loss
records only *explain* a gap (its reason); a gap without one is still
detected and still makes the run `partial`. Heartbeats are deduplicated by
`(source, epoch, kind, run_id, last_sequence)`, so a retried export counts
once. A run is `complete_for_declared_scope` only when its end is proven:
by its own paired `run_start`/`run_end` markers on every source it used,
or, for a run without markers, by its source epoch's `final` heartbeat
(written by a clean close, after which the epoch allocates nothing). Each
proven window names its evidence in `closed_by`; `periodic` heartbeats
never prove an end.

The run verdict is an integrity verdict for a declared scope (per-source
sequence windows and the evidence that closes them), not a quality
evaluation: `complete_for_declared_scope` means no known or unexplained
capture gap inside that scope, never that the agent behaved correctly.

The reconstruction report carries provider-derived ids (response,
previous-response and tool-call ids) only as `p-` + the first 16 hex of
their sha256, consistently within the report, and never names the location
a store resolved for an object. Operator labels follow spec 043 J1: capture
emits `fabric.source_id` and `service.name` as `s-`/`svc-` + the first 32
hex of `HMAC-SHA256(FABRIC_WIRE_ID_KEY, value)` (SHA-256 without a key)
unless `FABRIC_WIRE_LABELS=clear`, and the report shows the tenant as `t-` +
32 hex and source and run ids only in pseudonymous form;
`fixtures/run-ids/run-id-pseudonym-v1.json` pins the function (the same hex
under every prefix). A model name after a built-in or configured `prefix*`
carries at most two numbers of at most 4 digits and one date, no token
with a digit run over 4 (but an 8-digit date) and at most 6 digits outside
the date (spec 043 §7, J2/J2b; `fixtures/model-names/model-exposure-v1.json`).

**Spec 043 additions.** `scope_id` (`fabric.run.scope_id`, a lowercase
uuid4, unique per `fabric.wire.run()` block entry) appears on exchanges
started inside an open block, on `run_start`/`run_end` markers (never on
`periodic` or `final` heartbeats), on reconstruction windows that are one
scope and on reconstruction exchanges; `runs[].scopes[]` lists every scope
with its state. A complete run has only closed scopes; a scope window is
`[run_start.last_sequence + 1, run_end.last_sequence]` and only sequences
inside it decide completeness. A model name is kept as is only when it also
matches the model allowlist; otherwise it appears as `m-` + 16 hex of its
SHA-256.

**Spec 043 revision 3 additions.** A caller-supplied run id appears only
as `r-` + 32 hex of `HMAC-SHA256(FABRIC_WIRE_ID_KEY, run_id)` (or
`SHA-256(run_id)` without a key); `fixtures/run-ids/run-id-pseudonym-v1.json`
pins the function. A `prefix*` model allowlist entry matches only
version-like suffixes; `fixtures/model-names/model-exposure-v1.json` holds
the vectors capture (Python), fabricguard (Go) and `fabric.reconstruct`
all test against. Both are `vectors` artifacts in the manifest; the
validator checks their shape and that each output follows from its input
(the `m-` digest of a value that is not allowed, the `r-` pseudonym).

Completeness is claimed per scope and per unscoped run. The top-level
`scopes[]` gives each scope of a reported run its own `verdict`, `gaps`
(each also a gap of its run) and `checks`. A run without scopes is
`complete_for_declared_scope` at best; a run with scopes is never better
than its worst scope and at best `complete_for_observed_scopes`: a scope
whose records were all lost before reaching the agent's spool leaves no
trace, so the report makes no claim about it. A sequence claimed by
conflicting observations invalidates every window holding it
(`digest_mismatch`, `conflicting_claim`), and a `complete` or
`closed_early` exchange without a response digest is a `missing_object`
gap (`response_not_recorded`).

The content descriptor definition is identical in the spool and content
log-record schemas: the content-v2 descriptor fields without `encoding`
and `ref`, which every writer adds itself. `fixtures/golden/` pins the
exact bytes a writer must produce for the descriptor sidecar
(`json.dumps(descriptor, ensure_ascii=False, sort_keys=True) + "\n"`, so
`", "` and `": "` separators) and the object and descriptor keys of the
shared layout (`<prefix><tenant>/evidence/<object_id>` and
`<prefix><tenant>/evidence/meta/<object_id>.json`), for a file directory and
an S3 prefix. The Fabric Node's `fabriccontent` exporter and the SDK local
store must both match them byte for byte.

```bash
python scripts/contracts/validate_capture_contracts.py
```
