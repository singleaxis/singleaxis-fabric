# LLM wire-capture contract v1 (draft)

Specified by [spec 042](../../../specs/042-llm-wire-capture-and-reconstruction.md)
(revision 5: store-only stitching, object-id refs, closed metadata values,
heartbeat kinds, proven-end verdicts, pseudonymised report ids). Not emitted by recorder v1 and not part
of the published contracts archive until spec 042 is accepted.

| Schema | Document | Produced by |
|---|---|---|
| `schema/llm-exchange-v1.schema.json` | `fabric.llm-exchange/v1` — the JSON form of one `fabric.model_call` span: exchange id, source position, run, body digests and store object ids, closed-shape response metadata | wire tee (as an OTLP span); normalized by the verifier |
| `schema/loss-record-v1.schema.json` | `fabric.loss-record/v1` — `loss` (a range of exchange sequences that will never produce a span) or `heartbeat` (the source's last allocated sequence, with `heartbeat_kind` `periodic`, `run_start`, `run_end` or `final`) | the capture loss emitter (as `fabric.capture_loss` / `fabric.capture_heartbeat` spans) |
| `schema/run-reconstruction-v1.schema.json` | `fabric.run-reconstruction/v1` — per-run exchanges, threads, gaps and integrity verdict | `python -m fabric.reconstruct` |

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
a store resolved for an object.

```bash
python scripts/contracts/validate_capture_contracts.py
```
