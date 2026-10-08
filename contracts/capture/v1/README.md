# LLM wire-capture contract v1 (draft)

Specified by [spec 042](../../../specs/042-llm-wire-capture-and-reconstruction.md)
(revision 3, store-only stitching). Not emitted by recorder v1 and not part
of the published contracts archive until spec 042 is accepted.

| Schema | Document | Produced by |
|---|---|---|
| `schema/llm-exchange-v1.schema.json` | `fabric.llm-exchange/v1` — the JSON form of one `fabric.model_call` span: exchange id, source position, run, body digests and refs, cheap response metadata | wire tee (as an OTLP span); normalized by the verifier |
| `schema/loss-record-v1.schema.json` | `fabric.loss-record/v1` — `loss` (a range of exchange sequences that will never produce a span) or `heartbeat` (the source's last allocated sequence) | the capture loss emitter (as `fabric.capture_loss` / `fabric.capture_heartbeat` spans) |
| `schema/run-reconstruction-v1.schema.json` | `fabric.run-reconstruction/v1` — per-run exchanges, threads, gaps and integrity verdict | `python -m fabric.reconstruct` |

Every document is metadata only. Request and response bytes live in
customer-controlled content-v2 objects (`model.exchange.request`,
`model.exchange.response`) whose descriptors carry the exchange id, run id,
source position, media type and `content_encoding`. OTLP carries no
message hashes and no tool-call ids: all stitching is derived offline by
`fabric.reconstruct` from the stored bytes, so stitching requires read
access to the store.

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

The run verdict is an integrity verdict for a declared scope (per-source
sequence windows and the heartbeat that covers them), not a quality evaluation: `complete_for_declared_scope` means no
known or unexplained capture gap inside that scope, never that the agent
behaved correctly.

```bash
python scripts/contracts/validate_capture_contracts.py
```
