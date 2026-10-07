# LLM wire-capture contract v1 (draft)

Specified by [spec 042](../../../specs/042-llm-wire-capture-and-reconstruction.md).
Not emitted by recorder v1 and not part of the published contracts archive
until spec 042 is accepted.

| Schema | Document | Written by |
|---|---|---|
| `schema/llm-exchange-v1.schema.json` | `fabric.llm-exchange/v1` — one model API call: identity, sequence, run, stitching keys, body object pointers | wire tee / gateway tap, stored as content-v2 role `model.exchange.record` |
| `schema/loss-record-v1.schema.json` | `fabric.loss-record/v1` — a capture loss or a source watermark | normalized by the verifier from `fabric.capture_loss` / `fabric.capture_watermark` spans |
| `schema/run-reconstruction-v1.schema.json` | `fabric.run-reconstruction/v1` — per-run exchanges, threads, gaps and integrity verdict | `python -m fabric.reconstruct` |

Every document is metadata only. Request and response bytes live in
customer-controlled content-v2 objects (`model.exchange.request`,
`model.exchange.response`); OTLP carries digests, ids, counts and refs.

Digests in these JSON documents use the `sha256:<hex>` form. The OTLP
projection uses bare 64-hex values because the Node's hash-key rule
(`*_hash`, `*_hashes`, `*_sha256`) admits only bare lowercase hex.

`fixtures/digests/stitch-v1-messages.json` pins the `fabric.stitch/v1`
per-message projection: for each case, `projected` is what an
implementation must derive from `raw`, `canonical` is its spec-029
canonical JSON and `sha256` the digest of those UTF-8 bytes. Cases marked
`same_digest_as` prove that a message hashes identically when returned in a
response and when re-sent in the next request. Builders test their
projection against `raw -> projected`; the validator pins
`projected -> canonical -> sha256`.

The run verdict is an integrity verdict for a declared scope, not a quality
evaluation: `complete_for_declared_scope` means no known or unexplained
capture gap inside that scope, never that the agent behaved correctly.

```bash
python scripts/contracts/validate_capture_contracts.py
```
