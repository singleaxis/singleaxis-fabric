# Reconstruct and verdicts

`python -m fabric.reconstruct` is Fabric's offline verifier for wire
capture. It reads the capture spans and the content store, checks that the
record is complete and unaltered, rebuilds each run from the stored bytes,
and states an **integrity** verdict per run scope and per run. It is
read-only, makes no network call except to the store you name, and never
judges the agent's behaviour.

Source: `sdk/python/src/fabric/reconstruct/`. Report schema:
`fabric.run-reconstruction/v1`.

## Inputs

| Option | Meaning |
|---|---|
| `--spans PATH` (repeatable, required) | Span files: the example sink's JSONL, OTLP/JSON (one request per file or per line), or raw OTLP protobuf `*.otlp` files as `make export-spans` copies them. A directory stands for its `*.otlp` files. |
| `--store-root DIR` | A local content store (`file://` mode, or the Node's file backend). |
| `--content-key-file PATH` | The Node file backend's content key, to open its sealed objects under `--store-root`. Never logged. |
| `--store-uri s3://BUCKET/PREFIX` | An S3 or S3-compatible store. Needs `pip install "singleaxis-fabric[s3]"` (boto3). Credentials come from the default AWS chain. With `--s3-endpoint-url`, `--s3-region`, `--s3-path-style`. |
| `--tenant ID` | Tenant of the store; required with a store. |
| `--run RUN_ID` (repeatable) | Report only this run: the id given to `fabric.wire.run()` in the clear, its `r-` pseudonym, or a `source:`/`trace:` fallback id. |
| `--id-key-env NAME` | Variable holding the id key (default `FABRIC_WIRE_ID_KEY`). Needed to match clear run ids against keyed pseudonyms. |
| `--wait-for-objects SECONDS` | Re-read missing objects for up to this long (max 3600) before reporting them missing; content can still be in flight just after a run. |
| `--trusted-source` | The span files are the Node's own export or destination, read from a location you trust. Only then do the Node's `fabric.source.authenticated` stamps count. |
| `--profile local\|production` | Default: `production` when any span carries the Node's stamp, else `local`. Production requires every record to be authenticated. |
| `--model-allowlist TEXT` | Model names reported as is (default `$FABRIC_WIRE_MODEL_ALLOWLIST`); others appear as `m-` digests. |
| `--out FILE` | Write the report atomically with mode `0600` instead of stdout. |

Diagnostics never echo an argument value, path, key or exception message.

## What it checks

1. **Sequence.** Every capture source numbers its records per process epoch.
   A missing number is a `sequence_gap`; a range the capture side reported
   as lost (`fabric.capture_loss`) is a `loss`.
2. **Tail.** The closing heartbeat (`final`) proves nothing was lost after
   the last record. Without it the tail is `tail_unverified`.
3. **Bytes.** Every stored request and response is fetched, its digest and
   length are recomputed and its descriptor is checked against the
   content-v2 contract and the exchange identity. Split sides (a skeleton
   plus extracted parts) are reassembled and checked against the original
   digest.
4. **Stitching.** The bytes are parsed (OpenAI chat completions, responses,
   completions, embeddings; Anthropic messages; JSON and SSE) to link tool
   calls to the results sent back, conversation prefixes and
   `previous_response_id`.
5. **Source authentication** (production profile). Every record and every
   stored object must carry the Node's `fabric.source.authenticated` stamp,
   and the spans must come from `--trusted-source`.

## Gaps

| Gap type | Effect | Meaning |
|---|---|---|
| `sequence_gap` | partial | A record is missing with no loss record explaining it. |
| `loss` | partial | Capture recorded a loss (`queue_full`, `internal_error`, `shutdown`, `span_dropped`). |
| `tail_unverified` | unverified | No final heartbeat, so loss after the last record cannot be ruled out. |
| `missing_object` | partial | A body the record references is not in the store (`not_stored`, `absent`, `response_not_recorded`, `part_missing`, ...). |
| `digest_mismatch` | partial | Stored bytes or descriptor do not match the record, or two records conflict. |
| `truncated` | partial | A side was larger than the capture limits and stored truncated. |
| `unparsed_exchange` | unverified | Stored bytes could not be parsed (`not_json`, `unrecognized_shape`, ...). |
| `prefix_break` | info | The conversation history was rewritten between calls. |
| `unmatched_tool_call` | info or partial | A tool call with no result, or a result with no call, inside the run. |
| `unresolved_previous_response` | partial | A `previous_response_id` that no captured exchange produced. |
| `source_unauthenticated` | unverified | Production profile: a record or object without the Node's stamp, or spans that were imported rather than read back from a trusted location. |

Content that was **not captured by configuration** (production profile
without policy or keys, `metadata_only`, `omit`) produces no missing-object
gap, but the byte check is skipped, which makes the verdict `unverified`.
`tokenize` output cannot be parsed, so it is `unverified` too.

## Verdicts

A scope or run takes the worst effect among its gaps: any `partial` gap
gives `partial`; otherwise any `unverified` gap or skipped check gives
`unverified`; otherwise it is complete.

| Verdict | Applies to | Meaning |
|---|---|---|
| `complete_for_declared_scope` | a `fabric.wire.run()` scope, or a run without scopes | Every model call that started in the scope through an instrumented httpx/httpx2 transport to a matched endpoint was captured, stored unaltered and stitched without gaps. |
| `complete_for_observed_scopes` | a run made of scopes | Every scope that left a record is complete. A scope whose every record died in memory (for example a killed process) left nothing to claim. |
| `partial` | scope or run | Something the record proves existed is missing or altered. |
| `unverified` | scope or run | Completeness cannot be shown (missing tail, unparsable bytes, content not captured, or unauthenticated in production). |

Exit codes: `0` every run and scope is complete; `1` anything is `partial`
or `unverified`, or no run was reconstructed; `2` an input, usage or
internal error.

**What a complete verdict does not say.** It covers only calls made through
httpx or httpx2 to a matched endpoint, in processes whose records reached
the store. It says nothing about calls through `aiohttp`, `requests` or
other clients, other processes, unlisted endpoints, tool execution or
effects, and nothing about whether the agent behaved correctly. See
[limitations](limitations-and-roadmap.md).

Without `fabric.wire.run()`, each process epoch is its own run, named
`source:<source-id>:<epoch>`.

## Examples

Local `file://` store:

```bash
python -m fabric.reconstruct --spans spans.jsonl \
  --store-root ./store --tenant demo-tenant --run react-demo-1 --out report.json
```

Production Node with an S3 store, spans read back from the Node's
destination:

```bash
FABRIC_WIRE_ID_KEY=... python -m fabric.reconstruct \
  --spans ./node-export --trusted-source --profile production \
  --store-uri s3://my-bucket/fabric/content/ --tenant my-tenant \
  --wait-for-objects 30 --out report.json
```

Node file backend (objects are sealed):

```bash
python -m fabric.reconstruct --spans ./node-export --trusted-source \
  --store-root /var/lib/fabric-node/content --content-key-file ./content.key \
  --tenant my-tenant --out report.json
```

Try breaking a record: delete one `fabric.model_call` line from a span file
(`partial`, `sequence_gap`), flip a byte in a stored object (`partial`,
`digest_mismatch`), or remove the `fabric.capture_heartbeat` lines
(`unverified`, `tail_unverified`).

## Scope of the verifier

`fabric.reconstruct` verifies **wire capture** only. Records from the
explicit APIs (`decision()`, `CallRecorder`, byte-boundary adapters) are not
read by it; the explicit line has its own offline checks, and portable,
receipt-backed proof is [qualified-run mode](qualified-run-mode.md), which
alone can state `verified_complete_for_declared_scope`. The four-layer
coverage report of spec 049 (per-layer verdicts, step projection) is not
built.
