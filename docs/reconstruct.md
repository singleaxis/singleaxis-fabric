# Reconstruct and verdicts

> **Status:** describes built code, released in v0.8.0. Implementation:
> [`fabric/reconstruct/`](../sdk/python/src/fabric/reconstruct/). The
> options added in v0.10.0 (`--projection` and the run-state options) are
> in [the P1 run record](run-record.md#using-it), and the `actions` view in
> [agent action reconstruction](action-reconstruction.md); its production
> options (`--host-source`, `--host-pid-namespace`, `--agent-pid-namespace`,
> `--sandbox-peer`) were added in v0.11.0.

`python -m fabric.reconstruct` is Fabric's offline verifier for wire
capture. It reads the capture spans and the content store, checks that the
record is complete and unaltered, rebuilds each run from the stored bytes,
and states an **integrity** verdict per run scope and per run. It is
read-only, makes no network call except to the store you name, and never
judges the agent's behaviour.

The verifier checks integrity and pairs tool calls with their results.
Since v0.10.0, `python -m fabric.reconstruct actions` also links those
calls to the subprocess effects they caused and to host-sensor evidence
([spec 056](../specs/056-agent-action-reconstruction.md) milestone M1,
local profile). Since v0.11.0 (milestone M2) it also reads production host
sources from a Node's export; see
[agent action reconstruction](action-reconstruction.md).

Source: `sdk/python/src/fabric/reconstruct/`. Report schema:
`fabric.run-reconstruction/v1`.

## Inputs

| Option | Meaning |
|---|---|
| `--spans PATH` (repeatable, required) | Span files: the example sink's JSONL, OTLP/JSON (one request per file or per line), or raw OTLP protobuf `*.otlp` files as `make export-spans` copies them. A directory stands for its `*.otlp`, `*.json` and `*.jsonl` files (an OpenTelemetry Collector file exporter writes `.jsonl`), not recursively; a directory with none of its own but a `spans/` directory (the `./fabric-data` that `fabric up` prints) stands for that. |
| `--store-root DIR` | A local content store (`file://` mode, or the Node's file backend). |
| `--content-key-file PATH` | The Node file backend's content key, to open its sealed objects under `--store-root`. Never logged. |
| `--store-uri s3://BUCKET/PREFIX` | An S3 or S3-compatible store. Needs `pip install "singleaxis-fabric[s3]"` (boto3). Credentials come from the default AWS chain. With `--s3-endpoint-url`, `--s3-region`, `--s3-path-style`. |
| `--tenant ID` | Tenant of the store; required with a store. |
| `--run RUN_ID` (repeatable) | Report only this run: the id given to `fabric.wire.run()` in the clear, its `r-` pseudonym, or a `source:`/`trace:` fallback id. |
| `--latest` | Report only the run that started last (by its first model exchange). Use it instead of `--run`, not with it; `fabric verify` and `fabric show` select a `fabric run` by its label without it. |
| `--id-key-env NAME` | Variable holding the id key (default `FABRIC_WIRE_ID_KEY`). Needed to match clear run ids against keyed pseudonyms. |
| `--wait-for-objects SECONDS` | Re-read missing objects for up to this long (max 3600) before reporting them missing; content can still be in flight just after a run. |
| `--trusted-source` | The span files are the Node's own export or destination, read from a location you trust. Only then do the Node's `fabric.source.authenticated` stamps count. |
| `--profile local\|production` | Default: `production` when any span carries the Node's stamp, else `local`. Production requires every record to be authenticated. |
| `--model-allowlist TEXT` | Model names reported as is (default `$FABRIC_WIRE_MODEL_ALLOWLIST`); others appear as `m-` digests. |
| `--out FILE` | Write the full JSON report atomically with mode `0600`; the one-line summary per run goes to stderr. |
| `--json` | Print the full JSON report on stdout. Without `--json` or `--out`, the reader prints one line per run: `RUN: VERDICT (N exchanges, M gaps: GAP_TYPE, ...)`. Exit codes are the same either way. |
| `--projection FILE` | Since v0.10.0 (see [step projection](#step-projection)). Also write the `fabric.step-projection/v1` document here, atomically with mode `0600`. |
| `--coverage-profile ID` | Since v0.10.0. The coverage profile the projection is judged against (default `fabric.profile.model-calls/v1`). |
| `--evaluated-at RFC3339` | Since v0.10.0. The time run states and open-run deadlines are computed at (default: now). |
| `--clock-uncertainty DURATION` | Since v0.10.0. Added to each segment's declared clock uncertainty when segments are ordered (`250ms`, `2s`; a bare number is seconds; default `0`). |
| `--max-clock-uncertainty DURATION` | Since v0.10.0. The largest total clock uncertainty accepted before ordering is reported as `clock_uncertain` (default `300s`). |
| `--host-records FILE` (repeatable) | Since v0.10.0. Local-profile host-sensor records (OTLP/JSON or sink JSONL log rows) for the host join ([agent action reconstruction](action-reconstruction.md)). Since v0.11.0 (spec 056 M2): optional when `--spans` holds production host records, which the verifier splits out of the export. |
| `--host-label LABEL` | Since v0.10.0. The host of local records, as the agents' `FABRIC_HOST_LABEL` names it; taken only with `--host-records` (production records name their host). |
| `--host-source KIND[=SOURCE_ID]` (repeatable) | Since v0.11.0 (M2). Declares a host sensor (`host.ebpf`, `host.auditd`), optionally one process by its `s-` id (`print-source-id`). A declared source with no records in the run window is a `source_gap`. |
| `--host-pid-namespace KIND=MODE` (repeatable) | Since v0.11.0 (M2). `recorded` or `declared_same` for every source of a kind; default per source: `recorded` when every record carries `fabric.sensor.pid_ns`. |
| `--agent-pid-namespace NS` | Since v0.11.0 (M2). The agent's pid-namespace inode when its effects do not agree on one. |
| `--sandbox-peer ADDRESS[:PORT]` (repeatable) | Since v0.11.0 (M2). A remote sandbox provider (`[ADDRESS]:PORT` for IPv6): the agent's connections to it are H4 links, and while `remote.sandbox` is not active, `remote_sandbox_calls`. With a port, only that port. |
| `--endpoint-peer ID=ADDRESS`, `--known-peer ADDRESS` (repeatable) | Since v0.10.0. Addresses of a model endpoint, or of Fabric's own delivery and infrastructure: the agent's connections to them are not unexplained. |
| `--agent-pid PID` | Since v0.10.0. The agent's pid, for H4 when no effect names it. |
| `--host-coverage-declared` | Since v0.10.0. Declares that local records cover the run; refused for production records, whose heartbeats prove coverage. |
| `--derive RULE` (repeatable) | Unreleased (spec 057 P1). Applies a wire derivation rule to the stored model-call bytes: `wire.offered_grant`, `wire.safety_map`, `wire.tool_result_flag`, or `wire` for all three ([what the reader derives from the model wire](action-reconstruction.md#what-the-reader-derives-from-the-model-wire---derive)). Off by default: without it every run is reported as before. |
| `--tool-result-markers FILE` | Unreleased (spec 057 P1). A JSON file with your exact tool-result denial markers; a matching tool result gives one `configured_marker` control row. An entry that declares `allow`, or is malformed, is refused and named by index and reason in the report's `inputs.derivation`. |

Diagnostics never echo an argument value, path, key or exception message.

## Step projection

Spec 050 P1 waves 0–2 are released in v0.10.0 (except WP-15 and WP-21).
With them, the verifier also merges a run's segments (ordered within the
clock uncertainty above), reports run states, and can write the run as a
`fabric.step-projection/v1` document (`--projection`, spec 050 §3.13): the
steps, their parents and the typed links between them, judged against a
coverage profile. Sources: `reconstruct/_graph.py`, `reconstruct/_project.py`.

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
| `loss` | partial | Capture recorded a loss (`queue_full`, `disk_full`, `internal_error`, `shutdown`, `span_dropped`, or `uninstrumented_client`: a model call sent through `requests` or `urllib3`, which wire capture does not tee). |
| `tail_unverified` | unverified | No final heartbeat, so loss after the last record cannot be ruled out. |
| `missing_object` | partial | A body the record references is not in the store (`not_stored`, `absent`, `response_not_recorded`, `part_missing`, ...). |
| `digest_mismatch` | partial | Stored bytes or descriptor do not match the record, or two records conflict. |
| `truncated` | partial | A side was larger than the capture limits and stored truncated. |
| `unparsed_exchange` | unverified | Stored bytes could not be parsed (`not_json`, `unrecognized_shape`, ...). |
| `prefix_break` | info | The conversation history was rewritten between calls. |
| `unmatched_tool_call` | info or partial | A tool call with no result, or a result with no call, inside the run. |
| `unresolved_previous_response` | partial | A `previous_response_id` that no captured exchange produced. |
| `source_unauthenticated` | unverified | Production profile: a record or object without the Node's stamp, or spans that were imported rather than read back from a trusted location. |

**Gap listing.** A run lists up to 16 segments of a stretch of missing or
lost sequences one by one. A longer stretch (a heavily load-shed source)
is reported as one gap per reason, from its first to its last segment, and
that range can include sequences that were recorded. Take the exact
missing sequences from the source's `sources[].missing_sequences` (and
`loss_ranges`), which list every range once. Verdicts and checks are the
same either way. The report is streamed, so heavy loss keeps it bounded.

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
| `complete_for_declared_scope` | a `fabric.wire.run()` scope, or a run without scopes | Every model call that started in the scope through an instrumented httpx, httpx2 or aiohttp client to a matched endpoint was captured, stored unaltered and stitched without gaps. |
| `complete_for_observed_scopes` | a run made of scopes | Every scope that left a record is complete. A scope whose every record died in memory (for example a killed process) left nothing to claim. |
| `partial` | scope or run | Something the record proves existed is missing or altered. |
| `unverified` | scope or run | Completeness cannot be shown (missing tail, unparsable bytes, content not captured, or unauthenticated in production). |

Exit codes: `0` every run and scope is complete; `1` anything is `partial`
or `unverified`, or no run was reconstructed; `2` an input, usage or
internal error, including a content store that refuses the reader
(AccessDenied, an expired token, a local permission error).

**Reading objects.** A transient read failure (throttling, a 5xx, a reset
connection, a timeout, or a body that stops streaming) is retried up to 5
times, with about 3 s of backoff in all, before the object reads as
`missing_object` (`read_error`). An object the store does not hold reads as
`missing_object` (`absent`) at once, or after `--wait-for-objects`. A store
that refuses the reader's credentials is a setup error (exit 2): the reader
never reports objects as missing when it was not allowed to read them.

**What a complete verdict does not say.** It covers only calls made through
httpx, httpx2 or aiohttp to a matched endpoint, in processes whose records
reached the store. A matched call through `requests` or `urllib3` is not
silent: it is an `uninstrumented_client` loss and the run is `partial`. A
complete verdict says nothing about calls through other clients (`boto3`,
gRPC), other processes, unlisted endpoints, tool execution or effects, and
nothing about whether the agent behaved correctly. See
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
coverage report of spec 049 (per-layer verdicts, step projection) is not in
v0.8.0 or v0.9.x; since v0.10.0 the verifier also reads records-input
records and writes the step projection for model calls
([the P1 run record](run-record.md)).

When the inputs hold no run it can reconstruct, the reader prints
`no runs reconstructed` and then why, from what the inputs hold:
explicit-API spans with no capture record (as the TypeScript SDK sends:
they lack the capture sequence `fabric.source_id`, `fabric.source.epoch`,
`fabric.source.sequence` and the `fabric.capture_heartbeat` markers), spans
with no Fabric record at all (capture was not installed: run
`python -m fabric.wire status` with the agent's environment), capture
records with no model exchange (no call matched an endpoint), or a `--run`
that matches nothing. It names only Fabric span names, never a value from
the input. The exit code stays `1`.
