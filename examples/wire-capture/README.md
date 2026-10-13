<!-- Copyright 2026 AI5Labs Research OPC Private Limited -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# LLM wire capture and run reconstruction

A ReAct agent's model traffic is its decision log: request N+1 is request N
plus response N plus the tool results, linked by tool-call ids. This example
captures that traffic at the wire, with no framework adapter, and then
rebuilds the run offline ([spec 042](../../specs/042-llm-wire-capture-and-reconstruction.md),
[spec 043](../../specs/043-node-content-delivery-and-agent-spool.md)).

This example uses the direct local store (`file://` mode): one process,
fully offline. In a deployment the agent runs in **node mode** instead: it
spools capture events to disk and delivers the bodies to the Fabric Node,
which is the only writer of the content store (a directory or S3) and holds
the only store credentials. See
[Deploying LLM wire capture](../../docs/wire-capture-deployment.md).

```bash
# from the repository root
sdk/python/.venv/bin/python examples/wire-capture/react_agent.py
```

Expected tail of the output:

```text
run r-73312ae07246b3a81a3c4f7073ae3a4f: verdict=complete_for_observed_scopes
  scope …: verdict=complete_for_declared_scope
  thread-0: exchanges=['…', '…', '…']
reconstruct exit code: 0
```

The run id `react-demo-1` never appears in the record: capture writes only
its pseudonym `r-…` (keyed by `FABRIC_WIRE_ID_KEY` when that is set, which
production should do), and `--run react-demo-1` asks the verifier to
compute the same pseudonym.

## What happens

1. A plain `httpx` ReAct loop calls an OpenAI-compatible
   `/v1/chat/completions` endpoint. The model is an `httpx.MockTransport`
   handler, so nothing leaves the machine. It asks for `get_weather`, then
   `c_to_f`, then answers.
2. `fabric.wire.install(...)` is given a local content store, a tracer
   provider and an extra `EndpointMatcher` for the fake host. The client
   uses `fabric.wire.WireTransport`. (With the default `patch_httpx=True`,
   every `httpx.Client` in the process is covered, including the OpenAI and
   Anthropic SDKs.)
3. Each model call is teed: the request and response bytes, exactly as the
   transport saw them, go to `output/store/` as content-v2 objects
   (`model.exchange.request`, `model.exchange.response`). The
   `fabric.model_call` span written to `output/spans.jsonl` carries only ids,
   digests, the source sequence number and refs. No message is parsed at
   capture time. Each entry into `fabric.wire.run(...)` is a run scope with
   its own `fabric.run.scope_id`: entering and leaving it emits heartbeat
   run markers (`fabric.capture_heartbeat`) carrying that id, and every call
   inside it carries the id too. The run id itself leaves the process only
   as its `r-…` pseudonym. Closing the handle emits a final heartbeat
   that proves the tail. The model name `demo-model` is not on the public
   model allowlist, so spans carry it only as an `m-…` digest
   (`FABRIC_WIRE_MODEL_ALLOWLIST` extends the list).
4. `python -m fabric.reconstruct --spans … --store-root … --tenant …` reads
   both. It checks sequences, loss records and the run scope's markers, verifies
   every stored body against its digest, then parses the bytes to stitch the
   run (tool-call ids, message prefixes). It writes `output/report.json`
   (`fabric.run-reconstruction/v1`).

You can re-run the verifier yourself:

```bash
sdk/python/.venv/bin/python -m fabric.reconstruct \
  --spans examples/wire-capture/output/spans.jsonl \
  --store-root examples/wire-capture/output/store --tenant demo-tenant \
  --run react-demo-1
```

Try breaking the record and running it again. Delete a line from
`spans.jsonl` and you get `partial` (`sequence_gap`). Flip a byte in a store
object and you get `digest_mismatch`. Remove the `fabric.capture_heartbeat`
lines and you get `unverified` (`tail_unverified`).

## What the verdict means

Completeness is claimed per `fabric.wire.run()` entry (a *scope*) and per
unscoped process epoch. Each scope's `complete_for_declared_scope` is an
**integrity** statement about the record: every model call started inside
that block through the instrumented httpx transport was captured, stored,
unaltered and stitched without gaps. A run made of scopes is at best
`complete_for_observed_scopes`: it vouches for every scope that left a
record, and makes no claim about a block whose every record was lost
before reaching disk (for example when the process is killed). It does not judge the agent. It also does
not cover calls made through other clients (`requests`, `aiohttp`, gRPC),
other processes or unlisted endpoints.

## Passivity

The tee never changes the request or the response, never injects headers
and never raises into the agent. Hashing, storage and span export
run on a background worker with a bounded queue. If capture fails (queue
full, exporter failure, shutdown), the agent proceeds and a
`fabric.capture_loss` record makes the gap visible. A body over the buffer
cap or a store outage is flagged on the exchange span itself
(`fabric.wire.truncated`, `fabric.wire.store_status`).

## Privacy

`output/store/` holds the real request and response bodies. HTTP headers,
including `Authorization`, are never stored. Treat the directory as
sensitive and delete it when done. Spans and the report contain no content.
