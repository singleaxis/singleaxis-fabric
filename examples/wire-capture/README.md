<!-- Copyright 2026 AI5Labs Research OPC Private Limited -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# LLM wire capture and run reconstruction

A ReAct agent's model traffic is its decision log: request N+1 is request N
plus response N plus the tool results, linked by tool-call ids. This example
captures that traffic at the wire, with no framework adapter, and then
rebuilds the run offline ([spec 042](../../specs/042-llm-wire-capture-and-reconstruction.md)).

```bash
# from the repository root
sdk/python/.venv/bin/python examples/wire-capture/react_agent.py
```

Expected tail of the output:

```text
run react-demo-1: verdict=complete_for_declared_scope
  thread-0: exchanges=['…', '…', '…']
reconstruct exit code: 0
```

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
3. Each model call is teed: the exact request and response bytes go to
   `output/store/` as content-v2 objects (`model.exchange.request`,
   `model.exchange.response`, `model.exchange.record`). The
   `fabric.model_call` span written to `output/spans.jsonl` carries only ids,
   digests, sequence numbers and refs. Leaving `fabric.wire.run(...)` emits a
   run-close watermark (`fabric.capture_watermark`).
4. `python -m fabric.reconstruct --spans … --store-root … --tenant …
   --recompute-digests` reads both. It checks sequences, loss records, tail
   proof, stored bytes and stitching, then writes
   `output/report.json` (`fabric.run-reconstruction/v1`).

You can re-run the verifier yourself:

```bash
sdk/python/.venv/bin/python -m fabric.reconstruct \
  --spans examples/wire-capture/output/spans.jsonl \
  --store-root examples/wire-capture/output/store --tenant demo-tenant
```

Try breaking the record and running it again. Delete a line from
`spans.jsonl` and you get `partial` (`sequence_gap`). Flip a byte in a store
object and you get `digest_mismatch`. Remove the `fabric.capture_watermark`
line and you get `unverified` (`tail_unverified`).

## What the verdict means

`complete_for_declared_scope` is an **integrity** statement about the
record. Every model call made through the instrumented httpx transport in
this process was captured, stored, unaltered and stitched without gaps,
through the declared watermark. It does not judge the agent. It also does
not cover calls made through other clients (`requests`, `aiohttp`, gRPC),
other processes or unlisted endpoints.

## Passivity

The tee never changes the request or the response, never injects headers
and never raises into the agent. Hashing, parsing, storage and span export
run on a background worker with a bounded queue. If capture fails (queue
full, buffer cap, store outage, exporter failure), the agent proceeds and a
`fabric.capture_loss` record makes the gap visible.

## Privacy

`output/store/` holds the real request and response bodies. HTTP headers,
including `Authorization`, are never stored. Treat the directory as
sensitive and delete it when done. Spans and the report contain no content.
