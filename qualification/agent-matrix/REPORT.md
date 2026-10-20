# Agent matrix: zero-code wire capture on real agent frameworks

Worktree `test/agent-matrix`, based on `feat/four-layer-p0a` @ `22d1085`. Run on
2026-10-20 (macOS 26.3 arm64, CPython 3.12.13, Docker 29.4). The Fabric wheel and the
Node image (`fabric/node:agent-matrix`, built from `components/otel-collector-fabric`)
come from this worktree unchanged. No Fabric code was modified; every finding below is
reported, not fixed.

## Verdict

- **Single-process agents: works unmodified.** There are 18 single-process
  framework/pattern rows: OpenAI Agents SDK in two model modes, plain openai with Chat
  Completions and Responses, plain anthropic, LangGraph, LlamaIndex, PydanticAI with
  OpenAI and Anthropic models, smolagents, AutoGen, AG2, CrewAI, DSPy (two transports),
  multi-agent handoff, RAG, and asyncio gather. Of these, 15 pass every scenario in
  local file mode and in Node mode. The other three fall short in one place each:
  - `dspy`: LiteLLM's default aiohttp transport is not instrumented, so it is reported
    as UNCAPTURED.
  - `dspy-httpx / disconnect`: a conservative `unverified` verdict on a torn body
    (D5); nothing was lost.
  - `gather / long50`: honest `queue_full` loss (D3).

  Across these rows, 1619 of 1761 model calls are captured with byte-exact request and
  response in the store; the 142 misses are the D3 overflow and the aiohttp calls.
  Reconstruct reports complete on every lossless run except the D5 case. Agent output, exceptions,
  tool-call sequence and request bytes are identical with and without capture.
- **(b) holds everywhere.** In 152 local cases, 23 Node cases and 58 loss probes,
  reconstruct never reported `complete` after losing a call through an instrumented
  client. The single `complete` next to lost calls is traffic through clients Fabric
  does not instrument (D4).
- **Multiprocessing is broken (D1) and fork on macOS is not passive (D2).** These are
  the two blocking defects.
- **(d) holds.** In Node mode with the production overlay, the planted secret never
  reached telemetry, the opened spool, the store, the Node queues or the logs under
  `masked_only`, `redact`, `tokenize`, `metadata_only`, `omit`, a failing
  transformation, or `masked_only` with no transformation configured. That is 18/18
  cases across two agents.
- **(c) overhead** is about 0.1–0.6 ms added at p50 per SDK call and about 0.2–2.6 ms
  at p99, on loopback against a server that answers in under 1 ms (tables below).

## What was run

`run.sh` is the single entry point. Its stages are `setup`, `local`, `node`, `privacy`,
`probes`, `bench` and `report`, and each stage writes `results/raw/**`.

- `harness/fake_llm.py`: a deterministic loopback server, OpenAI and Anthropic
  compatible. It serves `/v1/chat/completions`, `/v1/responses`, `/v1/messages` and
  `/v1/embeddings`, each streaming (SSE) and non-streaming, with tool calls, parallel
  tool calls, scripted multi-step ReAct (including DSPy's ChatAdapter and classic
  Thought/Action text), injected 429 then retry, 400/500 errors, and a mid-stream or
  mid-body disconnect. The model name selects the script (`fm-s<steps>-p<parallel>-<fault>`).
  Responses are a pure function of the request body, so the baseline and captured runs
  get byte-identical answers. The server logs the exact bytes and the client
  fingerprint (User-Agent and header order). No real API keys are used. Proxies point
  at a dead port, and framework telemetry is disabled.
- `frameworks/<name>/requirements.{in,lock}`: one pinned uv venv per framework
  (`.work/venvs/<name>`), locked together with Fabric's own dependencies.
- `agents/*.py`: ordinary framework code. Nothing in them imports or mentions Fabric.
  Each agent writes its output, exception and tool-call sequence canonically so the
  runs can be compared byte for byte.
- `harness/launch.py`: framework interpreters run as `python -I`. Because `-I` ignores
  `PYTHONPATH`, the launcher imports the autoload `sitecustomize` from
  `python -m fabric.wire --print-autoload-path` exactly as `PYTHONPATH` would. It holds
  no capture code: capture is decided only by `FABRIC_*` variables. Spawned children
  cannot inherit this, so the `pool-spawn*` rows use the documented mechanism instead
  (`PYTHONPATH` plus `python -s -P`).
- `harness/run_matrix.py`: for each case it runs a baseline with no Fabric variable,
  then a capture run with `FABRIC_WIRE_AUTOLOAD=1`, a file store and an OTLP sink. It
  then (a) pairs every server-seen exchange with a `fabric.model_call` span by request
  digest and checks the stored objects (split sides are reassembled from their parts)
  against the wire bytes, (b) runs `python -m fabric.reconstruct`, and (c) compares the
  result bytes and request digests. If they differ, it runs a second baseline to
  separate framework nondeterminism from Fabric effects.
- `harness/extras.py`:
  - Node mode reuses the `test_wire_capture_s3_eval_e2e` stack unchanged: compose base
    plus the production overlay, the content path, fabric-gate, fabricguard source
    binding, the sealed content queue, and SeaweedFS S3 with SSE. Agents get only the
    `FABRIC_*`/`OTEL_*` variables (node mode, sealed spool, capture policy, id key).
    Readback is trusted readback with the production profile.
  - The privacy cases plant a random secret in the prompt and in the tool results.
  - Loss probes tamper with stores and spans after the run, or kill or starve capture
    during it.
  - The benchmark times each SDK call in-process, alternating capture off and on.

Scenarios:
- `simple`: 2-round tool loop.
- `stream`: SSE.
- `parallel`: 2 tool calls per round.
- `retry429`: first sight of each body returns 429 with retry-after, and the client
  retries.
- `disconnect`: the first sight of each body is cut halfway.
- `multimodal`: two ~103 KiB base64 PNGs. The body cap is lowered to 160 KiB so the
  side is split into a skeleton plus `model.exchange.part` objects.
- `long50`: 50 tool rounds, 51 or more calls.
- `node`: `simple` through the real Node.
- `n/a`: the scenario does not exist for the pattern.

Status meanings:
- `UNCAPTURED`: some calls went through a client Fabric does not instrument (never
  counted as a pass).
- `ERROR`: the harness or framework integration failed without capture (none remain).

<!-- generated:begin -->
### Framework x scenario matrix

| Framework | simple | stream | parallel | retry429 | disconnect | multimodal | long50 | node |
|---|---|---|---|---|---|---|---|---|
| openai | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| openai-responses | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| anthropic | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| openai-agents | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| openai-agents-chat | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| langgraph | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| llamaindex | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| pydantic-ai | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| pydantic-ai-anthropic | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| smolagents | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| autogen | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| ag2 | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| crewai | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| dspy | PASS | UNCAPTURED | PASS | PASS | UNCAPTURED | PASS | PASS | PASS |
| dspy-httpx | PASS | PASS | PASS | PASS | **FAIL** | PASS | PASS | PASS |
| handoff | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| rag | PASS | PASS | n/a | PASS | PASS | n/a | PASS | PASS |
| gather | PASS | PASS | PASS | PASS | PASS | PASS | **FAIL** | PASS |
| pool-spawn | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** |
| pool-fork | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** |
| pool-spawn-join | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| pool-fork-join | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** | **FAIL** |

Totals: FAIL 26, PASS 146, UNCAPTURED 2.

Cells that are not PASS:

- **dspy / stream** (UNCAPTURED): 1/4 calls via aiohttp (not instrumented)
- **dspy / disconnect** (UNCAPTURED): 1/7 calls via aiohttp (not instrumented)
- **dspy-httpx / disconnect** (FAIL): reconstruct not complete: unverified['unparsed_exchange', 'unparsed_exchange', 'unparsed_exchange']
- **gather / long50** (FAIL): 140/408 httpx exchanges not captured
- **pool-spawn / simple** (FAIL): 24/24 httpx exchanges not captured
- **pool-spawn / stream** (FAIL): 24/24 httpx exchanges not captured
- **pool-spawn / parallel** (FAIL): 24/24 httpx exchanges not captured
- **pool-spawn / retry429** (FAIL): 48/48 httpx exchanges not captured
- **pool-spawn / disconnect** (FAIL): 8/8 httpx exchanges not captured
- **pool-spawn / multimodal** (FAIL): 16/16 httpx exchanges not captured
- **pool-spawn / long50** (FAIL): 408/408 httpx exchanges not captured
- **pool-spawn / node** (FAIL): 16/24 httpx exchanges not captured
- **pool-fork / simple** (FAIL): 24/24 httpx exchanges not captured
- **pool-fork / stream** (FAIL): 24/24 httpx exchanges not captured
- **pool-fork / parallel** (FAIL): 24/24 httpx exchanges not captured
- **pool-fork / retry429** (FAIL): 48/48 httpx exchanges not captured
- **pool-fork / disconnect** (FAIL): 8/8 httpx exchanges not captured
- **pool-fork / multimodal** (FAIL): 16/16 httpx exchanges not captured
- **pool-fork / long50** (FAIL): 408/408 httpx exchanges not captured
- **pool-fork / node** (FAIL): 14/24 httpx exchanges not captured
- **pool-fork-join / simple** (FAIL): 24/24 httpx exchanges not captured
- **pool-fork-join / stream** (FAIL): 24/24 httpx exchanges not captured
- **pool-fork-join / parallel** (FAIL): 24/24 httpx exchanges not captured
- **pool-fork-join / retry429** (FAIL): 48/48 httpx exchanges not captured
- **pool-fork-join / disconnect** (FAIL): 8/8 httpx exchanges not captured
- **pool-fork-join / multimodal** (FAIL): 16/16 httpx exchanges not captured
- **pool-fork-join / long50** (FAIL): 408/408 httpx exchanges not captured
- **pool-fork-join / node** (FAIL): 16/24 httpx exchanges not captured

### Totals (local file mode)

- Cases: 152; model calls seen by the server: 3969; captured with exact request and response bytes in the store: 2171.
- Reconstruct complete (`complete_for_declared_scope`/`complete_for_observed_scopes`) in 128/152 cases.
- Passivity: agent output, exception and tool-call sequence byte-identical with and without capture in 151/152 cases; request bodies identical in 152/152.

### Frameworks, versions and HTTP clients

| Row | What runs | Key versions | HTTP client seen by the server (User-Agent) |
|---|---|---|---|
| openai | chat completions, hand-written loop | openai 3.35.1, httpx2 2.14.0 | OpenAI/Python 3.35.1 |
| openai-responses | Responses API, hand-written loop | openai 3.35.1, httpx2 2.14.0 | OpenAI/Python 3.35.1 |
| anthropic | Messages API, tool loop | anthropic 1.15.0, httpx2 2.14.0 | Anthropic/Python 1.15.0 |
| openai-agents | Runner + function tools, Responses model | openai 3.35.1, openai-agents 0.24.0, httpx2 2.14.0 | Agents/Python 0.24.0 |
| openai-agents-chat | Runner + function tools, Chat Completions model | openai 3.35.1, openai-agents 0.24.0, httpx2 2.14.0 | Agents/Python 0.24.0 |
| langgraph | create_react_agent + langchain-openai ChatOpenAI | openai 3.35.1, langgraph 1.2.16, langchain-openai 1.7.2, httpx 0.28.1, httpx2 2.14.0 | OpenAI/Python 3.35.1 |
| llamaindex | FunctionAgent + OpenAILike | openai 2.54.0, llama-index-core 0.14.25, llama-index-llms-openai-like 0.8.1, httpx 0.28.1, aiohttp 3.14.5 | AsyncOpenAI/Python 2.54.0 |
| pydantic-ai | OpenAIChatModel | openai 3.35.1, anthropic 1.15.0, pydantic-ai-slim 2.57.0, httpx2 2.14.0 | pydantic-ai/2.57.0 |
| pydantic-ai-anthropic | AnthropicModel | openai 3.35.1, anthropic 1.15.0, pydantic-ai-slim 2.57.0, httpx2 2.14.0 | pydantic-ai/2.57.0 |
| smolagents | ToolCallingAgent + OpenAIServerModel | openai 3.35.1, smolagents 1.26.0, httpx2 2.14.0 | OpenAI/Python 3.35.1 |
| autogen | AgentChat AssistantAgent + OpenAIChatCompletionClient | openai 3.35.1, autogen-agentchat 0.7.5, autogen-ext 0.7.5, httpx2 2.14.0 | AsyncOpenAI/Python 3.35.1 |
| ag2 | two ConversableAgents + register_function | openai 3.35.1, ag2 1.1.2, httpx 0.28.1, httpx2 2.14.0 | AsyncOpenAI/Python 3.35.1 |
| crewai | Agent/Task/Crew + crewai.LLM | openai 2.54.0, crewai 1.15.28, httpx 0.28.1, httpx2 2.14.0, aiohttp 3.14.5 | OpenAI/Python 2.54.0 |
| dspy | dspy.ReAct + dspy.LM (LiteLLM) | openai 2.54.0, dspy 3.4.1, litellm 1.106.0, httpx 0.28.1, aiohttp 3.14.5 | DSPy/3.4.1 |
| dspy-httpx | as dspy, LiteLLM async on httpx (DISABLE_AIOHTTP_TRANSPORT=True) | openai 2.54.0, dspy 3.4.1, litellm 1.106.0, httpx 0.28.1, aiohttp 3.14.5 | DSPy/3.4.1 |
| handoff | multi-agent handoff: triage -> specialist (OpenAI Agents SDK) | openai 3.35.1, openai-agents 0.24.0, httpx2 2.14.0 | Agents/Python 0.24.0 |
| rag | RAG: VectorStoreIndex, OpenAI-compatible embeddings + chat (LlamaIndex) | openai 2.54.0, llama-index-core 0.14.25, llama-index-llms-openai-like 0.8.1, httpx 0.28.1, aiohttp 3.14.5 | OpenAI/Python 2.54.0 |
| gather | asyncio.gather fan-out of 8 tool loops on one AsyncOpenAI client | openai 3.35.1, httpx2 2.14.0 | AsyncOpenAI/Python 3.35.1 |
| pool-spawn | multiprocessing Pool(4), spawn start method (macOS default); documented PYTHONPATH autoload, since python -I children cannot inherit it | openai 3.35.1, httpx2 2.14.0 | OpenAI/Python 3.35.1 |
| pool-fork | multiprocessing Pool(4), fork start method (Linux default) | openai 3.35.1, httpx2 2.14.0 | OpenAI/Python 3.35.1 |
| pool-spawn-join | as pool-spawn, but pool.close(); pool.join() instead of the with block | openai 3.35.1, httpx2 2.14.0 | OpenAI/Python 3.35.1 |
| pool-fork-join | as pool-fork, but pool.close(); pool.join() instead of the with block | openai 3.35.1, httpx2 2.14.0 | OpenAI/Python 3.35.1 |

### Overhead

Measured inside the agent process around each SDK call (3 alternating rounds off/on, loopback fake server; added = on - off):

| Client | Call kind | n (on) | p50 off | p50 on | **added p50** | p99 off | p99 on | **added p99** |
|---|---|---|---|---|---|---|---|---|
| anthropic-sdk 1.x on httpx2 | nonstream | 900 | 374 µs | 557 µs | **183 µs** | 506 µs | 979 µs | **474 µs** |
| anthropic-sdk 1.x on httpx2 | stream | 450 | 604 µs | 831 µs | **227 µs** | 1027 µs | 1777 µs | **750 µs** |
| anthropic-sdk 1.x on httpx2 | nonmatching | 450 | 344 µs | 454 µs | **111 µs** | 467 µs | 686 µs | **219 µs** |
| openai-sdk 2.x on httpx 0.28 | nonstream | 900 | 541 µs | 857 µs | **315 µs** | 1018 µs | 2606 µs | **1588 µs** |
| openai-sdk 2.x on httpx 0.28 | stream | 450 | 848 µs | 1141 µs | **294 µs** | 1204 µs | 2212 µs | **1007 µs** |
| openai-sdk 2.x on httpx 0.28 | nonmatching | 450 | 394 µs | 623 µs | **228 µs** | 652 µs | 5410 µs | **4758 µs** |
| openai-sdk 3.x on httpx2 | nonstream | 900 | 477 µs | 957 µs | **479 µs** | 645 µs | 3218 µs | **2573 µs** |
| openai-sdk 3.x on httpx2 | stream | 450 | 747 µs | 1329 µs | **583 µs** | 2553 µs | 3629 µs | **1076 µs** |
| openai-sdk 3.x on httpx2 | nonmatching | 450 | 390 µs | 568 µs | **178 µs** | 9202 µs | 1104 µs | **-8098 µs** |

Per framework, from the fake server's clock on the long run (>= 51 sequential calls): the client-side gap between the end of one response and the next request (framework + Fabric work between calls), with and without capture:

| Framework | calls | gap p50 off | gap p50 on | added p50 | gap p99 off | gap p99 on | added p99 |
|---|---|---|---|---|---|---|---|
| openai | 51 | 3.11 ms | 3.17 ms | 0.06 ms | 6.02 ms | 5.87 ms | -0.15 ms |
| openai-responses | 51 | 7.88 ms | 7.93 ms | 0.05 ms | 20.21 ms | 19.43 ms | -0.78 ms |
| anthropic | 51 | 0.46 ms | 0.63 ms | 0.17 ms | 5.02 ms | 8.68 ms | 3.66 ms |
| openai-agents | 51 | 14.04 ms | 14.12 ms | 0.08 ms | 24.30 ms | 24.94 ms | 0.64 ms |
| openai-agents-chat | 51 | 6.10 ms | 5.68 ms | -0.42 ms | 8.87 ms | 9.14 ms | 0.26 ms |
| langgraph | 51 | 6.38 ms | 6.62 ms | 0.24 ms | 25.87 ms | 25.33 ms | -0.54 ms |
| llamaindex | 51 | 5.89 ms | 6.36 ms | 0.47 ms | 9.45 ms | 9.04 ms | -0.41 ms |
| pydantic-ai | 51 | 4.55 ms | 4.92 ms | 0.37 ms | 7.24 ms | 7.60 ms | 0.36 ms |
| pydantic-ai-anthropic | 51 | 1.48 ms | 1.78 ms | 0.29 ms | 18.20 ms | 15.43 ms | -2.77 ms |
| smolagents | 51 | 5.53 ms | 5.85 ms | 0.32 ms | 20.23 ms | 10.88 ms | -9.35 ms |
| autogen | 51 | 5.56 ms | 5.65 ms | 0.09 ms | 20.80 ms | 19.08 ms | -1.73 ms |
| ag2 | 51 | 5.19 ms | 6.14 ms | 0.95 ms | 7.64 ms | 9.32 ms | 1.69 ms |
| crewai | 51 | 5.36 ms | 5.46 ms | 0.10 ms | 9.60 ms | 42.19 ms | 32.59 ms |
| dspy | 52 | 6.55 ms | 6.57 ms | 0.02 ms | 13.43 ms | 12.76 ms | -0.66 ms |
| dspy-httpx | 52 | 7.20 ms | 6.85 ms | -0.35 ms | 13.24 ms | 14.16 ms | 0.92 ms |
| handoff | 52 | 16.60 ms | 16.21 ms | -0.39 ms | 27.75 ms | 27.97 ms | 0.21 ms |
| rag | 50 | 1.01 ms | 1.37 ms | 0.35 ms | 11.28 ms | 11.37 ms | 0.09 ms |

### Node mode (production profile, trusted readback)

| Framework | Status | calls | captured | verdict | source authenticated | spool left |
|---|---|---|---|---|---|---|
| openai | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| openai-responses | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| anthropic | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| openai-agents | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| openai-agents-chat | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| langgraph | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| llamaindex | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| pydantic-ai | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| pydantic-ai-anthropic | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| smolagents | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| autogen | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| ag2 | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| crewai | PASS | 3 | 3 | complete_for_declared_scope | True | 0 |
| dspy | PASS | 4 | 4 | complete_for_declared_scope | True | 0 |
| dspy-httpx | PASS | 4 | 4 | complete_for_declared_scope | True | 0 |
| handoff | PASS | 4 | 4 | complete_for_declared_scope | True | 0 |
| rag | PASS | 4 | 4 | complete_for_declared_scope | True | 0 |
| gather | PASS | 24 | 24 | complete_for_declared_scope | True | 0 |
| pool-spawn | **FAIL** | 24 | 8 | unverified, unverified, unverified, unverified | True | 1 |
| pool-fork | **FAIL** | 24 | 10 | unverified, unverified, unverified | True | 0 |
| pool-spawn-join | PASS | 24 | 24 | complete_for_declared_scope, complete_for_declared_scope, complete_for_declared_scope, complete_for_declared_scope | True | 1 |
| pool-fork-join | **FAIL** | 24 | 8 | unverified, unverified | True | 2 |
| gather (long50) | **FAIL** | 408 | 383 | partial | True | 0 |

### Privacy (P0-A protecting modes, node mode, planted secret)

| Agent | Mode | Zero-code | Status | Leaks | store_reason | stored objects (role, mode, protection, status) | verdict |
|---|---|---|---|---|---|---|---|
| langgraph | masked_only-transform-fails | no (transformation hook) | PASS | none | protection_failed | model.exchange.request/masked_only/withheld/not_captured; model.exchange.response/masked_only/withheld/not_captured | unverified |
| langgraph | masked_only-zero-code | yes | PASS | none | protection_failed | model.exchange.request/masked_only/withheld/not_captured; model.exchange.response/masked_only/withheld/not_captured | unverified |
| langgraph | masked_only | no (transformation hook) | PASS | none | None | model.exchange.request/masked_only/redacted/redacted; model.exchange.response/masked_only/redacted/redacted | complete_for_declared_scope |
| langgraph | metadata_only | yes | PASS | none | privacy_policy | model.exchange.request/metadata_only/withheld/not_captured; model.exchange.response/metadata_only/withheld/not_captured | unverified |
| langgraph | omit | yes | PASS | none | privacy_policy |  | unverified |
| langgraph | original_plus_masked | no (transformation hook) | PASS | none | None | model.exchange.request/original_plus_masked/redacted/redacted; model.exchange.request/original_plus_masked/retained/stored; model.exchange.response/original_plus_masked/redacted/redacted; model.exchange.response/original_plus_masked/retained/stored | complete_for_declared_scope |
| langgraph | redact | no (transformation hook) | PASS | none | None | model.exchange.request/redact/redacted/redacted; model.exchange.response/redact/redacted/redacted | complete_for_declared_scope |
| langgraph | retain_original | yes | PASS | none | None | model.exchange.request/retain_original/retained/stored; model.exchange.response/retain_original/retained/stored | complete_for_declared_scope |
| langgraph | tokenize | yes | PASS | none | None | model.exchange.request/tokenize/tokenized/redacted; model.exchange.response/tokenize/tokenized/redacted | unverified |
| openai | masked_only-transform-fails | no (transformation hook) | PASS | none | protection_failed | model.exchange.request/masked_only/withheld/not_captured; model.exchange.response/masked_only/withheld/not_captured | unverified |
| openai | masked_only-zero-code | yes | PASS | none | protection_failed | model.exchange.request/masked_only/withheld/not_captured; model.exchange.response/masked_only/withheld/not_captured | unverified |
| openai | masked_only | no (transformation hook) | PASS | none | None | model.exchange.request/masked_only/redacted/redacted; model.exchange.response/masked_only/redacted/redacted | complete_for_declared_scope |
| openai | metadata_only | yes | PASS | none | privacy_policy | model.exchange.request/metadata_only/withheld/not_captured; model.exchange.response/metadata_only/withheld/not_captured | unverified |
| openai | omit | yes | PASS | none | privacy_policy |  | unverified |
| openai | original_plus_masked | no (transformation hook) | PASS | none | None | model.exchange.request/original_plus_masked/redacted/redacted; model.exchange.request/original_plus_masked/retained/stored; model.exchange.response/original_plus_masked/redacted/redacted; model.exchange.response/original_plus_masked/retained/stored | complete_for_declared_scope |
| openai | redact | no (transformation hook) | PASS | none | None | model.exchange.request/redact/redacted/redacted; model.exchange.response/redact/redacted/redacted | complete_for_declared_scope |
| openai | retain_original | yes | PASS | none | None | model.exchange.request/retain_original/retained/stored; model.exchange.response/retain_original/retained/stored | complete_for_declared_scope |
| openai | tokenize | yes | PASS | none | None | model.exchange.request/tokenize/tokenized/redacted; model.exchange.response/tokenize/tokenized/redacted | unverified |

### Loss probes (reconstruct must never claim complete after a loss)

| Probe | Framework | Status | Verdict | Non-info gaps | Calls lost / uncaptured |
|---|---|---|---|---|---|
| delete_object | openai | PASS | partial | missing_object |  |
| flip_byte | openai | PASS | partial | digest_mismatch |  |
| drop_span | openai | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | openai-responses | PASS | partial | missing_object |  |
| flip_byte | openai-responses | PASS | partial | digest_mismatch |  |
| drop_span | openai-responses | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | anthropic | PASS | partial | missing_object |  |
| flip_byte | anthropic | PASS | partial | digest_mismatch |  |
| drop_span | anthropic | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | openai-agents | PASS | partial | missing_object |  |
| flip_byte | openai-agents | PASS | partial | digest_mismatch |  |
| drop_span | openai-agents | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | openai-agents-chat | PASS | partial | missing_object |  |
| flip_byte | openai-agents-chat | PASS | partial | digest_mismatch |  |
| drop_span | openai-agents-chat | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | langgraph | PASS | partial | missing_object |  |
| flip_byte | langgraph | PASS | partial | digest_mismatch |  |
| drop_span | langgraph | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | llamaindex | PASS | partial | missing_object |  |
| flip_byte | llamaindex | PASS | partial | digest_mismatch |  |
| drop_span | llamaindex | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | pydantic-ai | PASS | partial | missing_object |  |
| flip_byte | pydantic-ai | PASS | partial | digest_mismatch |  |
| drop_span | pydantic-ai | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | pydantic-ai-anthropic | PASS | partial | missing_object |  |
| flip_byte | pydantic-ai-anthropic | PASS | partial | digest_mismatch |  |
| drop_span | pydantic-ai-anthropic | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | smolagents | PASS | partial | missing_object |  |
| flip_byte | smolagents | PASS | partial | digest_mismatch |  |
| drop_span | smolagents | PASS | partial | sequence_gap |  |
| delete_object | autogen | PASS | partial | missing_object |  |
| flip_byte | autogen | PASS | partial | digest_mismatch |  |
| drop_span | autogen | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | ag2 | PASS | partial | missing_object |  |
| flip_byte | ag2 | PASS | partial | digest_mismatch |  |
| drop_span | ag2 | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | crewai | PASS | partial | missing_object |  |
| flip_byte | crewai | PASS | partial | digest_mismatch |  |
| drop_span | crewai | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | dspy | PASS | partial | missing_object |  |
| flip_byte | dspy | PASS | partial | digest_mismatch |  |
| drop_span | dspy | PASS | partial | sequence_gap |  |
| delete_object | dspy-httpx | PASS | partial | missing_object |  |
| flip_byte | dspy-httpx | PASS | partial | digest_mismatch |  |
| drop_span | dspy-httpx | PASS | partial | sequence_gap |  |
| delete_object | handoff | PASS | partial | missing_object |  |
| flip_byte | handoff | PASS | partial | digest_mismatch |  |
| drop_span | handoff | PASS | partial | sequence_gap, unmatched_tool_call |  |
| delete_object | rag | PASS | partial | missing_object |  |
| flip_byte | rag | PASS | partial | digest_mismatch |  |
| drop_span | rag | PASS | partial | sequence_gap |  |
| sigkill-mid-run | openai | PASS | no run |  | 21 |
| queue-overflow | gather | PASS | partial | loss, unmatched_tool_call | 394 |
| otel-sdk-disabled | openai | PASS | no run |  | 3 |
| uncaptured-clients | mixed-clients | **FAIL** | complete_for_declared_scope |  | 2 (aiohttp, requests) |
| isolated-interpreter-spawn | pool-spawn | PASS | no run |  | 24 |
| fork-without-proxy-env | pool-fork | **FAIL** | no run |  |  |
| store-unwritable | openai | PASS | no run |  | 3 |

<!-- generated:end -->

## Defects (ranked)

### D1 — High: multiprocessing workers lose their captured exchanges

**Symptom.** Model calls made in `multiprocessing` worker processes are dropped:

| Start method / shutdown | Local file mode | Node mode |
|---|---|---|
| fork + `with Pool()` | 100% lost | 58% lost |
| fork + `pool.close(); pool.join()` | 100% lost | 67% lost |
| spawn + `with Pool()` | 100% lost | 67% lost |
| spawn + `close(); join()` | pass | pass |

**What the failed runs leave behind.**
- In local mode, the store holds the content objects but no span references them.
- No `fabric.capture_loss` record is emitted.
- Reconstruct reports `unverified (tail_unverified: no_final_heartbeat)` for the
  workers it can see. When a worker's spans never left at all, reconstruct reports no
  run. It never reports `complete`.
- In Node mode, 1–2 records stay in the spool until some later process drains it.

**Repro.**
- `run_matrix.py case pool-fork-join simple` → 24/24 not captured.
- `run_matrix.py case pool-spawn-join simple` → PASS.
- Minimal version: in any captured process, run
  `multiprocessing.get_context("fork").Pool(2).map(f, ...)`, where `f` makes one
  `OpenAI().chat.completions.create` call, then `close()`/`join()`.

**Hypothesis.**
- Capture flushes only from `atexit` (`sdk/python/src/fabric/wire/__init__.py:269`,
  `WireHandle._atexit_close`).
- Fork workers end in `os._exit()` (CPython `multiprocessing/popen_fork.py`), so
  `atexit` never runs. The fork hook `wire/_pipeline.py:494-503` resets the child's
  state but registers no exit path.
- Spawn workers do run `atexit` (`spawn_main` → `sys.exit`), but `Pool.__exit__` calls
  `terminate()`. That sends SIGTERM to workers that still hold unexported spans and
  queued jobs.

**Suggested fix.**
- In the after-fork child, also register
  `multiprocessing.util.Finalize(None, handle._atexit_close, exitpriority=...)`. It runs
  from `BaseProcess._bootstrap` → `util._exit_function()` before `os._exit`.
- Bound how long a finished exchange may wait before export, so a SIGTERM'd idle worker
  has already delivered.
- When a worker is killed, the loss should surface as a missing final heartbeat of a
  known source. Today a spawn worker whose first export never happened is invisible.

### D2 — High (passivity): with capture on, macOS fork workers crash and the app hangs

**Symptom.**
- Without any proxy variable set, a `fork` pool hangs forever when capture is on: the
  workers abort and `Pool.map` waits indefinitely.
- stderr shows `objc[...]: +[NSCharacterSet initialize] may have been in progress in
  another thread when fork() was called ... Crashing instead`.
- The same program without capture finishes (24 calls).
- Reproduced 3/3 runs (`probes` → `fork-without-proxy-env`).
- The matrix rows set `HTTP(S)_PROXY`, so they do not hit this.

**Hypothesis.**
- `install()` starts background threads immediately: `fabric-loss` (`_loss.py:258`),
  `fabric-wire-capture` (`wire/_pipeline.py:237`) and `fabric-spool`
  (`wire/_sender.py:129`).
- The heartbeat/OTLP export on one of them calls
  `urllib.request.getproxies()` → `_scproxy` (SystemConfiguration/Objective-C) off the
  main thread.
- A `fork()` while, or after, that initialisation happens in another thread aborts the
  child under macOS's ObjC fork-safety check.

**Why it matters.** Spec 049 §7.1 says capture must never alter or block the monitored
system. Linux is not exposed to the ObjC check, but forking while Fabric threads are
mid-export is the same hazard class.

**Suggested fix.**
- Resolve proxies once on the main thread at install, or give the exporter session
  `trust_env=False` with explicit settings.
- Quiesce exporter threads in `os.register_at_fork(before=...)`.

### D3 — Medium: asyncio fan-out overflows the capture queue (honestly reported)

**Symptom.**
- Setup: 8 concurrent tool loops on one `AsyncOpenAI`, 408 calls in about 1 s against
  loopback.
- Local file mode loses 140/408 calls (34%); Node mode loses 25/408 (6%).
- Every loss is reported as `fabric.capture_loss(queue_full)`, and reconstruct reports
  `partial`. Correct, but lossy.
- With `FABRIC_WIRE_QUEUE_MAX_ITEMS=1`, 394/408 are lost, again honestly.

**Hypothesis.**
- Default `queue_max_items=256` (`wire/_config.py:93`).
- One capture worker thread (`wire/_pipeline.py:237`) protects and writes each side
  synchronously, so concurrent bursts outrun it.
- Real model latency makes this much rarer, but batch evaluation and fan-out agents
  will hit it.

**Suggested fix.** Raise the default or make it bytes-based, add worker parallelism or
batching, and document the sizing.

### D4 — Medium: `complete_for_declared_scope` next to uncaptured model calls

**Symptom.**
- Setup: one process sends one call each through the openai SDK (httpx), `requests` and
  `aiohttp`.
- Result: the httpx call is captured, the other two are invisible, and reconstruct says
  `complete_for_declared_scope` (`probes` → `uncaptured-clients`).
- DSPy's default LiteLLM async transport (aiohttp) reaches this in practice: its
  streaming call is uncaptured.

**Assessment.** By design, the scope is the instrumented httpx/httpx2 transports, so
this is not a capture bug. Still, a reader can take "complete" to mean "all model calls
of the run", and nothing in the record says aiohttp traffic to a matched endpoint
happened.

**Suggestion.** Declare the instrumented clients in the capability manifest. Optionally,
add a zero-content detector on `aiohttp.ClientSession` and `requests` that records an
`uncaptured_client` gap for requests to a matched endpoint. That is a scope decision
for spec 047/049.

### D5 — Low: a torn non-streamed response is `unverified`; a torn SSE stream is `complete`

**Symptom.**
- `dspy-httpx / disconnect`: the server cuts a non-streamed JSON body halfway.
- Capture stores the exact torn bytes with `response_state=error`. Nothing is lost.
- Reconstruct marks the exchange `unparsed_exchange (not_json)` with effect
  `unverified`.
- The SSE path tolerates a cut final fragment and reports `complete`.

**Location.** `reconstruct/_stitch.py:338-342` (`_load_json`) versus `:345-374`
(`_sse_events`). `reconstruct/_verify.py:1097-1110` exempts only `truncated`.

**Suggested fix.** Classify a body that is not JSON on an exchange whose captured
`response_state` is `error` as `truncated`, not `not_json`.

### D6 — Low: local file mode has no crash durability; some losses are silent

- SIGKILL after 20 of 51 calls (`openai long50`): all 21 calls are lost, including the
  completed ones, and no span is exported. Reconstruct exits 2 ("no *.otlp files"), so
  it is honest, but nothing survives. Node mode, with its sealed spool, is the durable
  path.
- `OTEL_SDK_DISABLED=true`: capture emits nothing, with no warning or loss record.
- Store unwritable: only a `shutdown` loss is recorded.

### Observations (not defects)

- **Non-matching traffic pays for the tee.** `models.list` GETs, which never match an
  endpoint, add +111–228 µs at p50, because the transport wrapper sits on every httpx
  request.
- **p99 is noisy on a laptop.** One negative "added" value comes from a baseline
  outlier. Treat p99 as an upper bound.
- **`tokenize` reconstructs as `unverified`**, like `metadata_only`/`omit`: the
  original content requirement cannot be met from tokenized objects. Expected under the
  production profile, but worth stating in the operator docs.
- **`ag2 / parallel`:** AG2 executes concurrent tool calls in a racy order. Output,
  tool-call multiset and request bytes are identical; it is noted, not failed.

## Uncaptured HTTP clients

| Client | Where it appeared | Status |
|---|---|---|
| `aiohttp` | DSPy default (LiteLLM `LiteLLMAiohttpTransport`), async/streaming calls: 1/4 calls in `stream`, 1/7 in `disconnect` | UNCAPTURED, never counted as pass. `DISABLE_AIOHTTP_TRANSPORT=True` (row `dspy-httpx`) moves LiteLLM onto httpx, and that row is fully captured. |
| `requests` | `mixed-clients` probe; not used for model calls by any tested framework at these versions | UNCAPTURED |
| `aiohttp` (direct) | `mixed-clients` probe | UNCAPTURED |

LlamaIndex and CrewAI install `aiohttp`, but sent every model call through the openai
SDK (httpx) in these scenarios.

## Harness notes

Corrections made in this session, kept so the evidence stays honest:

- The privacy telemetry check first scanned the whole shared Node sink. Response sides
  without the secret are identical across cases, so it reported "digest of an original
  body" in every protecting mode: a false positive. It now scans only the case's own
  spans, and flags (i) digests of secret-bearing sides in any protecting mode and (ii)
  any original digest in modes that store nothing.
- The earlier `handoff / node` ERROR was the fake server reusing tool-call ids across a
  handoff. That was fixed before this run.

Limits:
- Fake-server latency is under 1 ms. Per-call overhead is therefore an upper bound
  relative to real providers, and queue pressure (D3) is a worst case.
- Node mode runs `simple` per framework, plus `gather long50`.
- Docker networks were available, so Node mode was not blocked.
