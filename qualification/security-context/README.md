# SC-RA-1: security context from the LLM wire and MCP, on real-agent shapes

> **Status:** test harness for unreleased code (spec 057 P1). The replay mode
> passes in CI on macOS and Linux
> ([`.github/workflows/security-context.yml`](../../.github/workflows/security-context.yml)).
> The live mode needs the model endpoint's key and is run by hand; its plumbing
> (key handling, the capture-off twin, `--record-cassette`) is tested end to end
> against a loopback stand-in for the endpoint
> ([`tests/test_sc_ra1_live_mode.py`](tests/test_sc_ra1_live_mode.py)). It has
> not yet run against the real endpoint.

SC-RA-1 is the acceptance run of
[spec 057 §10.2](../../specs/057-security-context-recording.md#102-p1--llm-wire-and-mcp-wire-derivation):
the security context Fabric derives from model requests and responses (offered
tools, tool choice, provider safety signals, tool-result error flags, tools
named but not offered) and from MCP messages (servers, listed tools and their
annotations, inventory changes, calls, user confirmations), recorded from
agents that contain no Fabric code and checked against a ground truth the
harness keeps itself.

## What runs

| Piece | File | Role |
|---|---|---|
| Agents | [`sc_ra1/agent.py`](sc_ra1/agent.py) | Plain hand-written tool loops. **loop**: posts the model's HTTP API with httpx (OpenAI Chat Completions, streamed or not, or Anthropic Messages) and runs `run_shell`, `read_file`, `write_file`, `python_exec` in a disposable workspace (`pip_install` is refused). **mcp**: the same loop whose tools are what two MCP servers list (`server__tool`) plus `run_shell`, through the MCP Python library's own client, one server over Streamable HTTP and one over stdio. It imports nothing from Fabric: capture is switched on from outside (autoload on `PYTHONPATH`, `FABRIC_*` variables). |
| MCP servers | [`sc_ra1/mcp_server.py`](sc_ra1/mcp_server.py) | `tickets` lists three tools, one annotated destructive; `create_ticket` changes its tool list mid-run and asks the user to confirm (`elicitation/create`). `notes` asks the client for its roots. Over HTTP the harness runs them; over stdio the agent's MCP library launches them. Each writes every message it sends and receives to its own ledger. |
| Model | [`sc_ra1/model.py`](sc_ra1/model.py), [`sc_ra1/cassette.json`](sc_ra1/cassette.json) | Replays recorded model responses byte for byte, per session, in order. |
| Runner | [`sc_ra1/harness.py`](sc_ra1/harness.py) | One agent process per session, capture off then on. Capture on: the production profile (a capture policy naming only the roles the derivation reads), the spool sealed with `FABRIC_WIRE_SPOOL_KEY`, `FABRIC_WIRE_EXEC=1`, `FABRIC_WIRE_MCP=1`, `FABRIC_WIRE_HTTP_HOSTS` for the HTTP MCP server. The agent first delivers to a closed port, so the canaries are searched in the sealed spool; a capturing process then drains the spool to the AR-1 sink ([`../action-record/ar1/sink.py`](../action-record/ar1/sink.py)). The reader runs as an operator runs it: `python -m fabric.reconstruct --derive wire --derive mcp.jsonrpc --mcp-host ...` and its `actions --json` view. |
| Ground truth | [`sc_ra1/truth.py`](sc_ra1/truth.py) | Computed from the agent's ledger (every request's offered tools, tool choice and bytes digest, every response, every tool result and its error flag, every elicitation answer and root it gave, every stdio server it launched) and the MCP servers' ledgers. Every grant digest, `grt-`, `src-` and endpoint `lbl-` id is computed by this file's own code from the spec text, and the code is pinned to the published contract vectors ([`tests/test_sc_ra1_truth.py`](tests/test_sc_ra1_truth.py)). |
| Checks | [`sc_ra1/check.py`](sc_ra1/check.py) | The pass criteria below; [`tests/test_sc_ra1_checks.py`](tests/test_sc_ra1_checks.py) shows each one fails when a record is missing, extra or wrong. |

## The sessions

| Session | Agent | Model responses | Spec 057 §10.2 events |
|---|---|---|---|
| `loop-anthropic` | loop, Anthropic Messages | real, 5 turns | 1 (the offered set drops `pip_install` after the first turn), 2 (`tool_choice: {"type": "any"}` on the first request), 3 (`is_error: true` fed back three times) |
| `loop-openai` | loop, Chat Completions, streamed | real, 4 turns | 1 (`write_file` offered from the second turn), 2 (`tool_choice: "required"`) |
| `mcp-http` | mcp, Chat Completions; `tickets` over Streamable HTTP, `notes` over stdio | real, 3 turns | 1 (the offered set follows the server's new tool), 2, 4, 5, 6 (accept), MCP roots |
| `mcp-stdio` | mcp; `tickets` over stdio, `notes` over Streamable HTTP | real, 3 turns | 1, 2, 4, 5, 6 (decline, so `isError`: F14), MCP roots |
| `unoffered-openai`, `unoffered-anthropic` | loop | a real response replayed where the tool it names was not offered | F12 |
| `safety-openai`, `safety-anthropic` | loop | the provider-safety contract fixtures' bodies (`finish_reason: "content_filter"`, `stop_reason: "refusal"`) | one provider safety signal per supported provider |

## Pass criteria

1. Every ground-truth event has exactly one record, with matching kind,
   stage, decision and join, and no record has no ground-truth entry: offered
   grants (one per digest change, each placed before its model call),
   tool choice, F12, F14 (wire flag and MCP `isError`), provider safety rows
   (`exchange_id · certain` to their model call), MCP extension rows
   (`mcp_initialize`, `mcp_tools_list` with annotation counts,
   `process_launch` with the `src-` id of the launch command), listed grants,
   MCP calls and their outcomes, the list-change notification and F11,
   elicitation requests (`escalate`, joined to the MCP session) and answers
   (`allow`/`deny`, `rpc_id · certain`, resolving their request), F2, F9,
   and the stdio server's launch and exit (exec hook). No other control,
   hook or declared-grant row, and no security row outside the agent's run.
2. Each offered and listed grant id, and each model call's
   `offered_grant_id`, equals the harness-computed keyed digest.
3. Capture on and off, same model responses: the same tool results, exit
   codes, process output, final answers and request bytes.
4. The B4 budgets: the passivity gates of every capture point the run uses
   (`wire.py.httpx`, `exec.subprocess`, `http.nonmodel`, `mcp.client`), each
   with its blocking negative control, pass.
5. Privacy canaries (a marker in the system prompt, a secret path in the MCP
   roots, a marker in an elicitation message) never appear in telemetry (every
   delivered record and the delivered bytes), the sealed spool, the export
   (the report, projection and view) or the logs (what the agent process and
   the reader printed). In the content store they appear only
   inside the bodies of the roles the capture policy names
   (`model.exchange.request`, `network.*`, `mcp.*`), never in a descriptor.
6. The reader's output has no evaluative word.
7. Every model response is HTTP 200. An endpoint that refuses or fails ends
   the loop early with ledgers and records that still agree, so the session
   fails by itself (`model_responses_ok`) and names what to check.
8. The run states no fact the ground truth has no event for
   (`events.no_other_fact`: for example a pending or denied gated call or an
   OS refusal), and every B4 scenario the table lists was measured
   (`b4.every_scenario_measured`).

An MCP call's join is its session: the checks require a stdio server's calls
under the transport hook's `mcps-` session, an HTTP server's under the host's
`hst-` session, and one session per server. An elicitation row must name the
server that asked (`engine`).

## Run it

```bash
cd sdk/python && uv sync --all-extras --group dev && cd ../..
sdk/python/.venv/bin/python qualification/security-context/run_sc_ra1.py --mode replay --out /tmp/sc-ra1
sdk/python/.venv/bin/python -m pytest qualification/security-context/tests -q   # the same, as tests
```

The run writes `sc-ra1-result.json` (every check), `sc-ra1-table.md` (the
measured results) and `on/<session>` and `off/<session>` directories (plan,
ledgers, outputs, sink, store, reader output). `--no-latency-gate` skips the
B4 gates.

Live mode sends the four agent sessions to the real model (DeepSeek V4.1 Flash
behind an OpenAI- and Anthropic-compatible endpoint, `--base-url` or
`SC_RA1_BASE_URL`) and still
replays the safety and un-offered sessions:

```bash
SC_RA1_MODEL_KEY_FILE=/path/to/key sdk/python/.venv/bin/python \
  qualification/security-context/run_sc_ra1.py --mode live --out /tmp/sc-ra1-live \
  --base-url https://model.example/v1 \
  --record-cassette qualification/security-context/sc_ra1/cassette.json
```

The key is read from the file, kept in the harness's memory (it is removed
from the harness's own environment) and passed to the live agent process
only: the reader, the spool drain and the B4 gates never get it. It is never
printed or written. The agent takes the key out of its environment before it
starts anything, so the tools the model runs (`run_shell`, `python_exec`) and
the stdio MCP servers never inherit it. The agent is also started without any
variable of the caller's environment that is named like a credential (`KEY`,
`TOKEN`, `SECRET`, `PASSWORD`, `CREDENTIAL`, `AUTH`, `COOKIE` in the name): a
model that runs `env` would otherwise send those to the endpoint and into the
content store. Each live session's capture-off twin
replays the responses that session received, so both see the same model
responses. `--record-cassette` writes those responses as the new cassette; it
does not write the endpoint's URL.

## Where this departs from §10.2, and why

- **The committed cassette's responses were recorded by an earlier live run,
  not by this harness.** Every agent-session response is a real DeepSeek V4.1
  Flash response (Anthropic Messages, Chat Completions streamed and not)
  recorded by an earlier field test run on 2026-11-09 and kept byte for
  byte; each session's `provenance` says which (each body was traced back to
  that run's ground-truth files). The live endpoint's key was not available
  when this harness was built (the endpoint answers 401 without it), so its
  live mode has not run against the real endpoint yet.
  Replayed, a response does not depend on the request, so the request-side
  events (offered sets, tool choice, error flags, MCP traffic) are this
  harness's own, while the responses (which tools the model called, in which
  order) are the real model's.
- **The provider safety signal replays documented shapes.** No provider
  returns a filtered or refused response on demand, and no live recording of
  one exists (spec 057 revision 3.6 note 5); the safety sessions replay the
  contract fixtures' bodies.
- **An offered grant's endpoint is its emitted id.** §5.2's example names a
  built-in endpoint in the clear; a configured endpoint is emitted as `lbl-` +
  the keyed v1 label of its name (spec 049 C35), and the reader, which sees
  only what was emitted, puts that id in the offered document. The harness
  computes the same `lbl-` id itself.
- **One agent process per session**, so each session is one run. Telemetry
  goes to the sink without a Node; the Node's own sealed content store is
  covered by AR-1 production.
