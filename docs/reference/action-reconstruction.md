# Agent action reconstruction

> **Status:** released: milestone M1 (local profile) in v0.10.0, milestone
> M2 (production profile, [below](#production-profile-m2)) in v0.11.0
> ([spec 056](../specs/056-agent-action-reconstruction.md)). Implementation:
> [`fabric/hooks/`](../sdk/python/src/fabric/hooks/) (the `exec.subprocess`
> hook), [`reconstruct/_attribute.py`](../sdk/python/src/fabric/reconstruct/_attribute.py)
> (attribution, chain verdicts, the `actions` view) and
> [`reconstruct/_host.py`](../sdk/python/src/fabric/reconstruct/_host.py)
> (host-sensor records and the process-tree join). The acceptance test,
> [AR-1](../qualification/action-record/README.md), passes in CI in hermetic
> mode (macOS and Linux) and in live mode on Linux with the eBPF sensor.
> Python agents only; on the local profile every host anchor is `tentative`.
> AR-1 production passes in CI against a production-profile Node: replay on
> macOS and Linux, live on Linux with the eBPF emitter in production mode,
> and the auditd sensor collector on a fixture audit log. Known limits:
> [what is not covered yet](#what-is-not-covered-yet).

For one run, Fabric can answer three questions: what the agent actually
ran, which model decision caused each command, and what the operating
system independently saw. Fabric stays a passive recorder: the hook
observes subprocess calls the agent already makes and never approves,
blocks, delays or changes them. A link in the record says how two records
are related. It says nothing about whether an action was right.

## What is recorded

The record has four chains, and each gets its own verdict:

| Chain | Evidence | How it is captured |
|---|---|---|
| `decisions` | Each model request and response, exact bytes | Wire capture (v0.8.0) |
| `actions` | The tool calls in each response and the results the agent fed back | Parsed offline from those bodies |
| `effects` | Each subprocess the agent started: argument list or shell command, working directory, environment variable **names**, stdout and stderr, exit status or signal, pid, parent pid, and on Linux the process start time | The opt-in `exec.subprocess` hook: two records per child, written when `Popen` returns and when `communicate`/`wait`/`poll` returns |
| `corroboration` | Process starts and network connections, with pid and parent pid | A host sensor (the eBPF emitter or the auditd receiver), read from a separate file |

The verifier links them with the rules of spec 056:

- **Effect → tool call** (§4.2). `output_match · certain` (A1) applies when
  the command's output (16 bytes or more) appears in exactly one open tool
  call's result. `sequence_bracket · tentative` (A2) applies when exactly
  one tool call was open when the command started. When two or more were
  open and the output does not decide, the effect is linked to every one of
  them with state `ambiguous` (A3); when the output appears in several
  results, it is linked to each of those, `output_match · tentative` and
  `ambiguous`. An ambiguous link is never `certain`. An effect with no open
  tool call is listed under *unattributed effects* (A4). No rule picks the
  most likely candidate.
- **Host event → effect** (§4.3). A host `exec` event with the effect's pid
  and parent pid corroborates it (`process_anchor`): `certain` with matching
  process start times (H1), `tentative` without them (H2). Local-profile
  sensor records have no start time, so today's anchors are `tentative`.
  Events whose parent-pid chain reaches an anchored process are `part_of`
  that effect (`process_lineage`, H3). This is how the `curl` that a shell
  script starts, and its connection, become visible. A failed `execve` (a
  `PATH` search that tries several directories, or a refused exec) is an
  event of the process that tried it and is lineage too; so are the
  anchored child's own failed attempts before the exec that anchors it,
  when their start tick is the child's. A shell that execs its
  command in place (`bash -c "cmd"`, or `dash` for the last command of
  `sh -c "a && b"`) gives two exec events with one pid and parent pid.
  Without start times, H2 reads them as one process (an exec chain): the
  first exec is the anchor and the second is lineage, both `tentative`. If
  the hook saw that pid exit between the two execs, they are two processes
  and the anchor stays `ambiguous`. A pid that a later, unrelated exec
  takes over leaves the chain. Events of the agent process itself are
  `part_of` the run (H4).
- **Unexplained host events.** A host event in the agent's scope that no
  rule links is listed, and so is an agent connection to a host that no
  model call reached. The list is a gap between the record and what the
  operating system saw; Fabric records it and draws no conclusion from it.

Environment values are never read. Arguments, the execution context and
output follow the `terminal.argv`, `terminal.context` (executable, working
directory and the names of an explicitly passed `env`), `terminal.stdout`
and `terminal.stderr` content roles of the capture policy, which can
redact, tokenise or withhold them like any other content (see
[privacy and security](privacy-and-security.md)). Withholding output turns
off A1 for that effect, and when no effect is left to match the report says
so (`output_match: not_applicable`).

The quickstart below sets no capture policy, so the implicit local policy
applies: every content role, `terminal.argv` included, is kept as
captured. A credential an agent writes literally on a command line (a
bearer token in a `curl -H` argument, `mysql -p…`) is then stored in clear,
and the `actions` view prints the first 48 characters of each command.
Before using the hook on real workloads, set a capture policy that redacts
`terminal.argv` or makes it `metadata_only`.

## Turn on the subprocess hook

The hook needs wire capture installed in the same process. With the
`fabric` CLI, `fabric init --exec` turns it on and `fabric run` passes the
generated id key; nothing below is needed.

By hand, start from the [quickstart's](quickstart.md#4-capture-an-unmodified-program-zero-code)
zero-code environment (its first five variables below) and add three: the
id key, the hook switch and a host label. The id key is 32 random bytes,
written once to a file only you can read:

```bash
python -c 'import secrets, sys; sys.stdout.write(secrets.token_hex(32))' > id-key
chmod 600 id-key

# The quickstart's environment:
export PYTHONPATH="$(python -m fabric.wire --print-autoload-path)"
export FABRIC_WIRE_AUTOLOAD=1
export FABRIC_TENANT_ID=demo
export FABRIC_WIRE_STORE="file://$PWD/store"
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
# The three this page adds:
export FABRIC_WIRE_ID_KEY_FILE="$PWD/id-key"  # also keys the host id
export FABRIC_WIRE_EXEC=1                     # the exec.subprocess hook
export FABRIC_HOST_LABEL=build-host-7         # names this host for the host join
python agent.py
```

In code, after `fabric.wire.install(...)`, use
`fabric.hooks.install(exec=True, host_label="build-host-7")`. The returned
handle has `status()`, `disable("exec.subprocess")` and `close()`. Without
a capturing wire install, nothing is patched and `status()` reports
`no_capture_handle`. The capture manifest records the channel state:
`active`, or `disabled(hook_disabled)` when the hook is off. That state is
how the verifier tells a hook that was off (`effects: not_observed`) from
one that saw nothing.

The hook covers `subprocess.Popen` and the functions built on it (`run`,
`check_output`, `call`) and asyncio's `create_subprocess_exec` and
`create_subprocess_shell` on the default event loop. `os.system`,
`os.exec*`, `os.posix_spawn` and `pty` are not hooked.

## Add a host sensor

Run one of the [host sensors](host-sensors.md) on the agent's host and send
its records to a local-profile Node:

- **eBPF emitter**: set `EMIT_CGROUP_PATH` to the agent's cgroup, so that
  every process the agent starts is in scope and nothing else is. Point
  `EMIT_ENDPOINT` at the Node's OTLP/gRPC port.
- **auditd receiver**: add `execve` and `connect` rules tagged with the
  receiver's `rule_key`, scoped to the agent (for example by its uid).

The sensor's records reach the Node's destination as `event_class=audit`
log records. Give that export, or any OTLP/JSON or sink JSONL file holding
those records, to the verifier with `--host-records`. Host records are
verified as their own source and never enter the agent run's sequence
accounting or seals. They reach the run only through its `corroboration`
chain, which, like every chain, keeps the run verdict from being
`complete` while it is `partial`. A host record never turns reported
content into observed content.

## Read a run: `python -m fabric.reconstruct actions`

```bash
export FABRIC_WIRE_ID_KEY="$(cat id-key)"   # the reader takes the key by value
python -m fabric.reconstruct actions spans.jsonl \
  --store-root store --tenant demo \
  --host-records node-export.jsonl --host-label build-host-7 \
  --host-coverage-declared --known-peer 10.0.4.9 \
  --endpoint-peer my-model=10.0.4.7
```

- `--host-records FILE` (repeatable): the host-sensor records.
- `--host-label`: the host the sensor runs on, as `FABRIC_HOST_LABEL`
  names it. Only effects on that host are joined, and the sensor's pids
  are taken to be in the agent's pid namespace.
- `--endpoint-peer ENDPOINT_ID=ADDRESS` (repeatable): the address each
  model endpoint resolves to (the `endpoint_id` of `FABRIC_WIRE_ENDPOINTS`,
  or a built-in endpoint's emitted name). Without it, every connection
  from the agent to its own model is reported as unexplained.
- `--host-source host.ebpf|host.auditd`: declare a sensor explicitly. A
  declared sensor with no records is a `source_gap`.
- `--host-coverage-declared`: declare that each sensor covered the whole
  run. Local-profile records carry no positions or heartbeats, so the
  verifier cannot prove coverage and, without this flag, reports a
  `source_gap`. A loss the records show (a loss summary, a record dropped
  as malformed) is a `source_gap` either way.
- `--agent-pid PID`: the agent's own pid. The export does not carry it, so
  without this H4 uses the parent pid every effect agrees on, and a run
  with no effects (the hook off) links nothing by H4.
- `--known-peer ADDRESS` (repeatable): an address the agent process
  contacts for Fabric's own delivery or its infrastructure (the Node's OTLP
  endpoint, the content store, a DNS resolver). Its connections are linked
  by H4 and not listed as unexplained.
- `--in-process-tool NAME`: a tool that runs inside the agent process. A
  call to it without an effect is reported as `no_effect_channel` instead
  of `none_in_window`.
- `--json` prints the same rows as one JSON document. The report command
  (`python -m fabric.reconstruct --spans ...`) takes the same host options
  and adds `chains`, `attribution` and `sensor_events` to each run.

Abridged output of the AR-1 run (paths shortened, host replay):

```text
run source:s-b42b…:1160…  decisions: complete  actions: complete  effects: partial(unattributed_effect)  corroboration: partial(unexplained_host_event)  verdict: partial
  1    effect     exec uname -p exit 0                 (startup: before the first model call)
  2      host     exec pid 24462                     ← #1  process_anchor · tentative
  5  model_call   m-b53a8eb814d42c21  → tool_call T1 run_shell
  6      host     connect pid 24459                  ← run  process_anchor · tentative
  7    effect     exec ls /srv/ar1/data && sha256sum /srv/ar1/da… exit 0 ← T1  output_match · certain
  8      host     exec pid 24464                     ← #7  process_anchor · tentative
  9      host     exec pid 3900001                   ← #7  process_lineage · tentative
 10      host     exec pid 24464                     ← #7  process_lineage · tentative
 11  model_call   m-b53a8eb814d42c21  ← result T1  → tool_call T2 fetch_url
 13    effect     exec sh -c curl -fsS --max-time 10 -H "Authorization… exit 0 ← T2  output_match · certain
 14      host     exec pid 24467                     ← #13  process_anchor · tentative
 15      host     exec pid 3900003                   ← #13  process_lineage · tentative
 17      host     connect pid 3900003                ← #13  process_lineage · tentative
 …
 30    effect     exec uname -a exit 0                 (no open tool call)
 35      host     connect pid 24459                  ← run  process_anchor · tentative  unexplained
  unattributed effects: 1   (exec uname -a, seq 16: no open tool call)
  startup effects: 2   (exec uname -p, seq 0; …: before the first model call; not attributed, not a gap)
  unexplained host events: 1
  output match: applied
```

How to read it:

- **Header.** The run id and each chain's verdict with its reasons. The
  run verdict is never `complete` while an observed chain is `partial`.
- **`model_call` rows.** The tool calls a response asked for (`T1`, `T2`,
  … in order) and the results a request fed back. Model names are `m-`
  digests unless `--model-allowlist` names them.
- **`effect` rows.** The command (cut at 48 characters), its exit status
  and the tool call it is linked to, with `method · confidence` and
  `ambiguous` when there are several candidates.
- **`host` rows.** Indented under the effect they belong to (`← #7` is row
  7). `← run` marks an event of the agent process itself, and
  `unexplained` marks an event that no rule explains. An unexplained event
  that no rule links at all (an `os.system` child, or any exec while the
  exec hook is off) has a row of its own at its time:
  `exec pid 4130 ppid 4100 00:00:02.500 unexplained` (pid, parent pid and
  UTC time; `--json` gives `time_ns`, `ppid` and `syscall`). Host records
  never carry the command line, so the row cannot show it; record the
  command through the exec hook (`subprocess`) where you need it.
- **`http` rows.** A non-model HTTP request the `http.nonmodel` hook
  recorded (method, status, keyed host id), marked `(recorded; not
  attributed)`: no rule links it to a tool call yet (see
  [what is not covered yet](#what-is-not-covered-yet)).
- **Footer.** The effects no tool call explains, the tool calls with no
  effect and why (`channel_disabled`, `no_effect_channel`,
  `none_in_window`), the non-model HTTP requests recorded but not
  attributed, the number of unexplained host events, and whether output
  matching applied.
- **`session` footer.** After the last run, the host events no run lists
  or counts, by reason: `other_process` (a process with a run's agent pids
  that is not that run's agent, such as a later container that reuses the
  pid namespace number, and that process's children, or any process that
  started before the run's agent, such as the previous container's), `out_of_scope` (in a run's window, outside the
  agent's scope) and `no_run` (in no run's window). Captured host activity
  is never dropped: `--json` lists every one, and the report's top-level
  `unattributed_host_events` gives the count per reason and the first 64.
- **One process, two runs.** When nothing in the record proves which
  agent a process belongs to (no known agent start, no certain anchor) and
  two runs' windows both hold it, neither run gets it: each shows the link
  as `process_anchor · tentative · ambiguous` (the report's link lists
  both run ids as `candidates`), and the run's `corroboration` is
  `partial(ambiguous_attribution)`.

**A process that made no model call** (a tool worker the agent started, or
an agent killed before its first model call) is a run of its own under its
source fallback id `source:<source>:<epoch>`; select it with `--run`. Its
effects are listed with `(no model call in this process)`, `decisions` is
`not_observed` when its record verifies, and the footer says `model calls:
none recorded in this run`. If the process ended without a final heartbeat
(SIGKILL, a crash), `decisions` is `unverified(tail_unverified)` and the
footer says `process end: no final heartbeat (killed or crashed)`: records
after the last delivered one may be missing.

The view never prints captured output. The exit code is that of the
report: `0` only when the run is complete, `1` when it is `partial` or
`unverified`, `2` for a usage or input error.

What this run shows: `uname -p` and `file -b` are started by Python's
`platform` module, which the OpenAI SDK calls while it builds its first
request. They run before the first model call of the run, so no call can
have caused them: they are **startup effects** (spec 056 revision 11),
listed and counted in the footer and in the report's
`attribution.startup_effects`, never attributed to a call, and they do not
make `effects` partial. An effect after the first model call with no open
tool call is still unattributed: `uname -a` is a background thread of the
agent, and it alone makes `effects` `partial(unattributed_effect)`. An
effect behind a lost sequence position stays unattributed too, because the
lost position may have been a model call. Row 35 is
the agent connecting to a host no model call reached.

## Security context in the view and the report (spec 057)

When a run holds control decisions, hook outcomes, grant snapshots or
extension loads (recorded through `fabric.records`, spec 057 §4.6), the
reader shows them beside the calls and effects. It never decides whether a
call was right: it joins records by id, scope or position and states a
closed list of mechanical facts.

```text
run r-3f2a…  decisions: complete  actions: complete  effects: complete  corroboration: not_observed(not_configured)  controls: complete  verdict: complete_for_observed_scopes
  grant   grt-8b53…  declared  api  run_start  allow 2  deny 1  fs 2  (reported)
  1  model_call   gpt-4o  → tool_call T1 write_file
  2    control    permission_check · pre_tool · deny  fs-write  path.outside_root  0.04 ms  (wrapped_check)   ← T1  pending_single · certain
  3      no effect observed for T1 (control_denied: #2)
  4  model_call   gpt-4o  ← result T1  → tool_call T2 read_file, T3 write_file
  5    control    permission_check · observation · allow  fs-read  (reported)   ← ambiguous: T2, T3  pending_set
  facts:
    F5  deny gates a tool call and no effect is attributed to it: 1 (#2)
```

- **`controls` chain.** The fifth chain. `not_observed` when the run has
  no such record (the report is otherwise unchanged); `complete` when every
  record's reference resolves, no request is pending at the end and every
  record carries both invariants; else `partial` with
  `control_unmatched`, `control_pending_at_end`, `ambiguous_attribution`,
  `grant_not_recorded`, `sequence_gap` or `invariant_conflict`. A partial
  controls chain makes the run partial. `complete` means the decisions
  Fabric was told about are consistent and joined, not that every control
  in your system was recorded.
- **How a decision is joined to its tool call.** The provider tool-call id
  (`gated_tool_call_id`) links it `provider_id · certain`; a reported step
  (`gated_step`) links it `reported_ref · certain`; a resolution joins its
  request by id across runs (`ref_join`). Otherwise, with wire capture on,
  the reader takes the tool calls still pending at the record's position:
  one pending call gives `pending_single · certain`; two or more give
  `ambiguous` with every candidate and the chain
  `partial(ambiguous_attribution)`: pass `gated_tool_call_id` to remove the
  ambiguity. A record with `gated_kind` other than `tool_call` is never
  linked by position.
- **Facts.** F1 to F14 of spec 057 §6.3, counted in the report's
  `security_context` with their first 64 event ids. F5 (`control_denied`)
  also moves the tool call's `effects_not_observed` reason to
  `control_denied`; it is stated only for a call the effect channels were
  watching (spec 056 reason `none_in_window` or `no_effect_channel`), never
  for one whose channel was disabled.
  F6 (`deny_with_effect`) is co-occurrence: the row lists the deny's mode
  and derivation, the effect's attribution and any later allow.
- **Grant in force.** In a run that holds a grant snapshot, every control
  row and every tool call carries `grant_in_force`: the `id` of the latest
  snapshot recorded in the run before it, `grant_basis` (`reported` for a
  snapshot from the records API or telemetry, `observed` for one derived
  from model-wire bytes, `none` when no snapshot precedes the row) and
  `certainty`. `certain` means the earlier snapshots come from one process,
  so their order is a sequence order. `ambiguous` means they come from more
  than one process and only wall clocks order them; the row then lists the
  `candidates`. The view prints `in force grt-… (observed)`, `in force none`
  or `in force ambiguous: …`; the report's `security_context.grant_in_force`
  counts the rows by basis. A run with no grant snapshot carries no such
  field and reads exactly as before.
- **Not yet.** Side effects that required approval (F7) are read from
  records-input `side_effect` records, which the records API does not emit
  yet. The `path_ref` join (a watched rule file to its operator snapshot)
  arrives with the work packages that record those opens and snapshots.

### What the reader derives from the model wire (`--derive`)

With wire capture on, the stored request and response bytes already hold
security context the agent never reported. The reader derives it offline,
on request, with no change to the agent and nothing added to its request
path:

```console
python -m fabric.reconstruct actions <export> --derive wire \
    --tool-result-markers markers.json
```

| Option | Rule | What you get |
|---|---|---|
| `--derive wire.offered_grant` | offered grants | One `offered` grant row for the first model call and one for each change of the offered tool set, with the tool count, the tool choice (`auto`, `none`, `required`, `specific`, `allowed_subset`), the parallel-tool setting and the instructions digest (never the text). Every model call names its grant (`offered_grant_id`). F12 states a tool call whose name was not offered in that request; provider-hosted tool types are excluded. |
| `--derive wire.safety_map` | provider safety signals | One `provider_safety` control row per literal safety field in a response: a content filter, a refusal field or a refusal stop reason. Only the published map applies (`contracts/coverage/v1/registry/provider-safety-map-v1.json`). A missing field gives no row, and no text is ever interpreted: a response that merely reads like a refusal gives nothing. |
| `--derive wire.tool_result_flag` | tool-result error flags | F14 counts tool results fed back to the model with the dialect's structured error flag (Anthropic `is_error`), once per tool call. It is a flag, not a denial claim. |
| `--derive wire` | all three | |
| `--tool-result-markers FILE` | denial markers | One `configured_marker` control row for each tool result whose text matches a marker you listed, linked to its tool call by the provider id. |

Supported dialects are the ones wire capture parses: OpenAI Chat
Completions (including Azure OpenAI's filter fields), OpenAI Responses,
OpenAI Completions and Anthropic Messages. Other dialects give no rows.

**Denial markers** are the exact text your own tool layer writes when it
refuses a call. `FILE` is a deployment policy with
`security_context.tool_result_markers`, an object with
`tool_result_markers`, or the list itself:

```json
[
  {"label": "fs-acl", "prefix": "permission denied", "reason_code": "path.outside_root"},
  {"label": "shell-gate", "equals": "needs approval", "kind": "policy", "decision": "escalate"},
  {"label": "api-acl", "json": {"pointer": "/error/code", "values": ["forbidden"]}}
]
```

Matching is byte-exact and case-sensitive: `equals` (the whole text),
`prefix` (the text begins with it) or `json` (an RFC 6901 pointer into a
JSON tool result, and the literal values that mean a refusal). There is no
regular expression, no search inside the text and no built-in marker, so a
near miss (one byte, a different case, a leading space) gives nothing. A
marker states `deny` (the default) or `escalate`, never `allow`: an entry
that declares `allow`, or is malformed, is refused when the list loads and
the others still apply. The report's `inputs.derivation` lists the rules
applied and, for the marker list, its size, digest and each refused entry's
index and reason (`decision_allow`, `invalid`, `over_limit`). The marker
strings never appear in the report or the view.

Without these options the reader reports every run exactly as before.

### MCP servers on the wire (`--derive mcp.jsonrpc`)

MCP is JSON-RPC 2.0 over Streamable HTTP or stdio. Fabric reads it at the
protocol level, so it works for any MCP client built on these transports,
whatever framework sits above it.

**Capture.**

- **Streamable HTTP**: put the MCP server's host in
  `FABRIC_WIRE_HTTP_HOSTS` and retain `network.request` and
  `network.response` for it in the capture policy. The existing non-model
  HTTP hook records the request and response bodies; nothing MCP-specific
  runs in the agent.
- **stdio (Python)**: set `FABRIC_WIRE_MCP=1` (or
  `fabric.hooks.install(mcp=True)`) and retain `mcp.request`,
  `mcp.response` and `mcp.notification`. The hook observes the bytes the
  MCP Python library's own stdio transport writes to and reads from the
  server it launched. It never relays the pipes and never reads them a
  second time. Only the library versions it was qualified on are hooked
  (`mcp` 2.3.x on `anyio` 4.x); any other version is reported in the
  capture manifest as `unsupported(unsupported_version)` and nothing is
  patched. With `FABRIC_WIRE_EXEC=1` as well, the server's process is one
  exec record from launch to exit.
- **Other languages**: only the server's launch and its connections are
  recorded (exec hook, host sensors).

All MCP content roles are `off` by default: without retained bodies
nothing about MCP can be derived.

**Reading.**

```console
python -m fabric.reconstruct actions <export> --derive mcp.jsonrpc \
    --mcp-host mcp.internal.example
```

| What | Rows |
|---|---|
| `initialize` | an `mcp_server` extension with the server's name, version and protocol version (`via mcp_initialize`) |
| `tools/list` | an extension with the tool count, the inventory digest and the counts of the server's annotation hints (destructive, read-only, idempotent, open-world: the server's own claims), and a `listed` grant; F11 when a later listing differs |
| `roots/list` | the `listed` grant counts the roots the client exposed (never their paths) |
| `tools/call` | an MCP call row: `ok`, `isError` (F14) or a protocol error; joined to the model's tool call of the same name when exactly one is pending (`sequence_bracket`, tentative) |
| `elicitation/create` | an `elicitation` control request (`escalate`) and the user's answer as its resolution (`accept` -> `allow`, `decline` -> `deny`, `cancel` -> `cancelled`), joined by JSON-RPC id; an unanswered request is F4 |
| stdio launch | an `mcp_server` extension `via process_launch` with the keyed reference (`src-`) of the launch command |

`--mcp-host` (spelled as in `FABRIC_WIRE_HTTP_HOSTS`, needs the id key)
lists an MCP host: a request to it whose bodies were not retained makes the
`controls` chain `partial(body_not_retained)`, so a reviewer sees that
MCP context was not available rather than absent. The same holds for an
`mcp.client` session recorded with the MCP roles off.

### Hook programs and control endpoints you declare (spec 057 P2)

Fabric never guesses that a process is a hook or that a host is a policy
service. You declare both in the capture policy (the
`FABRIC_CAPTURE_POLICY` file), under `security_context`:

```json
"security_context": {
  "hook_programs": [
    {"path": "/opt/hooks/pre-shell.sh", "label": "pre-shell-check",
     "exit_map": {"0": "passed", "2": "blocked"}},
    {"basename": "lint-hook", "label": "linter"}
  ],
  "control_hosts": [
    {"host": "policy.internal.example", "label": "policy-svc",
     "control_kind": "policy", "decision_pointer": "/decision",
     "decision_map": [{"value": "ALLOW", "decision": "allow"},
                      {"value": "DENY", "decision": "deny"}]}
  ],
  "control_addresses": [
    {"address": "10.0.3.0/24", "label": "policy-svc", "control_kind": "policy"}
  ]
}
```

- **Matching is exact.** A hook program is an exact executable path or an
  exact `argv[0]` basename; a control host is `host[:port]` exactly (no
  suffix, no wildcard; no port means 443); an address is one IP or a CIDR.
- **Lists are loaded once, at install.** A list with more than 256 entries,
  with two entries that match the same value, or with an entry that cannot
  be held is *refused*: it is not applied, capture carries on, and the
  capture manifest says `refused` with the reason (`over_limit`,
  `duplicate_entry`, `invalid_entry`). Fix the list and restart the agent.
  The manifest publishes each list's state, entry count and digest
  (`fabric.manifest.classifications`), never its contents.
- **Hook programs.** A subprocess the hook sees whose path or basename is
  listed is recorded with your label (`fabric.hook.program_label`, never the
  path) and shown as a `hook` row with `basis=process`. With an `exit_map`
  the outcome is the mapped one (`configured_exit_map`); without a map, or
  for a code the map does not name, it is `unknown` and the exit code is
  still shown. A signal is the negative code, as Python reports it
  (`"-9"`). `argv[0]` and `executable=` are matched when they are a string,
  `bytes` or a `pathlib` path, also when the argv is too long for the
  recorded argv body. Under `shell=True` the command string, or a list's
  first item, is matched by its first word when it is one simple command.
  An `executable=` of any other type is not read, so only `basename`
  entries can match that child. A hook started through an interpreter
  (`["sh", "hook.sh"]`, `["python", "hook.py"]`) has the interpreter as its
  `argv[0]`, so it cannot be listed without listing every use of that
  interpreter: give the script a shebang and an execute bit and run it
  directly, or it is linked as an unlisted process.
- **A hook program is never a tool call's effect.** A tool call whose
  window holds only hook programs stays under `tool_calls_without_effect`,
  and the `effects` chain is `partial(none_in_window)`: the hook shows the
  call was dispatched, and its effect was somewhere the enabled channels do
  not look (a remote sandbox, an unhooked client). There are two
  exceptions, where the missing effect is expected and the chain is not
  lowered: a hook whose `exit_map` outcome is `blocked` (the call was not
  dispatched), and a call a recorded deny gates (it is counted as
  `control_denied`, fact F5). A process you did not list is linked as before
  (`sequence_bracket`, tentative).
- **Control endpoints.** List the host in `control_hosts` and in the HTTP
  hook's allowlist (`FABRIC_WIRE_HTTP_HOSTS` / `http_hosts=`). Each request
  to it is one `control` row: kind and label from the list,
  `phase=observation`, `decision=unknown`, the HTTP status and measured
  latency. Its bodies are stored only under the roles
  `control.exchange.request` and `control.exchange.response`, both off
  unless your policy names them, so retaining general HTTP bodies
  (`network.*`) never retains what a control inspected.
- **Reading the decision (offline, opt-in).** Give the entry a
  `decision_pointer` (RFC 6901) and a `decision_map`, retain
  `control.exchange.response`, and pass the same policy file to the reader:
  `python -m fabric.reconstruct actions ... --capture-policy policy.json`.
  The reader then fills the decision (`configured_extract`). Nothing is
  parsed in the agent. If the pointer is listed but the body was not
  retained, the row says so and the `controls` chain is
  `partial(body_not_retained)`. A response the service sends compressed
  (`Content-Encoding: gzip`, which httpx asks for by default) is never
  stored, so it reads as not retained too: send `Accept-Encoding: identity`
  on requests to that host, or turn compression off for that endpoint. The
  policy applies only to runs whose capture manifest names its digest, so
  pass the exact file the agent ran with; a policy changed after the run
  (even only to add a `decision_pointer`) applies to no earlier run, and
  the reader prints a warning when it applied to none.
- **Host sensors.** With `--capture-policy`, a sensor `exec` whose
  executable-path digest is a listed `path` is a hook row (outcome
  `unknown` unless the sensor also records exits, `EMIT_EXIT=true`: then
  the exit record of that process gives its exit code or signal and the
  `exit_map` applies; like an in-process hook it is never an effect, and a call
  whose window holds it and no effect makes the `effects` chain
  `partial(none_in_window)`), and a sensor
  `connect` to a listed `control_addresses` entry is a contact row
  (`decision=unknown`). The sensor must be allowed to emit path digests for
  the first, and the reader needs the id key for the second
  (`FABRIC_WIRE_ID_KEY`). A `basename` entry matches in-process records
  only; a network wider than a /16 is not matched by the reader.
- **Spawn errors.** A spawn that raises an `OSError` now records the errno
  name (`EACCES`, `EPERM`, `ENOENT`, ...) beside `error_class`.

### Kernel refusals (spec 057 P2)

The view shows what the kernel refused as a control row, with no
configuration:

```text
  4  model_call   → tool_call T2 write_file
  5    control    os_access · effect · deny  kernel  errno.eacces  openat  (literal)  seen by host.ebpf   ← T2  process_anchor · tentative
```

- **The closed set.** An `execve`, `openat` or `connect` that failed with
  `EACCES` (`errno.eacces`) or `EPERM` (`errno.eperm`), and a process killed
  by `SIGSYS` (`signal.sigsys`, the seccomp kill action). Nothing else is a
  row: `ENOENT`, `ECONNREFUSED`, `ETIMEDOUT`, a nonzero exit and `SIGKILL`
  stay fields of their records.
- **Where they come from.** A host sensor's records (the eBPF emitter with
  `EMIT_SYSCALL_RESULTS=true` and `EMIT_EXIT=true`, or the auditd receiver;
  see [host sensors](host-sensors.md)), or the subprocess hook: a spawn that
  raised `PermissionError` (`errno.eacces_or_eperm` when only the class is
  known), or a child killed by `SIGSYS`. One refusal seen by both is one row
  (`host events 1`), and the sensor's exact errno replaces the class.
- **Linking.** The row is linked to the tool call its process belongs to,
  by `process_anchor`, with the confidence spec 056 gives that evidence:
  the subprocess record's own link, the effect the sensor event was joined
  to, or otherwise the calls open at that time (`tentative`; several give an
  ambiguous row that gates none). A refused call with no effect is counted
  as `control_denied` (F5); fact F13 counts the rows by syscall, reason and
  link.
- **What it does not say.** Which mechanism refused (file permissions, an
  LSM or a seccomp `ERRNO` action look the same), or that a policy was
  enforced. Fabric only reads the errno or signal the kernel reported.

## Production profile (M2)

Released in v0.11.0. Against a production-profile Node, a host sensor is a
source of its own (spec 053 §6.1, §6.2): it reports to a dedicated ingress
group with its own token and listener, its records carry positions,
heartbeats, a manifest and the process start time and pid namespace, and
the verifier reads them from the same export as the agent's records:

```bash
FABRIC_WIRE_ID_KEY=... python -m fabric.reconstruct actions export.jsonl \
  --store-root STORE --tenant TENANT --trusted-source --profile production \
  --host-source host.ebpf=s-<print-source-id> \
  --sandbox-peer 127.0.0.2:PORT --endpoint-peer openai.default=ADDRESS
```

No `--host-records`, `--host-label` or `--host-coverage-declared`: the
records name their source and host, and heartbeats prove coverage. A
declared source with no records in the run window is a `source_gap`.

What M2 adds to a run:

- **Certain anchors.** Rule H1 joins an effect to its exec event on the
  namespace-local pid, the parent pid and the start tick, so the link is
  `process_anchor · certain`, also for an agent in its own pid namespace
  (a pod) and for children spawned from a pool thread.
- **Container sandboxes.** A `docker run -d` (or `kubectl run … -o
  jsonpath={.metadata.uid}`) effect records the id the runtime printed as
  `fabric.sandbox.created_id`; the container's events, which the sensor
  scopes `sandbox` by their cgroup, are `part_of` that effect by rule H5
  (`sandbox_report · certain`, provenance `reported`). Sandbox events no
  reported id names are counted in `sandbox_events_unlinked`, never listed
  as unexplained.
- **Remote sandboxes.** The `remote.sandbox` hook records the E2B SDK's
  `commands.run` and `run_code` calls as effects, attributed by A1 on
  `remote.result`; the agent's connections to a `--sandbox-peer` are part of
  the run. With the hook off and the provider declared, those connections
  are listed in `remote_sandbox_calls` and bound `effects` with
  `remote_sandbox`.

[AR-1 production](../qualification/action-record/README.md#ar-1-production-m2)
is the acceptance test: `run_ar1.py --profile production --mode replay` runs
on macOS and Linux (the host side staged through the host-records library),
`--mode live` on Linux with Docker on the systemd cgroup driver (the
harness's choice; the emitter also works with the `cgroupfs` driver, see
[production setup](production-setup.md)), the eBPF emitter in production
mode and the agent in a container.

## What is not covered yet

- **Remote sandboxes other than E2B** (Modal, Daytona and similar). Host
  sensors cannot see inside them; M2 observes only the pinned E2B SDK
  (spec 056 §4.4.1, OD-3).
- **Container sandboxes without a reported id.** On the local profile, or
  when the create command prints no id (`docker run` without `-d`), the
  processes inside the container are children of the container runtime, so
  lineage (H3) does not reach them, and no H5 link exists: they are counted
  in `sandbox_events_unlinked`. Grouping them by a configured cgroup →
  sandbox label (spec 056 §4.4, `tentative`) is not built.
- **Local-profile host ingress.** Against a local-profile Node, host records
  carry no start time, so every anchor is `tentative` (H2); see
  [production profile](#production-profile-m2) for `certain` anchors.
- **Process exits from the host sensor.** No host sensor reports process
  exits, so the only evidence that a pid was freed is the hook's own exit
  record. A pid reused by a process the hook did not start, with the same
  parent pid inside the 100 ms window, reads as one exec chain
  (`tentative`). Start times (M2) remove this case.
- **Non-model HTTP is recorded, not attributed.** Calls through httpx to
  hosts you list (`http_hosts=`, `FABRIC_WIRE_HTTP_HOSTS`, since v0.11.0)
  are recorded and delivered, and the `actions` view lists each one as an
  `http` row `(recorded; not attributed)`. They are not effects in spec
  056: no rule links one to the tool call that made it, a tool call whose
  only effect was an HTTP request reads `none_in_window`, and the agent's
  host `connect` events to that host are not joined to the request, so they
  stay `unexplained` unless you list the host's addresses with
  `--known-peer`. Attributing them (by the same window and output-match
  rules as subprocesses) and joining their connects needs a peer-address
  rule the records do not support yet: host records carry keyed peer
  addresses, the HTTP record a host name.
- **Other channels.** File, database, MCP and SSH hooks (spec 053) are not
  built, and neither is a TypeScript subprocess hook. Tools that run inside
  the agent process leave no effect. Declare them with `--in-process-tool`.
- **Host id not bound to the ingress group (M2).** A host group binds one
  source id and one token, but the `hst-` host id in a sensor's records is
  only format-checked, so a sensor holding one group's credentials can name
  another host.
- **Fork-only parents (M2).** No host sensor reports forks, so an exec whose
  parent only forked and produced no event of its own is listed
  unexplained. bwrap's default pid-1 reaper is such a parent: run
  `bwrap --unshare-pid` with `--as-pid-1`, as AR-1 does.
- **Pod-selector scope reads pods cluster-wide (M2).**
  `EMIT_AGENT_POD_SELECTOR` needs a ClusterRole with `get`, `list` and
  `watch` on pods; RBAC cannot limit it to one node, so every node's emitter
  can read every pod object, inline environment values included. Use
  static cgroup roots or a dedicated node pool where that is not
  acceptable ([host sensors](host-sensors.md#production-mode)).
- **Reported links from the hook.** Inside an explicit records-mode tool
  call (`CallRecorder`, kind `tool`), the hook names that call's attempt
  as the effect's parent, and A0 links the effect `caused_by` that attempt
  (`reported · certain`). Nothing yet records which model tool call the
  explicit call executes, so that model tool call still reads
  `effect_not_observed(none_in_window)`. A `decision.tool_call()` span
  scope is not on the records input and is not reported. The explicit
  subprocess adapter (`BoundedTerminalAdapter`) opens a `terminal` scope,
  so the hook defers to it and the child is recorded once.

See also: [spec 056](../specs/056-agent-action-reconstruction.md),
[host sensors](host-sensors.md),
[reconstruct and verdicts](reconstruct.md),
[AR-1](../qualification/action-record/README.md).
