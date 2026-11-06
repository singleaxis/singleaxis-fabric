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
  script starts, and its connection, become visible. A shell that execs its
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

The hook needs wire capture installed in the same process. With zero-code
capture, add two variables:

```bash
export PYTHONPATH="$(python -m fabric.wire --print-autoload-path)"
export FABRIC_WIRE_AUTOLOAD=1
export FABRIC_TENANT_ID=demo
export FABRIC_WIRE_STORE="file://$PWD/store"
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export FABRIC_WIRE_ID_KEY="$(cat id-key)"   # 16+ bytes; also keys the host id
export FABRIC_WIRE_EXEC=1                   # the exec.subprocess hook
export FABRIC_HOST_LABEL=build-host-7       # names this host for the host join
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
export FABRIC_WIRE_ID_KEY="$(cat id-key)"
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
  1    effect     exec uname -p exit 0                 (no open tool call)
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
  unattributed effects: 3   (exec uname -p, seq 0: no open tool call; …; exec uname -a, seq 16: no open tool call)
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
  `unexplained` marks an event that no rule explains.
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
  pid namespace number), `out_of_scope` (in a run's window, outside the
  agent's scope) and `no_run` (in no run's window). Captured host activity
  is never dropped: `--json` lists every one, and the report's top-level
  `unattributed_host_events` gives the count per reason and the first 64.

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
`platform` module, which the OpenAI SDK calls at its first request, so no
tool call explains them. `uname -a` is a background thread of the agent. Row 35 is
the agent connecting to a host no model call reached.

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
