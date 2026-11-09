# AR-1: the agent action reconstruction acceptance scenario

> **Status:** test harness for code released in v0.10.0 (spec 056
> milestone M1, WP6-06). In CI, hermetic mode passes on macOS and Linux, and
> live mode passes on Linux with the eBPF sensor; the auditd fallback is
> written but not run live in CI. See
> [docs/action-reconstruction.md](../../docs/action-reconstruction.md) for the
> feature itself. [AR-1 production](#ar-1-production-m2) (milestone M2,
> WP6-10) is the harness for code released in v0.11.0; its CI jobs pass:
> `production-replay` (macOS and Linux), `production-live` (Linux, eBPF
> emitter in production mode, every variant) and `production-auditd`
> (Linux, the auditd sensor collector on a fixture audit log).

AR-1 is the end-to-end test of
[spec 056 §6.2](../../specs/056-agent-action-reconstruction.md#62-ar-1-the-acceptance-scenario).
Fabric claims no agent action reconstruction until it passes in CI
([`.github/workflows/action-record.yml`](../../.github/workflows/action-record.yml)).

## What runs

| Piece | File | Role |
|---|---|---|
| Agent | [`ar1/agent.py`](ar1/agent.py) | A plain Python agent on the OpenAI SDK. It imports nothing from Fabric: capture is switched on from outside (autoload path on `PYTHONPATH`, `FABRIC_*` variables, `FABRIC_WIRE_EXEC=1`). |
| Model | [`ar1/fixture_model.py`](ar1/fixture_model.py) | A deterministic OpenAI-compatible server on a real socket, scripting steps 1 to 7. It answers each turn in 40 ms and holds the fourth reply for 900 ms (step 5 runs then). |
| External host | [`ar1/fixture_host.py`](ar1/fixture_host.py) | Answers step 2's `curl` (and checks its bearer token) and step 6's raw ping, on `::1`, a different address from the model's `127.0.0.1`. |
| Node | [`ar1/node.py`](ar1/node.py) | The local-profile telemetry path of `deploy/compose/collector-config/collector.yaml`, started through `fabric-gate` from a native `components/otel-collector-fabric/dist` build. |
| Destination | [`ar1/sink.py`](ar1/sink.py) | Decodes what the Node delivers into sink JSONL (`span` and `log` rows) and keeps the raw bytes for the canary search. |
| Host sensor (live) | [`ar1/sensor.py`](ar1/sensor.py) | The eBPF emitter scoped to a cgroup made for the agent, or, when its programs do not load, the Node's auditd receiver with rules scoped to a dedicated user. |
| Host replay (hermetic) | [`ar1/replay.py`](ar1/replay.py), [`ar1/host-replay.json`](ar1/host-replay.json) | Recorded host-sensor events, written as process trees, bound to the real run's pids and times and posted through the Node. |
| Assertions | [`ar1/expect.py`](ar1/expect.py), [`ar1/harness.py`](ar1/harness.py) | Read `python -m fabric.reconstruct actions --json`, the report and the projection, all run with `--host-records`. |

Content mode is `retain_original`, set by an explicit local-profile capture
policy. The identity key is a fixed, published test value. The verifier runs
with `--host-coverage-declared` (the sensor, or the replay, covers the whole
run, which local records cannot prove), `--agent-pid` (the pid the agent
reports; an export does not carry the epoch registration) and
`--known-peer 127.0.0.1` (the agent's own telemetry to the Node).

## Run it

```bash
cd sdk/python && uv sync --all-extras && cd ../..
make -C components/otel-collector-fabric build      # the Node; needs Go and the OCB builder
sdk/python/.venv/bin/python qualification/action-record/run_ar1.py --mode hermetic --out /tmp/ar1
sdk/python/.venv/bin/python -m pytest qualification/action-record/tests -q   # the same, as a test
```

`--node off` sends the agent's telemetry straight to the sink when no Node
is built. `--variants base,a` runs a subset. The run writes
`ar1-result.json`, which lists every check, and one directory per variant.
Each directory holds the sink export, the agent's store, `actions.txt`,
`actions.json`, `report.json`, `projection.json` and the host records.

Live mode runs on Linux and needs passwordless `sudo`:
`run_ar1.py --mode live` (`--sensor ebpf|auditd` to force one sensor). The
emitter is built with `go generate ./... && go build` in
`components/host-emitter` (clang, llvm and libbpf-dev are needed).

## What is checked

| Variant | Run | Expected |
|---|---|---|
| base | the §6.2 script | `decisions` complete, `actions` complete, `effects` partial(`unattributed_effect`), `corroboration` partial(`unexplained_host_event`). Steps 1 to 4: `caused_by` their call, `output_match · certain` (step 2 may also be `sequence_bracket`). Every effect: `corroborated_by` its exec event, `process_anchor · tentative`. Children, step 1's in-place exec of `sha256sum`, `curl`'s connect and the sandboxed Python: `part_of` their effect, `process_lineage`. The agent's model connections: `part_of` the run (H4). Step 5 is the unattributed effect. The SDK probes run before the first model call: startup effects (spec 056 revision 11), listed in `startup_effects`, never attributed. Step 6 is the only unexplained host event. |
| a | base export without `--host-records` | `corroboration` not_observed(`not_configured`); other chains and links unchanged |
| b | step 1's `completed` exec record removed from the agent's spool before delivery | `effects` partial(`sequence_gap`, `unattributed_effect`); `decisions` partial(`sequence_gap`), because the lost position is on the epoch the exchanges share and nothing proves it was not an exchange; `actions` complete; `corroboration` as in base |
| c | hook off | `effects` not_observed(`channel_disabled`); manifest row `exec.subprocess` disabled(`hook_disabled`); T1 to T5 `effect_not_observed(channel_disabled)`; the host chain still runs: the agent's own connections are `part_of` the run by H4 (`--agent-pid`), and step 6 is unexplained |
| d | `terminal.stdout`/`stderr` as `metadata_only` | step 3's two effects are A3, `ambiguous`, over T3 and T4; steps 1, 2 and 4 keep their targets |
| e | capture off, then on | the same answer, tool exit codes and output digests; the 053 §4.4 latency gate of the hook (`sdk/python/tests/test_hooks_exec_passivity.py`) passes |
| canaries | every file written | neither the step 1 environment secret nor the step 2 bearer token appears in any spool file, Node export, report or store |

Step 1's command and the parallel step 3 commands are a list and two
pipelines. Step 5's `uname -a` and the sandbox launcher are started without
a shell.

## Where this departs from §6.2, and why

- **Anchors are `tentative`, not `certain`.** Local-profile host records
  carry no process start time, so H1 cannot apply; H2 links each effect.
  The WP6-01 fixture `ar1-run-local-profile` pins the same result. M2
  records add the start time. Every step's effect, steps 4 and 5
  included, has one `process_anchor · tentative` link and no step reports
  `anchor_missing`. Step 1 on Ubuntu, where `dash` execs `sha256sum` in
  place, is one exec chain (spec 056 §4.3): the anchor is the shell's
  exec, and the in-place exec is lineage.
- **Variant (b) also bounds `decisions`.** §6.2 names only the `effects`
  chain. With the shared allocator, the dropped record's position is on the
  exchanges' epoch, and the verifier cannot prove the missing position was
  not an exchange, so it reports `decisions` partial(`sequence_gap`) as well.
- **Variant (d) changes more than step 3.** Without content, rule A1 cannot
  apply, so steps 1, 2 and 4 become `sequence_bracket · tentative`. Their
  targets do not change.
- **More unattributed effects than step 5.** At its first request the
  OpenAI SDK calls `platform.platform()` and `platform.architecture()`,
  and these start `uname -p` and `file -b`. They are real subprocesses of
  the agent that no tool call explains, so the harness expects them.
- **The fixture model takes 40 ms per reply.** A reply faster than the
  agent's declared clock uncertainty (1 ms here) puts the next effect
  inside the margin of the previous tool call's window too, and A3 then
  lists both calls.
- **No kind or Compose.** The Node, sink and fixtures run as host processes
  from native builds, so the hermetic mode needs no Docker.
- **The auditd fallback is scoped by user, not by cgroup.** auditd cannot
  filter on a cgroup, so the agent runs as the `fabricar1` user and the
  rules filter on its uid. Spec OD-6 also allows a self-hosted runner for
  the host part instead.

## Limits of hermetic mode

The replay proves the reader, the join and the report on records shaped as
the eBPF emitter writes them. It does not prove the emitter: the join sees
what the template says. The template models `dash`, the Ubuntu `/bin/sh`:
it forks each command of a pipeline and every command of a list but the
last, which it execs in place. Step 1 (`ls … && sha256sum …`) therefore
has two exec events with the effect's pid and parent pid, and hermetic
mode checks the exec-chain rule of spec 056 §4.3 on every run. The replay
keeps the in-place exec before the effect's observed exit, as a real one
is. The template also leaves out Fabric's own connections from the agent
process to the Node; live mode declares the Node's loopback address with
`--known-peer`.

## Defects AR-1 found (fixed with it)

- The spool reader quarantined every records-input record whose bodies a
  `file://` store already held, so no `exec.subprocess` record left the
  agent (`wire/_spool.py`).
- A record outside every `fabric.wire.run()` scope had no run id, so its
  descriptors failed verification and no run held it (`_records.py`).
- An unscoped exchange kept no endpoint id, so H4 flagged every connection
  to the agent's own model as unexplained (`reconstruct/_inputs.py`).

## AR-1 production (M2)

[Spec 056 §6.2 "AR-1 production"](../../specs/056-agent-action-reconstruction.md#62-ar-1-the-acceptance-scenario):
the same run against a production-profile Node, with two more steps before
the answer. Step 8: the model asks for `run_container`, and the agent runs
`docker run -d --cgroup-parent fabric-sandboxes.slice IMAGE sh -c '…'` and
returns the container id. Step 9: the model asks for `run_remote`, and the
agent runs it with the pinned `e2b` SDK's `Sandbox.commands.run` against the
fixture E2B service of [`qualification/remote-sandbox`](../remote-sandbox/README.md).
Step 4 runs `bwrap --unshare-pid --as-pid-1 --unshare-net` when bwrap works.

```bash
make -C components/otel-collector-fabric build      # the Node (replay)
sdk/python/.venv/bin/python qualification/action-record/run_ar1.py \
  --profile production --mode replay --out /tmp/ar1-production   # macOS or Linux, needs Go
sdk/python/.venv/bin/python qualification/action-record/run_ar1.py \
  --profile production --mode live --out /tmp/ar1-production-live  # Linux, see below
```

| Piece | File | Role |
|---|---|---|
| Group Node (replay) | [`ar1/production.py`](ar1/production.py) | The native Node through `fabric-gate` with the static ingress groups of the `valid/agent-ebpf-auditd.yaml` golden without auditd, plus a second `host.ebpf` group (a quiet node): `agent` (telemetry and content into a `fabriccontent` file store sealed with the content key), `ebpf` and `quiet`. Every listener TLS, every group its own token; delivery is verified HTTPS to the sink, which checks its own token. Also the test CA and keys, the source ids and the agent's node-mode environment. |
| Host replay | [`ar1/replay.py`](ar1/replay.py) (`bind_production`, `run_replay`), [`ar1/host-replay.json`](ar1/host-replay.json) (`production`) | The trees of the local replay plus step 8's container (sandbox scope, the id the fixture `docker` printed) and step 9's provider connections, as `hostrecords.Event` lines, staged and posted by `hostrecords-replay` (`components/otel-collector-fabric/hostrecords/cmd`, built with `go build`, never by an image) to the `ebpf` group; the quiet node (manifest, heartbeats, one container nobody reported) to the `quiet` group. The library assigns the event ids; the harness reads them back by position. |
| Harness | [`ar1/production_harness.py`](ar1/production_harness.py) | The variants and the canaries. The verifier reads only the sink's export with `--trusted-source --profile production`, the Node's content store and key, `--host-source host.ebpf=<s- id>` for both sensors, `--sandbox-peer ADDRESS:PORT` and `--endpoint-peer`; no `--host-records`, `--host-label` or `--host-coverage-declared`. |
| Live | [`ar1/live.py`](ar1/live.py) | The Compose Node (`docker-compose.yml`, `.production.yml`, `.host-ingress.yml`, `.host-ingress-content.yml`, and a harness overlay: the content exporter on the file backend, the export CA, `host.docker.internal`), the eBPF emitter in production mode with the two slices as agent and sandbox roots, the agent in node mode in a container (`--cgroup-parent fabric-agents.slice`, its own pid namespace, host network, the harness's uid, the Docker socket), a real `docker run` of a pinned busybox and bwrap. `AR1_NODE_IMAGE` reuses a Node image built from this checkout. |

| Variant | Run | Expected |
|---|---|---|
| base | steps 1 to 9 | Chains as in M1. Steps 1-4 and 8: A1 (step 2 may be A2); step 9: A1 on `remote.result`. Every exec effect `corroborated_by` its exec event: `process_anchor · certain` (H1) where the hook recorded `fabric.process.start_ns` and `pid_ns` (Linux), else `tentative` (H2). Step 8's container events: one `sandbox` row, `sandbox_report · certain`, `part_of` the effect with provenance `reported` in the report. The agent's model and provider connections: H4 `part_of` the run. Step 6: the only unexplained event. `sandbox_events_unlinked`: the quiet node's events (0 live). Neither host source in `sources[]`. |
| a | base export without the host sources' spans, nothing declared | `corroboration` not_observed(`not_configured`); other chains unchanged |
| b | step 1's `completed` exec record removed from the agent's encrypted spool before delivery (opened and resealed with the spool key) | as M1 (b) |
| c | exec hook off, remote sandbox on | `effects` partial(`channel_disabled`): `remote.sandbox` stays enabled, so the chain is judged (spec 056 §4.5), not not_observed as with the M1 single channel; T1 to T6 `effect_not_observed(channel_disabled)`; T7's remote effect attributed |
| d | subprocess output `metadata_only` | step 3 A3 `ambiguous`; steps 1, 2, 4 and 8 A2; step 9 stays A1 (`remote.result` is content), so `output_match` is `applied` |
| e | capture off, then on | same answers and exit codes (step 8's output digest is not compared: each run prints a new container id); the latency gate |
| f | `FABRIC_WIRE_REMOTE_SANDBOX` unset, `FABRIC_WIRE_SANDBOX_HOSTS` set | manifest `remote.sandbox` disabled(`remote_sandbox`); `effects` partial(`unattributed_effect`, `remote_sandbox`); T7 `effect_not_observed(channel_disabled)`; the provider connections in `remote_sandbox_calls`, not unexplained |
| g | step 8 without `-d` | no `created_id`, no `sandbox` row; the container's events in `sandbox_events_unlinked`; `corroboration` unchanged |
| h | the host side to the agent group with its token; then the agent to the `ebpf` group with that group's token | the first: the replay is refused, the sink holds no host record, `corroboration` partial(`source_gap`, `anchor_missing`); the second: the sink holds no agent record |
| canaries | every file | the step 1 secret, the step 2 bearer token, the E2B API key and step 9's `envs` value in no file; the clear container ids in no file but the replay input (the kernel's view the replay stands in for); the clear peer addresses in no sensor state, host span or report |

Live mode needs Linux with cgroup v2, Docker on the `systemd` cgroup driver
(the harness fails, never skips, otherwise), passwordless `sudo` and the
emitter built for the kernel. The `systemd` driver is this harness's setup
(it scopes the agent with systemd slice units), not a requirement of the
emitter: with the `cgroupfs` driver, `--cgroup-parent=/fabric-agents` and
`EMIT_AGENT_CGROUP_ROOTS=/sys/fs/cgroup/fabric-agents` scope the agent the
same way (the v0.11.0 UAT ran so on Docker Desktop;
[production setup](../../docs/production-setup.md#4-the-ebpf-emitter)). It installs `fabric-agents.slice` and
`fabric-sandboxes.slice` as runtime units, relaxes
`kernel.apparmor_restrict_unprivileged_userns` for the run when it is set,
checks `print-source-id` against the label pseudonym, and fails the run
unless step 4 ran in bwrap.

### Where AR-1 production departs from §6.2, and why

- **No `--host-label` for production records.** §6.2 lists it among the
  verifier's flags; the CLI takes it only with `--host-records` (local
  records), and production records name their host themselves.
- **Variant (c) gives `effects` partial(`channel_disabled`).** Only the
  exec hook is off; `remote.sandbox` stays enabled and explains T7, so the
  chain is judged (§4.5: `not_observed` only with no effect channel
  enabled) and names the disabled channel. T1 to T6 are
  `channel_disabled`: each tool call is judged against the channel that
  would carry its effect.
- **Variant (h) also reports `anchor_missing`.** §6.2 names `source_gap`
  only. No record of the declared source names the agent's host, so the
  effects there have nothing to anchor them; the verifier says so.
- **Variant (f): the provider connections are also `part_of` the run.**
  They are H4 links of the agent process and listed in
  `remote_sandbox_calls`; neither is unexplained.
- **The replay's provider address.** On macOS only 127.0.0.1 answers on the
  loopback interface, so the fixture E2B service shares it with the model
  and the sandbox peer names the port (`--sandbox-peer 127.0.0.1:PORT`). On
  Linux it has 127.0.0.2 to itself.
- **Live content uses the file backend.** WP4-09's content overlay writes
  to S3, which the live job does not run; a harness config switches the
  agent group's `fabriccontent` exporter to the file backend, sealed with the
  content key. Listener, token, binding and sealed queue are WP4-09's. (Content
  in the agent's own store would not do: the production verifier marks
  objects the Node did not stamp `source_unauthenticated`.)
- **Step 4 adds `--as-pid-1`.** Without it, bwrap's pid-1 reaper forks the
  code without an exec. H3 links a fork-only child from its first connect or
  file event, but the reaper makes none, so no event names the inner
  Python's parent and its exec is listed unexplained (seen live). With the
  flag the code is pid 1 of the nested namespace, a direct child of the
  launcher, and H3 links it across the namespace boundary. Open with the
  spec owner: plain `--unshare-pid` (§6.2 step 4) needs a fork event from
  the sensor (`sched_process_fork`) or a spec change.
- **The live agent runs as the harness's user**, not root: as root without
  `CAP_SYS_ADMIN`, bwrap makes no user namespace and cannot unshare anything.
- **`hostrecords-replay` is built with `go build`** into the run directory
  once, instead of `go run` per variant; the command is the same.

### Limits of the production replay

It proves the gate, admission, delivery and reader path of a
production-profile Node and the host-records library's staging, not the
emitter: the template decides what the join sees. Off Linux the hook records
neither start time nor pid namespace, so the replay writes none and every
anchor is `tentative` (H2); on Linux it copies each effect's own values and
the anchors are `certain` (H1). The nested pid namespace of bwrap is modelled
only when the effect's command has `--unshare-pid`.
