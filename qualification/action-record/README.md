# AR-1: the agent action reconstruction acceptance scenario

> **Status:** test harness for code that is built but not yet released
> (spec 056 milestone M1, WP6-06). Hermetic mode passes on macOS; live mode
> (Linux, eBPF or auditd) is written for CI and has not been run yet. See
> [docs/action-reconstruction.md](../../docs/action-reconstruction.md) for the
> feature itself.

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
| base | the §6.2 script | `decisions` complete, `actions` complete, `effects` partial(`unattributed_effect`), `corroboration` partial(`unexplained_host_event`). Steps 1 to 4: `caused_by` their call, `output_match · certain` (step 2 may also be `sequence_bracket`). Every effect: `corroborated_by` its exec event, `process_anchor · tentative`. Children, step 1's in-place exec of `sha256sum`, `curl`'s connect and the sandboxed Python: `part_of` their effect, `process_lineage`. The agent's model connections: `part_of` the run (H4). Step 5 and the SDK probes are the unattributed effects. Step 6 is the only unexplained host event. |
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
