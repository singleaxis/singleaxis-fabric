# Agent action reconstruction fixtures (spec 056, milestone M1)

This directory holds the contract that the spec 056 work packages build
against:

- the **interface goldens**: one record of each kind the attribution rules
  read, exactly as the agent spool or the Node export holds it;
- the **rule fixtures**: small, complete inputs for every attribution rule
  (A0 to A4), every host-join rule (H1 to H4), the edge cases of spec 056
  §6.1 and the AR-1 scenario of §6.2, each with the links, chain verdicts
  and attribution summary a correct implementation must produce;
- **refused fixtures**: the expectation a wrong implementation would write,
  with the validator error that refuses it.

Status: draft. No runtime emits or reads these documents yet. The hooks
(WP6-02, WP6-03) must emit records shaped like the exec golden; the verifier
(WP6-04 `reconstruct/_attribute.py`, WP6-05 `reconstruct/_host.py`) must turn
each rule fixture's input into its expected output; the AR-1 harness
(WP6-06) runs the same scenario end to end.

Fabric records what the agent did. Nothing here evaluates whether it was
right: a link says how two records are related and how that relation was
established, nothing more.

## Layout

| Path | Document | What it pins |
|---|---|---|
| `interface/exec-subprocess-records.json` | `fabric.action-interface-golden/v1`, kind `exec.subprocess` | The two records of one `subprocess.run(...)` call on the records input |
| `interface/host-local-log-records.json` | same, kind `host.local_log` | Today's local-profile host records (eBPF emitter, auditd receiver) as a local Node exports them |
| `interface/host-sensor-spans.json` | same, kind `host.sensor_span` | The spec 053 §6.2.3 host record shape (production ingress, M2) |
| `rules/*.json` | `fabric.action-rule-fixture/v1` | One input and its expected output per rule, edge case and AR-1 variant |
| `invalid/*.json` | `fabric.action-rule-fixture/v1` | A rule fixture with a wrong expectation; the manifest names the error code |

Related fixtures outside this directory:

| Path | What it pins |
|---|---|
| `contracts/capture/v1/fixtures/valid/spool-record-exec-subprocess-{start,end}.json` | The exec golden's two records as complete spool records (descriptors, offsets), checked by the capture validator |
| `contracts/coverage/v1/{valid,invalid}/evidence-exec-*.json` | The `fabric.exec.observation/v1` evidence type, one document per `api` value and five refusals |
| `contracts/capture/v1/fixtures/{valid,invalid}/run-reconstruction-*chain*.json` | The report objects `chains`, `attribution` and `sensor_events` on a run |
| `contracts/coverage/v1/fixtures/vectors/records-span-v1.json` | Cases `exec.subprocess record keeps its process keys` and `process join keys only on exec.subprocess` |

## How the fixtures are made and checked

- `scripts/contracts/action_reference.py` is the executable form of the
  rules: `reconstruct(input, call_id)` returns the `expected` object of a rule
  fixture.
- `scripts/contracts/action_record.py` builds every fixture listed above.
  `python scripts/contracts/generate_p0_contracts.py` writes them and re-pins
  the family manifests; `--check` fails when a file would change.
- `python scripts/contracts/validate_coverage_contracts.py` checks every
  fixture here: the shape, the link rules (below), the chain rules, and that
  `expected` equals what the reference computes from `input`. A refused
  fixture must fail with the code its manifest entry names.
- `scripts/tests/test_coverage_contracts.py` and
  `scripts/tests/test_capture_contracts.py` (`-k 056`, and the chain tests)
  pin the behaviour of each rule directly.

Ids are reproducible test values. Pseudonyms use the shared test key
`fabric-test-id-key-not-a-secret` (`key` in each rule fixture), never a real
secret.

## 1. The exec.subprocess records (`interface/exec-subprocess-records.json`)

One subprocess call produces one **attempt** (`fabric.attempt.uid`) with at
least two records on the records input (spec 050 §3.4), each holding its own
sequence position:

| Record | Written when | Lifecycle |
|---|---|---|
| `start` | `Popen` returned (the child exists) | `fabric.step.lifecycle_state=running` |
| `end` | `communicate()` (or `wait`, `poll`) returned | `completed`, `fabric.step.status=ok` (a nonzero exit is still `ok`; the exit code is a field) |

**Span.** Name `fabric.activity`: the record passes the name hint
`fabric.terminal` and fabricguard's category function
(`span-category-v1.json`) maps any name it does not know to
`fabric.activity`; the step kind travels in `fabric.step.kind`. Kind
`internal`, status `unset`. `start_time_unix_nano` / `end_time_unix_nano`
bracket the observed call (Popen construction for `start`, `communicate`
for `end`). The `start` record's start time is the **effect's start time**
the attribution rules use.

**Attributes** (every one is admitted by rule A, the records key table
generated from `registry/telemetry-keys-v1.json`):

| Key | Record | Value in the golden | Meaning and source |
|---|---|---|---|
| `fabric.capture.input` | both | `records` | Hooks use the records input, never the wire input (053 §3.1) |
| `fabric.capture.source` | both | `observed` | `begin(provenance="observed")` (053 B1) |
| `fabric.capture.point` | both | `exec.subprocess@0.9.0` | Capture point id and SDK version |
| `fabric.source_id`, `fabric.source.epoch`, `fabric.source.sequence` | both | `s-…`, epoch, 5 and 6 | The shared allocator's position (050 §3.3); record order within an epoch is exact |
| `fabric.event_id` | both | uuid4 | Persisted per record. The `start` record's id is the effect's `event_id` in the report |
| `fabric.attempt.uid` | both | uuid4 | The effect's identity: the projection step's `attempt_id` |
| `fabric.run.id`, `fabric.run.scope_id`, `fabric.run.segment_id` | both | | The run, scope and segment the attempt belongs to |
| `fabric.step.kind` | both | `terminal` | |
| `fabric.actor.type` | both | `agent` | |
| `fabric.step.lifecycle_state` | both | `running`, `completed` | |
| `fabric.step.status` | `end` | `ok` | |
| `fabric.process.pid` | both | 4121 | The child's pid (`Popen.pid`, N35) |
| `fabric.process.parent_pid` | `start` | 4100 | The agent's pid at spawn (`os.getpid()`, no I/O). **New in spec 056**; admitted only when `fabric.capture.point` is `exec.subprocess` |
| `fabric.process.start_ns` | `start` | 60120000000 | The child's start time in boot-relative nanoseconds, read once by the capture worker from `/proc/<pid>/stat` field 22 × (10⁹ / `SC_CLK_TCK`). Absent when the child already exited, off Linux, or on any error (OD-2). **New in spec 056**; `exec.subprocess` only |
| `fabric.execution.host_id` | `start` | `hst-…` | `hst-` v2 pseudonym of the operator's configured host label (053 C41); trusted configuration only. In clear identity mode the check refuses a clear label, so the key is dropped (see Limits) |
| `fabric.process.exit_code` | `end` | 0 | `returncode` when ≥ 0 |
| `fabric.process.signal` | `end` | (absent) | The positive signal number when `returncode` < 0; never a fabricated exit code |
| `fabric.content.object_ids` | both | three uuid4s | The record's bodies, in order (X48) |

**Bodies** (content-v2 objects, content provenance `protocol`, boundary
`terminal`; the golden shows them as UTF-8 text in `bodies[].utf8`):

| Role | Record | Media type | Format |
|---|---|---|---|
| `terminal.argv` | `start` | `application/json` | `{"form": "shell", "command": CELL}` or `{"form": "argv", "args": [CELL, …]}`; a CELL is `{"t":"str","v":…}`, `{"t":"b64","v":…}` or `{"t":"not_exposed"}` (053 N32) |
| `terminal.context` | `start` | `application/json` | `{executable?, cwd?, shell, env_names?}`; `env_names` are the **names** of an explicitly passed `env` dict, never values; `os.environ` is never read |
| `terminal.stdout`, `terminal.stderr` | `end` | `text/plain` (text output) or `application/octet-stream` (bytes) | Exactly what `communicate()` returned. Text output is the caller's decoded `str`, never claimed to be the pipe's bytes (`output_form: text` in the evidence) |
| `record.evidence` | both | `application/vnd.fabric.record-evidence+json` | One `fabric.record-evidence/v1` document with one `fabric.exec.observation/v1` item (below) |

The PROTECT modes apply to every `terminal.*` role as usual: under
`metadata_only` the bodies are descriptor-only objects and output matching
(A1) does not apply.

**Evidence item** (`evidence/fabric.exec.observation-v1.schema.json`, closed):

| Property | Golden `start` | Golden `end` | Meaning |
|---|---|---|---|
| `api` | `run` | `run` | The observed call (`popen`, `run`, `communicate`, `wait`, `poll`, `check_output`, the `asyncio_*` equivalents; `audit` for the later exec-audit channel) |
| `argv_form` | `shell_string` | | `argv`, `shell_string` or `not_exposed` |
| `stdio` | `{stdin: inherit, stdout: pipe, stderr: pipe}` | | The caller's dispositions; Fabric never changes them |
| `output_form`, `text_encoding` | | `text`, `utf-8` | |
| `observation_index`, `cumulative`, `timeout_partial` | | 0 | Repeated `communicate` after a timeout |
| `pid_known` | true | true | False on a spawn failure; no pid is invented |
| `error_class` | | | The exception class's `__qualname__`, never its message |

`record_digest` is each record's spec 050 §3.7 digest
(`p1_reference.record_digest`), so a seal over these records is
recomputable.

**`normalized_effect`** is the effect as the attribution rules read it:

| Field | From |
|---|---|
| `attempt_uid` | `fabric.attempt.uid` |
| `event_id` | the `start` record's `fabric.event_id` |
| `sequence` | the `start` record's `fabric.source.sequence` |
| `start_ns` | the `start` record's span start time |
| `pid`, `parent_pid`, `process_start_ns`, `host_id` | `fabric.process.pid`, `.parent_pid`, `.start_ns`, `fabric.execution.host_id` (first record carrying each) |
| `exit_observed_ns` | the span end time of the first record carrying `fabric.process.exit_code` or `fabric.process.signal`: the hook saw the child reaped, so its pid was free, by then (absent when no record carries either, e.g. a timeout or a lost `end` record) |
| `stdout` | the `end` record's `terminal.stdout` body, decoded as UTF-8 (absent when not captured) |

## 2. Local-profile host records (`interface/host-local-log-records.json`)

What the eBPF emitter (`components/host-emitter/emitter.go`) and the auditd
receiver (`receiver/auditreceiver/translate.go`) produce today, as a
local-profile Node exports them after fabricguard's `audit` class allowlist
(`processor/fabricguardprocessor/allowlist.go`). The document holds an OTLP/JSON
`ExportLogsServiceRequest` (`export`) with one resource per sensor, and the
host event a reader derives from each log record (`normalized`, `null` for a
status record).

These records are **log records, not spans**, and carry no source, epoch,
sequence, host id, pid namespace or process start time.

| Key | Sensors | Meaning |
|---|---|---|
| `event_class` | both | Always `audit` |
| `audit.source` | both | `ebpf`, `netlink` or `logfile` |
| `audit.syscall` | both | `execve`, `execveat` (exec); `connect`, `accept`, `bind`, `socket` (connect); `openat`, `open` (file). Absent on a status record |
| `audit.result` | auditd, eBPF exec | `success` or `failed:<ERRNO>`; eBPF connect and file events carry none |
| `process.pid`, `process.parent_pid` | both | Pids as the sensor sees them (see pid namespaces below) |
| `process.executable.name` | both | `comm`, in clear in the local profile |
| `process.executable.path_sha256`, `process.command_args_sha256`, `file.path_sha256` | both | Bare hex SHA-256; argv and paths are never exported raw |
| `process.owner` | auditd | Audit uid |
| `network.peer.address`, `network.peer.port` | both | **In clear** in the local profile |
| `audit.serial` | auditd | Unsigned decimal string |
| `audit.cgroup_id` | eBPF | Integer |
| `audit.event` | both | On an event: `command_args_incomplete`, `path_incomplete`, `path_and_command_args_incomplete`. Alone (no `audit.syscall`): a status record such as `capture_loss` (with `audit.loss_reason`, `fabric.event_count`), `dedupe_collapsed`, rotation and source-loss markers |
| `log.record.uid` | eBPF | `host-` + 32 hex, set by the emitter's spool |
| `fabric.record_id`, `audit.source_id`, `audit.source_generation`, `audit.cursor_start`, `audit.cursor_end` | auditd logfile mode | Durable cursor identity |

**Host event id** (the `id` of an `event` link target and of
`sensor_events[].event_id`):

1. `fabric.event_id` on a spec 053 §6.2.3 record;
2. else `log.record.uid` (eBPF emitter), as is;
3. else `rec-` + `fabric.record_id` (auditd logfile mode);
4. else `hev-` + the first 32 hex of SHA-256 over the spec-029 canonical JSON
   of `{"time_unix_nano": <int>, "attributes": {<decoded attributes>}}`
   (auditd netlink mode). This id is stable for one export, not across a
   re-export with different attributes.

**Normalized host event** (`action_record.normalize_local`): `event_id`,
`source` (`host.ebpf` when `audit.source` is `ebpf`, else `host.auditd`),
`event_class` (from the syscall), `time_ns` (`timeUnixNano`), `pid`, `ppid`,
`result` (`success`, `failed` or `unknown`) and, for a connection,
`peer_id`: the `hst-` v2 pseudonym of the clear peer address under the
reader's id key. A local record carries no host id: the reader takes it from
the host-source declaration (`input.host_sources[].host_id`).

## 3. Production host records (`interface/host-sensor-spans.json`)

The spec 053 §6.2.3 shape, which no sensor emits yet (053 WP4-07, milestone
M2): one span named `fabric.sensor_event` per event, start time = end time
= the event time, status `unset`, no bodies, no evidence object. It carries
its own source, epoch and sequence, `fabric.sensor.*` keys and, for the
eBPF emitter, `fabric.sensor.process_start_ns` and `fabric.sensor.cgroup_id`.
The keys are not yet registry rows (053 WP4-01 registers them); the
validator checks the golden against the 053 §6.2.3 table, transcribed in
`action_record.SENSOR_KEYS`. Its normalized event adds `process_start_ns`,
`pid_ns`, `host_id` (`fabric.execution.host_id`) and `peer_id`
(`fabric.network.host_id`).

## 4. Rule fixtures (`rules/*.json`)

```text
{schema_version: "fabric.action-rule-fixture/v1",
 name, rules: ["A1", "H3", …], description, key,
 input:    {run, agent, content_mode, exchange_verdict, effect_channels,
            endpoint_peers, host_sources, exchanges, effects, host_events,
            [exchange_reasons], [exchange_gaps], [effect_sequence_gaps],
            [declared_outstanding], [in_process_tools]},
 expected: {projection_links, sensor_events, chains, attribution, trace}}
```

The input is normalized: every fact a rule reads, already extracted from the
records. Times are nanoseconds (Unix for wall clock, boot-relative for
process start times).

| Input field | Meaning | Where a reader finds it |
|---|---|---|
| `run.run_id`, `run.segment_id` | The run and its segment | `fabric.run.id`, `fabric.run.segment_id` |
| `run.window` | `[start, end]` of the run: the bound for H4, for unexplained events and for a window no later exchange closes | the run's markers (`run_start`, `run_end`) |
| `agent.source_id`, `agent.source_epoch` | The agent's epoch | `fabric.source_id`, `fabric.source.epoch` |
| `agent.pid` | The agent's own pid (H4) | the epoch registration (050 §3.2). An export does not carry the registration: `fabric.reconstruct` takes the operator's `--agent-pid`, else the parent pid every effect agrees on, so a run without effects needs `--agent-pid` for H4 |
| `agent.process_start_ns` | The agent's process start time, when known (H4 `certain`) | the epoch registration, when it records one |
| `agent.pid_ns` | The agent's pid namespace, when known | the epoch registration, when it records one |
| `agent.host_id` | The agent's host | `fabric.execution.host_id` |
| `agent.clock_uncertainty_ns` | The epoch's declared clock uncertainty: the window margin of A rules | the capture manifest / `install.config` (050 §1.3) |
| `content_mode` | `retain_original` or `metadata_only` | the capture policy in the manifest |
| `output_withheld` | Optional, `true` when PROTECT withheld some effect's output by policy. Only those effects lose A1 (they carry no `stdout`); the flag makes `output_match` read `not_applicable(privacy_policy)` when A1 applied to no effect | the `terminal.stdout` descriptors (`not_stored`, `privacy_policy`) |
| `exchange_verdict`, `exchange_reasons` | The existing run verdict over exchanges and its gap types: the `decisions` chain | the verifier's run verdict (050 §3.12) |
| `exchange_gaps` | Exchanges the action chain needs that are missing or unparsed | gaps of type `sequence_gap` / `unparsed_exchange` on exchanges |
| `effect_channels` | Per effect capture point: `active` or `disabled` | the manifest's capture-point rows |
| `effect_sequence_gaps` | Positions of effect records that do not verify | the verifier's sequence gaps |
| `endpoint_peers` | Per `fabric.wire.endpoint_id`, the peer ids the model endpoint resolves to | the reader's endpoint configuration (the wire records hold a label, not an address) |
| `declared_outstanding` | Tool-call ids the run declared outstanding at a normal end | the run outcome |
| `in_process_tools` | Tool names the operator declares pure in-process (`no_effect_channel`) | reader configuration |
| `host_sources[]` | `source` (`host.ebpf`, `host.auditd`), `host_id`, `pid_namespace` (`declared_same`: the operator declares the sensor reports pids in the agent's namespace; `recorded`: compare `pid_ns`), `verified` (positions, heartbeats, no upstream loss over the window), `clock_uncertainty_ns` | the host-source declaration and the sensor source's verification |
| `exchanges[]` | `exchange_id`, `sequence`, `start_ns`, `end_ns` (span times), `endpoint_id`, `tool_calls[] {id, name}` (from the response), `tool_results[] {id, text?, sha256?}` (from the request; `text` is the result content as fed back, absent when withheld) | the exchange span and the parsed stored bodies (`reconstruct/_stitch.py`) |
| `effects[]` | the normalized effect of section 1, plus `label` (for readers only), `reported_parent_attempt` / `reported_parent_call` (A0), `stdout_sha256` (when only a digest is available) | the exec records |
| `host_events[]` | the normalized host event of sections 2 and 3, plus `label` (for readers only) and `in_scope` (default true: the sensor is scoped to the agent's cgroup) | the host records |

| Expected field | Meaning |
|---|---|
| `projection_links[] {attempt_id, links[]}` | The spec 056 links on each effect's step in `fabric.step-projection/v1` (the step-projection `$defs/link` shape): `caused_by` a tool call (A rules) and `corroborated_by` a host event (H1, H2) |
| `sensor_events[]` | The run report's `sensor_events`: every host event a link names, in time order, with the `part_of` links whose subject it is (H3 to the effect's attempt, H4 to the run) |
| `chains` | The run report's `chains` (section 6) |
| `attribution` | The run report's `attribution` (section 6) |
| `trace` | Which rule decided each effect, anchor, host event and tool call. Not a report field; it makes the fixtures readable and pins the rule order |

## 5. The rules as these fixtures pin them

A link target of namespace `call` is a tool call, named by the `p-` v2
pseudonym of its provider id (as `reconstruct` names tool calls everywhere).

**Open window of a tool call** (§4.2): it opens at the end of the issuing
exchange's span and closes at the start of the first later exchange whose
request carries its result, else at the end of the run window. An effect is
a candidate when it is on the same segment and epoch, later in sequence
than the issuing exchange, and starts within the window widened by the
epoch's clock uncertainty on both sides.

| Rule | Decision | Link(s) on the effect step |
|---|---|---|
| A0 | The effect names a reported parent (an explicit `tool_call()` scope or `parent_attempt`) | `caused_by` → `attempt` the parent, provenance `reported`, `certain`, no method. When the parent names its tool call, that call counts as having its effect |
| A1 | The effect's stdout with trailing ASCII whitespace removed, at least 16 UTF-8 bytes, is a substring of exactly one candidate's result text; with digests only on either side, equal SHA-256. A1 applies only when the output **and every candidate's result** are available, and never in `metadata_only` | `caused_by` → `call`, `output_match`, `certain`. Two or more matches: one link per match, each `ambiguous`, `tentative` (an ambiguous link is never certain) and listing them all |
| A2 | Exactly one candidate | `sequence_bracket`, `tentative`, `resolved` |
| A3 | Two or more candidates, A1 not deciding | one link per candidate, `sequence_bracket`, `tentative`, `ambiguous`, each listing every candidate |
| A4 | No candidate | none; listed in `attribution.unattributed_effects` |

An ambiguous decision is several links, one per candidate, each with
`state: ambiguous` and the same `candidates` list. The link shape requires
a `target`; no target is preferred over another.

**Host joins** (§4.3). Two records join only on the same host (`host_id`)
and pid namespace (the source's `pid_namespace` basis). Process start times
are compared at the `/proc` tick, 10 ms (`USER_HZ` = 100): the hook's value
comes from `/proc/<pid>/stat` in ticks, a sensor's in nanoseconds.

| Rule | Decision | Link |
|---|---|---|
| H1 | A successful exec event with the effect's pid and parent pid and a start time in the same tick as `process_start_ns` (both present) | effect `corroborated_by` → `event`, `process_anchor`, `certain`. A later exec of the same process (same pid, parent and start) is lineage at depth 0 |
| H2 | No start time on one side; exactly one such exec event within 100 ms + both clock uncertainties of the effect's start, or several that form one exec chain (below) | `process_anchor`, `tentative`, on the match or the chain's first exec. Two or more that are not one chain: `ambiguous` with all; the effect counts as not anchored (`anchor_missing`) |
| H3 | A host event whose parent-pid chain reaches an anchored child, same host and namespace, times not earlier than its parent's, start times non-decreasing, depth ≤ 16, ≤ 4096 events per anchor; connect and file events of a process in the chain | event `part_of` → `attempt` the effect, `process_lineage`, the anchor's confidence. An event past a bound is not linked, is counted in `attribution.lineage_truncated` and is unexplained |
| H4 | A host event of the agent's own pid inside the run window | event `part_of` → `run`, `process_anchor`; `certain` only when the event carries the agent's start time and it matches, else `tentative`. A connect to a peer no exchange's endpoint resolves to is also unexplained |

**Exec chain** (H2). A shell that execs its command in place (`bash -c
"cmd"`; `dash` for the last command of a list) gives several successful
exec events with the effect's pid and parent pid. In time order, they are
one process when no exit of that pid is observed at or between two
consecutive execs and, where both carry a start time, the two are in one
tick. An exit is observed when an effect on the same host with that pid
has an `exit_observed_ns` (no host sensor reports exits). The later execs
are H3 lineage at depth 0. A chain is never `certain`.

Anchors are decided first (an anchor event is never another effect's
lineage), then lineage, then H4. Any other host event in the agent's scope
inside the run window is **unexplained**.

## 6. Chains and the attribution summary (§4.5)

| Chain | `not_observed` when | `partial` reasons, in order |
|---|---|---|
| `decisions` | never | the exchange verdict's own reasons (`exchange_reasons`) |
| `actions` | no tool call in the run | `tool_result_missing` (a call with no later result, not declared outstanding), `exchange_gap` |
| `effects` | no effect channel `active` (reason `channel_disabled`) | `sequence_gap`, `unattributed_effect`, `ambiguous_attribution` |
| `corroboration` | no host source (reason `not_configured`) | `source_gap`, `anchor_missing`, `unexplained_host_event` |

A chain is `complete` without reasons; `partial` and `unverified` always
name theirs. A `partial` or `unverified` chain bounds the run verdict (the
capture validator enforces it on reports).

| Attribution field | Meaning |
|---|---|
| `links` | Per basis (`reported`, `output_match`, `sequence_bracket`, `process_anchor`, `process_lineage`, `none`), how many decisions were `resolved`, `ambiguous` or `unresolved`: one per effect for the A rules (A4 is `none`/`unresolved`), one per effect with a pid for its anchor (no anchor is `process_anchor`/`unresolved`), one per lineage or H4 event |
| `unattributed_effects` | `{count, effects: [{attempt_uid, event_id}]}`, the first 64 in sequence order |
| `effects_not_observed` | Tool calls with no attributed effect, by reason: `channel_disabled`, `no_effect_channel`, `none_in_window`. Not a gap |
| `output_match` | `{state: applied}` when A1 was evaluated for at least one effect; else `{state: not_applicable, reason: privacy_policy}` (metadata-only) or `not_exposed` |
| `unexplained_host_events` | `{count, event_ids}`, the first 64 in time order |
| `lineage_truncated` | Host events an H3 bound left unlinked (present only when nonzero) |

## 7. Fixture index

| Fixture | Rules | What it pins |
|---|---|---|
| `a0-reported-parent` | A0 | A reported parent wins over the window rules |
| `a1-output-match` | A1 | The output is in the only candidate's result: certain |
| `a2-single-window` | A2 | One window, the agent summarised the output: tentative |
| `a3-several-windows` | A3 | Two parallel calls, outputs under 16 bytes: both ambiguous |
| `a4-no-window` | A4 | An effect before any tool call |
| `edge-parallel-distinct-outputs` | A1 | Two parallel calls, A1 resolves each |
| `edge-parallel-metadata-only` | A3 | The same in metadata-only mode: both ambiguous, `output_match` not applicable |
| `edge-clock-margin-boundary` | A3 | An effect inside the clock margin of two window boundaries is a candidate of both |
| `edge-background-thread` | A1, A4 | A background-thread effect between windows is unattributed |
| `h1-anchor-exact` | A1, H1 | Start times in the same tick: certain anchor |
| `h2-anchor-no-start` | A1, H2 | Today's local records: tentative anchor |
| `h3-lineage` | A1, H1, H3 | `sh -c curl`: the curl start and its connect are part of the effect |
| `h4-agent-process` | H4 | Agent-process events: certain with the agent's start time, else tentative |
| `edge-pid-reuse` | A1, H2 | Two candidates for one pid with an observed exit between them: ambiguous, never certain |
| `edge-exec-in-place` | A1, H2, H3 | `bash -c` execs in place: one exec chain, a tentative anchor on the first exec; the second exec and the file open are lineage |
| `edge-same-pid-other-parent` | A1, H2 | The effect's pid exec'd under another parent pid: not a chain; the other process and its connect are unexplained |
| `edge-lineage-depth-17` | A1, H1, H3 | Depth 17 is truncated and reported |
| `edge-a1-several-matches` | A1 | Two parallel calls fed back the same output: each effect links both, `output_match`, `tentative`, `ambiguous` |
| `edge-lineage-pid-reuse` | A1, H1, H3 | An unrelated exec takes over the anchored pid: it, its connect and its child are not lineage, they are unexplained |
| `edge-agent-uncalled-host` | H4 | The agent connects to a host no exchange called: listed as unexplained |
| `ar1-run` | A1, A4, H1, H3, H4 | AR-1 (§6.2) with spec 053 host records: the §6.2 step table and chain verdicts |
| `ar1-run-local-profile` | A1, A4, H2, H3, H4 | AR-1 with today's local-profile records: every anchor tentative |
| `ar1-negative-a-no-host-source` | A1, A4 | Negative (a): corroboration not observed, other chains unchanged |
| `ar1-negative-b-effect-dropped` | A1, A4, H1, H3, H4 | Negative (b): effects `partial(sequence_gap)`; decisions `partial(sequence_gap)` too (see section 8) |
| `ar1-negative-c-hook-disabled` | H4 | Negative (c): effects not observed, every tool call `channel_disabled` |
| `ar1-negative-d-metadata-only` | A2, A3, A4, H1, H3, H4 | Negative (d): step 3 ambiguous; the single-window steps fall back to A2 |

| Refused fixture | Error code | The mistake |
|---|---|---|
| `a0-reported-link-claims-inferred` | `coverage.action.link` | A reported link relabelled inferred, without a method |
| `a1-output-match-tentative` | `coverage.action.confidence` | A resolved `output_match` is certain (only an ambiguous one is tentative) |
| `a1-several-matches-claims-certain` | `coverage.action.confidence` | An ambiguous `output_match` claims `certain` |
| `a2-single-window-claims-certain` | `coverage.action.confidence` | `sequence_bracket` is always tentative (OD-5) |
| `a3-ambiguous-lists-one-candidate` | `coverage.action.link` | An ambiguous link lists every candidate |
| `a4-unattributed-effect-not-listed` | `coverage.action.chains` | `unattributed_effect` is a reason exactly when the list is not empty |
| `h1-certain-without-start-time` | `coverage.action.confidence` | A certain anchor needs both start times |
| `h2-pid-reuse-picks-one-candidate` | `coverage.action.expected` | Picking one of two pid-reuse candidates (an exit lies between them, so they are not one chain) |
| `h3-lineage-exceeds-anchor-confidence` | `coverage.action.confidence` | Lineage cannot be more certain than its anchor |
| `h3-lineage-past-depth-16` | `coverage.action.expected` | Linking the depth-17 process |
| `h4-agent-event-certain-without-start-time` | `coverage.action.confidence` | An agent-process event without the agent's start time is tentative |

## 8. Decisions these fixtures make where spec 056 is silent or loose

- **Start-time equality is per tick (10 ms).** `/proc` reports ticks; a
  sensor reports nanoseconds. Exact nanosecond equality would never hold.
- **Today's local records cannot give a certain anchor.** They carry no
  process start time, so AR-1 against a local-profile Node (M1) yields H2
  `tentative` anchors, not the `certain` of the §6.2 table, until the
  emitter records start times (`ar1-run-local-profile` pins this).
- **Pid namespaces.** The hook records no pid namespace and local records
  carry none, so a join needs the operator's declaration that the sensor
  reports pids in the agent's namespace (`pid_namespace: declared_same`).
  An eBPF emitter with `hostPID` reports host pids; an agent in a container
  sees container pids, and then nothing joins.
- **A1 needs every candidate's result.** If any candidate's result is
  withheld, A1 does not apply to that effect: a withheld result might also
  match.
- **An ambiguous anchor is not an anchor**: the effect counts towards
  `anchor_missing`.
- **Uncalled peers need an endpoint map.** Wire records name an endpoint
  label, not an address; without `endpoint_peers` every agent-process
  connection is unexplained.
- **AR-1 negative (b) bounds `decisions` too.** The dropped effect record
  held a position of the shared allocator (050 §3.3), on the epoch the
  exchanges use. The verifier cannot prove the lost position was not an
  exchange, so the exchange verdict, and with it `decisions`, is
  `partial(sequence_gap)`. Spec 056 §6.2 names only the `effects` chain.
- **Pid reuse ends a lineage.** A successful exec of a pid in the chain that
  is neither the same process (the same start tick; without both start
  times, the same parent) nor a child of the chain proves the pid now names
  another process. The pid leaves the
  chain, so nothing of that process is linked. So does an observed exit of
  the pid (`exit_observed_ns` of an effect with that pid on the same host).
  A connect or file event
  joins a process of the chain only when its start time, if both carry
  one, is in that process's tick.
- **Window margins.** H1 events and the H4 / unexplained window use the run
  window widened by the agent's and the sensor's clock uncertainty (the
  window is on the agent's clock, the events on the sensor's). An H1 event
  outside it is not an anchor: start ticks are boot-relative, so this is
  the only bound against a record of another boot (no record carries a
  boot id yet).
- **`socket` and `bind`** are connect-class but contact no host, so an
  agent-process event whose `syscall` (an optional normalized field) is one
  of them is never an uncalled-peer event. A `connect` whose peer is
  unknown stays uncalled.
- **AR-1 negative (d)** changes the method of the single-window steps (A1
  cannot apply without content, so they become A2); their targets do not
  change.
- **Sensor events in the report** (053 §6.3's `sensor_events[]`) carry the
  H3 and H4 links, whose subject is a host event, not an agent step.

## Limits

- Clear identity mode: `fabric.execution.host_id` admits only the `hst-`
  form, so a clear host label is dropped and no host join is possible. The
  053 §7 clear-mode alternative for host and sandbox ids is not added here.
- The spec 053 §6.2.3 host keys are checked against a transcription, not
  registry rows; 053 WP4-01 registers them.
- `exec.audit` is not registered for the exec evidence type; its schema
  already holds `api: audit` and `audit_event` (053 §3.2).
