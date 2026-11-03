---
title: Agent action reconstruction — linking model decisions, tool calls, effects and host evidence
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 1
last_updated: 2026-11-03
owner: recorder-engineering
depends_on: ["049", "050", "053"]
related: ["030", "031", "047", "048", "054", "055"]
---

# 056 — Agent action reconstruction

## 0. Summary

Fabric already records what an agent sent to its model and what came back.
This spec makes Fabric answer the next question for one production run:

> **What did the agent actually do, which model decision caused each
> action, and what independent evidence confirms it?**

It does this by linking four chains of evidence that Fabric records
separately today:

| Chain | Question it answers | Source |
|---|---|---|
| **Decisions** | What did the model see and return? | Wire capture of model calls (047, 048), on the P1 run record (050) |
| **Actions** | Which tools did the model ask for, with which arguments, and what result did the agent feed back? | Parsed from the captured model bodies (`reconstruct/_stitch.py`, 050 §3.13) |
| **Effects** | What did the agent's process actually run: commands, their output, their exit status? | The opt-in subprocess hook (053 §5.1) |
| **Corroboration** | What does the operating system independently say happened: process starts, network connections, the commands a script started? | Host sensors (eBPF emitter, auditd receiver; 030, 031, 053 §6) |

The new parts are small. This spec:
1. links an effect to the tool call that caused it, without changing the
   agent (§4.2);
2. links host-sensor events to an effect through the process tree,
   instead of a timing guess (§4.3);
3. reports each chain's completeness separately, and lists anything the
   agent did that no tool call explains (§4.5);
4. defines one acceptance scenario that must pass before Fabric claims any
   of this (§6).

Everything else (the run record, the subprocess hook, production ingress
for host sensors) is already specified in 050 and 053. This spec selects
the parts of 053 that this outcome needs and moves them earlier (§7, owner
decision OD-1).

Fabric stays a passive recorder (AGENTS.md). Nothing in this spec approves,
blocks, delays or modifies what the agent does. Evaluation, guardrails and
enforcement consume this record downstream; they are not part of Fabric.

## 1. Why this is needed

The record is for three uses:
- **Compliance:** an auditor asks what an agent did in production and why.
  The answer has to come from evidence, with every link labelled by how it
  was established.
- **Incident review:** an operator reconstructs a bad run step by step.
- **Learning:** guardrail and evaluation work downstream needs real,
  linked examples of decisions and their effects.

Today (v0.8.0, and the P1 branch) Fabric can show the decision and action
chains for Python agents, but not the effects. An agent's account of a
tool call ("I ran `ls` and got this output") is recorded only as the text
it fed back to the model. Nothing independent confirms that the command ran,
what it really printed, or what else it started. A host sensor can see
process starts, but the only link to the agent is a pid and time window,
which is a guess (053 §6.3, method `pid_time_join`, confidence
`tentative`).

## 2. Terms

| Term | Meaning |
|---|---|
| Run | One logical agent task. 050 §3.6 defines run identity and segments. |
| Source, epoch | One agent process is one source epoch: a 63-bit random id drawn at `install()` (050 §3.2). Every record the process emits carries `(source, epoch, sequence)`. |
| Shared allocator | The single per-process sequence counter used by wire exchanges and every other record (050 §3.3). Record order within an epoch is exact. |
| Exchange | One model HTTP request and its response, captured at the wire. |
| Tool call | A tool request the model returned in a response (`tool_calls[i]`, a `function_call` item or a `tool_use` block), with its id. Its **result** is the matching tool-result item in a later request. |
| Effect | A record of something the agent's process did outside the model call. In this spec: a subprocess start, its arguments, its returned output and its exit status (053 §5.1). |
| Host event | A record from a host sensor: a process start, a network connection or a file open, with pid, parent pid and time (053 §6.2.3). |
| Link | A typed edge in the step projection (`fabric.step-projection/v1`): a type (`caused_by`, `part_of`, `corroborated_by`, ...), a **method** saying how it was established, a **provenance** (`observed`, `reported`, `inferred`) and a **confidence** (`certain`, `tentative`). |
| Chain verdict | `complete`, `partial`, `unverified` or `not_observed`, reported per chain (§4.5). |

## 3. Current state

| Capability | Where | State |
|---|---|---|
| Model exchanges with full bodies, run reconstruction | `fabric/wire/`, `fabric/reconstruct/` | Built (v0.8.0) |
| Tool call ↔ tool result pairing by id | `reconstruct/_stitch.py` (`tool_call_id`, Responses `function_call` / `function_call_output`, Anthropic `tool_use` / `tool_result`) | Built (v0.8.0) |
| Shared allocator, records input, segments, seals, manifests, step projection | `_sequence.py`, `_records.py`, `_segments.py`, `_seal.py`, `_manifest.py`, `reconstruct/_project.py`, `reconstruct/_graph.py` | Built on `feat/p1-integration` (050 waves 0–2 and the WP-50 end-to-end test); not on main; P1-A (050 wave 4) not built |
| Subprocess hook (`exec.subprocess`) | 053 §5.1, `fabric/hooks/_exec.py` | Specified, not built |
| Hooks foundation (`fabric.hooks.install`) | 053 §4, `fabric/hooks/` | Specified, not built |
| Host sensors, local profile | `components/host-emitter`, `receiver/auditreceiver` | Built; records carry pid, parent pid, hashed executable and argv, peer address and port; no source, epoch or sequence |
| Host sensors, production ingress | 053 §6.1, §6.2 | Specified, not built; a production Node refuses host receivers today |
| Host ↔ agent join | 053 §6.3 (`pid_time_join`, tentative) | Specified, not built |
| Effect ↔ tool call link | — | Not specified (this spec, §4.2) |
| Process-tree join | — | Not specified (this spec, §4.3) |
| Remote sandboxes (E2B, Modal, Daytona and similar) | — | Not specified (this spec, §4.4) |

## 4. Design

### 4.1 Rules that apply to every part

- **Passive.** No hook waits, polls, retries, tees a pipe, changes a
  `stdout`/`stderr` disposition or alters a child's environment. 053 §4.1
  (callback discipline) and §4.4 (latency and behaviour gates) apply
  unchanged.
- **Links are never guessed silently.** Every link names its method and
  confidence. A rule that cannot decide reports `ambiguous` with every
  candidate, or `unresolved`. No rule picks the "most likely" candidate.
- **Inferred never upgrades reported.** A host event that matches an
  effect corroborates it; it never turns reported content into observed
  content (053 §6.3).
- **Order comes from the shared allocator.** Within one epoch, record
  order is the sequence order. Wall-clock time is used only to compare
  records across epochs or hosts, and then only with the clock uncertainty
  each source declares (050 §1.3, `install.config`).

**Rejected alternatives**, recorded so they are not re-proposed:

| Alternative | Why rejected |
|---|---|
| Inject `TRACEPARENT` or a Fabric run id into each child's environment | Changes the monitored process's environment; breaks the passivity rule; a child can read and log it |
| `LD_PRELOAD`, `ptrace` or seccomp-notify on children | Changes or delays the child; needs privileges the agent does not have |
| Teeing the child's pipes | Changes I/O timing and can deadlock a caller that reads pipes directly; 053 §5.1 forbids it |
| Matching host events by time window alone | That is the guess this spec replaces |

### 4.2 Effect → tool call attribution (`reconstruct/_attribute.py`, new)

A zero-code agent does not tell Fabric which tool call it is executing.
The rule below derives the link from evidence Fabric already has: the model
exchanges and the effect records sit on one ordered sequence in the same
process.

**Inputs.** For one run segment on one epoch: the exchanges in sequence
order with their parsed tool calls and tool results (050 §3.13), and the
effect records (`exec.subprocess` records, 053 §5.1).

**Open window of a tool call T.** T is issued by exchange `X_i` (its
response contains T). Its result is fed back in the first later exchange
`X_j` whose request contains a result item for T's id. T's open window is:

- **opens** at the end of `X_i`'s response (the exchange span's end time);
- **closes** at the start of `X_j`'s request (the exchange span's start
  time), or at the segment end if no `X_j` was captured.

**Candidates of an effect E.** A tool call T is a candidate for E when all
of these hold:
1. E and `X_i` are in the same run segment and the same epoch;
2. `seq(E) > seq(X_i)`;
3. E's start time ≥ T's window open and < T's window close, with a margin
   equal to the epoch's declared clock uncertainty; an effect inside the
   margin of a boundary is a candidate of both sides;
4. E has no reported parent (A0 below).

**Rules, applied in order.**

| Rule | Condition | Link from E | Method | Provenance | Confidence | State |
|---|---|---|---|---|---|---|
| A0 Reported | E was recorded inside an explicit `decision.tool_call()` scope, or its record names a parent attempt (053 §3, B1 `parent_attempt`) | `caused_by` → that tool call | (inherited) | `reported` | `certain` | `resolved` |
| A1 Output match | E has captured output (053 N34) and exactly one candidate's result contains it: E's decoded stdout, with trailing whitespace removed and at least 16 bytes long, is a contiguous substring of the result text; or, when only digests are available, `sha256(stdout) == sha256(result)` | `caused_by` → that tool call | `output_match` | `inferred` | `certain` | `resolved` |
| A2 Single window | Exactly one candidate | `caused_by` → it | `sequence_bracket` | `inferred` | `tentative` | `resolved` |
| A3 Several windows | Two or more candidates, and A1 does not single one out | `caused_by` → every candidate | `sequence_bracket` | `inferred` | `tentative` | `ambiguous` |
| A4 No window | No candidate | none; E is listed in `attribution.unattributed_effects` | — | — | — | `unresolved` |

Notes:
- A1 needs both contents in the verifier's input. In metadata-only modes,
  or when either side was withheld by PROTECT, A1 does not apply and the
  report says so (`output_match: not_applicable`). It never falls back to a
  weaker match.
- A1 with two or more matching candidates stays `ambiguous`; the matches
  are listed.
- A tool call with no attributed effect is not a gap. It is reported as
  `effect_not_observed` with a reason: `channel_disabled` (the hook was
  off), `no_effect_channel` (a pure in-process tool, which no hook
  observes), or `none_in_window`.
- Parallel tool calls in one response share a window. A1 is what
  separates them. Without output capture they stay `ambiguous`, by design.
- Effects from another thread of the same run fall into the same windows.
  A background effect is attributed only if it lands in a window; this is
  why A2 is `tentative`, never `certain`.

### 4.3 Host event → effect: the process-anchored join (amends 053 §6.3)

The subprocess hook knows the child's pid the moment `Popen` returns, and
the agent's own pid. A host sensor reports every process start with its pid
and parent pid. Matching on both, on the same host and pid namespace, is a
join on the process tree, not on timing.

**New fields on the `exec.subprocess` record** (registry rows in §5):

| Key | Value | How it is obtained |
|---|---|---|
| `fabric.process.pid` | child pid (already 053 N35) | `Popen.pid` |
| `fabric.process.parent_pid` | the agent's pid at spawn | `os.getpid()`; no I/O |
| `fabric.process.start_ns` | the child's start time, boot-relative ns (Linux) | Read once by the **capture worker**, never the caller, from `/proc/<pid>/stat` field 22 × (10⁹ / `SC_CLK_TCK`). Absent when the child has already exited, off Linux, or on any error. Owner decision OD-2. |
| `fabric.execution.host_id` | configured host label, `hst-` v2 (053 C41) | trusted configuration only |

**Join rules** (`reconstruct/_host.py`, extending 053 WP4-10b):

| Rule | Condition | Link | Method | Confidence |
|---|---|---|---|---|
| H1 Anchor, exact | A host `exec` event with the same host, pid namespace, pid, parent pid = the effect's `parent_pid`, and process start time equal to `fabric.process.start_ns` | effect `corroborated_by` → event | `process_anchor` | `certain` |
| H2 Anchor, no start time | As H1 without a start time on either side; the event lies within the bounded window (default 100 ms, 053 §6.3) and is the only match | `corroborated_by` | `process_anchor` | `tentative` |
| H3 Lineage | A host event whose parent-pid chain reaches an anchored child, on the same host, pid namespace and boot, with non-decreasing start times; at most depth 16 and 4096 events per anchor | event `part_of` → the anchored effect | `process_lineage` | the confidence of the anchor |
| H4 Agent process | A host event whose pid is the agent's own pid (registered in the epoch registration, 050 §3.2) | event `part_of` → the run | `process_anchor` | `certain` with start time, else `tentative` |

H3 is what makes a shell script visible: `sh -c "curl …"` is anchored by
H1, and the `curl` process start and its `connect` to the peer are linked
to it by H3.

**Unexplained host events.** A host event in the agent's configured cgroup
scope during the run that no rule links is listed under
`attribution.unexplained_host_events` (count, plus the first 64 events).
H4 events that connect to a host the run's exchanges did not call are
listed there too. These lists are the main compliance signal: the operating
system saw the agent do something the agent's own record does not explain.

**Pid reuse.** Where two host events match one anchor under H2, the state
is `ambiguous` with both. H1 cannot be ambiguous: pid plus start time is
unique per boot.

### 4.4 Sandboxes

Three kinds of sandbox, three answers:

| Sandbox | Example | What this spec provides |
|---|---|---|
| **Child-process sandbox** | `bubblewrap`, `nsjail`, `firejail`, `python -I` runners started by the agent | Fully covered: the sandbox launcher is an `exec.subprocess` effect, attributed by §4.2; everything inside it is linked by H3 lineage. |
| **Local container** | `docker run`, a Kubernetes job or pod | The container's processes are children of the container runtime, not the agent, so H3 does not reach them. The `docker run` effect is attributed by §4.2. Container processes are grouped by `fabric.execution.sandbox_id`, which comes from the operator's configured cgroup → sandbox label map (053 C41). The link from that group to the effect is `tentative` (method `pid_time_join`) in milestone M1. M2 adds a reported container id (OD-4). |
| **Remote sandbox service** | E2B, Modal, Daytona | Not observable by host sensors. Needs the allowlisted non-model HTTP channel (053 §5.4) plus a per-provider dialect that decodes "run this code" and "here is the output". M2, one provider first (OD-3). Until then the manifest reports `not_captured(remote_sandbox)` for runs that call a configured sandbox host. |

### 4.5 Chain verdicts and the attribution summary

`fabric.run-reconstruction/v1` gains two optional objects (§5). The verdict
for each chain is reported separately. The overall run verdict is unchanged
in meaning (050 §3.12), and is never `complete` when any observed chain is
`partial`.

| Chain | `complete` when | `partial` reasons | `not_observed` when |
|---|---|---|---|
| `decisions` | The existing run verdict for exchanges is complete | the existing reasons | never; wire capture is the base |
| `actions` | Every tool call in a captured response has its result in a later captured request, or the run ended normally with it outstanding and declared | `tool_result_missing`, `exchange_gap` | no tool calls in the run |
| `effects` | Every record of every enabled effect channel verifies (positions, seals) and no effect is unattributed | `sequence_gap`, `unattributed_effect`, `ambiguous_attribution` | no effect channel enabled (the manifest says so) |
| `corroboration` | A host source verified for the whole run window, every effect with a known pid is anchored, and no host event is unexplained | `source_gap`, `anchor_missing`, `unexplained_host_event` | no host source configured |

`attribution` object: counts of `resolved`, `ambiguous` and `unresolved`
links by method; `unattributed_effects[]` (event ids, at most 64);
`effects_not_observed` counts by reason; `output_match`
(`applied`, `not_applicable` with reason); `unexplained_host_events`
(count and the first 64 event ids).

### 4.6 Reading a run: the action view

`python -m fabric.reconstruct actions <export>` prints one run as a
timeline a person can read:

```text
run r-3f2a…  decisions: complete  actions: complete  effects: partial(unattributed_effect)  corroboration: complete
  1  model_call   gpt-4.1   → tool_call T1 run_shell
  2    effect     exec sh -c '…' exit 0           ← T1  output_match · certain
  3      host     exec sh (pid 4121)              ← #2  process_anchor · certain
  4      host     exec curl (pid 4122)            ← #3  process_lineage · certain
  5      host     connect 10.0.4.7:443            ← #4  process_lineage · certain
  6  model_call   gpt-4.1   ← result T1
  …
  unattributed effects: 1   (exec uname -a, seq 88: no open tool call)
```

The view is a rendering of the step projection and the report. It adds no
contract. `--json` prints the same rows as JSON for downstream tools.

### 4.7 Privacy

- Command arguments and output follow the PROTECT roles already defined
  (`terminal.argv`, `terminal.stdout`, `terminal.stderr`; 053 §5.1). The
  same redaction, tokenisation and withholding modes apply.
- Environment values are never read. The hook records environment
  variable **names** only, and only from an explicitly passed `env` dict
  (053 §5.1).
- Host events keep the 053 §6.2.5 rules: executable path and argv are
  digests only under an explicit permission, and peer addresses are keyed
  ids in production.
- Output matching (A1) runs inside the verifier, on content the verifier
  was already given. It stores no new content.

## 5. Contract changes

Applied by WP6-01 only.

| File | Change |
|---|---|
| `contracts/coverage/v1/schema/step-projection-v1.schema.json` | Link and field `method` enums gain `sequence_bracket`, `output_match`, `process_anchor`, `process_lineage` |
| `contracts/capture/v1/schema/run-reconstruction-v1.schema.json` | Optional `chains` object (`decisions`, `actions`, `effects`, `corroboration`, each a verdict with reasons) and optional `attribution` object (§4.5) |
| `contracts/coverage/v1/registry/telemetry-keys-v1.json` | Rows for `fabric.process.parent_pid` and `fabric.process.start_ns`, placement `record`, capture point `exec.subprocess`. The 053 rows needed by `exec.subprocess` (053 §7) land here too if 053 WP4-01 has not run. |
| `contracts/coverage/v1/registry/vocabularies-v1.json` | Reason values: `unattributed_effect`, `ambiguous_attribution`, `anchor_missing`, `unexplained_host_event`, `tool_result_missing`; `effect_not_observed` reasons `channel_disabled`, `no_effect_channel`, `none_in_window`; `not_captured` reason `remote_sandbox` |
| `contracts/coverage/v1/fixtures/projection/` | Valid and invalid fixtures for every rule A0–A4 and H1–H4 (§6.1) |

## 6. Qualification

### 6.1 Rule fixtures

One fixture per rule, plus these edge cases, each with its expected
projection and report:
- two parallel tool calls with distinct outputs (A1 resolves both);
- the same two in metadata-only mode (both stay `ambiguous`);
- an effect within the clock margin of a window boundary (candidate of
  both sides);
- a background-thread effect between windows (A4);
- a pid reused within the window (H2 `ambiguous`, never `certain`);
- a lineage chain of depth 17 (truncated at 16, reported);
- a host event from the agent process to a host no exchange called
  (listed as unexplained).

### 6.2 AR-1: the acceptance scenario

AR-1 is the end-to-end test. Fabric does not claim agent action
reconstruction until AR-1 passes in CI on the milestone's profile.

**Setup.**
- A plain Python agent using the OpenAI SDK; no framework.
- A deterministic, OpenAI-compatible fixture model server that returns
  scripted tool calls.
- Wire capture and the `exec.subprocess` hook enabled; content mode
  `retain_original`.
- A host sensor scoped to the agent's cgroup. M1: the eBPF emitter, or
  auditd where eBPF cannot run, against a local-profile Node. M2: the same
  against a production-profile Node.
- A fixture HTTP server standing in for an external host.

**Script (one run).**
1. The model asks for `run_shell("ls /data && sha256sum /data/a.txt")`.
   The agent runs it with `subprocess.run(..., capture_output=True)` and
   returns the output.
2. The model asks for `fetch_url(<fixture host>)`. The agent runs `curl`
   as a subprocess.
3. The model asks for two shell commands in parallel, with different
   outputs.
4. The model asks for `run_python(code)`. The agent runs it in a
   child-process sandbox (`bubblewrap` where available, else `python -I`).
5. A background thread, not a tool, runs `uname -a` while no tool call is
   open.
6. The agent process itself opens a TCP connection to the fixture host
   without any hook.
7. The model returns the final answer.

**Expected result.**

| Step | Expected link | Method · confidence |
|---|---|---|
| 1 | effect `caused_by` T1; host `exec sh` `corroborated_by` | `output_match` · certain; `process_anchor` · certain |
| 2 | effect `caused_by` T2; `curl` start and its `connect` `part_of` the effect | `output_match` or `sequence_bracket`; `process_lineage` |
| 3 | each effect `caused_by` its own call | `output_match` · certain, both |
| 4 | sandbox launcher `caused_by` T4; the Python process inside `part_of` it | `output_match`; `process_lineage` |
| 5 | listed in `unattributed_effects` | A4 |
| 6 | listed in `unexplained_host_events` | H4, uncalled host |

Chain verdicts: `decisions` complete, `actions` complete, `effects`
`partial(unattributed_effect)`, `corroboration`
`partial(unexplained_host_event)`.

**Negative variants**, each a separate CI case:
- (a) host source removed → `corroboration: not_observed`; other chains
  unchanged;
- (b) one effect record dropped from the spool → `effects:
  partial(sequence_gap)`;
- (c) hook disabled → `effects: not_observed`, with the manifest reason;
  every tool call is `effect_not_observed(channel_disabled)`;
- (d) metadata-only content mode → step 3 is `ambiguous`; no other link
  changes;
- (e) the agent run with capture off, then on → identical agent outputs and
  exit codes, and the 053 §4.4 latency budgets hold.

**Privacy canaries.** A secret placed in an environment variable of the
step 1 command, and a bearer token in an HTTP header of the step 2 request,
never appear in clear in any spool file, Node export or report.

## 7. Milestones and work packages

### 7.1 Ordering change (owner decision OD-1)

053 enters after the P2 exit and requires the 051 and 052 contract work
packages first. This spec moves only what it needs earlier:
- the hooks foundation and the `exec.subprocess` channel (053 WP4-00
  subset, WP4-02 without exec audit), and
- host production ingress (053 WP4-07a/b/c, WP4-08a/b, WP4-09),

so that they start after 050 WP-50, without waiting for 051 or 052. Its
contract rows take the next slot after 050 WP-00. When 051 WP2-0 and 052
WP3-0 land later, they rebase onto these rows. The other 053 channels
(file, database, HTTP, MCP, SSH) keep 053's order.

### 7.2 M1: local profile (first build)

Goal: AR-1 passes against a local-profile Node.

| WP | Owner area | Depends | Delivers | Exit |
|---|---|---|---|---|
| **WP6-01 Contracts** | `contracts/**`, `scripts/contracts/**`, contract tests | — | §5 deltas; the 053 §7 rows `exec.subprocess` needs; rule fixtures §6.1 | Contract validators pass; every fixture validates or is refused as expected |
| **WP6-02 Hooks foundation** | `fabric/hooks/__init__.py`, `_config.py`, `_producer.py`, `_patches.py`, `_guard.py`; `fabric/__init__.py` export | 01 | 053 §4: `fabric.hooks.install(exec=…)`, `FABRIC_WIRE_EXEC=1`, `status()`, `disable()`, `close()`, patch ownership, records-input producer; only the `exec` channel is registered | Install, disable, close are idempotent; config error matrix; no hook without a capture handle |
| **WP6-03 Subprocess hook** | `fabric/hooks/_exec.py`, `tests/test_hooks_exec*` | 02 | 053 §5.1 (no exec audit); §4.3 fields, including the worker-side start-time read | 053 §5.1 behaviour tests; passivity: outputs, return codes, exceptions and timing unchanged; fork safety |
| **WP6-04 Attribution and chain verdicts** | `reconstruct/_attribute.py` (new), report writer extension, `reconstruct/__main__.py` (`actions` command) | 01; P1 projection | §4.2, §4.5, §4.6 | Every A-rule fixture gives its expected projection and report |
| **WP6-05 Host reader and process join** | `reconstruct/_host.py` | 01; P1 projection | §4.3 H1–H4 over today's local-profile host records (pid, parent pid, time); start-time joins when the record carries one | Every H-rule fixture; no `certain` link without a start-time match |
| **WP6-06 AR-1 harness** | `qualification/action-record/**` (new), a CI job | 02–05 | §6.2 on a local-profile Node, with every negative variant and the canaries | AR-1 green in CI |
| **WP6-07 Researcher-ready documentation** | `docs/**` (except pages owned above), `specs/README.md`, the front matter and introductions of specs 049–056, `README.md`, `CONTRIBUTING.md` | — | §8 | §8 checklist |

WP6-04, WP6-05 and WP6-07 can run in parallel with WP6-02 and WP6-03.
WP6-06 runs last.

### 7.3 M2: production profile

| WP | Delivers |
|---|---|
| 053 WP4-07a/b/c | Host-records library; auditd and eBPF production mode (source, epoch, sequence, persisted ids, encrypted state); eBPF records gain `process_start_ns` and `cgroup_id` |
| 053 WP4-08a/b | Gate rules and fabricguard admission for host groups |
| 053 WP4-09 | Chart and Compose wiring for dedicated host ingress groups |
| WP6-08 Container sandboxes | Reported container id → sandbox group link (OD-4) |
| WP6-09 First remote sandbox dialect | 053 §5.4 HTTP channel plus one provider dialect (OD-3) |
| WP6-10 AR-1 production | §6.2 against a production-profile Node |

## 8. Documentation for outside readers

The repository is being shared with an outside researcher. WP6-07 makes it
readable without the team's history:
1. `docs/README.md` opens with a one-page map: what Fabric is, the four
   chains, where each piece of code lives, and which pages to read first.
2. A glossary (`docs/glossary.md`) defining every term a spec uses without
   explanation: epoch, segment, seal, manifest, records input, D2,
   capture point, field ids (X/C/S/N/D rows), coverage statuses, verdicts.
3. `specs/README.md` lists every spec with a one-line plain description
   and a status a reader can trust (`draft`, `accepted`, `implemented`,
   `superseded`), and says which specs describe built code.
4. Specs 049–056 lose internal process notes in their front matter and
   introductions: reviewer names, session decision codes and revision
   histories that refer to private discussions. The technical content and
   the decision records (OD tables) stay.
5. No private material: no customer names, business plans, private
   repository paths or SingleAxis platform internals (AGENTS.md).
6. Every page states whether it describes built code, and links the
   module that implements it.

## 9. Owner decisions

| Id | Decision | Recommendation |
|---|---|---|
| OD-1 | Move the 053 `exec.subprocess` channel and host production ingress ahead of 051/052 (§7.1) | Yes |
| OD-2 | Let the capture worker read `/proc/<pid>/stat` for the child start time | Yes. It runs off the caller's path, is Linux-only and bounded, and fails silently. It is what makes H1 exact. |
| OD-3 | First remote sandbox provider for WP6-09 | The provider the first customer uses |
| OD-4 | Container sandboxes: record the container id the runtime returns (`docker run` output, or the Kubernetes API) as a reported link | Decide in M2 |
| OD-5 | A2 (single window) confidence: `tentative` or `certain` | `tentative`; only A0 and A1 are `certain` |
| OD-6 | AR-1 host sensor in hosted CI | Try eBPF on the hosted runner first; if it cannot load, run the host part on a self-hosted runner and keep the rest in hosted CI |
