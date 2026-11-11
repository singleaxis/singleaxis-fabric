---
title: Agent action reconstruction — linking model decisions, tool calls, effects and host evidence
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 12
last_updated: 2026-11-11
owner: recorder-engineering
depends_on: ["049", "050", "053"]
related: ["030", "031", "047", "048", "054", "055", "057", "058"]
---

# 056 — Agent action reconstruction

> **Revision 12** (2026-11-11, field harness): effects are linked to tool
> calls by exact content match and by execution context, not by timing
> alone (§4.2.1 to §4.2.3). The harness found that 41% of the links from
> an effect to its tool call are `ambiguous`: two tool calls were open at
> once and rule A3 lists both. Three exact tests now narrow the
> candidates of an open window: the effect's command appears in a call's
> recorded arguments (`command_match`), the effect's file path appears in
> them (`path_match`), and the effect ran on the thread or asyncio task
> that made the call's model request (`execution_context`). A1's output
> test stays as it is. A test either holds or does not: there is no score,
> no ranking, no model call, and no normalisation of either side. Every
> link names the tests that held (`match`), and **every inferred link from
> an effect to a tool call is `tentative`**, including A1, which revision
> 11 marked `certain`; only a reported link (A0) is `certain` (this
> replaces OD-5; question OQ12-1). The in-process audit records of spec
> 053 revision 5 (`exec.audit`, `file.audit`) become effects (§4.2.3).
> Hook records and model exchanges carry two small integers naming the
> thread and task that produced them (§4.2.2). §6.3 defines how the 41%
> figure is measured again. §7.4 lists the six build units and the files
> each owns in `fabric/reconstruct/`, where spec 057 P1 and P2 are also
> landing. §10 lists the open questions, each with a recommendation.
>
> **Revision 11** (2026-11-09, integration audit F10/N8): an effect the
> agent process runs before its first model call of the run is a **startup
> effect** (rule S0, §4.2), reported in `attribution.startup_effects`
> (counted, the first 64 listed), never attributed to a call, not counted in
> `links`, and not a reason of the `effects` chain, so it does not make the
> run `partial`. The case: an OpenAI-style client library runs `uname -p`
> at import to describe the platform, so with `FABRIC_WIRE_EXEC=1` every
> run read `partial(unattributed_effect)` although nothing the model asked
> for went unexplained. The decision is mechanical, not a guess about
> intent: S0 applies only when (1) the effect has no reported parent (A0,
> or an explicit tool-call scope), (2) the run has a captured exchange on
> the effect's own epoch (one process, one exact sequence order) and the
> effect's sequence is lower than every such exchange's, and (3) no
> unverified position (`effect_sequence_gaps`) lies below the effect,
> because a lost position could have been a model call. Anything else is
> decided by A1-A4 exactly as before: an effect after the first call with
> no open window is still A4 and `partial(unattributed_effect)`, and a
> process with no model call on the effect's epoch (a tool worker, rev 6)
> has no first call, so its effects stay A4. A startup effect keeps its
> host anchors (§4.3). Fixtures `edge-startup-effect` and
> `edge-startup-after-gap` pin it; `a4-no-window` now places its effect
> after a model call that opened no window, so it still pins A4.
>
> **Revision 10** (2026-11-08, after the 0.12.0 acceptance N2): a host
> event's clock margin is the clock uncertainty of the manifest in force for
> its record, not the widest value its source's manifests declare. 049 §2.4
> defines which manifest that is: manifest `k` of a source epoch governs
> sequences `after_source_sequence(k) + 1` up to the next manifest's
> `after_source_sequence`, and a host record carries its source position
> (`fabric.source.epoch`, `fabric.source.sequence`). Before, one clock step
> widened every host link of a long export (to 67.5 ms in the acceptance
> run); now only the records the widened manifest governs take it. The
> source's widest value is still used where the governing manifest is not
> known: a record without a position, an epoch with no known manifest, a
> record no known manifest precedes, a missing next manifest that a later
> manifest or a heartbeat's `fabric.capture.manifest_seq` proves exists (049
> §2.4 rule 4), two differing copies of one manifest, decreasing positions,
> or an unreadable clock. Coverage checks (heartbeats, position gaps, §4.5
> `source_gap`) keep the widest value. Fixture `edge-clock-per-manifest`
> pins it (§6.1, README §9.1).
>
> **Revision 9** (2026-11-07, v0.11.2 follow-up): a host event whose process
> started in an earlier tick than the agent is neither the agent nor its
> descendant, so it lies outside the run (§4.3 "Agent identity", trace
> `H4-earlier-process`). Before, the previous container's descendant whose
> exec the sensor stamped before its parent's escaped the walk and was listed
> as the next run's unexplained activity. A host event that H4 links to more
> than one run is `ambiguous` in each, never given to one silently (§4.3
> "One event, several runs").
>
> **Revision 8** (2026-11-07, v0.11.2): one epoch is one process on one
> clock, so §4.2 condition 3 no longer widens a window boundary set by an
> exchange of the effect's own epoch; the declared clock uncertainty still
> widens a close set by another epoch's exchange or the segment end, and
> every host-event comparison (two clocks). Before, the default 1 s margin
> made an effect that started after its call visibly closed ambiguous
> (0.11.1 acceptance B4). The `actions` view also renders unexplained host events no
> link names as rows (§4.6), and an unsupported `FABRIC_WIRE_REMOTE_SANDBOX`
> provider disables only `remote.sandbox` (§7.3.3).
>
> **Revision 7** (2026-11-06, v0.11.2): H4 checks the agent's process
> identity, not only its pids. The kernel reuses a freed pid namespace's
> number, so back-to-back containers report the same `pid_ns` and `ns_pid`;
> an event whose identity contradicts the agent's is another process,
> outside the run, and so are its descendants (§4.3 "Agent identity"). A host event no run lists or
> counts is listed once at report level, with its reason, never dropped
> (§4.3 "Host events in no run").
>
> **Revision 6** (2026-11-05, v0.11.1): a process that made no model call (a
> tool worker, or one killed before its first call) is a run of its own,
> never dropped. Its effects are listed, all unattributed, and its
> `decisions` chain is `not_observed` when its epoch verifies, or keeps its
> gap verdict (a lost position may have been a model call). The `decisions`
> chain is `not_observed` only for a run with no captured exchange (§4.5).
>
> **Revision 5** (2026-11-04): review of the M2 plan. Agent scope is a set
> of cgroup roots, static or the pods of a label selector on the sensor's
> node, so an agent in a pod can be scoped (§4.3, OD-12). A Kubernetes
> cluster has one host group per node, provisioned per node (§7.3.3 (n)).
> H5 matches a created id on any host source, so a pod scheduled on another
> node is still linked. The pid-namespace mode is chosen per source, and
> `ns_ppid` is the parent's thread-group id. The host-records API stages
> every marker. The id key file format is fixed. Build files the library
> touches have owners. Each pending owner decision has a fallback. 053 is
> amended to revision 4.
>
> **Revision 4** (2026-11-04): milestone M2 (production profile) becomes a
> build plan (§7.3). OD-3 is decided (E2B, observed at its Python SDK's
> command and code API, because that SDK no longer sends through httpx) and
> OD-4 is decided (yes: the container or pod id the runtime prints, rule H5).
> Production host records report pids in two namespaces, so H1 works for an
> agent in a pod and H3 still crosses a nested sandbox (§4.3). New owner
> decisions OD-8 to OD-11 (§9). 053 is amended only where M2 needs it: the
> §6.2.3 host record, the §6.2.9 emitter configuration and the WP4-07a
> module path (053 revision 3).
>
> **Revision 3** (2026-11-04): H2 reads a same-pid, same-parent re-exec as
> one exec chain (§4.3, owner decision OD-7).

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
| Shared allocator, records input, segments, seals, manifests, step projection | `_sequence.py`, `_records.py`, `_segments.py`, `_seal.py`, `_manifest.py`, `reconstruct/_project.py`, `reconstruct/_graph.py` | Built, released in v0.10.0 (050 waves 0–2 except WP-15 and WP-21, and the WP-50 end-to-end test); P1-A (050 wave 4) not built |
| Subprocess hook (`exec.subprocess`) | 053 §5.1, `fabric/hooks/_exec.py` | Specified, not built |
| Hooks foundation (`fabric.hooks.install`) | 053 §4, `fabric/hooks/` | Specified, not built |
| Host sensors, local profile | `components/host-emitter`, `receiver/auditreceiver` | Built; records carry pid, parent pid, hashed executable and argv, peer address and port; no source, epoch or sequence |
| Host sensors, production ingress | 053 §6.1, §6.2 | Specified, not built; a production Node refuses host receivers today |
| Host ↔ agent join | 053 §6.3 (`pid_time_join`, tentative) | Specified, not built |
| Effect ↔ tool call link | — | Not specified (this spec, §4.2) |
| Process-tree join | — | Not specified (this spec, §4.3) |
| Remote sandboxes (E2B, Modal, Daytona and similar) | — | Not specified (this spec, §4.4) |

The table is the state this spec started from. Milestone M1 (WP6-01 to
WP6-07) is built and released in v0.10.0: the hooks foundation, the
`exec.subprocess` hook, the effect ↔ tool call link (§4.2) and the
process-tree join for local-profile host records (§4.3). AR-1 (§6.2) passes
in CI in hermetic mode and in live mode (Linux, eBPF). Milestone M2 (§7.3,
the production profile) is built and released in v0.11.0: AR-1 production
passes in CI (`production-replay` on macOS and Linux, `production-live` and
`production-auditd` on Linux), which was this spec's condition for
changing the status.

What M2 starts from, checked against the v0.10.0 code:

| Piece | State at v0.10.0 | M2 work |
|---|---|---|
| Host records in the 053 §6.2.3 shape | Read by `reconstruct/_host.py` (`normalize_sensor_span`, `host_evidence_from_spans`, `source_verified`); emitted by no sensor; not in the registry; the verifier's main path (`_inputs.py`) does not set them apart from agent records | 053 WP4-07a/b/c emit them; WP6-11 registers them; WP6-12 reads them from a Node export |
| eBPF process start time | Not captured: `struct event` in `components/host-emitter/bpf/emit.bpf.c` has no start time; pids are init-namespace tgids | WP4-07c (§4.3 "Production host records") |
| Production Node with host groups | Refused: `gate/gate.go` `checkDedicatedEvidenceIngress` requires one processor named `fabricguard` and one OTLP receiver | WP4-08a, WP4-08b, WP4-09 |
| `fabric.process.start_ns` coverage | Read by the capture worker only (`hooks/_exec.py` `read_start_ns`), dropped for an exited or zombie child; a short command is often reaped first | WP6-08 (OD-8) |
| Container link | Not built (the M1 text in §4.4 named a `pid_time_join` link; no code produced it) | WP6-08, WP6-12 (rule H5) |
| `http.nonmodel` channel, route table | Not built (`wire/_routes.py` does not exist; `hooks/_config.py` lists `FABRIC_WIRE_HTTP_HOSTS` as not in this build) | WP6-09a |
| Remote sandbox | Not built | WP6-09b |

[Agent action reconstruction](../docs/action-reconstruction.md) describes
what is built.

What revision 12 starts from, checked against main at `de693caa`
(2026-11-11). Paths are under `sdk/python/src/fabric/`:

| Piece | State on main | Revision 12 work |
|---|---|---|
| Rules A0 to A4 and S0 | Built: `reconstruct/_attribute.py:391-423` (`attribute_effect`), `:365-388` (`startup_effects`), `:279-297` (`candidates`) | A1 becomes the set rule of §4.2.1; A2 to A4 and S0 unchanged |
| A1 output match | Built: `reconstruct/_attribute.py:300-327` (`output_matches`), `:108` (`MIN_MATCH_BYTES = 16`); a single match is `certain` (`:411`) | Unchanged test; the link becomes `tentative` (OQ12-1) |
| Tool call in the rules' input | `{id, name}` only: `reconstruct/_attribute.py:1276-1313` (`_tool_io`) reads names from `_stitch.py`'s `extract_stitch_keys` and result texts from `tool_result_texts` (`:741`). **The arguments are not read** | `_stitch.py` returns each call's arguments; the input gains `argument_leaves` (§4.2.1) |
| Effect in the rules' input | Identity, process keys, `stdout` (`:1323-1379`, `:1429-1442`). The argv body is read only to print a label (`:785` `argv_label`, `:1381-1391`) and only when runs are kept. **No command or path for matching** | The input gains `command`, `path`, `target_path` (§4.2.1) |
| Effect capture points | `exec.subprocess` and `remote.sandbox` (`reconstruct/_attribute.py:113`) | `exec.audit` and `file.audit` join them (§4.2.3) |
| Thread or task of a record | **Not recorded.** No key names it; `_records.py` and the wire transport stamp neither | §4.2.2 |
| Link shape | `type`, `target`, `provenance`, `method`, `confidence`, `state`, `candidates` (`contracts/coverage/v1/schema/step-projection-v1.schema.json`, `$defs/link`; the method list is closed) | Three methods and an optional closed `match` list (§5.2) |
| Attribution summary | `attribution.links` counts by basis; `attribution.output_match` says `applied` or `not_applicable` (`contracts/capture/v1/schema/run-reconstruction-v1.schema.json:592-611`) | `attribution.content_match` per test (§4.5) |
| Rule fixtures | 55 files under `contracts/coverage/v1/fixtures/action-record/rules/`; 123 files in the repository name `output_match` | New fixtures (§6.1); the `certain` to `tentative` change is regenerated by `scripts/contracts/action_record.py` |
| Spec 057 in `reconstruct/` | #293 (P1a) and #295 (P2a), both in review, edit `_attribute.py`, `_security.py`, `__main__.py`; P1a adds `_derive.py` and `dialects/`; P2a makes A2 skip declared hook programs | §7.4 keeps this spec's rules in a new file and names the few lines it changes in theirs |

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
  each source declares (050 §1.3, `install.config`); for a host record,
  the uncertainty its governing manifest declares (revision 10).

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
3. E's start time ≥ T's window open and < T's window close. The open is
   `X_i`'s end on E's own epoch and clock, so it takes no margin; the close
   takes a margin equal to the epoch's declared clock uncertainty only when
   `X_j` is on another epoch or the window ends at the segment end (an
   effect inside that margin is a candidate of both sides). Revision 8:
   records of one epoch share one clock and their order is exact;
4. E has no reported parent (A0 below).

**Rules, applied in order.**

| Rule | Condition | Link from E | Method | Provenance | Confidence | State |
|---|---|---|---|---|---|---|
| A0 Reported | E was recorded inside an explicit `decision.tool_call()` scope, or its record names a parent attempt (053 §3, B1 `parent_attempt`) | `caused_by` → that tool call | (inherited) | `reported` | `certain` | `resolved` |
| A1 Output match (revision 12: one of the four tests of §4.2.1, and `tentative`) | E has captured output (053 N34) and exactly one candidate's result contains it: E's decoded stdout, with trailing whitespace removed and at least 16 bytes long, is a contiguous substring of the result text; or, when only digests are available, `sha256(stdout) == sha256(result)` | `caused_by` → that tool call | `output_match` | `inferred` | `certain` | `resolved` |
| A2 Single window | Exactly one candidate | `caused_by` → it | `sequence_bracket` | `inferred` | `tentative` | `resolved` |
| A3 Several windows | Two or more candidates, and A1 does not single one out | `caused_by` → every candidate | `sequence_bracket` | `inferred` | `tentative` | `ambiguous` |
| A4 No window | No candidate | none; E is listed in `attribution.unattributed_effects` | — | — | — | `unresolved` |

**Startup effects (rule S0, revision 11).** Before A1-A4 (after A0), an
effect E is a startup effect when E has no reported parent, the run has a
captured exchange on E's epoch, `seq(E)` is lower than the sequence of
every such exchange, and no unverified position lies below `seq(E)`. S0
makes no link. E is listed in `attribution.startup_effects`, is not
counted in `links` and is not a reason of any chain. It is the work a
process does before it first asks the model anything (an SDK's platform
probe at import); because it comes before every model call, no call can
have caused it.

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

#### 4.2.1 Content and context match (revision 12)

**The problem.** A3 lists every open tool call when two or more are open:
parallel tool calls in one response, or two sessions in one process. The
record usually already says which call it was. The model wrote the
command or the file path into the call's arguments, the agent ran exactly
that, and Fabric recorded both sides. This section turns that into four
exact tests. It adds no judgement about the agent and produces no score:
it is the same kind of statement as A1, "these recorded bytes equal those
recorded bytes".

**Inputs added to the rules' normalized input.** All are read by the
verifier from records and bodies it has already verified.

| Item | Field | What it is |
|---|---|---|
| Tool call | `argument_leaves` | The string values of the call's arguments. The arguments are parsed as JSON (a JSON string for OpenAI-style calls, an object for Anthropic-style `input`). Every string **value** is a leaf, in document order, at any depth up to 16; keys, numbers, booleans and nulls are not leaves. Arguments that are not valid JSON give one leaf, the raw text. More than 256 leaves, a leaf over 1 MiB or a depth over 16 gives no leaves and the reason `payload_too_large`. A truncated or withheld response body gives no leaves and the reason `withheld` |
| Tool call | `result.text` | As A1 uses it today (unchanged) |
| Effect at `exec.subprocess` or `exec.audit` | `command` | From its `terminal.argv` body: `{form: shell, text}`, or `{form: argv, args}` where each element is the `str` cell's value, or absent for a `b64` or `not_exposed` cell |
| Effect at `remote.sandbox` | `command` | From its `remote.request` body: `{form: shell, text}` with the `command` or `code` cell's value |
| Effect at `file.audit` | `path`, `target_path` | From its `artifact.locator` body: the `str` cell's value; a `b64` cell's bytes when they are valid UTF-8; otherwise absent |
| Effect, exchange | `thread_ref`, `task_ref` | §4.2.2 |

**Strings are compared as recorded.** Both sides are sequences of Unicode
code points decoded from the verified bytes. Nothing is trimmed, case
folded, re-quoted, split by a shell lexer, path-normalised or Unicode
normalised. "Contains" means a contiguous run of equal code points. A
length is counted in UTF-8 bytes. The one length floor is A1's:
`MIN_MATCH_BYTES` = 16.

**The four tests.** For an effect E and a candidate tool call T of E's
open window (§4.2 conditions 1 to 4), each test holds or does not hold.

| Test (link `method`) | Applies to | Holds when any of these is true | `match` entry |
|---|---|---|---|
| `output_match` | effects with captured output | A1's test, unchanged: E's output with trailing ASCII whitespace removed, at least 16 bytes, is contained in T's result text; or the digests are equal when only digests exist | `output` / `result` / `contains` or `digest_equal` |
| `command_match` | effects with a `command` | (a) the whole command equals a leaf of T: the `text` of a shell form, or the `args` of an argv form joined by single spaces when every element is present (any length of 1 byte or more) | `command` / `arguments` / `equal` |
| | | (b) an argv element of at least 16 bytes equals a leaf of T | `argv_element` / `arguments` / `equal` |
| | | (c) a leaf of T of at least 16 bytes is contained in the shell text or in one argv element (the agent wrapped what the model wrote: `cd dir && <command>`, `bash -lc <command>`) | `command` or `argv_element` / `arguments` / `contains` |
| | | (d) the shell text or an argv element, at least 16 bytes, is contained in a leaf of T (the agent ran one line of a longer script) | `command` or `argv_element` / `arguments` / `contained` |
| | | (e) the shell text, at least 16 bytes, is contained in T's result text | `command` / `result` / `contains` |
| `path_match` | effects with a `path` (and, for a rename, a `target_path`; each is tested) | (a) the path equals a leaf of T (1 byte or more) | `path` or `target_path` / `arguments` / `equal` |
| | | (b) one of the two strings ends with `/` or `\` followed by the whole of the other, and the other does not start with `/` or `\` (the model named `src/a.py`, the agent opened `/work/s1/src/a.py`; both separators are accepted so the result does not depend on the verifier's platform) | `path` or `target_path` / `arguments` / `path_suffix` |
| | | (c) the path, at least 16 bytes, is contained in T's result text | `path` or `target_path` / `result` / `contains` |
| `execution_context` | effects and exchanges that carry the tags of §4.2.2 | E's `(thread_ref, task_ref)` equals that of the exchange that issued T, or of the exchange that fed T's result back | `context` / `issuing_exchange` or `result_exchange` / `equal` |

When several lines of one test are true, the `match` entry is the first
true line in the table's order. This only names what is reported; a test
holds as soon as one line is true.

**When a test applies.** A test is evaluated for E only when both sides
are in the verifier's input for **every** candidate of E's window. This is
A1's rule ("it never falls back to a weaker match"), kept for each test:
- `output_match`: as today.
- `command_match` and `path_match`: E's command or path is present, and
  every candidate has leaves (an empty list counts: the arguments were
  read and hold no string). The lines that read the result text, (e) and
  path (c), are evaluated only when every candidate also has its result
  text; otherwise only the argument lines are. In metadata-only mode, or when the
  `terminal.argv`, `artifact.locator` or response body was withheld,
  truncated or over a bound, the test does not apply and the report gives
  the reason (§4.5 `content_match`).
- `execution_context`: E has a `thread_ref`, and the issuing exchange of
  every candidate has one. It needs no content, so it applies in
  metadata-only mode.

**The rule.** It replaces A1 in the order A0, S0, A1, A2, A3, A4. Let W be
E's window candidates (not empty; an empty W is A4 as before). For each
test that applies, let its match set be the candidates it holds for. Call
a test **holding** when its match set is not empty.

| Case | Decision | Links | Trace `rule` |
|---|---|---|---|
| No test is holding | A2 or A3, unchanged (`sequence_bracket`) | as today | `A2`, `A3` |
| The intersection of all holding match sets is one call | `resolved` | one `caused_by` link to it | `A1` |
| The intersection holds two or more calls | `ambiguous` among them only | one link per call in the intersection, each listing them as `candidates` | `A1-ambiguous` |
| The intersection is empty (two tests point at different calls) | `ambiguous` among the union of the holding match sets | one link per call in the union | `A1-conflict` |

Every such link has provenance `inferred`, confidence **`tentative`**, and:
- `method`: the first holding test that matched this link's target, in
  the fixed order `output_match`, `command_match`, `path_match`,
  `execution_context`. The order only chooses the label; it gives no test
  more weight in the decision.
- `match`: one entry per holding test that matched this target, in the
  same order: `{basis, effect_part, call_part, relation}`, closed
  enumerations only (§5.2). It never holds a string from either side.

A contradiction is never resolved by preferring one test. `A1-conflict`
keeps every call a test pointed at, and counts in
`attribution.content_match.conflicts`.

**Certainty (replaces OD-5).** A link from an effect to a tool call is
`certain` only when it was reported (A0). Every inferred one is
`tentative`: A1 in all its cases, A2 and A3. Revision 11 marked a single
`output_match` `certain`. That overstated it. An agent that cuts a tool
result to a length limit drops the true call's match, and another open
call whose result happens to contain the output then becomes the only
match; the harness agents cut their results exactly this way. A reader
tells a content match from a timing bracket by `method` and `match`, not
by confidence. Host links (§4.3) and spec 057's joins keep their own
grades; this paragraph is about effect-to-tool-call links only.

**What this is not.** No similarity measure, no longest common substring,
no token overlap, no edit distance, no weighting of tests, no "most
likely" choice, no model call, no learned or tuned threshold, no name
lists. Tests are fixed in this spec and in the reference rules
(`scripts/contracts/action_reference.py`); adding one is a spec revision
with fixtures. The output is a link in the run's own record that says how
it was established. It does not group, score or rank runs, findings or
agents, which is the Decision Graph work `AGENTS.md` keeps out of this
repository.

**Declared limits.** A command the agent rewrote before running it (a
template, an added flag, different quoting) may match nothing: the effect
falls through to A2 or A3 exactly as today. Two parallel calls with the
same arguments stay `ambiguous`; nothing in the record tells them apart.
A short relative path that equals an unrelated argument value can make
`path_match` hold for a second call; the result is then `ambiguous`,
never a wrong `resolved` link, unless that second call is the only match,
which is why the link is `tentative`. `pip install <name>` with a short
name matches by (a) only when the model wrote the whole command.

**Interaction with spec 057.** A process that 057 P2a classifies as a
declared hook program is not an effect of a tool call (057 finding F2):
the rule above is not applied to it, exactly as A2 skips it. 057's own
joins (`provider_id`, `pending_single`, the MCP `tools/call` join) are
unchanged. Non-model HTTP and MCP records are not effects in this spec and
get no content match here (OQ12-5).

#### 4.2.2 Execution context tags (revision 12)

A tag says which thread and which asyncio task of the agent process
produced a record. It is the one piece of evidence that separates two
sessions running at once in one process when their commands look alike.

| Key | Value | Minted |
|---|---|---|
| `fabric.execution.thread_ref` | integer 1 to 2147483647 | The first time Fabric records anything on a thread, it takes the next number of a per-process counter and keeps it in a Fabric-owned `threading.local`. A number is never reused within a source epoch, unlike `threading.get_ident()` |
| `fabric.execution.task_ref` | integer 1 to 2147483647; absent when no asyncio task is running | The first time Fabric sees a task, it takes the next number of a second counter and keeps it in a `weakref.WeakKeyDictionary` keyed by the task. The task object is never written to. A task type that cannot be weakly referenced gets no tag |

Rules:
- **Where they are stamped.** On every record of an observed hook attempt
  (`exec.subprocess`, `exec.audit`, `file.audit`, `http.nonmodel`,
  `remote.sandbox`, and `mcp.client` when 057 P1b's hook is present),
  read once when the attempt begins; and on every model exchange span of
  the Python wire capture points, read when the request is handed to the
  transport. One helper, `fabric/_exec_context.py`, is the only reader.
- **Passive.** The helper reads a thread-local and one dictionary. It
  never imports `asyncio` (it looks in `sys.modules`), never creates a
  task or a loop, never sets a context variable in the application's
  context, never names a thread or task, and never raises: any failure
  gives no tag. Budget: at most 1 µs median added to an attempt's `begin`
  and to a wire request, inside the existing budgets (053 §4.4; the wire
  passivity suite).
- **Privacy.** Two small integers. A thread's or task's name can carry
  application text and is never read.
- **Fork.** The child clears both maps and restarts both counters; it has
  its own epoch, so numbers of different epochs are never compared.
- **Other runtimes.** TypeScript records carry no tag (spec 055 is
  unaffected; `execution_context` simply does not apply to them).
- **Meaning.** Equal tags mean "the same thread, and the same task or no
  task". A tool the agent runs in a worker thread or a new task has a tag
  that equals no exchange's; `execution_context` then holds for no
  candidate and changes nothing.

#### 4.2.3 In-process file and audit effects (revision 12)

Spec 053 revision 5 adds two capture points whose records are effects:

| Capture point | Effect | Tests that can apply |
|---|---|---|
| `exec.audit` | A command the process started through `os.system`, `os.posix_spawn`, `os.exec*`, or `subprocess.Popen` with the subprocess hook off. No pid, output or exit status | `command_match`, `execution_context` |
| `file.audit` | A file operation the process made: a write-intent open, a rename, a delete, a truncate, a directory create or remove | `path_match`, `execution_context` |

- They enter §4.2 exactly as `exec.subprocess` effects do: windows, A0,
  S0, the rule of §4.2.1, A2 to A4, and the `effects` chain.
- **Startup.** Files a process writes before its first model call (a log
  file, a cache) are S0 startup effects: listed, not attributed, not a
  gap.
- **Unattributed file operations** (A4: after the first model call, with
  no tool call open) are listed in `attribution.unattributed_effects` like
  any effect. Their chain reason is the new `unattributed_file_effect`,
  not `unattributed_effect`, so a reader can tell "the process wrote a
  file no tool call explains" from "the process ran a command no tool call
  explains" (OQ12-3).
- **A tool call with no effect.** With `file.audit` on, an in-process file
  tool has an effect. `effects_not_observed.no_effect_channel` is then
  counted only for calls with no effect while no file channel is active.
- **No pid, no anchor.** Neither kind has a child pid, so neither counts
  for or against the `corroboration` chain, as a remote effect does not.
  No new host join is added: joining a host `open` event to a `file.audit`
  record would need the path on the host side, which production sensors
  carry only as a permitted digest (053 §6.2.5).
- **Action view.** `effect file open(w) src/app.py ← T2 path_match ·
  tentative`; `effect file rename a.tmp → a.json`; `effect exec(audit)
  git commit -q -m …`. The label is cut at 48 characters as today and is
  shown only where the verifier was given the locator or argv body.

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
| H2 Anchor, no start time | As H1 without a start time on either side; the event lies within the bounded window (default 100 ms, 053 §6.3) and is the only match, or every match is one exec chain (below) | `corroborated_by` the match, or the chain's first exec | `process_anchor` | `tentative` |
| H3 Lineage | A host event whose parent-pid chain reaches an anchored child, on the same host, pid namespace and boot, with non-decreasing start times; at most depth 16 and 4096 events per anchor | event `part_of` → the anchored effect | `process_lineage` | the confidence of the anchor |
| H4 Agent process | A host event whose pid is the agent's own pid (registered in the epoch registration, 050 §3.2) and whose identity does not contradict the agent's (below) | event `part_of` → the run | `process_anchor` | `certain` with start time, else `tentative` |

H3 is what makes a shell script visible: `sh -c "curl …"` is anchored by
H1, and the `curl` process start and its `connect` to the peer are linked
to it by H3.

**Unexplained host events.** A host event in the agent's configured cgroup
scope during the run that no rule links is listed under
`attribution.unexplained_host_events` (count, plus the first 64 events).
H4 events that connect to a host the run's exchanges did not call are
listed there too. These lists are the main compliance signal: the operating
system saw the agent do something the agent's own record does not explain.

**Host events in no run.** Captured host activity is never dropped
silently. A host event of a host source that no run lists (linked, or
unexplained) or counts (`sandbox_events_unlinked`) is listed once in the
report's top-level `unattributed_host_events` (count, count per reason,
plus the first 64 events in time order), with its reason: `other_process`
(inside a run's window with the agent's pids but another process, or a
descendant of one: "Agent identity" below), `out_of_scope` (inside a run's window, outside the
agent's scope) or `no_run` (inside no run's window, both clock margins
applied; every event when no run was reconstructed). It is computed over
every run, so a report limited to some runs (`--run`) omits it, and it
bounds no run verdict: the events belong to no run. The `actions` view
ends with their count per reason and lists every one with `--json`.

**One event, several runs (revision 9).** Each run joins its host events
alone. When the agents' identities are not proven (no known start, no
`certain` anchor), H4's pid comparison can link one process to more than
one run: back-to-back containers report the same `pid_ns` and `ns_pid`,
and their windows overlap by the clock margins. Once every run is joined,
no rule picks one of them: in each run the `part_of` run link becomes
`tentative` and `ambiguous`, with every claiming run id as `candidates`
(at most 64), it counts as `ambiguous` under `process_anchor`, and the
run's `corroboration` chain is `partial(ambiguous_attribution)` (so the run
verdict is `partial`). When exactly one run's link is `certain` (the
event's start tick is its known agent start), that run keeps it and only
the others' links become ambiguous.

**Exec chains.** A shell that execs its command in place (`bash -c "cmd"`,
or `dash` for the last command of `sh -c "a && b"`) keeps its pid and
parent pid, so the sensor reports two successful exec events for one
process. Several H2 matches (same pid and parent pid, inside the bounded
window) are one exec chain when, in time order, no exit of that pid is
observed at or between two consecutive execs and, where both carry a
start time, their start times are in the same tick. The effect is
`corroborated_by` the chain's first exec (`process_anchor · tentative`);
the later execs, and the events of the pid until an observed exit, are H3
lineage at depth 0. No host sensor reports
process exits today (event classes `exec`, `connect`, `file`), so the
only exit evidence is the hook's: a record of an effect with that pid,
carrying `fabric.process.exit_code` or `fabric.process.signal`, shows the
pid free by that record's end time. Without that evidence, same pid and
parent pid in succession is accepted as a chain. A chain is never
`certain`. When both start times exist, H1 decides and no chain is needed.

**Pid reuse.** Where two host events match one anchor under H2 and are not
one exec chain (an observed exit between them, or start times in different
ticks), the state is `ambiguous` with every match, and the effect counts as
`anchor_missing`. An exec of the anchored pid under another parent pid is
another process: it is not an H2 match, and H3 drops the pid from the
lineage. H1 cannot be ambiguous: pid plus start time is unique per boot.

**Start-time resolution.** `/proc/<pid>/stat` reports the start time in
clock ticks (10 ms at the usual `USER_HZ` of 100), while the eBPF sensor
reports nanoseconds. H1 compares both at tick resolution.

**One clock on both sides (M2).** Both values are the same kernel field,
the thread-group leader's `task_struct.start_boottime` (`CLOCK_BOOTTIME`,
nanoseconds since boot, suspend included):
- the hook reads `/proc/<pid>/stat` field 22, which the kernel computes as
  `start_boottime / (10⁹ / USER_HZ)` rounded down, and records
  `ticks × 10⁹ / SC_CLK_TCK`. It records the value only when `SC_CLK_TCK`
  is 100 (every mainstream Linux architecture), because the reader's tick is
  fixed at 10 ms (`_host.TICK_NS`);
- the eBPF emitter reads `start_boottime` of `task->group_leader` at the
  `sched_process_exec` tracepoint, through CO-RE, unrounded
  (`fabric.sensor.process_start_ns`). Kernel 5.8 or later is already
  required (ring buffer, `CAP_BPF`), and every such kernel has the field.

H1 compares `floor(a / 10⁷)` on both sides (`_host.same_tick`). An agent in
a time namespace with a boot-time offset (none of Docker, containerd or
Kubernetes sets one by default) reads a shifted value: its start times
never match, so its effects fall back to H2 or `anchor_missing`, never to a
wrong `certain`.

**Production host records and pid namespaces (M2).** A Kubernetes pod, a
Docker container and `bwrap --unshare-pid` each give their processes a pid
namespace of their own. The hook records pids as the agent sees them, while
today's sensors report init-namespace pids, so a pid-only join cannot work
for an agent in a pod. Production eBPF records therefore carry both
numberings (053 §6.2.3 as amended by this revision):

| Key | Value |
|---|---|
| `fabric.sensor.pid`, `.ppid` | Init-namespace tgid and parent tgid (what the local profile reports today) |
| `fabric.sensor.ns_pid` | The process as numbered in its own pid namespace: `pid_nr_ns` of the group leader's `thread_pid` at that pid's own level (`level = thread_pid->level`, value `numbers[level].nr`) |
| `fabric.sensor.ns_ppid` | The parent's **thread-group id** as numbered in that same namespace, which is what `getppid()` returns there: `pid_nr_ns` of `real_parent->group_leader->thread_pid` for the child's namespace (`numbers[level].nr` of that pid when its `level` is at least the child's and `numbers[level].ns` is the child's namespace, else 0). Never the spawning thread's own number: a child spawned from a non-main thread has that thread as `real_parent`, and the thread's own pid is its tid |
| `fabric.sensor.pid_ns` | The inode number of the child's namespace (`numbers[level].ns->ns.inum`), as decimal text |

The exec record gains `fabric.process.pid_ns`: the inode number of the
agent's own `/proc/self/ns/pid`, read once per process by the capture
worker (the child is in the agent's namespace when `Popen` returns; a
sandbox that unshares does so in a later process).

**Pid-namespace mode, per source.** Each host source (one source id) has
one mode, chosen per source, never for a whole export:
- `recorded` when every host record of that source carries
  `fabric.sensor.pid_ns` (production eBPF records);
- `declared_same` otherwise (local-profile records and auditd records,
  which carry init-namespace pids only): the operator declares, with
  `--host-label`, that the agent shares the sensor's pid numbering.

`--host-pid-namespace KIND=MODE` overrides the mode for every source of one
sensor kind (§7.3.3 (l)). An export holding both eBPF and auditd records
therefore compares eBPF events in the agent's own namespace and auditd
events in the init namespace, each by its own rule.

**The agent's namespace.** `AgentProcess.pid_ns` is the value every effect's
`fabric.process.pid_ns` agrees on, derived the same way as the agent's pid
is derived from the effects' `parent_pid` (§4.3 H4); `--agent-pid-namespace`
declares it, as `--agent-pid` declares the pid. Effects that disagree, or a
run with no effect carrying it, give no agent namespace, so H4 links nothing
from a `recorded` source.

The rules use them so:
- **H1, H2** compare, per effect, the effect's `pid` and `parent_pid` with
  the event's `ns_pid` and `ns_ppid` when the source is `recorded` and the
  effect's own `fabric.process.pid_ns` equals the event's
  `fabric.sensor.pid_ns`; with the event's `pid` and `ppid` when the source
  is `declared_same`.
- **H4** compares the agent's pid with the event's `ns_pid` when the source
  is `recorded` and `AgentProcess.pid_ns` equals the event's `pid_ns`; with
  the event's `pid` when the source is `declared_same`.
- **Agent identity (H4).** The pids alone do not name the agent: the kernel
  reuses a freed pid namespace's inode number, so back-to-back containers
  report the same `pid_ns` and `ns_pid` (1) for their first process. An
  event H4's comparison matches is another process when its identity
  contradicts the agent's, checked in this order: its start time is in
  another tick than the agent's known one (`AgentProcess.process_start_ns`;
  the same tick makes the link `certain`); else, from a `recorded` source,
  its `pid` is not the init-namespace pid the run's `certain` anchors name
  as their parent (the `ppid` of each H1 event whose effect is the agent's
  child); else it started in a later tick than the agent's earliest child
  (a parent starts before its child). Two processes with the agent's pids
  never live at the same time, so such an event lies outside the agent's
  life and outside the run: it is neither linked nor listed as unexplained
  (trace `H4-other-process`). Its descendants are its own, not the
  agent's: an event whose parent-pid chain reaches such a process, by the
  H3 walk from that process (same host, init-namespace pids, start ticks,
  depth 16 and 4096 events), is outside the run too (trace
  `H4-other-lineage`), whatever its time. The walk starts only from a
  process whose pid cannot name the agent when a child is seen: from a
  `recorded` source, its `pid` is not the anchors' init pid; else it
  started in a later tick than the agent (its known start, else its
  earliest child). An earlier process that may share the agent's init pid
  (`declared_same`, or no `certain` anchor) has no descendants this way.
  Identity moves an event out of a run, never its time alone. Unless
  another run lists them, these events are listed as host events in no
  run with reason `other_process` (above). The cgroup id is not an
  identity check: a process can change cgroup, and the anchors' init pid
  is the stronger key.
- **Earlier process (revision 9).** When the agent's start tick is known
  (`AgentProcess.process_start_ns`, else the one start tick of the events
  H4's comparison matches whose `pid` is the anchors' init pid, from a
  `recorded` source, no later than the agent's earliest child), any host
  event whose process started in an earlier tick is neither the agent nor
  one of its descendants (a child starts after its parent): outside the
  run, neither linked nor unexplained (trace `H4-earlier-process`),
  whatever its time, and listed at report level with reason
  `other_process` unless another run lists it. Start ticks are
  boot-relative and read by the kernel, so neither a clock step nor a
  clock margin moves them. This reaches the previous container's processes
  that no walk does: a child whose exec the sensor stamped before its
  parent's (the walk needs non-decreasing times), or a parent with no event
  in the record. A process that started after the agent and whose parent
  chain reaches nothing stays unexplained.
- Different namespaces never join. Under `recorded`, an effect without
  `fabric.process.pid_ns` (an agent off Linux, or a failed read) or an agent
  without a namespace never joins: the effect is `anchor_missing`. The
  reader never falls back to comparing the effect's pids with init-namespace
  pids.
- **H3** follows `ppid` → `pid` in the init namespace, where every process
  has a number, so lineage crosses a nested pid namespace (a sandbox's
  inner processes) without a gap. The anchor's init-namespace pid is the
  matched event's `fabric.sensor.pid`.

auditd has no namespace-local pid: an agent in its own pid namespace cannot
be anchored from auditd records (`anchor_missing`), only from eBPF records.

**Sensor scope (M2).** Scope is a set of cgroup **roots**: an event is in
scope when the cgroup of the task that raised it is a root or a descendant
of one. A production eBPF record carries `fabric.sensor.scope`:
- `agent` under an **agent root**: a static cgroup v2 directory
  (`EMIT_AGENT_CGROUP_ROOTS`, at most 8: a Docker `--cgroup-parent` slice
  the agent containers run under, a systemd service, one container's
  scope), or the pod slice of each pod on the sensor's node that matches a
  label selector (`EMIT_AGENT_POD_SELECTOR`, Kubernetes, OD-12). A pod's
  processes run in per-container `cri-containerd-<id>.scope` cgroups below
  its pod slice, and their ids change on every restart, so an exact cgroup
  match (the local mode's `EMIT_CGROUP_PATH`) cannot scope a pod;
- `sandbox` under a **sandbox root** (`EMIT_SANDBOX_CGROUP_ROOTS`, at most 8):
  the parent the operator gives the container runtime for agent-started
  containers, such as a Docker `--cgroup-parent` slice, or a node's
  `kubepods` slices (below).

When an event's cgroup lies under both kinds of root, the deepest root
decides (an agent pod under `kubepods.slice` is `agent`). Agent-scope
events follow the rules above and are listed as unexplained when no rule
links them. Sandbox-scope events are read only for rule H5: one that H5
does not link is counted in `attribution.sandbox_events_unlinked`, never
listed as unexplained, because the operator scoped other workloads'
containers in only so that the agent's could be found.

A pod root that matches the selector is installed when its pod slice
appears. If the slice already holds a container cgroup other than the pod's
first (sandbox) container when the root is installed, events may have been
missed: the next heartbeat reports upstream loss `scope_late` with an
unknown count (053 §6.2.4), so `corroboration` is `partial(source_gap)` for
that window and never `complete` by omission.

**Kubernetes sandbox roots and their cost.** The kubelet places every pod at
`kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<uid>.slice` (systemd
driver) or `kubepods/<qos>/pod<uid>` (cgroupfs driver); nothing groups pods
by namespace. To see a pod the agent creates, the sandbox roots must be the
node's `kubepods` slice (or its QoS slices), and then **every** workload on
that node is in sandbox scope. Those events leave the node as host records
(event class, syscall, result, pids, times, keyed cgroup, container, pod
and peer ids; no executable name, argv or path, and digests only under both
digest permissions, 053 §6.2.5) and are only counted by the verifier. The
supported pod form is therefore a **dedicated node pool** for agents and the
pods they create (a taint the agent's pods tolerate, and a node selector on
the pods the agent creates), where every other workload is Fabric's own or
the cluster's daemons. On a shared node the operator accepts that
over-collection explicitly; the DaemonSet example (WP4-09) says so where it
sets the roots. A pod the agent creates may be scheduled on another node:
H5 below matches on any host source, so it is linked when that node's
sensor also scopes its `kubepods` slices.

**Container group (rule H5, M2, owner decision OD-4).** A container's
processes are children of the container runtime (`containerd-shim`,
`conmon`, the kubelet's runtime), not of the agent, so H3 cannot reach them.
The runtime prints the id of what it created, and the agent usually returns
that text to the model:
- `docker run -d`, `docker create`, `podman run -d`, `podman create`,
  `nerdctl run -d`, `nerdctl create`: the full 64-hex container id on
  standard output;
- `kubectl run … -o jsonpath='{.metadata.uid}'`, or `kubectl create`,
  `run` or `apply` with `-o json` for a `kind: Pod` object: the pod uid.

The exec hook (WP6-08) derives `fabric.sandbox.created_id` from that
output: `sbx-` v2 of `container:<64 hex>` or `k8s-pod:<uid>` under the id
key. The eBPF emitter (WP4-07c) derives the same ids, for sandbox-scope
events only, from the names of the event's cgroup and its parent
(`docker-<64 hex>.scope`, `cri-containerd-<64 hex>.scope`,
`crio-<64 hex>.scope`, `libpod-<64 hex>.scope`, or a component that is
exactly 64 lowercase hex, as Docker's and the kubelet's cgroupfs driver
name a container under any parent; the pod uid from a
`kubepods…-pod<uid>.slice` or `pod<uid>` component, with `_` read as `-`)
into `fabric.execution.sandbox_id` (container) and `fabric.sensor.pod_id`
(pod). The BPF program reads those two kernfs names at event time
(`task->cgroups->dfl_cgrp->kn`, through CO-RE), so a short-lived container
whose cgroup is removed before user space reads the event still gets its
ids. Both sides use the same id key, as they already do for
`fabric.execution.host_id`.

| Rule | Condition | Link | Method | Provenance | Confidence |
|---|---|---|---|---|---|
| H5 Sandbox report | A host event of **any** host source, inside the run window widened by both clock margins, at or after the effect's start minus the margins, whose `fabric.execution.sandbox_id` or `fabric.sensor.pod_id` equals the effect's `fabric.sandbox.created_id`; at most 4096 events per effect | event `part_of` → the effect's attempt | `sandbox_report` | `reported` | `certain` |

- The link rests on an id the container runtime reported in the effect's
  own output, so its provenance is `reported`; the match itself is exact
  (container ids are 256-bit random values, pod uids are UUIDs), so it is
  `certain`. It never upgrades any content's provenance.
- Unlike H1 to H4, H5 does not require the effect's host: the id is unique
  across hosts, and a scheduler places a created pod on any node. Both
  sources must use the same id key (otherwise the keyed ids differ and
  nothing matches).
- An effect without a created id (a foreground `docker run`, output not
  captured, a runtime or form not listed above, an API client in the agent
  process) links nothing by H5; its container's events stay unlinked
  sandbox-scope events. A Docker or Kubernetes API client in the agent
  process (the `docker` or `kubernetes` Python packages, which send through
  `requests`/`urllib3`) is not observed in M2.
- The `docker` CLI process itself is an ordinary effect: H1/H2 anchor it,
  H3 links its own children.
- H5 events are reported in `sensor_events[]` with their link, like H3.

### 4.4 Sandboxes

Three kinds of sandbox, three answers:

| Sandbox | Example | What this spec provides |
|---|---|---|
| **Child-process sandbox** | `bubblewrap`, `nsjail`, `firejail`, `python -I` runners started by the agent | Fully covered: the sandbox launcher is an `exec.subprocess` effect, attributed by §4.2; everything inside it is linked by H3 lineage. |
| **Local container** | `docker run -d`, `kubectl run`, a pod the agent creates | The container's processes are children of the container runtime, not the agent, so H3 does not reach them. The `docker run` effect is attributed by §4.2. Its container's processes are `part_of` it by rule H5 (§4.3): the id the runtime printed, recorded by the hook, equals the id the eBPF emitter derives from the cgroup path (`sandbox_report · certain`, provenance `reported`; OD-4). M1 built no container link. |
| **Remote sandbox service** | E2B first (OD-3); Modal, Daytona later | Not observable by host sensors. M2 observes E2B at its Python SDK's command and code API, capture point `remote.sandbox` (§4.4.1), and the agent's connections to the provider are linked to the run by H4. The allowlisted non-model HTTP channel (053 §5.4) ships in M2 too, but cannot see E2B (§4.4.1). Until a provider is enabled, the manifest reports `remote.sandbox` disabled with reason `remote_sandbox` for configured sandbox hosts. |

#### 4.4.1 Remote sandboxes: E2B (OD-3)

**Why E2B.** E2B documents a Python SDK whose calls run a command
(`Sandbox.commands.run`) or code (`e2b_code_interpreter.Sandbox.run_code`)
in a remote sandbox and return its standard output, standard error and exit
code (`CommandResult`) or its logs, results and error (`Execution`). It is
widely used as the code tool of OpenAI-style tool loops, which is the agent
shape AR-1 tests. Modal and Daytona come later, one provider at a time.

**Why not the HTTP channel.** 053 §5.4 observes httpx's `HTTPTransport`.
E2B's Python SDK 2.62 (`packages/python-sdk` in `e2b-dev/E2B`, released
2026-11-03) sends its envd RPCs (commands, files) through `pyqwest`, a
Rust HTTP client, directly, and builds its httpx clients (control plane,
`run_code`'s `/execute` stream) on `pyqwest.httpx.PyqwestTransport`, not
on `HTTPTransport`. A transport-level hook would see none of it, and
`pyqwest`'s transports are native classes that cannot be patched. The
stable, documented boundary is the SDK's own call API, which returns the
decoded result to the agent: the same kind of boundary as
`Popen.communicate` (053 §5.1) and the MCP SDK's transport (053 §5.5).
This is an observation point, not an agent framework adapter: it sees what
the agent asked the provider to run and what came back, whatever framework
drives the agent.

**What is observed** (`hooks/_sandbox.py`, provider module
`hooks/_sandbox_e2b.py`, pinned `e2b` 2.62.x and `e2b-code-interpreter`
2.11.x; other versions report `unsupported_version`):

| Call (sync and async) | Records | Content |
|---|---|---|
| `Commands.run(cmd, background=False/None, …)` returned `CommandResult` or raised `CommandExitException` | `start` (`remote.request`), then `end` with `exit_code` | `remote.result` = `stdout`, `remote.stream` = `stderr`; `retain_output=False` gives `output_form: none` and no bodies |
| `Commands.run(cmd, background=True)` returned a `CommandHandle` | `start` only (`background: true`) | request only |
| `CommandHandle.wait()` returned or raised `CommandExitException` | `end` of the attempt its `run` opened (`call: command_wait`) | as foreground |
| `Sandbox.run_code(code, language=…, …)` returned `Execution` | `start`, then `end` | `remote.result` = the joined `logs.stdout`, `remote.stream` = the joined `logs.stderr`; `results[]` only as a count; `error.name` as a label |
| Any of them raised another exception | `end`, `result_status=error`, `error_class` | none |

- Identity: `fabric.execution.sandbox_id` = `sbx-` v2 of `e2b:<sandbox_id>`,
  read as an exact `str` from the instance dictionary of the `Sandbox` that
  owns the `Commands` object (never a property call); absent without an id
  key.
- `remote.request` is JSON `{"kind": "command", "command": CELL, "cwd"?:
  CELL, "user"?: CELL, "env_names"?: [str]}` or `{"kind": "code", "code":
  CELL, "language"?: str, "env_names"?: [str]}` with 053 §5.1 cells;
  environment variable names come only from an explicitly passed exact
  `dict` (`envs`), values never.
- Callbacks (`on_stdout`, `on_stderr`, `on_result`, `on_error`) are the
  application's; the hook never wraps or calls them.
- The hook never calls the provider, never creates, connects to or kills a
  sandbox, and never reads files from one.

Effects of `remote.sandbox` are attributed by §4.2 exactly as `exec`
effects (A1 compares `remote.result` with the tool result). They carry no
pid, so no H rule anchors them and they never count as `anchor_missing`.
The provider is a different trust domain: the record says what the SDK
returned to the agent, not what ran on the remote side.

**Configured sandbox hosts.** `FABRIC_WIRE_SANDBOX_HOSTS` (JSON array of
canonical host names, as `FABRIC_WIRE_HTTP_HOSTS`) declares the sandbox
providers a deployment uses. When it is set and no provider is enabled
(`FABRIC_WIRE_REMOTE_SANDBOX` unset), the manifest row is
`remote.sandbox@<ver>:H:disabled:0:0:remote_sandbox`: the manifest's
`not_captured(remote_sandbox)`. The verifier adds `remote_sandbox` to the
`effects` chain's reasons for a run only when it has evidence that the run
called a sandbox host: an H4 connect event of the agent process to a peer
declared with `--sandbox-peer` (listed in `attribution.remote_sandbox_calls`).
Without a host sensor the manifest row is the only statement. A connection
of the agent process to a declared sandbox peer is linked by H4 (`part_of`
the run, as a model endpoint's is) and never listed as unexplained, whether
or not the channel is active; to an undeclared provider it stays
unexplained, which is the signal that a sandbox call went unrecorded.

### 4.5 Chain verdicts and the attribution summary

`fabric.run-reconstruction/v1` gains two optional objects (§5). The verdict
for each chain is reported separately. The overall run verdict is unchanged
in meaning (050 §3.12), and is never `complete` when any observed chain is
`partial`.

| Chain | `complete` when | `partial` reasons | `not_observed` when |
|---|---|---|---|
| `decisions` | The existing run verdict for exchanges is complete | the existing reasons | only for a run with no captured exchange whose record verifies (rev 6, below); never for a run with an exchange |
| `actions` | Every tool call in a captured response has its result in a later captured request, or the run ended normally with it outstanding and declared | `tool_result_missing`, `exchange_gap` | no tool calls in the run |
| `effects` | Every record of every enabled effect channel verifies (positions, seals) and no effect is unattributed | `sequence_gap`, `unattributed_effect`, `ambiguous_attribution`; `remote_sandbox` (M2: the run called a declared sandbox host with no remote-sandbox channel, §4.4.1) | no effect channel enabled (the manifest says so) |
| `corroboration` | A host source verified for the whole run window, every effect with a known pid is anchored, and no host event is unexplained | `source_gap`, `anchor_missing`, `unexplained_host_event` | no host source configured |

**A process with no model call (rev 6).** Every source epoch the export
delivers is in the report. An epoch whose records (effects) name a run that
no exchange or scope names (a tool-worker process, or an agent killed
before its first model call) is a run of its own: under its source fallback
run id (`source:<source>:<epoch>`) its window is the whole epoch, otherwise
the span of its records (047 §9.5 rule b). Its gaps and its end are judged
as an exchange epoch's are: an epoch without a final heartbeat (a killed
process) is `tail_unverified(no_final_heartbeat)`. Its effects lie in no
open tool-call window, so each is A4 and `effects` is
`partial(unattributed_effect)`. Its `decisions` chain is `not_observed`,
without reasons, when the record verifies; with a gap it keeps the gap's
verdict, because a lost position may have been a model call. Nothing about
such a run is ever `complete` by omission. An epoch with no record at all
stays the silent-loss run it was (every sequence missing).

`attribution` object: counts of `resolved`, `ambiguous` and `unresolved`
links by method; `unattributed_effects[]` (event ids, at most 64);
`startup_effects` (revision 11: `{count, effects[]}`, at most 64, present
only when there is one; never a chain reason);
`effects_not_observed` counts by reason; `output_match`
(`applied`, `not_applicable` with reason); `unexplained_host_events`
(count and the first 64 event ids).

Revision 12 adds to `attribution` (unit 056-c2 schema): the bases
`command_match`, `path_match` and `execution_context` in `links`;
`content_match`, an object with one entry per test (`output_match`,
`command_match`, `path_match`, `execution_context`), each
`{state: applied | not_applicable, reason?, held, narrowed}` where
`reason` is one of `metadata_only`, `withheld`, `payload_too_large`,
`not_captured`, `no_effect`; `held` counts the effects the test held for
and `narrowed` those where it removed at least one window candidate; and
`content_match.conflicts`, the count of `A1-conflict` decisions. The
existing `output_match` object stays as it is. The `effects` chain gains
the reason `unattributed_file_effect` (§4.2.3).

M2 adds to `attribution` (WP6-11 schema): the basis `sandbox_report` in
`links`; `sandbox_events_unlinked` (`{count}`: sandbox-scope events no H5
link names); `remote_sandbox_calls` (`{count, event_ids}`, at most 64: H4
connect events to a declared sandbox peer while `remote.sandbox` is not
active). A remote effect (no pid) never counts against `corroboration`.

### 4.6 Reading a run: the action view

`python -m fabric.reconstruct actions <export>` prints one run as a
timeline a person can read:

```text
run r-3f2a…  decisions: complete  actions: complete  effects: partial(unattributed_effect)  corroboration: complete
  1  model_call   gpt-4.1   → tool_call T1 run_shell
  2    effect     exec sh -c '…' exit 0           ← T1  output_match · tentative
  3      host     exec sh (pid 4121)              ← #2  process_anchor · certain
  4      host     exec curl (pid 4122)            ← #3  process_lineage · certain
  5      host     connect 10.0.4.7:443            ← #4  process_lineage · certain
  6  model_call   gpt-4.1   ← result T1
  …
  unattributed effects: 1   (exec uname -a, seq 88: no open tool call)
```

Revision 12: the link text of an effect row names the method and, when
more than one test held, the others in brackets, for example
`← T1  command_match [+execution_context] · tentative`; an `A1-conflict`
row reads `← T1 | T2  conflict(output_match, command_match) · tentative`.
Rows of revision 11 that read `output_match · certain` now read
`output_match · tentative`.

A startup effect (S0, revision 11) is a row marked
`(startup: before the first model call)` and a closing line
`startup effects: N (…: before the first model call; not attributed, not a gap)`.

M2 adds two row kinds (the view stays a rendering; no contract):

```text
  9  model_call   gpt-4.1   → tool_call T8 run_container
 10    effect     exec docker run -d … exit 0     ← T8  output_match · tentative
 11      host     exec docker (pid 4180)          ← #10 process_anchor · certain
 12      sandbox  sbx-1f2e… 14 host events        ← #10 sandbox_report · certain
 13    effect     remote e2b commands_run exit 0  ← T9  output_match · tentative
```

A `sandbox` row groups the H5 events of one created id (count, first and
last time); `--json` lists each event.

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
  was already given. It stores no new content. Revision 12: the same holds
  for `command_match` and `path_match`. A link's `match` entries are closed
  enumerations; no argument, command, path or output text is copied into a
  link, the report or a log. The thread and task tags are small integers
  (§4.2.2).
- M2: container and pod ids, sandbox ids and pid namespace numbers leave
  the process only as keyed `sbx-` pseudonyms or bounded decimal text.
  `fabric.sandbox.created_id` is derived by the capture worker from output
  the caller already received; it is not derived when the `terminal.stdout`
  role is `omit` (053 §4.1: `omit` means no work). The E2B request, output
  and error are `remote.*` CONTENT under their roles; the E2B API key,
  request headers and environment values are never read.
- M2: sandbox roots collect other workloads' process and connection
  metadata (§4.3 "Kubernetes sandbox roots and their cost"). It carries no
  executable name, argv, path or clear address, and the report holds only
  its count. The operator bounds it by choosing the roots: a dedicated
  `--cgroup-parent` slice, or a dedicated node pool in Kubernetes.
- M2: the eBPF emitter's Kubernetes pod selector reads pod uids, labels and
  phases from the API server for its own node only, to find agent pod
  slices. It never exports them: only the keyed `fabric.sensor.pod_id` of
  sandbox-scope events leaves the node.

## 5. Contract changes

Applied by WP6-01 only.

| File | Change |
|---|---|
| `contracts/coverage/v1/schema/step-projection-v1.schema.json` | Link and field `method` enums gain `sequence_bracket`, `output_match`, `process_anchor`, `process_lineage` |
| `contracts/capture/v1/schema/run-reconstruction-v1.schema.json` | Optional `chains` object (`decisions`, `actions`, `effects`, `corroboration`, each a verdict with reasons) and optional `attribution` object (§4.5) |
| `contracts/coverage/v1/registry/telemetry-keys-v1.json` | Rows for `fabric.process.parent_pid` and `fabric.process.start_ns`, placement `record`, capture point `exec.subprocess`. The 053 rows needed by `exec.subprocess` (053 §7) land here too if 053 WP4-01 has not run. |
| `contracts/coverage/v1/registry/vocabularies-v1.json` | Reason values: `unattributed_effect`, `ambiguous_attribution`, `anchor_missing`, `unexplained_host_event`, `tool_result_missing`, `exchange_gap`, `source_gap`; `effect_not_observed` reasons `channel_disabled`, `no_effect_channel`, `none_in_window`; `not_captured` reason `remote_sandbox` |
| `contracts/coverage/v1/fixtures/action-record/` | Valid and invalid fixtures for every rule A0–A4 and H1–H4 (§6.1), plus the interface goldens: the `exec.subprocess` effect record and the host-sensor record, with a README mapping each field |

### 5.1 M2 contract changes (applied by WP6-11 only)

These land before any other M2 work package. They include the 053 §7 rows
that M2 needs (053 WP4-01 has not run); 053 rows that M2 does not need (file,
database, MCP, SSH, exec audit) stay with 053 WP4-01. Registry operations
are keyed by id, key or role and keep every column not named. Registry
revisions, family manifest minor versions and pins are bumped together.

| File | Change |
|---|---|
| `contracts/coverage/v1/registry/telemetry-keys-v1.json` | The `fabric.sensor.*` keys of 053 §6.2.3 (as amended in 053 revisions 3 and 4: `ns_pid`, `ns_ppid`, `scope`, `pod_id` added) with placement `record` and `capture_point_kinds: ["S"]`; `fabric.sensor.upstream_lost` and `.upstream_loss_reason` (053 §6.2.4, enum with revision 4's `scope_late`) with placement `heartbeat`; `fabric.process.pid_ns` (`^[0-9]{1,20}$`) and `fabric.sandbox.created_id` (`^sbx-[0-9a-f]{32}$`, field X21), placement `record`, `capture_points: ["exec.subprocess"]`; `http.request.method` (closed enum `GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, other`) and `http.response.status_code` (int 100..599), placement `record`, `capture_points: ["http.nonmodel"]` (053 §7) |
| `contracts/coverage/v1/registry/capture-points-v1.json` | 053 §7 rows for `http.nonmodel` (`input`: `records`; `observes` appended) and both host rows (`state`, `passivity_gate`, `observes`); new row `remote.sandbox`: kind `H`, runtime "Python; `e2b` 2.62.x, `e2b-code-interpreter` 2.11.x", activation "opt-in per provider (`FABRIC_WIRE_REMOTE_SANDBOX`)", observes "the command or code the agent asked the provider SDK to run and the result the SDK returned", cannot_observe "the remote side, other providers, SDK versions outside the pins, streaming callbacks", passivity gate `P4-SANDBOX`, supplies `N37`, `C41`, input `records` |
| `contracts/coverage/v1/registry/field-registry-v1.json` | `observed_by`: N37 and C41 add `remote.sandbox`; C41 and X21 add `exec.subprocess`; C41 keeps both host points. `evidence_types` adds `fabric.http.observation/v1` (053 §3.2 schema, unchanged) and `fabric.sandbox.observation/v1` (below) |
| `contracts/coverage/v1/evidence/fabric.sandbox.observation-v1.schema.json` (new) | Closed item `{provider: enum[e2b], call: enum[commands_run, command_wait, run_code], background?: bool, output_form: enum[text, none], exit_code?: int -1..255, result_count?: int 0..1024, language?: enum[python, javascript, typescript, r, java, bash, other], error_name?: LABEL ^[A-Za-z_][A-Za-z0-9_.]{0,127}$, error_class?: LABEL}`, points `["remote.sandbox"]`, step kind `remote_exec`, with the 053 §3.2 per-type fixtures |
| `contracts/coverage/v1/evidence/fabric.http.observation-v1.schema.json` (new) | 053 §3.2 `fabric.http.observation/v1` as written there; M2 emits `dialect: none` only |
| `contracts/coverage/v1/registry/vocabularies-v1.json` | `inference_method` `sandbox_report` (confidence `certain`; "a host event whose sandbox or pod id equals the id the container runtime printed in the effect's output; provenance `reported`; §4.3 rule H5") |
| `contracts/coverage/v1/schema/step-projection-v1.schema.json` | Link and field `method` enums gain `sandbox_report` |
| `contracts/capture/v1/schema/run-reconstruction-v1.schema.json` | `actionLink`: `method` gains `sandbox_report`, `provenance` becomes `inferred` or `reported` (`reported` exactly when the method is `sandbox_report`); `attribution.links` gains the basis `sandbox_report`; optional `attribution.sandbox_events_unlinked` (`{count}`) and `attribution.remote_sandbox_calls` (`{count, event_ids}`, `maxItems` 64); 053 §7 `sensor_events[]` unchanged |
| `contracts/coverage/v1/fixtures/vectors/span-category-v1.json` | The `fabric.sensor_event` branch (053 §7) |
| `contracts/coverage/v1/fixtures/vectors/records-span-v1.json` | 053 §7 host cases (admitted and stripped keys, S-scoped keys on an agent record, agent keys on a host record); `fabric.process.pid_ns` and `fabric.sandbox.created_id` only on `exec.subprocess`; `remote.sandbox` record keys |
| `contracts/coverage/v1/fixtures/vectors/peer-address-v1.json` (new) | The canonical peer text that `fabric.network.host_id` maps: IPv4 dotted decimal; an IPv4-mapped IPv6 address as its IPv4 text; other IPv6 in RFC 5952 form (lower case, longest zero run compressed); then `hst-` v2 under the test key. Python `peer_id` and the Go library must equal it (Python's own `str(IPv6Address)` changed for mapped addresses in 3.13, so neither side may rely on it) |
| `contracts/coverage/v1/fixtures/vectors/sandbox-id-v1.json` (new) | Cgroup paths (Docker cgroupfs default and with a custom parent (`/<parent>/<64 hex>`), Docker systemd (`<parent>.slice/docker-<64 hex>.scope`), containerd CRI, CRI-O, Podman, kubepods for each QoS class under both drivers), each also as its last two components only (what the BPF program reads), and runtime outputs (`docker run -d`, `podman create`, `kubectl … -o jsonpath`, `kubectl … -o json`) → clear text (`container:<64 hex>`, `k8s-pod:<uid>`) → `sbx-` v2; non-matching paths and outputs → no id |
| `contracts/capture/v1/fixtures/host/id-key-file-v1.json` (new) | The id key file format (§7.3.3 (b) `ReadIDKeyFile`): file bytes (base64) → key bytes, or the refusal (shorter than 16 bytes, longer than 4096, a trailing `\n` or `\r`, a NUL byte, not UTF-8); for each accepted key, `hst-` v2 of the host label `ar1-host`, `s-` of the source label `node-a/ebpf`, and the same values from Python's `id_key_from_env` given the file's text as `FABRIC_WIRE_ID_KEY` |
| `contracts/capture/v1/fixtures/host/` (new) | 053 §7: a host record per syscall class, `manifest`, periodic heartbeat with upstream loss, loss, `final`; invalid cases (duplicated identity key, agent impersonation by a sensor, sensor impersonation by an agent, replay with a changed event id, unknown source kind, digest key without permission); M2 adds an eBPF exec record with both pid numberings (one for a child spawned from a non-main thread, whose `ns_ppid` is the parent's thread-group id), `scope: sandbox` with a container and pod id, two heartbeats of one interval with different upstream-loss reasons (§7.3.3 (b)), a `scope_late` heartbeat, and the encrypted-state envelope vectors (`host-state-envelope-v1.json`: magic `FABRIC-HOST-RECORDS-1\n`, AAD = schema `fabric.host-records/v1` plus state kind `epoch`, `staging`, `spool` or `cursor`) |
| `contracts/capture/v1/fixtures/ingress-groups/` (new) | Rendered Node configurations as fabric-gate reads them: `valid/agent-ebpf-auditd.yaml` (one agent group with content, one `host.ebpf` and one `host.auditd` group), `valid/agent-ebpf-three-nodes.yaml` (one agent group and three per-node `host.ebpf` groups, §7.3.3 (n)), `valid/legacy-single-binding.yaml` (today's plain `fabricguard` render, unchanged), `valid/sensor-auditd.yaml` (the sensor collector, `otlp_http` exporter), and one `invalid/*.yaml` per gate rule of 053 §6.1 and §6.2.6, each with the error text its README row names. Paths follow one convention: token files at `/etc/fabric/ingress/<g>/token`, receiver TLS at `/etc/fabric/receiver-tls/{tls.crt,tls.key,ca.crt}` (the chart's existing mount), the sensor collector's client token at `/etc/fabric/sensor/token`. The fixture tree `files/etc/fabric/…` holds a distinct token per group (and two equal ones for the duplicate-credential case); tests copy it to a temporary root with modes 0400 and rewrite the prefix `/etc/fabric/` to that root before running the gate. WP4-08a tests against them; WP4-09's renders must equal the valid ones after the documented normalisation (sorted keys, resolved names, the same prefix rewrite) |
| `contracts/coverage/v1/fixtures/action-record/` | §6.1 M2 fixtures; interface goldens updated: `host-sensor-spans.json` gains `ns_pid`, `ns_ppid`, `scope`, `pod_id`; `exec-subprocess-records.json` gains `fabric.process.pid_ns` and a container-create pair with `fabric.sandbox.created_id`; new `remote-sandbox-records.json` (one `commands_run` and one `run_code` attempt) |
| `contracts/connect/v1/manifests/ebpf-host-emitter.json`, `auditd-host-connector.json`, `python-sdk.json` | Data only (connect v1 schemas are immutable): the production mode's bound source and keyed ids; the SDK's `http.nonmodel` and `remote.sandbox` surfaces and their blind spots |
| Generated tables | `_records_keys_generated.py`, `_manifest_fields_generated.py`, `_roles.py`, fabricguard's `coverage_keys.go` generated block, `fabriccontentexporter/evidence_types_generated.go`, regenerated by `scripts/contracts/generate_p0_contracts.py` |
| `scripts/contracts/action_reference.py`, `action_record.py` | Reference rules H5, the namespace-aware anchor and the scope rule; builders for every new fixture |

### 5.2 Revision 12 contract changes (applied by unit 056-c2 only)

Registry operations are keyed by id, key or value and keep every column
not named. Registry revisions, manifest minors and pins are bumped
together, after whatever spec 053, 055 and 057 units have merged.

| File | Change |
|---|---|
| `contracts/coverage/v1/registry/vocabularies-v1.json` | `inference_method` gains `command_match`, `path_match`, `execution_context`, each with confidence `tentative` and the meaning of §4.2.1 (the confidence of `output_match` itself is changed by unit 056-c1). `reason` gains `unattributed_file_effect`. New closed vocabularies `link_match_effect_part` (`output`, `command`, `argv_element`, `path`, `target_path`, `context`), `link_match_call_part` (`arguments`, `result`, `issuing_exchange`, `result_exchange`) and `link_match_relation` (`equal`, `contains`, `contained`, `path_suffix`, `digest_equal`) |
| `contracts/coverage/v1/schema/step-projection-v1.schema.json` | `$defs/link`: `method` gains the three values; new optional `match`: an array of 1 to 4 closed objects `{basis, effect_part, call_part, relation}`, `basis` one of the four tests, no two entries with the same `basis`; allowed only on a `caused_by` link whose `method` is one of the four tests; such a link must have `confidence: tentative` |
| `contracts/capture/v1/schema/run-reconstruction-v1.schema.json` | `attribution.links` gains the bases `command_match`, `path_match`, `execution_context`; optional `attribution.content_match` (§4.5); the `effects` chain's reasons gain `unattributed_file_effect` |
| `contracts/coverage/v1/registry/telemetry-keys-v1.json` | `fabric.execution.thread_ref` and `fabric.execution.task_ref`: field X21, META, integer 1 to 2147483647, placement `exchange` and `record`, capture point kinds H and W (Python points only; the note says TypeScript does not emit them) |
| `contracts/coverage/v1/registry/capture-points-v1.json` | `reconstruct.infer.observes` names the four tests; the hook rows and the Python wire rows gain the two keys in what they supply for X21 |
| `contracts/coverage/v1/fixtures/action-record/` | The §6.1 revision 12 fixtures; the README's normalized-input section gains `argument_leaves`, `command`, `path`, `target_path`, `thread_ref`, `task_ref` and the `kind` of an effect; existing goldens regenerated for the `tentative` change; interface goldens: one `exec.audit` and one `file.audit` effect record, and an exchange span with both tags |
| `contracts/coverage/v1/fixtures/vectors/records-span-v1.json` | The two keys admitted on hook records and on Python exchange spans, refused out of range, absent allowed |
| `scripts/contracts/action_reference.py`, `action_record.py` | The reference implementation of §4.2.1 (leaf extraction, the four tests, the set rule), independent of `fabric/reconstruct/`; builders for every new fixture |
| Generated tables | Regenerated by the existing generators, including fabricguard's key table (the Node must admit the two keys) |

## 6. Qualification

### 6.1 Rule fixtures

One fixture per rule, plus these edge cases, each with its expected
projection and report:
- two parallel tool calls with distinct outputs (A1 resolves both);
- the same two in metadata-only mode (both stay `ambiguous`);
- an effect within the clock margin of a window boundary (candidate of
  both sides);
- a background-thread effect between windows (A4);
- a pid reused within the window, with an observed exit between the two
  execs (H2 `ambiguous`, never `certain`);
- a shell that execs its command in place (one exec chain, H2
  `tentative`), and the same pid exec'd under another parent pid (not a
  chain: another process);
- a lineage chain of depth 17 (truncated at 16, reported);
- a host event from the agent process to a host no exchange called
  (listed as unexplained).

M2 adds (WP6-11; file names under `rules/` and `invalid/`):

| Fixture | Pins |
|---|---|
| `h1-anchor-exact-production.json` | Production span shape; the agent in its own pid namespace; H1 on `ns_pid`/`ns_ppid` and the start tick; `certain` |
| `edge-production-other-namespace.json` | Same `ns_pid` and parent in a different `pid_ns`: no join (`anchor_missing`) |
| `edge-nested-pid-namespace.json` | `bwrap --unshare-pid`: inner processes reached by H3 on init-namespace pids, depth counted across the boundary |
| `edge-start-tick-boundary.json` | Hook value `ticks × 10⁷`, sensor value one ns below and one tick above: same tick `certain`, next tick no H1 |
| `h5-sandbox-report.json` | `docker run -d` effect with `fabric.sandbox.created_id`; container events `part_of` it, `sandbox_report · certain`, provenance `reported`; the docker CLI process anchored by H1 |
| `h5-pod-report.json` | `kubectl run … -o jsonpath` effect; pod events matched by `fabric.sensor.pod_id` |
| `h5-pod-report-other-node.json` | The same with the pod's events from a second `host.ebpf` source on another host: linked by H5, while H1 to H4 still never join across hosts |
| `edge-mixed-namespace-modes.json` | One eBPF source (`recorded`) and one auditd source (`declared_same`) in one input: each source joins by its own mode; the auditd events of an agent in its own namespace are not anchored |
| `edge-recorded-effect-without-pid-ns.json` | A `recorded` source and an effect without `fabric.process.pid_ns`: `anchor_missing`, no fallback to init-namespace pids |
| `edge-thread-spawned-child.json` | A child spawned from a non-main agent thread: `ns_ppid` equals the agent's pid (its tgid), H1 `certain` |
| `edge-quiet-host-epoch.json` | A declared host source whose epoch holds only a manifest and heartbeats in the window: a host source (never in `sources[]` gaps), `corroboration` from its heartbeats |
| `edge-sandbox-peer-port.json` | A model endpoint and a sandbox provider on one address, different ports: `--sandbox-peer ADDRESS:PORT` classifies only the provider's connections |
| `edge-scope-late.json` | A `scope_late` upstream loss inside the run window: `corroboration` `partial(source_gap)` |
| `edge-startup-effect.json` | Revision 11: `uname -p` before the first model call is S0 (listed in `startup_effects`, no link, `effects` complete); the tool's own effect is still A1 |
| `edge-startup-after-gap.json` | Revision 11: the same effect behind an unverified position stays A4 (`partial(sequence_gap, unattributed_effect)`) |
| `edge-clock-per-manifest.json` | Revision 10: base, widened (67.5 ms) and base manifests of one host epoch; each exec record takes its governing manifest's margin, so only the record under the widened manifest anchors its effect (H2) |
| `edge-sandbox-unlinked.json` | Sandbox-scope events with no reported id: `sandbox_events_unlinked`, not unexplained; `corroboration` unaffected |
| `edge-sandbox-before-effect.json` | Events of the created id earlier than the effect start minus the margin: not linked |
| `remote-sandbox-output-match.json` | A `remote.sandbox` `commands_run` effect resolved by A1; no anchor expected, no `anchor_missing` |
| `edge-remote-sandbox-off.json` | Manifest row `remote.sandbox` disabled(`remote_sandbox`), H4 connect to a declared sandbox peer: `effects` partial(`remote_sandbox`), `remote_sandbox_calls` lists it, the event is not unexplained |
| `ar1-run-production.json` | The M2 AR-1 run (§6.2) with every expected link |
| `ar1-negative-f-remote-sandbox-off.json`, `ar1-negative-g-container-id-not-reported.json` | AR-1 negative variants (f) and (g) |
| `invalid/h5-sandbox-report-claims-inferred.json`, `invalid/h5-tentative.json`, `invalid/h1-across-pid-namespaces.json`, `invalid/sandbox-scope-listed-unexplained.json` | Refused expectations |

Revision 12 adds (unit 056-c2; file names under `rules/` and `invalid/`).
Each has its normalized input, expected projection links, report and
trace, produced by the reference rules:

| Fixture | Pins |
|---|---|
| `c-command-equal-shell.json` | Two parallel calls with different commands, shell form, outputs withheld: each effect `resolved` by `command_match` (a), `tentative` |
| `c-command-argv-element.json` | `["python", "-c", code]` with the code in one call's arguments: (b) |
| `c-command-wrapped.json` | The agent runs `cd /w && <command>`: (c) |
| `c-command-script-line.json` | The agent runs one line of a multi-line `script` argument: (d) |
| `c-command-in-result.json` | The result echoes the command: (e) |
| `c-command-short-no-substring.json` | A 15-byte command contained in a longer argument: (c) and (d) do not hold; A3 |
| `c-command-identical-args.json` | Two calls with the same command: `A1-ambiguous` among the two, both listed |
| `c-command-rewritten.json` | The agent changed the quoting: no test holds; A3 as in revision 11 |
| `c-path-equal.json`, `c-path-suffix.json`, `c-path-suffix-backslash.json`, `c-path-absolute-leaf.json` | `path_match` (a) and (b) in both directions and with both separators |
| `c-path-rename-target.json` | A rename whose target only is named by the call |
| `c-path-no-boundary.json` | `a.py` against `/w/data.py`: not a suffix at a separator; no match |
| `c-path-in-result.json` | (c) |
| `c-leaves-nested.json`, `c-leaves-not-json.json`, `c-leaves-over-bound.json`, `c-leaves-escaped.json` | Leaf extraction: nested arrays and objects; raw text when not JSON; `payload_too_large`; a command with quotes, a newline and a non-ASCII character matches after JSON decoding |
| `c-context-two-sessions-threads.json` | Two sessions on two threads, same command text: `execution_context` resolves each |
| `c-context-two-sessions-tasks.json` | The same with two asyncio tasks on one thread |
| `c-context-worker-thread.json` | The tool runs on a worker thread: the test holds for nobody; A3 |
| `c-context-untagged-candidate.json` | One candidate's exchange has no tag: the test does not apply |
| `c-intersection.json` | `command_match` holds for {T1, T2}, `execution_context` for {T1, T3}: `resolved` T1, `match` lists both |
| `c-conflict.json` | `output_match` holds for T1 only and `command_match` for T2 only: `A1-conflict`, links to both, counted |
| `c-metadata-only.json` | Content tests `not_applicable(metadata_only)`; `execution_context` still resolves |
| `c-withheld-one-side.json` | One candidate's response body withheld: `command_match` not applicable; A3 |
| `c-output-now-tentative.json` (added by unit 056-c1) | The revision 11 A1 case: same link, `tentative` |
| `c-file-effect-window.json`, `c-file-effect-startup.json`, `c-file-effect-unattributed.json` | A `file.audit` effect in one window (A2), before the first model call (S0), and after it with no window (`unattributed_file_effect`) |
| `c-exec-audit-effect.json` | An `exec.audit` effect resolved by `command_match`; no pid, no anchor, `corroboration` unaffected |
| `c-hook-program-skipped.json` | A declared hook program (057 P2a) whose argv contains a call's arguments: no content link |
| `invalid/match-on-sequence-bracket.json`, `invalid/match-certain.json`, `invalid/match-duplicate-basis.json`, `invalid/match-free-text.json` | Schema refusals: `match` on a `sequence_bracket` link; a content-matched link marked `certain`; two entries with one `basis`; a `relation` outside the enumeration |

### 6.2 AR-1: the acceptance scenario

Revision 12: AR-1's expected links keep their targets and methods; every
`output_match` link is `tentative`. Unit 056-c1 updates the harness's
expectations with the goldens.

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
| 1 | effect `caused_by` T1; host `exec sh` `corroborated_by` | `output_match` · tentative; `process_anchor` · certain |
| 2 | effect `caused_by` T2; `curl` start and its `connect` `part_of` the effect | `output_match` or `sequence_bracket`; `process_lineage` |
| 3 | each effect `caused_by` its own call | `output_match` · tentative, both |
| 4 | sandbox launcher `caused_by` T4; the Python process inside `part_of` it | `output_match`; `process_lineage` |
| 5 | listed in `unattributed_effects` | A4 |
| 6 | listed in `unexplained_host_events` | H4, uncalled host |

Chain verdicts: `decisions` complete, `actions` complete, `effects`
`partial(unattributed_effect)`, `corroboration`
`partial(unexplained_host_event)`.

**M1 difference.** Today's local-profile host records carry no process
start time, so in M1 the host links in steps 1, 2 and 4 are
`process_anchor · tentative` (rule H2), not `certain`. They become
`certain` in M2, when the production host records add
`fabric.sensor.process_start_ns` (053 §6.2.3). The rule fixtures pin both
cases (`ar1-run` and `ar1-run-local-profile`).

**Negative variants**, each a separate CI case:
- (a) host source removed → `corroboration: not_observed`; other chains
  unchanged;
- (b) one effect record dropped from the spool → `effects:
  partial(sequence_gap)`;
- (c) hook disabled → `effects: not_observed`, with the manifest reason;
  every tool call is `effect_not_observed(channel_disabled)`;
- (d) metadata-only content mode → step 3 is `ambiguous`; the other
  effects keep their targets, but their method becomes `sequence_bracket`
  and their confidence `tentative`, because A1 needs content;
- (e) the agent run with capture off, then on → identical agent outputs and
  exit codes, and the 053 §4.4 latency budgets hold.

**Privacy canaries.** A secret placed in an environment variable of the
step 1 command, and a bearer token in an HTTP header of the step 2 request,
never appear in clear in any spool file, Node export or report.

**M2: AR-1 production** (WP6-10). Setup as above, with:
- a production-profile Node from the Compose production overlay plus the
  host-ingress overlay (WP4-09): one `agent` group (telemetry and content)
  and one `host.ebpf` group, each with its own token, TLS on the group
  listeners, delivery over verified HTTPS to an authenticated test sink;
- Docker with the `systemd` cgroup driver on cgroup v2 (the ubuntu-24.04
  default); the harness asserts `docker info --format '{{.CgroupDriver}}'`
  is `systemd` and fails, never skips, otherwise. Before the emitter
  starts, it installs two runtime slice units,
  `/run/systemd/system/fabric-agents.slice` and
  `/run/systemd/system/fabric-sandboxes.slice` (each `[Slice]` only), runs
  `systemctl daemon-reload` and `systemctl start` on both, and asserts the
  directories `/sys/fs/cgroup/fabric.slice/fabric-agents.slice` and
  `/sys/fs/cgroup/fabric.slice/fabric-sandboxes.slice` exist (systemd reads
  a dash in a slice name as hierarchy, so both lie under `fabric.slice`);
- the agent in a container started with `--cgroup-parent
  fabric-agents.slice`, with its own pid namespace (the production shape of
  a pod), `FABRIC_HOST_LABEL` set, the Docker socket mounted for step 8, the
  fixture E2B server of WP6-09b reachable for step 9 on an address of its
  own (no other fixture or the Node listens on it), and
  `--security-opt seccomp=unconfined --security-opt apparmor=unconfined`,
  so that bwrap can create its namespaces in step 4 (on a runner with
  `kernel.apparmor_restrict_unprivileged_userns=1` the harness sets it to 0
  for the job and restores it);
- the eBPF emitter in production mode (`EMIT_PRODUCTION=true`) on the
  runner's kernel, with `EMIT_AGENT_CGROUP_ROOTS=/sys/fs/cgroup/fabric.slice/fabric-agents.slice`
  (the agent container's `docker-<id>.scope` lies below it, as a pod's
  container scopes lie below its pod slice) and
  `EMIT_SANDBOX_CGROUP_ROOTS=/sys/fs/cgroup/fabric.slice/fabric-sandboxes.slice`
  (the parent the operator gives agent-started containers);
- the verifier reading only the sink's export (host and agent records
  together), with `--trusted-source`, `--profile production`, the id key,
  `--host-label`, `--host-source host.ebpf=<the emitter's s- id>` (from
  `print-source-id`), `--sandbox-peer ADDRESS:PORT` for step 9's provider
  and no `--host-coverage-declared` (production records prove coverage).

Script additions, after step 6 and before the final answer:
8. The model asks for `run_container(...)`. The agent runs
   `docker run -d --cgroup-parent fabric-sandboxes.slice <pinned image>
   sh -c '<two commands>'` with `capture_output=True` and returns the id.
   The container exits as soon as its commands do: the ids come from the
   cgroup names read at event time, so no keep-alive is needed.
9. The model asks for `run_remote(code)`. The agent runs it with the
   pinned `e2b` SDK's `Sandbox.commands.run` against the fixture server and
   returns its output.

Under `AR1_PROFILE=production`, step 4 runs
`bwrap --unshare-pid --unshare-net …`, and the `python -I` fallback is
refused: the harness records which sandbox branch ran and fails the
production-live job unless it is `bwrap`. Step 4's inner Python process then
lies in a pid namespace nested in the agent's, which is the live proof that
H3 crosses it (§4.3).

| Step | Expected link | Method · confidence |
|---|---|---|
| 1, 2, 4 | as above; the host link of each effect | `process_anchor` · **certain** (H1) |
| 3 | as above; each effect, spawned from a pool thread, anchored | `process_anchor` · **certain** (H1 on `ns_ppid`, the agent's tgid) |
| 4 | the inner Python process `part_of` the launcher's effect, its `pid_ns` differing from the agent's | `process_lineage` · certain |
| 8 | effect `caused_by` T8; the `docker` CLI exec `corroborated_by`; every container process event `part_of` the effect | `output_match` · tentative; `process_anchor` · certain; `sandbox_report` · certain, provenance `reported` |
| 9 | remote effect `caused_by` T9; the agent's connections to the fixture provider `part_of` the run | `output_match` · tentative; H4 |

Chain verdicts are as in M1. `attribution.sandbox_events_unlinked` is 0.
Every effect of steps 1 to 4 and 8 carries `fabric.process.start_ns`
(OD-8 makes the read happen before the child can be reaped), so no H2
fallback is accepted for them.

Additional negative variants (each a CI case):
- (f) `FABRIC_WIRE_REMOTE_SANDBOX` unset, `FABRIC_WIRE_SANDBOX_HOSTS` set →
  manifest row `remote.sandbox` disabled(`remote_sandbox`); `effects`
  partial(`remote_sandbox`, `unattributed_effect`); T9
  `effect_not_observed(channel_disabled)`; step 9's connections listed in
  `remote_sandbox_calls`, not as unexplained;
- (g) step 8 without `-d` (the container's output, not its id, on
  standard output) → no H5 link; the container's events counted in
  `sandbox_events_unlinked`; `corroboration` unchanged;
- (h) swapped credentials, two cases: the emitter sends to the agent group
  with the agent group's token → the agent `fabricguard` instance refuses
  every host batch (053 §6.2.7), the sink holds no host record, and,
  because the verifier declares the source (`--host-source
  host.ebpf=<s- id>`, as in every production run), `corroboration` is
  partial(`source_gap`), not `not_observed`; the agent sends to the host
  group with the host group's token → every agent batch is refused and
  the sink holds no agent record.

**Hermetic production replay** (WP6-10). A local run of the same shape
without Docker or a kernel sensor: the Node is the native build with the
host-ingress configuration (the `valid/agent-ebpf-auditd.yaml` golden
without the auditd group, plus a second `host.ebpf` group); the host side
is the replay command of the WP4-07a module (`hostrecords-replay`,
§7.3.3 (m)), which stages recorded process trees as production host records
through the library itself (epochs, positions, persisted ids, manifests,
heartbeats) and posts them to each host group with that group's token. The
second group replays a quiet node: a manifest, heartbeats and sandbox-scope
events of no created id, which must stay out of `sources[]` and count in
`sandbox_events_unlinked`. On Linux the replay copies each effect's real
`fabric.process.start_ns` and `fabric.process.pid_ns` into its exec event,
with the agent's namespace-local pids as `ns_pid`/`ns_ppid`, so H1 gives
`certain`; off Linux the hook records neither, so the replay writes records
without `ns_pid`, `ns_ppid` and `pid_ns` (an agent on the host's pid
numbering, mode `declared_same`), and the expected anchors are `tentative`
(H2), which the replay test asserts. Steps 8 and 9 run against a fixture
`docker` script and the fixture E2B server. It proves the gate, admission,
delivery and reader path, not the emitter.

M2 privacy canaries:
- the E2B API key (`E2B_API_KEY`) and a value in step 9's `envs`: in no file
  at all. The fixture E2B server, like the fixture host, compares the key
  and the `envs` value with the canaries and keeps only a boolean and the
  variable names in its ledger, never the values;
- the clear peer addresses and the sensor's executable names: in no sensor
  staging, spool or state file, telemetry span or report;
- the clear container id of step 8: the agent returns it to the model, which
  A1 needs, so it is agent-held CONTENT. It may appear only in step 8's
  `terminal.stdout` content object, in the content object of the next model
  request (the tool result the agent sent), wherever those two content
  objects are held (the agent's spool, the content queues, the store), and
  in the fixture model server's own ledger (a test fixture, not a Fabric
  file). The harness finds the allowed occurrences by content object id,
  not by file name. It must not
  appear in any sensor staging, spool or state file, any telemetry span
  (agent or host), the report, the projection or the `actions --json`
  output (which carries argv labels and keyed ids, never output).

### 6.3 Measuring the ambiguous share again (revision 12)

**The figure.** The build plan states that 41% of effect-to-tool-call
links are ambiguous. The number comes from the field harness, a test
harness kept outside this repository that runs real agent shapes with an
independent ground-truth log; build agents may read it and never write
it. Its comparator classes every ground-truth process as
`linked:certain`, `linked:tentative`, `linked:ambiguous`,
`captured:unlinked`, `wrong` or `missing`. Recomputing from its stored
second smoke run over every process class gives 26 ambiguous of 58 linked
(45%), and 17 of those 26 are hook-program processes. The plan's 41% is
close to this but the stored reports do not reproduce it exactly, so the
first step below is a fresh baseline, not a reuse of the old number.

**Definition.**

```text
ambiguous_share = linked:ambiguous / (linked:certain + linked:tentative + linked:ambiguous)
```

over the ground-truth items of the classes `proc:*` and, once captured,
`file_write(in-process)`, for the Python shapes A-modal, A-local, B, C, E
and F. It is reported three ways, because the lane changes two things at
once: all classes; without `proc:hook_program` (spec 057 P2a turns
declared hook programs into hook rows, which removes them from this
population on its own); and file effects only.

**Procedure.** Same harness commit, same configuration and seeds, tier
`smoke` (about 40 to 70 real model calls per run), capture policy
retaining `terminal.argv`, `terminal.stdout`, `artifact.locator` and the
model request and response bodies.
1. **Baseline:** Fabric at the commit the lane starts from, with
   `FABRIC_WIRE_EXEC=1`.
2. **Hooks only:** Fabric at unit 053-a4, adding
   `FABRIC_WIRE_EXEC_AUDIT=1` and `FABRIC_WIRE_FILE_AUDIT=1`. This
   measures capture (the "0 of 7" file writes), before any linking change.
3. **Links:** Fabric at unit 056-c6, same switches.
4. **Metadata only:** as 3 with a metadata-only policy, to show the
   content tests report `not_applicable` and only `execution_context`
   narrows.

**Reported for each run:** the three shares; the count of `wrong` links;
`attribution.links` by basis and state; `attribution.content_match`; the
file-write capture count.

**Gates.**
- `wrong` is 0 in every run. One wrong link fails the measurement,
  whatever the share.
- File writes: 7 of 7 captured in runs 2 and 3 (or all of the run's
  ground-truth writes when the count differs).
- The share has no numeric gate (OQ12-4). What must hold exactly is the
  in-repository scenario below.

**What the harness needs** (changes in the owner's repository, outside
this lane): the comparator joins `file_write` ground truth to `file.audit`
effects by path (today it marks every one `missing` without looking); it
adds an `os.system` process class; its agent images set the two new
switches; its link classifier keeps working unchanged, because the action
view's link fields keep their names.

**In-repository stand-in (unit 056-c6).** The harness needs real model
calls and cloud resources, so CI cannot run it.
`qualification/action-record/link_ambiguity/` replays recorded,
framework-free runs shaped like the harness's: parallel calls with
different commands; parallel calls with identical commands; two sessions
on two threads; two sessions as two asyncio tasks; a tool on a worker
thread; a result cut to a length limit; a wrapped command; an in-process
file write named by a relative path; a declared hook program beside a
tool process. `run.py` computes the same `ambiguous_share` with the
revision 11 rules (the reference implementation with the new tests
switched off) and with the revision 12 rules, and asserts the exact
expected counts for both, and zero wrong links against the scenario's
ground truth.

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
(file, database, MCP, SSH) keep 053's order. M2 also moves the 053 §5.4
HTTP channel forward without its two dialects (WP6-09a); `jsonrpc2` and
`qdrant_rest_v1` stay with 053 WP4-05.

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

Goal: reconstruct what an agent did **in production**. AR-1 passes against
a production-profile Node, with the eBPF emitter in production mode, in CI
(§6.2 "AR-1 production"), and its hermetic replay passes locally.

M2 builds these 053 work packages under this spec's ordering (OD-1), with
the 053 revision 3 and 4 amendments: WP4-07a/b/c, WP4-08a/b and WP4-09. 053
WP4-01's rows that M2 needs are applied by WP6-11; WP4-10b's host reader
exists from M1 and is extended by WP6-12. Each WP below states the exact
names that cross its boundary (§7.3.3); a builder who needs a name not
listed there stops and asks the spec owner, never invents one.

#### 7.3.1 Waves

| Wave | Python track | Go and deployment track |
|---|---|---|
| A | WP6-11 (single, first) | — |
| B | WP6-08, WP6-09a, WP6-12 | WP4-07a, WP4-08a, WP4-08b |
| C | WP6-09b (after WP6-09a merged) | WP4-07b, WP4-07c (after WP4-07a merged); WP4-09 (after WP4-08a and WP4-08b merged) |
| D | WP6-10 (joins both tracks; last) | |

Every WP in a wave is independent of the others in that wave except the
intra-wave dependencies named in the table. No WP of wave B or C edits a
file another one owns (§7.3.4).

**OD gate.** Wave A starts when the owner has answered OD-8 to OD-12
(§9). Each of them names the WPs it shapes and a fallback; when the owner
takes a fallback, the spec owner amends §7.3 before wave A, and no builder
applies a fallback on their own.

#### 7.3.2 Work packages

| WP | Owner area (exact; *new* marks a path that does not exist at v0.10.0) | Depends | Delivers | Exit (named tests) |
|---|---|---|---|---|
| **WP6-11 Contracts** | `contracts/coverage/v1/**`, `contracts/capture/v1/**`, `contracts/connect/v1/manifests/{ebpf-host-emitter,auditd-host-connector,python-sdk}.json`, `scripts/contracts/**`, `scripts/tests/test_{coverage,capture,connector}_contracts.py`, `scripts/tests/test_contract_generators.py`; the generated tables `sdk/python/src/fabric/{_records_keys_generated,_manifest_fields_generated,_roles}.py`, the generated block of `processor/fabricguardprocessor/coverage_keys.go`, `exporter/fabriccontentexporter/evidence_types_generated.go` | — (starts after the OD gate, §9) | §5.1 in full: registry rows (with the `scope_late` upstream-loss reason), the two evidence types, vectors (`peer-address-v1`, `sandbox-id-v1`, `id-key-file-v1`, span category, records span), host fixtures and envelope vectors, ingress-group configuration goldens with their path convention and fixture token tree, the §6.1 M2 rule fixtures and interface goldens, reference rules H5 (any host source), the per-source pid-namespace mode and the namespace-aware anchor in `action_reference.py` | `python scripts/contracts/generate_p0_contracts.py --check`; `validate_coverage_contracts.py`, `validate_capture_contracts.py`, `validate_connector_contract.py` pass; new tests `test_coverage_contracts.py::test_056_m2_sensor_keys_are_s_scoped`, `::test_056_m2_rule_fixtures_match_reference`, `::test_056_m2_h5_is_reported_and_certain`, `::test_056_m2_refused_fixtures`, `::test_056_m2_peer_address_and_sandbox_id_vectors`, `test_capture_contracts.py::test_053_host_record_fixtures`, `::test_056_m2_id_key_file_vectors` (Python's `id_key_from_env` gives each vector's `hst-` and `s-` values), `::test_056_m2_run_reconstruction_attribution`, `::test_056_m2_ingress_group_goldens_parse`; every M1 test still passes |
| **WP4-07a Host-records library** | `components/otel-collector-fabric/hostrecords/**` *new* (Go module `github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords`, including the test-only command `hostrecords/cmd/hostrecords-replay`, which no image or release builds); one line in `components/otel-collector-fabric/Makefile` (`RECORDER_PROCESSOR_DIRS`); the module's entries in `.github/workflows/recorder-license.yml` and `.github/workflows/recorder-security.yml` | WP6-11 | 053 §6.2.2–§6.2.5 as the §7.3.3 (b) API: label and v2 pseudonyms, `ReadIDKeyFile`, peer text, sandbox-id derivation from a cgroup path, `epoch.state`, the allocator, persisted ids, the AES-256-GCM envelope, encrypted staging of every record and marker, span and marker builders, the upstream-loss accumulator; the replay command (§7.3.3 (m)) | `go test -race ./...` in the module: `TestLabelPseudonymVectors` (`run-id-pseudonym-v1.json`), `TestV2Vectors` (`pseudonym-v2.json`), `TestIDKeyFileVectors` (`id-key-file-v1.json`), `TestPeerTextVectors`, `TestSandboxIDVectors`, `TestEnvelopeVectors` (equal `fabricenvelopeextension`'s sealing for the host magic), `TestSpanGoldens` (equal `contracts/capture/v1/fixtures/host/`), `TestEpochRestartListsUnsealedPrior`, `TestReplayKeepsPositionsAndIDs`, `TestMarkersAreStagedAndReplayed` (manifest 0, heartbeat, `span_dropped` loss and `final` survive a crash before acknowledgement with the same event ids and `manifest_seq`), `TestOneHeartbeatPerLossReason`, `TestKeyRotation`, `TestCorruptStateRefusesStart`, `TestUpstreamLossUnknownStaysUnknown`, `cmd/hostrecords-replay`: `TestReplayCommandGolden` (an events file gives the host goldens' shape, posted with the token to a test OTLP/HTTP server); `go vet`; the module builds on linux and darwin |
| **WP4-07b auditd production mode** | `components/otel-collector-fabric/receiver/auditreceiver/**`; `components/otel-collector-fabric/ocb-config.yaml` (the `hostrecords` `replaces:` line); `components/otel-collector-fabric/Dockerfile` (one `COPY hostrecords ./hostrecords` line, without which the Node image no longer builds) | WP4-07a merged | 053 §6.2.8: `mode: production` (§7.3.3 (d)), a traces creator in `factory.go`, translation to host records through the library, the id key read with `ReadIDKeyFile`, logfile cursor advanced only after full acknowledgement, netlink and logfile losses as upstream loss; local mode unchanged | `TestProductionTracesGolden`, `TestLogfileCursorAdvancesOnlyAfterAck`, `TestNetlinkOverflowIsUpstreamLoss`, `TestStagedReplayKeepsIDs`, `TestRotationAndTruncationReasons`, `TestProductionRefusesWithoutLabelOrKey`, `TestCanariesNotInStagingOrCheckpoint`; every existing auditreceiver test; `make -C components/otel-collector-fabric test lint`; `docker build components/otel-collector-fabric` succeeds |
| **WP4-07c eBPF production mode** | `components/host-emitter/**`; the `host-emitter` job of `.github/workflows/recorder-ci.yml` (build context); the `publish-image` matrix of `.github/workflows/release.yml` (a per-component `context`: `components/` for `host-emitter`, unchanged for `otel-collector-fabric`) | WP4-07a merged | 053 §6.2.9 with §7.3.3 (c): `struct event` gains the group leader's `start_boottime`, `ns_pid`, `ns_ppid` (the parent's tgid, §4.3), `pid_ns` inode and, for sandbox-scope events, the kernfs names of the cgroup and its parent; root-based scope (a hash map of root cgroup ids walked with `bpf_get_current_ancestor_cgroup_id`, deepest root wins) for static agent and sandbox roots and for the pod roots of `EMIT_AGENT_POD_SELECTOR` (an API-server watch of the node's pods over plain HTTPS with the service-account token, no client library; `scope_late` upstream loss); container and pod ids from those names; traces export of host records through the library; encrypted spool; ring-buffer and rate-limit loss as upstream loss; partial-success quarantine as `span_dropped`; `EMIT_ENDPOINT_FILE`; `print-source-id` subcommand; the Docker build gains the library (context `components/`) | `go test ./...`: `TestProductionTranslateGolden`, `TestProductionRefusesDedupeAndMissingKeys`, `TestProductionRefusesExactCgroupPath`, `TestEncryptedSpoolHasNoClearBytes`, `TestPartialSuccessQuarantineIsSpanDropped`, `TestRestartReplayNoIDChurn`, `TestKernfsNamesToSandboxIDs`, `TestUnresolvableCgroupHasNoIDs`, `TestPodWatcherInstallsAndRemovesRoots` (fake API server and fake cgroupfs: a matching pod's slice is installed when it appears and removed after deletion; a non-matching pod and another node's pod are not), `TestScopeLateIsUpstreamLoss`, `TestEndpointFileExclusive`; Linux, privileged container (`go generate` with clang and libbpf): the existing `e2e-emitter.sh` gains `--production`, which runs `TestNamespacePidsMatchProc` (a workload in its own pid namespace: `ns_pid` equals `/proc/<pid>/status` `NSpid`, `pid_ns` equals the `ns/pid` inode, `process_start_ns // 10⁷` equals `/proc/<pid>/stat` field 22, and for a child spawned from a second thread `ns_ppid` equals the child's own `getppid()` and `PPid` read from a `/proc` mounted inside the namespace), `TestAgentRootPodShape` (an agent root `…/e2e-pod<uid>.slice` with two `cri-containerd-<64 hex>.scope` children created at run time: both containers' events are scope `agent`; a sibling outside the root is not emitted) and `TestSandboxRootScope` (a short-lived container cgroup removed right after its exec still carries its container id); `docker build -f components/host-emitter/Dockerfile components` succeeds |
| **WP4-08a Gate** | `components/otel-collector-fabric/gate/**` | WP6-11 (ingress-group goldens) | 053 §6.1 rules 1–10 and §6.2.6 rules 1–5 over the merged graph when any `fabricguard/<group>` instance exists (new file `gate/groups.go`); the sensor-collector profile (§7.3.3 (f)); the legacy single binding path (`checkDedicatedEvidenceIngress`) unchanged (053 revision 4 §6.1) | `TestIngressGroupGoldens` (every `valid/` passes, every `invalid/` fails with its named error, run over the fixture token tree with the prefix rewrite), `TestGroupCredentialBytesCompared`, `TestGroupCrossWiringRefused`, `TestHostGroupHasOnlyTracesPipeline`, `TestSensorProfileRefusesOtherComponents`, `TestGroupLimits` (64 default, 256 ceiling), `TestLegacySingleBindingStillPasses`, `TestMixingLegacyAndGroupsRefused`; every existing gate test |
| **WP4-08b fabricguard** | `components/otel-collector-fabric/processor/fabricguardprocessor/**` except the generated block of `coverage_keys.go` | WP6-11 (generated tables) | `source_kind` and `host_digests` (§7.3.3 (e)); §6.2.7 admission in that order; the `fabric.sensor_event` branch of `categorise`; `remote.sandbox` in `capturePointKinds` (`records.go`); agent-side refusal of S-kind spans and of any `fabric.sensor.*` key | `TestHostAdmissionOrder` (one case per §6.2.7 step), `TestHostBatchWithAgentRecordRefused`, `TestAgentBatchWithSensorKeyRefused`, `TestHostDigestsNeedBothPermissions`, `TestSensorEventCategory` (`span-category-v1.json`); the existing `TestRecordsSpanVectors` (now with the `records-span-v1.json` host cases) and `TestCapturePointKinds` (with `remote.sandbox`); every existing fabricguard test |
| **WP4-09 Deployment** | `charts/**`; `deploy/compose/**`; `deploy/kubernetes/host-emitter-daemonset.yaml`; `deploy/kubernetes/auditd-sensor-collector.yaml` *new*; `deploy/kubernetes/host-bindings.py` *new*; `scripts/tests/test_host_emitter_manifest.py`; `scripts/tests/test_compose_host_ingress.py` *new*; `scripts/tests/test_host_bindings.py` *new* | WP4-08a and WP4-08b merged (renders are checked by the gate) | Chart values `receiver.sourceBindings[]` (§7.3.3 (g)), Service ports, Secrets, NetworkPolicy, the profile `charts/fabric/profiles/shadow-production-host-ingress.yaml` *new*; Compose overlays and configurations (§7.3.3 (h)), with the auditd group on OTLP/HTTP; `deploy/compose/qualify-sensor-auditd.sh` *new* (the sensor collector in logfile mode on a fixture `audit.log`, through its group, to the sink); the per-node topology of §7.3.3 (n): the production DaemonSet (per-node hostPath provisioning, `EMIT_SOURCE_LABEL=$(NODE_NAME)/ebpf`, the pod selector and its read-only RBAC, the dedicated-node-pool note), the sensor-collector example and the bindings generator. No sensor workload in the chart (OD-10) | `charts/fabric/charts/otel-collector/tests/test-source-bindings.sh` *new* (render, then `fabric-gate` on the render; equals the `ingress-groups/valid/agent-ebpf-auditd.yaml` and `valid/agent-ebpf-three-nodes.yaml` goldens after normalisation; 64/256 limits; legacy and mixed forms; cross-wiring and duplicate-secret negatives); `charts/fabric/tests/test-values-schema.sh` with new `invalid-values/source-bindings-*.yaml`; `charts/fabric/tests/test-package-boundary.sh` (no privileged workload in the package); `scripts/tests/test_compose_host_ingress.py` (merged config passes `fabric-gate`; preflight refuses equal token bytes and equal source labels; the sensor-collector config passes the sensor profile); `scripts/tests/test_host_emitter_manifest.py` (production env complete, no secret in the manifest, RBAC only `get`, `list`, `watch` on `pods`); `scripts/tests/test_host_bindings.py` (source ids equal `run-id-pseudonym-v1.json` and `print-source-id`; one group per node; distinct tokens; no secret on standard output); `deploy/compose/qualify-sensor-auditd.sh` green on Linux (run by WP6-10's CI job) |
| **WP6-08 Exec record for production and containers** | `sdk/python/src/fabric/hooks/_exec.py`; `sdk/python/tests/test_hooks_exec.py`, `test_hooks_exec_passivity.py`, `test_hooks_exec_sandbox.py` *new* | WP6-11 | §7.3.3 (a): the start time read before the child can be reaped (OD-8), zombie state accepted, `SC_CLK_TCK == 100` only; `fabric.process.pid_ns`; `fabric.sandbox.created_id` from the outcome's standard output on the capture worker | `test_hooks_exec.py::test_start_ns_read_before_reap` (a child that exits at once still carries `start_ns`), `::test_start_ns_absent_for_other_clock_tick`, `::test_pid_ns_is_proc_self_ns_inode`; `test_hooks_exec_sandbox.py` (every runtime output form of `sandbox-id-v1.json`; shell-string and argv forms; no id under `omit`, without a key, for a foreground `run`, a compound shell command or a mismatching output; parsing happens on the worker); `test_hooks_exec_passivity.py` P4-EXEC start budget (50 µs) still holds with the read |
| **WP6-09a HTTP channel and hooks configuration** | `sdk/python/src/fabric/hooks/{__init__,_config}.py` (integration owner), `hooks/_http.py` *new*, `sdk/python/src/fabric/wire/_routes.py` *new*, the route call in `wire/_transport.py`; `sdk/python/tests/test_hooks_http.py` *new*, `test_hooks_http_passivity.py` *new*, `test_wire_routes.py` *new*, `test_hooks_foundation.py` | WP6-11 | 053 §5.4 without dialects (`dialect: none`), §3.1 pieces and redirects; the route table (§7.3.3 (j)); `install(http_hosts=…, remote_sandbox=…, sandbox_hosts=…)` and their environment switches (§7.3.3 (i)), including the `remote.sandbox` slot in `CHANNELS` and the `remote_sandbox` manifest row; `FABRIC_WIRE_HTTP_HOSTS` leaves `NOT_IN_BUILD_ENV` | `test_wire_routes.py` (route-table golden; model routing unchanged with the HTTP hook off); `test_hooks_http.py` (host confusion: IDNA, case, port, scheme, no substring; each redirect hop its own attempt; partial consumption, early close, cancellation; no headers recorded; bearer canary); `test_hooks_http_passivity.py` (P4-HTTP: 50 µs per exchange, 2 µs per chunk, 5 µs non-matching; blocking-injection control); `test_hooks_foundation.py` (config error matrix for the three new arguments; environment never raises; manifest row `remote.sandbox` disabled(`remote_sandbox`) when only sandbox hosts are set) |
| **WP6-09b Remote sandbox: E2B** | `sdk/python/src/fabric/hooks/{_sandbox,_sandbox_e2b}.py` *new*; `sdk/python/pyproject.toml` (extra `hooks-sandbox-e2b` pinning `e2b==2.62.*`, `e2b-code-interpreter==2.11.*`; test deps); one matrix entry `hooks-sandbox-e2b` in the Python job of `.github/workflows/recorder-license.yml` and, when the inventory needs it, `.github/license-allowlist.txt` (after WP4-07a's edit of the same workflow); `sdk/python/tests/test_hooks_sandbox_e2b.py` *new*, `test_hooks_sandbox_passivity.py` *new*; `qualification/remote-sandbox/**` *new* (fixture E2B server, ledger, `pins.json`) | WP6-11; **WP6-09a merged** (configuration and channel slot) | §4.4.1 records (§7.3.3 (k)); version check at install (`unsupported_version` outside the pins); the fixture server answering the pinned SDK's control-plane and envd calls on a configurable address (`E2B_API_URL`, `E2B_SANDBOX_URL`), its ledger holding variable names and canary booleans, never values | `test_hooks_sandbox_e2b.py` against the fixture server: foreground, background plus `wait`, `CommandExitException`, `retain_output=False`, `run_code` with stdout, results and an error, a transport error, async variants; returned objects are the SDK's own (identity); callbacks never called by Fabric; canaries (`E2B_API_KEY`, an `envs` value) never stored, the fixture ledger included; `qualification/remote-sandbox/test_fixture_ledger.py` (the fixture's request ledger equals the agent's calls: no extra request); `test_hooks_sandbox_passivity.py` (P4-SANDBOX: 50 µs per start or outcome, 5 µs when the hook is off or the provider is not enabled; blocking-injection control); the license inventory lists `e2b`, `e2b-code-interpreter` and `pyqwest` |
| **WP6-12 Reconstruct for production** | `sdk/python/src/fabric/reconstruct/**`; `sdk/python/tests/test_reconstruct_action_host.py`, `test_reconstruct_host.py`, `test_reconstruct_attribute_export.py`, `test_reconstruct_action_production.py` *new* | WP6-11 | §7.3.3 (l): host records and host-source markers split from agent records before verification (the host-source rule); production source verification (positions, heartbeats, upstream loss, authentication stamp); the per-source pid-namespace mode and the namespace-aware anchor; the agent's namespace from its effects; H5 on any host source; the scope rule; `remote.sandbox` effects in §4.2; `attribution.sandbox_events_unlinked` and `remote_sandbox_calls`; `effects` reason `remote_sandbox`; `peer_id` per `peer-address-v1`; the action view rows of §4.6; CLI options | Every M1 and M2 rule fixture gives its expected output through the SDK (`test_reconstruct_action_host.py::test_rule_fixture_with_the_real_host_join`, parametrised over `rules/*.json`); `test_reconstruct_action_production.py`: a Node-shaped export with agent and host records gives the same report as the fixture input; host records and host-source markers never enter `sources[]` gaps, segments or seals, a quiet host epoch and a declared source with nothing included; imported (unstamped) host records give `corroboration` `unverified(source_unauthenticated)` under `--profile production`; a heartbeat-less tail is `source_gap`; an export with eBPF and auditd records joins each by its own mode; no `certain` link without a start-tick match or a reported sandbox id |
| **WP6-10 AR-1 production** | `qualification/action-record/**`; `.github/workflows/action-record.yml`; `scripts/tests/test_recorder_release_boundary.py` (M2 additions); `docs/action-reconstruction.md`, `docs/host-sensors.md` (production section, the Kubernetes topology), `docs/reconstruct.md` (new options); `specs/README.md` (056 and 053 status lines); `CHANGELOG.md` | all of the above merged | §6.2 "AR-1 production" and its hermetic replay (§7.3.3 (m)); CI jobs `production-replay` (ubuntu-latest, macos-latest; Go set up for the replay command), `production-live` (ubuntu-24.04, Docker with the systemd cgroup driver, sudo) and `production-auditd` (ubuntu-latest, runs WP4-09's `qualify-sensor-auditd.sh`); release-boundary checks that the default wheel installs no provider SDK, the chart packages no privileged workload, no image or release builds `hostrecords-replay`, and no image or wheel gains an evaluator, policy or enforcement component | `qualification/action-record/tests/test_ar1_production_replay.py::test_ar1_production_replay` (two host groups, the quiet one included); `run_ar1.py --profile production --mode live` green in CI with every variant (base, a–h), the bwrap branch asserted, and the canaries; `production-auditd` green; `scripts/tests/test_recorder_release_boundary.py`; markdownlint; the 056 and 053 status lines changed only after the three CI jobs pass |

#### 7.3.3 Interfaces between work packages

Every name below is normative for M2. Registry checks are in WP6-11's rows.

**(a) Exec record (WP6-08 → WP6-12, WP6-10).** On `exec.subprocess`
records, in addition to M1's keys:

| Key | Record | Value | Read by |
|---|---|---|---|
| `fabric.process.start_ns` | `start` | M1 meaning; read once on the calling thread right after `Popen.__init__` returned (open, read, close of `/proc/<pid>/stat`; no other I/O), else by the worker as in M1; state `Z` (zombie, not yet reaped) accepted; absent unless `os.sysconf("SC_CLK_TCK") == 100` | caller (OD-8), worker fallback |
| `fabric.process.pid_ns` | `start` | decimal `os.stat("/proc/self/ns/pid").st_ino`, cached per process id (reset after fork); Linux only | worker (`late`) |
| `fabric.sandbox.created_id` | the record that carries the first observed standard output (`end`, `data` or `update`) | `sbx-` v2 of the clear text below; absent without an id key, when the role `terminal.stdout` is `omit`, or when nothing matches | worker (`late`) |

Container create forms (argv, or a shell string that `shlex.split` turns
into one simple command with no `;`, `&`, `|`, `&&`, `||`, `<`, `>` token;
`argv[0]` compared by basename):

| Command | Standard output (after removing one trailing newline) | Clear text |
|---|---|---|
| `docker`, `podman`, `nerdctl` with subcommand `run` and `-d` / `--detach` (also in a combined short flag such as `-dit`), or subcommand `create`; `container run`/`container create` accepted | exactly `^[0-9a-f]{64}$` | `container:<64 hex>` |
| `kubectl` `run`, `create` or `apply` with `-o jsonpath={.metadata.uid}` (quoted or not) | exactly a lowercase UUID | `k8s-pod:<uid>` |
| `kubectl` `run`, `create` or `apply` with `-o json` | a JSON object of at most 1 MiB whose `kind` is `Pod` and `metadata.uid` is a UUID | `k8s-pod:<uid>` |

**(b) Host-records library (WP4-07a → WP4-07b, WP4-07c, WP6-10).** Package
`hostrecords`:

```go
type Kind string // "host.ebpf" | "host.auditd"
type Config struct {
    Kind        Kind
    Version     string // capture point version, "<component version>"
    TenantID    string
    SourceLabel string // clear label; refused empty or equal to another source's
    HostLabel   string // the agent's FABRIC_HOST_LABEL value on this host
    IDKey       []byte // >= 16 bytes; the agents' FABRIC_WIRE_ID_KEY (ReadIDKeyFile)
    StateKey    []byte // 32 bytes; seals epoch.state, staging, spool and cursor
    StateDir    string // 0700, owned by the sensor; refused if shared
    Digests     bool   // sensor policy digests: permitted
    Classes     []string // enabled event classes for the manifest row
}
// Every record and every marker reaches the exporter as a staged *Batch:
// sealed in the state directory with its positions and persisted uuid4
// event ids before it is first sent, returned by Pending() until
// Acknowledge, and replayed after a restart with the same ids, sequences
// and manifest_seq. Nothing is sent unstaged.
func Open(cfg Config) (*Source, error) // new epoch; stages the prior epoch's heartbeat (if unsealed) and manifest 0
func (s *Source) SourceID() string     // "s-" + label pseudonym
func (s *Source) Epoch() uint64
func (s *Source) Stage(events []Event) (*Batch, error) // positions + ids, one fsync per batch
func (s *Source) Pending() ([]*Batch, error)         // staged, unacknowledged, oldest first: records and markers
func (s *Source) Acknowledge(b *Batch) error
func (s *Source) Quarantine(b *Batch, rejected int) (*Batch, error) // stages the span_dropped loss marker; b kept sealed
func (s *Source) UpstreamLoss(reason string, count int64) // count -1 = unknown; accumulated per reason
func (s *Source) Heartbeat() (*Batch, error) // stages this interval's periodic heartbeat span(s)
func (s *Source) Manifest() (*Batch, error)  // stages the next manifest (manifest_seq + 1), on a configuration change only
func (s *Source) Close(final bool) (*Batch, error) // final: stages the final marker; epoch.state gets final once it is acknowledged; nil batch when !final
func (b *Batch) Traces() ptrace.Traces // fabric.sensor_event spans or marker spans, 053 §6.2.3
func ReadIDKeyFile(path string) ([]byte, error)  // id-key-file-v1
func LabelPseudonym(prefix, value string, key []byte) string
func V2(prefix, value string, key []byte) string // "" without a key
func PeerText(addr netip.Addr) string            // peer-address-v1
func SandboxIDs(cgroupPath string) (container, podUID string) // sandbox-id-v1; a full path or its last two components
```

- **Upstream loss per heartbeat.** A heartbeat span carries one
  `upstream_loss_reason`, so `Heartbeat()` stages one heartbeat span per
  reason accrued since the previous heartbeat, all at the same last
  sequence, in the order of the 053 §6.2.4 enum, each with its own count
  (−1 when any report of that reason had an unknown count) and its own
  event id. An interval with no loss stages one heartbeat with
  `upstream_lost = 0` and no reason. The verifier reads every heartbeat of
  an interval.
- **The id key file.** `ReadIDKeyFile` returns the file's bytes unchanged:
  they are the key exactly as `FABRIC_WIRE_ID_KEY` holds it, which Python
  uses as its UTF-8 bytes (`_sequence.id_key_from_env`). There is no hex or
  base64 decoding and no trimming. The file must be a regular file of mode
  0400 or 0440 holding 16 to 4096 bytes of UTF-8 with no NUL. A file that
  ends with `\n` or `\r` is refused, so a newline added by an editor or
  `echo` can never silently give a key different from the agents' (the
  deployment examples write it with `printf %s`, and the same Secret feeds
  the agents' environment). Errors never include the file's contents. The
  auditd receiver and the eBPF emitter read the id key only through this
  function.

`Event` holds exactly the 053 §6.2.3 values (amended) before keying:
`TimeUnixNano`, `Class`, `Syscall`, `Result`, `Errno`, `Pid`, `Ppid`,
`NsPid`, `NsPpid`, `PidNS`, `ProcessStartNs`, `CgroupID`, `Scope`,
`ContainerID`, `PodUID`, `PeerFamily`, `Peer` (`netip.Addr`), `PeerPort`,
`AuditSerial`, `Incomplete`, `ExeSHA256`, `ArgvSHA256`, `PathSHA256`
(optional values as pointers or empty strings). The library keys ids, drops
digests unless `Digests`, and never logs a value.

**(c) eBPF emitter configuration (WP4-07c → WP4-09, WP6-10).** Environment
variables, as the emitter reads today (`loadConfig` in `main.go`); 053
§6.2.9's flag names are replaced by these (053 revisions 3 and 4):

| Variable | Meaning |
|---|---|
| `EMIT_PRODUCTION` | `true` selects production mode (host records as traces); default `false` (local mode, unchanged) |
| `EMIT_TENANT_ID`, `EMIT_SOURCE_LABEL`, `EMIT_HOST_LABEL` | Required in production |
| `EMIT_ID_KEY_FILE`, `EMIT_STATE_KEY_FILE`, `EMIT_STATE_DIR` | Required in production; key files 0400/0440, the directory 0700 |
| `EMIT_CGROUP_PATH` | Local mode only (exact cgroup, unchanged). Production refuses it with an error naming `EMIT_AGENT_CGROUP_ROOTS`, because an exact match cannot scope a pod |
| `EMIT_AGENT_CGROUP_ROOTS` | Production: comma-separated cgroup v2 directories, at most 8, each existing at start (else refused); each and its descendants are scope `agent` |
| `EMIT_AGENT_POD_SELECTOR`, `EMIT_NODE_NAME` | Production, Kubernetes (OD-12): a label selector (`key=value` terms joined by `,`, as `kubectl -l` takes them) and the node name (from `spec.nodeName`). The emitter watches the API server's pods with `fieldSelector=spec.nodeName=<node>` and the selector (in-cluster service account, read-only `get`, `list`, `watch` on `pods`; plain HTTPS with the mounted CA, no client library), and installs the pod slice of each matching pod as an agent root when the slice appears under `/sys/fs/cgroup` (watched with inotify on the QoS slices), at most 64 pod roots; a root is removed when its pod is deleted. A root installed after a non-sandbox container cgroup already exists in the slice gives upstream loss `scope_late` (−1). API errors are retried with backoff and reported through the emitter's health counters; they never stop capture of the roots already installed |
| `EMIT_SANDBOX_CGROUP_ROOTS` | Comma-separated cgroup v2 directories, at most 8, each existing at start (else refused); their descendants are scope `sandbox` |
| (scope rules) | Production needs at least one agent root or the selector, or `EMIT_ALL_HOST=true` (every event scope `agent`, so every unlinked one is listed unexplained). Roots may nest; the deepest root that contains the event's cgroup decides its scope. The BPF program keeps all roots in one hash map (cgroup id → scope, at most 256 entries) and walks `bpf_get_current_ancestor_cgroup_id` from level 1 to 32 |
| `EMIT_DIGESTS` | `omitted` (default) or `permitted` |
| `EMIT_HEARTBEAT_INTERVAL` | Default `10s`, 1 s to 60 s |
| `EMIT_ENDPOINT`, `EMIT_BEARER_TOKEN_FILE`, `EMIT_TLS_*`, `EMIT_INSECURE` | Unchanged; production refuses `EMIT_INSECURE=true` to a non-loopback endpoint |
| `EMIT_ENDPOINT_FILE` | Alternative to `EMIT_ENDPOINT` (setting both is refused): a file holding one line `host:port`, so a per-node provisioning directory can name each node's own group port (§7.3.3 (n)) |
| `EMIT_DEDUPE_WINDOW` | Must be `0` in production: every event keeps its own position |

`fabric-host-emitter print-source-id` prints the `s-` id for the
configured label and key and exits; the operator puts it in the Node's
group (`sourceId`). The key files are read with `ReadIDKeyFile` and the
state-key rules of 053 §6.2.5.

**(d) auditd receiver production configuration (WP4-07b → WP4-09).** The
`audit` receiver gains:

```yaml
receivers:
  audit:
    mode: production            # default local (logs, unchanged)
    production:
      tenant_id: ...
      source_label: <node>/auditd
      host_label: <the agents' FABRIC_HOST_LABEL>
      id_key_file: /run/secrets/fabric_id_key   # read with hostrecords.ReadIDKeyFile
      state_key_file: /run/secrets/fabric_sensor_state_key
      state_dir: /var/lib/fabric-sensor/auditd
      digests: omitted          # or permitted
      heartbeat_interval: 10s
```

**(e) fabricguard configuration (WP4-08b → WP4-08a, WP4-09).**
`source_kind`: `agent`, `host.auditd` or `host.ebpf`; absent means the
legacy single-source behaviour (`agent`). `host_digests`: `omitted`
(default) or `permitted`; refused on an `agent` instance. A host instance
requires `profile: production` and `evidence_source_binding`.

**(f) Node group configuration (WP6-11 goldens → WP4-08a, WP4-09).** Group
`<g>` matches `^[a-z][a-z0-9-]{0,31}$` and does not start with `content`
(fabric-gate reads `otlp/content…` and `logs/content…` as content
components). Component ids:

| Component | Id | Group kinds |
|---|---|---|
| Authenticator | `bearertokenauth/<g>` (`filename`, `require_single_token: true`) | all |
| Telemetry receiver | `otlp/<g>` (gRPC and/or HTTP; TLS unless loopback) | all |
| Content receiver | `otlp/content-<g>` (HTTP) | `agent` with content |
| Guard | `fabricguard/<g>` with `profile: production`, `source_kind`, `evidence_source_binding` | all |
| Content exporter | `fabriccontent/<g>` with `source_binding`, its own `sending_queue.storage` (`file_storage/fabric_content_<g>` or `fabricenvelope/fabric_content_<g>`) | `agent` with content |
| Pipelines | `traces/<g>`; `logs/<g>` (`agent` only); `logs/content-<g>` (`agent` with content) | |

Every telemetry pipeline is `[otlp/<g>] → [memory_limiter, fabricguard/<g>,
batch?] → [approved telemetry exporters]`. A configuration either has no
`fabricguard/<g>` (the legacy single binding, rendered and checked as today,
053 revision 4 §6.1) or has only group instances (no plain `fabricguard`).
The **sensor-collector profile** applies when an `audit` receiver sets
`mode: production`: exactly that receiver, one `traces` pipeline with
processors from `[memory_limiter, batch]`, one `otlp_http/<x>` exporter
(the only OTLP exporter the Node build contains; `ocb-config.yaml` has no
gRPC exporter, and M2 adds none) with TLS (or loopback), the no-redirect
egress rule and a client `bearertokenauth/<x>` authenticator reading a
token file, and no other receiver, exporter, processor or pipeline. A
`host.auditd` group therefore listens on OTLP/HTTP.

**(g) Chart values (WP4-09).** Under `otel-collector.receiver`:

| Value | Rule |
|---|---|
| `sourceBindings[]` | 053 §6.1 table: `name`, `tenantId`, `sourceId`, `kind`, `tokenSecret {name, key}`, `protocols {grpc?, http?}` (ports), `content {port}` (agent only, needs `content.enabled`), plus `hostDigests` (host kinds only; `omitted` default) and `ingressFrom` (NetworkPolicy peers for this group's ports; default the chart's `networkPolicy.ingressFrom`) |
| `maxSourceBindings` | Default 64, at most 256 |

A non-empty `sourceBindings` with `evidenceSourceBinding.enabled` or
`workloadAuthentication.enabled` fails the render; so do duplicate names,
ports, `(tenantId, sourceId)` pairs or token Secret references. Tokens
mount at `/etc/fabric/ingress/<name>/token`. Service ports are named
`g<index>-grpc`, `g<index>-http` and `g<index>-content` (Kubernetes port
names are at most 15 characters). The profile
`shadow-production-host-ingress.yaml` layers on `shadow-production.yaml`
with one agent group and one `host.ebpf` group per node to fill in, in the
shape `deploy/kubernetes/host-bindings.py` generates (§7.3.3 (n)).

**(h) Compose (WP4-09 → WP6-10).** `docker-compose.host-ingress.yml`
(overlay on `docker-compose.production.yml`) runs the Node with
`collector-config/collector-production-groups.yaml` (agent and `ebpf`
groups), plus `collector-production-groups-auditd.yaml` and
`collector-production-groups-content.yaml` when those are enabled; Make
targets `up-prod-groups` and `up-sensor-auditd`
(`docker-compose.sensor-auditd.yml`, `collector-config/sensor-auditd.yaml`).
Variables: `FABRIC_TENANT_ID`; `FABRIC_AGENT_SOURCE_ID` with
`FABRIC_INGRESS_TOKEN_FILE` (ports 4317, 4318, content 4319);
`FABRIC_EBPF_SOURCE_ID`, `FABRIC_EBPF_TOKEN_FILE` (`FABRIC_EBPF_GRPC_PORT`,
default 4417; the emitter's own OTLP client is gRPC); `FABRIC_AUDITD_SOURCE_ID`,
`FABRIC_AUDITD_TOKEN_FILE` (`FABRIC_AUDITD_HTTP_PORT`, default 4428, because
the sensor collector exports with `otlp_http`). `preflight-prod.sh` refuses
equal token bytes across groups and an unset source id for an enabled
group. `qualify-sensor-auditd.sh` runs `up-sensor-auditd` with the receiver
in logfile mode on a checked-in fixture `audit.log` (no kernel audit
needed) and asserts that the sink holds authenticated `host.auditd`
records, manifests and heartbeats of the expected source.

**(i) Hooks API and switches (WP6-09a → WP6-08, WP6-09b).**

```python
fabric.hooks.install(
    exec=False, host_label=None,
    http_hosts=(),        # exact canonical "host" or "host:port"; https unless "http://" given
    remote_sandbox=(),    # providers; only "e2b" in M2
    sandbox_hosts=(),     # declared provider hosts (manifest only)
)
```

Environment: `FABRIC_WIRE_HTTP_HOSTS` and `FABRIC_WIRE_SANDBOX_HOSTS`
(JSON arrays of strings), `FABRIC_WIRE_REMOTE_SANDBOX` (comma-separated;
revision 8: a provider this build does not have, such as `modal`, is
dropped with one warning and disables only `remote.sandbox`, which
`status()` reports as `disabled(unsupported_provider)`; the manifest keeps
`disabled(hook_disabled)` or `disabled(remote_sandbox)`, and every other
hook and capture run).
`CHANNELS` gains `http.nonmodel` (module `fabric.hooks._http`) and
`remote.sandbox` (module `fabric.hooks._sandbox`, which dispatches to
`_sandbox_e2b`). `HooksConfig.requested(point)` covers both. When
`sandbox_hosts` is non-empty and `remote_sandbox` is empty, the handle
publishes `capture_point_changed("remote.sandbox", "disabled",
"remote_sandbox")`.

**(j) Route table (WP6-09a; next owner 054 WP5-00a).** `fabric.wire._routes`:
`register_route(rule: RouteRule) -> None` and `route(request) -> Route`,
`Route` one of `internal`, `owned`, `model`, `nonmodel`, `none`, in 053
§5.4 order. `_transport.py` calls `route()` once per request at the existing
capture decision; `model` keeps today's code path byte for byte.

**(k) Remote sandbox records (WP6-09b → WP6-12).** Capture point
`remote.sandbox@<sdk version>`, step kind `remote_exec`, `begin(provenance=
"observed")`; one attempt per `run`/`run_code` call; records per §4.4.1;
attributes `fabric.execution.sandbox_id` (`sbx-` v2 of `e2b:<sandbox_id>`);
evidence `fabric.sandbox.observation/v1`; bodies `remote.request`
(`application/json`), `remote.result` and `remote.stream` (`text/plain`,
`str` bodies, 053 §3.1). The `end` record's start time is the call's start;
the `start` record's start time is the effect's start time for §4.2.

**(l) Reconstruct (WP6-12 → WP6-10).**

| Name | Change |
|---|---|
| `_host.HostEvent` | adds `ns_pid`, `ns_ppid`, `scope`, `sandbox_id`, `pod_id` (all optional) |
| `_host.ProcessEffect` | adds `pid_ns`, `created_sandbox_id`; H1 and H2 compare the effect's own `pid_ns` (§4.3) |
| `_host.AgentProcess.pid_ns` | the value every effect's `fabric.process.pid_ns` agrees on, or `--agent-pid-namespace`; else `None` |
| `_host.HostSource.pid_namespace` | per source id: `recorded` when every host record of the source carries `fabric.sensor.pid_ns`, else `declared_same`; never one mode for a whole export |
| `_host.split_host_records(spans, declared: Collection[str] = ()) -> tuple[list[SpanRecord], HostEvidence]` | new: host records and their markers out of an export, before the agent verifier sees it. **Host-source rule:** a source id is a host source when any span of it (any epoch) is a host record (capture point kind `S`), or is a manifest whose capture-point rows are all of kind `S`, or the id is in `declared`. Every span of a host source (records, manifests, heartbeats, loss and `final` markers) goes to `HostEvidence`; every other span stays with the agent verifier. A host source never creates a `sources[]` entry |
| `_host.host_joiner(…, sandbox_peers: Collection[tuple[str, int \| None]] = ())` | new keyword: `(peer_id, port or None)` pairs |
| `_attribute.EFFECT_POINTS` | `{"exec.subprocess", "remote.sandbox"}`; the output an A1 match reads is `terminal.stdout` or `remote.result` |
| CLI (`actions`, `report`, `project`) | `--sandbox-peer ADDRESS[:PORT]` (repeatable; IPv6 with a port as `[ADDRESS]:PORT`): with a port, only connections whose `fabric.sensor.peer_port` equals it are sandbox calls; `--host-source KIND[=SOURCE_ID]` (a declared id is a host source by the rule above, and one with no records in the window is a `source_gap`); `--host-pid-namespace KIND=recorded\|declared_same` (repeatable; overrides the per-source default for every source of that kind); `--agent-pid-namespace NS`; `--host-records` optional when `--spans` holds host records; `--host-coverage-declared` refused for a source with production records |

**(m) AR-1 harness and replay command (WP6-10, WP4-07a).**
`run_ar1.py --profile local|production` (default `local`, today's
behaviour) with `--mode hermetic|live` for `local` and `--mode replay|live`
for `production`; `--variants` accepts `f`, `g`, `h` for `production`.
Files: `ar1/production.py` *new* (Compose, slices, certificates, tokens,
`print-source-id`), `ar1/agent.py` (steps 8 and 9, and step 4's
`--unshare-pid` with no fallback, under `AR1_PROFILE=production`),
`ar1/replay.py` (builds the events file and runs the replay command),
`ar1/expect.py` (§6.2 M2 table).

The replay command is Go, in the library's module, so the replay exercises
the library's staging, ids and markers rather than a copy of its span shape:

```text
go run ./cmd/hostrecords-replay \
    --config CONFIG.json      # hostrecords.Config without keys: kind, version, tenant, labels, digests, classes
    --id-key-file F --state-key-file F --state-dir DIR
    --events EVENTS.jsonl     # one hostrecords.Event per line (JSON field names = Go field names)
    --endpoint https://HOST:PORT/v1/traces --token-file F --ca-file F
    [--heartbeats N]          # N heartbeats after the events (default 1), then a final marker
```

It opens a source, stages the events in batches of 512, posts each pending
batch as OTLP/HTTP protobuf with the bearer token, acknowledges it on a
full success, exits nonzero on any refusal, and prints only counts. It is
built only by tests and CI (`go run` in `components/otel-collector-fabric/hostrecords`),
never by an image or release, and runs on linux and darwin.

**(n) Kubernetes topology: one host group per node (WP4-09 → WP6-10 docs).**
A sensor process is one source (053 §6.2.2), and a group binds one source
and one credential (053 §6.1), so a cluster of N nodes has N `host.ebpf`
groups (and N `host.auditd` groups when auditd runs), each with its own
source id, token and port on the Node. The 64-group default and 256 ceiling
bound the nodes one Node serves; a larger cluster deploys several Nodes,
each for a node pool, until the credential-to-source authenticator of 053
§6.1 exists.
- **Source label** `$(NODE_NAME)/ebpf`, with `NODE_NAME` from the downward
  API (`fieldRef: spec.nodeName`) and Kubernetes' dependent environment
  expansion; `EMIT_HOST_LABEL` is the agents' `FABRIC_HOST_LABEL` on that
  node, set the same way (`$(NODE_NAME)`).
- **Per-node credentials.** Each node's token is provisioned on that node
  only, in a hostPath directory `/etc/fabric-host-emitter/` (mode 0700,
  files 0400, owned by root): `token`, `state_key`, `endpoint` (the
  node's group as `host:port`, read through `EMIT_ENDPOINT_FILE`). The id
  key, which every agent and sensor shares, comes from a Secret. A single
  Secret holding every node's token is not used, because every emitter pod
  could then read, and present, every other node's credential. A node whose
  directory is missing or incomplete fails to start, visibly, and never
  falls back.
- **Generator.** `deploy/kubernetes/host-bindings.py --nodes FILE --tenant T
  --id-key-file F --base-port P --out DIR` (standard library only) writes
  the chart values fragment (`sourceBindings[]`, one `ebpf-<index>` group
  per node, ports `P + index`, a token Secret reference per group) and one
  provisioning directory per node (a fresh random token, the endpoint line,
  a fresh state key), files 0400, and prints only names and counts. Source
  ids are `s-` label pseudonyms of `<node>/ebpf` (vector
  `run-id-pseudonym-v1.json`). Adding a node is a regeneration and a chart
  upgrade (053 §6.1: no dynamic onboarding).
- **Scope.** Agent pods by `EMIT_AGENT_POD_SELECTOR`; sandbox roots only on
  the dedicated node pool (§4.3 "Kubernetes sandbox roots and their cost").

A live multi-node cluster test is not an M2 exit: the per-node render is
proved by `valid/agent-ebpf-three-nodes.yaml`, two sources by the hermetic
replay, the pod-shaped scope by `TestAgentRootPodShape`, cross-node H5 by
`h5-pod-report-other-node.json`.

#### 7.3.4 Shared files and their integration owners

| File or area | Integration owner in M2 | Other M2 WPs |
|---|---|---|
| Contracts, registries, vectors, fixtures, generated tables | WP6-11 | read only |
| `fabric/hooks/__init__.py`, `_config.py` | WP6-09a | WP6-09b registers through the `remote.sandbox` slot; WP6-08 adds no switch |
| `fabric/hooks/_exec.py` | WP6-08 | — |
| `wire/_routes.py`, the route call in `wire/_transport.py` | WP6-09a | — (054 WP5-00a next) |
| `sdk/python/pyproject.toml` | WP6-09b | — |
| `.github/workflows/recorder-license.yml` | WP4-07a (the `hostrecords` module) | WP6-09b adds the `hooks-sandbox-e2b` Python matrix entry, after WP4-07a merged (wave C) |
| `.github/license-allowlist.txt` | WP6-09b (only if the e2b inventory needs it) | — |
| `fabric/reconstruct/**` | WP6-12 | — |
| `hostrecords/**`, the Makefile module line, license and security module lists | WP4-07a | — |
| `receiver/auditreceiver/**`, `ocb-config.yaml`, `components/otel-collector-fabric/Dockerfile` | WP4-07b | — |
| `components/host-emitter/**`, the `host-emitter` job of `recorder-ci.yml`, the `publish-image` matrix of `release.yml` | WP4-07c | — |
| `gate/**` | WP4-08a | — |
| `processor/fabricguardprocessor/**` (not generated) | WP4-08b | — (054 WP5-01g next) |
| `charts/**`, `deploy/compose/**`, `deploy/kubernetes/**` | WP4-09 | WP6-10 uses them unchanged and runs `qualify-sensor-auditd.sh` in CI |
| `qualification/action-record/**`, `action-record.yml`, M2 docs, `CHANGELOG.md`, `specs/README.md` | WP6-10 | — |
| `qualification/remote-sandbox/**` | WP6-09b | WP6-10 imports its fixture server |
| `scripts/tests/test_recorder_release_boundary.py` | WP6-10 | — |

Rules for every M2 WP: 053 §8's rules; `ruff` (0.13.0) check and format and
`mypy --strict` on touched Python, `gofmt`, `go vet` and the module's tests
on touched Go; `scripts/tests/test_recorder_release_boundary.py` passes;
baseline failures recorded before the change; nothing approves, blocks,
delays or changes the monitored agent, and no evaluation or enforcement
code is added (AGENTS.md).

### 7.4 Revision 12: content-matched links (lane 053, after the audit units)

Six units, one pull request each, stacked in this order on top of spec
053's four audit units (053 §8.1). A unit is at most about 2,000 changed
lines, tests included; generated golden files count, which is why the
certainty change is a unit of its own.

| Order | Unit | Delivers |
|---|---|---|
| 5 | `056-c1` | The certainty change alone: a single `output_match` is `tentative` (§4.2.1 "Certainty"). Skipped entirely if the owner answers no to OQ12-1 |
| 6 | `056-c2` | §5.2 contracts, the reference rules and every §6.1 revision 12 fixture; no SDK behaviour |
| 7 | `056-c3` | Execution context tags (§4.2.2) on hook records and Python model exchanges |
| 8 | `056-c4` | The set rule of §4.2.1 for command effects: argument leaves, `command_match`, `output_match`, `execution_context`, the report and the action view |
| 9 | `056-c5` | §4.2.3: `exec.audit` and `file.audit` records as effects, `path_match`, `unattributed_file_effect` |
| 10 | `056-c6` | The link-ambiguity scenario of §6.3, AR-1 additions, documentation |

**Starts when** (build plan): spec 053's audit units are merged or
stacked below, the owner has accepted §10, and spec 057 P1 and P2 have
merged their `fabric/reconstruct/` changes. If a 057 pull request is
still open when a unit starts, the unit rebases on it rather than
duplicating or moving its code.

**Files in `fabric/reconstruct/` and who owns them.** Spec 057 P1a (#293)
and P2a (#295) edit `_attribute.py`, `_security.py`, `_controls.py`,
`__main__.py`, `_inputs.py`, `_host.py`, `_project.py` and `_verify.py`,
and add `_derive.py` and `dialects/`. To keep the two efforts apart, the
rules of this revision live in one new file, and this lane changes only
the named functions elsewhere.

| File | This lane | Unit |
|---|---|---|
| `reconstruct/_content_link.py` (new) | **Owns it.** Leaf extraction, the four tests, the set rule, the `match` entries. Pure functions over the normalized input; imports nothing from `_security.py`, `_derive.py` or `dialects/` | c4 creates, c5 extends |
| `reconstruct/_stitch.py` | `extract_stitch_keys` and `StitchKeys` gain each tool call's arguments beside its name (every wire dialect the parser already reads, streamed responses included). Nothing else | c4 |
| `reconstruct/_attribute.py` | Only: the confidence of the single-match link in `attribute_effect` (c1); `attribute_effect`, `Decision`, `output_matches` (moved behind `_content_link`), `_RunReader._tool_io`, `_RunReader._exchanges`, `_RunReader._effect`, and the `content_match` summary in `attribute` (c4); `EFFECT_POINTS`, the effect's `kind`, `path` and `target_path`, the chain reason and `action_rows` labels (c5). Code spec 057 added (`_apply_security`, the hook-program skip, grant joins) is not moved, renamed or reformatted; the hook-program skip stays ahead of the content rule | c1, c4, c5 |
| `reconstruct/_report.py` | `link_counts` and `attribution_json`: the new bases and `content_match` | c4 |
| `reconstruct/__main__.py` | The link text of an effect row in the `actions` rendering | c4, c5 |
| `reconstruct/_security.py`, `_controls.py`, `_derive.py`, `dialects/**`, `_host.py`, `_inputs.py`, `_project.py`, `_verify.py`, `_graph.py`, `_evidence.py` | **Not edited.** If a unit finds it needs one, it stops that part and says so in its pull request | — |

Outside `reconstruct/`: `fabric/_exec_context.py` (new), the attempt
stamp in `fabric/_records.py` and the request stamp in
`fabric/wire/_transport.py` and `_aiohttp.py` belong to c3;
`scripts/contracts/action_reference.py` and `action_record.py` to c2;
`qualification/action-record/**` to c6 (c1 only regenerates its expected
output).

**The pending list.** `sdk/python/tests/test_reconstruct_attribute.py`
runs every fixture under `action-record/rules/` against the SDK. c2 adds
fixtures the SDK cannot pass yet, so it also adds
`contracts/coverage/v1/fixtures/action-record/pending.json`, a list of
fixture names with the unit that will make each pass. The SDK test skips
listed fixtures and fails on a listed name that does not exist. c4 and c5
remove their names. c5 leaves the list empty and adds a test that it stays
empty. The reference rules (`scripts/contracts/`) pass every fixture from
c2 on; the list never applies to them.

**Unit 056-c1: every inferred effect link is tentative.**
- Changes: the `output_match` meaning in `vocabularies-v1.json`; the
  schema rule that a `caused_by` link whose method is `output_match` has
  `confidence: tentative`; `reconstruct/_attribute.py` (one value); the
  reference rules; every golden regenerated with the existing builders;
  AR-1's expected output; the action-view examples in
  `docs/action-reconstruction.md` and `docs/reconstruct.md`, and the
  sample action view in spec 058 (its `output_match · certain` lines).
- Acceptance tests: every rule fixture and golden passes after
  regeneration; a new fixture `c-output-now-tentative.json`; a new invalid
  fixture `invalid/output-match-certain.json`; a test that greps the
  generated goldens and finds no `output_match` link with `certain`;
  `tests/test_reconstruct_attribute.py`, `test_reconstruct_action_host.py`,
  `test_reconstruct_action_production.py`, `test_reconstruct_security.py`
  and AR-1 hermetic pass.
- The diff must contain no change other than `certain` to `tentative` on
  `output_match` links and the texts that describe it; the pull request
  says how that was checked.

**Unit 056-c2: contracts, reference rules, fixtures.** §5.2 and §6.1.
- Acceptance tests: the contract validators and generator checks pass;
  every §6.1 revision 12 fixture exists and the reference rules reproduce
  its expected output byte for byte; each `invalid/` fixture is refused
  with the error its README row names; a property test of leaf extraction
  in the reference rules (JSON with nested values, escapes and non-ASCII
  text: every string value appears once, no key appears); the pending
  list names exactly the fixtures the SDK does not pass; `pytest
  scripts/tests` passes; Go tests of the regenerated fabricguard table
  pass.

**Unit 056-c3: execution context tags.** §4.2.2.
- Acceptance tests, in `tests/test_exec_context.py`:
  `test_thread_ref_stable_per_thread_and_never_reused`,
  `test_task_ref_per_task_absent_outside_a_task`,
  `test_never_imports_asyncio`, `test_task_object_not_mutated`,
  `test_unweakrefable_task_gets_no_tag`,
  `test_failure_gives_no_tag_and_no_exception`,
  `test_fork_child_restarts_counters`,
  `test_no_context_variable_set_in_application_context`; in the hook
  suites, one test per channel that its records carry both keys and that
  two threads and two tasks get different values; in the wire suites,
  `test_exchange_span_carries_context_tags` for httpx sync, httpx async
  and aiohttp; `test_records_match_contract_vectors`; passivity:
  `test_context_tag_budget` (1 µs median on `begin` and on a wire
  request) with a blocking-injection negative control; the existing wire
  and hook passivity suites pass unchanged.

**Unit 056-c4: the set rule for command effects.** §4.2.1, for effects
at `exec.subprocess` and `remote.sandbox`.
- Acceptance tests: every `c-command-*`, `c-leaves-*`, `c-context-*`,
  `c-intersection`, `c-conflict`, `c-metadata-only`,
  `c-withheld-one-side` and `c-hook-program-skipped` fixture passes in the
  SDK and leaves the pending list; `tests/test_reconstruct_content_link.py`
  with a differential test (the SDK and the reference rules agree on 500
  generated inputs with a fixed seed), `test_no_string_from_either_side_in_links_or_report`
  (canaries in arguments, commands and outputs),
  `test_argument_leaves_per_wire_dialect` (chat completions, Responses and
  Messages, streamed and not), `test_revision_11_fixtures_unchanged`
  (every older fixture gives the same links as after c1); the action view
  golden for the new link text; `test_reconstruct_scale.py` still within
  its time bound.

**Unit 056-c5: file and audit effects.** §4.2.3 and `path_match`.
- Acceptance tests: every `c-path-*`, `c-file-effect-*` and
  `c-exec-audit-effect` fixture passes and the pending list is empty;
  an end-to-end test that runs a process with `file_audit` and
  `exec_audit` on, exports, and reads `path_match` and `command_match`
  links from the report; `test_unattributed_file_effect_reason`;
  `test_file_effect_never_counts_for_corroboration`;
  `test_no_effect_channel_only_without_file_channel`; action view goldens
  for the three new row texts; a run with no audit records gives a report
  byte-identical to c4's.

**Unit 056-c6: acceptance and documentation.**
- `qualification/action-record/link_ambiguity/` (§6.3) with its `run.py`
  and a job in `.github/workflows/action-record.yml`; the expected
  `ambiguous_share` for the revision 11 rules and the revision 12 rules,
  both exact, and zero wrong links.
- AR-1 gains one in-process file tool and one parallel pair of shell
  calls with outputs withheld, and expects `path_match` and
  `command_match` links.
- `docs/action-reconstruction.md` (how links are made, what each method
  means, why inferred links are tentative, the limits),
  `docs/reconstruct.md`, `docs/glossary.md`, `docs/limitations-and-roadmap.md`,
  `CHANGELOG.md`, `specs/README.md`.
- `scripts/tests/test_recorder_release_boundary.py`: the wheel holds no
  scoring, ranking or model-calling code in `reconstruct/` (a source check
  that `_content_link.py` imports no network, model or numeric library and
  defines no weight or threshold other than `MIN_MATCH_BYTES`).

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
| OD-3 | First remote sandbox provider for WP6-09 | **Decided (rev 4): E2B.** It documents an SDK call that runs a command or code in a remote sandbox and returns stdout, stderr and the exit code, and it is widely used as the code tool of OpenAI-style tool loops. It is observed at its Python SDK's call API (`Commands.run`, `CommandHandle.wait`, `run_code`; `e2b` 2.62.x, `e2b-code-interpreter` 2.11.x), not through the 053 §5.4 HTTP channel, because that SDK sends through `pyqwest`, which httpx's transport patch cannot see (§4.4.1) |
| OD-4 | Container sandboxes: record the container id the runtime returns (`docker run` output, or the Kubernetes API) as a reported link | **Decided (rev 4): yes.** The id `docker`/`podman`/`nerdctl run -d` or `create` prints, or the pod uid `kubectl … -o jsonpath={.metadata.uid}` or `-o json` prints, becomes `fabric.sandbox.created_id`; the eBPF emitter derives the same `sbx-` id from the cgroup path; rule H5 links the group, `sandbox_report · certain`, provenance `reported` (§4.3). A Docker or Kubernetes API client inside the agent process is not observed in M2. Revision 5: H5 matches on any host source, not only the effect's host, because the id is unique across hosts and a created pod may run on another node |
| OD-5 | A2 (single window) confidence: `tentative` or `certain` | `tentative`; only A0 and A1 are `certain`. **Revision 12 proposes to replace the A1 part: only A0 is `certain` (§4.2.1, OQ12-1)** |
| OD-6 | AR-1 host sensor in hosted CI | Try eBPF on the hosted runner first; if it cannot load, run the host part on a self-hosted runner and keep the rest in hosted CI |
| OD-7 | Local profile: two exec events with one pid and parent pid and no start times (a shell that execs in place) | Decided: one exec chain, `process_anchor · tentative`, unless an exit of the pid is observed between them (§4.3) |
| OD-8 | When the exec hook reads the child's start time | **Recommended — pending owner confirmation** (amends OD-2): read `/proc/<pid>/stat` once on the calling thread right after `Popen` returns, and accept a zombie child. Until the caller waits, the child cannot be reaped, so the read is exact even for a command that has already exited, which the worker-only read of M1 misses. Cost: one open, read and close of an in-memory procfs file, inside the 50 µs P4-EXEC start budget, failing silently. The worker read stays as the fallback. **Shapes:** WP6-08, WP6-10. **Fallback** (owner keeps OD-2 as is): H1 applies only to effects whose worker read won the race; WP6-08 drops the caller-side read and `test_start_ns_read_before_reap`, and AR-1 M2 asserts `certain` only for effects that carry `start_ns`, accepting H2 `tentative` for the rest |
| OD-9 | Pids in production eBPF records | **Recommended — pending owner confirmation:** both numberings (`pid`/`ppid` in the init namespace, `ns_pid`/`ns_ppid` with `pid_ns` in the process's own namespace); anchors use the namespace-local pair, lineage the init-namespace pair (§4.3). An agent in a pod is then anchored exactly, and lineage crosses a nested sandbox. **Shapes:** WP6-11 (record rows and goldens), WP4-07a, WP4-07c, WP6-12. **Fallback** (init-namespace pids only): production supports only agents that share the host's pid numbering (`hostPID: true` pods, agents not in containers), with mode `declared_same`; an agent in its own pid namespace is `anchor_missing`, and AR-1 production runs the agent container with `--pid host`. `ns_pid`, `ns_ppid` and `pid_ns` leave the §6.2.3 amendment |
| OD-10 | The eBPF emitter as a chart workload | **Recommended — pending owner confirmation:** no. The chart adds only the host ingress groups; the privileged sensor stays a customer-deployed example (`deploy/kubernetes/host-emitter-daemonset.yaml`, updated to production mode, and a new auditd sensor-collector manifest), as 053 K4 and WP4-09 ("DaemonSet example") require. **Shapes:** WP4-09. **Fallback** (a chart workload): an opt-in `hostEmitter` DaemonSet template, disabled by default, with the per-node provisioning of §7.3.3 (n); `test-package-boundary.sh` then asserts that the default render has no privileged workload instead of the package having none, and WP6-10's release-boundary check changes the same way |
| OD-11 | Location of the host-records library | **Recommended — pending owner confirmation:** `components/otel-collector-fabric/hostrecords` (its own Go module), not 053's `components/host-records`, because the Node image is built with context `components/otel-collector-fabric` and the auditd receiver must compile in it; the emitter's image build moves to context `components/`. **Shapes:** WP4-07a (module path), WP4-07b (Dockerfile line), WP4-07c (build context, `release.yml`). **Fallback** (053's `components/host-records`): WP4-07b moves the Node image's build context to `components/` in its Dockerfile and in every workflow that builds it (`recorder-ci.yml`, `e2e.yml`, `e2e-production-profile.yml`, `release.yml`), which WP4-07b then owns for that line |
| OD-12 | How the eBPF emitter scopes an agent in a Kubernetes pod | **Recommended — pending owner confirmation:** a label selector (`EMIT_AGENT_POD_SELECTOR`) resolved by the emitter itself through a read-only, node-scoped API-server watch, installing each matching pod's slice as an agent root (§4.3, §7.3.3 (c)). A static path cannot name a pod slice (its uid is unknown before the pod exists), and a Docker-style cgroup parent cannot be set per pod. Cost: the emitter needs `get`, `list`, `watch` on `pods` and reads pod uids and labels; nothing it reads is exported. **Shapes:** WP4-07c, WP4-09, WP6-11 (`scope_late`). **Fallback** (no API access): Kubernetes agents run on a dedicated node pool whose `kubepods` QoS slices are the static agent roots, and every other pod on those nodes is agent scope and listed unexplained; the selector, its RBAC and `scope_late` leave M2 |

## 10. Open questions for the owner (revision 12)

Each row has a recommendation. Build agents follow it unless the owner
records a different answer in this table.

| # | Question | Recommendation | If the owner says no |
|---|---|---|---|
| OQ12-1 | **Is a single `output_match` still `certain`?** Revision 11 (OD-5) says yes. The direction for this revision says an inferred link is always tentative. They conflict | **Tentative.** A cut tool result can leave another call as the only match, so `certain` overstates it; one rule ("only a reported link is certain") is easier to explain to an auditor. Cost: one mechanical unit (056-c1) that changes about 120 golden files and the AR-1 expectations | Unit 056-c1 is skipped. A `resolved` link whose `method` is `output_match` stays `certain`, as in revision 11; links whose method is one of the three new tests are `tentative`; the schema rule of §5.2 then exempts `output_match` |
| OQ12-2 | **Does `execution_context` count as a test?** It is exact (equal tags) but it is not content, and it needs two new keys on hook records and on Python model exchanges | **Yes.** It is the only evidence that separates two sessions running the same command at once in one process (harness shape C), it costs under a microsecond, and it works in metadata-only mode | Unit 056-c3 is skipped; the keys, the test and the `c-context-*` fixtures are removed from c2, c4 and c6 |
| OQ12-3 | **A file the process writes outside every tool call** (after the first model call): does it make the `effects` chain `partial`? | **Yes, with its own reason** `unattributed_file_effect`. The chain's promise is that nothing the process did is unexplained by omission; a separate reason lets a reader set file writes apart from commands. Writes before the first model call are startup effects and never a gap | Such operations are listed in `attribution.unattributed_effects` and do not change the chain; the reason is not added |
| OQ12-4 | **A numeric target for the ambiguous share** in the field harness | **No number.** Gate on zero wrong links, on the exact counts of the in-repository scenario, and report the share in the three ways of §6.3. A percentage target would invite loosening a test to reach it | The owner names the number; §6.3 gains it as a gate of run 3 |
| OQ12-5 | **Content match for non-model HTTP and MCP records** (a URL or an MCP tool name and arguments against the model's call) | **Later, in a spec 057 revision**, after 057 P1 has merged. Those records are not effects in this spec and 057 already joins MCP `tools/call` by name inside the window | A seventh unit after c6 adds a `request_match` test for `http.nonmodel` and `mcp.client` records |
| OQ12-6 | **The 16-byte floor for "contains"** (shared with A1) | **Keep 16** for every "contains" line and no floor for whole-value equality. One constant, already qualified by AR-1 | The owner names another value; it changes `MIN_MATCH_BYTES` for A1 too, and c1 regenerates the goldens |
| OQ12-7 | **A context marker instead of tags.** Fabric could set a private context variable when a model response arrives, so that tasks and threads started afterwards inherit "last model call seen", which would also cover tools run in worker threads | **No.** It writes into the application's context, which is a change to the monitored process, however small. Tags only read | A later revision specifies the marker with its own passivity proof |

