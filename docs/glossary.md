# Glossary

> **Status:** reference page. It defines the terms that specs 047–056 use,
> whether or not the code behind a term is built. Each entry says where the
> term is defined and, where it matters, whether it is released (v0.8.0 or
> v0.10.0) or only specified. For the code itself see the [map in docs/README.md](README.md).

Spec references look like "049 §2.4": spec number, then section. Specs live
in [`specs/`](../specs/README.md). Where a term has a module, the path is
relative to `sdk/python/src/fabric/` unless it starts with another top-level
directory.

Groups:
[product and components](#product-and-components) ·
[inputs and capture](#inputs-and-capture) ·
[ordering and run structure](#ordering-and-run-structure) ·
[fields, coverage and the projection](#fields-coverage-and-the-projection) ·
[verdicts](#verdicts) ·
[identity and privacy](#identity-and-privacy) ·
[agent action reconstruction](#agent-action-reconstruction-spec-056) ·
[spec conventions](#spec-conventions).

## Product and components

**CAPTURE -> PROTECT -> DELIVER.** The product model. Capture records
observable AI activity. Protect applies privacy rules to the record before
it leaves the agent process or reaches disk. Deliver moves the record
durably to destinations the customer chooses. "Verify" is a property of the
record (sequence numbers, digests, seals, offline checks), not a fourth
runtime stage. Defined in [AGENTS.md](../AGENTS.md) and [027].

**Passive.** Fabric never approves, blocks, delays, retries or modifies
what the monitored agent does. Recording failures are swallowed; the
application sees the same results and exceptions. Overhead is bounded and
measured, not zero. 049 §7.1 and owner decision 2 ([049] §9).

**Agent.** The monitored application process. It runs the Fabric SDK.

**Fabric Node (the Node).** Fabric's OpenTelemetry Collector distribution
(image `ghcr.io/singleaxis/fabric-otelcol`, source
[`components/otel-collector-fabric`](../components/otel-collector-fabric/)).
It receives spans and content from agents, filters and authenticates them,
queues them durably, writes content to a store and forwards metadata to an
OTLP destination. Built (v0.8.0). [048] §4; [deployment](deployment.md).

**fabric-gate.** The Node's entry point
([`gate/`](../components/otel-collector-fabric/gate/)). It validates the
collector configuration at start and refuses unsafe ones, for example a
host-sensor receiver on a production Node. Built. [048] §5.

**fabricguard.** The Node's processor
([`fabricguardprocessor`](../components/otel-collector-fabric/processor/fabricguardprocessor/)).
It keeps only allowlisted telemetry keys, checks identifier forms, binds
each batch to an authenticated source and stamps
`fabric.source.authenticated=true` on admitted records. Built; the P1
records class since v0.10.0. 049 §7.9, [050] §3.14.

**fabriccontent.** The Node's content exporter
([`fabriccontentexporter`](../components/otel-collector-fabric/exporter/fabriccontentexporter/)).
It checks each content descriptor against the content-role table and the
source binding, then writes the object once to a file directory or an S3
bucket. Built. [048] §4, 049 §4.3.

**fabricenvelope, noredirect.** Node extensions
([`extension/`](../components/otel-collector-fabric/extension/)).
`fabricenvelope` encrypts the Node's content queue and file store with the
Node content key (049 §7.8). `noredirect` makes the OTLP/HTTP exporter
refuse HTTP redirects (048). Both built.

**Host sensor.** An optional Linux component that records process starts,
network connections and file opens as metadata: the auditd receiver
(capture point `host.auditd`, [030]) and the eBPF host emitter
(`host.ebpf`, [031]). Corroboration only. Built for the local profile
(v0.8.0); production mode, through a production Node's host ingress groups
([053] §6.2), released in v0.11.0.
[Host sensors](host-sensors.md).

**Node mode, local file mode, direct mode.** How an agent delivers. Node
mode spools every record to disk and sends it to a Node (required in the
production profile). Local file mode writes content to a `file://` store
itself. Direct mode exports telemetry with no Node. [048] §1;
[deployment](deployment.md).

**Profile (`local`, `production`).** The deployment profile. `production`
requires a capture policy, an id key and a spool key for content, and an
authenticated single-source Node. `local` is for development and never
yields production-qualified verdicts. 049 §7.3. Not the same as a
*coverage profile* (below).

**Spool.** The agent's durable on-disk queue
([`wire/_spool.py`](../sdk/python/src/fabric/wire/_spool.py)): fsync'd,
encrypted with the spool key in production, shared by every process on the
same directory through a file lock. Records leave it only when the Node has
accepted them. Built. [048] §2, [050] §3.5. Spool *kinds* name what a spool
file holds: `exchange`, `record` (v0.10.0), `marker`, and loss entries.

**Capture worker.** The one background thread per agent process that
protects, digests and spools what was captured
([`wire/_pipeline.py`](../sdk/python/src/fabric/wire/_pipeline.py)). The
application thread only allocates a sequence and hands the job over
without waiting. [050] §3.1.

**Sender.** The one thread that drains the spool to the Node: content
first, then the span
([`wire/_sender.py`](../sdk/python/src/fabric/wire/_sender.py)). Built.

**Redaction service.** A small local service the customer runs beside the
agent (Unix socket or loopback HTTP) that performs `redact` and
`masked_only`. Fabric posts bytes to it from the capture worker and never
runs customer code itself. Contract
[`contracts/redaction/v1`](../contracts/redaction/v1/README.md); reference
service in [`examples/redaction-service`](../examples/redaction-service/).
Built. 049 §7.7, owner decision 21.

**Content store, destination.** The content store is the directory or S3
bucket where the Node writes content objects. The destination is the OTLP
endpoint that receives metadata. Both are chosen by the customer.

## Inputs and capture

**Wire capture (the wire input, the tee).** Automatic, in-process copying
of model HTTP request and response bytes on the `httpx`, `httpx2` and
`aiohttp` transports, enabled by `fabric.wire.install()` or the autoload.
Python only. Built ([`wire/`](../sdk/python/src/fabric/wire/)). [047],
[048], 049 §1.3. TypeScript wire capture is specified in [055], not built.

**Exchange.** One model HTTP request and its response, captured at the
wire, identified by `fabric.wire.exchange_id`. [047].

**Records input.** Fabric's second input: everything the application
reports through the SDK, and everything an opt-in hook observes, as
sequenced records on the same allocator and spool as the wire input.
Released in v0.10.0 ([`_records.py`](../sdk/python/src/fabric/_records.py));
the explicit producers (`CallRecorder` and the adapters) can use it there
when a wire handle is installed; the `decision()` API does not yet (050
WP-15 is not built). 049 §1.3, [050] §3.4.

**Explicit line, decision line.** The application-reported APIs that
predate the records input: `decision()` and its `record_*` methods (the
*decision line*, `fabric.decision` spans), plus `CallRecorder`,
`ByteEvidenceRecorder` and the byte-boundary adapters. Built.
[Explicit APIs](explicit-apis.md); [050] §3.10–3.11 move them onto the
records input.

**Capture point.** A named, versioned place where Fabric gets data, written
`id@version`: for example `wire.py.httpx`, `sdk.records`, `run.scope`,
`exec.subprocess`, `reconstruct.infer`, `host.ebpf`. The registry
[`capture-points-v1.json`](../contracts/coverage/v1/registry/capture-points-v1.json)
lists each with its state, what it can and cannot observe and which fields
it supplies. 049 §2.8.

**Capture point kinds (F, W, H, R, P, I, S).** F `fabric`: Fabric's own
records (ids, sequences, manifests, losses). W `wire`: bytes copied from a
transport. H `hook`: an operation the application already performs,
observed. R `reported`: values the application passes to an API. P
`provider_assertion`: a literal parsed offline from captured bytes. I
`inference`: an offline derivation. S `sensor`: a host sensor or
independent feed. 049 §2.2.

**Hook.** An opt-in observer of an operation the application already
performs, such as starting a subprocess (`exec.subprocess`) or running a
database statement (`db.dbapi`). Hooks emit on the records input with
provenance `observed`. Specified in [053]. Only the hooks foundation and
the subprocess hook are built, released in v0.10.0 for spec 056 M1
([`fabric/hooks/`](../sdk/python/src/fabric/hooks/)); the other channels are
not built.

**Run, run scope.** A run is one logical agent task. `fabric.wire.run()`
brackets a *scope* of it in one process. Without scopes, each process epoch
is its own run named `source:<source-id>:<epoch>`. [048] §6, 049 §2.10.

**Heartbeat, `final`.** A record that states the last sequence a source
allocated. The `final` heartbeat at process end proves nothing was lost
after the last record; without it the tail is `tail_unverified`. Run
markers (`run_start`, `run_end`, `segment_seal`) travel as heartbeat
records. Built. [047] §6, [048] §6.

**Loss record.** A `fabric.capture_loss` record naming positions Fabric
knows it lost and why (`queue_full`, `disk_full`, `shutdown`,
`span_dropped`, `uninstrumented_client`, ...). A loss is a visible gap,
never a silent one. Built. [047] §6.

**D2 (explicit wins).** When an explicit API already records a model call,
the wire tee records nothing for that call, so a call is recorded once. 053
§4.3 applies the same rule to hooks: an explicit producer of the same kind
wins. Built for the wire line. 049 §1.3.

**D3 (protected provider).** A tracer provider that Fabric protects never
carries wire spans or markers; hooks never emit through a global tracer.
049 §1.3, [053] §4.3.

**Sticky withholding.** If the explicit recorder withheld a call's bytes
under its privacy policy, the wire line never captures them raw, even when
the response outlives the explicit call. Specified (P1-A); not built.
049 §1.3.

## Ordering and run structure

**Source.** One emitter identity, `fabric.source_id`, by default derived
from host and service. 049 §2.4.

**Epoch.** One lifetime of a source's sequence counter, normally one
process. Since v0.10.0 (P1) an epoch is a 63-bit random number drawn at
`install()` and again in a forked child; before, it was derived from time
and pid. Every sequenced record carries `(source, epoch, sequence)`.
049 §2.4, [050] §3.2.

**Epoch registration.** Since v0.10.0 (P1), `install()` creates a lock-held
registration file for its epoch in the spool directory. The next process
can then tell that a writer was killed and declare its epoch
`unsealed_epoch`.
[`wire/_registration.py`](../sdk/python/src/fabric/wire/_registration.py),
[050] §3.2.

**Sequence, sequence gap.** Positions 0, 1, 2, ... within one
`(source, epoch)`. A missing position with no loss record is a
`sequence_gap`. Built. [047] §6.

**Shared allocator.** The single per-process sequence counter
(`SourceAllocator`,
[`_sequence.py`](../sdk/python/src/fabric/_sequence.py)) that gives
positions to wire exchanges and records alike, so record order within an
epoch is exact. Allocation is one short lock with no I/O. Released in
v0.10.0 (before, only the wire input was sequenced). 049 §2.4,
[050] §3.3.

**Event id.** `fabric.event_id`, a uuid4 minted once per record before it is
spooled and kept on every retry, so receivers can deduplicate. 049 §2.4.

**Attempt id, step id.** An *attempt* is one physical execution (one
exchange, one record call), identified by a Fabric-minted `attempt_id`. A
*step* is the logical node, stable across retries, identified by
`step_id`. Caller-supplied ids are kept as *aliases* that join records but
never identify them. 049 §2.3.

**Segment.** A contiguous piece of one run recorded by one
`(source, epoch)`, with an id `seg-` + 32 hex. A process has one open
segment per run; a new one opens on a resume token, a fork or re-entry.
Released in v0.10.0 ([`_segments.py`](../sdk/python/src/fabric/_segments.py)).
049 §2.10, [050] §3.6.

**Seal (segment seal).** A digest over a segment's sequenced records (and
the positions of its losses), written as a `segment_seal` marker once every
position has *settled*, that is, been spooled or recorded as lost. The
verifier recomputes it; a difference is `partial(seal_mismatch)`, a missing
seal leaves the segment `unsealed`. Released in v0.10.0
([`_seal.py`](../sdk/python/src/fabric/_seal.py)). 049 §2.12, [050] §3.7.

**Unsealed epoch.** A prior epoch on the same spool that never wrote its
`final` heartbeat and seals, declared by the next epoch's first manifest.
Its runs are `partial`. 049 §2.12.

**Resume token.** Text returned by `fabric.wire.resume_token()`. Issuing
one seals the current segment; another process that passes it continues
the run in a new segment whose *predecessor* is the sealed one. The P1
format is `fr3/` (it carries the run correlation id); 049 describes the
older `fr2/`. `resume_tokens(n)` mints `n` *branch tokens* (`br-` ids), each
for exactly one consumer. `fabric.wire.end_run()` ends a resumable run from
its tokens. Released in v0.10.0. 049 §2.10, [050] §3.6.

**Run states and rules G1–G10.** The verifier builds each run's segment
graph and applies rules G1–G10 in order. The run state is `terminated`,
`open` (resumable, before its deadline), `unterminated` (after it),
`conflicted`, `not_resumable_unclosed` or `deadline_uncertain`. Released
in v0.10.0 ([`reconstruct/_graph.py`](../sdk/python/src/fabric/reconstruct/_graph.py)).
049 §2.10.

**Capture manifest.** A `fabric.capture-manifest/v1` document per
`(source, epoch)` that states what that process could capture: profile,
identity mode, capture-policy reference, limits, every capture point with
its state and supplied fields, and the classes it cannot capture. Manifests
are numbered (`manifest_seq`) and chained by digest. They let the verifier
tell "nothing happened" from "nothing was instrumented". Released in
v0.10.0 ([`_manifest.py`](../sdk/python/src/fabric/_manifest.py)). 049 §2.4,
§2.8; [050] §3.8. Not the same as the content-v1 *transcript manifest* of
[029].

**Evidence carrier, evidence object, evidence type.** The one closed,
bounded container for structured metadata that has no single telemetry key
(lists, indexes, correlations). A record has at most one evidence object
(role `record.evidence`); its shape is one of the registered *evidence
types* (for example `fabric.exec.observation/v1`). Released in v0.10.0
([`_evidence.py`](../sdk/python/src/fabric/_evidence.py)). [050] §3.4a,
[053] §3.2.

## Fields, coverage and the projection

**Four layers and field ids.** The record is described in four layers, each
with stable field ids that are never renumbered or reused:

| Prefix | Layer | Question | Ids |
|---|---|---|---|
| `X` | Cross-cutting | Identity, ordering, links, provenance, coverage, policy | `X01`–`X49` |
| `C` | 1 Context | What was the agent asked to do, with what instructions, tools, model and rules? | `C01`–`C42` |
| `S` | 2 Structure | What happened, in what order, by whom, how did it end? | `S01`–`S34` |
| `N` | 3 Content | What was said, sent, run, read and returned? | `N01`–`N60` |
| `D` | 4 Decisions and effects | What did external controls decide, what changed, what was delivered or consumed? | `D01`–`D35` |

Note that content is `N`, not `C`. The layers describe the record, not the
product. Registry:
[`field-registry-v1.json`](../contracts/coverage/v1/registry/field-registry-v1.json).
049 §1.2, §3.

**Field wrapper.** How every field of a step is reported in the projection:
a coverage status, a reason when needed, provenance, capture point, and
either a value (metadata only) or a locator to stored content. A missing
field never looks like an empty one. 049 §2.6.

**Coverage status.** One of nine values per field. 049 §2.6.

| Status | Meaning |
|---|---|
| `captured` | Recorded (or an exact locator to it). Says nothing about whether the fact is true. |
| `absent` | A complete, parsed carrier shows the property was not there. |
| `not_applicable` | The field has no meaning for this step or API. |
| `not_captured` | The field applied but Fabric did not keep it; a reason is required. |
| `redacted` | Withheld or transformed by policy or by the provider; a reason is required. |
| `truncated` | Only a bounded part was kept; a reason is required. |
| `unsupported` | The capture point or parser cannot provide it, as the manifest declares. |
| `unknown` | The evidence cannot establish the field (for example, no manifest). |
| `conflict` | Assertions disagree; all are kept, none chosen. |

**Reason.** A closed list of why a field or record is not fully captured
(`privacy_policy`, `body_cap`, `queue_full`, `not_instrumented`,
`segment_missing`, `unattributed_effect`, ...). New failure modes add a
reason, never a new status. 049 §2.6.

**Field class.** For verdicts, each wrapper falls in one class: `ok`,
`withheld` (privacy or provider withholding), `gap`, `unsupported` or
`uncertain`. 049 §2.6.

**Coverage profile.** The declared set of steps and fields a verdict is
judged against: `fabric.profile.model-calls/v1` (the first release),
`agent-run/v1`, `execution/v1` and `full/v1`. 049 §6.1.

**Step projection.** `fabric.step-projection/v1`, a document the verifier
writes offline next to its report: one entry per attempt with its step
kind, links, field wrappers in the four layers and per-layer verdicts.
It is a verifier output, never produced in the agent or the Node. Released
in v0.10.0, for model calls
([`reconstruct/_project.py`](../sdk/python/src/fabric/reconstruct/_project.py);
`python -m fabric.reconstruct --projection FILE`). 049 §4.4, [050] §3.13.

**Step kind.** What a step is: `model_call`, `tool_call`, `terminal`,
`retrieval`, `side_effect`, `control`, and about 25 more. 049 §2.3.

**Link.** A typed, many-to-many edge between steps, records or objects:
`caused_by`, `emits`, `consumes`, `retries`, `resumes`, `part_of`,
`corroborated_by` and others. Each link carries a provenance, a method and
a confidence when inferred, and a state (`resolved`, `unresolved`,
`ambiguous`, `conflict`). No link is ever invented from timestamps or pids
alone. 049 §2.5.

**Provenance.** How Fabric came to know a value: `observed` (by a capture
point Fabric installed, with no caller cooperation), `reported` (the
application told Fabric) or `inferred` (derived offline by the verifier).
Provenance never upgrades: corroboration adds a link, it never turns
`reported` into `observed`. 049 §2.2.

**Assertion origin.** Who asserted a fact: `application`, `provider`,
`service`, `human`, `fabric` or `unknown`. Observing a provider's
"completed" does not prove the effect happened. 049 §2.2.

**Method (inference method).** The closed list of ways the verifier may
infer a link or field, each with a fixed confidence: `tool_call_id`,
`previous_response_id`, `prefix_digest`, `pid_time_join`, and the spec 056
methods `sequence_bracket`, `output_match`, `process_anchor`,
`process_lineage`. 049 §2.5.

**Confidence.** `certain` or `tentative`, required on every inferred link
and field. A tentative inference is reported but never makes a field `ok`.
049 §2.5, §2.6.

**Corroboration.** A record from an independent source (a host sensor, an
independent feed) about the same fact, attached by a `corroborated_by`
link. 049 §2.2.

## Verdicts

**Integrity verdict.** The verifier's statement about the record of each
scope and run, in the `fabric.run-reconstruction/v1` report. Built
([`reconstruct/`](../sdk/python/src/fabric/reconstruct/)). [047] §9, [048]
§6, [reconstruct](reconstruct.md).

| Verdict | Meaning |
|---|---|
| `complete_for_declared_scope` | Every model call in the scope through an instrumented client to a matched endpoint was captured, stored unaltered and stitched. |
| `complete_for_observed_scopes` | Every scope that left a record is complete. |
| `partial` | Something the record proves existed is missing or altered. |
| `unverified` | Completeness cannot be shown. |
| `verified_complete_for_declared_scope` | Only in qualified-run mode, backed by independent witnesses and signed receipts. |

**Gap.** One finding behind a verdict: `sequence_gap`, `loss`,
`tail_unverified`, `missing_object`, `digest_mismatch`, `truncated`,
`unparsed_exchange`, `source_unauthenticated` and others.
[Reconstruct](reconstruct.md#gaps).

**Layer verdict.** Per step and per run, for each of the four layers:
`captured_for_declared_fields`, `captured_with_withholding`, `open` (run
only), `partial`, `unsupported`, `unverified`, `none_observed` (run only).
Computed by decision tables R1–R6 (per step) and RR1–RR7 (per run).
Released in v0.10.0, in the step projection. 049 §6.2.

**Chain verdict.** Spec 056 reports four chains separately: `decisions`,
`actions`, `effects`, `corroboration`, each `complete`, `partial` (with
reasons), `unverified` or `not_observed`. Released in v0.10.0
(`reconstruct/_attribute.py`, WP6-04). [056] §4.5.

**Qualified-run mode.** An opt-in, Python-only verification path for the
explicit `CallRecorder` line, on its own journal, with independent witness
feeds and four signed receipt stages. The only path to
`verified_complete_for_declared_scope`. Built.
[Qualified-run mode](qualified-run-mode.md); 049 §2.13, [045], [046].

## Identity and privacy

**Identity mode.** `pseudonymous` (default) or `clear`, set by
`FABRIC_IDENTITY_MODE`. In pseudonymous mode every externally meaningful id
leaves the process only as a keyed pseudonym. Clear mode is an explicit,
manifest-recorded opt-in. Built. 049 §2.9 rule 7.

**Keyed pseudonym, pseudonym v1 and v2.** A prefix plus the first 32 hex
characters of an HMAC-SHA256 of the value, keyed by `FABRIC_WIRE_ID_KEY`.
Version 1 covers run (`r-`), source (`s-`), service (`svc-`) and operator
labels (`lbl-`). Version 2 derives a separate key per id type (`sess-`,
`usr-`, `act-`, `hst-`, `sbx-`, `p-` and others) for domain separation.
Without a key, production omits v2 ids. Built
([`_sequence.py`](../sdk/python/src/fabric/_sequence.py),
[`_identity.py`](../sdk/python/src/fabric/_identity.py)). 049 §2.9.

**EmittedId.** A string subtype for ids this process minted or emitted.
Only these pass through unchanged; every caller-supplied id is mapped,
whatever it looks like. Built. 049 §2.9 rule 9, owner decision 22.

**Key id.** `kid-` + 8 hex, derived from the id key and recorded in the
manifest so a reader knows which key applied. A key change starts a new
epoch. 049 §2.9 rule 6.

**Capture policy.** The customer's configuration of how Fabric records and
protects: content role to privacy mode, storage, retention and profile
([`contracts/deployment-policy/v1`](../contracts/deployment-policy/v1/)).
In the local profile with no policy, the implicit `fabric.local-default`
applies. Not to be confused with the agent's *execution policy*, which
Fabric only records. 049 §2.7.

**Content role (PROTECT role).** The name of what a content object is, for
example `model.exchange.request`, `tool.call.result`, `terminal.stdout` or
`record.evidence`. The role table
([`content-roles-v1.json`](../contracts/coverage/v1/registry/content-roles-v1.json))
gives each role its default policy, permitted boundaries, provenance,
media types and size cap; the capture policy maps roles to privacy modes.
049 §4.3.

**Privacy mode.** What PROTECT does with one object: `omit` (nothing
stored), `metadata_only` (descriptor, no bytes), `redact` and `masked_only`
(transformed by the redaction service), `tokenize` (HMAC with a separate
tokenization key), `original_plus_masked` (original plus a masked review
copy) or `retain_original`. A failure withholds the object; it never falls
back to raw bytes. Built. 049 §2.7, §7.7.

**PROTECT stage.** The step on the capture worker, before the spool, that
applies each object's privacy mode. Nothing reaches disk or the network
before it runs. Built
([`wire/_protect.py`](../sdk/python/src/fabric/wire/_protect.py)). 049 §7.7.

**Privacy class.** How a value may travel: `ID`, `META`, `LABEL`, `DIGEST`
or `CONTENT`. Content lives only in content objects, never in telemetry,
logs or diagnostics. 049 §2.7.

**Source authentication, source binding.** A production Node ingress is
bound to one tenant and one source by a bearer token; fabricguard checks
every record against that binding and stamps
`fabric.source.authenticated=true`. In the production profile an
unstamped record makes a run `unverified(source_unauthenticated)`. The stamp
counts only on *trusted readback*: spans read from the Node's own export or
store, not imported files. Built for one source per Node; several sources
per Node (static dedicated ingress groups) are specified in [053] §6.1.
049 §7.9.

**Encryption at rest.** The agent spool is encrypted with a spool key; the
Node's content queue and file store with a Node content key. Required in
production. Built. 049 §7.8.

## Agent action reconstruction (spec 056)

All of this is specified in [056]. Milestone M1 is released in v0.10.0
for the local profile: the contracts and rule fixtures
([`contracts/coverage/v1/fixtures/action-record/`](../contracts/coverage/v1/fixtures/action-record/README.md)),
the hooks, the subprocess hook, attribution, chain verdicts, the `actions`
view, the host join and its `--host-records` option (WP6-01 to WP6-06).
The AR-1 acceptance test passes in CI in hermetic mode and in live mode
(Linux, eBPF). Milestone M2, the production profile, is released in
v0.11.0, and AR-1 production passes in CI. See
[agent action reconstruction](action-reconstruction.md).

**The four chains.** *Decisions*: what the model saw and returned (wire
capture). *Actions*: which tools the model asked for and what result the
agent fed back (parsed from captured model bodies). *Effects*: what the
agent's process actually ran (the subprocess hook). *Corroboration*: what
the operating system independently saw (host sensors). [056] §0.

**Tool call, tool result.** A tool request the model returned in a response
(`tool_calls[i]`, a `function_call` item or a `tool_use` block) and the
matching result item in a later request, paired by id. Built
([`reconstruct/_stitch.py`](../sdk/python/src/fabric/reconstruct/_stitch.py)).

**Effect.** A record of something the agent's process did outside the model
call; in M1, one subprocess run (`exec.subprocess`): arguments, returned
output, exit status. [056] §2, [053] §5.1.

**Host event.** A host-sensor record of a process start, connection or file
open, with pid, parent pid and time. [056] §2, [053] §6.2.3.

**Open window.** The time between the response that issued a tool call and
the request that fed its result back. An effect inside a call's window, on
the same epoch and segment, is a candidate for that call. [056] §4.2.

**Attribution rules A0–A4.** How an effect is linked to the tool call that
caused it: A0 reported parent (`certain`), A1 output match (`certain`), A2
single window (`tentative`), A3 several windows (`ambiguous`, all
candidates listed), A4 no window (listed as unattributed). [056] §4.2.

**Host join rules H1–H4.** How host events are linked to effects through
the process tree rather than timing: H1 pid, parent pid and process start
time match (`certain`); H2 the same without a start time (`tentative`); H3
descendants of an anchored process (`process_lineage`); H4 events of the
agent process itself. [056] §4.3.

**Exec chain.** Two or more exec events with one pid and parent pid and no
observed exit of that pid between them: one process that exec'd again in
place, as a shell does for its last command. H2 anchors the effect on the
first exec (`tentative`); the later ones are its lineage. [056] §4.3.

**`pid_time_join`.** The older rule of [053] §6.3: join a host event to a
record by pid and a time window, always `tentative`. Spec 056 replaces it
with H1–H4 where the process tree is known.

**Unattributed effects, unexplained host events.** Effects no tool call
explains, and host events no rule links (including connections by the agent
process to hosts no model call used). They are listed in the report's
`attribution` object: a gap between the record and what the operating system
saw, recorded without a judgement. Host events that no run lists at all
(another process with a run's agent pids, or activity in no run's window)
are listed once in the report's top-level `unattributed_host_events`, with
the reason. [056] §4.3, §4.5.

**AR-1.** The end-to-end acceptance scenario of [056] §6.2. Fabric does not
claim agent action reconstruction until AR-1 passes in CI on the
milestone's profile. Built
([`qualification/action-record/`](../qualification/action-record/README.md)):
hermetic mode (recorded host-sensor events) passes in CI on macOS and
Linux, and live mode with a real eBPF sensor on Linux; the auditd fallback
is not run live in CI.

## Spec conventions

**Phases P0–P5, P0-A, P1-A, TS-0 to TS-2.** The build order of [049] §8:

| Phase | Adds | State |
|---|---|---|
| P0 | Coverage contract freeze (`contracts/coverage/v1`) | Built (v0.8.0) |
| P0-A | PROTECT stage, production gate, encryption at rest, source authentication, typed extraction, pseudonym v2 | Built (v0.8.0) |
| P1 | Shared allocator, records input, event ids, segments, seals, manifests, step projection ([050]) | Mostly built (v0.10.0); WP-15 and WP-21 not built |
| P1-A | Mixed explicit and wire capture, passivity harness ([050] wave 4) | Not built |
| P2 | Run context and lifecycle reporting ([051]) | Not built |
| P3 | Decision and effect records, record-only ([052]) | Not built |
| P4 | Opt-in hooks and production host sensors ([053]) | Not built, except the parts moved into [056] M1 (v0.10.0) and M2 (v0.11.0) |
| P5 | Realtime, media, batch, files, UI automation ([054]) | Not built |
| TS-0, TS-1, TS-2 | TypeScript identity parity, wire capture, reporting APIs ([055]) | Not built |

**Owner decisions.** Decisions recorded by the project owner. "Decision
*n*" or "owner decision *n*" without a spec number means row *n* (1–25) of
[049] §9. Specs 050–056 keep their own tables: `OD-n` ([050], [056]),
`O2-n` ([051]), `O4-n` ([053]), `OD5-n` ([054]), `TS-OD-n` ([055]). An
entry marked **RPOC** is "recommended, pending owner confirmation".

**Revision decisions R1–R16.** Labels for sixteen cross-spec decisions
applied in revision 2 of specs 050–055. The specs cite them in parentheses
to say why a rule exists:

| Code | Decision | Main section |
|---|---|---|
| R1 | Every resume token carries the run's correlation id | 050 §3.6, §3.12 |
| R2 | Run-marker event ids are persisted uuid4 values | 050 §3.5 |
| R3 | Losses are attributed to the segment they belong to | 050 §3.5, §4.2 |
| R4 | Records have three separate status inputs: lifecycle, result and OTLP status | 050 §3.4 |
| R5 | A body that cannot be produced becomes a descriptor-only object with a reason | 050 §3.4 |
| R6 | At most 260 content objects per exchange (8 per record), checked by the spool writer before it writes | 050 §3.5, §4.2 |
| R7 | One structured evidence carrier; hook records use the records input, never the wire input | 050 §3.4a |
| R8 | One identity rule for every API: caller ids are mapped, clear mode is explicit | 049 §2.9, 050 §3.6, 053 §4.2 |
| R9 | Every recording API fails open; encoders do bounded work | 050 §3.4, 053 §4.1 |
| R10 | The Node validates content before acknowledging it (050 WP-21, not built) | 050 §3.14, OD-1 |
| R11 | Several sources per Node through static, dedicated ingress groups | 053 §6.1 |
| R12 | The TypeScript native addon interface is frozen | 055 §4.4 |
| R13 | Every shared file has one integration owner, and dependencies between work packages are explicit | each spec's work-package section |
| R14 | Oversized work packages are split into buildable ones | each spec's work-package section |
| R15 | Registry rows for `C35`, `C40`, `N51`, `fabric.capture.source`, and bounded `event_ids` | 050 §4.1 |
| R16 | Where the agent-matrix and chaos test harnesses live (`qualification/agent-matrix`, `qualification/chaos`; neither is in this repository yet) | 050 §6.3 |

Do not confuse these with the verdict rules R1–R6 and RR1–RR7 of 049 §6.2,
or with the appendix row labels below.

**Other rule and row labels.** G1–G10: segment-graph rules (049 §2.10).
A0–A4 and H1–H4: spec 056 rules. E1, E2, ... and T1, T2, ...: exit gates.
C1-1, C0A-3, ...: conformance tests (049 §8.2). D-1, D-2, ... in [051] are
deltas to 049, not field ids. A1, A2, ... in [051] are assumptions.

**Design-review labels.** Earlier revisions of specs 049–055 were checked
by design reviews. Their findings and how each was resolved are kept in
traceability tables: 049 appendices A–E (rows `A-*`, `B-*`, `R3F-*`,
`R6-*`, `R64-*` and similar) and the closing sections of 051–055, which cite
reviews by short labels. The review documents themselves are not part of
this repository; each table row states the finding and its resolution in
full.

**Work packages (WP).** The unit of build work in a spec, with an owner
area, dependencies and an exit check: `WP-nn` ([050], [055]), `WP2-n`
([051]), `WP3-n` ([052]), `WP4-n` ([053]), `WP5-n` ([054]), `WP6-nn`
([056]).

**LR-1.** The long-running reference scenario: one resumable run across
three processes on two hosts, with a key rotation and a lost middle
segment. 049 §8.2 (P1 exit).

**Qualification markers.** `NO_COVERAGE_CLAIM`: the spec claims no coverage
beyond the clients and endpoints it lists. `NO_GO`: the work was not
qualified for production use when written. See
[specs/README.md](../specs/README.md#status-values).

**`file:line` references.** Specs 049–055 cite code as `file:line` at the
commit they were written against (`36f7a89`, then `main`). Line numbers
drift; the file and function names are the stable part.

**Generated blocks.** Tables in 049 between `<!-- generated:... -->`
comments are rendered from the registries in
[`contracts/coverage/v1/registry/`](../contracts/coverage/v1/registry/).
The registries are the source of truth;
`scripts/contracts/validate_coverage_contracts.py` checks the tables.

[027]: ../specs/027-recorder-v1.md
[029]: ../specs/029-content-objects-transcript-contract.md
[030]: ../specs/030-auditd-host-connector.md
[031]: ../specs/031-ebpf-host-emitter.md
[045]: ../specs/045-independent-evidence-feeds.md
[046]: ../specs/046-qualified-call-run-verification.md
[047]: ../specs/047-llm-wire-capture-and-reconstruction.md
[048]: ../specs/048-node-content-delivery-and-agent-spool.md
[049]: ../specs/049-four-layer-capture-coverage.md
[050]: ../specs/050-run-structure-and-records-p1.md
[051]: ../specs/051-context-and-lifecycle-p2.md
[052]: ../specs/052-decisions-and-effects-p3.md
[053]: ../specs/053-execution-channels-p4.md
[054]: ../specs/054-specialised-runtimes-p5.md
[055]: ../specs/055-typescript-wire-capture.md
[056]: ../specs/056-agent-action-reconstruction.md
