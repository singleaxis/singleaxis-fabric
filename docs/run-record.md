# The P1 run record

> **Status:** released in v0.10.0, except the work packages marked
> **Not built** [below](#what-is-built-and-what-is-not); v0.9.x and earlier
> do not have it. Design:
> [spec 050](../specs/050-run-structure-and-records-p1.md), which builds
> phase P1 of [spec 049](../specs/049-four-layer-capture-coverage.md).
> Implementation: the modules listed [below](#where-the-code-lives).
> Terms are defined in the [glossary](glossary.md).

Before v0.10.0 Fabric sequenced only wire-captured model calls, per
process. P1 turns the record into one ordered structure that both inputs
share and that can span processes and hosts:

- **one allocator per process.** Wire exchanges and records from the SDK
  take positions from the same counter, so their order within a process
  epoch is exact;
- **the records input.** Records the application reports (and, later,
  records opt-in hooks observe) travel on the same spool and sender as
  wire exchanges, with the same loss and delivery guarantees;
- **epochs that are identities.** An epoch is a 63-bit random number,
  registered at `install()` so a killed writer is detected by the next
  process;
- **segments, seals and resume tokens.** A run is a graph of immutable
  segments. Each segment is sealed with a digest that the verifier
  recomputes from the store; a resume token lets another process or host
  continue the run;
- **capture manifests.** Each epoch states what it could capture, so the
  verifier can tell "nothing happened" from "nothing was instrumented";
- **the step projection.** The verifier writes a second document,
  `fabric.step-projection/v1`, with one entry per model call, its field
  coverage in the four layers and per-layer verdicts.

## What is built and what is not

Every package marked Built is in v0.10.0.


| 050 work package | What it delivers | State |
|---|---|---|
| WP-00, WP-01 | Contract deltas, vectors, shared types | Built |
| WP-10 | Random epochs, registration, shared allocator | Built |
| WP-11a, WP-11b | Records input, evidence carrier, seal accumulator; `record` spool kind, typed markers, segment-attributed losses | Built |
| WP-12 | Segments, run identity, `fr3/` resume tokens, `end_run` | Built |
| WP-13 | Capture manifests | Built |
| WP-14 | Wire exchange enrichment (event ids, segment ids, endpoint id) | Built |
| WP-16 | `CallRecorder` and the adapters as records producers | Built |
| WP-20 | fabricguard records class and seal-parity test | Built |
| WP-30 to WP-33 | Verifier: records, manifests, seals, segment graph, run states, step projection, model-call fields | Built |
| WP-50 | P1 end-to-end test | An end-to-end test is built (`sdk/python/tests/test_p1_projection_e2e.py`); the full LR-1 harness (`qualification/run-structure/`) is not |
| WP-15 | `decision()` and `record_*` on the records input | **Not built** |
| WP-21 | Node content validation before acknowledgement | **Not built** |
| WP-40 to WP-45 | P1-A: sticky withholding, parity, governed store, passivity harness | **Not built** |

## Using it

Nothing changes for an agent that only uses wire capture: install as in
the [quickstart](quickstart.md). The new run controls are in
`fabric.wire`:

| API or setting | Effect |
|---|---|
| `fabric.wire.run(run_id, *, session_id, user_id, parent_run_id, resumed_from, links, resume, resumable, final, open_deadline_s)` | Opens a run scope. The new arguments describe the run and how it continues; malformed arguments are dropped, never raised (unless `FABRIC_RECORDS_STRICT=1`). |
| `fabric.wire.resume_token()` | Seals the current segment and returns an `fr3/` token another process can pass as `resume=` to continue the run. |
| `fabric.wire.resume_tokens(n)` | Seals once and returns `n` branch tokens, each for exactly one consumer. |
| `fabric.wire.end_run(run_id, outcome, *, resume, stop_reason=None)` | Ends a resumable run from its tokens (for an orchestrator). Returns a status; never raises. |
| `fabric.wire.install(patch_httpx=False, patch_aiohttp=False)` | Records-only install: spool, allocator, manifests and sender without teeing any model client. |
| `FABRIC_RUN_ID`, `FABRIC_RUN_RESUME_TOKEN` | Same-host child processes join the parent's run, or resume from a token, without code changes. |
| `FABRIC_RUN_OPEN_DEADLINE_S` | How long a resumable run may stay open (default 7 days). |
| `FABRIC_CLOCK_UNCERTAINTY_MS` | The clock uncertainty this process declares in its manifest (default 1 s). |
| `FABRIC_RECORDS_MAX_OBJECT_BYTES` | Size cap of one records-input content object (default and maximum 16 MiB). |

The verifier gains these options (see [reconstruct](reconstruct.md) for the
rest):

| Option | Effect |
|---|---|
| `--projection FILE` | Also write the `fabric.step-projection/v1` document. |
| `--coverage-profile ID` | The coverage profile the projection is judged against (default `fabric.profile.model-calls/v1`). |
| `--evaluated-at RFC3339` | The time at which run states and open-run deadlines are evaluated (default: now). |
| `--clock-uncertainty`, `--max-clock-uncertainty` | The verifier's own clock uncertainty, and the largest total it accepts before ordering is `clock_uncertain`. |

The exit code is `0` only when every run is complete **and** its run state
is `terminated` (or absent, for a pre-P1 capture). An `open` run exits `1`:
it is not a completeness claim.

## Where the code lives

Paths are relative to
[`sdk/python/src/fabric/`](../sdk/python/src/fabric/) unless noted.

| Module | Role | 050 section |
|---|---|---|
| [`_sequence.py`](../sdk/python/src/fabric/_sequence.py) | Source identity, epochs, the shared `SourceAllocator`, run-scope context, pseudonyms | §3.2, §3.3 |
| [`wire/_registration.py`](../sdk/python/src/fabric/wire/_registration.py) | Epoch registration files in the spool directory | §3.2 |
| [`_records.py`](../sdk/python/src/fabric/_records.py) | The records input: `Attempt.emit`, phases and status inputs | §3.4 |
| [`_evidence.py`](../sdk/python/src/fabric/_evidence.py) | The structured evidence carrier | §3.4a |
| [`_capture_types.py`](../sdk/python/src/fabric/_capture_types.py) | Types shared by every P1 module | §3 |
| [`wire/_spool.py`](../sdk/python/src/fabric/wire/_spool.py), [`wire/_sender.py`](../sdk/python/src/fabric/wire/_sender.py), [`wire/_pipeline.py`](../sdk/python/src/fabric/wire/_pipeline.py) | Spool kinds, sender, capture worker | §3.5 |
| [`_segments.py`](../sdk/python/src/fabric/_segments.py) | Run table, segments, resume tokens, `end_run` | §3.6 |
| [`_seal.py`](../sdk/python/src/fabric/_seal.py) | Canonical record digest, seal digest, seal accumulator | §3.7 |
| [`_manifest.py`](../sdk/python/src/fabric/_manifest.py) | Capture manifests | §3.8 |
| [`wire/_attrs.py`](../sdk/python/src/fabric/wire/_attrs.py) | P1 keys on every exchange span | §3.9 |
| [`call_recorder.py`](../sdk/python/src/fabric/call_recorder.py), [`adapters/`](../sdk/python/src/fabric/adapters/), [`http_dispatch.py`](../sdk/python/src/fabric/http_dispatch.py) | Explicit producers in `records` mode | §3.10 |
| [`reconstruct/_inputs.py`](../sdk/python/src/fabric/reconstruct/_inputs.py), [`_verify.py`](../sdk/python/src/fabric/reconstruct/_verify.py), [`_report.py`](../sdk/python/src/fabric/reconstruct/_report.py) | Reading records, manifests and seals; integrity | §3.12 |
| [`reconstruct/_graph.py`](../sdk/python/src/fabric/reconstruct/_graph.py) | Segment graph, rules G1–G10, run states | §3.12 |
| [`reconstruct/_project.py`](../sdk/python/src/fabric/reconstruct/_project.py), [`_fields_model.py`](../sdk/python/src/fabric/reconstruct/_fields_model.py), [`reconstruct/_evidence.py`](../sdk/python/src/fabric/reconstruct/_evidence.py) | The step projection | §3.13 |
| [`fabricguardprocessor/records.go`](../components/otel-collector-fabric/processor/fabricguardprocessor/records.go) | Node admission of the records class | §3.14 |
| [`contracts/coverage/v1/`](../contracts/coverage/v1/README.md), [`contracts/capture/v1/`](../contracts/capture/v1/README.md) | Schemas, registries, fixtures and vectors | §4 |
| [`scripts/contracts/p1_reference.py`](../scripts/contracts/p1_reference.py) | Reference implementations used to produce the vectors | §4.3 |

Tests: `sdk/python/tests/test_records_*.py`, `test_segments*.py`,
`test_manifest.py`, `test_reconstruct_project.py`,
`test_reconstruct_records.py` and `test_p1_*.py`; Go tests in the
fabricguard package (`records_test.go`, `seal_parity_test.go`).
