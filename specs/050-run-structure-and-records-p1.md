---
title: Run structure, records input and model-call projection (049 P1 and P1-A build spec)
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 1
last_updated: 2026-10-22
owner: recorder-engineering
depends_on: 047, 048, 049
related: 029, 043, 044, 045, 046, 053, 055
implements: 049 rev 6.4 §8.2 P1 and P1-A (sections 1.3, 2.3-2.6, 2.8, 2.10-2.13, 4.4, 6, 7.1)
---

# 050 — Run structure, records input and model-call projection (P1, P1-A)

This is the build spec for spec 049 phases **P1** (emitters and model-call
projection) and **P1-A** (mixed capture and passivity qualification). It
implements 049 rev 6.4. It does not redesign 049. Where 049 is ambiguous or
conflicts with the code or with owner decisions 21–25, the conflict is listed
in section 9 with exact replacement text.

References are `file:line` at main `36f7a89`. Python paths are relative to
`sdk/python/src/fabric/`. Collector paths are relative to
`components/otel-collector-fabric/`: `P/` is `processor/fabricguardprocessor/`
and `E/` is `exporter/fabriccontentexporter/`.

---

## 1. Scope

### 1.1 Phases and outcome

| Phase | Delivers |
|---|---|
| P1 | 63-bit CSPRNG epochs registered at `install()`. One `SourceAllocator` per process, shared by both inputs. The **records input** on the unified spool (spool kind `record`). `fabric.event_id` on every record. Segments, the segment seal, the resume contract and `end_run`. Capture manifests. Wire-span enrichment. The explicit producers moved onto the records input. Verifier support for records, manifests, the segment graph and run states (`open`, `unterminated`). The model-call `fabric.step-projection/v1`. The fabricguard records class. Content validation before acknowledgement (§3.14). |
| P1-A | Sticky withholding (`ExplicitScope.withheld`). D2 ownership shown in the projection. Explicit-line parity (exact bytes, governed redaction, 16 MiB cap). A qualified-run regression. The governed local store as a backend of the one content writer. A per-client qualification matrix. A shared passivity harness. A list of modules proposed for retirement, for owner sign-off. Nothing is deleted. |

### 1.2 Field ids delivered

| Layer | P1 | P1-A |
|---|---|---|
| Cross-cutting | X02, X03 (key only, no producer), X04, X05 (wire spans and markers), X06, X07, X08 (mapping per decision 22), X10–X14 (`run()` arguments), X17–X19, X21 (projection links), X22–X27, X30, X34–X36, X38, X39, X41–X46, X48 (new, §4.1) | X32 parity |
| Context | C08 and C11 (inferred `input` steps), C16, C19–C23, C34–C40 | — |
| Structure | S01, S03, S07–S09, S11 (provider), S12 (parsed), S13 and S15 (inferred `retry` only), S29–S31, S34 | — |
| Content | N01–N16, N18–N21, N53, N55 (parsed), N60 | N01 explicit parity |
| Decisions and effects | D17, D31–D34; D30 only when `end_run()` emits it (§3.6) | — |

### 1.3 Capture points

| Capture point | P1 change |
|---|---|
| `fabric.self` | Event ids, manifests, segment seals, epoch registration |
| `install.config` | Identity block (X05) on wire spans and markers; clock uncertainty |
| `wire.py.httpx`, `wire.py.aiohttp` | Sequenced on the shared allocator; S01, S03, S07–S09, S30, X05, X26 on exchange spans |
| `run.scope` | `run()` arguments, segments, tokens, `end_run` |
| `sdk.records` | `decision()`, `record_*`, `tool_call()` and `llm_call()` emit sequenced records (metadata only; decision content stays on its current path until P2) |
| `explicit.call_recorder`, `explicit.final_http`, `explicit.byte_boundary`, `explicit.subprocess_artifact` | Records producers on the shared allocator and spool, unless qualified-run mode is selected (§3.10) |
| `reconstruct.parse`, `reconstruct.infer` | Model-call projection and inferred links |

The TypeScript side is out of scope (decision 9; spec 055). The TypeScript
manifest keeps reporting `unsupported`. The vectors added here (§4.3) are
shared with spec 055.

### 1.4 Exit gates

These are copied from 049 §8.2 and tightened. Each **T** row is added by this
spec.

**P1 exit — projection.**
- The verifier rebuilds the OpenAI Chat, OpenAI Responses (hosted tools,
  `previous_response_id`, stored conversations) and Anthropic Messages
  (thinking, redacted thinking, server tools) fixtures with a wrapper for
  every `R` field of `fabric.profile.model-calls/v1`.
- A 40 MiB request with one image keeps its text and reassembles to
  `source_sha256`. A 70 MiB side is `truncated(body_cap)`.
- Fixtures for malformed, compressed, SSE, early-close, cancellation,
  unknown-item and unresolved-dependency cases.
- The 047 §4.10 budgets still pass.
- **T1:** every projection the test suite produces passes
  `validate_coverage_contracts.validate_projection`.

**P1 exit — shared allocator and manifests.**
- Wire exchanges, decision records and explicit-producer records interleave
  on one source and verify.
- A sampled-out host span is not a gap. A dropped spool entry is a gap.
- A lost trailing manifest is detected from the heartbeat.
- A 047/048-era verifier is refused by documentation only.
- Two retries with identical caller ids are two attempts.
- Two processes forced onto the same epoch are detected. On one spool the
  epoch is redrawn at `install()`; otherwise the verifier reports
  `segment_conflict`.
- A `spawn` pool worker killed before its first record is declared as
  `unsealed_epoch`. A forked `with Pool()` worker killed by `terminate()` stays
  accounted and never complete.
- An `r-`-shaped caller run id is mapped. Two processes passing the same clear
  id under one key share one run id.
- **T2:** a spawned worker that allocated a sequence and was SIGKILLed before
  its capture worker wrote it shows as a sequence gap of its epoch, not only
  as an epoch declaration (§3.2 rule 5).
- **T3:** the seal digest the agent computes equals the digest the verifier
  recomputes from a Node export, byte for byte, across every record class
  (§3.7). This is the seal-parity test.

**P1 exit — LR-1.** The full long-running reference scenario of 049 §8.2,
every asserted verdict, run as `qualification/run-structure/lr1` (§6.2).

**P1 exit — Node.**
- **T4:** a content record that fails any stateless check is refused with
  HTTP 400 before acknowledgement and counted `content_rejected` by the agent.
  No refused record reaches the Node queue (§3.14).

**P1-A exit.** All of the following hold:
- nested and concurrent calls; explicit failure and withholding;
- a response that outlives its scope, and one that outlives a withholding
  scope (sequence allocated, no bytes, `store_reason=explicit_withheld`);
- executor duplicates (both kept, linked only by an explicit `same_as`);
- fork and restart; recorder fault injection;
- results, exceptions and chunk behaviour unchanged;
- latency and memory budgets pass.

Further P1-A gates:
- **T5:** the explicit-line parity suite (§3.15) passes for every privacy
  mode.
- **T6:** the 045/046 suites pass unchanged on the qualified-run journal.

**Conformance:**
- C1-1: event id stable across retry and re-export.
- C1-2: manifest sequencing and chain.
- C1-3: projection schema.
- C1-4: split reassembly.
- C1-5: no false complete (a fixture for every rule of 049 §6.2).
- New C1-6: seal parity (T3).
- New C1-7: LR-1.
- New C1A-1: explicit parity (T5).
- New C1A-2: qualified-run regression (T6).
- New C1A-3: shared passivity harness.

---

## 2. Current state

| Area | Today | Missing for P1 |
|---|---|---|
| Epochs | `_new_epoch()` is wall-clock µs plus `pid % 1000` (`_sequence.py:152-157`). Fork re-draws it (`_sequence.py:428-433`). There is no registration. | CSPRNG epochs; registration under `flock(.admit)`; spawned-worker visibility |
| Allocator | `SourceAllocator` refuses any component except `wire` (`_sequence.py:165-167`). `next_sequence()` returns `(epoch, seq, scope)` (`:174-188`). `close_scope` is at `:193-196`. `seal()` re-draws the epoch (`:202-210`). | One process component; segment id at allocation; settlement accounting |
| Run scope | `fabric.wire.run(run_id)` only (`wire/__init__.py:594-620`). `run_scope` is at `_sequence.py:231-247`. Markers are `run_start` and `run_end` only (`_loss.py:40,206-220`). | `run()` arguments, segments, predecessors, tokens, `end_run`, env |
| Markers | `_Beat` is a 6-tuple `(source, epoch, last, run_id, scope_id, kind)` (`_loss.py:46,65-73`). The spool marker allows `run_start`, `run_end` and `final` only (`wire/_spool.py:230-234,263-266`). | Typed markers carrying segment, seal and manifest fields |
| Spool | Kinds are `exchange`, `loss` and `marker` (`wire/_spool.py:79,219-251`). Exchanges are written in batches (`FWSPOOLB`). The envelope (`FWSPENC1`), the loss ledger (`wire/_ledger.py`) and the fork ledger (`wire/_forks.py`) exist. | Kind `record` with bodies; marker extensions |
| Wire span | Ids, digests, refs and `gen_ai.*` (`wire/_pipeline.py:162-192`). The name is `fabric.model_call` (`wire/_model.py:22`). | `fabric.event_id`, `fabric.capture.input`, `fabric.capture.point`, `fabric.run.segment_id`, S01, S03, S07–S09, S30, X05 |
| Records | `decision()` spans and events go through the host tracer only (`decision.py:607-700`; events at `:1119,1235,1323,1398,1557,1605,1680,1803,1935,1999,2139,2209`). `tool_call()` and `llm_call()` spans are named per the GenAI convention (`_calls.py:178-181`). They have no sequence and no event id. | A sequenced records copy on Fabric's path |
| Explicit line | `CallRecorder` has its own per-(tenant, run) sequence (`call_recorder.py:151-175`) and journals to `SyntheticSourceSpool` (`:189-229`). Bytes go to `ByteEvidenceRecorder.capture` (`byte_evidence.py:471`), whose cap is `payload_max_bytes` (default 1 MiB, maximum 16 MiB, `:276,352`). An oversized object is `dropped` / `payload_too_large` (`:656-661`). `FinalHTTPAdapter` uses a `CallRecorder` (`http_dispatch.py:45-66`). `ByteBoundaryAdapter` uses `SyntheticCaptureSession` (`adapters/byte_boundary.py`). | Records-producer mode |
| D2 | A provisional exchange exists and `adopt()` is implemented (`wire/_transport.py:140-220`). `ExplicitScope` holds only `model` and `ended` (`_capture_scope.py:43-58`). | `withheld` (P1-A) |
| Verifier | `observe()` classifies spans as exchange, heartbeat or loss, and ignores everything else (`reconstruct/_inputs.py:520-551`). `HEARTBEAT_KINDS` lacks `segment_seal` (`:73-74`). `SpanRecord` has no status (`:111-122`). A records span's sequence counts as missing because only exchanges fill `_Source.sequences` (`_verify.py:495`). The report schema is closed (`contracts/capture/v1/schema/run-reconstruction-v1.schema.json`). | Records, manifests, seals, graph, run states, projection |
| Projection | The schema, 8 valid and 23 invalid fixtures, and `validate_projection` exist (`contracts/coverage/v1/schema/step-projection-v1.schema.json`; `scripts/contracts/validate_coverage_contracts.py:1202-1438`). There is no producer. `StitchKeys` already computes tools and system digests, finish reasons, usage and roles, which are not reported (`reconstruct/_stitch.py:47-67`). | A producer |
| fabricguard | Admits `segment_seal`, `run_start`, `run_end` and `final` (`P/processor.go:1093`). Places P1 keys by class (`P/coverage_keys.go:314-370`). A span with no marker key is not a capture span. `fabric.attempt.uid` is admitted on non-capture spans only. `fabric.capture.input` is admitted on exchanges only. The span name is re-derived from attributes (`P/processor.go:895-947`). | A records class; seal-safe naming; X05/X13/X14 placement |
| fabriccontent | The receiver returns 200 once the record is queued. Validation runs in the queue consumer (`E/exporter.go:108-154`). A refused record is dropped and returns nil (`:183-187`). The gate allows only `memory_limiter` before it (`gate/gate.go:725-747`). | Stateless validation before acknowledgement |

---

## 3. Design

### 3.1 One process, one source, one path

```text
host thread                       capture worker (1 thread)        sender (spool holder)
-----------                       -------------------------        ---------------------
wire tee begin/adopt ─┐
records.emit(...)  ───┼─ allocate(scope) under allocator lock
CallRecorder event ───┘   -> (epoch, seq, segment_id)
                           put_nowait(Job) ── full: queue_full loss
                                              PROTECT bodies (wire _protect.Protector)
                                              record digest -> SealAccumulator
                                              spool write (exchange|record batch)
                                              settle(seq) ── seal ready -> marker
                                                                       drain: content POST,
                                                                       then span export
```

All of these hold at once:
- `SourceAllocator` (`_sequence.py`) is the only allocator in the process.
- `CapturePipeline` (`wire/_pipeline.py`) is the only capture worker.
- The wire `Spool` is the only spool, outside qualified-run mode.
- `Sender` is the only drainer.
- `fabric.reconstruct` is the only verifier.

The records input therefore has exactly the wire input's delivery guarantees,
which is the claim of 049 §2.4.

**Activation.** The records input is active only while a wire handle is
installed (`install()` or autoload). The handle is the single install: there
is no second install API. Without a handle, every records producer behaves as
it does today and emits nothing sequenced. `decision()` keeps its host spans,
and `CallRecorder` keeps its legacy journal (§3.10).

### 3.2 Epochs and registration (`_sequence.py`, new `wire/_registration.py`)

1. **Drawing an epoch.** `_new_epoch()` becomes `secrets.randbits(63)`,
   redrawn while it is 0. Drawing needs no `_LOCK`, but `_LIVE` stays guarded.
   The fork hook (`_sequence.py:428-433`) and `seal()` use the same function.
   `os.urandom` is fork-safe.
2. **Registration** (install only, synchronous). `install()` calls
   `registration.register(spool, source_id, epoch)` after the allocator is
   created and before the handle is published (`wire/__init__.py:386-393`). Under
   `Spool._admission()` (`wire/_spool.py:484-510`):
   - It creates `.epochs/<epoch:020d>.reg` with mode 0600, `O_NOFOLLOW` and
     `O_EXCL`, at a fixed size of 4096 bytes. It writes it fully and fsyncs it.
   - It holds `flock(LOCK_EX)` on the file for the writer's lifetime.
   - If the name exists and its flock is held, or exists unheld without the
     `final` flag, the epoch is redrawn (at most 8 times, then `internal_error`
     is reported in `status()` and capture continues unregistered).
   - Layout of the 4096 bytes:

     | Offset | Field |
     |---|---|
     | 0 | `b"FWEPOCH1"` |
     | 8 | u32 version (1) |
     | 12 | u64 epoch |
     | 20 | u32 pid |
     | 24 | u64 registered_at_unix_nano |
     | 32 | u16 source_id length, then the UTF-8 source id (at most 160 bytes) |
     | 256 | u64 `next_sequence` |
     | 264 | u8 `final` |
     | 4064 | sha256 of bytes 0–255 (the immutable header) |

3. **The hot-path mirror.** The file is `mmap`ed with `MAP_SHARED`.
   `SourceAllocator.next_sequence*` stores `next_sequence` with one
   `struct.pack_into` under the allocator lock. That is a memory store with no
   system call, the technique `wire/_forks.py:42-46` already uses on the
   request path. `final()` sets the `final` flag, then the writer closes and
   unlinks the file after the `final` marker is spooled.
4. **No registration** for a forked child (the child drops the parent's
   mapping in `after_fork`; the fork ledger and declared branches cover it), for
   direct mode without a spool, or for an epoch drawn by `seal()`. A post-final
   epoch is registered by the sender thread off the request path on its first
   allocation; until then it is covered as a fork child is.
5. **Orphans.** On each pass the drainer (the holder of `.lock`) scans
   `.epochs/` under `_admission()`. A registration it can `flock` (the writer
   is gone) with `final == 0` is an orphan. For each orphan:
   1. It queues a `periodic` heartbeat for `(source_id, epoch, next_sequence − 1)`
      when `next_sequence > 0`, exactly as `_child_beats` does
      (`wire/_transport.py:188-192`). The killed worker's allocated but unwritten
      positions then become a visible gap (T2).
   2. It renames the file to `.epochs/<epoch>.orphan`.
   3. Manifest 0 of every later registered epoch on this spool lists the
      `.orphan` files in `unsealed_prior_epochs` / `unsealed_prior_epoch_count`
      (049 §2.12 rule 5).
   4. An `.orphan` file is removed after it has been declared by one spooled
      manifest 0 and its heartbeat has been delivered, or after
      `open_run_deadline_s`, whichever is later.

   At most 4096 registration files are kept. Beyond that a new registration is
   refused (`registration_full` in `status()`) and capture continues.
6. **Limits, stated exactly.**
   - Run attribution of an orphan epoch exists only for the segments whose
     records reached the store.
   - A consumer that is wholly lost stays the residual limit of 049 §2.10.
   - A host crash that loses the dirty mmap page loses the `next_sequence`
     mirror, but not the registration, which was fsynced at install.

### 3.3 Shared allocator (`_sequence.py`)

- `Component = Literal["process"]`, and the guard at `:165-167` accepts it. A
  `"wire"` argument is accepted as an alias for one release.
  `get_allocator("process")` is the only call site. The default source label
  stays `default_source_id("wire")` so source ids are unchanged across the
  upgrade.
- **Allocation result.** `next_sequence()` and `next_sequence_for(scope)`
  return an `Allocation(epoch, sequence, scope, segment_id, manifest_seq)`
  named tuple. Under the allocator lock they:
  1. resolve the scope as today;
  2. call `segments.on_allocate(allocation)` (§3.6), which returns the open
     segment id of the scope's run and opens a new segment if none is open;
  3. update the registration mirror (§3.2 rule 3);
  4. increment `outstanding[segment_id]` (§3.7).

  The lock stays short, with no I/O and no allocation beyond small objects.
- **Settlement API** (worker and loss paths only):
  `allocator.settle(segment_id, sequence, entry)`, where `entry` is a record
  digest or `"loss:<reason>"`. It decrements `outstanding` and hands the entry
  to the `SealAccumulator`.
- **Losses settle too.** Every loss path settles: `_drop`, `_fail`,
  `_spool_batch` non-spooled outcomes (`wire/_pipeline.py:246-273,363-405`),
  `WireTee.lose` (`wire/_transport.py:284-286`), uninstrumented clients
  (`:276-282`) and shutdown claims in `close()`. The single funnel is
  `LossEmitter.record` (`_loss.py:183-187`), which gains an optional
  `segment_id` and calls `settle`.

### 3.4 Records input (new `_records.py`)

**API (internal; a public facade is P2).**

```python
Phase = Literal["start", "data", "update", "end"]
PrivacyMode = Literal["omit", "metadata_only", "redact", "tokenize", "masked_only",
                      "original_plus_masked", "retain_original"]

class RecordsInput:                       # one per installed handle
    def begin(self, kind: StepKind, point: str, *, step_id: str | None = None,
              parent_attempt: str | None = None,
              aliases: Mapping[str, str] = {}) -> Attempt | None: ...
    def mode_of(self, role: str) -> PrivacyMode: ...      # R-D
    def v2(self, prefix: str, value: str) -> str | None: ...  # R-E
class Attempt:                            # never raises; None/False on any Fabric failure
    uid: EmittedId                        # uuid4, dashed (X19); minted here, never taken
    def emit(self, phase: Phase, *, name_hint: str,
             attributes: Mapping[str, AttrValue], start_ns: int, end_ns: int,
             status: Literal["unset", "ok", "error"] = "unset",
             bodies: Sequence[RecordBody] = (), event_id: str | None = None,
             span_ids: SpanIds | None = None) -> bool: ...
@dataclass(frozen=True, slots=True)
class RecordBody:                         # data stays in memory until the worker's PROTECT
    role: str; data: bytes | str; media_type: str; boundary: str   # R-B
    provenance: Literal["caller_reported"] = "caller_reported"
    stream_id: str | None = None; chunk_index: int | None = None
MAX_RECORD_BODIES = 8                     # R-A
```

**Phases (R-C).**

| Phase | Lifecycle and status it stamps |
|---|---|
| `start` | `fabric.step.lifecycle_state=running` |
| `data` | `fabric.step.lifecycle_state=running`. Use it only while the step is in progress. |
| `update` | Neither `fabric.step.lifecycle_state` nor `fabric.step.status`. It adds bodies or attributes to an attempt in any lifecycle state, including after `end` (for example a P2/P3 resolution, receipt or late content). The projection merges it into the attempt without changing the lifecycle. |
| `end` | `completed` or `cancelled`, plus `fabric.step.status` |

A caller-supplied lifecycle or status key on an `update` is dropped by rule A.

**`mode_of(role)` (R-D).**
- It returns the privacy mode the capture policy resolves for `role`, using the
  049 §2.7 precedence. The result is cached per role for the epoch, because the
  policy is fixed per epoch.
- It returns `omit` when content capture is disabled (049 §7.3), when the role
  is unknown to the role table, or on any internal failure (fail closed).
- Producers call it **before** serialising a body. Under `omit` they build no
  `RecordBody` at all: no `json.dumps`, no encoding and no copy on the app
  thread. Under `metadata_only` they still pass the body, because the worker
  needs its length for the descriptor, or they pass a zero-length placeholder
  with `metadata_only` noted (a P2 producer's choice).
- The call is pure and lock-free, a dict lookup.

**`v2(prefix, value)` (R-E).**
- It returns:
  - `value` unchanged when `value` is an `EmittedId` issued under this handle's
    key (or generator);
  - otherwise the pseudonym v2 of `value` with the handle's id key
    (`_sequence.pseudonym_v2`, 049 §2.9 rule 2), whatever the value's shape
    (decision 22);
  - `None` without a key (049 §2.9 rule 5: omitted).
- In the production profile without a key it returns `GeneratedIds.other(value)`
  (random `g-` ids) only for the explicit line's join ids. For every v2 type it
  returns `None`.
- In `identity_mode=clear` it returns the value as given.
- Results are `EmittedId`s, so they pass through again.
- `prefix` must be a key of `_sequence.V2_TYPES`; anything else raises
  `ValueError`, which is an API misuse, not a capture failure.

**String bodies (R-B).**
- A `str` body is kept by reference. It is encoded to UTF-8
  strictly (a lone surrogate makes the object `not_captured(parse_failed)`) on
  the capture worker, never on the app thread.
- Until it is encoded, the in-flight charge is `len(data) * 4`, the UTF-8 upper
  bound. The charge is corrected after encoding.
- Bodies are frozen. A mutable object (a `bytearray` or `memoryview` of mutable
  memory) is refused with `ValueError` at `RecordBody` construction, because a
  later mutation by the app would change captured bytes.

**Each `emit` call:**
1. Projects the attributes (rule A below).
2. Allocates one sequence through `allocator.next_sequence()`.
3. Builds an immutable `RecordJob` holding the span dict and the bodies by
   reference. Retention follows the wire rule (049 §7.4): bodies are charged to
   `max_inflight_bytes` and refused beyond it as `inflight_budget`.
4. Calls `pipeline.submit(job)`. A full queue is a `queue_full` loss for that
   position, as for exchanges (`wire/_pipeline.py:249-262`). It never waits.
5. Catches every exception. After allocation an exception becomes an
   `internal_error` loss.

**Rule A — the attribute projection.** It is fail-closed and generated.
- `_records_keys_generated.py` is generated by
  `scripts/contracts/generate_p0_contracts.py` from the telemetry-key registry
  and `P/allowlist.go`. It holds the exact key set fabricguard admits on a
  records-class span (§3.14), with each key's check (enum, pattern, int range,
  bool, array bound).
- A key that is not in the table, a value that fails its check, a float, a
  map or bytes is dropped and counted (`records_keys_dropped`). It is never
  hashed or truncated.
- The emitter therefore emits exactly what the Node keeps, which is what makes
  the seal recomputable (§3.7).
- No content key exists in the table. A CI test asserts that the table and the
  Go table are equal.

**Rule N — names.**
- The record's span name is `category(name_hint, attributes)`, a Python port of
  fabricguard's derivation (`P/processor.go:895-947`).
- It is pinned by the shared vector `span-category-v1.json` (§4.3), so the name
  in the agent's digest equals the name the Node exports.
- Wire spans already use `fabric.model_call`.

**Keys every record carries.**

| Key | Value |
|---|---|
| `fabric.capture.input` | `records` |
| `fabric.source_id` | the allocation's source |
| `fabric.source.epoch` | the allocation's epoch |
| `fabric.source.sequence` | the allocation's sequence |
| `fabric.event_id` | dashed uuid4, minted before allocation, or the explicit `record_id` normalised |
| `fabric.attempt.uid` | the attempt's uid |
| `fabric.capture.point` | `<id>@<sdk version>` |
| `fabric.step.kind` | the record's step kind |
| `fabric.actor.type` | `agent` unless supplied |
| `fabric.run.id` | when in a run |
| `fabric.run.scope_id` | when in a run |
| `fabric.run.segment_id` | when in a run |
| `fabric.step.lifecycle_state` | `running` for `start` and `data`; `completed` or `cancelled` for `end`; absent on `update` |
| `fabric.step.status` | on `end` only |
| `fabric.content.object_ids` | when there are bodies (new key, X48, §4.1) |

Caller ids appear only as their mapped forms (decision 22), for example
`fabric.step.id` and `fabric.step.attempt_id`.

**Span ids.**
- When `span_ids` names a host span (the decision span or a `tool_call()`
  span), the record reuses that span's `trace_id`, `span_id` and
  `parent_span_id`. The host span id then is the record's own span id, and the
  `records.span_id` alias (049 X38) needs no new key.
- Otherwise the span id is new and its parent is the current span.
- On the spool path the ids are written into the span dict directly
  (`wire/_pipeline.py:474-487` pattern).
- On the private-provider path Fabric's private `TracerProvider` uses an
  `IdGenerator` that honours a thread-local override set for the one
  `start_span` call.
- In `global` tracer mode the ids cannot be chosen. The record is then a child
  span of the host span, and the alias is unresolved (§8, R3).

**Without a spool.** The worker emits the record through
`resolve_capture_provider` (`_loss.py:128-145`), exactly as `_emit` does for
exchanges (`wire/_pipeline.py:489-514`).
- A refused provider or a non-recording span is a `span_dropped` loss.
- D3 is unchanged: a protected provider never carries a record.
- The host's own spans stay best-effort duplicates. They never carry
  `fabric.source.*`, and the verifier ignores an unsequenced span that has an
  `event_id` (§3.12).

### 3.5 Spool and sender (`wire/_spool.py`, `wire/_sender.py`, `wire/_pipeline.py`)

- **Record kind.**
  - `_KEYS["record"] = {"service_name", "span", "bodies"}`.
  - `valid_header` accepts `record_kind == "record"` with the same span checks
    as an exchange, but requires `fabric.capture.input == "records"` and
    `fabric.attempt.uid`, and forbids `fabric.wire.exchange_id`.
  - Bodies have the same shape as exchange bodies, with `MAX_RECORD_BODIES = 8`
    (R-A: up to four roles per record, each with a primary and a review copy;
    a P3 control record uses three roles).
  - `record_doc(...)` mirrors `exchange_doc` (`:269-276`).
  - Batches mix `exchange` and `record` frames in one `FWSPOOLB` file.
- **Markers.**
  - `_Beat` is replaced by a frozen `Marker` dataclass in the new
    `_capture_types.py`. Its fields are `kind`, `source_id`, `epoch`,
    `last_sequence`, `run_id`, `scope_id`, `segment_id`, `predecessors`,
    `resumable`, `open_deadline_s`, `declared_branches`, `branch_ids`,
    `terminal`, `seal` (`last_sequence`, `manifest_digest`, `seal_digest`,
    `branch_ids`), `manifest_id`, `manifest_digest`, `manifest_seq`,
    `scope_status`, `outcome`, `session_id`, `user_id`, `parent_run_id`,
    `resumed_from`, `links`, `manifest` (attributes) and `event_id`.
  - `marker_doc` / `valid_header` follow the capture/v1 `marker` branch
    exactly. That branch is already in the schema; nothing changes except the
    session and user keys in §4.2.
  - The loss ledger (`wire/_ledger.py`) stores marker records unchanged. A
    manifest marker that exceeds `_PAYLOAD_MAX` is not mirrored there
    (`manifests_unledgered` stat). The heartbeat's `manifest_seq` still exposes
    the loss (049 §2.4 rule 4).
- **Sender.**
  - `_drain` sends a record's bodies with `_send_bodies`, exactly as for
    exchanges (`wire/_sender.py:333-384,412-426`).
  - `_span` builds record spans and marker spans from the typed marker.
  - Root ids of loss and heartbeat spans stay derived from the seed (`:428`).
  - Markers carry `fabric.event_id`, a uuid5 of the marker's logical identity.
    A replayed marker therefore has the same event id, which satisfies X02
    rule 2 without persisting extra state.
- **Pipeline.**
  - `submit` accepts `RecordJob` alongside `CaptureJob`.
  - `_prepare` dispatches on the job class.
  - Record bodies go through the same `Protector.side()`
    (`wire/_protect.py`) with the body's role and boundary, and
    `provenance: caller_reported`. They take the descriptor base of
    `wire/_pipeline.py:537-550`, extended with `attempt_id`.
  - The per-object cap is `min(role cap, records_max_object_bytes)`. An object
    above it becomes a descriptor-only `not_captured` object with
    `status_reason: payload_too_large`, which the projection maps to
    `not_captured(body_cap)` (§9, delta 7).
  - There is no truncation of exact bytes: exact or nothing, as today
    (`byte_evidence.py:656-661`).

### 3.6 Segments and run structure (new `_segments.py`; `wire/__init__.py`)

**State.** A process-level `RunTable` holds one entry per emitted run id. All
of it is mutated only under the allocator lock.

```text
RunEntry {run_id, open_segment: seg-id | None, pending_start: Marker | None,
          sealed: list[SealedSegment], depth: int, resumable: bool, terminal_sealed: bool,
          final_block: bool, open_deadline_s: int | None, root_done: bool,
          outcome: RunOutcome | None, stop_reason: StopReason | None}
SealedSegment {segment_id, last_sequence, manifest_digest, terminal, resumable, branch_ids}
```

**Opening a segment.**
- `segments.on_allocate(allocation)` (called under the allocator lock) and
  block entry both open a segment when `open_segment is None`:
  1. mint `seg-` + 32 hex (`secrets.token_hex(16)`);
  2. set `predecessors` to the pending predecessor list (tokens passed in, the
     local last sealed segment, or the fork parent);
  3. queue a `run_start` marker for it.
- A segment opened by an allocation inside an open block emits a
  **continuation `run_start`**: the block's `scope_id`, the new `segment_id`
  and the predecessors. This needs delta 1 (§9) in the verifier's scope
  pairing.
- A run's root segment has `predecessors = ["none"]`. It carries
  `fabric.run.resumable`, `fabric.run.open_deadline_s`, `fabric.session_id`,
  `fabric.user_id`, `fabric.run.parent_id`, `fabric.run.resumed_from` and
  `fabric.run.links` when supplied. Later segments carry only predecessors,
  branch ids and declared branches.

**Sealing.** A seal moves `open_segment` to `sealed` under the lock and calls
`SealAccumulator.request_seal(segment_id, last_sequence, manifest_digest,
terminal, resumable, branch_ids)`. The accumulator writes the `segment_seal`
once the segment has no outstanding positions (§3.7). The seal triggers are
the five of 049 §2.10:

| Trigger | Seal | Next |
|---|---|---|
| `resume_token()` | non-terminal, `resumable=true`, `branch_ids` | The next allocation or block entry opens a segment with predecessor = this segment |
| fork (before-fork hook) | non-terminal | Child: segment C (minted in the parent). Parent: the next allocation opens P2 with `declared_branches=[C]` |
| Outermost block exit in this process, resumable run | non-terminal, unless the block was `final=True` | — |
| Outermost block exit, non-resumable run | terminal | Any later allocation for this run is post-terminal by construction (§8, R2) |
| `end_run(...)` | terminal, zero-width | — |
| `final()` (epoch end) | non-terminal for every open segment; terminal for a non-resumable run whose outermost block has exited | — |

"Outermost block in this process" means `depth` falls to 0. Depth counts every
open `run()` block of that run id in the process, across threads and tasks.

**Public API** (`fabric.wire`). Every function catches all Fabric failures and
never raises because of capture. Argument errors (an invalid run id) raise
`ValueError`, as `run()` already does (`_sequence.py:239-240`).

```python
@contextmanager
def run(run_id: str | None = None, *, session_id: str | None = None,
        user_id: str | None = None, parent_run_id: str | None = None,
        resumed_from: str | None = None, links: Sequence[str] = (),
        resume: str | Sequence[str] | None = None, resumable: bool = False,
        final: bool = False, open_deadline_s: int | None = None) -> Iterator[None]: ...
def resume_token() -> str | None: ...                      # seals; None outside a run or not capturing
def resume_tokens(branches: int) -> tuple[str, ...]: ...   # 1 <= branches <= 64; () when not capturing
def end_run(run_id: str, outcome: RunOutcome, *, resume: Sequence[str],
            stop_reason: StopReason | None = None) -> EndRunStatus: ...
EndRunStatus = Literal["ended", "refused_no_token", "refused_bad_token", "not_capturing", "failed"]
```

049 writes `resume_token(branches=n)`. This spec splits it into two functions
so the return type is not mixed (§9, delta 4).

**Run outcome hook (for P2).** `run()` still yields `None`; the outcome is not
a return value. P1 ships this internal hook, which P2's public
`fabric.records.set_run_outcome()` calls:

```python
# fabric/_segments.py (P1)
def set_run_outcome(outcome: RunOutcome, stop_reason: StopReason | None = None, *,
                    run_id: str | None = None) -> bool: ...
```

- It stores `outcome` and `stop_reason` on the `RunEntry` of `run_id`, or of
  the innermost open scope's run when `run_id` is `None`. A `run_id` argument
  is mapped (decision 22) unless it is an `EmittedId`.
- It returns `False` (and never raises) when there is no open run or capture is
  not installed. The last call before the scope closes wins.
- `RunOutcome` and `StopReason` are the D30 field-type enums of the registry.
  An unknown value is refused with `ValueError`.
- The **outermost** `run_end` of the run in this process carries
  `fabric.run.outcome` and `fabric.run.stop_reason` (`Marker` gains
  `stop_reason`). fabricguard already admits both keys on `run_end` only
  (`P/coverage_keys.go:367-371`). An inner block's `run_end` carries neither.
- Without a call, the keys are absent and D30 is `unknown` (registry "If hook
  absent").
- `end_run` takes the same optional `stop_reason`.
- P1 emits the keys only through `end_run` and this hook. The public API, its
  docs and the D30 field statuses are P2.

**Argument rules.**
- `run_id`, `parent_run_id`, `resumed_from` and `links` are mapped with
  `run_pseudonym` and the handle's key (decision 22). An `EmittedId` of the
  same issuer passes through.
- `session_id` → `sess-` and `user_id` → `usr-` (v2), omitted without a key.
- `run_id=None` takes `FABRIC_RUN_ID`, which `install_from_env` reads once
  (the clear id).
- `run_id=None` with valid `resume` tokens and no `FABRIC_RUN_ID` is allowed.
  The run id is then **derived from the tokens**: `r-` + the first 32 hex of
  SHA-256 of `"fabric-run-from-token/v1\0"` + the segment id of the first
  valid token. It is an emitted value with no caller input, and every consumer
  of one token derives the same id.

  The verifier joins it with the issuing run through the predecessor entry as
  a `run_aliases` member, exactly as across a key rotation (049 §2.10). This is
  the path for a service-boundary hop that carries only a token (OD-7).
- With neither a run id nor a token, the call raises `ValueError`, as today.
- `resume` takes tokens. When `resume` is `None` and the run id came from the
  environment, it takes `FABRIC_RUN_RESUME_TOKEN` (comma-separated, already
  percent-decoded by the caller). The environment tokens are consumed by the
  first root entry only.

**Resume contract (decision 22).**

| What | How it travels |
|---|---|
| The **clear** run id | The application's own value: `run(run_id=…)` in process, `FABRIC_RUN_ID` to child processes on the same host. Every process maps it with the same key to the same `r-`. An emitted `r-` value is never propagated as a run id: passed in, it is a plain string and is mapped again. |
| Resume tokens | Fabric-emitted values (`fr2/…`), passed on exactly as returned and never mapped. Their segment and source ids are emitted values, so they carry no caller input. Across a service or host boundary, the token alone is the recommended carrier (W3C `baggage` entry `fabric.resume`, or the message attribute `fabric.resume`); the consumer derives its run id from it, as above (OD-7). |
| Key rotation and token-only hops | Both produce different `r-` values for one run. The verifier merges them through predecessor entries into `run_aliases`. |

**Token rules.**
- Tokens are parsed strictly by the `resume-token-v1.json` grammar, with the
  reference parser ported from
  `scripts/contracts/validate_coverage_contracts.py:1541-1588`.
- A malformed token is dropped (`tokens_rejected` stat, one class-only
  warning). If no valid token remains, the segment is emitted as a root
  (`none`). The verifier then sees more than one root, which is
  `segment_conflict`; the run is never silently complete.
- A run opened with a valid token is resumable.
- A token's `branch_id` goes into `fabric.run.branch_ids` of the consumer's
  `run_start`.
- A token is `fr2/<seg>/<source_id>/<epoch>/<last_seq>/sha256:<manifest
  digest>[/br-<hex>]`, built from the sealed segment. `last_seq` is the
  allocator's last sequence at the seal (one counter per source).

**`end_run` emits a zero-width segment.**
1. It mints a scope id and segment id.
2. It emits `run_start` (predecessors = tokens).
3. It emits `run_end` (`fabric.run.outcome` = `outcome`,
   `fabric.run.scope_status=ok`).
4. It emits a terminal `segment_seal` over an empty member list.

The outcome rides on `run_end` because fabricguard admits `fabric.run.outcome`
only on `run_end` (`P/coverage_keys.go:369`; §9, delta 2). Without at least one
valid token, `end_run` returns `refused_no_token` and emits nothing.

**Fork** (`os.register_at_fork`; locks only, no I/O).
- *Before fork*, for each run in the forking thread's scope chain
  (`_SCOPE.get()` and its parents): mint the child segment id C and seal the
  parent's open segment S as non-terminal; record C as a declared branch for
  the parent's next segment.
- *After fork in the child*:
  - The new epoch draw happens in `_sequence._after_fork_in_child`.
  - For each run in the inherited chain: open segment C with predecessor S, and
    replace each inherited open `RunScope.scope_id` with a fresh uuid4. Only
    the child's memory changes. This keeps scope ids unique per source, which
    048 §6 pairing requires.
  - Queue the `run_start` for C and manifest 0 for the child epoch (§3.8).
  - The child's inherited block exit seals C non-terminal (049 §2.10).

**Thread pools.** `ThreadPoolExecutor.submit` does not copy `contextvars`, so
its work runs outside the run (the `trace:` fallback). `asyncio.to_thread` and
`contextvars.copy_context().run` do keep the run. LR-1's thread-pool case uses
the latter, and the docs state this (§9, delta 3).

### 3.7 Segment seal (new `_seal.py`)

**Canonical record digest** (049 §2.12 rule 1). It is computed over
`{name, start_ns, end_ns, status, attributes, content}` with spec-029 canonical
JSON (sorted keys, `(",", ":")`, UTF-8, no floats):

| Part | Value |
|---|---|
| `name` | The category name (§3.4 rule N). |
| `status` | `"unset"`, `"ok"` or `"error"`. Never a description. |
| `attributes` | The emitted attributes minus receiver-owned keys (`fabric.source.authenticated`). Arrays are lists, ints are ints, bools are bools. Attribute decoding in the verifier must produce the same JSON types. `reconstruct/_inputs.py:285-308` already maps int64 strings to int. |
| `content` | For a wire exchange: the stored digests (`sha256:` form) of the request and response primaries, in that order, when present. For a record: the `stored_sha256` of each object in `fabric.content.object_ids`, in list order. A descriptor-only object contributes `null`. |

**Seal digest.** `sha256:` over the canonical JSON of the list of
`[sequence, entry]` pairs, sorted by sequence. Each entry is either a record
digest or `"loss:<reason>"`. An empty segment hashes `[]`.

**`SealAccumulator`.**
- It is owned by the pipeline. It keeps `segment_id → {entries,
  outstanding, seal_request}`.
- The worker calls `settle()` after `spool_exchanges` returns `spooled`, or
  after a span is emitted on the provider path. Loss paths call it through
  `LossEmitter.record`.
- When a seal is requested and `outstanding == 0`, it builds the
  `segment_seal` marker and queues it through `LossEmitter.queue_beat`.
- Memory is bounded: each open or unsealed segment holds at most one
  32-byte digest per position. At 1,000,000 entries for a segment, the
  segment is forced to seal (non-terminal, a new segment continues it locally,
  `segment_forced_seal` stat).
- At `close()`, positions still outstanding become `shutdown` losses (existing
  behaviour), so pending seals complete before `final`. A crash leaves the
  segment unsealed, which the verifier reports as `partial(source_lost)`
  (049 X44).

**What the seal does not include.** A record that was spooled and later
quarantined as corrupt is already in the seal as a digest. Its later
`internal_error` loss makes the segment `partial(seal_mismatch)`. That is
correct, because it is partial either way.

### 3.8 Capture manifests (new `_manifest.py`)

- **Build.**
  - `build_manifest(handle, epoch, *, seq, after, previous_digest,
    unsealed_prior)` returns a `capture-manifest-v1` document. Inputs:
    - the gate (`profile`, `content_capture`, reason, policy reference);
    - the identity mode, pseudonym mode and `key_id`;
    - the limits from `WireConfig`, plus `records_max_object_bytes` from
      `FABRIC_RECORDS_MAX_OBJECT_BYTES` (default 16777216, range 1..16777216)
      and `open_run_deadline_s` from `FABRIC_RUN_OPEN_DEADLINE_S` (default
      604800);
    - `spool_encrypted` and `spool_key_id`;
    - `sequence_unit: record`;
    - `clock` (`uncertainty_ns` from `FABRIC_CLOCK_UNCERTAINTY_MS`; §8, OD-3);
    - `explicit_wins` (D2 state);
    - `endpoint_set_sha256`;
    - `inputs: ["wire","records"]`;
    - `source_auth` (`bound` in node mode, else `unbound`);
    - `chunk_boundaries_retained: false`;
    - `uncaptured_classes` from the detection table (`wire/_detect.py`);
    - one `capture_points[]` row per registry point this runtime has.
  - The `fields` of each row are what **this build** supplies: a generated
    per-build table (`_manifest_fields_generated.py`). The registry `supplies`
    list is a superset. A field the registry assigns to the point but this
    build does not supply is omitted, so the projection reports it
    `unsupported(unsupported_version)` (049 §2.6).
- **Emission.**
  - Manifest 0 is emitted at `install()` for the registered epoch, in a forked
    child's after-fork hook (built from a template cached at install; no I/O),
    and for a post-final epoch on its first allocation.
  - It is a `marker` of kind `manifest` with `last_sequence =
    after_source_sequence`.
  - It is exported as a `fabric.capture_manifest` span whose attributes are
    the `manifest-span-v1` mapping.
  - Its digest is `sha256:` of the canonical JSON of the document. It is
    computed once and cached, so token issue and seals read it without work.
- **State change.**
  - `manifest.capture_point_changed(point, state, reason)` allocates the next
    `manifest_seq` and `after_source_sequence` under the allocator lock,
    chains `previous_manifest_sha256`, and queues the marker. Triggers in P1:
    an aiohttp patch failure or unpatch, `uninstall()`, an `OTEL_SDK_DISABLED`
    install, and the D2 state.
  - Policy, key, identity mode, profile and limits never change within an
    epoch. A re-install calls `allocator.seal()` (with `final`) first when the
    current epoch has allocated anything, so the new manifest 0 is
    `after_source_sequence = −1` of a fresh epoch.
- **Keys on other markers.** Run markers carry `fabric.capture.manifest_id`
  and `fabric.capture.manifest_digest` of the manifest in force. Every
  heartbeat carries `fabric.capture.manifest_seq` of the latest manifest.

### 3.9 Wire exchange enrichment (new `wire/_attrs.py`; hook in `wire/_pipeline.py:162-192`)

`exchange_attributes` merges `p1_attributes(job)`:

| Key | Value |
|---|---|
| `fabric.event_id` | minted in `WireTee.begin` / `adopt`, stored on the job |
| `fabric.capture.input` | `wire` |
| `fabric.capture.point` | `wire.py.httpx@<v>` or `wire.py.aiohttp@<v>` |
| `fabric.run.segment_id` | from the `Allocation` |
| `fabric.step.kind` | `embedding` for `openai.embeddings`, else `model_call` |
| `fabric.actor.type` | `agent` |
| `fabric.step.lifecycle_state` | `completed`; `cancelled` for `closed_early` |
| `fabric.step.status` | the 049 §2.3 legacy mapping of `response_state` and HTTP status |
| `fabric.error.domain` | `transport` for an exception with no HTTP status; `provider` for HTTP ≥ 400 |
| `fabric.wire.first_chunk_offset_ns` | the monotonic delta between request start and the first non-empty response chunk |
| `fabric.tenant_id` | the tenant |
| X05 identity block | `fabric.agent_id` and the other X05 keys, from `FABRIC_*`, emitted through the same `_identity.py` policy object `decision()` uses |

The first-chunk time is one `time.monotonic_ns()` call on the first
non-empty chunk only (`wire/_stream.py:_retain`; `wire/_aiohttp.py`
`feed_data`). It fits within the ≤ 2 µs per-chunk budget.

### 3.10 Explicit producers on the records input (`call_recorder.py`, `adapters/*`, `http_dispatch.py`)

**`CallRecorder(..., mode: Literal["auto", "records", "journal", "legacy"] = "auto")`.**

| Mode | When `auto` selects it | Behaviour |
|---|---|---|
| `journal` | `source_spool` was given | Qualified-run mode (049 §2.13). Byte-for-byte today's behaviour. |
| `records` | No `source_spool` and a wire handle is installed | The records producer below. |
| `legacy` | Neither | Today's behaviour, plus one `DeprecationWarning` per process. |

**In records mode:**
- `_base` takes `Allocation` from the records input instead of
  `self._sequence`. `source_id` and `source_epoch` become the process
  source's.
- Each journal event becomes one `Attempt.emit`:

  | Journal event | Phase | Bodies |
  |---|---|---|
  | `operation.start` | `start` | the input body |
  | each capture (`_capture`, `record_data`, stream chunk) | `data` | its body |
  | `operation.outcome` | `end` | none |

  `fabric.step.status` = `result_status`; `deferred` maps to lifecycle
  `deferred` with status `unknown`.
- **Ids:**
  - `event_id` = `record_id` in dashed form.
  - `fabric.attempt.uid` = `call_id` in dashed form (049 §2.3 table).
  - `fabric.step.id` = mapped `operation_id`.
  - `fabric.step.attempt_id` = mapped caller `attempt_id`.
  - `fabric.step.parent_id` = parent `call_id` in dashed form.
  - `fabric.step.kind`: `model` → `model_call`, `tool` → `tool_call`,
    `database` → `database`, `agent` → `delegation`.
- **Bytes:**
  - Bytes become `RecordBody` objects with the roles of `_KINDS`
    (`call_recorder.py:42-47`), all admitted by the role table.
  - The capture policy of the install governs them through the shared
    `Protector`. A `ByteEvidenceConfig` whose role policies disagree with the
    capture policy for the same role raises `ValueError` at construction.
    Malformed configuration raises (049 §7.3).
  - `ByteEvidenceRecorder.capture` is not called.
- **Snapshots:**
  - `snapshot()` keeps working as an in-memory view. Descriptor statuses are
    `pending` until the worker settles, and `writer_settled` reflects
    `handle.flush()`.
  - `seal_source()` returns the refusal `records_mode`, because sealing
    belongs to qualified-run mode.
- **Unchanged:** the 16 MiB cap (§3.5), D2 (the model kind still opens an
  `ExplicitScope`), and EmittedId handling (`call_recorder.py:113-121`).

`FinalHTTPAdapter` inherits records mode through its `CallRecorder`.
`SyntheticCaptureSession` (`adapters/synthetic_evidence.py`, used by
`ByteBoundaryAdapter`) gets the same three-way mode, with `step.kind`
`terminal` for subprocess artifacts and the `terminal.*` and `artifact.*`
roles.

**Not moved in P1:** `GovernedLocalContentStore` (it becomes a writer backend
in P1-A), `DurableByteSpool` (it stays until parity passes), receipts,
attestations and witnesses (qualified-run only).

### 3.11 Decision records (`decision.py`, `_calls.py`, new `_records_mirror.py`)

- `Decision.__enter__` wraps the host span in `_MirrorSpan`
  (`decision.py:618-620`). `_MirrorSpan` forwards every call and also keeps
  `set_attribute` values in a Fabric-owned dict, so the record survives host
  sampling (`NonRecordingSpan` has no attributes).
- `Decision.__enter__` calls `records.begin(kind, "sdk.records")`, with the
  step kind from the table below. The decision attempt emits:
  - one `start` record at enter;
  - one `end` record at `__exit__`, with `start_ns` and `end_ns`, the status,
    and the projected attributes.
  - Each `span.add_event(name, attributes=…)` the mirror sees (the twelve
    event sites in `decision.py`) emits one record of its own attempt, with
    `name_hint` = the event name, `start_ns = end_ns` = now, and phase `end`.
  - The extra host child spans opened at some of those sites (for example
    `decision.py:1121`) are not mirrored. The event record is the sequenced
    copy.
- `tool_call()` and `llm_call()` (`_calls.py:400,984`) wrap their host span the
  same way. They emit `start` at enter and `end` at exit with `span_ids` = the
  host span.

**Step kinds:**

| Source | `fabric.step.kind` |
|---|---|
| decision | `agent_turn` (new kind, §4.1). One `decision()` block is one agent turn. `workflow_node` is not used, because its S18 (`workflow.node`, `workflow.iteration`) is `R (workflow_node)` and a decision has neither. |
| `tool_call` | `tool_call` |
| `llm_call` | `model_call` |
| retrieval | `retrieval` |
| memory | `memory` |
| side effect | `side_effect` |
| checkpoint | `checkpoint` |
| delegation | `delegation` |
| interaction | `interaction` |
| hook | `hook` |
| skill | `skill` |
| file | `file` |
| replay | `extension` (`x-fabric.replay`) |

- Content captured by `decision()` keeps its current path
  (`_content_writer.py`, governed sink). Moving it onto the unified spool is
  the P2 work of `sdk.records` content roles. In P1, records carry metadata
  only.
- A host attribute that rule A drops is still on the host span. It is never on
  Fabric's record.

### 3.12 Verifier (`reconstruct/`)

**Inputs (`_inputs.py`).**
- `SpanRecord` gains `status` and `kind`, read in `_sink_span` and
  `_otlp_spans`.
- New observations:
  - `RecordObs` for spans with `fabric.capture.input=records`, a valid source
    triple, an event id and an attempt uid;
  - `SegmentSealObs` (`HEARTBEAT_KINDS` gains `segment_seal`);
  - `ManifestObs` for spans named `fabric.capture_manifest`, decoded back to
    the document through the `manifest-span-v1` mapping and digested;
  - `run_start` and `run_end` extended with segment, predecessor, branch,
    manifest, session, user and run-link keys.
- Each observation keeps the `SpanRecord`, so the record digest can be
  computed.
- A span carrying `fabric.event_id` but no `fabric.source.sequence` is ignored
  for accounting. It is a host duplicate.

**Integrity (`_verify.py`).**
- `RecordObs` fills `_Source.sequences` the way `ExchangeObs` does (`:495`).
  Duplicates by `(source, epoch, sequence)` with differing digests are
  `conflicting_claim`.
- Scope pairing allows continuation `run_start` markers (§9, delta 1). The
  window starts at the minimum `last_sequence` of the scope's `run_start`
  markers. Two starts of one scope on different sources are still
  `scope_conflict`.
- **Manifests:**
  - The chain is checked per `(source, epoch)`: contiguous `manifest_seq`,
    `previous_manifest_sha256`, and heartbeat `manifest_seq` ≤ the highest
    present. A failure records the sequence window as manifest-less (rule R1).
  - Two different manifest-0 documents for one `(source, epoch)` mark it
    `conflict`, and every run with a segment there is `partial(segment_conflict)`.
- **Seal recomputation:**
  - For each `segment_seal`, the verifier collects the records and losses of
    the segment's source whose `fabric.run.segment_id` equals the seal's
    segment id, computes `_seal.seal_digest`, and compares it.
  - A mismatch is the gap `seal_mismatch`.
  - A segment with records and no seal is `unsealed_segment`, mapped to
    `partial(source_lost)`.
  - A record with a sealed segment's id above its `last_sequence` is G1.
- **Unsealed epochs:**
  - `unsealed_prior_epochs` from manifests, and orphan heartbeats (a periodic
    heartbeat for an epoch with no `final`), are listed in
    `sources[].unsealed_epochs`.
  - A run with a segment in such an epoch is `partial(unsealed_epoch)`.

**Segment graph (new `_graph.py`).**
- It builds per-run graphs from run markers and seals and applies G1–G10 of
  049 §2.10 in order, producing `run_state` and gaps.
- Runs whose segments are joined by a predecessor entry are merged. Differing
  `r-` values become `run_aliases` (decision 22). Merging is transitive, by
  union-find over segment ids.
- Deadline: the root `run_start` time plus `open_deadline_s`, else the root
  manifest's `limits.open_run_deadline_s`.
- `U` = the root manifest's `clock.uncertainty_ns` + `--clock-uncertainty`. G4
  compares the two segments' declared uncertainties.

**Report (`_report.py`, `__main__.py`).**
- `runs[]` gains `run_state` (absent for pre-P1 captures), `segments[]`,
  `run_aliases`, `deadline_at` and `evaluated_at`.
- `sources[]` gains `manifests[]` (`{manifest_id, sha256, manifest_seq}`) and
  `unsealed_epochs[]`.
- New gap types (§4.2): `segment_missing`, `segment_conflict`,
  `post_terminal_activity`, `run_unterminated`, `run_open`, `seal_mismatch`,
  `unsealed_segment`, `unsealed_epoch`, `manifest_gap`, `clock_uncertain`.
  `run_open` has effect `info` (see below).
- **Exit code:** 0 requires every run verdict complete and `run_state` in
  {absent, `terminated`}. An `open` run exits 1.
- **New flags:**
  - `--projection FILE`: write `fabric.step-projection/v1` next to the report.
  - `--coverage-profile ID` (default `fabric.profile.model-calls/v1`).
  - `--evaluated-at RFC3339` (default now).
  - `--clock-uncertainty DURATION` (default 0).
  - `--max-clock-uncertainty DURATION` (default 300 s).

**The layer verdict for `open` is not swallowed by integrity.** The report's
integrity verdict for an open run is computed over the present segments
(`complete_for_observed_scopes` at best). The gap `run_open` is not counted in
`verdict_for`; it is counted only in the exit code. So 049 RR1 does not
pre-empt RR5a (§9, delta 5).

### 3.13 `fabric.step-projection/v1` (new `reconstruct/_project.py`, `reconstruct/_fields_model.py`)

**Document.** It follows the existing schema exactly.
- Inputs: `reconstruction_sha256` (sha256 of the report bytes written),
  `manifests[]`, `telemetry_origin`, `pseudonym_mode`, `key_id`,
  `content_inline` (false unless `--inline-content`), `projection_revision` 1,
  `parser {name: fabric.reconstruct, version}`, `field_registry
  {schema_version, registry_revision}` and `evaluated_at`.
- **Steps:** one per `attempt_id`.
  - Wire: `exchange_id`.
  - Records: `fabric.attempt.uid`. Every record of an attempt is merged;
    `event_ids` lists them all.
  - Inferred `input` steps: a uuid5 of the evidence locator.
- **Step ids, aliases and parents** follow the 049 §2.3 table exactly. A wire
  exchange's parent is the step whose record has span id = the exchange's
  `parent_span_id` (the `records.span_id` alias), else the run-scope step.
- **Run-scope steps.** Each scope id yields one `run`-kind step (`run:` +
  `scope_id`) with S34 from `run_end`.

**Fields.**
- Every field the registry assigns to the step's kind gets a wrapper (049
  §2.6).
- The capture point's manifest row decides `not_captured(not_instrumented)`
  versus `unsupported(unsupported_version)` versus `unknown` (no manifest).
- Field keys come from `field-registry-v1.json` through the 049 §3 key
  derivation.

**Model-call fields (`_fields_model.py`).** These are pure functions over the
stored, reassembled request and response bytes. They reuse `_stitch._decode`,
`_sse_events` and the `_parse_request` / `_parse_response` dispatch
(`_stitch.py:309-402,549-628,916-982`) and return field sets with locators
(JSON pointers into the stored object). The dialects are OpenAI chat,
responses, completions and embeddings, and Anthropic messages, each in
document and SSE form.

| Field | Source | Rule |
|---|---|---|
| C19, C20 | chat `messages[role in {system, developer}]`; responses `instructions` + `input[role in {system, developer}]`; anthropic `system` | Locator list. The digest is the canonical digest of the projected parts. |
| C21, C22 | `tools[]` | Names as LABEL. `type`: function, custom, provider_hosted (web_search, file_search, code_interpreter, image_generation, computer_use_preview, Anthropic server tools), mcp, computer, other. |
| C23 | thread order (`_stitch_check`) | `tools_digest_change`, `certain` |
| C36 | request `model` | 048 §7 exposure rule |
| C37 | response model | provider assertion |
| C38 | the request keys listed in 049 C38 | — |
| C39 | `previous_response_id`, `conversation`, `thread_id`, cached-content and file ids | Resolution `resolved` only when the named response is in the record; else `unresolved`, class gap, reason `provider_held` (049 §6.3) |
| C40 | — | Always `not_captured(hook_disabled)` in P1. No header is read. |
| C34, C35 | span `gen_ai.provider.name`, `fabric.wire.api`; endpoint id from the matcher, emitted in the projection only (manifest endpoint digest) | — |
| N01 | stored objects | — |
| N02 | `model.exchange.part` descriptors | reassembly per 049 §6.3 |
| N03–N05 | messages and parts with roles | — |
| N06 | `refusal` (OpenAI), `stop_reason: refusal` (Anthropic) | — |
| N07 | finish reasons, including streamed | — |
| N08–N11 | reasoning formats (below) | — |
| N12–N16 | tool calls | Ids as keyed `p-` (`_inputs.py:399-406`); links by `tool_call_id`, `certain` |
| N18 | `tool.execution_side` | `provider` for hosted items, else `agent` |
| N19–N21 | hosted tool items | `web_search_call`, `file_search_call`, `code_interpreter_call`, `image_generation_call`, `mcp_call`, Anthropic `server_tool_use` + `*_tool_result` |
| N53, N55 | `computer_call` actions; screenshots in `computer_call_output` | → `ui_action` steps |
| N60 | embeddings `input` locator and `dimensions` | — |
| D17 | `prefix_break` | `tentative` |
| D31–D33 | usage blocks | — |
| D34 | — | `usage.basis`: `provider_reported` when present, else `not_captured(provider_not_returned)` |
| S11 | provider `error.code` from the error body | — |
| S12 | locator to the error body | — |
| S13 | — | `retry` only, `identical_request_after_error`, `tentative` |

**Reasoning formats (N08–N11).**
- OpenAI responses `reasoning` items: the summary maps to N10; with
  `encrypted_content`, N09 is `redacted(provider_encrypted)` and N11 is a
  locator.
- Chat `reasoning_content` and `reasoning` (vendor extensions on
  OpenAI-compatible endpoints) map to N09 `captured`.
- Anthropic `thinking` maps to N09 `captured`; `redacted_thinking` maps to N09
  `redacted(provider_redacted)`.
- APIs without reasoning are `not_applicable`.

**Unknown items** become `extension` steps (`x-provider.<type>`) with
`unsupported(unsupported_api)`. An unknown item is never coerced (049 §5 rule
6).

**Records and explicit steps in P1.**
- Their X fields and S01, S03, S07, S08 and S10 come from the record's keys.
- Explicit model-call steps get N01 and N03/N04 locators (`explicit.call_recorder`).
- P2/P3 fields their manifest row does not list are
  `unsupported(unsupported_version)`.
- **D2:** when the source manifest has `explicit_wins: true` and a wire point
  `active`, the explicit model step's wire-only fields (C34, C35, S29, S30) are
  `not_captured(deferred_to_explicit)` (P1-A, §3.15).

**Verdicts.** The step and run decision tables R1–R6 and RR1–RR7 of 049 §6.2
are implemented as data. Each row is a predicate plus a verdict, evaluated in
order. A unit test per row (C1-5) uses the existing `projection-*` fixtures
plus new ones (§4.3).

### 3.14 Collector

**fabricguard records class** (`P/processor.go`, `P/coverage_keys.go` through
the generator, `P/capture_identity.go`).
- **Class `onRecord`.** A span with `fabric.capture.input=records` and
  `fabric.source.sequence`, and with none of `fabric.wire.exchange_id`,
  `fabric.heartbeat.last_sequence` or `fabric.loss.reason`, is a capture span
  of class records. It gets `captureProfile` (`P/processor.go:1125-1155`): the
  source triple validators, the `s-` label rule and the binding check.
- **Admitted on records:**
  - `fabric.capture.input`, `fabric.attempt.uid`, `fabric.event_id`,
    `fabric.capture.point`;
  - `fabric.run.id`, `fabric.run.scope_id`, `fabric.run.segment_id`;
  - `fabric.step.kind`, `fabric.step.lifecycle_state`, `fabric.step.status`,
    `fabric.actor.type`, `fabric.error.domain`;
  - `fabric.step.id`, `fabric.step.attempt_id`, `fabric.step.parent_id`;
  - `fabric.content.object_ids`;
  - the existing decision metadata keys of the allowlist.

  The registry's `check.span` gains `record`, and the generator emits the bit.
- **Placement fixes found while grounding:**
  - `fabric.session_id` (`sess-`), `fabric.user_id` (`usr-`) and the X05
    identity keys on `run_start` and on exchanges;
  - the `s-` rule applied to `fabric.source_id` on the `fabric.capture_manifest`
    span;
  - `fabric.source.epoch` stays `intAtLeast(0)`, so pre-P1 and P1 epochs are
    both admitted, and the predecessor epoch stays ≥ 1.
- **Name stability.** A Go test feeds `span-category-v1.json` through the
  category function. The Python port must produce the same names.
- **Seal parity (T3).** A Go test feeds `seal-parity-v1.json` (spans as the
  Python emitter writes them) through `processTraces` and asserts the exported
  attributes and name equal the vector's `expected_export`. A Python test
  recomputes the record digests from that output.

**Content validation before acknowledgement (decision 24 candidate).
Recommendation: build it in P1.**

Design (`E/factory.go`, new `E/prevalidate.go`):
- `createLogsExporter` returns a `validatingLogs` wrapper whose
  `ConsumeLogs(ctx, ld)` runs the stateless checks on every record before
  handing the batch to the exporterhelper queue:
  - `parseRecord`, which includes the length and digest recompute
    (`E/record.go:166-188`);
  - `parseDescriptor` and the role, protection and link consistency checks
    (`:192-246,489-501`);
  - the tenant allowlist (`E/exporter.go:139-141`);
  - the source binding (`:142-144`).
- Any failure returns
  `consumererror.NewPermanent(status.Error(codes.InvalidArgument, <fixed
  reason>))`. The OTLP receiver maps that to **HTTP 400**. Nothing is
  enqueued, and the counter `fabric_content_prevalidate_refused{reason}`
  increments.
- The batch is refused as a whole. The Python sender sends one record per
  request (`wire/_content.py:41-62,100-129`), so this is per-record in
  practice.
- No gate change is needed, because the wrapper is inside the exporter
  component (`gate/gate.go:736`).
- The post-queue checks stay as defence in depth: the queue is on disk and
  could be tampered with.
- The conflict check (it needs a store read) stays post-queue, with drop and
  log, because it cannot be decided before acknowledgement without a
  synchronous store read.
- **Agent side.** `NodeContentClient.send` already maps 400 to `rejected`
  (`wire/_content.py:100-129`) and the sender counts `content_rejected`
  (`wire/_sender.py:424`). P1 adds:
  - `WireHandle.status()["content_rejected"]`;
  - a class-only warning per epoch.

  The span is still exported. Its seal digest was fixed at spool time, so the
  span is never rewritten. The projection maps the missing object to
  `not_captured(store_failed)`. 049's "`destination_rejected` loss" wording is
  replaced (§9, delta 6).
- **Cost.** The receiver hashes each body once more before answering, up to
  63 MiB, about 0.1 s. That runs on the sender thread's request, never on the
  application's.

**Why build it now.**
- A 200 then means the record passed every check that does not need a store
  read.
- A misconfigured tenant or binding becomes visible on the agent at once
  instead of only in Node logs.
- The encrypted Node queue never holds refused records.
- Spec 055's Node.js sender inherits the same semantics.

### 3.15 P1-A

1. **Sticky withholding.**
   - `ExplicitScope` adds a `withheld` slot (`_capture_scope.py:46`).
   - `CallRecorder._start` sets it when the capture policy maps the model
     input role to `omit` or `metadata_only` at call start, which is decidable
     synchronously. A protection failure on the worker is not withholding.
   - `WireTee.adopt` (`wire/_transport.py:200-220`) reads
     `exchange.deferral.withheld` after the scope ended. When it is set:
     1. allocate the sequence as today;
     2. set `job.withheld = True`;
     3. `_prepare` skips PROTECT and stores no body (`store_status=disabled`,
        `store_reason=explicit_withheld`).
   - The wire line never falls back to raw bytes.
2. **D2 in the projection**, as in §3.13. A deferred exchange has no record,
   so `deferred_to_explicit` appears on the owning explicit step's wire-only
   fields. An adopted withheld exchange is its own step, with N01
   `not_captured(explicit_withheld)` (class `withheld`).
3. **Explicit-line parity** (`sdk/python/tests/parity/`). For each privacy mode
   (`retain_original`, `redact`, `tokenize`, `masked_only`,
   `original_plus_masked`, `metadata_only`, `omit`), redaction-service
   failure, and object sizes 0, 1 MiB, 16 MiB and 16 MiB + 1:

   | Run | Stores into |
   |---|---|
   | The same calls in `legacy` mode | `GovernedLocalContentStore` |
   | The same calls in `records` mode | local writer backend, then Node, then directory store |

   The two runs must agree on:
   - stored bytes;
   - `privacy_mode`, `protection_status`, `transformation_id`/`version`;
   - status and the oversize outcome;
   - absence of any original digest where the mode forbids it.
4. **Qualified-run regression.** `tests/test_qualified_run*.py`,
   `test_call_source_spool.py` and `test_source_spool_readback.py` run
   unchanged, plus an assertion that `journal` mode allocates nothing on the
   process allocator.
5. **Governed local store as a writer backend.**
   `GovernedLocalContentStore` implements the `ByteEvidenceStore` protocol the
   pipeline's direct store path uses (`wire/_pipeline.py:516-535`), so the
   local profile writes through the one writer.
6. **Qualification matrix.** Registry capture-point rows gain
   `qualified_versions` for httpx, httpx2, aiohttp, openai and anthropic,
   filled from the agent-matrix run (§4.1).
7. **Shared passivity harness** (`sdk/python/tests/passivity/`):
   - the 047 §4.10 calibration;
   - identity checks (value, exception object, cancellation, chunk order);
   - a fault injector (raising, slow and full recorder);
   - a fork probe;
   - a recursion probe (Fabric's own spool writes);
   - for PEP 578, an audit-hook body checker (`never raises`), used by P4.

   Budgets for P1:
   - `records.emit` ≤ 20 µs median without bodies, ≤ 30 µs with one body (by
     reference);
   - allocation including the segment hook ≤ 3 µs;
   - the wire budgets unchanged.
8. **Retirement list** (in the P1-A exit report; nothing is deleted):
   - `ByteEvidenceRecorder.capture` default path;
   - `byte_spool.py` (`DurableByteSpool`) for non-qualified use;
   - `call_reconcile.py` / `synthetic_reconcile.py` for non-qualified use;
   - legacy mode of `CallRecorder` and `SyntheticCaptureSession`.

### 3.16 Passivity and failure behaviour

| Event | Behaviour |
|---|---|
| Queue full at `emit` | `queue_full` loss for the allocated position; no wait |
| Exception anywhere in `_records`, `_segments`, `_seal` or `_manifest` on a host thread | Caught; `internal_error` loss when a sequence was allocated, else a counter |
| Registration I/O failure at install | Capture continues unregistered; `status()["registration"]="failed"`, class-only warning |
| Seal accumulator over its bound | Forced seal (§3.7) |
| Token parse failure | Token dropped (§3.6) |
| `end_run` without a token | `refused_no_token`, nothing emitted |
| Manifest build failure | No manifest: projection R1 `unverified` for that epoch; class-only warning |
| Redaction service down for a records body | Withheld (`protection_failed`), as for the wire |
| Node 400 on content | `rejected`, counted; span exported |

No new code runs on the host thread beyond: the allocation hook, building
an immutable job, `put_nowait`, and (D2) reading one boolean. Fork hooks take
locks only.

### 3.17 Privacy of every new datum

| Datum | Class | Rule |
|---|---|---|
| epoch | META | random; reveals nothing |
| registration file | — | 0600 in the 0700 spool dir. Holds the source id as emitted (pseudonymous), pid and time. No content. |
| `seg-`, `br-`, `fr2/` | ID | random or emitted ids; tokens carry the emitted source id |
| `run_id`, `parent_run_id`, `resumed_from`, `links` | ID | `r-` mapped (decision 22) |
| `session_id`, `user_id` on `run_start` | ID | `sess-`, `usr-` v2; omitted without a key |
| `fabric.content.object_ids` | ID | uuid4 |
| record attributes | META/ID/LABEL | rule A; caller ids mapped; no content key exists |
| record bodies | CONTENT | PROTECT before spool; spool envelope in production |
| manifest | META/DIGEST | no endpoint hostnames, only the endpoint-set digest |
| projection | — | locators only unless `--inline-content`; written 0600 |
| `FABRIC_RUN_ID` | clear app id | never emitted; the app's own value; in-host only (OD-7) |
| token-derived run id | ID | `r-` digest of an emitted segment id; no caller input |

Privacy canaries for P1 cover:
- a clear run, session and user id passed through `run()` and the environment;
- caller operation and attempt ids;
- content in `record_data`;
- an error message in an explicit call;
- the endpoint host.

The canaries are scanned in the spool files, the registration files, the
ledger, Node telemetry, the report, the projection and logs.

---

## 4. Contract deltas

These are not edited in this task. WP-00 makes them.

### 4.1 Registries (`contracts/coverage/v1/registry/`)

| File | Change |
|---|---|
| `field-registry-v1.json` | X08 definition: "a caller value is always mapped (decision 22); only an `EmittedId` passes through". The P0/P0-A phase relabels of R64-10. **New X48** `content_object_ids` (list of uuid4, max 8, observed by `fabric.self`, metadata, ID, O, absent, P1, lives in T `fabric.content.object_ids`): content objects a records-input record references, in reference order. D30 `phase`: "P1 (`end_run`), P2". |
| `telemetry-keys-v1.json` | New `fabric.content.object_ids` (X48; array 1–8 of uuid4; `span: [record]`). `check.span` placements: `record` added for the 15 keys of §3.14; `fabric.session_id`, `fabric.user_id` and the X05 keys on `run_start` and `exchange`. `fabric.run.outcome` phase "P1 (`end_run`)". |
| `capture-points-v1.json` | `state` text for `explicit.*`, `sdk.records`, `run.scope` and `fabric.self` set to "P1: built" when built. New property `qualified_versions` (P1-A) on W points. The R64-5 host-sensor wording. |
| `vocabularies-v1.json` | `reason` definition of `body_cap` widened to "… or a records object exceeded `records_max_object_bytes`" (minor). New `step_kind` value **`agent_turn`**: "One agent turn reported by `decision()`: the agent's handling of one input, enclosing its model, tool and other steps." (minor; the generated fabricguard `fabric.step.kind` enum and the projection schema enum follow, through the validator's enum-equality check). Profile `fabric.profile.agent-run/v1` does not add it to its required step kinds in P1; P2 decides its required fields. |

### 4.2 Schemas

| Schema | Change | Version |
|---|---|---|
| `capture/v1/schema/spool-record-v1.schema.json` | `record` branch gains optional `bodies` (exchange body shape, `maxItems: 8`), plus `service_name` (already present). The `run_start` marker admits `session_id` and `user_id`. | capture/v1 1.3.0 |
| `capture/v1/schema/run-reconstruction-v1.schema.json` | `runs[]`: `run_state`, `segments[]` (the projection's segment shape), `run_aliases`, `deadline_at`, `evaluated_at`. `sources[]`: `manifests[]`, `unsealed_epochs[]`. `gapType` adds the 10 types of §3.12. `inputs.evaluated_at`. | capture/v1 1.3.0 |
| `coverage/v1/schema/step-projection-v1.schema.json` | No change expected. The build must not need one (T1). | — |
| `coverage/v1/schema/capture-manifest-v1.schema.json` | No change. | — |

### 4.3 New vectors and fixtures

| Path | Content |
|---|---|
| `contracts/coverage/v1/fixtures/vectors/seal-digest-v1.json` | Record digests for an exchange, a record with and without bodies, an empty segment, a loss entry, receiver-owned key exclusion and int64/array typing. Seal digests. |
| `contracts/coverage/v1/fixtures/vectors/span-category-v1.json` | `(name_hint, attribute keys) → name`, covering every branch of `P/processor.go:895-947`. |
| `contracts/coverage/v1/fixtures/vectors/seal-parity-v1.json` | Emitted span, fabricguard export and digest (T3). |
| `contracts/coverage/v1/fixtures/vectors/records-span-v1.json` | Admitted and stripped attributes on a records span. |
| `contracts/coverage/v1/fixtures/projection/` | Model-call input bytes plus expected field sets per dialect: chat, chat-stream, responses with hosted tools and reasoning, responses stream, `previous_response_id` resolved and unresolved, anthropic thinking, redacted thinking and server tools, embeddings, refusal, unknown item, 40 MiB image request, 70 MiB side. |
| `contracts/coverage/v1/valid/projection-records-explicit-d2.json` | P1-A projection with `deferred_to_explicit` and `explicit_withheld`. |
| `contracts/capture/v1/fixtures/valid/spool-record-record-bodies.json`, `run-reconstruction-segments.json` | New valid examples. |

---

## 5. Work packages

Rules for every WP:
- Each WP touches only its **owner area**.
- A shared file is listed under exactly one WP. Other WPs call into it only
  through the interfaces WP-01 lands.
- Each WP ends with `ruff`, `mypy --strict` (Python) or `go test ./...` (Go)
  for its area, its own tests, and `scripts/tests/test_recorder_release_boundary.py`.
- Every code-writing WP runs on Opus-class agents; read-only research may use
  Sonnet.

### Wave 0 (sequential foundation; WP-00 and WP-01 run in parallel, then everything else)

| WP | Owner area | Depends | Deliverables | Tests | Exit check |
|---|---|---|---|---|---|
| **WP-00 Contracts** (sequential, first) | `contracts/coverage/v1/**`, `contracts/capture/v1/**`, `scripts/contracts/**`, `scripts/tests/test_coverage_contracts.py`, `scripts/tests/test_capture_contracts.py`, generated `P/coverage_keys.go` table, `sdk/python/src/fabric/_records_keys_generated.py`, `_manifest_fields_generated.py` | — | All of section 4. Generator outputs: the Go placement bits and the Python records-key table. A reference Python implementation of the seal digest and span category, in `scripts/contracts/`, used to produce the vectors. | Validator over every new fixture and vector. Generated-file drift check. C0-1..C0-5 still pass. | `validate_coverage_contracts.py` and `validate_capture_contracts.py` pass; the generators run with `--check` |
| **WP-01 SDK interfaces** (sequential, first) | `_capture_types.py` (new), stub modules `_records.py`, `_segments.py`, `_seal.py`, `_manifest.py`, `wire/_registration.py`, `wire/_attrs.py`, `reconstruct/_graph.py`, `reconstruct/_project.py`, `reconstruct/_fields_model.py`; call sites in `wire/__init__.py` (install, close, run hooks), `_sequence.py` (`Allocation` and hook call), `wire/_pipeline.py` (job dispatch and settle calls), `_loss.py` (`Marker` type) | — | Dataclasses and protocols of §3 (`Allocation`, `Marker`, `RecordJob`, `RecordBody`, `Attempt`, `SealAccumulator` protocol, `RunTable` protocol). No-op stubs, so the existing suite passes unchanged. | The full existing suite. A type-check of the stubs. | No behaviour change (the wire golden tests pass) |
| **WP-21 Node pre-ack validation** (parallel from day 0) | `E/**` (excluding the generated roles file), `charts/fabric/charts/otel-collector/tests/test-content-delivery.sh` (new assertions), `wire/_content.py` and `wire/_sender.py` **status() only** | — | §3.14 pre-validation; the counter; agent status and warning | Go: each refusal reason gives 400 and nothing enqueued; a valid record gives 200; a conflict stays post-queue. Python: 400 maps to `rejected` and a status count. An e2e (compose) case. | T4 |

### Wave 1 (parallel; at most 6 agents)

| WP | Owner area | Depends | Deliverables | Tests | Exit check |
|---|---|---|---|---|---|
| **WP-10 Epochs and allocator** | `_sequence.py`, `wire/_registration.py`, `wire/_forks.py` | 00, 01 | §3.2, §3.3: CSPRNG epochs, registration, mmap mirror, orphan scan API (called by the sender in WP-11), `Allocation`, process component, settlement accounting | Property: epochs nonzero and 63-bit; redraw on a held or unsealed collision. Multiprocess: two installs on one spool never share an epoch. SIGKILL of a spawned worker after allocation is seen by an orphan scan. Fork: the child does not write the parent's mirror. Passivity: allocation ≤ 3 µs. | Unit + multiprocess suites green |
| **WP-11 Records input, spool, seal** | `_records.py`, `_seal.py`, `wire/_spool.py`, `wire/_sender.py` (except WP-21's status lines), `wire/_pipeline.py`, `wire/_ledger.py` | 00, 01; WP-10 interface | §3.4, §3.5, §3.7: rule A projection, rule N names, the four phases (including `update`), `mode_of`, `v2`, `str` bodies encoded on the worker, record jobs, PROTECT of bodies, `record` spool kind, typed markers, `SealAccumulator`, orphan heartbeat emission from the drainer | Spool header property tests (exchange, record and marker round trip; corrupt frames). Seal vectors. Queue-full and disk-full losses settle the seal. Provider path, including sampled-out → `span_dropped`. D3 refusal. Canaries in spool files. Passivity of `emit`. | `seal-digest-v1` and `records-span-v1` vectors pass; existing spool suites green |
| **WP-13 Manifests** | `_manifest.py` | 00, 01 | §3.8: build, digest, span mapping, chain, fork template, state-change API, per-epoch fixed fields | Every emitted manifest validates with `validate_manifest_document`. Chain vectors. A forked child's manifest 0. Re-install starts a fresh epoch. | Manifest fixtures reproduced byte for byte from a configured handle |
| **WP-20 fabricguard records class** | `P/**` (non-generated) | 00 | §3.14: records class, placements, manifest `s-` rule, category test, seal-parity Go test | Go unit tests for each admitted and stripped key on the records class. The binding check on records. Vectors. | `go test ./processor/...`; T3 Go half |
| **WP-30 Verifier: inputs and integrity** | `reconstruct/_inputs.py`, `reconstruct/_verify.py`, `reconstruct/_report.py`, `reconstruct/__main__.py` | 00, 01 | §3.12 inputs, integrity, manifests, seal recompute (using `_seal.py` from WP-11 through the WP-01 interface), report fields, CLI flags, exit code | Extends the `Capture` builder (`tests/test_reconstruct_verifier.py:123-421`) with `record()`, `manifest()` and `segment_seal()`. Records interleaved with exchanges verify. Host duplicates ignored. Seal mismatch for a deleted tail, an edited record and a moved record. Unsealed segment. Manifest gap. The report validates against the new schema. | Existing reconstruct suites green; new cases green |
| **WP-33 Model-call field extraction** | `reconstruct/_fields_model.py`, `reconstruct/_stitch.py` (extension only) | 00 (fixtures), 01 | §3.13 table and reasoning formats, hosted tools, unknown items | Golden: every `fixtures/projection/` case. Fuzz: malformed JSON, SSE and compression never raise and give `parse_failed`. The 64 MiB decode cap is kept. | Goldens equal; no exception under fuzz (10k cases) |

### Wave 2 (parallel; at most 6 agents)

| WP | Owner area | Depends | Deliverables | Tests | Exit check |
|---|---|---|---|---|---|
| **WP-12 Segments and run API** | `_segments.py`, `wire/__init__.py`, `_loss.py` | 10, 11 | §3.6: `RunTable`, segment open and seal triggers, `set_run_outcome` hook and `stop_reason`, token-derived run ids, continuation `run_start`, fork hooks, `run()` arguments, `resume_token(s)`, `end_run`, environment intake, marker emission | Unit: every row of the seal-trigger table. Concurrency: `gather` and `to_thread` share a segment. Fork: child segment and fresh scope ids; parent `declared_branches`. Tokens: the vector grammar (accept and reject). `end_run` refusal. Canaries: clear run id in env and arguments. | LR-1 single-host subset (in-process re-entry, fork, branch tokens) passes against WP-30 |
| **WP-14 Wire enrichment** | `wire/_attrs.py`, `wire/_stream.py`, `wire/_aiohttp.py`, `wire/_transport.py` (event id minting only) | 11 | §3.9 | Exchange spans carry the keys and pass fabricguard tests (WP-20 vectors). First-chunk offset is present for streams and absent for empty responses. The 047 §4.10 budgets. | `test_wire_passivity.py` and `test_wire_aiohttp_passivity.py` green |
| **WP-15 Decision records** | `decision.py`, `_calls.py`, `_records_mirror.py` | 11 | §3.11 | Every `record_*` gives one sequenced record. A sampled-out host span still gives the record. No content key ever reaches the record. Host spans have no `fabric.source.*`. Passivity: `record_*` overhead ≤ 30 µs median. | TypeScript-parity check not required (TS track) |
| **WP-16 Explicit producers** | `call_recorder.py`, `adapters/synthetic_evidence.py`, `adapters/byte_boundary.py`, `http_dispatch.py`, `byte_evidence.py` (config-conflict check only) | 11 | §3.10 three-way mode | Records mode: one record per journal event; ids per §3.10; bodies protected; the 16 MiB + 1 outcome. Journal mode unchanged (existing suites). Legacy mode warning. | `test_wire_explicit_coexistence.py` green in records mode |
| **WP-31 Segment graph and run states** | `reconstruct/_graph.py` | 30 | G1–G10, deadline and clocks, `run_aliases`, run states | One test per G rule using the 7 `projection-run-*` fixtures as expected outputs, plus synthetic graphs: cycle, two roots, replayed `br-`, post-terminal, skew. | All G-rule tests green |
| **WP-32 Projection core** | `reconstruct/_project.py` | 30, 33; 31 for run fields | §3.13 document, steps, aliases, parents, field wrappers, manifest-driven statuses, R1–R6 / RR1–RR7 | C1-3 schema validation of every produced projection. C1-5: one fixture per verdict row. `projection-*` valid fixtures reproduced from synthetic inputs. | T1 |

### Wave 3 (P1 gate; sequential)

| WP | Owner area | Depends | Deliverables | Exit check |
|---|---|---|---|---|
| **WP-50 P1 integration and LR-1** | `qualification/run-structure/**` (new), `sdk/python/tests/test_p1_*.py`, `docs/reconstruct.md`, `docs/` run-structure page, CHANGELOG | all of waves 0–2 | §6.2 harness; full LR-1; shared-allocator exit cases; T2; T3 end-to-end (Python → Node image → verifier); privacy canary sweep | Every P1 gate in §1.4 |

### Wave 4 (P1-A; parallel, 4 agents, then sequential WP-45)

| WP | Owner area | Depends | Deliverables | Exit check |
|---|---|---|---|---|
| **WP-40 Sticky withholding and D2 projection** | `_capture_scope.py`, `wire/_transport.py` (adopt), `wire/_pipeline.py` (`withheld` branch), `reconstruct/_project.py` (D2 rules) | 50 | §3.15 items 1 and 2 | P1-A exit rows on withholding |
| **WP-41 Parity and qualified regression** | `sdk/python/tests/parity/**`, `tests/test_qualified_run_regression.py` | 50 | §3.15 items 3 and 4 | T5, T6 |
| **WP-42 Governed store backend** | `governed_store.py`, `wire/_pipeline.py` store-protocol adapter (only `_store_object`) | 50; serial after WP-40 for `_pipeline.py` | §3.15 item 5 | Local-profile e2e writes through one writer |
| **WP-43 Passivity harness and qualification matrix** | `sdk/python/tests/passivity/**`, registry `qualified_versions` (contract edit; coordinate with WP-00 owner), `qualification/agent-matrix` additions | 50 | §3.15 items 6 and 7 | C1A-3; matrix rows filled |
| **WP-45 P1-A exit report** (sequential) | `docs/`, the retirement list | 40–43 | §3.15 item 8; fault-injection and fork/restart runs | P1-A exit |

**Agent count per wave:**

| Wave | Agents |
|---|---|
| 0 | 3 (WP-00, WP-01, WP-21) |
| 1 | 6 |
| 2 | 6 |
| 3 | 1 |
| 4 | 4, then 1 |

**File conflicts resolved by assignment:**
- `wire/_pipeline.py`: WP-11 in waves 1–2; then WP-40, then WP-42.
- `wire/_sender.py`: WP-11, except WP-21's `status()` lines.
- `wire/__init__.py`: WP-01, then WP-12.
- `_sequence.py`: WP-01, then WP-10.
- `reconstruct/_project.py`: WP-32, then WP-40.
- Contracts: WP-00, then WP-43 (one field).

---

## 6. Test and qualification plan

### 6.1 Unit, property and passivity

The tests are listed under each WP. The cross-cutting suites are:
- **C1-1:** an event id is stable across a sender retry, a ledger replay
  (`wire/_ledger.py` orphan export) and a re-export (`Capture.repeat()`).
- **C1-2:** manifests chain across a capture-point state change, and a lost
  trailing manifest is detected from the heartbeat.
- **Passivity:** the shared harness runs the wire, records and explicit paths
  under raising, slow and full recorders, plus fork and recursion probes.

### 6.2 `qualification/run-structure/` (new)

It is a pytest harness that runs the LR-1 processes as real OS processes:
- "Hosts" are separate spool directories, distinct `FABRIC_SOURCE_ID` values
  and distinct `hostname` overrides, plus one docker-compose variant with two
  containers and a Node image built from the branch.
- Time travel uses the verifier's `--evaluated-at`. The agents' clocks are not
  mocked.
- The key rotation is a second `FABRIC_WIRE_ID_KEY` for process B.

Every LR-1 variant of 049 §8.2 is one test with its asserted verdict:
- `open`, `terminated`, lost middle, never-arriving C, no propagation;
- in-process fan-out, re-entry, fork option (a) ×3, branch tokens ×4, plain
  token limit, post-terminal resume, `end_run` and its refusal;
- skewed clocks, epoch collision across a fork;
- seal recompute ×5 (matching, deleted tail, edited, moved, crash-before-seal);
- zero-survivor prior epoch.

Additional cases:
- `with Pool()` fork with `terminate()`: an accounted, never-complete epoch.
- A `spawn` pool killed with SIGKILL: T2 and `unsealed_epoch`.
- Two installs forced onto one epoch on one spool: redrawn.
- The same epoch on two spools: `segment_conflict`.

### 6.3 Agent matrix and chaos (`test/agent-matrix`, `test/chaos` branches)

**Agent matrix.** Rerun every framework row with records on: `decision()` plus
wire, and `CallRecorder` in records mode where the row uses it. Each row
asserts that the projection validates and that model-call `R` fields are `ok`
or `withheld`. The rows also fill `qualified_versions`.

**Chaos.** Readers must accept spool kind `record` and typed markers before
rerun (the batch-format note in the chaos PR body). New faults:
- SIGKILL between allocation and spool write for records;
- `ENOSPC` while a seal is pending;
- a corrupt `.epochs/` file;
- a held registration flock from a hung process;
- the redaction service hanging during records PROTECT;
- a Node returning 400 on the content path.

### 6.4 Conformance map

| Id | Satisfied by |
|---|---|
| C1-1 | §6.1 |
| C1-2 | WP-13, WP-30 |
| C1-3 | WP-32 (T1) |
| C1-4 | WP-33, the 40 MiB fixture |
| C1-5 | WP-32 verdict rows |
| C1-6 | WP-20 and WP-50 (T3) |
| C1-7 | WP-50 (LR-1) |
| C1A-1 | WP-41 (T5) |
| C1A-2 | WP-41 (T6) |
| C1A-3 | WP-43 |
| 049 P1-A exit rows | WP-40, WP-45 |

---

## 7. Interface for P4 (spec 053 §3)

The facade 053 assumes maps onto §3.4:

| 053 facade | §3.4 |
|---|---|
| `begin` | `RecordsInput.begin` |
| `observe(handle, phase, …)` | `Attempt.emit` with `fields` delivered as attributes (rule A) |
| content | `RecordBody` |

P2 and P3 (specs 051 and 052) build on `update`, `mode_of`, `v2`, `str` bodies, `MAX_RECORD_BODIES = 8` and `set_run_outcome` (§3.4, §3.6).

Two of 053's assumptions are not provided by P1:
- **Assumption 9** (field data with no telemetry key). P1 has no generic
  "fields" carrier. Such data needs a registry telemetry key or a registered
  content role, added by the phase that needs it.
- **Assumption 7** (spawn epoch registration as a P1 gate). It is provided
  (§3.2) and covered by T2.

---

## 8. Risks and open owner decisions

| # | Risk or decision | Recommended default |
|---|---|---|
| R1 | Seal drift: a fabricguard change (a new strip rule, a renamed category) silently breaks every seal | The generated tables plus the T3 parity vectors run in both repos' CI. A fabricguard change that alters an export fails T3. |
| R2 | Reusing a run id sequentially in one process after a non-resumable block exits is `post_terminal_activity` (049 X42) | Keep 049 semantics. Document "one run id, one run; use `session_id` across requests". Status counter `post_terminal_allocations`. |
| R3 | `global` tracer mode cannot reuse host span ids, so `records.span_id` aliases for decision and tool spans are unresolved and a wire exchange's parent falls back to the run-scope step | State it in the manifest (`uncaptured_classes: ["global_tracer_parent_join"]`); recommend spool or `private` mode. |
| R4 | Drain order across epochs follows random epoch values (file names start with the epoch, `wire/_spool.py:3-4`) | Accept. The verifier is order-free. The 048 name format is unchanged. |
| R5 | Seal accumulator memory on very long segments | Forced seal at 1,000,000 positions (§3.7). |
| R6 | Records-mode `CallRecorder.snapshot()` reports `pending` where legacy reported final statuses | Documented; parity tests compare after `flush()`. |
| OD-1 | Decision 24 candidate: pre-ack content validation | **Build in P1 (WP-21)**: stateless checks before 200; conflict stays post-queue; no `destination_rejected` loss (delta 6). |
| OD-2 | `CallRecorder` default when no wire handle is installed | `legacy` with a `DeprecationWarning`. Do not auto-install the wire tee from a recorder. |
| OD-3 | Default declared clock uncertainty | 1 s (`FABRIC_CLOCK_UNCERTAINTY_MS=1000`). Zero claims perfect clocks Fabric cannot know. |
| OD-4 | Decision span step kind in P1 | **`agent_turn`**, a new step kind (minor vocabulary growth, 049 §5 rule 3). It replaces the earlier `workflow_node` default, which made S18 a required field that every decision lacks. Its required fields are P2's (spec 051). |
| OD-5 | Decision content on the unified spool | P2, not P1. P1 moves only explicit-producer bytes. |
| OD-6 | Orphan-registration retention | Until declared and delivered, or `open_run_deadline_s`, whichever is later; at most 4096 files. |
| OD-7 | **What carries a run across processes (privacy).** Under decision 22 the application's clear run id travels in `FABRIC_RUN_ID` and, in 049 rev 6.4's resume table, in W3C `baggage` (`fabric.run`) or message attributes. Baggage crosses service boundaries and is easily forwarded to third parties, so the clear id would leave the host. | **Across a service or host boundary, carry only Fabric-emitted resume tokens** (`baggage` `fabric.resume`, or message attribute `fabric.resume`). The consumer passes `resume=` without a run id and derives its run id from the token (§3.6). The verifier joins the two pseudonyms as `run_aliases` through the predecessor entry, so no clear id and no emitted `r-` value is needed on the wire. **Only in-host environment variables** (`FABRIC_RUN_ID` to child processes) carry the clear id. Drop the `fabric.run` baggage entry from the resume table. Cost: every boundary hop adds one alias. Without a token, a hop yields a separate run (stated limit). Owner to decide. |

---

## 9. Spec 049 deltas (against rev 6.4 in this worktree)

1. **Continuation `run_start` within a scope.** §2.10 "Segments", after "A
   segment is sealed by …". Add:

   > When a segment opens inside an open block — after a token issue or a fork
   > — its first marker is a *continuation* `run_start` that carries the
   > block's `scope_id`, the new `segment_id` and its predecessors. A scope
   > may therefore have several `run_start` markers, one per segment, on one
   > source. Its window starts at the lowest `last_sequence` of them and ends
   > at its `run_end`; two `run_start` markers of one scope on different
   > sources, or two with the same segment id and different values, are
   > `scope_conflict`. A forked child gives every inherited open scope a new
   > scope id.

   048 §6 "exactly one start" needs the same amendment.
2. **`end_run` outcome placement.** §2.10 "Termination". Replace "emits a
   zero-width segment (a `run_start` with the tokens as predecessors and an
   immediate terminal `segment_seal` with the outcome, `D30`)" with:

   > emits a zero-width segment: a `run_start` with the tokens as
   > predecessors, a `run_end` carrying the outcome (`fabric.run.outcome`,
   > `D30`) and an immediate terminal `segment_seal`

   This is because fabricguard admits `fabric.run.outcome` only on `run_end`
   (`P/coverage_keys.go:369`).
3. **Thread pools in LR-1.** §8.2 P1, LR-1 "**in-process fan-out**
   (`asyncio.gather` and a thread pool inside one block …)". Replace "a thread
   pool" with:

   > `asyncio.to_thread` or a pool whose tasks run under `contextvars.copy_context()`

   Add to §2.10 "One process, one open segment per run":

   > Work submitted to a `ThreadPoolExecutor` without a copied context runs
   > outside the run (047 fallback run id).

4. **Token API shape.** §2.10 and §8.2. Replace `resume_token(branches=n)` with:

   > `resume_token()` (one token) and `resume_tokens(n)` (n branch tokens)

   Both return nothing (`None`/`()`) when capture is not installed and never
   raise.
5. **Open runs and the integrity verdict.** §6.2, after the run table. Add:

   > The run-reconstruction integrity verdict of a run in state `open` is
   > computed over its present segments; the open state itself is not an
   > integrity gap, so RR1 does not pre-empt RR5a. The verifier's exit code
   > treats any run state other than `terminated` (or absent, pre-P1) as not
   > complete.

6. **Decision 24 candidate wording.** §7.9 "Content validation after
   acknowledgement", last sentence, and §8.2 P1 "Candidate". Replace "so a
   refusal reaches the agent as a non-retryable error and a
   `destination_rejected` loss" with:

   > so a refusal reaches the agent as a non-retryable HTTP 400, counted
   > (`content_rejected`) and reported in `status()`; the record's span is
   > still delivered (its seal digest is fixed at spool time) and reconstruct
   > reports the object missing (`not_captured(store_failed)`); the conflict
   > check stays after acknowledgement

7. **Records object cap reason.** §2.11 row "16 MiB explicit object cap". Add:

   > An object above `records_max_object_bytes` is a descriptor-only
   > `not_captured` object (`status_reason: payload_too_large`), projected as
   > `not_captured(body_cap)`; exact bytes are never truncated.

8. **Seal content for records.** §2.12 rule 1. Replace "and `content` is the
   `stored_sha256` of each content object the record references, in reference
   order" with:

   > and `content` is, for a wire exchange, the stored digests of its request
   > and response primaries (in that order, when present) and, for a records
   > record, the `stored_sha256` of each object listed in
   > `fabric.content.object_ids` (new field `X48`), in list order, `null` for
   > a descriptor-only object; the record's `name` is the name fabricguard
   > derives for it, which the emitter uses as the span name

9. **Spawned-worker visibility.** §2.10 "Process pools" and §2.12 rule 5. Add:

   > Each registration mirrors its epoch's next sequence in a shared mapping
   > (a memory store, no system call); the spool drainer emits a `periodic`
   > heartbeat at the last allocated sequence of an orphaned registration, so
   > positions allocated but never written by a killed spawned worker are a
   > sequence gap, in addition to the next manifest 0's `unsealed_epoch`
   > declaration.

10. **Manifest `fields` per build.** §2.8, after "every capture point with state
    and the field ids it supplies". Add:

    > (the fields this build supplies; a registry field of the point that the
    > build does not supply is omitted and projected
    > `unsupported(unsupported_version)`)

11. **Allocator component name.** §2.4 "The code changes are relaxing the
    `component == "wire"` guard …". Add:

    > The component becomes `process`; the default source label keeps its
    > `wire-` prefix so source ids do not change on upgrade.

12. **Run identity across service boundaries (OD-7, pending owner).** §2.10
    resume-contract table, row "Run id", column "Across services and
    machines". Replace "W3C `baggage` entry `fabric.run=<run id>`, or the
    message attribute `fabric.run`" (line 1207 of rev 6.4) with:

    > not propagated; pass only resume tokens, and the consumer derives its run
    > id from the first token (`r-` + 32 hex of SHA-256 of
    > `"fabric-run-from-token/v1\0"` + segment id), joined by the verifier as a
    > `run_aliases` member

    Add to rules:

    > `fabric.wire.run(resume=tokens)` without a run id is valid.

13. **New step kind `agent_turn`.** §2.3 step-kind vocabulary: add
    `agent_turn` ("One agent turn reported by `decision()`"), in the
    `step_kind` registry vocabulary and the generated block (049 currently
    names no kind for a `decision()` span).
