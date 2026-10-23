---
title: Run structure, records input and model-call projection (049 P1 and P1-A build spec)
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 2
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

Revision 2 applies the Astra and Fable reviews of the v0.9 spec set and the
main-session revision decisions R1–R16. The changes:
- run correlation ids carried in every token (R1);
- persisted uuid4 marker ids (R2);
- segment-attributed losses (R3);
- three status inputs (R4);
- descriptor-only bodies (R5);
- the 260 bound (R6);
- one structured-evidence carrier, §3.4a (R7);
- one identity rule (R8);
- fail-open APIs and bounded encoders (R9);
- pre-ack validation as the default (R10);
- split WPs with explicit dependencies (R13, R14);
- C35, C40, N51, `fabric.capture.source` and bounded `event_ids` (R15);
- harness paths (R16);
- the registration-fd fork fix.

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
| Cross-cutting | X02, X03 (key only, no producer), X04, X05 (wire spans and markers), X06, X07, X08 (identity rule, run correlation), X10–X14 (`run()` arguments), X17–X19, X21 (projection links), X22–X26, X27 (`fabric.capture.source`, now with a registry row), X30, X34–X36, X38, X39, X41–X46, X48 and X49 (new, §4.1) | X32 parity |
| Context | C08 and C11 (inferred `input` steps), C16, C19–C23, C34–C39, C35 (persisted `fabric.wire.endpoint_id`), C40 (opt-in, WP-14) | — |
| Structure | S01, S03, S07–S09, S11 (provider), S12 (parsed), S13 and S15 (inferred `retry` only), S29–S31, S34 | — |
| Content | N01–N16, N18–N21, N51 (parsed asset references, WP-33), N53, N55 (parsed), N60 | N01 explicit parity |
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

**P1 exit — run correlation and losses (revision 2).**
- **T7:** a token-only chain A → B → C across three "hosts", with B's spool
  destroyed. A and C carry one run id (the minted correlation id), the run is
  `partial(segment_missing)` naming B, and no clear run id appears in any
  token, baggage value or record.
- **T8:** two runs interleaving positions on one source, with `queue_full`
  losses in both. Each seal verifies with only its own segment's losses, and
  no loss record names two segments.

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

**Records-only install.** An application with no model HTTP traffic to tee
installs with `fabric.wire.install(patch_httpx=False, patch_aiohttp=False)`
(or `FABRIC_WIRE_HTTPX=0` with `FABRIC_WIRE_AIOHTTP=0`). It gets the spool,
allocator, manifests and sender, and therefore the same delivery guarantee, for
the records input alone. The manifest reports the wire points
`installed_inactive`.

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
4. **Fork.** In `after_in_child` the child closes its inherited registration
   file descriptor and unmaps the mirror. `flock` belongs to the open file
   description, so a child that kept the descriptor would hold the parent's
   lock after the parent died. The parent would then never become an orphan
   and never be declared in `unsealed_prior_epochs`. The child never writes
   the parent's mirror.

   **No registration** for a forked child (the fork ledger and declared
   branches cover it), for
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
  `LossEmitter.record` (`_loss.py:183-187`), which gains `segment_id` and
  calls `settle`. The stub call sites are landed by WP-01 and the logic by
  WP-11b.
- **Segment-attributed losses (R3).**
  - The loss aggregation key becomes `(source, epoch, reason, segment_id |
    None)`, so ranges of different segments **never coalesce**. Concurrent
    runs interleave positions, so one range may not span two segments.
  - `segment_id` is carried through the pending table (`_loss.py:194-204`), the
    ledger slot records (`wire/_ledger.py`), the spool `loss` doc, the
    `fabric.capture_loss` span (`fabric.run.segment_id`, admitted on loss
    records by WP-20) and the verifier's loss selection.
  - A loss for a position allocated outside any run has no `segment_id`.

### 3.4 Records input (new `_records.py`)

**API (internal; a public facade is P2).** It is frozen by WP-01.

```python
Phase = Literal["start", "data", "update", "end"]
Lifecycle = Literal["queued", "running", "suspended", "deferred", "completed",
                    "cancelled", "unknown"]                       # 049 §2.3 vocabulary
ResultStatus = Literal["ok", "error", "cancelled", "timeout", "unknown"]
OtlpStatus = Literal["unset", "ok", "error"]
Provenance = Literal["reported", "observed"]                      # X27, fabric.capture.source
PrivacyMode = Literal["omit", "metadata_only", "redact", "tokenize", "masked_only",
                      "original_plus_masked", "retain_original"]

class RecordsInput:                       # one per installed handle
    def begin(self, kind: StepKind, point: str, *, provenance: Provenance = "reported",
              step_id: str | None = None, parent_attempt: str | None = None,
              aliases: Mapping[str, str] = {}) -> Attempt | None: ...
    def mode_of(self, role: str) -> PrivacyMode: ...
    def v2(self, prefix: str, value: str) -> str | None: ...
class Attempt:                            # fail-open: None/False on any Fabric failure
    uid: EmittedId                        # uuid4, dashed (X19); minted here, never taken
    def emit(self, phase: Phase, *, name_hint: str,
             attributes: Mapping[str, AttrValue], start_ns: int, end_ns: int,
             lifecycle: Lifecycle | None = None,          # R4: three separate inputs
             result_status: ResultStatus | None = None,
             otlp_status: OtlpStatus = "unset",
             bodies: Sequence[RecordBody | DescriptorOnlyBody] = (),
             evidence: EvidenceDoc | None = None,         # R7, §3.4a
             event_id: str | None = None, span_ids: SpanIds | None = None) -> bool: ...
@dataclass(frozen=True, slots=True)
class RecordBody:                         # data stays in memory until the worker's PROTECT
    role: str; data: bytes | str; media_type: str; boundary: str
    content_provenance: Literal["caller_reported", "protocol"] = "caller_reported"
    stream_id: str | None = None; chunk_index: int | None = None
@dataclass(frozen=True, slots=True)
class DescriptorOnlyBody:                 # R5: a body that could not be produced; never bytes
    role: str; media_type: str; boundary: str
    status: Literal["not_captured", "unsupported"]
    reason: Literal["payload_too_large", "parse_failed", "not_exact_bytes", "encoding_failed"]
    observed_byte_length: int | None = None   # only when known without encoding
MAX_RECORD_BODIES = 8                     # bodies + descriptor-only bodies + the evidence object
```

**Fail-open rule (R9).**
- Every function above and in §3.6 returns `None`, `False` or `()` on misuse
  or internal failure, and counts it in `status()["api_misuse"]` or
  `["internal_errors"]`. Misuse includes an unknown prefix for `v2`, a mutable
  body, an unknown enum value, or a lifecycle on `update`.
- These functions raise (`ValueError`) only under `FABRIC_RECORDS_STRICT=1`,
  which the test suites set.
- Malformed *configuration* still raises at `install()` and at recorder
  construction (049 §7.3); that is configuration, not a recorder call.

**Phases and the three status inputs (R4).** `lifecycle`, `result_status` and
`otlp_status` are independent inputs. None is derived from another, except the
defaults in this table:

| Phase | `lifecycle` | `result_status` | `otlp_status` |
|---|---|---|---|
| `start` | default `running`; may be `queued` or `suspended` | must be `None` | as given (default `unset`) |
| `data` | default `running`; may be `suspended` | must be `None` | as given |
| `update` | must be `None` (stamps no lifecycle) | must be `None` | must be `unset` |
| `end` | required: `completed`, `cancelled`, `deferred` or `unknown` (default `completed`) | default `unknown`, never inferred as `ok` | as given; the default is `unset` even when `result_status=error` |

- `fabric.step.lifecycle_state` and `fabric.step.status` carry the first two.
  The span status carries the third.
- A value outside the table is misuse (fail-open: the record is still emitted
  with the offending input dropped).
- An `update` adds bodies, evidence or attributes to an attempt in any state,
  including after `end`. The projection merges it without changing lifecycle or
  status.
- The run outcome (D30) is **not** an `Attempt` input. It is set only through
  the run-level hook `set_run_outcome` and carried by the outermost `run_end`
  (§3.6).

**Descriptor-only bodies (R5).**
- A producer that fails before it has bytes passes a `DescriptorOnlyBody`
  instead of empty content. Examples: an over-cap value measured before
  encoding, a value that is not exact bytes (`call_recorder.py`
  `not_exact_bytes`), or a bounded encoder refusing on depth or item limits.
- The worker writes a descriptor-only content-v2 object (no bytes, no digests).
  Its `status` and `status_reason` are as given, its `representation` is
  `unavailable`, and its `privacy_mode` is that of the role.

| Reason | Projection mapping |
|---|---|
| `payload_too_large` | `not_captured(body_cap)` |
| `parse_failed`, `encoding_failed` | `not_captured(parse_failed)` |
| `not_exact_bytes` | `unsupported(unsupported_api)` |

- Empty `data` is always a captured zero-byte object (049 §2.6), never a
  failure marker.

**`mode_of(role)`.**
- It returns the privacy mode the capture policy resolves for `role`, using the
  049 §2.7 precedence. The result is cached per role for the epoch, because the
  policy is fixed per epoch.
- It returns `omit` when content capture is disabled (049 §7.3), when the role
  is unknown to the role table, or on any internal failure (fail closed).
- Producers call it **before** serialising a body. Under `omit` they build no
  body at all: no encoding and no copy on the app thread. Under
  `metadata_only` they pass the `RecordBody`, because the worker needs its
  length for the descriptor.
- The call is pure and lock-free, a dict lookup.

**Bounded encoding (R9).**
- Any producer that serialises an application value on the app thread checks
  size, depth and item limits **before** serialising, never only the output
  size. Over a limit it passes a `DescriptorOnlyBody(payload_too_large)`.
- No producer calls `str()` or `repr()` on an application object, or
  `str(exc)`. Automatic error capture is the exception class name
  (`error.type`) plus Fabric-computed bounded metadata. Text is recorded only
  when the caller passes a preformatted `str`.

**One identity rule (R8, decisions 7 and 22).** This rule holds across specs
050–055 and every language.

| Mode | Behaviour |
|---|---|
| Pseudonymous (the default) | Every caller-supplied id is mapped by the keyed function of its type, whatever its shape. Only an `EmittedId` of this handle's issuer passes through. |
| Clear | An explicit opt-in (`identity_mode="clear"` / `FABRIC_IDENTITY_MODE=clear`, owner decision 7). Ids are emitted as given, recorded in the manifest (`identity_mode: clear`). A Node configured for pseudonymous identity rejects them (049 §2.9 rule 7). |

`v2(prefix, value)` implements this rule:
- It returns an `EmittedId` of this handle's issuer unchanged.
- In pseudonymous mode it returns `_sequence.pseudonym_v2(prefix, value,
  key)` as an `EmittedId`. Without a key it returns `None` (049 §2.9 rule 5).
  The explicit line's join ids in the production profile without a key use
  `GeneratedIds` (random `g-`), as today.
- In clear mode it returns the value as given.

**String bodies.**
- A `str` body is kept by reference. It is encoded to UTF-8 strictly on the
  capture worker, never on the app thread. A lone surrogate yields a
  descriptor-only object `not_captured(parse_failed)`.
- Until it is encoded, the in-flight charge is `len(data) * 4`, the UTF-8 upper
  bound. The charge is corrected after encoding.
- Bodies are frozen. A mutable buffer (a `bytearray`, or a `memoryview` of
  mutable memory) is misuse, and the body is dropped (fail-open).

**Provenance.**
- `begin(provenance="observed")` is for opt-in hooks (P4/P5) only. It sets
  `fabric.capture.source=observed` and permits `content_provenance="protocol"`
  on bodies.
- `reported` (the default) sets `fabric.capture.source=reported`. On a
  `reported` attempt, `protocol` content provenance is misuse.
- Hooks never use a third input class: `fabric.capture.input` is always
  `records` on this input (R7; §9, delta 14).

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
- Placement conditions are table columns, not code. A key row may restrict
  its `record` placement by capture-point kind (`capture_point_kinds`, added
  by 053 WP4-01) or by exact capture-point id (`capture_points`, added by 054
  WP5-01), matched against the id part of `fabric.capture.point` (before
  `@`). The generator emits both columns to this table and to the Go table;
  rule A and fabricguard apply them identically, and the table-equality test
  covers them. P1 ships no conditional row.

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
| `fabric.capture.source` | `reported` or `observed`, from `begin(provenance=)` |
| `fabric.step.lifecycle_state` | the `lifecycle` input (§3.4 phase table); absent on `update` |
| `fabric.step.status` | the `result_status` input; `end` only |
| `fabric.content.object_ids` | when there are bodies or an evidence object (new key, X48, §4.1) |

The span status is the `otlp_status` input.

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
  span of the host span, and the alias is unresolved (§8, K3).

**Without a spool.** The worker emits the record through
`resolve_capture_provider` (`_loss.py:128-145`), exactly as `_emit` does for
exchanges (`wire/_pipeline.py:489-514`).
- A refused provider or a non-recording span is a `span_dropped` loss.
- D3 is unchanged: a protected provider never carries a record.
- The host's own spans stay best-effort duplicates. They never carry
  `fabric.source.*`, and the verifier ignores an unsequenced span that has an
  `event_id` (§3.12).

### 3.4a Structured evidence carrier (R7; consumed by 051–054)

This is the one generic, closed carrier for evidence that has no single
telemetry key: lists, per-item metadata, correlations, indexes and
continuation ranges. P2–P5 add **evidence types**, never a new carrier, spool
property, input class or Node component.

**1. Split.** A producer's fields fall into exactly one of three classes:

| Class | Carried as | Example |
|---|---|---|
| Scalar or array metadata (META, ID mapped, LABEL, DIGEST) with a registry telemetry key | Attributes on the records span (§3.4 rule A) | `fabric.db.rows_affected` |
| Structured metadata without a single key (lists of objects, indexes, per-item metadata, correlations) | The record's one **evidence object** (below) | MCP JSON-RPC correlation (N23), media index, realtime window index |
| CONTENT | Its own registered content role, as a `RecordBody` | `database.rows`, `terminal.stdout` |

Content never appears in attributes or evidence. Evidence refers to content
only by locator.

**2. Evidence object.**
- **Role:** `record.evidence` (new). `boundary` is the record's boundary. Its
  content provenance is `caller_reported` for `reported` attempts and
  `protocol` for `observed` ones.
- **Media type:** `application/vnd.fabric.record-evidence+json`.
- **Cap:** 1 MiB. There is at most **one** evidence object per record, and it
  counts toward `MAX_RECORD_BODIES`.
- **Document:** `fabric.record-evidence/v1`, spec-029 canonical JSON, closed:

  ```text
  {schema_version: "fabric.record-evidence/v1",
   evidence_type: "<namespace>.<name>/v<n>",     # registered, §4.1
   items: [ {<type-defined closed properties>} ],   # 0..4096 items, depth <= 4
   continuation?: {index: int >= 0, final: bool},  # §3.13 bounded continuation
   refs?: [ {object_id, role, pointer?, byte_range?} ]}   # locators into this record's bodies
  ```

- **Allowed value classes:** META (bounded ints, enums, times), LABEL
  (pattern-checked), DIGEST, and ID in mapped form (`v2`, `run_pseudonym`) or
  as Fabric-generated ids. Strings are at most 256 characters and must match
  the type schema's pattern. Every type schema is closed
  (`additionalProperties: false`), so free text cannot enter.
- **Clear-mode ids (R8).** An ID property may instead take the clear-mode
  forms (the opaque clear id or the `h-` form a type schema names) only when
  the record's source manifest declares `identity_mode: clear`, as for the
  marker ids of §4.1. This is the single clear-mode rule (R8): `clear` is an
  explicit opt-in, recorded in the manifest, never a default.
  `fabric.reconstruct` refuses a clear form under any other manifest, and a
  Node configured for pseudonymous identity refuses clear-mode sources (049
  §2.9 rule 7). 053 §3.2 and 054 §7.1 use this alternative.
- **Building:** `EvidenceDoc.build(evidence_type, items, refs=(), continuation=None)`
  checks the item count, depth and string lengths **before** serialising
  (R9). It is serialised on the capture worker. Over a bound, the record
  carries a `DescriptorOnlyBody(role="record.evidence",
  reason="payload_too_large")` instead.

**3. Protection.**
- `record.evidence` holds no CONTENT, so its role-table `default_policy` is
  `metadata` (new for a role, §4.1).
- It is stored whenever the content path exists, unless the capture policy
  maps it explicitly to `omit` or `metadata_only`.
- The modes `redact`, `tokenize`, `masked_only` and `original_plus_masked` are
  refused for this role at policy validation. A malformed policy raises at
  install.
- When content capture is disabled for the production profile (no policy or
  key), the evidence object is still written. Its ids are already mapped, or
  omitted without a key.
- With no content destination at all, it is a descriptor-only object (049
  §7.3) and its fields project as `not_captured(not_configured)`.

This exemption from precedence rule 1 is §9, delta 15.

**4. Node admission.**
- `fabriccontent` admits the role by the generated role-table row: all
  boundaries, provenance `caller_reported` or `protocol`, the media type above,
  and the 1 MiB cap.
- Pre-ack validation (§3.14) additionally checks four things:
  - canonical JSON;
  - the closed envelope keys;
  - `evidence_type` is in the generated registered-type list (`E/evidence_types_generated.go`);
  - the item count, depth and string-length bounds.
- Per-type schemas are validated by `fabric.reconstruct`. An invalid item makes
  the fields it carries `not_captured(parse_failed)`. That validation, and
  WP-00's reference envelope check, apply item 2's id rule, including the
  clear-mode alternative gated on the manifest's `identity_mode`; WP-00 adds
  a valid clear-mode fixture and an invalid clear id under a pseudonymous
  manifest.

**5. Seal representation.** The evidence object is one of the record's
bodies. Its `object_id` is in `fabric.content.object_ids` and its
`stored_sha256` is in the record digest's `content` list (§3.7), so the seal
covers it. A descriptor-only evidence object contributes `null`.

**6. Projection.**
- `reconstruct/_evidence.py` decodes the object.
- The registry declares a field-key → JSON-pointer map per evidence type
  (`evidence_types` in `field-registry-v1.json`, §4.1). It fills field wrappers
  with provenance from `fabric.capture.source` and the capture point from the
  record.

**7. Fixtures (WP-00).**
- the envelope schema `contracts/coverage/v1/schema/record-evidence-v1.schema.json`;
- the test type `fabric.test.items/v1`;
- valid and invalid evidence documents (an unknown type, an extra key, free
  text over the bound, too deep, too many items, a CONTENT-class value);
- a records span plus evidence object with its expected record digest and seal;
- a fabriccontent pre-ack case for each refusal.

053 and 054 register their types: N23 correlation, channel evidence, realtime
observations and media indexes.

### 3.5 Spool and sender (`wire/_spool.py`, `wire/_sender.py`, `wire/_pipeline.py`)

- **Record kind.**
  - `_KEYS["record"] = {"service_name", "span", "bodies"}`.
  - `valid_header` accepts `record_kind == "record"` with the same span checks
    as an exchange, but requires `fabric.capture.input == "records"` and
    `fabric.attempt.uid`, and forbids `fabric.wire.exchange_id`.
  - Bodies have the same shape as exchange bodies, with `MAX_RECORD_BODIES = 8`
    (up to four roles, each with a primary and a review copy; the evidence
    object and descriptor-only bodies count). A descriptor-only body has
    length 0 and no `stored_sha256` (R5).
- **Bounds checked by the writer (R6).**
  - `MAX_BODIES` (`wire/_spool.py:85`) becomes **260**:
    `original_plus_masked` gives every extracted part its own review copy
    (`wire/_protect.py` `_part_with_review_copy`), so 2 × (1 + 64 + 64 + 1).
  - `write_batch` / `_prepare` check the 260 and 8 bounds **before** writing.
    An over-bound record is refused as an `internal_error` loss for its
    position. Today only readers check (`wire/_spool.py:138`;
    `wire/_sender.py:292`), so an overflow is written and later quarantined as
    corrupt.
  - The bound belongs to this spec (WP-00 schema, WP-11b writer). The
    TypeScript track (055) consumes it and does not edit Python.
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
  - Two more fields: `id_basis` and `stop_reason`. `marker_doc` and
    `valid_header` follow the capture/v1 1.3.0 `marker` branch exactly. The full
    list of marker schema and validator additions is in §4.2. The 1.2.0 schema
    lacks `event_id`, `outcome`, `stop_reason`, `parent_run_id`,
    `resumed_from`, `links`, `session_id`, `user_id`, `id_basis` and the
    identity block.
  - The `loss` doc gains `segment_id` (R3).
  - The loss ledger (`wire/_ledger.py`) stores marker records unchanged. A
    manifest marker that exceeds `_PAYLOAD_MAX` is not mirrored there
    (`manifests_unledgered` stat). The heartbeat's `manifest_seq` still exposes
    the loss (049 §2.4 rule 4).
- **Sender.**
  - `_drain` sends a record's bodies with `_send_bodies`, exactly as for
    exchanges (`wire/_sender.py:333-384,412-426`).
  - `_span` builds record spans and marker spans from the typed marker.
  - Root ids of loss and heartbeat spans stay derived from the seed (`:428`).
  - **Marker event ids (R2).** Every marker (`run_start`, `run_end`,
    `segment_seal`, `final`, `periodic`, `manifest`) gets a uuid4 minted once
    when the `Marker` is built. It is persisted in the spool marker doc and in
    the ledger slot record, and exported as `fabric.event_id`. A replay or
    ledger export reads it back, so it is identical on every retry (X02 rule
    2). It is never uuid5, which the registry's uuid4 check would strip.
  - Loss spans carry `fabric.run.segment_id` when present.
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
  - A `DescriptorOnlyBody` from the producer goes straight to a descriptor-only
    object without PROTECT (there are no bytes).
  - The evidence object is serialised from `EvidenceDoc`, then protected under
    its role's mode (§3.4a).
  - There is no truncation of exact bytes: exact or nothing, as today
    (`byte_evidence.py:656-661`).

### 3.6 Segments and run structure (new `_segments.py`; `wire/__init__.py`)

**State.** A process-level `RunTable` holds one entry per emitted run id. All
of it is mutated only under the allocator lock.

```text
RunEntry {run_id, open_segment: seg-id | None, pending_start: Marker | None,
          sealed: list[SealedSegment], depth: int, resumable: bool, terminal_sealed: bool,
          final_block: bool, open_deadline_s: int | None, root_done: bool,
          outcome: RunOutcome | None, stop_reason: StopReason | None,
          correlation_id: EmittedId, id_basis: IdBasis}
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
| Outermost block exit, non-resumable run | terminal | Any later allocation for this run is post-terminal by construction (§8, K2) |
| `end_run(...)` | terminal, zero-width | — |
| `final()` (epoch end) | non-terminal for every open segment; terminal for a non-resumable run whose outermost block has exited | — |

"Outermost block in this process" means `depth` falls to 0. Depth counts every
open `run()` block of that run id in the process, across threads and tasks.

**Public API** (`fabric.wire`). Every function catches all Fabric failures and
never raises because of capture. Argument errors also fail open (R9, OD-11).
Today `run()` raises `ValueError` for a run id outside the opaque-id pattern
(`_sequence.py:239-240`). From P1:
- in pseudonymous mode any string is mapped;
- in clear mode an invalid id is emitted as `encode_opaque_id(value)` (`h-`
  form);
- a non-string runs the block uncaptured.

Only `FABRIC_RECORDS_STRICT=1` keeps the `ValueError`.

```python
@contextmanager
def run(run_id: str | None = None, *, session_id: str | None = None,
        user_id: str | None = None, parent_run_id: str | None = None,
        resumed_from: str | None = None, links: Sequence[str] = (),
        resume: str | Sequence[str] | None = None, resumable: bool = False,
        final: bool = False, open_deadline_s: int | None = None) -> Iterator[None]: ...
def resume_token() -> str | None: ...                      # seals; None outside a run or not capturing
def resume_tokens(branches: int) -> tuple[str, ...]: ...   # 1 <= branches <= 64; () when not capturing
def end_run(run_id: str | None, outcome: RunOutcome, *, resume: Sequence[str],
            stop_reason: StopReason | None = None) -> EndRunStatus: ...
EndRunStatus = Literal["ended", "refused_no_token", "refused_bad_token",
                       "refused_conflicting_tokens", "not_capturing", "failed"]
```

049 writes `resume_token(branches=n)`. This spec splits it into two functions
so the return type is not mixed (§9, delta 4). All of these functions are
fail-open (R9, §3.4).

**Run outcome hook (D30; the only path for it, R4).** `run()` yields `None`.
P2's public `fabric.records.set_run_outcome()` calls this P1 hook:

```python
# fabric/_segments.py (P1)
def set_run_outcome(outcome: RunOutcome, stop_reason: StopReason | None = None, *,
                    run_id: str | None = None) -> bool: ...
```

- It stores `outcome` and `stop_reason` on the `RunEntry` of `run_id`, or of
  the innermost open scope's run when `run_id` is `None`. A `run_id` argument
  is mapped by the identity rule (§3.4).
- It returns `False` when there is no open run, capture is not installed, or a
  value is outside the D30 field-type enums. The last call before the run's
  outermost block closes wins.
- The **outermost** `run_end` of the run in this process carries
  `fabric.run.outcome` and `fabric.run.stop_reason`. fabricguard admits both
  only on `run_end` (`P/coverage_keys.go:367-371`). Inner blocks' `run_end`
  markers carry neither. The verifier reads D30 from the `run_end` of the
  terminal segment's outermost scope; 051 follows this.
- Without a call, D30 is `unknown`.
- `end_run` carries its `outcome` and `stop_reason` the same way.

**Run identity (R1: minted run correlation id).** Every segment's
`fabric.run.id` is decided once, at segment open, by the first rule that
applies. The basis is emitted as `fabric.run.id_basis` on every `run_start`
(new key, §4.1):

| # | Situation | `fabric.run.id` | `id_basis` |
|---|---|---|---|
| 1 | Valid tokens given, all with the same correlation id `c` | `c`, verbatim. It is an emitted value parsed from Fabric tokens and is never re-mapped, so key rotation does not change it. A clear `run_id` also passed is ignored for the id, and its mapping is not emitted. | `token` |
| 2 | Valid tokens with different correlation ids, and the caller passed a clear `run_id` (fan-in under one application run) | the mapped clear id (identity rule, §3.4) | `caller_join` |
| 3 | Valid tokens with different correlation ids, no clear `run_id` | the lowest correlation id (byte order) | `token_conflict` |
| 4 | No valid token, clear `run_id` (argument or same-host `FABRIC_RUN_ID`) | the mapped clear id | `caller` |
| 5 | No valid token and no run id (`run()` with no arguments, typically an orchestrator that only issues tokens) | a **minted** correlation id: `r-` + 32 hex from `secrets.token_hex(16)`, an `EmittedId` with no caller input | `minted` |
- The run's correlation id is the run id of its root segment (rule 4 or 5). It
  is copied into every token the run issues, so A → B → C keeps one id even
  when B is wholly lost: C's tokens came from B, which carried A's id.
- **Verifier:**
  - Segments are grouped by `fabric.run.id`.
  - Rule 2 merges the runs named by the tokens' predecessors into the
    consumer's run as `run_aliases`.
  - Rule 3 is `segment_conflict` (G1, a new conflict reason class: tokens of
    different runs joined without a caller join).
  - Two runs whose ids differ only by key (rotation with rule-4 ids) are joined
    as aliases only through a predecessor entry, as in 049 rev 6.4.
- In clear mode (R8), rules 4 and 2 emit the clear id as given. Rule 5 still
  mints. A caller-rooted run's correlation id is therefore its clear id, and
  its tokens carry that clear id across service and host boundaries (W3C
  `baggage` `fabric.resume` or the message attribute). Clear mode is an
  explicit opt-in (`identity_mode="clear"`, R8), never a default; the OD-7
  docs state this next to K7.
- This rule (correlation id = the mapped clear id when the caller gives one,
  otherwise minted) is the one 051, 052 and 055 follow (055 TS-OD-8). The
  resume-token-v2 vectors of WP-00 encode it.

**Argument rules.**
- `run_id` (clear), `parent_run_id`, `resumed_from` and `links` follow the
  identity rule. `session_id` maps to `sess-` and `user_id` to `usr-` (v2);
  without a key they are omitted.
- `run_id=None` takes `FABRIC_RUN_ID` (same-host only, OD-7), read once by
  `install_from_env`.
- `resume` takes tokens. When `resume` is `None`, the first root entry takes
  `FABRIC_RUN_RESUME_TOKEN` (comma-separated, percent-decoded by the caller).
  The environment tokens are consumed once.
- `end_run(run_id=None, …)` takes the run id from the tokens' correlation id.
  If the tokens disagree and no `run_id` is given, it returns
  `refused_conflicting_tokens`.

**Resume contract (decision 22; R1; OD-7).**

| What | Within a process | To a child process on the same host | Across a service or host boundary |
|---|---|---|---|
| Clear run id (the application's) | `run(run_id=…)` | env `FABRIC_RUN_ID` | **not propagated** |
| Resume tokens (Fabric-emitted, never mapped) | `run(resume=…)` | env `FABRIC_RUN_RESUME_TOKEN` | W3C `baggage` entry `fabric.resume` (percent-encoded), or message attribute `fabric.resume` |
| Emitted `r-` run id | never passed as a run id: passed in, it is a plain string and is mapped again | — | — |

**Tokens.**
- The token format moves to `fr3/` because it now carries the correlation id
  (resume-token-v2 vectors, §4.3):

  ```text
  fr3/<run correlation id>/<seg-id>/<source_id>/<epoch>/<last_seq>/sha256:<manifest digest>[/br-<32 hex>]
  ```

  - The correlation id is `r-` + 32 hex (minted, or the mapped clear id). In
    clear mode (an explicit opt-in) a caller-rooted run's correlation id is
    the clear run id as given, so the token in `baggage` carries it; it must
    match `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` (no `/`),
    else the token is not issued (`api_misuse`).
  - `fr2/` tokens (no correlation) are still parsed for one release. A segment
    opened from them takes its run id by rule 4 or 5 with
    `id_basis: legacy`. The verifier joins it by predecessor union, as in rev
    6.4.
- Tokens are parsed strictly by the v2 grammar. The reference parser is ported
  from `scripts/contracts/validate_coverage_contracts.py:1541-1588` and
  extended.
- A malformed token is dropped (`tokens_rejected` stat, one class-only
  warning). If none remains, rules 4 or 5 apply and the segment is a root
  (`none`). The verifier then sees more than one root, which is
  `segment_conflict`; it is never silently complete.
- A run opened with a valid token is resumable.
- A token's `branch_id` goes into `fabric.run.branch_ids` of the consumer's
  `run_start`.
- `last_seq` is the allocator's last sequence at the seal (one counter per
  source).
- Under `FABRIC_WIRE_LABELS=clear` the token's `source_id` is the operator's
  clear label, and it crosses the boundary with the token. The OD-7 docs say
  so.

**`end_run` emits a zero-width segment.**
1. It mints a scope id and segment id, and takes the run id by the
   run-identity rules (`run_id=None`: the tokens' correlation id).
2. It emits `run_start` (predecessors = tokens, `id_basis`).
3. It emits `run_end` (`fabric.run.outcome` = `outcome`,
   `fabric.run.scope_status=ok`).
4. It emits a terminal `segment_seal` over an empty member list.

The outcome rides on `run_end` because fabricguard admits `fabric.run.outcome`
only on `run_end` (`P/coverage_keys.go:369`; §9, delta 2). Without at least one
valid token, `end_run` returns `refused_no_token` and emits nothing. With
`run_id=None` and tokens whose correlation ids differ, it returns
`refused_conflicting_tokens`.

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

Loss entries come only from losses attributed to **this** segment (R3). The
verifier selects them by the loss record's `segment_id`, never by sequence
range.

**`SealAccumulator`.**
- It is owned by the pipeline. It keeps `segment_id → {entries,
  outstanding, seal_request}`.
- The worker calls `settle()` after `spool_exchanges` returns `spooled`, or
  after a span is emitted on the provider path. Loss paths call it through
  `LossEmitter.record`.
- When a seal is requested and `outstanding == 0`, it builds the
  `segment_seal` marker and queues it through `LossEmitter.queue_beat`.
- Memory is bounded: each open or unsealed segment holds at most one
  32-byte digest per position. At 65,536 entries for a segment, the
  segment is forced to seal (non-terminal, a new segment continues it locally,
  `segment_forced_seal` stat). The bound also caps the cost of releasing any one
  segment's state, wherever that happens (P1 review).
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
| `fabric.capture.source` | `observed` |
| `fabric.wire.endpoint_id` (C35) | The matched endpoint's id from the matcher (`wire/_match.py`). A built-in default endpoint is `<provider>.default` (not sensitive). A configured endpoint is `lbl-` + keyed v1 label of its configured name, or the clear name under `FABRIC_WIRE_LABELS=clear`. A hostname is never emitted. |
| `fabric.wire.provider_request_id` (C40) | Only with opt-in `FABRIC_WIRE_PROVIDER_REQUEST_ID=1` (default off, 049 C40 policy `off`). The value of exactly one response header (`x-request-id` for OpenAI and Azure, `request-id` for Anthropic) is read from the response object the client already has (httpx `Response.headers` / aiohttp `ClientResponse.headers`) at response start, mapped to `p-` (v2), and omitted without a key. The header block is never read or stored. |

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

  The `end` emit passes `lifecycle` and `result_status` separately (R4):

  | Explicit result | `lifecycle` | `result_status` |
  |---|---|---|
  | `ok` | `completed` | `ok` |
  | `error` | `completed` | `error` |
  | `cancelled` | `cancelled` | `cancelled` |
  | `deferred` | `deferred` | `unknown` |

  `otlp_status` is `error` only for `error`.
- A capture of a non-bytes value (today `unsupported` / `not_exact_bytes`,
  `call_recorder.py:350-354`) becomes a
  `DescriptorOnlyBody(status="unsupported", reason="not_exact_bytes")`.
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
    (`call_recorder.py:42-47`), all admitted by the role table. An object over
    the cap, measured by `len()` on the app thread with no copy, becomes
    `DescriptorOnlyBody(payload_too_large)`.
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
  - Each `span.add_event(name, attributes=…)` the mirror sees emits one record
    of its own attempt, with `name_hint` = the event name,
    `start_ns = end_ns` = now, phase `end`, lifecycle `completed` and
    result status `ok`. There are **13** event sites in `decision.py`:
    `:1119` retrieval, `:1235`, `:1323` and `:1398` memory, `:1557` side
    effect, `:1605` checkpoint, `:1680` replay, `:1803` interaction, `:1858`
    coverage (`_add_coverage_event`), `:1935` skill, `:1999` delegation,
    `:2139` hook and `:2209` file.
  - The coverage event (`:1858`) is Fabric's own signal. It is emitted as an
    `extension` step `x-fabric.coverage` and never counts toward a profile.
  - Attribute values pass rule A only. No `str()` or `repr()` of an application
    value is taken (R9).
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
| coverage | `extension` (`x-fabric.coverage`) |

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
  - For each `segment_seal`, the verifier collects the records of the
    segment's source whose `fabric.run.segment_id` equals the seal's segment
    id, and the loss records whose `segment_id` equals it (R3). It computes
    `_seal.seal_digest` and compares it.
  - A loss record without `segment_id` (pre-P1, or outside runs) is never a
    seal member.
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
- **Run grouping (R1).**
  - Segments are grouped by `fabric.run.id`.
  - A `run_start` with `id_basis=caller_join` merges the runs of its
    predecessors' segments into its own run as `run_aliases`. Merging is
    transitive, by union-find over segment ids.
  - Predecessor entries across differing run ids with any other basis are not
    merged: they are `segment_conflict` (G1). For `token_conflict` they are
    reported in `id_basis_conflicts`.
  - Rotation joins happen only through `caller_join`, or automatically, since
    a token keeps the correlation id.
  - `legacy` (`fr2/` tokens and pre-P1 segments) keeps the rev 6.4 behaviour:
    predecessor union with aliases.
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
  - Inferred `input` steps: a uuid4-**format** id derived from SHA-256 of the
    evidence locator, with the version and variant bits set (RFC 9562 §5.4
    layout). It satisfies the schema's uuid4 pattern and is reproducible across
    regenerations. It is never uuid5.

    The verifier has no store to persist a minted id into, and a regenerated
    projection must give the same ids. This is the one reviewed exception to
    R2's "minted once"; every emitted id (markers, records) is minted once and
    persisted.
  - **Bounded `event_ids` (R15).** The schema caps `event_ids` at 64. When an
    attempt has more records (long explicit streams, realtime windows), the
    step lists the first 64 by `(source, epoch, sequence)`. Its `event_id`
    field wrapper (X02) carries `collection {completeness: complete |
    partial, observed_count: n}`. The full membership is the attempt's
    sequence set in the run-reconstruction report. An evidence object's
    `continuation {index, final}` (§3.4a) gives windowed producers a bounded
    per-record index.
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
| C40 | `fabric.wire.provider_request_id` | `captured` when present; `not_captured(hook_disabled)` when the opt-in is off; `not_captured(missing_id_key)` without a key; `not_captured(provider_not_returned)` when the header is absent |
| C34, C35 | span `gen_ai.provider.name`, `fabric.wire.api`; C35 from the persisted `fabric.wire.endpoint_id` | C35 `unsupported(unsupported_version)` for pre-P1 spans |
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
| N51 | asset references in the request: non-data `image_url.url`, `file_id`, `input_file.file_id`/`file_url`, Anthropic `source.type` `url`/`file` | Locator only (CONTENT), never dereferenced; `absent` when the parsed request has none |
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
- Fields carried in an evidence object are decoded by `_evidence.py`
  (§3.4a item 6).
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
  - `fabric.capture.input` (`records` only: no W-class records, R7),
    `fabric.capture.source`, `fabric.attempt.uid`, `fabric.event_id`,
    `fabric.capture.point`;
  - `fabric.run.id`, `fabric.run.scope_id`, `fabric.run.segment_id`;
  - `fabric.step.kind`, `fabric.step.lifecycle_state`, `fabric.step.status`,
    `fabric.actor.type`, `fabric.error.domain`;
  - `fabric.step.id`, `fabric.step.attempt_id`, `fabric.step.parent_id`;
  - `fabric.content.object_ids`;
  - the existing decision metadata keys of the allowlist.

  The registry's `check.span` gains `record`, and the generator emits the bit.
- **Loss class (R3):** `fabric.run.segment_id` is admitted on loss records.
- **Every marker kind** admits `fabric.event_id` (uuid4), including the
  `fabric.capture_manifest` span.
- **Exchange class:** `fabric.capture.source`, `fabric.wire.endpoint_id` and
  `fabric.wire.provider_request_id` are admitted.
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

**Content validation before acknowledgement (R10: the default, flipping
decision 24, RPOC).**

Design (`E/factory.go`, new `E/prevalidate.go`):
- `createLogsExporter` returns a `validatingLogs` wrapper whose
  `ConsumeLogs(ctx, ld)` runs the stateless checks on every record before
  handing the batch to the exporterhelper queue:
  - `parseRecord`, which includes the length and digest recompute
    (`E/record.go:166-188`);
  - `parseDescriptor` and the role, protection and link consistency checks
    (`:192-246,489-501`);
  - the tenant allowlist (`E/exporter.go:139-141`);
  - the source binding (`:142-144`);
  - for `record.evidence`, the envelope check of §3.4a item 4.
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
- **Acceptance is not durability.** A 200 means the record passed every check
  that needs no store read and is in the persistent queue. It does not mean the
  object reached the store. Durability is shown only by reconstruct's readback
  of the configured store (049 §7.9 trusted readback), and receipts stay
  qualified-run only.
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
| Recorder API misuse (bad enum, mutable body, unknown prefix, lifecycle on `update`) | Fail-open: dropped input, `api_misuse` count; raises only under `FABRIC_RECORDS_STRICT=1` (R9) |
| Over-bound record or exchange (260 / 8) | Refused before write; `internal_error` loss |
| Evidence over its bounds | `DescriptorOnlyBody(record.evidence, payload_too_large)` |

No new code runs on the host thread beyond: the allocation hook, building
an immutable job, `put_nowait`, and (D2) reading one boolean. Fork hooks take
locks only.

### 3.17 Privacy of every new datum

| Datum | Class | Rule |
|---|---|---|
| epoch | META | random; reveals nothing |
| registration file | — | 0600 in the 0700 spool dir. Holds the source id as emitted (pseudonymous), pid and time. No content. |
| `seg-`, `br-`, `fr3/` | ID | random or emitted ids; tokens carry the run correlation id and the emitted source id (a clear label only under `FABRIC_WIRE_LABELS=clear`) |
| `run_id`, `parent_run_id`, `resumed_from`, `links` | ID | `r-` mapped (decision 22) |
| `session_id`, `user_id` on `run_start` | ID | `sess-`, `usr-` v2; omitted without a key |
| `fabric.content.object_ids` | ID | uuid4 |
| record attributes | META/ID/LABEL | rule A; caller ids mapped; no content key exists |
| record bodies | CONTENT | PROTECT before spool; spool envelope in production |
| manifest | META/DIGEST | no endpoint hostnames, only the endpoint-set digest |
| projection | — | locators only unless `--inline-content`; written 0600 |
| `FABRIC_RUN_ID` | clear app id | never emitted; the app's own value; in-host only (OD-7) |
| minted run correlation id | ID | `r-` + 32 CSPRNG hex; no caller input |
| `fabric.wire.endpoint_id` | LABEL | built-in `<provider>.default` or keyed `lbl-`; never a hostname |
| `fabric.wire.provider_request_id` | ID | opt-in; `p-` v2 keyed; omitted without a key |
| evidence object | META/ID/LABEL/DIGEST | closed registered types; ids mapped; no CONTENT (§3.4a) |
| marker `event_id` | ID | uuid4 |

Privacy canaries for P1 cover:
- a clear run, session and user id passed through `run()` and the environment;
- caller operation and attempt ids;
- content in `record_data`;
- an error message in an explicit call;
- the endpoint host and a provider request id header value;
- a free-text string inside an evidence item (must be refused).

The canaries are scanned in the spool files, the registration files, the
ledger, Node telemetry, the report, the projection and logs.

---

## 4. Contract deltas

These are not edited in this task. WP-00 makes them, in this order, before any
other WP.

### 4.1 Registries (`contracts/coverage/v1/registry/`)

**`field-registry-v1.json`.**
- X08 definition: "a caller value is mapped in pseudonymous mode and emitted as
  given in clear mode (decisions 7, 22); only an `EmittedId` passes through; a
  run started from tokens takes the tokens' run correlation id".
- The P0/P0-A phase relabels of R64-10.
- **New X48** `content_object_ids`: a list of uuid4 (max 8), observed by
  `fabric.self`, metadata, ID, O, absent, P1, lives in T
  `fabric.content.object_ids`. It names the content objects a records-input
  record references, including its evidence object, in reference order.
- **New X49** `run.id_basis`: an enum `caller`, `caller_join`, `token`,
  `token_conflict`, `minted`, `legacy`. Observed by `run.scope`, metadata,
  META, R (`run_start`), always, P1, lives in T `fabric.run.id_basis`.
- **C35** lives in T `fabric.wire.endpoint_id` (R15).
- **C40** lives in T `fabric.wire.provider_request_id`. It stays P1, built in
  WP-14 (R15).
- **N51** is P1 via `reconstruct.parse` in WP-33. It is unchanged in the
  registry and now has an owner.
- D30 `phase`: "P1 (`end_run`, run hook), P2 (public API)".
- **New `evidence_types` block.** Each row has a type id, a schema path, the
  field-key → JSON-pointer map, and the capture points allowed to emit it. P1
  registers only `fabric.test.items/v1`.

**`telemetry-keys-v1.json`.**

New keys:

| Key | Field | Check | Placement |
|---|---|---|---|
| `fabric.content.object_ids` | X48 | array 1–8 of uuid4 | `record` |
| `fabric.run.id_basis` | X49 | enum | `run_start` |
| `fabric.wire.endpoint_id` | C35 | `^(?:[a-z][a-z0-9_]{0,31}\.default\|lbl-[0-9a-f]{32})$` | `exchange` |
| `fabric.wire.provider_request_id` | C40 | `^p-[0-9a-f]{32}$` | `exchange` |

- **A row for the existing `fabric.capture.source`** (X27, `change: reused`):
  enum `observed`, `reported`, placed on `exchange` and `record` (R15). Today
  it has only the legacy allowlist entry (`P/allowlist.go:30`).
- **`check.span` placements:**
  - `record` added for the keys of §3.14;
  - `fabric.session_id`, `fabric.user_id` and the X05 keys on `run_start` and
    `exchange`;
  - `fabric.run.segment_id` also on `loss` (R3);
  - `fabric.event_id` on every marker kind including `manifest`.
- `fabric.run.outcome` and `fabric.run.stop_reason` phase becomes "P1
  (`end_run`, run hook)".

**`content-roles-v1.json`.** New role `record.evidence`:

| Property | Value |
|---|---|
| layer | cross-cutting |
| boundary | every boundary |
| provenance | `caller_reported`, `protocol` |
| media type | `application/vnd.fabric.record-evidence+json` |
| cap | 1 MiB |
| `default_policy` | `metadata` (a first for a role) |
| `telemetry_forbidden` | true |
| phase | P1 |
| allowed modes | `retain_original`, `metadata_only`, `omit` |

The table version becomes `fabric.content-role-table/v1@4`. The Go and Python
role tables are regenerated.

**`capture-points-v1.json`.**
- The `state` text for `explicit.*`, `sdk.records`, `run.scope` and
  `fabric.self` reads "P1: built" once built.
- New property `qualified_versions` (P1-A) on W points.
- The R64-5 host-sensor wording.

**`vocabularies-v1.json`.**
- The `reason` definition of `body_cap` is widened to "… or a records object
  exceeded `records_max_object_bytes`" (minor).
- New `step_kind` value **`agent_turn`**: "One agent turn reported by
  `decision()`: the agent's handling of one input, enclosing its model, tool
  and other steps." The generated fabricguard `fabric.step.kind` enum and the
  projection schema enum follow through the validator's enum-equality check.
  `fabric.profile.agent-run/v1` does not add it to its required kinds in P1.
- New `run_id_basis` vocabulary (X49).

### 4.2 Schemas

**`capture/v1/schema/spool-record-v1.schema.json`** (capture/v1 1.3.0):
- **R6.** Exchange `bodies.maxItems` goes from 130 to **260**: 2 sides × (1
  primary + 64 parts + 64 per-part review copies + 1 side review copy).
- The `record` branch gains optional `bodies` (exchange body shape,
  `maxItems: 8`), with `service_name` (already present).
- A body descriptor may be descriptor-only (`stored_byte_length` absent, length
  0) with `status` in {`not_captured`, `unsupported`} and a `status_reason`
  (R5).
- **Loss branch:** optional `segment_id` (`seg-` + 32 hex) (R3).
- **Marker branch, the full list of additions:**

| Property | Allowed on | Check |
|---|---|---|
| `event_id` | every kind, **required** from 1.3.0 | uuid4 (R2) |
| `session_id`, `user_id` | root `run_start` only (`predecessors == ["none"]`) | `sess-`/`usr-` + 32 hex, or clear under `identity_mode=clear` |
| `parent_run_id`, `resumed_from` | root `run_start` only | `r-` + 32 hex, or clear in clear mode |
| `links` | root `run_start` only | array 0–16 of the same |
| `id_basis` | every `run_start` | X49 enum |
| `outcome`, `stop_reason` | `run_end` only | D30 field-type enums |
| `identity` (X05 block) | `run_start` | the X05 key checks |

- A pre-1.3.0 marker without `event_id` stays readable. The writer always sets
  it.

**`capture/v1/schema/loss-record-v1.schema.json`** (heartbeat/loss form):
- `segment_id` on loss;
- `event_id` on every heartbeat;
- the marker additions above with the same placement.

**`capture/v1/schema/run-reconstruction-v1.schema.json`:**
- `runs[]` gains `run_state`, `segments[]` (the projection's segment shape),
  `run_aliases`, `id_basis_conflicts`, `deadline_at` and `evaluated_at`.
- `sources[]` gains `manifests[]` and `unsealed_epochs[]`.
- `gapType` adds the 10 types of §3.12.
- `inputs.evaluated_at`.

**`coverage/v1/schema/record-evidence-v1.schema.json`** (new): the §3.4a
envelope, plus `coverage/v1/evidence/fabric.test.items-v1.schema.json`.

**No change to:**
- `coverage/v1/schema/step-projection-v1.schema.json`. T1 requires the build
  not to need one. The >64 records rule of §3.13 uses the existing `collection`
  wrapper.
- `coverage/v1/schema/capture-manifest-v1.schema.json`.

**Validator deltas** (`validate_capture_contracts.py` `_check_marker` and the
loss check):
- outcome and stop_reason only on `run_end`;
- session, user, parent, resumed_from and links only on a root `run_start`;
- `id_basis` required on `run_start`;
- `event_id` uuid4 on every marker and heartbeat;
- a loss `segment_id` must match the segment pattern;
- one loss record never names two segments.

`validate_coverage_contracts.py` gains:
- `validate_evidence_document`;
- an `evidence_types` registry check (schema exists, pointer map resolves,
  points exist);
- the resume-token v2 grammar.

### 4.3 New vectors and fixtures

| Path | Content |
|---|---|
| `contracts/coverage/v1/fixtures/vectors/seal-digest-v1.json` | Record digests for an exchange, a record with bodies, a record with a descriptor-only body, a record with an evidence object, an empty segment, segment-attributed loss entries, receiver-owned key exclusion and int64/array typing. Seal digests. |
| `contracts/coverage/v1/fixtures/vectors/span-category-v1.json` | `(name_hint, attribute keys) → name`, covering every branch of `P/processor.go:895-947`. |
| `contracts/coverage/v1/fixtures/vectors/seal-parity-v1.json` | Emitted span, fabricguard export and digest (T3), including a loss with `segment_id`. |
| `contracts/coverage/v1/fixtures/vectors/records-span-v1.json` | Admitted and stripped attributes on a records span, including `fabric.capture.source`. |
| `contracts/coverage/v1/fixtures/vectors/resume-token-v2.json` | `fr3/` grammar: valid, rejected, clear-mode correlation id, `fr2/` back-compat. Run-identity rules 1–5 as `(inputs → run id, id_basis)` cases. |
| `contracts/coverage/v1/fixtures/vectors/record-evidence-v1.json`, `contracts/coverage/v1/valid/evidence-*.json`, `contracts/coverage/v1/invalid/evidence-*.json` | The §3.4a carrier fixtures. |
| `contracts/coverage/v1/fixtures/projection/` | Model-call input bytes plus expected field sets per dialect: chat, chat-stream, responses with hosted tools and reasoning, responses stream, `previous_response_id` resolved and unresolved, anthropic thinking, redacted thinking and server tools, embeddings, refusal, unknown item, asset references (N51), 40 MiB image request, 70 MiB side. |
| `contracts/coverage/v1/valid/projection-records-explicit-d2.json`, `projection-many-records.json` | P1-A D2 projection; an attempt with 300 records (bounded `event_ids`). |
| `contracts/capture/v1/fixtures/valid/spool-record-record-bodies.json`, `spool-record-exchange-260.json`, `loss-record-segment.json`, `spool-record-marker-run-end-outcome.json`, `run-reconstruction-segments.json`, and invalid counterparts for every new marker rule | New examples. |
| `contracts/content/v2/fixtures/node-prevalidate-v1.json` | One case per pre-ack refusal reason (WP-21), including evidence-envelope failures. |

---

## 5. Work packages

Rules for every WP:
- Each WP touches only its **owner area**.
- A shared file has exactly one owner at a time; the order is listed under
  "File ownership" below. Other WPs call into it only through the interfaces
  WP-01 lands.
- Each WP ends with `ruff`, `mypy --strict` (Python) or `go test ./...` (Go)
  for its area, its own tests, and `scripts/tests/test_recorder_release_boundary.py`.
- Every code-writing WP runs on Opus-class agents; read-only research may use
  Sonnet.
- **No TypeScript-track WP edits Python files (R13).** The shared Python
  changes 055 needs belong to these WPs: the 260 bound (WP-00, WP-11b),
  `wire/_spool.py` (WP-11b) and `reconstruct/**` (WP-30–WP-33). Python exit
  gates never depend on a TypeScript WP.

**Pre-requisites (outside this spec's WPs).**

| Id | What | Must be merged to main before |
|---|---|---|
| H0 | The v0.8.1 hotfix branch `fix/decision-line-privacy` (rewrites `decision.py`, `integrations/mcp.py`, `_identity.py`, `decision.ts`, `identity.ts`; 051 marks its items "landed in v0.8.1 (hotfix)") | **WP-15** here; 051 WP2-1a; 055 WP-08a |
| R16 | `test/agent-matrix` and `test/chaos` (§6.3) | WP-43, WP-50 |

### Wave 0 (foundation: WP-00 and WP-01 in parallel; WP-21 independent)

| WP | Owner area | Depends | Deliverables | Tests | Exit check |
|---|---|---|---|---|---|
| **WP-00 Contracts** | `contracts/coverage/v1/**`, `contracts/capture/v1/**`, `contracts/content/v2/fixtures/node-prevalidate-v1.json`, `scripts/contracts/**`, `scripts/tests/test_coverage_contracts.py`, `scripts/tests/test_capture_contracts.py`; generated files `P/coverage_keys.go` table, `E/roles_generated.go`, `E/evidence_types_generated.go`, `sdk/python/src/fabric/_records_keys_generated.py`, `_manifest_fields_generated.py`, `_roles.py` table | — | All of section 4, including the §3.4a carrier fixtures and the 260 bound. Reference Python implementations of the seal digest, the span category, the run-identity rules and the evidence envelope check, in `scripts/contracts/`, used to produce the vectors. | Validator over every new fixture and vector. Generated-file drift check. C0-1..C0-5 still pass. | `validate_coverage_contracts.py` and `validate_capture_contracts.py` pass; generators pass `--check` |
| **WP-01 SDK interfaces** | `_capture_types.py` (new). Stub modules `_records.py`, `_evidence.py`, `_segments.py`, `_seal.py`, `_manifest.py`, `wire/_registration.py`, `wire/_attrs.py`, `reconstruct/_graph.py`, `reconstruct/_project.py`, `reconstruct/_fields_model.py`, `reconstruct/_evidence.py`. Call sites: `wire/__init__.py` (install, close, run hooks), `_sequence.py` (`Allocation` and hook call), `wire/_pipeline.py` (job dispatch, the `p1_attributes` merge hook in `exchange_attributes`, settle calls), `_loss.py` (`Marker` type; `record(…, segment_id=None)` and `settle` call sites, no-op) | — | Dataclasses and protocols of §3: `Allocation`, `Marker`, `RecordJob`, `RecordBody`, `DescriptorOnlyBody`, `EvidenceDoc`, `Attempt` with the R4 inputs, the `SealAccumulator` and `RunTable` protocols, the fail-open/strict decorator. No-op stubs, so the existing suite passes unchanged. | The full existing suite. A type-check of the stubs. | No behaviour change (wire goldens pass) |
| **WP-21 Node pre-ack validation** | `E/**` (except generated files), `charts/fabric/charts/otel-collector/tests/test-content-delivery.sh` (new assertions), `wire/_content.py` and `wire/_sender.py` **`status()` lines only** | WP-00 for the evidence-type list (stub until merged) | §3.14 pre-validation, including the evidence envelope check; the counter; agent status and warning | Go: each refusal reason gives 400 and nothing enqueued; a valid record gives 200; a conflict stays post-queue. Python: 400 maps to `rejected` and a status count. An e2e (compose) case. | T4 |

### Wave 1 (parallel; at most 6 agents)

| WP | Owner area | Depends | Deliverables | Tests | Exit check |
|---|---|---|---|---|---|
| **WP-10 Epochs and allocator** | `_sequence.py`, `wire/_registration.py`, `wire/_forks.py` | 00, 01 | §3.2, §3.3: CSPRNG epochs; registration with an explicit status (`registered`, `failed`, `registration_full`, `unregistered_fork`, `unregistered_direct`); the mmap mirror; the child closing the registration fd and mmap; the orphan scan API (called by WP-11b's drainer); `Allocation`; the process component; settlement accounting | Property: epochs nonzero and 63-bit; redraw on a held or unsealed collision. Multiprocess: two installs on one spool never share an epoch. A spawned worker SIGKILLed after allocation is seen by an orphan scan. **Fork:** the child does not write the parent's mirror, and a parent SIGKILLed while forked children live becomes an orphan. Passivity: allocation ≤ 3 µs. | Unit and multiprocess suites green |
| **WP-11a Records input and seal** | `_records.py`, `_evidence.py`, `_seal.py`, `wire/_pipeline.py` | 00, 01; WP-10 interface | §3.4, §3.4a, §3.7: rule A, rule N, phases and the three status inputs, descriptor-only bodies, `mode_of`, `v2`, string bodies, bounded `EvidenceDoc`, record jobs, PROTECT of bodies and evidence, `SealAccumulator`, settle paths | Seal vectors. Evidence fixtures. R4 phase-table cases. R9 strict versus fail-open. Queue-full losses settle the seal per segment. Provider path, including sampled-out → `span_dropped`. D3 refusal. Passivity of `emit`. | `seal-digest-v1`, `records-span-v1` and `record-evidence-v1` vectors pass |
| **WP-11b Spool, sender, markers and losses** | `wire/_spool.py`, `wire/_sender.py` (except WP-21's lines), `wire/_ledger.py`, `_loss.py` | 00, 01 | §3.5: the `record` kind, descriptor-only bodies, the writer-side 260/8 bound check (refusal → `internal_error` loss), typed markers with persisted uuid4 `event_id`, segment-attributed loss aggregation, ledger and spool (R3), marker spans, orphan heartbeat emission | Spool header property tests (exchange, record, marker and loss round trip; corrupt frames; 260 bodies accepted, 261 refused before write). A ledger replay keeps the marker `event_id`. Losses of two segments never coalesce. Disk-full losses settle. | Existing spool suites green; capture/v1 1.3.0 fixtures round trip |
| **WP-13 Manifests** | `_manifest.py` | 00, 01 | §3.8: build, digest, span mapping, chain, fork template, state-change API, per-epoch fixed fields | Every emitted manifest validates with `validate_manifest_document`. Chain vectors. A forked child's manifest 0. Re-install starts a fresh epoch. | Manifest fixtures reproduced byte for byte from a configured handle |
| **WP-20 fabricguard records class** | `P/**` (non-generated) | 00 | §3.14: records class, placements (including loss `segment_id` and marker `event_id`), the manifest `s-` rule, the category test, the seal-parity Go test | Go unit tests for each admitted and stripped key on the records and loss classes. The binding check on records. Vectors. | `go test ./processor/...`; T3 Go half |
| **WP-30 Verifier: inputs and integrity** | `reconstruct/_inputs.py`, `reconstruct/_verify.py`, `reconstruct/_report.py`, `reconstruct/__main__.py` | 00, 01 | §3.12 inputs, integrity, manifests, segment-attributed loss selection, seal recompute (using `_seal.py` through the WP-01 interface), report fields, CLI flags, exit code | Extends the `Capture` builder (`tests/test_reconstruct_verifier.py:123-421`) with `record()`, `manifest()` and `segment_seal()`. Records interleaved with exchanges verify. Host duplicates are ignored. Seal mismatch for a deleted tail, an edited record and a moved record. Unsealed segment. Manifest gap. Interleaved segments with losses. The report validates. | Existing reconstruct suites green; new cases green |

WP-33 runs in wave 1 as a seventh slot only if an agent is free; otherwise it
moves to the start of wave 2.

| WP | Owner area | Depends | Deliverables | Tests | Exit check |
|---|---|---|---|---|---|
| **WP-33 Model-call field extraction** | `reconstruct/_fields_model.py`, `reconstruct/_stitch.py` (extension only) | 00 (fixtures), 01 | §3.13 table: reasoning formats, hosted tools, unknown items, N51 asset references | Golden: every `fixtures/projection/` case. Fuzz: malformed JSON, SSE and compression never raise and give `parse_failed`. The 64 MiB decode cap is kept. | Goldens equal; no exception under fuzz (10k cases) |

Intra-wave integration: WP-11a's end-to-end spool tests run after WP-11b
merges. Until then they run against the WP-01 spool stub.

### Wave 2 (at most 6 agents)

| WP | Owner area | Depends | Deliverables | Tests | Exit check |
|---|---|---|---|---|---|
| **WP-12 Segments and run API** | `_segments.py`, `wire/__init__.py` | 10, 11a, 11b | §3.6: `RunTable`, run identity rules 1–5 and `id_basis`, `fr3/` tokens, segment open and seal triggers, continuation `run_start`, fork hooks, `run()` arguments, `resume_token(s)`, `end_run(run_id=None)`, `set_run_outcome`, environment intake, records-only install documentation | Unit: every seal-trigger row; every run-identity rule with the v2 token vectors. Concurrency: `gather` and `to_thread` share a segment. Fork: child segment and fresh scope ids; parent `declared_branches`. `end_run` refusals. Canaries: clear run id in env and arguments, and never in baggage-shaped outputs. | LR-1 single-host subset (re-entry, fork, branch tokens, lost middle with token-only hops) passes against WP-30 and WP-31 |
| **WP-14 Wire enrichment** | `wire/_attrs.py`, `wire/_stream.py`, `wire/_aiohttp.py`, `wire/_transport.py` (event id minting, the provider-request-id header read) | 11a (hook) | §3.9, including C35 `endpoint_id` and C40 | Exchange spans carry the keys and pass the fabricguard tests (WP-20 vectors). First-chunk offset is present for streams and absent for empty responses. C40: no header read unless opted in; never the header block; omitted without a key. The 047 §4.10 budgets. | `test_wire_passivity.py` and `test_wire_aiohttp_passivity.py` green |
| **WP-15 Decision records** | `decision.py`, `_calls.py`, `_records_mirror.py` | 11a; **H0** (hotfix `fix/decision-line-privacy` merged to main) | §3.11, all 13 event sites | Every `record_*` gives one sequenced record. A sampled-out host span still gives the record. No content key reaches the record. Host spans have no `fabric.source.*`. No `str()` or `repr()` of application objects. Passivity: `record_*` overhead ≤ 30 µs median. | Suites green |
| **WP-16 Explicit producers** | `call_recorder.py`, `adapters/synthetic_evidence.py`, `adapters/byte_boundary.py`, `http_dispatch.py`, `byte_evidence.py` (config-conflict check only) | 11a | §3.10 three-way mode | Records mode: one record per journal event; ids per §3.10; bodies protected; the 16 MiB + 1 outcome as a descriptor-only body; `not_exact_bytes` as a descriptor-only body. Journal mode unchanged. Legacy mode warning. | `test_wire_explicit_coexistence.py` green in records mode |
| **WP-31 Segment graph and run states** | `reconstruct/_graph.py` | 30 | G1–G10, the run-identity merge rules (`id_basis`), deadline and clocks, `run_aliases`, run states | One test per G rule using the 7 `projection-run-*` fixtures as expected outputs, plus synthetic graphs: cycle, two roots, replayed `br-`, post-terminal, skew, token-conflict fan-in, caller-join fan-in, lost middle. | All G-rule tests green |
| **WP-32 Projection core** (**sequential after WP-31 and WP-33** within the wave) | `reconstruct/_project.py`, `reconstruct/_evidence.py` | 30, **31**, **33** | §3.13 document, steps, aliases, parents, field wrappers, bounded `event_ids`, evidence decoding, manifest-driven statuses, R1–R6 and RR1–RR7 | C1-3 schema validation of every produced projection. C1-5: one fixture per verdict row. The `projection-*` valid fixtures reproduced from synthetic inputs. `projection-many-records`. | T1 |

### Wave 3 (P1 gate; sequential)

| WP | Owner area | Depends | Deliverables | Exit check |
|---|---|---|---|---|
| **WP-50 P1 integration and LR-1** | `qualification/run-structure/**` (new), `sdk/python/tests/test_p1_*.py`, `docs/reconstruct.md`, `docs/` run-structure page (including the records-only install), CHANGELOG | all of waves 0–2 | §6.2 harness; full LR-1; shared-allocator exit cases; T2; T3 end-to-end (Python → Node image → verifier); privacy canary sweep | Every P1 gate in §1.4 |

### Wave 4 (P1-A; 4 agents in parallel, then WP-45)

| WP | Owner area | Depends | Deliverables | Exit check |
|---|---|---|---|---|
| **WP-40 Sticky withholding and D2 projection** | `_capture_scope.py`, `wire/_transport.py` (adopt), `wire/_pipeline.py` (`withheld` branch), `reconstruct/_project.py` (D2 rules) | 50 | §3.15 items 1 and 2 | P1-A exit rows on withholding |
| **WP-41 Parity and qualified regression** | `sdk/python/tests/parity/**`, `tests/test_qualified_run_regression.py` | 50 | §3.15 items 3 and 4 | T5, T6 |
| **WP-42 Governed store backend** | `governed_store.py`, `wire/_pipeline.py` store-protocol adapter (only `_store_object`) | 50; **after WP-40** for `_pipeline.py` | §3.15 item 5 | Local-profile e2e writes through one writer |
| **WP-43 Passivity harness and qualification matrix** | `sdk/python/tests/passivity/**`; registry `qualified_versions` (one contract field, after WP-00's last merge); `qualification/agent-matrix/**` additions (R16: merged to main before this WP) | 50 | §3.15 items 6 and 7 | C1A-3; matrix rows filled |
| **WP-45 P1-A exit report** (sequential) | `docs/`, the retirement list | 40–43 | §3.15 item 8; fault-injection and fork/restart runs | P1-A exit |

**Dependency list (R13).**

| WP | Depends on | Notes |
|---|---|---|
| 10, 11a, 11b, 13, 30 | 00, 01 | — |
| 20 | 00 | — |
| 33 | 00, 01 | — |
| 21 | — | Uses the generated evidence-type list from 00 when merged |
| 12 | 10, 11a, 11b | — |
| 14, 16 | 11a | — |
| 15 | 11a, **H0** | H0: hotfix `fix/decision-line-privacy` merged to main first (pre-requisites above) |
| 31 | 30 | — |
| 32 | 30, 31, 33 | **Intra-wave:** starts after WP-31 merges |
| 50 | every WP of waves 0–2 | — |
| 40, 41, 43 | 50 | — |
| 42 | 50, 40 | — |
| 45 | 40, 41, 42, 43 | — |

**Agent count per wave:**

| Wave | Agents |
|---|---|
| 0 | 3 (WP-00, WP-01, WP-21) |
| 1 | 6 (WP-10, 11a, 11b, 13, 20, 30), plus WP-33 if a slot is free |
| 2 | 6 (WP-12, 14, 15, 16, 31, then 32) |
| 3 | 1 |
| 4 | 4, then 1 |

**File ownership (in order).**
- `wire/_pipeline.py`: WP-01 (stubs) → WP-11a → WP-40 → WP-42.
- `_loss.py`: WP-01 (stubs) → WP-11b.
- `wire/_sender.py`: WP-11b, except WP-21's `status()` lines.
- `wire/__init__.py`: WP-01 → WP-12.
- `_sequence.py`: WP-01 → WP-10.
- `reconstruct/_project.py`: WP-32 → WP-40.
- Contracts: WP-00 → WP-43 (one field) → 051 WP2-0 (serial chain). 055
  WP-01's TS-only rows (055 §8) take the next free slot after WP-00 and
  never block WP-43 or 051 WP2-0; its shared rows stay last in the chain,
  after 054 WP5-01.
- `decision.py` in P1: WP-15 only, after H0 merges. P2's integration owner (051 WP2-1) starts
  after WP-50.

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
- `open`, `terminated`, lost middle (token-only hops, T7), never-arriving C,
  no propagation, fan-in with conflicting tokens (`segment_conflict`) and with
  a caller run id (`caller_join`);
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

### 6.3 Agent matrix and chaos (`qualification/agent-matrix`, `qualification/chaos`)

Both harnesses are merged to main from `test/agent-matrix` and `test/chaos`
before WP-43 and WP-50 start (R16).

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

P2 and P3 (specs 051 and 052) build on these (§3.4, §3.4a, §3.6):
- the `update` phase and the three status inputs;
- `mode_of`, `v2`, `str` bodies and `DescriptorOnlyBody`;
- `MAX_RECORD_BODIES = 8`;
- the evidence carrier;
- `set_run_outcome`.

053's assumptions are now covered:
- **Assumption 9** (field data with no telemetry key) is the §3.4a evidence
  carrier. 053 and 054 register evidence types (WP4-01 and WP5-01), never a
  new carrier.
- **W-class records** (053/054 `capture.input=wire` on a record) are rejected
  (R7, OD-9). Hooks use `begin(provenance="observed")`.
- **Assumption 7** (spawn epoch registration as a P1 gate). It is provided
  (§3.2) and covered by T2.

---

## 8. Risks and open owner decisions

**Status key.** **RPOC** means "Recommended — pending owner confirmation".
Build agents follow these defaults unless the owner changes them.

| # | Risk | Mitigation |
|---|---|---|
| K1 | Seal drift: a fabricguard change (a new strip rule, a renamed category) silently breaks every seal | The generated tables plus the T3 parity vectors run in both repos' CI. A fabricguard change that alters an export fails T3. |
| K2 | Reusing a run id sequentially in one process after a non-resumable block exits is `post_terminal_activity` (049 X42) | Keep 049 semantics. Document "one run id, one run; use `session_id` across requests". Status counter `post_terminal_allocations`. |
| K3 | `global` tracer mode cannot reuse host span ids, so `records.span_id` aliases for decision and tool spans are unresolved and a wire exchange's parent falls back to the run-scope step | State it in the manifest (`uncaptured_classes: ["global_tracer_parent_join"]`); recommend spool or `private` mode. |
| K4 | Drain order across epochs follows random epoch values (file names start with the epoch, `wire/_spool.py:3-4`) | Accept. The verifier is order-free. The 048 name format is unchanged. |
| K5 | Seal accumulator memory on very long segments | Forced seal at 65,536 positions (§3.7). |
| K6 | Records-mode `CallRecorder.snapshot()` reports `pending` where legacy reported final statuses | Documented; parity tests compare after `flush()`. |
| K7 | Under `FABRIC_WIRE_LABELS=clear`, a resume token carries the operator's clear source label across the boundary (049:1100) | Stated in the OD-7 docs. The pseudonymous default emits `s-`. |
| K7a | In clear mode (explicit opt-in, R8), a caller-rooted run's tokens carry the application's clear run id across the boundary (rule 4 emits the clear id) | Stated in the OD-7 docs. The pseudonymous default carries the mapped `r-` id. |
| K8 | A token-only hop without a token, or a lost token, yields a separate run | Stated limit; branch tokens and the open-run deadline still detect the declared cases. |

| # | Decision | Default | Status |
|---|---|---|---|
| OD-1 | Content validation before acknowledgement (flips decision 24; R10) | Build in P1 (WP-21). The stateless checks, including the evidence envelope, run before the 200. The store-conflict check stays post-queue. A 200 is acceptance, never durability. No `destination_rejected` loss (delta 6). | RPOC (both reviews approve) |
| OD-2 | `CallRecorder` default when no wire handle is installed | `legacy` with a `DeprecationWarning`. The wire tee is never auto-installed from a recorder. The records-only install is documented. | RPOC |
| OD-3 | Default declared clock uncertainty | 1 s (`FABRIC_CLOCK_UNCERTAINTY_MS=1000`), documented as a configurable declared assumption, not a measurement. | RPOC |
| OD-4 | Decision span step kind | `agent_turn` (a new kind); its required fields are P2's. | RPOC |
| OD-5 | Decision content on the unified spool | P2, not P1. P1 claims no privacy parity for legacy decision payload hashes. | RPOC |
| OD-6 | Orphan-registration retention | Until declared and delivered, or `open_run_deadline_s`, whichever is later; at most 4096 files. `status()["registration"]` reports `registered`, `failed`, `registration_full` or `unregistered_*` explicitly. | RPOC |
| OD-7 | What carries a run across processes (privacy; R1) | **Only Fabric-emitted resume tokens cross service or host boundaries** (`baggage` `fabric.resume`, message attribute `fabric.resume`). Tokens carry the **run correlation id**: the root's run id, minted (`r-` + 32 CSPRNG hex) when the caller gave none, else the mapped clear id. A → B → C keeps one run id even if B is lost entirely, and key rotation does not change it. Fan-in with differing correlation ids is `segment_conflict` unless the caller supplies a clear run id (`caller_join`). Clear run ids are passed only in process and through same-host `FABRIC_RUN_ID`. In clear mode (an explicit opt-in, R8) a caller-rooted run's correlation id is its clear id, so the token in `baggage` carries the clear id across the boundary; the OD-7 docs say so. 051, 052 and 055 (TS-OD-8) follow this rule. The earlier token-derived hash design is withdrawn. | RPOC |
| OD-8 | Marker and inferred-step event ids (R2) | Markers: a uuid4 minted once and persisted in the spool and ledger record. Inferred-step attempt ids: see §3.13 (the one reviewed exception). | RPOC |
| OD-9 | Structured evidence carrier (R7) | §3.4a: one evidence object per record, role `record.evidence` with `default_policy: metadata`, registered closed types. No W-class records; hooks use `records` with `fabric.capture.source=observed`. | RPOC |
| OD-10 | Identity rule (R8) | Pseudonymous by default and always mapped. `clear` is an explicit opt-in that emits ids as given, recorded in the manifest, in every language. | RPOC |
| OD-11 | Fail-open APIs (R9) | Every recorder API fails open; `FABRIC_RECORDS_STRICT=1` raises (tests). The existing `run_id` pattern check also fails open (the block runs uncaptured, or the id is mapped). | RPOC |
| OD-12 | Bodies bound (R6) | 260 per exchange and 8 per record, checked by the writer. | RPOC |
| OD-13 | C40 provider request id (R15) | Built in P1 (WP-14), opt-in, `p-` keyed, only the named header value. | RPOC |

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

12. **Run identity across service boundaries (R1, OD-7, RPOC).** §2.10.

    In the resume-contract table, row "Run id", column "Across services and
    machines" (line 1207 of rev 6.4), replace "W3C `baggage` entry
    `fabric.run=<run id>`, or the message attribute `fabric.run`" with:

    > not propagated; only resume tokens cross service or host boundaries

    Replace the token format `fr2/<segment_id>/…` with:

    > `fr3/<run correlation id>/<segment_id>/<source_id>/<epoch>/<last_sequence>/sha256:<hex>[/br-<hex>]`

    Add to "Key rotation":

    > Every resume token carries the run's correlation id — the root segment's
    > run id: the mapped clear id when the caller gave one, else a minted
    > `r-` + 32 CSPRNG hex, an emitted value never derived from caller input.
    > A segment opened from tokens takes that id verbatim (`id_basis: token`),
    > so a chain keeps one run id across key rotations and lost middle
    > segments. Tokens with differing correlation ids form one run only when
    > the consumer supplies a clear run id (`caller_join`, merged as
    > `run_aliases`); otherwise the join is `segment_conflict`. A clear run id
    > is passed only in process and through same-host `FABRIC_RUN_ID`.

    `end_run(run_id: str | None, …)` takes the run id from the tokens when it
    is `None`.

13. **New step kind `agent_turn`.** §2.3 step-kind vocabulary: add
    `agent_turn` ("One agent turn reported by `decision()`"), in the
    `step_kind` registry vocabulary and the generated block (049 currently
    names no kind for a `decision()` span).

14. **No third input class for hooks (R7).** §1.3, line 118 ("Opt-in hooks
    (P4/P5) also emit through the records input, with provenance
    `observed`"). Keep it, and add:

    > They set `fabric.capture.source=observed` (X27) and use content
    > provenance `protocol` for exact bytes; `fabric.capture.input` stays
    > `records`. Structured evidence without a telemetry key travels in the
    > record's single `record.evidence` object (050 §3.4a).

15. **Metadata-class content role.** §2.7 precedence. Add rule 0:

    > A role whose default policy is `metadata` (`record.evidence`) carries no
    > CONTENT-class value; it is stored whenever a content destination exists,
    > including when content capture is disabled (rule 1), unless the capture
    > policy maps it to `metadata_only` or `omit`; `redact`, `tokenize`,
    > `masked_only` and `original_plus_masked` are refused for it at policy
    > validation.

16. **Persisted uuid4 marker ids (R2).** §2.4 "Event identity", rule 2. Add:

    > For markers (run markers, seals, heartbeats, manifests) the uuid4 is
    > persisted in the spool and ledger record and read back on replay.

    In the §2.3 table row "Inferred step", replace "deterministic: uuid5 of the
    evidence locator" with:

    > deterministic: a uuid4-format id from SHA-256 of the evidence locator
    > with the version and variant bits set

17. **Segment-attributed losses (R3).** §2.12 rule 1. Replace "A loss record
    contributes only its positions" with:

    > A loss record carries the `segment_id` of its positions (losses of
    > different segments never coalesce) and contributes only its positions to
    > that segment's seal

18. **Three status inputs (R4).** §2.3 "Lifecycle and outcome". Add:

    > Emitters set lifecycle state, result status and the OTLP span status as
    > three independent inputs; none is derived from another; the run outcome
    > (D30) is set only at run level and carried by the outermost `run_end`.

19. **Bodies bound (R6).** §7.4, after the extraction rules. Add:

    > One exchange record holds at most 260 stored objects: two sides × (one
    > primary, 64 parts, 64 per-part review copies, one side review copy). The
    > writer refuses a record over the bound as an `internal_error` loss.

20. **C35, C40 and N51 (R15).**
    - **C35** "Lives in" → `T fabric.wire.endpoint_id` (built-in
      `<provider>.default` or keyed `lbl-`); the manifest keeps the
      endpoint-set digest.
    - **C40** "Lives in" → `T fabric.wire.provider_request_id`, P1 (WP-14),
      opt-in.
    - **N51**: unchanged, owned by 050 WP-33.
    - X27 gets its registry row.

21. **Resumable-runs architecture row (R15, honest).** §8.3 row
    "Resumable / long-running (additional)", column "2 Structure". Append:

    > Limit: a hop that carries no token, or tokens of different runs without a
    > caller run id, is a separate or conflicting run; under
    > `FABRIC_WIRE_LABELS=clear` tokens carry a clear source label.

22. **Identity rule (R8).** §2.9 rule 7. Add:

    > This is the only exception to rule 9: in `clear` mode ids are emitted as
    > given in every language; in the default `pseudonymous` mode every caller
    > id is mapped whatever its shape.
