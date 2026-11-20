// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The JavaScript shared runtime of wire capture (spec 055 §4.5): the control block, the
 * source-position allocator and the bounded try-lock.
 *
 * The installing thread creates the shared memory once, before application code runs,
 * and publishes it with `worker_threads.setEnvironmentData`, so every Worker created
 * afterwards receives the same buffers (shared, not copied). Each isolate then wraps
 * them in its own {@link WireRuntime}.
 *
 * Passivity rules this file keeps:
 * - a position is one `Atomics.add`; it is never refused and never waits;
 * - an application isolate never calls `Atomics.wait`. The try-lock spins for at most
 *   20 µs; on timeout the position is still allocated and is reported as an
 *   `internal_error` loss in the run's last-read segment, so the run is partial, never
 *   complete. Only the Fabric worker waits, with `Atomics.waitAsync`;
 * - nothing here throws into a caller, logs, reads a file or touches the network.
 */
import { randomBytes, randomFillSync } from "node:crypto";
import { getEnvironmentData, setEnvironmentData } from "node:worker_threads";

import { MAX_VECTOR_SLOTS, SLAB_BYTES, createPayload, createPool } from "./arena.js";
import type { PayloadShared, PoolShared } from "./arena.js";
import { Ring, createRing, type RingShared } from "./queue.js";

/** The `setEnvironmentData` key (spec 055 §4.5) and the per-isolate global slot (§4.1). */
export const RUNTIME_KEY = "fabric.wire.runtime/1";

export const CONTROL_BYTES = 32 * 1024;
export const MAX_RUNS = 256;
export const MAX_ISOLATES = 1024;
/** Exchange slots: 2 KiB each, at most 65,536 active (spec 055 §4.5 item 4). */
export const EXCHANGE_SLOT_BYTES = 2048;
export const MAX_EXCHANGE_SLOTS = 65536;
/** Completed-job records are 2 KiB; loss records are 32 bytes. */
export const JOB_RECORD_BYTES = 2048;
export const LOSS_RECORD_BYTES = 32;
export const LOSS_RING_ENTRIES = 4096;
/** At most this many mirror stores per allocation (see `WireRuntime.next`). */
const MIRROR_ROUNDS = 8;
/** The longest an application isolate spins for the control-block lock. */
export const LOCK_SPIN_MS = 0.02;

const MAGIC = 0x4657_5254_0000_0001n; // "FWRT", layout 1

// BigInt64 words of the control block (bytes 0..255).
const C_MAGIC = 0;
const C_EPOCH = 1;
const C_NEXT = 2;
const C_NONCE = 3; // two words
const C_MIRROR = 5; // the registration mirror's map handle, or -1
// Word 6 is unused: fd handles are never published to application isolates (§4.4).
const C_LOSSES = 8; // one counter per LossReason code
const C_UNATTRIBUTED = 16;
const C_LOCK_TIMEOUTS = 17;
const C_REFUSED = 18;
const C_UNPROCESSED = 19;
// Int32 words (bytes 256..511).
const W_STATE = 64;
const W_LOCK = 65;
const W_WORKER_GENERATION = 66;
const W_WORKER_RESTARTS = 67;
const W_STOP = 68;
const W_FAILURE = 69;
// Run table: 4 BigInt64 words per run (segment hi, segment lo, positions, reserved).
const RUN_BASE = 64;
// Isolate table: 4 Int32 words per isolate (state, environment id, role, reserved).
const ISOLATE_BASE = (512 + MAX_RUNS * 32) / 4;

export const STATE_RUNNING = 1;
export const STATE_CLOSING = 2;
export const STATE_CLOSED = 3;
/** The Fabric worker could not be kept running: capture is off, with a reason. */
export const STATE_FAILED = 4;

/**
 * Why the runtime is {@link STATE_FAILED}, for the status document (spec 055 §4.7):
 * the Fabric worker could not be constructed, or it died five times in a row, each
 * within a second of its start.
 */
export const FAILURE_REASONS = ["worker_start_failed", "worker_crash_loop"] as const;
export type RuntimeFailureReason = (typeof FAILURE_REASONS)[number];

/** Reasons an allocated position is lost in the shared runtime (Python `LossReason`). */
/** Loss reasons the runtime carries; `disk_full` comes from the Fabric worker's spool admission. */
export const LOSS_REASONS = ["queue_full", "internal_error", "shutdown", "disk_full"] as const;
export type RuntimeLossReason = (typeof LOSS_REASONS)[number];

export type IsolateRole = "installer" | "worker" | "application";
/** Isolate table rows of the two isolates this unit knows. Application isolates follow. */
const ROLE_SLOT: Readonly<Record<IsolateRole, number>> = {
  installer: 0,
  worker: 1,
  application: 2,
};

/** Everything another isolate needs: shared buffers and plain numbers. Cloneable. */
export interface RuntimeShared {
  readonly control: SharedArrayBuffer;
  readonly payload: PayloadShared;
  readonly exchanges: PoolShared;
  readonly jobs: RingShared;
  readonly losses: RingShared;
  /** Per-side retained byte cap (`max_retain_bytes`). */
  readonly maxRetainBytes: number;
}

export interface RuntimeOptions {
  /** The epoch to start in. Default: a fresh CSPRNG epoch ({@link newEpoch}). */
  readonly epoch?: bigint;
  /** The first position to allocate. */
  readonly firstSequence?: bigint;
  /** Global retained-byte budget (`max_inflight_bytes`); the payload arena's maximum. */
  readonly maxInflightBytes?: number | bigint;
  readonly maxRetainBytes?: number;
  /** Completed jobs the ring holds (`queue_max_items`). */
  readonly queueMaxItems?: number;
  /** Active exchanges; at most 65,536. */
  readonly maxExchanges?: number;
  /** Payload bytes committed before the Fabric worker starts growing the arena. */
  readonly initialPayloadBytes?: number;
  /** Chunk-vector slots; at most 65,536. Lowered only by tests. */
  readonly maxVectors?: number;
  /** Loss-ring entries. Lowered only by tests. */
  readonly lossRingEntries?: number;
}

const MIB = 1024 * 1024;
const EPOCH_MASK = (1n << 63n) - 1n;

/**
 * A fresh epoch (spec 050 §3.2 rule 1): 63 bits from the CSPRNG, redrawn while 0. Two
 * processes sharing a spool are told apart by registration, never by the clock or pid.
 */
export function newEpoch(): bigint {
  for (;;) {
    const epoch = randomBytes(8).readBigUInt64BE(0) & EPOCH_MASK;
    if (epoch !== 0n) return epoch;
  }
}

/** Creates the shared memory. Installing thread only, once per process. */
export function createRuntimeShared(options: RuntimeOptions = {}): RuntimeShared {
  const maxInflight = Number(options.maxInflightBytes ?? 256 * MIB);
  const maxExchanges = Math.min(MAX_EXCHANGE_SLOTS, Math.max(1, options.maxExchanges ?? 65536));
  const queue = Math.min(65536, Math.max(1, options.queueMaxItems ?? 16384));
  const maxRetainBytes = Math.min(0x7fff_ffff, Math.max(0, options.maxRetainBytes ?? 64 * MIB));
  // One whole side stays committed ahead of use, so a chunk within the side cap and the
  // global budget is never refused because the Fabric worker had not grown the arena yet.
  const payload = createPayload(
    maxInflight,
    options.initialPayloadBytes ?? 4 * MIB,
    maxRetainBytes,
  );
  const maxVectors = Math.min(MAX_VECTOR_SLOTS, options.maxVectors ?? MAX_VECTOR_SLOTS);
  const shared: RuntimeShared = {
    control: new SharedArrayBuffer(CONTROL_BYTES),
    payload:
      maxVectors === MAX_VECTOR_SLOTS
        ? payload
        : {
            slabs: payload.slabs,
            vectors: createPool({ slotBytes: 64, maxSlots: maxVectors, initialSlots: maxVectors }),
          },
    exchanges: createPool({
      slotBytes: EXCHANGE_SLOT_BYTES,
      maxSlots: maxExchanges,
      initialSlots: 256,
      lowWater: 128,
      growStep: 256,
    }),
    jobs: createRing(JOB_RECORD_BYTES, queue),
    losses: createRing(LOSS_RECORD_BYTES, options.lossRingEntries ?? LOSS_RING_ENTRIES),
    maxRetainBytes,
  };
  const i64 = new BigInt64Array(shared.control);
  i64[C_MAGIC] = MAGIC;
  i64[C_EPOCH] = options.epoch ?? newEpoch();
  i64[C_NEXT] = options.firstSequence ?? 0n;
  i64[C_MIRROR] = -1n;
  randomFillSync(new Uint8Array(shared.control, C_NONCE * 8, 16));
  Atomics.store(new Int32Array(shared.control), W_STATE, STATE_RUNNING);
  return shared;
}

/** Publishes the runtime to every Worker created from now on, nested ones included. */
export function publishRuntime(shared: RuntimeShared): void {
  setEnvironmentData(RUNTIME_KEY, shared as unknown as Parameters<typeof setEnvironmentData>[1]);
}

/** The runtime this isolate inherited at construction, or `undefined`. */
export function inheritedRuntime(): RuntimeShared | undefined {
  const value = getEnvironmentData(RUNTIME_KEY) as unknown;
  if (value === null || typeof value !== "object") return undefined;
  const control = (value as RuntimeShared).control;
  if (!(control instanceof SharedArrayBuffer) || control.byteLength !== CONTROL_BYTES) {
    return undefined;
  }
  return new BigInt64Array(control)[C_MAGIC] === MAGIC ? (value as RuntimeShared) : undefined;
}

/** A lost position as the Fabric worker reads it from the loss ring. */
export interface RuntimeLoss {
  readonly reason: RuntimeLossReason;
  readonly sequence: bigint;
  readonly segmentHi: bigint;
  readonly segmentLo: bigint;
}

/** A position and what was decided with it. */
export interface Allocation {
  readonly sequence: bigint;
  /** The run's open segment (two 64-bit halves); both zero outside a run. */
  readonly segmentHi: bigint;
  readonly segmentLo: bigint;
  /** True when the lock timed out: the position is already an `internal_error` loss. */
  readonly lost: boolean;
}

/** Content-free counters (spec 055 §4.7 reads these for the status document). */
export interface RuntimeStats {
  readonly state: number;
  /** Set when {@link state} is {@link STATE_FAILED}. */
  readonly failureReason: RuntimeFailureReason | undefined;
  readonly nextSequence: bigint;
  readonly losses: Readonly<Record<RuntimeLossReason, bigint>>;
  /** Losses that did not fit the loss ring: their positions are gaps without a reason. */
  readonly lossesUnattributed: bigint;
  readonly lockTimeouts: bigint;
  /** Exchanges not captured because the runtime was not running. */
  readonly refused: bigint;
  /** Jobs the Fabric worker removed without a pipeline to handle them. */
  readonly jobsUnprocessed: bigint;
  readonly workerGeneration: number;
  readonly workerRestarts: number;
  readonly queuedJobs: number;
}

export class WireRuntime {
  readonly i64: BigInt64Array;
  readonly i32: Int32Array;
  readonly jobs: Ring;
  readonly lossRing: Ring;
  private readonly owner: number;
  private readonly lossScratch = new BigInt64Array(3);
  private readonly lossBytes = new Uint8Array(this.lossScratch.buffer);
  /**
   * The registration mirror (spec 050 §3.2): called with the next sequence after every
   * allocation. `registration.ts` binds it to the native `store64` (a memory store, no
   * system call); see {@link next} for how concurrent isolates keep it current.
   */
  mirror: ((next: bigint) => void) | undefined;

  constructor(
    readonly shared: RuntimeShared,
    readonly role: IsolateRole,
  ) {
    this.i64 = new BigInt64Array(shared.control);
    this.i32 = new Int32Array(shared.control);
    this.jobs = new Ring(shared.jobs);
    this.lossRing = new Ring(shared.losses);
    this.owner = ROLE_SLOT[role] + 1;
    const row = ISOLATE_BASE + ROLE_SLOT[role] * 4;
    Atomics.store(this.i32, row + 2, this.owner);
    Atomics.store(this.i32, row, 1);
  }

  get state(): number {
    return Atomics.load(this.i32, W_STATE);
  }
  get running(): boolean {
    return Atomics.load(this.i32, W_STATE) === STATE_RUNNING;
  }
  setState(state: number): void {
    Atomics.store(this.i32, W_STATE, state);
    this.jobs.wake();
  }
  /** Stops capture with a named reason: hooks return at once from now on. */
  fail(reason: RuntimeFailureReason): void {
    Atomics.store(this.i32, W_FAILURE, FAILURE_REASONS.indexOf(reason) + 1);
    this.setState(STATE_FAILED);
  }
  get epoch(): bigint {
    return Atomics.load(this.i64, C_EPOCH);
  }
  /** The next position the allocator hands out (the count allocated so far in the epoch). */
  get nextSequence(): bigint {
    return Atomics.load(this.i64, C_NEXT);
  }

  /**
   * An exact allocator boundary for a state change (spec 050 §3.8, 055 §7.2): runs
   * `change` (which makes the new state visible, for example a shared state word), then
   * reads the counter with a read-modify-write, a full fence. Returns the last position
   * allocated before the read (-1 when none): every position above it was allocated after
   * the change took effect, so a manifest effective after it never covers a position
   * allocated under the old state's promise. Allocation is one `Atomics.add`, so the read
   * is ordered with every isolate's allocations; nothing waits.
   */
  cut(change?: () => void): bigint {
    change?.();
    return Atomics.add(this.i64, C_NEXT, 0n) - 1n;
  }

  // ------------------------------------------------------------------- registration

  /**
   * Adopts a registered epoch (spec 050 §3.2 rule 2): the epoch and the mirror's map
   * handle go into the control block, where an attaching application isolate reads the
   * handle to mirror. The file's descriptor handle never does: spec 055 §4.4 publishes
   * only the mirror's map handle to application isolates. A redrawn epoch replaces
   * `drawnFrom` only while nothing was allocated in it; otherwise nothing changes and the
   * result is `false`. Called at install, before any hook exists, so no allocation can
   * race it.
   */
  adoptRegistration(drawnFrom: bigint, epoch: bigint, mirror: number): boolean {
    const i64 = this.i64;
    const current = Atomics.load(i64, C_EPOCH);
    if (current !== drawnFrom || (epoch !== current && Atomics.load(i64, C_NEXT) !== 0n)) {
      return false;
    }
    Atomics.store(i64, C_EPOCH, epoch);
    Atomics.store(i64, C_MIRROR, BigInt(mirror));
    return true;
  }
  /** Forgets the registration's mirror (orderly close). Mirrors elsewhere become no-ops. */
  releaseRegistration(): void {
    Atomics.store(this.i64, C_MIRROR, -1n);
    this.mirror = undefined;
  }
  /**
   * The mirror's map handle, or -1 when the epoch is not registered: while it is set,
   * this process holds the registration of {@link epoch}.
   */
  get mirrorHandle(): number {
    return Number(Atomics.load(this.i64, C_MIRROR));
  }
  /** The 16 random bytes that name this runtime instance. */
  get nonce(): Uint8Array {
    return new Uint8Array(this.shared.control.slice(C_NONCE * 8, C_NONCE * 8 + 16));
  }

  // ------------------------------------------------------------------------- the lock

  /**
   * Takes the control-block lock without ever blocking: one compare-exchange, then a
   * spin of at most 20 µs. Returns `false` on timeout.
   */
  tryLock(spinMs: number = LOCK_SPIN_MS): boolean {
    const words = this.i32;
    if (Atomics.compareExchange(words, W_LOCK, 0, this.owner) === 0) return true;
    const deadline = performance.now() + spinMs;
    do {
      if (Atomics.compareExchange(words, W_LOCK, 0, this.owner) === 0) return true;
    } while (performance.now() < deadline);
    return false;
  }

  unlock(): void {
    if (Atomics.compareExchange(this.i32, W_LOCK, this.owner, 0) === this.owner) {
      Atomics.notify(this.i32, W_LOCK, 1);
    }
  }

  /**
   * Waits for the lock with `Atomics.waitAsync`. Fabric worker only: an application
   * isolate uses {@link tryLock}. Resolves `false` after `timeoutMs`.
   */
  async lockAsync(timeoutMs = 1000): Promise<boolean> {
    const words = this.i32;
    const deadline = performance.now() + timeoutMs;
    for (;;) {
      const holder = Atomics.compareExchange(words, W_LOCK, 0, this.owner);
      if (holder === 0) return true;
      const left = deadline - performance.now();
      if (left <= 0) return false;
      const waited = waitAsync(words, W_LOCK, holder, left);
      if (waited.async) await waited.value;
    }
  }

  /** Releases a lock left by a dead Fabric worker. Called before its replacement starts. */
  breakWorkerLock(): void {
    Atomics.compareExchange(this.i32, W_LOCK, ROLE_SLOT.worker + 1, 0);
  }

  // -------------------------------------------------------------------- the allocator

  /**
   * Allocates the next source position. With `runSlot`, the run's open segment is read
   * and its position count advanced under the lock, so membership is decided with the
   * allocation. Never refuses: when the lock is not free within 20 µs the position is
   * allocated anyway and recorded as an `internal_error` loss in the last-read segment.
   */
  allocate(runSlot = -1): Allocation {
    const i64 = this.i64;
    if (runSlot < 0 || runSlot >= MAX_RUNS) {
      return { sequence: this.next(), segmentHi: 0n, segmentLo: 0n, lost: false };
    }
    const run = RUN_BASE + runSlot * 4;
    if (!this.tryLock()) {
      const sequence = this.next();
      const segmentHi = Atomics.load(i64, run);
      const segmentLo = Atomics.load(i64, run + 1);
      Atomics.add(i64, C_LOCK_TIMEOUTS, 1n);
      this.lose("internal_error", sequence, segmentHi, segmentLo);
      return { sequence, segmentHi, segmentLo, lost: true };
    }
    const sequence = this.next();
    const segmentHi = Atomics.load(i64, run);
    const segmentLo = Atomics.load(i64, run + 1);
    Atomics.add(i64, run + 2, 1n);
    this.unlock();
    return { sequence, segmentHi, segmentLo, lost: false };
  }

  /**
   * One position, then the mirror. Isolates allocate without a lock, so two stores can
   * land out of order (one isolate stores 7, another that allocated earlier then stores
   * 6). Each isolate therefore re-reads the counter after its store, with a read-modify-
   * write (a full fence after the native release store, on x64 and arm64), and stores
   * again until the counter equals what it stored, at most 8 rounds. Once allocation
   * stops, the mirror equals the counter unless one isolate spent all 8 rounds behind
   * newer allocations and its last store landed after every later one: the mirror is
   * then behind, as Python's is after a SIGKILL between its increment and its store, and
   * the next allocation in any isolate repairs it. No lock, no wait, no system call.
   */
  private next(): bigint {
    const i64 = this.i64;
    const sequence = Atomics.add(i64, C_NEXT, 1n);
    const mirror = this.mirror;
    if (mirror !== undefined) {
      try {
        let value = sequence + 1n;
        for (let round = 0; round < MIRROR_ROUNDS; round++) {
          mirror(value);
          const now = Atomics.add(i64, C_NEXT, 0n);
          if (now === value) break;
          value = now;
        }
      } catch {
        // A mirror failure is never the agent's problem; the orphan scan covers it.
      }
    }
    return sequence;
  }

  /**
   * Opens, moves or closes a run's segment (both halves zero closes it). The caller
   * holds the lock. Unit 055-t11 owns the run table's meaning; the allocator only reads
   * the segment and counts positions.
   */
  setRunSegment(runSlot: number, segmentHi: bigint, segmentLo: bigint): void {
    const run = RUN_BASE + runSlot * 4;
    Atomics.store(this.i64, run, segmentHi);
    Atomics.store(this.i64, run + 1, segmentLo);
    Atomics.store(this.i64, run + 2, 0n);
  }

  /** Positions allocated in the run's open segment. */
  runPositions(runSlot: number): bigint {
    return Atomics.load(this.i64, RUN_BASE + runSlot * 4 + 2);
  }

  // --------------------------------------------------------------------------- losses

  /**
   * Records an allocated position as lost, with its segment (R3). The record goes to
   * the loss ring for the Fabric worker; when that ring is full only the counters move,
   * and the position stays a gap, so its segment cannot seal as complete.
   */
  lose(reason: RuntimeLossReason, sequence: bigint, segmentHi = 0n, segmentLo = 0n): void {
    const code = LOSS_REASONS.indexOf(reason);
    Atomics.add(this.i64, C_LOSSES + code, 1n);
    const scratch = this.lossScratch;
    scratch[0] = sequence;
    scratch[1] = segmentHi;
    scratch[2] = segmentLo;
    if (!this.lossRing.push(code, this.lossBytes)) Atomics.add(this.i64, C_UNATTRIBUTED, 1n);
  }

  /** The oldest loss record, or `undefined`. Fabric worker only; `commitLoss` removes it. */
  peekLoss(): RuntimeLoss | undefined {
    const record = this.lossRing.peek();
    if (record === undefined) return undefined;
    const words = new BigInt64Array(this.shared.losses.buffer, record.byteOffset, 3);
    return {
      reason: LOSS_REASONS[record.kind] ?? "internal_error",
      sequence: words[0]!,
      segmentHi: words[1]!,
      segmentLo: words[2]!,
    };
  }
  commitLoss(): void {
    this.lossRing.commit();
  }

  /** A loss record nobody could handle: its position stays a gap without a reason. */
  countUnattributed(): void {
    Atomics.add(this.i64, C_UNATTRIBUTED, 1n);
  }
  countRefused(): void {
    Atomics.add(this.i64, C_REFUSED, 1n);
  }
  countUnprocessed(): void {
    Atomics.add(this.i64, C_UNPROCESSED, 1n);
  }

  // --------------------------------------------------------------------------- worker

  get workerGeneration(): number {
    return Atomics.load(this.i32, W_WORKER_GENERATION);
  }
  /** A Fabric worker announces itself; returns its generation (1 for the first). */
  workerStarted(): number {
    Atomics.store(this.i32, ISOLATE_BASE + ROLE_SLOT.worker * 4, 1);
    return Atomics.add(this.i32, W_WORKER_GENERATION, 1) + 1;
  }
  countWorkerRestart(): number {
    return Atomics.add(this.i32, W_WORKER_RESTARTS, 1) + 1;
  }
  get stopRequested(): boolean {
    return Atomics.load(this.i32, W_STOP) !== 0;
  }
  requestStop(): void {
    Atomics.store(this.i32, W_STOP, 1);
    this.jobs.wake();
  }

  stats(): RuntimeStats {
    const i64 = this.i64;
    return {
      state: this.state,
      failureReason: FAILURE_REASONS[Atomics.load(this.i32, W_FAILURE) - 1],
      nextSequence: Atomics.load(i64, C_NEXT),
      losses: {
        queue_full: Atomics.load(i64, C_LOSSES),
        internal_error: Atomics.load(i64, C_LOSSES + 1),
        shutdown: Atomics.load(i64, C_LOSSES + 2),
        disk_full: Atomics.load(i64, C_LOSSES + 3),
      },
      lossesUnattributed: Atomics.load(i64, C_UNATTRIBUTED),
      lockTimeouts: Atomics.load(i64, C_LOCK_TIMEOUTS),
      refused: Atomics.load(i64, C_REFUSED),
      jobsUnprocessed: Atomics.load(i64, C_UNPROCESSED),
      workerGeneration: this.workerGeneration,
      workerRestarts: Atomics.load(this.i32, W_WORKER_RESTARTS),
      queuedJobs: this.jobs.count,
    };
  }
}

/** `Atomics.waitAsync` (ES2024; Node 16+), which the ES2022 library types do not declare. */
export function waitAsync(
  words: Int32Array,
  index: number,
  value: number,
  timeoutMs: number,
): { async: boolean; value: Promise<string> | string } {
  return (
    Atomics as unknown as {
      waitAsync(
        words: Int32Array,
        index: number,
        value: number,
        timeout: number,
      ): { async: boolean; value: Promise<string> | string };
    }
  ).waitAsync(words, index, value, timeoutMs);
}

/** Bytes the metadata arenas reach at the maximum configured counts (spec 055 §4.5). */
export function metadataBytesAtMaximum(queueMaxItems = 65536): number {
  return (
    MAX_EXCHANGE_SLOTS * EXCHANGE_SLOT_BYTES +
    MAX_VECTOR_SLOTS * 64 +
    queueMaxItems * JOB_RECORD_BYTES
  );
}

export { SLAB_BYTES };
