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
import { RING_VOID, Ring, createRing, type RingShared } from "./queue.js";

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
/**
 * Run-structure messages (run markers and seal requests, `segments.ts`) travel to the
 * Fabric worker in their own ring of 4 KiB records; a longer message is split into parts
 * (`segments.ts` `RunMessages`). 512 records: 2 MiB of address space.
 */
export const RUN_RECORD_BYTES = 4096;
export const RUN_RING_ENTRIES = 512;
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
// Application isolates (spec 055 §4.5, unit 055-t19): counters, content-free.
const C_ISOLATES_ATTACHED = 20;
const C_ISOLATES_UNATTACHED = 21;
const C_ISOLATES_DETACHED = 22;
const C_DETACHED_SHUTDOWN = 23; // positions settled as `shutdown` for a torn-down isolate
const C_DETACHED_OVERFLOW = 24; // `takeDetachedEnvs` returned OVERFLOW
const C_SLOTS_ABANDONED = 25; // a torn-down isolate died inside finish (position a gap)
const C_LOCKS_BROKEN = 26;
const C_RING_VOIDED = 27; // ring cells a torn-down isolate claimed and never published
// Int32 words (bytes 256..511).
const W_STATE = 64;
const W_LOCK = 65;
const W_WORKER_GENERATION = 66;
const W_WORKER_RESTARTS = 67;
const W_STOP = 68;
const W_FAILURE = 69;
// Run table: 4 BigInt64 words per run (segment hi, segment lo, positions, flags).
const RUN_BASE = 64;
/** Run-slot flag: the run is resumable (a forced seal written by the worker says so). */
export const RUN_FLAG_RESUMABLE = 1n;
// Isolate table: 4 Int32 words per isolate (state, environment id, role, thread id). Row 0
// is the installing thread, row 1 the Fabric worker, rows 2.. attached application isolates.
const ISOLATE_BASE = (512 + MAX_RUNS * 32) / 4;
// The manifest in force (bytes 25088..25159), written by the Fabric worker only, under a
// version word (odd while it writes): version (Int32), epoch, manifest_seq (BigInt64),
// manifest id (16 bytes) and digest (32 bytes).
const M_BYTE = ISOLATE_BASE * 4 + MAX_ISOLATES * 16;
const M_VERSION = M_BYTE / 4;
const M_EPOCH = M_BYTE / 8 + 1;
const M_SEQ = M_BYTE / 8 + 2;
const M_ID = M_BYTE + 24;
const M_DIGEST = M_BYTE + 40;
// Run-slot claims (bytes 25600..26623): one Int32 word per run slot, the claiming isolate's
// row + 1, so the run tables of every attached isolate share the 256 slots (unit 055-t19).
const RUN_CLAIM_BASE = 25600 / 4;
// Worker threads created by an attached isolate and not yet seen attached (bytes
// 26624..28671): one Int32 thread id per entry, 0 when free (unit 055-t19).
const PENDING_BASE = 26624 / 4;
export const MAX_PENDING_THREADS = 512;

/** Isolate-table row states. A detached row is free again once settled. */
const ROW_FREE = 0;
const ROW_ATTACHED = 1;
/** The first isolate-table row an application isolate can claim (0: installer, 1: worker). */
export const FIRST_APPLICATION_ROW = 2;

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
export const LOSS_REASONS = [
  "queue_full",
  "internal_error",
  "shutdown",
  "disk_full",
  // A matched call published by an undici copy the table does not qualify (spec 055 §3.1).
  "uninstrumented_client",
] as const;
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
  /** Run markers and seal requests for the Fabric worker (`segments.ts`). */
  readonly runs: RingShared;
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
  /** Run-ring entries. Lowered only by tests. */
  readonly runRingEntries?: number;
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
    runs: createRing(RUN_RECORD_BYTES, options.runRingEntries ?? RUN_RING_ENTRIES),
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

/** The manifest in force as the Fabric worker published it (spec 050 §3.8). */
export interface PublishedManifest {
  readonly epoch: bigint;
  readonly manifestSeq: number;
  /** The manifest's uuid4 (`manifest_id`). */
  readonly manifestId: string;
  /** `sha256:<hex>`. */
  readonly digest: string;
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
  /** Application isolates (spec 055 §4.5, §6.4): content-free counters. */
  readonly isolates: IsolateStats;
}

export interface IsolateStats {
  /** Application isolates that attached (ever). */
  readonly attached: bigint;
  /** Worker threads that did not attach, or could not be followed: declared uncaptured. */
  readonly unattached: bigint;
  /** Attached isolates torn down and settled. */
  readonly detached: bigint;
  /** Positions of torn-down isolates settled as `shutdown` losses. */
  readonly shutdownPositions: bigint;
  /** Times the detached ring overflowed: those positions settle at `close()`. */
  readonly overflows: bigint;
  /** Exchanges a torn-down isolate left inside `finish`: their positions stay gaps. */
  readonly abandoned: bigint;
  /** The control-block lock freed after its holder was torn down. */
  readonly locksBroken: bigint;
  /** Ring cells a torn-down isolate claimed and never filled, skipped. */
  readonly ringVoided: bigint;
}

export class WireRuntime {
  readonly i64: BigInt64Array;
  readonly i32: Int32Array;
  readonly jobs: Ring;
  readonly lossRing: Ring;
  /** Run markers and seal requests (`segments.ts`); a runtime made before it has none. */
  readonly runRing: Ring | undefined;
  private readonly owner: number;
  private readonly lossScratch = new BigInt64Array(3);
  private readonly lossBytes = new Uint8Array(this.lossScratch.buffer);
  /**
   * The registration mirror (spec 050 §3.2): called with the next sequence after every
   * allocation. `registration.ts` binds it to the native `store64` (a memory store, no
   * system call); see {@link next} for how concurrent isolates keep it current.
   */
  mirror: ((next: bigint) => void) | undefined;

  /**
   * `row`: an application isolate's own isolate-table row, claimed with
   * {@link claimIsolateRow} (`isolate.ts`). Without one, an application isolate uses the
   * first application row (the simulated isolates of the runtime tests). Row `-1` is a
   * view that writes no row and must not take the lock (an isolate before it attaches).
   */
  constructor(
    readonly shared: RuntimeShared,
    readonly role: IsolateRole,
    row?: number,
  ) {
    this.i64 = new BigInt64Array(shared.control);
    this.i32 = new Int32Array(shared.control);
    this.jobs = new Ring(shared.jobs);
    this.lossRing = new Ring(shared.losses);
    this.runRing = shared.runs === undefined ? undefined : new Ring(shared.runs);
    const slot = role === "application" && row !== undefined ? row : ROLE_SLOT[role];
    this.owner = slot + 1;
    if (slot < 0) return;
    const at = ISOLATE_BASE + slot * 4;
    Atomics.store(this.i32, at + 2, ROLE_SLOT[role] + 1);
    Atomics.store(this.i32, at, ROW_ATTACHED);
  }

  /**
   * This isolate's tag (its isolate-table row + 1): the lock owner value, and the owner
   * written into each exchange slot and run-slot claim it takes, so the Fabric worker can
   * settle what a torn-down isolate left behind.
   */
  get ownerTag(): number {
    return this.owner;
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
   *
   * The guarantee covers a hook that reads the state after it allocates (as the boundary
   * test's producers do); a hook that read the old state before allocating above the cut
   * recorded under the old promise, which a change to a lesser state only understates.
   * A `change` that throws is no change: `undefined`, and nothing reaches the caller
   * (it may be the agent's thread at install or uninstall).
   */
  cut(change?: () => void): bigint | undefined {
    try {
      change?.();
    } catch {
      return undefined;
    }
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

  /**
   * The lock's holder tag (0: free). The Fabric worker reads it on every isolate poll: a
   * holder that keeps it across a whole second is a torn-down isolate the detached ring
   * could not name ({@link breakLock}); a live one holds it for microseconds.
   */
  get lockHolder(): number {
    return Atomics.load(this.i32, W_LOCK);
  }
  /** Frees the lock if `tag` still holds it. Fabric worker only. `true` when it did. */
  breakLock(tag: number): boolean {
    if (tag === 0 || Atomics.compareExchange(this.i32, W_LOCK, tag, 0) !== tag) return false;
    Atomics.add(this.i64, C_LOCKS_BROKEN, 1n);
    Atomics.notify(this.i32, W_LOCK, 1);
    return true;
  }

  // -------------------------------------------------------------- application isolates

  /**
   * Claims a free isolate-table row for an attaching application isolate (spec 055
   * §4.5), recording its environment id (`envAttach`) and thread id. `-1` when all 1,022
   * application rows are live. Never waits.
   */
  claimIsolateRow(envId: number, threadId: number): number {
    const i32 = this.i32;
    for (let row = FIRST_APPLICATION_ROW; row < MAX_ISOLATES; row++) {
      const at = ISOLATE_BASE + row * 4;
      if (Atomics.load(i32, at) !== ROW_FREE) continue;
      // The state word is the only one two isolates race on; the ids follow the claim
      // (a reader that sees the row before them matches nothing yet).
      if (Atomics.compareExchange(i32, at, ROW_FREE, ROW_ATTACHED) !== ROW_FREE) continue;
      Atomics.store(i32, at + 1, envId);
      Atomics.store(i32, at + 2, ROLE_SLOT.application + 1);
      Atomics.store(i32, at + 3, threadId);
      // This thread is no longer pending: resolved here, not by the Fabric worker's next
      // scan, which a thread that attaches and exits at once could otherwise miss (it
      // would be counted unattached after the grace period). Thread ids are never reused.
      for (let n = 0; n < MAX_PENDING_THREADS; n++) {
        Atomics.compareExchange(i32, PENDING_BASE + n, threadId, 0);
      }
      return row;
    }
    return -1;
  }

  /**
   * Counts one application isolate as attached: called once its hook is installed, so a
   * thread whose attach failed after claiming its row is never counted attached.
   */
  countAttached(): void {
    Atomics.add(this.i64, C_ISOLATES_ATTACHED, 1n);
  }

  /**
   * Frees a row claimed by an attach that then failed (nothing was allocated under its
   * tag: no exchange, lock or run slot). Not a teardown: not counted as detached.
   */
  freeIsolateRow(row: number): void {
    if (row < FIRST_APPLICATION_ROW || row >= MAX_ISOLATES) return;
    const at = ISOLATE_BASE + row * 4;
    Atomics.store(this.i32, at + 3, 0);
    Atomics.store(this.i32, at + 1, 0);
    Atomics.store(this.i32, at, ROW_FREE);
  }

  /** The attached application row of `envId`, or -1 (ids are never reused, §4.4). */
  rowOfEnv(envId: number): number {
    const i32 = this.i32;
    for (let row = FIRST_APPLICATION_ROW; row < MAX_ISOLATES; row++) {
      const at = ISOLATE_BASE + row * 4;
      if (Atomics.load(i32, at) === ROW_ATTACHED && Atomics.load(i32, at + 1) === envId) {
        return row;
      }
    }
    return -1;
  }

  /** Whether an attached application row holds `threadId`. */
  threadAttached(threadId: number): boolean {
    const i32 = this.i32;
    for (let row = FIRST_APPLICATION_ROW; row < MAX_ISOLATES; row++) {
      const at = ISOLATE_BASE + row * 4;
      if (Atomics.load(i32, at) === ROW_ATTACHED && Atomics.load(i32, at + 3) === threadId) {
        return true;
      }
    }
    return false;
  }

  /**
   * Releases what a torn-down isolate held in the control block (Fabric worker only,
   * after its exchanges were settled): the lock, if it died holding it, and its run-slot
   * claims, whose open segments are left unsealed (never sealed with a wrong count). The
   * row becomes free for a later isolate. Returns the run slots it released.
   */
  detachIsolate(row: number): number {
    const tag = row + 1;
    this.breakLock(tag);
    let released = 0;
    for (let slot = 0; slot < MAX_RUNS; slot++) {
      if (Atomics.load(this.i32, RUN_CLAIM_BASE + slot) !== tag) continue;
      this.setRunSegment(slot, 0n, 0n);
      this.setRunFlags(slot, 0n);
      Atomics.compareExchange(this.i32, RUN_CLAIM_BASE + slot, tag, 0);
      released++;
    }
    const at = ISOLATE_BASE + row * 4;
    Atomics.store(this.i32, at + 3, 0);
    Atomics.store(this.i32, at + 1, 0);
    Atomics.store(this.i32, at, ROW_FREE);
    Atomics.add(this.i64, C_ISOLATES_DETACHED, 1n);
    return released;
  }

  /** Counts a torn-down isolate's positions settled as `shutdown`, and slots it abandoned. */
  countDetached(shutdown: number, abandoned: number): void {
    if (shutdown > 0) Atomics.add(this.i64, C_DETACHED_SHUTDOWN, BigInt(shutdown));
    if (abandoned > 0) Atomics.add(this.i64, C_SLOTS_ABANDONED, BigInt(abandoned));
  }
  countDetachOverflow(): void {
    Atomics.add(this.i64, C_DETACHED_OVERFLOW, 1n);
  }
  countRingVoided(): void {
    Atomics.add(this.i64, C_RING_VOIDED, 1n);
  }
  /** One worker thread that did not attach (or could not be followed). */
  countUnattached(delta = 1n): void {
    Atomics.add(this.i64, C_ISOLATES_UNATTACHED, delta);
  }

  /**
   * A worker thread an attached isolate just created (the `worker_threads` diagnostics
   * channel): the Fabric worker decides later whether it attached. `false` when the
   * table is full; the caller then counts it unattached, never silently.
   */
  notePendingThread(threadId: number): boolean {
    if (!(threadId > 0)) return false;
    // It already attached (the creating thread was slower than the new one's preload).
    if (this.threadAttached(threadId)) return true;
    const i32 = this.i32;
    for (let n = 0; n < MAX_PENDING_THREADS; n++) {
      if (Atomics.compareExchange(i32, PENDING_BASE + n, 0, threadId) === 0) return true;
    }
    return false;
  }
  /** The pending thread ids, by entry (0: free). Fabric worker only. */
  pendingThread(entry: number): number {
    return Atomics.load(this.i32, PENDING_BASE + entry);
  }
  clearPendingThread(entry: number, threadId: number): void {
    Atomics.compareExchange(this.i32, PENDING_BASE + entry, threadId, 0);
  }

  // ------------------------------------------------------------------ run-slot claims

  /**
   * Claims a free run slot for this isolate's run table: one compare-exchange per slot,
   * lowest first, never a wait. `-1` when all 256 are live.
   */
  claimRunSlot(): number {
    const i32 = this.i32;
    for (let slot = 0; slot < MAX_RUNS; slot++) {
      if (Atomics.load(i32, RUN_CLAIM_BASE + slot) !== 0) continue;
      if (Atomics.compareExchange(i32, RUN_CLAIM_BASE + slot, 0, this.owner) === 0) return slot;
    }
    return -1;
  }
  /** Returns a run slot this isolate claimed. */
  releaseRunSlot(slot: number): void {
    if (slot < 0 || slot >= MAX_RUNS) return;
    Atomics.compareExchange(this.i32, RUN_CLAIM_BASE + slot, this.owner, 0);
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

  /** The run's open segment as two 64-bit halves (both zero: none open). */
  runSegment(runSlot: number): readonly [bigint, bigint] {
    const run = RUN_BASE + runSlot * 4;
    return [Atomics.load(this.i64, run), Atomics.load(this.i64, run + 1)];
  }

  /** Positions allocated in the run's open segment. */
  runPositions(runSlot: number): bigint {
    return Atomics.load(this.i64, RUN_BASE + runSlot * 4 + 2);
  }

  /** The run slot's flags ({@link RUN_FLAG_RESUMABLE}). */
  runFlags(runSlot: number): bigint {
    return Atomics.load(this.i64, RUN_BASE + runSlot * 4 + 3);
  }
  setRunFlags(runSlot: number, flags: bigint): void {
    Atomics.store(this.i64, RUN_BASE + runSlot * 4 + 3, flags);
  }

  // ------------------------------------------------------------- run-structure ring

  /**
   * Hands one run-structure record to the Fabric worker and wakes it (it waits on the
   * job ring's word). `false`, changing nothing, when the ring is full or absent.
   */
  pushRun(kind: number, body: Uint8Array): boolean {
    const ring = this.runRing;
    if (ring === undefined || !ring.push(kind, body)) return false;
    this.jobs.wake();
    return true;
  }

  // ------------------------------------------------------------ manifest in force

  /**
   * Publishes the manifest in force (Fabric worker only, the single writer), so the run
   * table on an application thread can name it in run markers and tokens without
   * waiting. A reader that meets a write in progress retries, then goes without.
   */
  publishManifest(manifest: PublishedManifest): void {
    const id = Buffer.from(manifest.manifestId.replace(/-/g, ""), "hex");
    const digest = Buffer.from(manifest.digest.slice("sha256:".length), "hex");
    if (id.length !== 16 || digest.length !== 32) return;
    const i32 = this.i32;
    const version = Atomics.load(i32, M_VERSION) & ~1;
    Atomics.store(i32, M_VERSION, version + 1); // odd: a write is in progress
    Atomics.store(this.i64, M_EPOCH, manifest.epoch);
    Atomics.store(this.i64, M_SEQ, BigInt(manifest.manifestSeq));
    const bytes = new Uint8Array(this.shared.control);
    bytes.set(id, M_ID);
    bytes.set(digest, M_DIGEST);
    Atomics.store(i32, M_VERSION, version + 2 === 0 ? 2 : version + 2);
  }

  /** The manifest the Fabric worker published last, or `undefined` (none yet, or busy). */
  publishedManifest(): PublishedManifest | undefined {
    const i32 = this.i32;
    const bytes = new Uint8Array(this.shared.control);
    for (let attempt = 0; attempt < 4; attempt++) {
      const before = Atomics.load(i32, M_VERSION);
      if (before === 0) return undefined;
      if ((before & 1) === 1) continue;
      const epoch = Atomics.load(this.i64, M_EPOCH);
      const seq = Atomics.load(this.i64, M_SEQ);
      const id = Buffer.from(bytes.slice(M_ID, M_ID + 16)).toString("hex");
      const digest = Buffer.from(bytes.slice(M_DIGEST, M_DIGEST + 32)).toString("hex");
      if (Atomics.load(i32, M_VERSION) !== before) continue;
      return {
        epoch,
        manifestSeq: Number(seq),
        manifestId: `${id.slice(0, 8)}-${id.slice(8, 12)}-${id.slice(12, 16)}-${id.slice(16, 20)}-${id.slice(20)}`,
        digest: "sha256:" + digest,
      };
    }
    return undefined;
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
    let record = this.lossRing.peek();
    // A cell a torn-down isolate claimed and never filled names no position: its loss is
    // a gap without a reason (counted), and the ring moves on.
    while (record !== undefined && record.kind === RING_VOID) {
      this.lossRing.commit();
      this.countUnattributed();
      record = this.lossRing.peek();
    }
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
        uninstrumented_client: Atomics.load(i64, C_LOSSES + 4),
      },
      lossesUnattributed: Atomics.load(i64, C_UNATTRIBUTED),
      lockTimeouts: Atomics.load(i64, C_LOCK_TIMEOUTS),
      refused: Atomics.load(i64, C_REFUSED),
      jobsUnprocessed: Atomics.load(i64, C_UNPROCESSED),
      workerGeneration: this.workerGeneration,
      workerRestarts: Atomics.load(this.i32, W_WORKER_RESTARTS),
      queuedJobs: this.jobs.count,
      isolates: {
        attached: Atomics.load(i64, C_ISOLATES_ATTACHED),
        unattached: Atomics.load(i64, C_ISOLATES_UNATTACHED),
        detached: Atomics.load(i64, C_ISOLATES_DETACHED),
        shutdownPositions: Atomics.load(i64, C_DETACHED_SHUTDOWN),
        overflows: Atomics.load(i64, C_DETACHED_OVERFLOW),
        abandoned: Atomics.load(i64, C_SLOTS_ABANDONED),
        locksBroken: Atomics.load(i64, C_LOCKS_BROKEN),
        ringVoided: Atomics.load(i64, C_RING_VOIDED),
      },
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
