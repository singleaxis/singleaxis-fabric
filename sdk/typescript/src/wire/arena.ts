// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Shared-memory slot pools and the payload arena (spec 055 §4.5).
 *
 * A {@link SlotPool} is a growable `SharedArrayBuffer` cut into fixed-size slots, with a
 * lock-free free list in a second, fixed buffer. Any isolate takes and returns slots
 * with `Atomics` only: no lock, no wait, no allocation of shared memory. Only the Fabric
 * worker grows a pool, ahead of a low-water mark; a hook that finds the pool empty gets
 * `-1` and reports the named loss.
 *
 * The {@link PayloadArena} stores body bytes in 64 KiB slabs. A body side is a chain of
 * 64-byte chunk-vector slots, each naming up to 14 slabs; bytes are packed, so every slab
 * of a side is full except the last. A chunk is admitted whole or not at all, and is
 * copied exactly once, before the caller's observation callback returns.
 */

/** Payload slab size (spec 055 §4.5). */
export const SLAB_BYTES = 64 * 1024;
/** Chunk-vector slot size and the process-wide slot count (spec 055 §4.5 item 4). */
export const VECTOR_BYTES = 64;
export const MAX_VECTOR_SLOTS = 65536;
/** Slabs one chunk-vector slot names: 16 words less `next` and `count`. */
export const SLABS_PER_VECTOR = 14;

const POOL_HEADER_BYTES = 32;
// Int32 words of the pool header; the free-list head is the BigInt64 word at byte 0.
const P_COMMITTED = 2;
const P_IN_USE = 3;
const P_PEAK = 4;
const LOW32 = 0xffffffffn;

/** What crosses to another isolate: plain data plus shared buffers. */
export interface PoolShared {
  readonly data: SharedArrayBuffer;
  readonly meta: SharedArrayBuffer;
  readonly slotBytes: number;
  readonly maxSlots: number;
  /** Free slots below which the Fabric worker commits more (0: never grows). */
  readonly lowWater: number;
  /** Slots committed per growth step. */
  readonly growStep: number;
}

export interface PoolOptions {
  readonly slotBytes: number;
  readonly maxSlots: number;
  readonly initialSlots: number;
  readonly lowWater?: number;
  readonly growStep?: number;
}

/** The part of a growable `SharedArrayBuffer` this file uses (ES2024; Node 22+). */
interface GrowableShared {
  grow(newLength: number): void;
}

export function createPool(options: PoolOptions): PoolShared {
  const { slotBytes, maxSlots } = options;
  const initial = Math.max(1, Math.min(options.initialSlots, maxSlots));
  const SharedBuffer = SharedArrayBuffer as unknown as new (
    length: number,
    options: { maxByteLength: number },
  ) => SharedArrayBuffer;
  const shared: PoolShared = {
    data: new SharedBuffer(initial * slotBytes, { maxByteLength: maxSlots * slotBytes }),
    meta: new SharedArrayBuffer(POOL_HEADER_BYTES + 4 * maxSlots),
    slotBytes,
    maxSlots,
    lowWater: options.lowWater ?? 0,
    growStep: options.growStep ?? Math.max(1, initial),
  };
  const pool = new SlotPool(shared);
  for (let index = 0; index < initial; index++) pool.free(index, false);
  Atomics.store(pool.words, P_COMMITTED, initial);
  return shared;
}

export class SlotPool {
  /** Length-tracking views: they follow growth, in every isolate that shares the buffer. */
  readonly bytes: Uint8Array;
  readonly i32: Int32Array;
  readonly i64: BigInt64Array;
  readonly words: Int32Array;
  private readonly head: BigInt64Array;
  private readonly next: Int32Array;

  constructor(readonly shared: PoolShared) {
    this.bytes = new Uint8Array(shared.data);
    this.i32 = new Int32Array(shared.data);
    this.i64 = new BigInt64Array(shared.data);
    this.words = new Int32Array(shared.meta, 0, POOL_HEADER_BYTES / 4);
    this.head = new BigInt64Array(shared.meta, 0, 1);
    this.next = new Int32Array(shared.meta, POOL_HEADER_BYTES, shared.maxSlots);
  }

  get committed(): number {
    return Atomics.load(this.words, P_COMMITTED);
  }
  get inUse(): number {
    return Atomics.load(this.words, P_IN_USE);
  }
  /** The most slots ever in use at once (for the memory report). */
  get peak(): number {
    return Atomics.load(this.words, P_PEAK);
  }

  /** True when the Fabric worker should commit more slots: hooks wake it, never grow. */
  get low(): boolean {
    const committed = this.committed;
    return committed < this.shared.maxSlots && committed - this.inUse < this.shared.lowWater;
  }

  /**
   * Takes a free slot, or returns `-1` when none is committed and free. The head word
   * carries a 32-bit change counter beside the slot index, so a slot freed and taken
   * again between this load and the exchange is not mistaken for the same list.
   */
  take(): number {
    for (;;) {
      const head = Atomics.load(this.head, 0);
      const top = Number(head & LOW32);
      if (top === 0) return -1;
      const next = Atomics.load(this.next, top - 1);
      const replacement = BigInt.asIntN(64, (((head >> 32n) + 1n) << 32n) | BigInt(next));
      if (Atomics.compareExchange(this.head, 0, head, replacement) !== head) continue;
      const used = Atomics.add(this.words, P_IN_USE, 1) + 1;
      if (used > Atomics.load(this.words, P_PEAK)) Atomics.store(this.words, P_PEAK, used);
      return top - 1;
    }
  }

  /** Returns a slot to the free list. */
  free(index: number, wasInUse = true): void {
    for (;;) {
      const head = Atomics.load(this.head, 0);
      Atomics.store(this.next, index, Number(head & LOW32));
      const replacement = BigInt.asIntN(64, (((head >> 32n) + 1n) << 32n) | BigInt(index + 1));
      if (Atomics.compareExchange(this.head, 0, head, replacement) === head) break;
    }
    if (wasInUse) Atomics.sub(this.words, P_IN_USE, 1);
  }

  /**
   * Commits one growth step when fewer than `lowWater` slots are free. Fabric worker
   * only (one grower at a time): a hook never grows or allocates an arena.
   * Returns the number of slots added.
   */
  growIfLow(): number {
    const { lowWater, growStep, maxSlots, slotBytes } = this.shared;
    const committed = this.committed;
    if (committed >= maxSlots || committed - this.inUse >= lowWater) return 0;
    const target = Math.min(maxSlots, committed + growStep);
    // A Fabric worker terminated part-way through a step leaves the buffer grown; its
    // replacement must not shrink it (a RangeError) or grow it again.
    if (this.shared.data.byteLength < target * slotBytes) {
      (this.shared.data as unknown as GrowableShared).grow(target * slotBytes);
    }
    // Count each slot as committed before it is freed: a step cut short by a terminated
    // worker can leak the one slot in flight, but its replacement, which starts from the
    // committed count, never frees a slot twice (two exchanges would share a slab).
    for (let index = committed; index < target; index++) {
      Atomics.store(this.words, P_COMMITTED, index + 1);
      this.free(index, false);
    }
    return target - committed;
  }
}

// --------------------------------------------------------------------------- body sides

/**
 * Where a body side's descriptor lives: four consecutive Int32 words (first vector + 1,
 * last vector + 1, slab count, byte length) in an exchange slot or a job record.
 */
export interface SideWords {
  readonly i32: Int32Array;
  readonly at: number;
}
export const SIDE_HEAD = 0;
export const SIDE_TAIL = 1;
export const SIDE_SLABS = 2;
export const SIDE_LENGTH = 3;

export const APPEND_OK = 0;
/** No free payload slab: the process byte budget, or growth has not caught up. */
export const APPEND_NO_SLAB = 1;
/** No free chunk-vector slot. */
export const APPEND_NO_VECTOR = 2;
export type AppendResult = typeof APPEND_OK | typeof APPEND_NO_SLAB | typeof APPEND_NO_VECTOR;

export interface PayloadShared {
  readonly slabs: PoolShared;
  readonly vectors: PoolShared;
}

/**
 * The payload arena. `headroomBytes` is the free space the Fabric worker keeps committed
 * ahead of use: at least one whole side (`max_retain_bytes`), so a single large chunk
 * that is within the side cap and the global budget is never refused only because
 * growth had not caught up. Committing a growable `SharedArrayBuffer` reserves address
 * space; pages become resident only when a slab is first written.
 */
export function createPayload(
  maxBytes: number,
  initialBytes: number,
  headroomBytes = 0,
): PayloadShared {
  const maxSlabs = Math.max(1, Math.floor(maxBytes / SLAB_BYTES));
  const lowWater = Math.min(maxSlabs, Math.max(32, Math.ceil(headroomBytes / SLAB_BYTES)));
  const initialSlabs = Math.max(
    lowWater,
    Math.min(maxSlabs, Math.ceil(initialBytes / SLAB_BYTES)),
    1,
  );
  return {
    slabs: createPool({
      slotBytes: SLAB_BYTES,
      maxSlots: maxSlabs,
      initialSlots: initialSlabs,
      lowWater,
      growStep: Math.max(64, lowWater),
    }),
    vectors: createPool({
      slotBytes: VECTOR_BYTES,
      maxSlots: MAX_VECTOR_SLOTS,
      initialSlots: 4096,
      lowWater: 2048,
      growStep: 4096,
    }),
  };
}

export class PayloadArena {
  readonly slabs: SlotPool;
  readonly vectors: SlotPool;
  /** Scratch for the slots one append takes, so a refused chunk takes none. */
  private readonly taken: number[] = [];

  constructor(shared: PayloadShared) {
    this.slabs = new SlotPool(shared.slabs);
    this.vectors = new SlotPool(shared.vectors);
  }

  /** Bytes charged against the process budget: whole slabs, not visible lengths. */
  get chargedBytes(): number {
    return this.slabs.inUse * SLAB_BYTES;
  }

  /**
   * Copies `chunk` onto the end of a side, whole or not at all. The one writer of a side
   * is the isolate that owns its exchange; slots come from the shared pools.
   */
  append(side: SideWords, chunk: Uint8Array): AppendResult {
    const { i32, at } = side;
    const slabCount = i32[at + SIDE_SLABS]!;
    const length = i32[at + SIDE_LENGTH]!;
    const tailFree = slabCount * SLAB_BYTES - length;
    const newSlabs =
      chunk.length > tailFree ? Math.ceil((chunk.length - tailFree) / SLAB_BYTES) : 0;
    const vectorCount = Math.ceil(slabCount / SLABS_PER_VECTOR);
    const newVectors = Math.ceil((slabCount + newSlabs) / SLABS_PER_VECTOR) - vectorCount;
    const taken = this.taken;
    taken.length = 0;
    for (let n = 0; n < newVectors + newSlabs; n++) {
      const pool = n < newVectors ? this.vectors : this.slabs;
      const index = pool.take();
      if (index < 0) {
        for (let k = 0; k < n; k++) (k < newVectors ? this.vectors : this.slabs).free(taken[k]!);
        return n < newVectors ? APPEND_NO_VECTOR : APPEND_NO_SLAB;
      }
      taken[n] = index;
    }

    const bytes = this.slabs.bytes;
    const vectors = this.vectors.i32;
    let copied = Math.min(tailFree, chunk.length);
    let tail = i32[at + SIDE_TAIL]! - 1;
    if (copied > 0) {
      const used = slabCount % SLABS_PER_VECTOR || SLABS_PER_VECTOR;
      const slab = vectors[tail * 16 + 1 + used]!;
      bytes.set(chunk.subarray(0, copied), slab * SLAB_BYTES + (SLAB_BYTES - tailFree));
    }
    let nextVector = 0;
    for (let n = 0; n < newSlabs; n++) {
      const slab = taken[newVectors + n]!;
      if ((slabCount + n) % SLABS_PER_VECTOR === 0) {
        const vector = taken[nextVector++]!;
        vectors.fill(0, vector * 16, vector * 16 + 16);
        if (tail < 0) i32[at + SIDE_HEAD] = vector + 1;
        else vectors[tail * 16] = vector + 1;
        tail = vector;
      }
      const count = vectors[tail * 16 + 1]!;
      vectors[tail * 16 + 2 + count] = slab;
      vectors[tail * 16 + 1] = count + 1;
      const end = Math.min(chunk.length, copied + SLAB_BYTES);
      bytes.set(chunk.subarray(copied, end), slab * SLAB_BYTES);
      copied = end;
    }
    i32[at + SIDE_TAIL] = tail + 1;
    i32[at + SIDE_SLABS] = slabCount + newSlabs;
    i32[at + SIDE_LENGTH] = length + chunk.length;
    return APPEND_OK;
  }

  /**
   * The side's bytes as views of the slabs, in order. The Fabric worker reads them in
   * place: nothing is copied again before PROTECT.
   */
  *chunks(side: SideWords): Generator<Uint8Array> {
    let remaining = side.i32[side.at + SIDE_LENGTH]!;
    let vector = side.i32[side.at + SIDE_HEAD]! - 1;
    const vectors = this.vectors.i32;
    while (vector >= 0 && remaining > 0) {
      const count = vectors[vector * 16 + 1]!;
      for (let n = 0; n < count && remaining > 0; n++) {
        const start = vectors[vector * 16 + 2 + n]! * SLAB_BYTES;
        const size = Math.min(SLAB_BYTES, remaining);
        yield this.slabs.bytes.subarray(start, start + size);
        remaining -= size;
      }
      vector = vectors[vector * 16]! - 1;
    }
  }

  /**
   * Returns a side's slabs and vector slots to the pools and empties its descriptor.
   * Each slot is unlinked from the side before it is freed, so a release that is cut
   * short (a terminated Fabric worker) and run again by its replacement can leak a
   * slot but never frees one twice: two exchanges can never share a slab.
   */
  release(side: SideWords): void {
    const { i32, at } = side;
    const vectors = this.vectors.i32;
    let vector = i32[at + SIDE_HEAD]! - 1;
    while (vector >= 0) {
      for (let n = vectors[vector * 16 + 1]! - 1; n >= 0; n--) {
        const slab = vectors[vector * 16 + 2 + n]!;
        vectors[vector * 16 + 1] = n;
        this.slabs.free(slab);
      }
      const next = vectors[vector * 16]! - 1;
      i32[at + SIDE_HEAD] = next + 1;
      this.vectors.free(vector);
      vector = next;
    }
    i32.fill(0, at, at + 4);
  }
}
