// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * A multi-producer, single-consumer ring of fixed-size records in shared memory
 * (spec 055 §4.5 "Job handoff").
 *
 * Producers are hooks in any attached isolate: `push` is a bounded number of `Atomics`
 * operations plus one copy, never a wait, and `Atomics.notify` wakes the consumer
 * without waiting for it. A full ring refuses the record; the caller reports the named
 * loss. The one consumer is the Fabric worker. Its read position lives in the shared
 * header, so a worker that replaces a crashed one continues where it stopped, and a
 * record is removed only by `commit`, after it has been handled.
 *
 * No `MessagePort` carries a record: there is no hidden unbounded queue and no
 * structured clone.
 */

const HEADER_BYTES = 64;
const Q_TAIL = 0;
const Q_HEAD = 1;
const Q_COUNT = 2;
const Q_WAKE = 3;
const Q_PEAK = 4;
/** Bytes of each record the ring owns: the cell's sequence word and the record kind. */
export const RECORD_PREFIX_BYTES = 8;

export interface RingShared {
  readonly buffer: SharedArrayBuffer;
  readonly recordBytes: number;
  /** Records the ring admits at once (the configured entry count). */
  readonly limit: number;
  /** Cells allocated: the next power of two at or above `limit`. */
  readonly cells: number;
}

export function createRing(recordBytes: number, limit: number): RingShared {
  let cells = 2;
  while (cells < limit) cells *= 2;
  const shared = {
    buffer: new SharedArrayBuffer(HEADER_BYTES + cells * recordBytes),
    recordBytes,
    limit,
    cells,
  };
  const words = new Int32Array(shared.buffer);
  for (let cell = 0; cell < cells; cell++) words[(HEADER_BYTES + cell * recordBytes) / 4] = cell;
  return shared;
}

export class Ring {
  private readonly words: Int32Array;
  private readonly bytes: Uint8Array;
  private readonly mask: number;
  private readonly recordWords: number;

  constructor(readonly shared: RingShared) {
    this.words = new Int32Array(shared.buffer);
    this.bytes = new Uint8Array(shared.buffer);
    this.mask = shared.cells - 1;
    this.recordWords = shared.recordBytes / 4;
  }

  get count(): number {
    return Atomics.load(this.words, Q_COUNT);
  }
  get peak(): number {
    return Atomics.load(this.words, Q_PEAK);
  }
  /** The word a consumer waits on; it changes on every push and every {@link wake}. */
  get wakeWords(): Int32Array {
    return this.words;
  }
  get wakeIndex(): number {
    return Q_WAKE;
  }

  /**
   * Adds one record: `kind`, then `body` (at most `recordBytes - 8` bytes). Returns
   * `false`, changing nothing, when the ring already holds `limit` records.
   */
  push(kind: number, body: Uint8Array): boolean {
    const words = this.words;
    const held = Atomics.add(words, Q_COUNT, 1) + 1;
    if (held > this.shared.limit) {
      Atomics.sub(words, Q_COUNT, 1);
      return false;
    }
    if (held > Atomics.load(words, Q_PEAK)) Atomics.store(words, Q_PEAK, held);
    for (;;) {
      const tail = Atomics.load(words, Q_TAIL);
      const cell = HEADER_BYTES / 4 + (tail & this.mask) * this.recordWords;
      const turn = (Atomics.load(words, cell) - tail) | 0;
      if (turn < 0) {
        // The consumer has not released this cell yet; `count` admitted us, so this is
        // a consumer between `peek` and `commit`. Refuse rather than spin.
        Atomics.sub(words, Q_COUNT, 1);
        return false;
      }
      if (turn !== 0 || Atomics.compareExchange(words, Q_TAIL, tail, (tail + 1) | 0) !== tail) {
        continue;
      }
      words[cell + 1] = kind;
      this.bytes.set(body, cell * 4 + RECORD_PREFIX_BYTES);
      Atomics.store(words, cell, (tail + 1) | 0);
      this.wake();
      return true;
    }
  }

  /** Wakes the consumer without waiting for it. */
  wake(): void {
    Atomics.add(this.words, Q_WAKE, 1);
    Atomics.notify(this.words, Q_WAKE, 1);
  }

  /**
   * The oldest record, in place, or `undefined` when there is none. Consumer only. The
   * record stays in the ring until {@link commit}; a consumer that dies before
   * committing leaves it for its replacement.
   */
  peek():
    { readonly kind: number; readonly body: Uint8Array; readonly byteOffset: number } | undefined {
    const words = this.words;
    const head = Atomics.load(words, Q_HEAD);
    const cell = HEADER_BYTES / 4 + (head & this.mask) * this.recordWords;
    if (((Atomics.load(words, cell) - (head + 1)) | 0) !== 0) return undefined;
    const byteOffset = cell * 4 + RECORD_PREFIX_BYTES;
    return {
      kind: words[cell + 1]!,
      body: this.bytes.subarray(byteOffset, cell * 4 + this.shared.recordBytes),
      byteOffset,
    };
  }

  /**
   * Changes the kind of the record {@link peek} returned, in place. Consumer only: it
   * marks how far the record's handling got, for a consumer that replaces this one.
   */
  retag(kind: number): void {
    const words = this.words;
    const head = Atomics.load(words, Q_HEAD);
    Atomics.store(words, HEADER_BYTES / 4 + (head & this.mask) * this.recordWords + 1, kind);
  }

  /** Removes the record {@link peek} returned. Consumer only. */
  commit(): void {
    const words = this.words;
    const head = Atomics.load(words, Q_HEAD);
    const cell = HEADER_BYTES / 4 + (head & this.mask) * this.recordWords;
    Atomics.store(words, cell, (head + this.shared.cells) | 0);
    Atomics.store(words, Q_HEAD, (head + 1) | 0);
    Atomics.sub(words, Q_COUNT, 1);
  }
}
