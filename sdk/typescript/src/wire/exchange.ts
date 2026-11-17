// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Exchange slots and the finish-once state machine (spec 055 §4.5, §4.6).
 *
 * One model call is one exchange: a 2 KiB slot in shared memory holding its ids, clean
 * parent context, source position, segment and the descriptors of its two body sides.
 * A transport hook calls `begin`, `admit` for each observed chunk and `finish` once;
 * each is a bounded number of `Atomics` operations and at most one copy, with no
 * hashing, parsing, I/O, logging or wait. Nothing here throws into the caller.
 *
 * Finish happens exactly once, whoever gets there first: end of body, early close or
 * abort, a transport failure, a garbage-collection notice or recorder shutdown. The
 * slot's state word carries its reuse generation, so a late or repeated finish, from
 * this isolate or another, can never act on the slot's next exchange.
 *
 * Every bound has a named outcome, and none labels a partial body exact:
 * - side over `max_retain_bytes`: that side is `truncated(body_cap)`;
 * - no free payload slab: that side is `truncated(inflight_budget)`;
 * - a body backed by a `SharedArrayBuffer`: `truncated(transport_incomplete)`;
 * - no chunk-vector slot, no exchange slot, or a full job ring: the exchange's position
 *   is lost as `queue_full` and its bytes are released.
 */
import { randomFillSync } from "node:crypto";
import { types } from "node:util";

import { APPEND_NO_SLAB, APPEND_OK, PayloadArena, SlotPool, type SideWords } from "./arena.js";
import { RECORD_PREFIX_BYTES } from "./queue.js";
import {
  type RuntimeLossReason,
  STATE_FAILED,
  STATE_RUNNING,
  type WireRuntime,
} from "./runtime.js";

// Slot states (low 3 bits of word 0; the rest is the reuse generation).
const FREE = 0;
const PROVISIONAL = 1;
const OPEN = 2;
const WRITING = 3;
const WRITING_PROVISIONAL = 4;
const FINISHING = 5;

const SLOT_WORDS = 512;
const SLOT_I64 = 256;
// BigInt64 words of a slot.
const X_SEQUENCE = 1;
const X_SEGMENT = 2; // two words
const X_START_NS = 4;
const X_END_NS = 5;
// Int32 words of a slot.
const X_FLAGS = 12;
const X_RESPONSE_STATE = 13;
const X_RUN = 14;
const X_SIDE = 16; // request; response is 8 words later
const SIDE_WORDS = 8;
const SIDE_STATE = 4;
const SIDE_REASON = 5;
// Byte offsets of a slot.
const X_IDS = 128; // exchange uuid4 (16), event uuid4 (16), span id (8)
const X_PARENT = 168; // trace id (16), span id (8), flags, remote, present
/** Bytes of a slot the transport hook defines (URL, status, headers digest inputs). */
export const META_OFFSET = 256;
export const META_BYTES = 2048 - META_OFFSET;

const FLAG_ADOPTED = 1;
const FLAG_WITHHELD = 2;
const FLAG_LOST = 4;

/** Ring record kind of a completed exchange. */
export const JOB_EXCHANGE = 1;
/**
 * A completed exchange the Fabric worker has already handled and is releasing. A worker
 * that replaces one that died here finishes the release and never handles the job
 * again: its sides may already be empty, and an empty side must not be read as exact.
 */
export const JOB_RELEASING = 2;

export const REQUEST = 0;
export const RESPONSE = 1;
export type Side = typeof REQUEST | typeof RESPONSE;

/** A side's content state: never `exact` unless every byte was retained. */
export const SIDE_STATES = ["absent", "exact", "truncated"] as const;
export type SideState = (typeof SIDE_STATES)[number];
export const TRUNCATION_REASONS = [
  "",
  "body_cap",
  "inflight_budget",
  "transport_incomplete",
] as const;
export type TruncationReason = Exclude<(typeof TRUNCATION_REASONS)[number], "">;

/** The existing response-state vocabulary (`fabric.wire.response_state`). */
export const RESPONSE_STATES = ["complete", "closed_early", "error", "abandoned"] as const;
export type ResponseState = (typeof RESPONSE_STATES)[number];

/**
 * The explicit-model ownership scope a provisional exchange refers to (§4.6): mutable
 * flags held in the application's `AsyncLocalStorage` by the explicit producer.
 */
export interface ExplicitOwnership {
  /** The explicit scope has ended; an exchange still open is adopted by wire capture. */
  ended: boolean;
  /** The explicit producer withheld content; it stays withheld after the scope ends. */
  withheld: boolean;
}

/** Trace id, span id, flags and remoteness only: no baggage, tracestate or attributes. */
export interface ParentContext {
  readonly traceId: Uint8Array;
  readonly spanId: Uint8Array;
  readonly flags: number;
  readonly remote: boolean;
}

export interface BeginOptions {
  readonly runSlot?: number;
  readonly ownership?: ExplicitOwnership;
  readonly parent?: ParentContext;
  /** Wall-clock start in nanoseconds; default: now. */
  readonly startNs?: bigint;
}

/** What `finish` did. Only `enqueued` hands a record to the Fabric worker. */
export type FinishOutcome =
  /** The completed job is in the ring. */
  | "enqueued"
  /** The position is a named loss (`queue_full`, `internal_error` or `shutdown`). */
  | "lost"
  /** A live explicit scope owns this model call: no position, no bytes kept. */
  | "deferred_to_explicit"
  /** Someone finished it before; nothing happened. */
  | "already_finished";

/** No exchange: `begin` did not capture (the loss, if a position exists, is recorded). */
export const NO_EXCHANGE = -1;

export interface SideDescriptor {
  readonly state: SideState;
  readonly reason: TruncationReason | undefined;
  readonly byteLength: number;
  /** Pass to {@link PayloadArena.chunks} and {@link PayloadArena.release}. */
  readonly words: SideWords;
}

/** A completed exchange as the Fabric worker reads it from a ring record. */
export interface ExchangeJob {
  readonly sequence: bigint;
  readonly segmentHi: bigint;
  readonly segmentLo: bigint;
  readonly startNs: bigint;
  readonly endNs: bigint;
  readonly responseState: ResponseState;
  /** Adopted from an explicit scope that withheld content: store nothing, no digest. */
  readonly withheld: boolean;
  readonly adopted: boolean;
  readonly exchangeId: Uint8Array;
  readonly eventId: Uint8Array;
  readonly spanId: Uint8Array;
  readonly parent: ParentContext | undefined;
  readonly request: SideDescriptor;
  readonly response: SideDescriptor;
  readonly meta: Uint8Array;
}

/** A Node string encoding (`BufferEncoding`). */
export type Encoding = NonNullable<Parameters<Buffer["toString"]>[0]>;

const now = (): bigint => BigInt(Date.now()) * 1_000_000n;

export class ExchangeTable {
  readonly arena: PayloadArena;
  readonly pool: SlotPool;
  /** Ownership flags of this isolate's provisional exchanges, by handle. */
  private readonly owned = new Map<number, ExplicitOwnership>();
  private readonly random = new Uint8Array(40);

  constructor(readonly runtime: WireRuntime) {
    this.arena = new PayloadArena(runtime.shared.payload);
    this.pool = new SlotPool(runtime.shared.exchanges);
  }

  /**
   * Starts an exchange and returns its handle, or {@link NO_EXCHANGE}. With a live
   * explicit ownership scope the exchange is provisional: bytes are teed but no
   * position is allocated until `finish` decides who owns the call.
   */
  begin(options: BeginOptions = {}): number {
    const runtime = this.runtime;
    if (!runtime.running) {
      runtime.countRefused();
      return NO_EXCHANGE;
    }
    const runSlot = options.runSlot ?? -1;
    const ownership = options.ownership;
    const provisional = ownership !== undefined && !ownership.ended;
    const index = this.pool.take();
    if (index < 0) {
      // No slot to follow the call with, so nobody can decide ownership later: the
      // position is a visible gap rather than a silent miss.
      const lost = runtime.allocate(runSlot);
      if (!lost.lost) runtime.lose("queue_full", lost.sequence, lost.segmentHi, lost.segmentLo);
      return NO_EXCHANGE;
    }
    if (this.pool.low) runtime.jobs.wake();
    const { i32, i64, bytes } = this.pool;
    const word = index * SLOT_WORDS;
    try {
      // The whole slot, hook-defined bytes included: nothing of the slot's previous
      // exchange can appear in this one's record.
      bytes.fill(0, index * 2048 + 8, index * 2048 + 2048);
      i32[word + X_RUN] = runSlot;
      i32[word + X_SIDE + SIDE_STATE] = 1; // a request with no body is an exact empty body
      i64[index * SLOT_I64 + X_START_NS] = options.startNs ?? now();
      this.writeIds(index, options.parent);
      // A call that starts after its explicit scope ended is adopted at once, and keeps
      // the scope's withheld flag (it survives scope exit).
      if (ownership !== undefined && !provisional) i32[word + X_FLAGS] = FLAG_ADOPTED;
      if (ownership?.withheld === true) i32[word + X_FLAGS] = i32[word + X_FLAGS]! | FLAG_WITHHELD;
      // Last: nothing below can fail once a position exists.
      if (!provisional && !this.position(index, runSlot)) {
        this.recycle(index);
        return NO_EXCHANGE;
      }
    } catch {
      // Never the caller's problem: the call goes on uncaptured. No position was
      // allocated, so there is no gap to name.
      try {
        this.recycle(index);
      } catch {
        // Nothing more can be done here.
      }
      return NO_EXCHANGE;
    }
    const generation = Atomics.load(i32, word) >>> 3;
    Atomics.store(i32, word, (generation << 3) | (provisional ? PROVISIONAL : OPEN));
    const handle = generation * 65536 + index;
    if (provisional) this.owned.set(handle, ownership);
    // Shutdown may have swept the table between the check above and this store.
    if (!runtime.running) this.finish(handle, "abandoned");
    return handle;
  }

  /**
   * Retains one observed chunk, copying it once before returning. Returns `false` when
   * the chunk was not retained; the caller forwards the data unchanged either way.
   * A string is encoded with the same Node encoder and encoding as the original write.
   */
  admit(handle: number, side: Side, chunk: Uint8Array | string, encoding?: Encoding): boolean {
    if (handle < 0) return false;
    const index = handle % 65536;
    const { i32 } = this.pool;
    const word = index * SLOT_WORDS;
    const open = (Math.floor(handle / 65536) << 3) | OPEN;
    let restore = open;
    if (Atomics.compareExchange(i32, word, open, open - OPEN + WRITING) !== open) {
      restore = open - OPEN + PROVISIONAL;
      if (
        Atomics.compareExchange(i32, word, restore, open - OPEN + WRITING_PROVISIONAL) !== restore
      )
        return false;
    }
    let retained = false;
    try {
      retained = this.retain(index, side, chunk, encoding);
    } catch {
      this.truncate(word + X_SIDE + side * SIDE_WORDS, 3);
    }
    Atomics.store(i32, word, restore);
    return retained;
  }

  private retain(
    index: number,
    side: Side,
    chunk: Uint8Array | string,
    encoding: Encoding | undefined,
  ): boolean {
    const { i32 } = this.pool;
    const word = index * SLOT_WORDS;
    const at = word + X_SIDE + side * SIDE_WORDS;
    if ((i32[word + X_FLAGS]! & (FLAG_LOST | FLAG_WITHHELD)) !== 0) return false;
    if (i32[at + SIDE_STATE] === 0) i32[at + SIDE_STATE] = 1;
    if (i32[at + SIDE_STATE] !== 1) return false;
    if (typeof chunk !== "string" && types.isSharedArrayBuffer(chunk.buffer)) {
      // Another thread may write these bytes while they are copied: no atomic snapshot.
      return this.truncate(at, 3);
    }
    const data = typeof chunk === "string" ? Buffer.from(chunk, encoding) : chunk;
    if (data.length === 0) return true;
    if (i32[at + 3]! + data.length > this.runtime.shared.maxRetainBytes) {
      return this.truncate(at, 1);
    }
    const result = this.arena.append({ i32, at }, data);
    if (result === APPEND_OK) {
      if (this.arena.slabs.low) this.runtime.jobs.wake();
      return true;
    }
    if (result === APPEND_NO_SLAB) return this.truncate(at, 2);
    // No chunk-vector slot: the exchange is lost as queue_full; keep none of its bytes.
    i32[word + X_FLAGS] = i32[word + X_FLAGS]! | FLAG_LOST;
    this.releaseSides(index);
    return false;
  }

  /** Retention stops at the first rejected chunk; the retained prefix stays, labelled. */
  private truncate(at: number, reason: number): false {
    const { i32 } = this.pool;
    i32[at + SIDE_STATE] = 2;
    if (i32[at + SIDE_REASON] === 0) i32[at + SIDE_REASON] = reason;
    return false;
  }

  /** The response has started (headers seen): from now a missing body is zero bytes. */
  responseStarted(handle: number): void {
    this.touch(handle, RESPONSE, false);
  }

  /** The request body was not sent whole: `truncated(transport_incomplete)`. */
  requestIncomplete(handle: number): void {
    this.touch(handle, REQUEST, true);
  }

  private touch(handle: number, side: Side, incomplete: boolean): void {
    if (handle < 0) return;
    const index = handle % 65536;
    const { i32 } = this.pool;
    const word = index * SLOT_WORDS;
    const open = (Math.floor(handle / 65536) << 3) | OPEN;
    let restore = open;
    if (Atomics.compareExchange(i32, word, open, open - OPEN + WRITING) !== open) {
      restore = open - OPEN + PROVISIONAL;
      if (
        Atomics.compareExchange(i32, word, restore, open - OPEN + WRITING_PROVISIONAL) !== restore
      )
        return;
    }
    const at = word + X_SIDE + side * SIDE_WORDS;
    if (incomplete) this.truncate(at, 3);
    else if (i32[at + SIDE_STATE] === 0) i32[at + SIDE_STATE] = 1;
    Atomics.store(i32, word, restore);
  }

  /**
   * The slot's hook-defined bytes, or `undefined` for a handle that is no longer open.
   * Write them before `finish`; the view must not be kept.
   */
  meta(handle: number): Uint8Array | undefined {
    if (handle < 0) return undefined;
    const index = handle % 65536;
    const state = Atomics.load(this.pool.i32, index * SLOT_WORDS);
    const live = state & 7;
    if (state >>> 3 !== Math.floor(handle / 65536)) return undefined;
    if (live !== OPEN && live !== PROVISIONAL) return undefined;
    return this.pool.bytes.subarray(index * 2048 + META_OFFSET, index * 2048 + 2048);
  }

  /**
   * Finishes the exchange exactly once. Later calls, from any path or isolate, return
   * `already_finished` and change nothing.
   */
  finish(handle: number, responseState: ResponseState, endNs?: bigint): FinishOutcome {
    if (handle < 0) return "already_finished";
    const index = handle % 65536;
    const { i32, i64 } = this.pool;
    const word = index * SLOT_WORDS;
    const open = (Math.floor(handle / 65536) << 3) | OPEN;
    let provisional = false;
    if (Atomics.compareExchange(i32, word, open, open - OPEN + FINISHING) !== open) {
      const waiting = open - OPEN + PROVISIONAL;
      provisional =
        Atomics.compareExchange(i32, word, waiting, open - OPEN + FINISHING) === waiting;
      if (!provisional) {
        this.owned.delete(handle);
        return "already_finished";
      }
    }
    const runtime = this.runtime;
    // A provisional exchange has no position until it is adopted below.
    let positioned = !provisional;
    try {
      if (provisional) {
        const ownership = this.owned.get(handle);
        this.owned.delete(handle);
        if (ownership === undefined || !ownership.ended) {
          this.releaseSides(index);
          return "deferred_to_explicit";
        }
        // The explicit scope ended first: wire capture adopts the call and allocates now.
        i32[word + X_FLAGS] = i32[word + X_FLAGS]! | FLAG_ADOPTED;
        if (ownership.withheld) {
          i32[word + X_FLAGS] = i32[word + X_FLAGS]! | FLAG_WITHHELD;
          this.releaseSides(index);
        }
        if (!this.position(index, i32[word + X_RUN]!)) {
          this.releaseSides(index);
          return "lost";
        }
        positioned = true;
      }
      i32[word + X_RESPONSE_STATE] = RESPONSE_STATES.indexOf(responseState);
      i64[index * SLOT_I64 + X_END_NS] = endNs ?? now();
      const state = runtime.state;
      const lost = (i32[word + X_FLAGS]! & FLAG_LOST) !== 0;
      if (state !== STATE_RUNNING || lost) {
        // Not running: an unresolved exchange is a shutdown loss, never a synthetic
        // response (internal_error when the Fabric worker could not be kept running).
        const reason = lost ? "queue_full" : state === STATE_FAILED ? "internal_error" : "shutdown";
        return this.loseSlot(index, reason);
      }
      const body = this.pool.bytes.subarray(
        index * 2048 + RECORD_PREFIX_BYTES,
        index * 2048 + 2048,
      );
      if (!runtime.jobs.push(JOB_EXCHANGE, body)) return this.loseSlot(index, "queue_full");
      // The job record now owns the sides' slabs; the slot is free for the next call.
      return "enqueued";
    } catch {
      try {
        // Without a position there is nothing to lose: only the bytes are released.
        if (positioned) return this.loseSlot(index, "internal_error");
        this.releaseSides(index);
      } catch {
        // Nothing more can be done here; the caller is never told to throw.
      }
      return "lost";
    } finally {
      this.recycle(index);
    }
  }

  /**
   * A garbage-collection notice for an exchange whose owner was collected unfinished.
   * It is a finish like any other, never a durability mechanism and never a read.
   */
  noticeCollected(handle: number): FinishOutcome {
    return this.finish(handle, "abandoned");
  }

  /**
   * Recorder shutdown: every exchange still open is finished as a `shutdown` loss; no
   * synthetic response is created. Call after the runtime left the running state.
   * Returns the number of positions lost. May run on any isolate; never waits.
   */
  shutdown(): number {
    const { i32 } = this.pool;
    let lost = 0;
    for (let index = 0; index < this.pool.committed; index++) {
      const word = index * SLOT_WORDS;
      for (let attempt = 0; attempt < 1000; attempt++) {
        const state = Atomics.load(i32, word);
        const live = state & 7;
        if (live === FREE || live === FINISHING) break;
        // An owner inside `admit` holds the slot for the length of one copy: try again.
        if (live !== OPEN && live !== PROVISIONAL) continue;
        if (Atomics.compareExchange(i32, word, state, (state & ~7) | FINISHING) !== state) continue;
        try {
          if (live === OPEN) {
            this.loseSlot(index, "shutdown");
            lost++;
          } else if (this.adoptAtShutdown(state, index)) {
            lost++;
          } else {
            this.releaseSides(index);
          }
        } catch {
          // A sweep that fails for one slot still frees it and goes on to the next.
        }
        this.recycle(index);
        break;
      }
    }
    return lost;
  }

  /**
   * A provisional exchange swept by shutdown. If this isolate knows its explicit scope
   * has already ended, `finish` would have adopted it and allocated a position, so
   * shutdown does the same and loses that position as `shutdown` (§4.6): the call is a
   * visible gap, never a silent miss. Returns `true` when a position was lost. A scope
   * that is still live owns the call, and shutdown only releases its bytes.
   */
  private adoptAtShutdown(state: number, index: number): boolean {
    const handle = (state >>> 3) * 65536 + index;
    const ownership = this.owned.get(handle);
    this.owned.delete(handle);
    if (ownership === undefined || !ownership.ended) return false;
    // On a lock timeout the position is already an internal_error loss.
    if (this.position(index, this.pool.i32[index * SLOT_WORDS + X_RUN]!)) {
      this.loseSlot(index, "shutdown");
    } else {
      this.releaseSides(index);
    }
    return true;
  }

  /** Reads a job record the Fabric worker took from the ring with `peek`. */
  job(byteOffset: number): ExchangeJob {
    const buffer = this.runtime.shared.jobs.buffer;
    const base = byteOffset - RECORD_PREFIX_BYTES;
    const i64 = new BigInt64Array(buffer, base, SLOT_I64);
    const i32 = new Int32Array(buffer, base, SLOT_WORDS);
    const bytes = new Uint8Array(buffer, base, 2048);
    const flags = i32[X_FLAGS]!;
    const side = (which: Side): SideDescriptor => {
      const at = X_SIDE + which * SIDE_WORDS;
      return {
        state: SIDE_STATES[i32[at + SIDE_STATE]!] ?? "absent",
        reason: (TRUNCATION_REASONS[i32[at + SIDE_REASON]!] || undefined) as
          TruncationReason | undefined,
        byteLength: i32[at + 3]!,
        words: { i32, at },
      };
    };
    return {
      sequence: i64[X_SEQUENCE]!,
      segmentHi: i64[X_SEGMENT]!,
      segmentLo: i64[X_SEGMENT + 1]!,
      startNs: i64[X_START_NS]!,
      endNs: i64[X_END_NS]!,
      responseState: RESPONSE_STATES[i32[X_RESPONSE_STATE]!] ?? "abandoned",
      withheld: (flags & FLAG_WITHHELD) !== 0,
      adopted: (flags & FLAG_ADOPTED) !== 0,
      exchangeId: bytes.slice(X_IDS, X_IDS + 16),
      eventId: bytes.slice(X_IDS + 16, X_IDS + 32),
      spanId: bytes.slice(X_IDS + 32, X_IDS + 40),
      parent:
        bytes[X_PARENT + 26] === 0
          ? undefined
          : {
              traceId: bytes.slice(X_PARENT, X_PARENT + 16),
              spanId: bytes.slice(X_PARENT + 16, X_PARENT + 24),
              flags: bytes[X_PARENT + 24]!,
              remote: bytes[X_PARENT + 25] === 1,
            },
      request: side(REQUEST),
      response: side(RESPONSE),
      meta: bytes.subarray(META_OFFSET),
    };
  }

  /** Active exchanges, process-wide. */
  get active(): number {
    return this.pool.inUse;
  }

  // ---------------------------------------------------------------------------- parts

  /** Allocates the slot's position; `false` when it was lost to a lock timeout. */
  private position(index: number, runSlot: number): boolean {
    const allocation = this.runtime.allocate(runSlot);
    const i64 = this.pool.i64;
    i64[index * SLOT_I64 + X_SEQUENCE] = allocation.sequence;
    i64[index * SLOT_I64 + X_SEGMENT] = allocation.segmentHi;
    i64[index * SLOT_I64 + X_SEGMENT + 1] = allocation.segmentLo;
    return !allocation.lost;
  }

  /** A new exchange uuid4, event uuid4 and span id, and the clean parent context. */
  private writeIds(index: number, parent: ParentContext | undefined): void {
    const random = this.random;
    randomFillSync(random);
    random[6] = (random[6]! & 0x0f) | 0x40;
    random[8] = (random[8]! & 0x3f) | 0x80;
    random[22] = (random[22]! & 0x0f) | 0x40;
    random[24] = (random[24]! & 0x3f) | 0x80;
    const bytes = this.pool.bytes;
    const base = index * 2048;
    bytes.set(random, base + X_IDS);
    if (parent === undefined || parent.traceId.length !== 16 || parent.spanId.length !== 8) return;
    bytes.set(parent.traceId, base + X_PARENT);
    bytes.set(parent.spanId, base + X_PARENT + 16);
    bytes[base + X_PARENT + 24] = parent.flags & 0xff;
    bytes[base + X_PARENT + 25] = parent.remote ? 1 : 0;
    bytes[base + X_PARENT + 26] = 1;
  }

  private loseSlot(index: number, reason: RuntimeLossReason): "lost" {
    const i64 = this.pool.i64;
    this.releaseSides(index);
    this.runtime.lose(
      reason,
      i64[index * SLOT_I64 + X_SEQUENCE]!,
      i64[index * SLOT_I64 + X_SEGMENT]!,
      i64[index * SLOT_I64 + X_SEGMENT + 1]!,
    );
    return "lost";
  }

  private releaseSides(index: number): void {
    const i32 = this.pool.i32;
    const at = index * SLOT_WORDS + X_SIDE;
    this.arena.release({ i32, at });
    this.arena.release({ i32, at: at + SIDE_WORDS });
  }

  /** Frees the slot under the next generation, so every old handle is stale. */
  private recycle(index: number): void {
    const i32 = this.pool.i32;
    const word = index * SLOT_WORDS;
    const generation = ((Atomics.load(i32, word) >>> 3) + 1) & 0x0fff_ffff;
    Atomics.store(i32, word, (generation << 3) | FREE);
    this.pool.free(index);
  }
}
