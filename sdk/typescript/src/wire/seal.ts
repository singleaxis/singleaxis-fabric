// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Segment seals (spec 055 §4.3 "Seal", §7.2; spec 050 §3.7): the seal accumulator the
 * Fabric worker's capture pipeline owns, a port of Python's `_seal.SegmentSeals`.
 *
 * The digests are `p1.ts`'s (`recordDigest`, `sealDigest`), pinned by the shared
 * `seal-digest-v1` and `seal-parity-v1` vectors, so the agent and `fabric.reconstruct`
 * can never disagree on the digest rule.
 *
 * What differs from Python, and why:
 * - Positions are allocated in application isolates (`WireRuntime.allocate`), which count
 *   them per run in the shared run table, and settled here, in the Fabric worker, once the
 *   record is spooled or the position is lost. So a seal request carries the number of
 *   positions its segment holds (`positions`, read with the segment under the run-table
 *   lock); the accumulator seals once that many distinct positions have settled.
 *   `noteAllocated` (Python's protocol) is kept for producers that allocate here.
 * - Everything here runs on the Fabric worker, never on an application thread, so there
 *   is no lock and no seal thread. A seal handed off is built by {@link drain}, which the
 *   worker calls from its tick with a time budget and at close, in hand-off order.
 * - A segment's settled entries are kept in columns (8-byte sequence, 1-byte kind, 32-byte
 *   digest), about 41 bytes a position, because a segment may hold up to
 *   {@link FORCED_SEAL_POSITIONS} of them (055 §4.3).
 *
 * Nothing here does I/O or throws into a caller; every failure is counted in
 * {@link SegmentSeals.stats}.
 */
import { createHash, randomUUID } from "node:crypto";

import { compactInt } from "./codec.js";
import { recordDigest } from "./p1.js";
import { SEGMENT_ID_RE, type SealEntry } from "./p1-types.js";

/** 055 §4.3: a segment this long is force-sealed (non-terminal; the run continues locally). */
export const FORCED_SEAL_POSITIONS = 1_000_000;
/** Seals handed off and not built yet: at most this many segments (Python's bound). */
export const MAX_PENDING_SEALS = 4096;
/**
 * ...and at most this many settled positions in all. One seal is always admitted when
 * none is waiting (a forced segment alone holds {@link FORCED_SEAL_POSITIONS}). Past a
 * bound the segment's state is dropped and counted (`seals_dropped`): no `segment_seal`
 * is written, so the verifier reports the segment unsealed, never complete.
 */
export const MAX_PENDING_SEAL_POSITIONS = 2 * FORCED_SEAL_POSITIONS;
/**
 * Open segments this accumulator keeps. A settle that would open one more is dropped and
 * counted (`segments_dropped`); that segment can then never seal complete.
 */
export const MAX_OPEN_SEGMENTS = 65_536;
/** Sealed (or dropped) segment ids remembered to tell a late settle from a new segment. */
const RECENT_SEGMENTS = 4096;
export const LOSS_ENTRY_PREFIX = "loss:";
export const DIGEST_PREFIX = "sha256:";
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const REASON_RE = /^[a-z][a-z_]{0,63}$/;
const BRANCH_ID_RE = /^br-[0-9a-f]{32}$/;
const MAX_BRANCHES = 64;
const HASH_SLICE = 4096;

/** The seal entry of a lost position: `loss:<reason>`. */
export function lossEntry(reason: string): SealEntry {
  return LOSS_ENTRY_PREFIX + reason;
}

const u64hex = (value: bigint): string => BigInt.asUintN(64, value).toString(16).padStart(16, "0");

/** The segment id of the run table's two 64-bit halves (`undefined` when both are zero). */
export function segmentIdOf(hi: bigint, lo: bigint): string | undefined {
  return hi === 0n && lo === 0n ? undefined : `seg-${u64hex(hi)}${u64hex(lo)}`;
}

/** The spool span of a written exchange, as far as its digest reads it. */
export interface DigestableSpan {
  readonly name: string;
  readonly start_time_unix_nano: bigint;
  readonly end_time_unix_nano: bigint;
  readonly status: string;
  readonly attributes: Readonly<Record<string, unknown>>;
}

/**
 * The seal entry of a written exchange (Python `wire/_pipeline._record_entry`): the record
 * digest over its span, with the stored request and response digests, in that order, as
 * its content.
 */
export function exchangeSealEntry(span: DigestableSpan): SealEntry {
  const attributes = span.attributes;
  const content: string[] = [];
  for (const key of ["fabric.wire.request_sha256", "fabric.wire.response_sha256"]) {
    const digest = attributes[key];
    if (typeof digest === "string") content.push(DIGEST_PREFIX + digest);
  }
  return recordDigest(
    {
      name: span.name,
      start_ns: span.start_time_unix_nano,
      end_ns: span.end_time_unix_nano,
      status: span.status,
      attributes,
    },
    content,
  );
}

// ------------------------------------------------------------------- settled entries

/** One segment's settled positions, in columns. Kind 0 is a digest, k > 0 a loss reason. */
class Entries {
  seqs = new BigInt64Array(8);
  kinds = new Uint8Array(8);
  digests = new Uint8Array(8 * 32);
  length = 0;
  /** `length` distinct positions in ascending order (no push since the last compaction). */
  compact = true;

  push(sequence: bigint, kind: number, digest: Uint8Array | undefined): void {
    if (this.length === this.seqs.length) this.#grow(this.length * 2);
    const at = this.length++;
    this.seqs[at] = sequence;
    this.kinds[at] = kind;
    if (digest !== undefined) this.digests.set(digest, at * 32);
    if (this.compact && at > 0 && this.seqs[at - 1]! >= sequence) this.compact = false;
  }

  #grow(size: number): void {
    const seqs = new BigInt64Array(size);
    seqs.set(this.seqs.subarray(0, this.length));
    const kinds = new Uint8Array(size);
    kinds.set(this.kinds.subarray(0, this.length));
    const digests = new Uint8Array(size * 32);
    digests.set(this.digests.subarray(0, this.length * 32));
    this.seqs = seqs;
    this.kinds = kinds;
    this.digests = digests;
  }

  /**
   * Sorts by sequence and keeps the first outcome of each position (one outcome per
   * position: the first wins, as in Python). Returns the number of distinct positions.
   */
  compactNow(): number {
    if (this.compact) return this.length;
    const n = this.length;
    const order = new Uint32Array(n);
    for (let i = 0; i < n; i++) order[i] = i;
    const seqs = this.seqs;
    // Stable on equal sequences (index order): the first settled outcome stays first.
    order.sort((a, b) => (seqs[a]! < seqs[b]! ? -1 : seqs[a]! > seqs[b]! ? 1 : a - b));
    const size = Math.max(8, n);
    const outSeqs = new BigInt64Array(size);
    const outKinds = new Uint8Array(size);
    const outDigests = new Uint8Array(size * 32);
    let kept = 0;
    for (let i = 0; i < n; i++) {
      const from = order[i]!;
      if (kept > 0 && outSeqs[kept - 1] === seqs[from]) continue;
      outSeqs[kept] = seqs[from]!;
      outKinds[kept] = this.kinds[from]!;
      outDigests.set(this.digests.subarray(from * 32, from * 32 + 32), kept * 32);
      kept++;
    }
    this.seqs = outSeqs;
    this.kinds = outKinds;
    this.digests = outDigests;
    this.length = kept;
    this.compact = true;
    return kept;
  }
}

// ----------------------------------------------------------------------- the request

/** A `segment_seal` request (Python `request_seal`, plus `positions` and the marker's ids). */
export interface SealRequest {
  /** The allocator's last position at the seal (Python `_seal`). */
  readonly lastSequence: bigint;
  readonly manifestDigest?: string;
  readonly terminal: boolean;
  /** Absent: the marker carries no `resumable` (Python writes a field only when set). */
  readonly resumable?: boolean;
  readonly branchIds?: readonly string[];
  readonly runId?: string;
  readonly scopeId?: string;
  readonly sourceId?: string;
  readonly epoch?: bigint;
  /**
   * Positions the segment holds (the run table's count, read with the segment). Absent:
   * the positions {@link SegmentSeals.noteAllocated} counted.
   */
  readonly positions?: bigint | number;
  /** `manifest_seq` of the manifest in force; absent: the accumulator's `manifestSeq`. */
  readonly manifestSeq?: number;
}

/** A built seal: what its `segment_seal` marker carries. */
export interface SegmentSeal {
  readonly sourceId: string;
  readonly epoch: bigint;
  readonly segmentId: string;
  readonly runId: string | undefined;
  readonly scopeId: string | undefined;
  readonly lastSequence: bigint;
  readonly manifestDigest: string | undefined;
  readonly sealDigest: string;
  readonly branchIds: readonly string[];
  readonly terminal: boolean;
  readonly resumable: boolean | undefined;
  readonly manifestSeq: number | undefined;
  /** uuid4, minted once when the seal is built and persisted with its marker (R2). */
  readonly eventId: string;
}

/**
 * The `marker` object of a seal (Python `marker_fields` for `segment_seal`): only the
 * fields the kind may carry, and only those set. The spool sorts keys when it writes.
 */
export function sealFields(seal: SegmentSeal): Record<string, unknown> {
  const fields: Record<string, unknown> = {
    kind: "segment_seal",
    last_sequence: compactInt(seal.lastSequence),
  };
  if (seal.manifestSeq !== undefined) fields.manifest_seq = seal.manifestSeq;
  if (seal.resumable !== undefined) fields.resumable = seal.resumable;
  if (seal.runId !== undefined) fields.run_id = seal.runId;
  if (seal.scopeId !== undefined) fields.scope_id = seal.scopeId;
  fields.segment_id = seal.segmentId;
  fields.terminal = seal.terminal;
  const body: Record<string, unknown> = {
    last_sequence: compactInt(seal.lastSequence),
    seal_digest: seal.sealDigest,
  };
  if (seal.manifestDigest !== undefined) body.manifest_digest = seal.manifestDigest;
  if (seal.branchIds.length > 0) body.branch_ids = [...seal.branchIds];
  fields.seal = body;
  fields.event_id = seal.eventId;
  return fields;
}

/** The spool `marker` entry of a seal (Python `marker_doc`). */
export function sealMarker(seal: SegmentSeal): {
  doc: Record<string, unknown>;
  bodies: Uint8Array[];
} {
  return {
    doc: {
      record_kind: "marker",
      source: { source_id: seal.sourceId, source_epoch: compactInt(seal.epoch) },
      marker: sealFields(seal),
    },
    bodies: [],
  };
}

// ------------------------------------------------------------------- the accumulator

interface Segment {
  entries: Entries;
  /** `noteAllocated` calls (positions allocated here, Python's outstanding + settled). */
  noted: number;
  request: SealRequest | undefined;
  runId: string | undefined;
  scopeId: string | undefined;
  source: readonly [string, bigint] | undefined;
  forced: boolean;
}

interface Ready {
  readonly segmentId: string;
  readonly segment: Segment;
  readonly request: SealRequest;
}

/** Where built seals go: `true` when queued (`MarkerQueue.queue`). */
export type SealSink = (marker: ReturnType<typeof sealMarker>, seal: SegmentSeal) => boolean;

export interface SealOptions {
  readonly sink?: SealSink;
  /** `(source_id, epoch)` of the allocator served, for a seal that names neither. */
  readonly source?: () => readonly [string, bigint] | undefined;
  /** `manifest_seq` in force for an epoch (`ManifestChain.latestSeq`). */
  readonly manifestSeq?: (epoch: bigint) => number | undefined;
  /** The forced-seal bound (tests scale it down). */
  readonly forcedAt?: number;
  readonly maxPendingSeals?: number;
  readonly maxPendingPositions?: number;
  readonly maxOpenSegments?: number;
  readonly newId?: () => string;
}

export type SealStatName =
  | "sealed"
  | "seal_markers_unqueued"
  | "segment_forced_seal"
  | "late_settles"
  | "internal_errors"
  | "seals_dropped"
  | "segments_dropped";

/** Content-free counters, open segments and seals waiting to be built. */
export type SealStats = Readonly<Record<SealStatName, number>> & {
  readonly open_segments: number;
  readonly seals_pending: number;
  readonly seals_waiting: number;
};

/**
 * The capture pipeline's seal accumulator (050 §3.7): per open segment, one entry per
 * settled position and the seal request. A segment seals once it has a request and as
 * many distinct settled positions as it holds; it is then forgotten here and handed to
 * the build queue, which {@link drain} empties in hand-off order, queueing each
 * `segment_seal` marker to the sink.
 */
export class SegmentSeals {
  /** Called once when a segment reaches the forced bound: seal it non-terminally. */
  onForced: ((segmentId: string) => void) | undefined;
  #sink: SealSink | undefined;
  readonly #source: (() => readonly [string, bigint] | undefined) | undefined;
  readonly #manifestSeq: ((epoch: bigint) => number | undefined) | undefined;
  readonly #forcedAt: number;
  readonly #maxPending: number;
  readonly #maxPendingPositions: number;
  readonly #maxOpen: number;
  readonly #newId: () => string;
  readonly #segments = new Map<string, Segment>();
  readonly #ready: Ready[] = [];
  #readyHead = 0;
  #readyPositions = 0;
  #droppedSinceDrain = false;
  /** Sealed or dropped ids (late settles) and forced ids, each bounded, oldest first. */
  readonly #recent = new Set<string>();
  readonly #forced = new Set<string>();
  /** Loss reasons by kind code (1-based); a reason is interned once. */
  readonly #reasons: string[] = [];
  readonly #reasonCodes = new Map<string, number>();
  readonly #stats: Record<SealStatName, number> = {
    sealed: 0,
    seal_markers_unqueued: 0,
    segment_forced_seal: 0,
    late_settles: 0,
    internal_errors: 0,
    seals_dropped: 0,
    segments_dropped: 0,
  };

  constructor(options: SealOptions = {}) {
    this.#sink = options.sink;
    this.#source = options.source;
    this.#manifestSeq = options.manifestSeq;
    this.#forcedAt = options.forcedAt ?? FORCED_SEAL_POSITIONS;
    this.#maxPending = options.maxPendingSeals ?? MAX_PENDING_SEALS;
    this.#maxPendingPositions = options.maxPendingPositions ?? MAX_PENDING_SEAL_POSITIONS;
    this.#maxOpen = options.maxOpenSegments ?? MAX_OPEN_SEGMENTS;
    this.#newId = options.newId ?? randomUUID;
  }

  /** The forced-seal bound in force. */
  get forcedAt(): number {
    return this.#forcedAt;
  }

  setSink(sink: SealSink | undefined): void {
    this.#sink = sink;
  }

  // ------------------------------------------------------------------ the protocol

  #open(segmentId: string): Segment | undefined {
    let segment = this.#segments.get(segmentId);
    if (segment !== undefined) return segment;
    if (!SEGMENT_ID_RE.test(segmentId)) throw new Error("segment id must be seg- + 32 hex");
    if (this.#segments.size >= this.#maxOpen) {
      this.#stats.segments_dropped++;
      this.#remember(this.#recent, segmentId);
      return undefined;
    }
    segment = {
      entries: new Entries(),
      noted: 0,
      request: undefined,
      runId: undefined,
      scopeId: undefined,
      source: undefined,
      forced: this.#forced.has(segmentId),
    };
    this.#segments.set(segmentId, segment);
    return segment;
  }

  #remember(set: Set<string>, segmentId: string): void {
    set.delete(segmentId);
    set.add(segmentId);
    if (set.size > RECENT_SEGMENTS) set.delete(set.values().next().value as string);
  }

  /** The pipeline saw a job of `segmentId`: remember its source and run. */
  noteJob(
    segmentId: string,
    sourceId: string,
    epoch: bigint,
    runId?: string,
    scopeId?: string,
  ): void {
    try {
      if (this.#recent.has(segmentId)) return;
      const segment = this.#open(segmentId);
      if (segment === undefined) return;
      segment.source ??= [sourceId, epoch];
      segment.runId ??= runId;
      segment.scopeId ??= scopeId;
    } catch {
      this.#stats.internal_errors++;
    }
  }

  /**
   * One more position allocated in `segmentId` (producers that allocate in this isolate;
   * Python's `note_allocated(segment_id, sequence)`, whose sequence is not needed here).
   */
  noteAllocated(segmentId: string): void {
    try {
      if (this.#recent.has(segmentId)) return;
      const segment = this.#open(segmentId);
      if (segment === undefined) return;
      segment.noted++;
      this.#checkForced(segmentId, segment, Math.max(segment.noted, segment.entries.length));
    } catch {
      this.#stats.internal_errors++;
    }
  }

  /**
   * The run table holds `positions` in `segmentId` (the Fabric worker reads it each tick,
   * {@link observeRunTable}): at the forced bound, {@link onForced} is called once.
   */
  observePositions(segmentId: string, positions: bigint | number): void {
    try {
      if (this.#forced.has(segmentId) || BigInt(positions) < BigInt(this.#forcedAt)) return;
      this.#force(segmentId, this.#segments.get(segmentId));
    } catch {
      this.#stats.internal_errors++;
    }
  }

  #checkForced(segmentId: string, segment: Segment, size: number): void {
    if (!segment.forced && size >= this.#forcedAt) this.#force(segmentId, segment);
  }

  #force(segmentId: string, segment: Segment | undefined): void {
    if (this.#forced.has(segmentId) || segment?.forced === true) return;
    if (segment !== undefined) segment.forced = true;
    this.#remember(this.#forced, segmentId);
    this.#stats.segment_forced_seal++;
    try {
      this.onForced?.(segmentId);
    } catch {
      this.#stats.internal_errors++;
    }
  }

  /**
   * One position of `segmentId` settled: written (its record digest) or lost
   * (`loss:<reason>`). Call it only after the record is in the spool. The first outcome
   * of a position wins; a settle for a segment already sealed is counted (`late_settles`).
   */
  settle(segmentId: string, sequence: bigint, entry: SealEntry): void {
    try {
      let kind: number;
      let digest: Uint8Array | undefined;
      if (DIGEST_RE.test(entry)) {
        kind = 0;
        digest = Buffer.from(entry.slice(DIGEST_PREFIX.length), "hex");
      } else if (entry.startsWith(LOSS_ENTRY_PREFIX)) {
        kind = this.#reasonCode(entry.slice(LOSS_ENTRY_PREFIX.length));
      } else {
        throw new Error("a seal entry is a record digest or loss:<reason>");
      }
      if (this.#recent.has(segmentId)) {
        this.#stats.late_settles++;
        return;
      }
      const segment = this.#open(segmentId);
      if (segment === undefined) return;
      segment.entries.push(sequence, kind, digest);
      this.#checkForced(segmentId, segment, segment.entries.length);
      this.#handOff(segmentId, segment);
    } catch {
      this.#stats.internal_errors++;
    }
  }

  #reasonCode(reason: string): number {
    let code = this.#reasonCodes.get(reason);
    if (code !== undefined) return code;
    if (!REASON_RE.test(reason) || this.#reasons.length >= 255) {
      throw new Error("a loss reason is a lower-case word");
    }
    this.#reasons.push(reason);
    code = this.#reasons.length;
    this.#reasonCodes.set(reason, code);
    return code;
  }

  /**
   * Seal `segmentId` once every position it holds has settled. The digest is built by
   * {@link drain}. A segment with no position (zero-width, `endRun`) seals `[]`.
   */
  requestSeal(segmentId: string, request: SealRequest): void {
    try {
      const branches = request.branchIds ?? [];
      if (branches.length > MAX_BRANCHES || !branches.every((b) => BRANCH_ID_RE.test(b))) {
        throw new Error("branch ids must be br- + 32 hex, at most 64");
      }
      if (this.#recent.has(segmentId)) {
        this.#stats.late_settles++;
        return;
      }
      const segment = this.#open(segmentId);
      if (segment === undefined) return;
      segment.request = request;
      this.#handOff(segmentId, segment);
    } catch {
      this.#stats.internal_errors++;
    }
  }

  #expected(segment: Segment): bigint {
    const positions = segment.request?.positions;
    return positions === undefined ? BigInt(segment.noted) : BigInt(positions);
  }

  /** When the segment can seal now: forget it and queue it for {@link drain}. */
  #handOff(segmentId: string, segment: Segment): void {
    if (segment.request === undefined) return;
    const expected = this.#expected(segment);
    if (BigInt(segment.entries.length) < expected) return;
    if (BigInt(segment.entries.compactNow()) < expected) return;
    this.#segments.delete(segmentId);
    this.#remember(this.#recent, segmentId);
    const positions = segment.entries.length;
    const waiting = this.#ready.length - this.#readyHead;
    if (
      waiting > 0 &&
      (waiting >= this.#maxPending || this.#readyPositions + positions > this.#maxPendingPositions)
    ) {
      // Fail open: the state goes and the missing seal is counted; nothing waits.
      this.#stats.seals_dropped++;
      this.#droppedSinceDrain = true;
      return;
    }
    this.#ready.push({ segmentId, segment, request: segment.request });
    this.#readyPositions += positions;
  }

  /**
   * Builds the handed-off seals in order and queues their markers, until `budgetMs`
   * passes (the worker's tick) or none is left (close). `false` when one is still
   * waiting, or when a seal was dropped at the pending bound since the previous drain
   * ({@link dropped} keeps the total). Never throws.
   */
  drain(budgetMs = Number.POSITIVE_INFINITY): boolean {
    const deadline = performance.now() + Math.max(0, budgetMs);
    try {
      while (this.#readyHead < this.#ready.length) {
        const ready = this.#ready[this.#readyHead]!;
        this.#ready[this.#readyHead] = undefined as never;
        this.#readyHead++;
        this.#readyPositions -= ready.segment.entries.length;
        try {
          this.#emit(ready);
        } catch {
          this.#stats.internal_errors++;
        }
        if (performance.now() >= deadline) break;
      }
      if (this.#readyHead === this.#ready.length) {
        this.#ready.length = 0;
        this.#readyHead = 0;
      }
    } catch {
      this.#stats.internal_errors++;
      return false;
    }
    if (this.#readyHead < this.#ready.length) return false;
    const dropped = this.#droppedSinceDrain;
    this.#droppedSinceDrain = false;
    return !dropped;
  }

  /** Seals dropped at the pending bound since this accumulator started (sticky). */
  dropped(): number {
    return this.#stats.seals_dropped;
  }

  /** Segments with a seal request whose positions have not all settled. */
  waiting(): string[] {
    const out: string[] = [];
    for (const [id, segment] of this.#segments) if (segment.request !== undefined) out.push(id);
    return out;
  }

  /** Positions of `segmentId` not settled yet (the request's or the noted count). */
  outstanding(segmentId: string): number {
    const segment = this.#segments.get(segmentId);
    if (segment === undefined) return 0;
    const expected = this.#expected(segment);
    const settled = BigInt(segment.entries.compactNow());
    return expected > settled ? Number(expected - settled) : 0;
  }

  /** The settled entries of an open segment, sorted (tests, diagnostics). */
  entries(segmentId: string): [bigint, SealEntry][] {
    const segment = this.#segments.get(segmentId);
    if (segment === undefined) return [];
    segment.entries.compactNow();
    return this.#expand(segment.entries);
  }

  #expand(entries: Entries): [bigint, SealEntry][] {
    const out: [bigint, SealEntry][] = [];
    for (let i = 0; i < entries.length; i++)
      out.push([entries.seqs[i]!, this.#entryText(entries, i)]);
    return out;
  }

  #entryText(entries: Entries, i: number): SealEntry {
    const kind = entries.kinds[i]!;
    if (kind === 0) {
      return (
        DIGEST_PREFIX + Buffer.from(entries.digests.subarray(i * 32, i * 32 + 32)).toString("hex")
      );
    }
    return LOSS_ENTRY_PREFIX + this.#reasons[kind - 1]!;
  }

  stats(): SealStats {
    return {
      ...this.#stats,
      open_segments: this.#segments.size,
      seals_pending: this.#ready.length - this.#readyHead,
      seals_waiting: this.waiting().length,
    };
  }

  // ---------------------------------------------------------------------- building

  /**
   * `sha256:` over the canonical JSON of the sorted `[sequence, entry]` pairs, hashed in
   * slices (equal to `p1.sealDigest` byte for byte: an entry is ASCII hex or a lower-case
   * reason, so it needs no escaping, and an integer is its decimal text).
   */
  #digest(entries: Entries): string {
    const hash = createHash("sha256");
    hash.update("[");
    for (let start = 0; start < entries.length; start += HASH_SLICE) {
      const end = Math.min(entries.length, start + HASH_SLICE);
      let text = "";
      for (let i = start; i < end; i++) {
        text += `${i === 0 ? "" : ","}[${entries.seqs[i]!.toString()},"${this.#entryText(entries, i)}"]`;
      }
      hash.update(text);
    }
    hash.update("]");
    return DIGEST_PREFIX + hash.digest("hex");
  }

  #emit({ segmentId, segment, request }: Ready): void {
    segment.entries.compactNow();
    const digest = this.#digest(segment.entries);
    const source =
      request.sourceId !== undefined && request.epoch !== undefined
        ? ([request.sourceId, request.epoch] as const)
        : (segment.source ?? this.#source?.());
    this.#stats.sealed++;
    const runId = request.runId ?? segment.runId;
    if (source === undefined || runId === undefined) {
      // A seal no marker can carry (a segment_seal names its run): counted, never spooled
      // to be refused on read. The verifier reports the segment unsealed.
      this.#stats.seal_markers_unqueued++;
      return;
    }
    const seal: SegmentSeal = {
      sourceId: source[0],
      epoch: source[1],
      segmentId,
      runId,
      scopeId: request.scopeId ?? segment.scopeId,
      lastSequence: request.lastSequence,
      manifestDigest: request.manifestDigest,
      sealDigest: digest,
      branchIds: [...(request.branchIds ?? [])],
      terminal: request.terminal,
      resumable: request.resumable,
      manifestSeq: request.manifestSeq ?? this.#manifestSeq?.(source[1]),
      eventId: this.#newId(),
    };
    const sink = this.#sink;
    let queued: boolean;
    try {
      queued = sink !== undefined && sink(sealMarker(seal), seal);
    } catch {
      queued = false;
    }
    if (!queued) this.#stats.seal_markers_unqueued++;
  }
}

/** What {@link observeRunTable} reads of the shared runtime. */
export interface RunTableView {
  runSegment(runSlot: number): readonly [bigint, bigint];
  runPositions(runSlot: number): bigint;
}

/**
 * The Fabric worker's tick: each run slot's open segment and its position count, so a
 * segment that reached the forced bound is sealed non-terminally (spec 055 §4.3). The
 * run-table owner (`055-t11`) rolls the segment in {@link SegmentSeals.onForced}.
 */
export function observeRunTable(runtime: RunTableView, seals: SegmentSeals, runs: number): void {
  for (let slot = 0; slot < runs; slot++) {
    try {
      const [hi, lo] = runtime.runSegment(slot);
      const segmentId = segmentIdOf(hi, lo);
      if (segmentId === undefined) continue;
      const positions = runtime.runPositions(slot);
      if (positions >= BigInt(seals.forcedAt)) seals.observePositions(segmentId, positions);
    } catch {
      // one slot that cannot be read never stops the scan
    }
  }
}
