// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Visible capture loss (spec 055 §4.3 "Losses", §7.2; spec 050 §3.3, R3): the loss half
 * of Python's `_loss.py` and the spool `loss` entry of `wire/_spool.py`.
 *
 * {@link LossTable.record} is the single loss funnel of the Fabric worker: every lost
 * position, whatever its origin (an application isolate's `queue_full` or lock timeout,
 * the pipeline's `queue_full`/`disk_full`/`internal_error`, a `shutdown` at close), comes
 * through the runtime's loss ring to the worker's `loss` handler and then here. It settles
 * the position in its segment's seal (`loss:<reason>`) and keeps the range for the spool.
 *
 * R3: a range is keyed by `(source, epoch, reason, segment_id | undefined)`. Ranges of
 * different segments, reasons, sources or epochs never coalesce; a segment-attributed
 * range is exact (its count is its width), because concurrent runs interleave positions,
 * so only adjacent positions of one segment merge. A loss outside any run has no segment
 * and keeps one merged range per key (spec 047). Runs are distinct by segment: a segment
 * belongs to exactly one run.
 *
 * Also here: Python's `marker_span` for every marker kind but `manifest` (run markers,
 * `segment_seal`, heartbeats), so a spooled marker exports with its persisted event id.
 *
 * Nothing here does I/O except {@link LossTable.pump}, which writes to the spool on the
 * Fabric worker; nothing throws into a caller.
 */
import { compactInt } from "./codec.js";
import { lossEntry } from "./seal.js";
import type { Spool } from "./spool.js";

export const SPAN_LOSS = "fabric.capture_loss";
export const SPAN_HEARTBEAT = "fabric.capture_heartbeat";

/** Reasons a loss range may carry (Python `LossReason`; the spool accepts exactly these). */
export const LOSS_REASONS = [
  "queue_full",
  "internal_error",
  "shutdown",
  "span_dropped",
  "uninstrumented_client",
  "disk_full",
] as const;
export type LossReason = (typeof LOSS_REASONS)[number];
const REASONS: ReadonlySet<string> = new Set(LOSS_REASONS);
const SEGMENT_RE = /^seg-[0-9a-f]{32}$/;

/** Ranges held in memory before the spool takes them (Python `_MAX_PENDING_RANGES`). */
export const MAX_PENDING_RANGES = 1024;

/** One loss range: its key and `(first, last, count)`. */
export interface LossRange {
  readonly sourceId: string;
  readonly epoch: bigint;
  readonly reason: LossReason;
  /** Absent for a position allocated outside any run. */
  readonly segmentId: string | undefined;
  readonly first: bigint;
  readonly last: bigint;
  readonly count: bigint;
}

/**
 * `allocator.settle` (050 §3.3): a position's seal entry, `undefined` segment outside
 * runs, with the position's source and epoch (a segment settled only by losses still
 * names them on its seal).
 */
export type Settle = (
  segmentId: string | undefined,
  sequence: bigint,
  entry: string,
  sourceId: string,
  epoch: bigint,
) => void;

const minBig = (a: bigint, b: bigint): bigint => (a < b ? a : b);
const maxBig = (a: bigint, b: bigint): bigint => (a > b ? a : b);

/**
 * The `fabric.capture_loss` attributes of one range (Python `loss_attributes`), with
 * `fabric.run.segment_id` when it is segment-attributed (R3).
 */
export function lossAttributes(range: LossRange): Record<string, unknown> {
  const attrs: Record<string, unknown> = {
    "fabric.source_id": range.sourceId,
    "fabric.source.epoch": compactInt(range.epoch),
    "fabric.loss.reason": range.reason,
    "fabric.loss.count": compactInt(minBig(range.count, range.last - range.first + 1n)),
    "fabric.loss.first_sequence": compactInt(range.first),
    "fabric.loss.last_sequence": compactInt(range.last),
  };
  if (range.segmentId !== undefined) attrs["fabric.run.segment_id"] = range.segmentId;
  return attrs;
}

/** The spool `loss` entry of a range (Python `loss_doc`). */
export function lossDoc(range: LossRange): { doc: Record<string, unknown>; bodies: Uint8Array[] } {
  const loss: Record<string, unknown> = {
    reason: range.reason,
    first_sequence: compactInt(range.first),
    count: compactInt(minBig(range.count, range.last - range.first + 1n)),
    last_sequence: compactInt(range.last),
  };
  if (range.segmentId !== undefined) loss.segment_id = range.segmentId;
  return {
    doc: {
      record_kind: "loss",
      source: { source_id: range.sourceId, source_epoch: compactInt(range.epoch) },
      loss,
    },
    bodies: [],
  };
}

/** The range of a spool or ledger `loss` entry (Python `loss_range`, the inverse of {@link lossDoc}). */
export function lossFromDoc(doc: Readonly<Record<string, unknown>>): LossRange {
  const source = doc.source as Record<string, unknown>;
  const loss = doc.loss as Record<string, unknown>;
  const reason = loss.reason as string;
  if (!REASONS.has(reason)) throw new Error("loss reason outside the vocabulary");
  return {
    sourceId: source.source_id as string,
    epoch: BigInt(source.source_epoch as number | bigint),
    reason: reason as LossReason,
    segmentId: loss.segment_id as string | undefined,
    first: BigInt(loss.first_sequence as number | bigint),
    last: BigInt(loss.last_sequence as number | bigint),
    count: BigInt(loss.count as number | bigint),
  };
}

interface Pending {
  readonly key: Omit<LossRange, "first" | "last" | "count">;
  /** One merged range (no segment) or disjoint exact ranges sorted by first (a segment). */
  ranges: [bigint, bigint, bigint][];
}

/** Content-free counters of a {@link LossTable}. */
export interface LossStats {
  /** Positions recorded lost through {@link LossTable.record}. */
  readonly recorded: number;
  readonly byReason: Readonly<Record<LossReason, number>>;
  /** Ranges in memory, not yet spooled. */
  readonly pendingRanges: number;
  /** Ranges spooled. */
  readonly spooled: number;
  /** New ranges past {@link MAX_PENDING_RANGES}: only gaps, never explained. */
  readonly rangesDropped: number;
  readonly internalErrors: number;
}

/**
 * Coalesces loss ranges per `(source, epoch, reason, segment_id)` (Python `LossEmitter`'s
 * range table) and spools them. Lives in the Fabric worker.
 */
export class LossTable {
  #settle: Settle | undefined;
  readonly #pending = new Map<string, Pending>();
  #ranges = 0;
  #recorded = 0;
  readonly #byReason = Object.fromEntries(LOSS_REASONS.map((r) => [r, 0])) as Record<
    LossReason,
    number
  >;
  #spooled = 0;
  #dropped = 0;
  #errors = 0;

  constructor(options: { settle?: Settle } = {}) {
    this.#settle = options.settle;
  }

  /** The settle hook losses call (`undefined`: none); set at install, cleared after final. */
  setSettle(settle: Settle | undefined): void {
    this.#settle = settle;
  }

  /**
   * Count one position lost before it reached the record, and settle it in its
   * segment's seal (050 §3.3: the single loss funnel). `segmentId` is `undefined` for a
   * position allocated outside any run. Never throws.
   */
  record(
    sourceId: string,
    epoch: bigint,
    reason: LossReason,
    sequence: bigint,
    segmentId?: string,
  ): void {
    try {
      if (!REASONS.has(reason)) throw new Error("loss reason outside the vocabulary");
      if (segmentId !== undefined && !SEGMENT_RE.test(segmentId)) {
        throw new Error("segment id must be seg- + 32 hex");
      }
      this.#recorded++;
      this.#byReason[reason]++;
    } catch {
      this.#errors++;
      return;
    }
    try {
      this.#settle?.(segmentId, sequence, lossEntry(reason), sourceId, epoch);
    } catch {
      this.#errors++;
    }
    this.retain({ sourceId, epoch, reason, segmentId, first: sequence, last: sequence, count: 1n });
  }

  /**
   * Merges a range into the table (also: a range the spool could not take yet). A
   * segment-less key keeps one merged range (spec 047); a segment-attributed key merges
   * only touching ranges, so each stays exact and inside its segment (R3). Past the cap a
   * new range is only a gap (counted).
   */
  retain(range: LossRange): void {
    try {
      const id = `${range.sourceId}\u0000${range.epoch}\u0000${range.reason}\u0000${range.segmentId ?? ""}`;
      const found = this.#pending.get(id);
      if (found === undefined) {
        if (this.#ranges >= MAX_PENDING_RANGES) {
          this.#dropped++;
          return;
        }
        this.#pending.set(id, {
          key: {
            sourceId: range.sourceId,
            epoch: range.epoch,
            reason: range.reason,
            segmentId: range.segmentId,
          },
          ranges: [[range.first, range.last, range.count]],
        });
        this.#ranges++;
      } else if (range.segmentId === undefined) {
        const [low, high, total] = found.ranges[0]!;
        found.ranges[0] = [minBig(low, range.first), maxBig(high, range.last), total + range.count];
      } else {
        this.#mergeExact(found, [range.first, range.last, range.count]);
      }
    } catch {
      this.#errors++;
    }
  }

  #mergeExact(found: Pending, added: [bigint, bigint, bigint]): void {
    let [low, high, total] = added;
    const kept: [bigint, bigint, bigint][] = [];
    for (const [first, last, count] of found.ranges) {
      if (first <= high + 1n && low <= last + 1n) {
        low = minBig(low, first);
        high = maxBig(high, last);
        total += count;
      } else {
        kept.push([first, last, count]);
      }
    }
    if (kept.length + 1 > found.ranges.length && this.#ranges >= MAX_PENDING_RANGES) {
      this.#dropped++;
      return;
    }
    this.#ranges += kept.length + 1 - found.ranges.length;
    kept.push([low, high, total]);
    kept.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    found.ranges = kept;
  }

  /** Whether ranges wait in memory (not yet spooled). */
  get pending(): boolean {
    return this.#ranges > 0;
  }

  /** Takes every range, in key order of first loss, then ascending within a key. */
  take(): LossRange[] {
    const out: LossRange[] = [];
    for (const { key, ranges } of this.#pending.values()) {
      for (const [first, last, count] of ranges) out.push({ ...key, first, last, count });
    }
    this.#pending.clear();
    this.#ranges = 0;
    return out;
  }

  /**
   * Spools the pending ranges in order, into the spool's reserve (Python's sender writes
   * losses first). What is spooled is a prefix: at the first refused or failed record the
   * rest stay in memory for the next pump. `true` when nothing is left.
   */
  pump(spool: Pick<Spool, "writeBatch">): boolean {
    const ranges = this.take();
    let index = 0;
    for (; index < ranges.length; index++) {
      let result: unknown;
      try {
        [result] = spool.writeBatch([lossDoc(ranges[index]!)], true);
      } catch {
        result = undefined;
      }
      if (typeof result !== "string") break;
      this.#spooled++;
    }
    for (const range of ranges.slice(index)) this.retain(range);
    return index === ranges.length;
  }

  stats(): LossStats {
    return {
      recorded: this.#recorded,
      byReason: { ...this.#byReason },
      pendingRanges: this.#ranges,
      spooled: this.#spooled,
      rangesDropped: this.#dropped,
      internalErrors: this.#errors,
    };
  }
}

// ------------------------------------------------------------------- marker spans

const ROOT_FIELDS = ["session_id", "user_id", "parent_run_id", "resumed_from", "links"];
const ALL_FIELDS = [
  "run_id",
  "scope_id",
  "segment_id",
  "predecessors",
  "resumable",
  "open_deadline_s",
  "declared_branches",
  "branch_ids",
  "terminal",
  "seal",
  "manifest_id",
  "manifest_digest",
  "manifest_seq",
  "scope_status",
  "manifest",
  "event_id",
  "id_basis",
  ...ROOT_FIELDS,
  "outcome",
  "stop_reason",
  "identity",
];
const without = (drop: readonly string[]): ReadonlySet<string> =>
  new Set(ALL_FIELDS.filter((name) => !drop.includes(name)));
/** The marker fields each kind may carry (Python `_loss.MARKER_FIELDS`). */
export const MARKER_FIELDS: Readonly<Record<string, ReadonlySet<string>>> = {
  run_start: without(["terminal", "seal", "scope_status", "manifest", "outcome", "stop_reason"]),
  run_end: without([
    "predecessors",
    "resumable",
    "open_deadline_s",
    "declared_branches",
    "branch_ids",
    "terminal",
    "seal",
    "manifest",
    "id_basis",
    ...ROOT_FIELDS,
    "identity",
  ]),
  segment_seal: new Set([
    "run_id",
    "scope_id",
    "segment_id",
    "resumable",
    "terminal",
    "seal",
    "manifest_seq",
    "event_id",
  ]),
  final: new Set(["manifest_seq", "event_id"]),
  periodic: new Set(["manifest_seq", "event_id"]),
  manifest: new Set(["manifest", "event_id"]),
};
/** Marker field -> span attribute (registry telemetry keys; run-marker-v1), in Python's order. */
const SPAN_KEYS: readonly (readonly [string, string])[] = [
  ["run_id", "fabric.run.id"],
  ["scope_id", "fabric.run.scope_id"],
  ["segment_id", "fabric.run.segment_id"],
  ["predecessors", "fabric.run.predecessors"],
  ["resumable", "fabric.run.resumable"],
  ["open_deadline_s", "fabric.run.open_deadline_s"],
  ["declared_branches", "fabric.run.declared_branches"],
  ["branch_ids", "fabric.run.branch_ids"],
  ["terminal", "fabric.run.terminal"],
  ["manifest_id", "fabric.capture.manifest_id"],
  ["manifest_digest", "fabric.capture.manifest_digest"],
  ["manifest_seq", "fabric.capture.manifest_seq"],
  ["scope_status", "fabric.run.scope_status"],
  ["outcome", "fabric.run.outcome"],
  ["stop_reason", "fabric.run.stop_reason"],
  ["session_id", "fabric.session_id"],
  ["user_id", "fabric.user_id"],
  ["parent_run_id", "fabric.run.parent_id"],
  ["resumed_from", "fabric.run.resumed_from"],
  ["links", "fabric.run.links"],
  ["id_basis", "fabric.run.id_basis"],
  ["event_id", "fabric.event_id"],
];
const SEAL_KEYS: readonly (readonly [string, string])[] = [
  ["last_sequence", "fabric.segment.last_sequence"],
  ["manifest_digest", "fabric.segment.manifest_digest"],
  ["seal_digest", "fabric.segment.seal_digest"],
  ["branch_ids", "fabric.segment.branch_ids"],
];

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/**
 * `(span name, attributes)` of a non-manifest marker from its spool form (Python
 * `marker_span`): a `fabric.capture_heartbeat` with the run-marker-v1 keys placed by kind.
 * `fabric.event_id` is the persisted one; a marker without one exports none (never a
 * fresh one, which would differ on every replay).
 */
export function heartbeatSpan(
  sourceId: string,
  epoch: bigint,
  fields: Readonly<Record<string, unknown>>,
): [string, Record<string, unknown>] {
  const kind = fields.kind as string;
  const allowed = MARKER_FIELDS[kind];
  if (allowed === undefined || kind === "manifest") {
    throw new Error("a heartbeat span is built from a non-manifest marker");
  }
  const attrs: Record<string, unknown> = {
    "fabric.source_id": sourceId,
    "fabric.source.epoch": compactInt(epoch),
    "fabric.heartbeat.last_sequence": fields.last_sequence,
    "fabric.heartbeat.kind": kind,
  };
  for (const [name, key] of SPAN_KEYS) {
    const value = fields[name];
    if (allowed.has(name) && value !== undefined && value !== null) {
      attrs[key] = Array.isArray(value) ? [...value] : value;
    }
  }
  const seal = fields.seal;
  if (isObject(seal) && allowed.has("seal")) {
    for (const [name, key] of SEAL_KEYS) {
      const value = seal[name];
      if (value !== undefined && value !== null)
        attrs[key] = Array.isArray(value) ? [...value] : value;
    }
  }
  const identity = fields.identity;
  if (isObject(identity) && allowed.has("identity")) {
    for (const [name, value] of Object.entries(identity)) attrs[`fabric.${name}`] = value;
  }
  return [SPAN_HEARTBEAT, attrs];
}
