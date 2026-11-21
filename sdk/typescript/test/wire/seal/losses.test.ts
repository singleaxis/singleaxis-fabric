// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §9.5 (unit 055-t10), §4.3 "Losses" (R3): loss ranges keyed by segment never
 * coalesce across segments, reasons, sources, epochs or runs; a segment-attributed range
 * is exact; a loss outside any run keeps one merged range (spec 047). The spooled loss
 * records are the ones Python's drainer reads, with the same `fabric.capture_loss`
 * attributes.
 */
import { afterAll, describe, expect, it } from "vitest";

import {
  LossTable,
  MAX_PENDING_RANGES,
  type LossRange,
  lossAttributes,
  lossDoc,
  lossFromDoc,
} from "../../../src/wire/loss.js";
import { Spool } from "../../../src/wire/spool.js";

import { norm } from "../helpers.js";
import { KEY, cleanupDirs, native, spoolDir } from "../spool/helpers.js";
import { SOURCE, pythonReads, segment } from "./helpers.js";

afterAll(() => cleanupDirs());

const A = segment(1).id;
const B = segment(2).id;
const OTHER = "s-" + "ef".repeat(16);

const shape = (ranges: LossRange[]) =>
  ranges.map((r) => [r.sourceId, r.epoch, r.reason, r.segmentId ?? null, r.first, r.last, r.count]);

describe("loss ranges (R3)", () => {
  it("never coalesce across segments, even for interleaved adjacent positions", () => {
    const table = new LossTable();
    // Two concurrent runs interleave positions 1..6; each segment's losses stay its own.
    for (const [p, seg] of [
      [1n, A],
      [2n, B],
      [3n, A],
      [4n, B],
      [5n, B],
      [6n, A],
    ] as const) {
      table.record(SOURCE, 9n, "queue_full", p, seg);
    }
    expect(shape(table.take())).toEqual([
      [SOURCE, 9n, "queue_full", A, 1n, 1n, 1n],
      [SOURCE, 9n, "queue_full", A, 3n, 3n, 1n],
      [SOURCE, 9n, "queue_full", A, 6n, 6n, 1n],
      [SOURCE, 9n, "queue_full", B, 2n, 2n, 1n],
      [SOURCE, 9n, "queue_full", B, 4n, 5n, 2n],
    ]);
  });

  it("never coalesce across reasons, sources or epochs", () => {
    const table = new LossTable();
    table.record(SOURCE, 9n, "queue_full", 1n, A);
    table.record(SOURCE, 9n, "disk_full", 2n, A);
    table.record(OTHER, 9n, "queue_full", 3n, A);
    table.record(SOURCE, 10n, "queue_full", 4n, A);
    table.record(SOURCE, 9n, "shutdown", 5n, A);
    const ranges = table.take();
    expect(ranges).toHaveLength(5);
    expect(ranges.every((r) => r.count === 1n && r.first === r.last)).toBe(true);
  });

  it("never coalesce across runs: each run's segment, and a loss outside any run, stay apart", () => {
    const table = new LossTable();
    // Run 1 owns segment A, run 2 segment B; positions 7 and 9 fall outside any run.
    table.record(SOURCE, 9n, "internal_error", 6n, A);
    table.record(SOURCE, 9n, "internal_error", 7n);
    table.record(SOURCE, 9n, "internal_error", 8n, B);
    table.record(SOURCE, 9n, "internal_error", 9n);
    expect(shape(table.take())).toEqual([
      [SOURCE, 9n, "internal_error", A, 6n, 6n, 1n],
      [SOURCE, 9n, "internal_error", null, 7n, 9n, 2n],
      [SOURCE, 9n, "internal_error", B, 8n, 8n, 1n],
    ]);
  });

  it("merges touching positions of one segment into one exact range, in any order", () => {
    const table = new LossTable();
    for (const p of [5n, 3n, 4n, 9n, 8n, 7n, 6n]) table.record(SOURCE, 9n, "shutdown", p, A);
    expect(shape(table.take())).toEqual([[SOURCE, 9n, "shutdown", A, 3n, 9n, 7n]]);
  });

  it("settles each lost position in its own segment's seal (the single funnel)", () => {
    const settled: [string | undefined, bigint, string, string, bigint][] = [];
    const table = new LossTable({ settle: (...args) => settled.push(args) });
    table.record(SOURCE, 9n, "queue_full", 1n, A);
    table.record(SOURCE, 9n, "disk_full", 2n);
    expect(settled).toEqual([
      [A, 1n, "loss:queue_full", SOURCE, 9n],
      [undefined, 2n, "loss:disk_full", SOURCE, 9n],
    ]);
    table.setSettle(undefined);
    table.record(SOURCE, 9n, "queue_full", 3n, A);
    expect(settled).toHaveLength(2);
    expect(table.stats()).toMatchObject({ recorded: 3, byReason: { queue_full: 2, disk_full: 1 } });
  });

  it("refuses a malformed reason or segment and never throws", () => {
    const table = new LossTable();
    table.record(SOURCE, 9n, "nope" as never, 1n, A);
    table.record(SOURCE, 9n, "queue_full", 1n, "seg-xyz");
    expect(table.pending).toBe(false);
    expect(table.stats().internalErrors).toBe(2);
  });

  it("holds at most MAX_PENDING_RANGES ranges; a new one past it is only a counted gap", () => {
    const table = new LossTable();
    for (let i = 0; i < MAX_PENDING_RANGES + 5; i++) {
      table.record(SOURCE, 9n, "queue_full", BigInt(i * 2), A);
    }
    expect(table.stats()).toMatchObject({ pendingRanges: MAX_PENDING_RANGES, rangesDropped: 5 });
    // A position that only extends an existing range still merges.
    table.record(SOURCE, 9n, "queue_full", 1n, A);
    expect(table.stats().pendingRanges).toBe(MAX_PENDING_RANGES - 1);
  });

  it("round-trips the spool loss entry", () => {
    const range: LossRange = {
      sourceId: SOURCE,
      epoch: 4611686018427387905n,
      reason: "queue_full",
      segmentId: A,
      first: 6n,
      last: 7n,
      count: 2n,
    };
    expect(lossFromDoc(lossDoc(range).doc)).toEqual(range);
    expect(lossAttributes(range)).toMatchObject({
      "fabric.run.segment_id": A,
      "fabric.loss.count": 2,
    });
    const unattributed = { ...range, segmentId: undefined };
    expect("segment_id" in (lossDoc(unattributed).doc.loss as object)).toBe(false);
    expect("fabric.run.segment_id" in lossAttributes(unattributed)).toBe(false);
  });
});

// Python subprocesses: slow on a loaded runner.
describe("spooled loss records", { timeout: 60_000 }, () => {
  it("are what Python's drainer reads, with the same capture_loss attributes", () => {
    const dir = spoolDir();
    const spool = new Spool(dir, { maxBytes: 1 << 20, addon: native().addon, key: KEY });
    const table = new LossTable();
    table.record(SOURCE, 9n, "queue_full", 1n, A);
    table.record(SOURCE, 9n, "queue_full", 2n, A);
    table.record(SOURCE, 9n, "queue_full", 3n, B);
    table.record(SOURCE, 9n, "shutdown", 4n);
    const expected = [
      lossAttributes({
        sourceId: SOURCE,
        epoch: 9n,
        reason: "queue_full",
        segmentId: A,
        first: 1n,
        last: 2n,
        count: 2n,
      }),
      lossAttributes({
        sourceId: SOURCE,
        epoch: 9n,
        reason: "queue_full",
        segmentId: B,
        first: 3n,
        last: 3n,
        count: 1n,
      }),
      lossAttributes({
        sourceId: SOURCE,
        epoch: 9n,
        reason: "shutdown",
        segmentId: undefined,
        first: 4n,
        last: 4n,
        count: 1n,
      }),
    ];
    expect(table.pump(spool)).toBe(true);
    expect(table.pending).toBe(false);
    expect(table.stats().spooled).toBe(3);
    const read = pythonReads(dir);
    expect(read.map((r) => [r.kind, r.ok])).toEqual([
      ["loss", true],
      ["loss", true],
      ["loss", true],
    ]);
    expect(norm(read.map((r) => r.loss))).toEqual(norm(expected));
    spool.close();
  });

  it("keep what the spool refused, in order, for the next pump", () => {
    const table = new LossTable();
    table.record(SOURCE, 9n, "queue_full", 1n, A);
    table.record(SOURCE, 9n, "queue_full", 5n, A);
    table.record(SOURCE, 9n, "disk_full", 2n, B);
    let budget = 1;
    const written: unknown[] = [];
    const spool = {
      writeBatch: (records: readonly { doc: Record<string, unknown> }[]) => {
        if (budget-- <= 0) return [new Error("full")];
        written.push(records[0]!.doc.loss);
        return ["a.rec"];
      },
    };
    expect(table.pump(spool as never)).toBe(false);
    expect(written).toHaveLength(1);
    expect(table.stats().pendingRanges).toBe(2);
    budget = 10;
    expect(table.pump(spool as never)).toBe(true);
    expect(norm(written)).toEqual(
      norm([
        { reason: "queue_full", first_sequence: 1, count: 1, last_sequence: 1, segment_id: A },
        { reason: "queue_full", first_sequence: 5, count: 1, last_sequence: 5, segment_id: A },
        { reason: "disk_full", first_sequence: 2, count: 1, last_sequence: 2, segment_id: B },
      ]),
    );
  });
});
