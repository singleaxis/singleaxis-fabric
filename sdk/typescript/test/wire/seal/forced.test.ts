// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §9.5 (unit 055-t10), §4.3 "Seal": a segment that reaches the forced bound
 * (1,000,000 positions; scaled down here) is sealed non-terminally and the run continues
 * in a new segment. The Fabric worker reads the run table's position counts each tick;
 * the roll itself is the run table's (`055-t11`), stood in for here by one locked step.
 */
import { describe, expect, it } from "vitest";

import { sealDigest } from "../../../src/wire/p1.js";
import { MAX_RUNS } from "../../../src/wire/runtime.js";
import { SegmentSeals, type SegmentSeal, observeRunTable } from "../../../src/wire/seal.js";
import { CapturePipeline, pipelineHandlers } from "../../../src/wire/worker.js";

import { isolate } from "../runtime/helpers.js";
import { RUN, SOURCE, openSegment, pipelineConfig, rollSegment, segment } from "./helpers.js";

const A = segment(1);
const B = segment(2);

describe("forced non-terminal seal", () => {
  it("seals a segment at the bound from the run table, exactly once, and the run continues", () => {
    const { runtime } = isolate();
    const built: SegmentSeal[] = [];
    const seals = new SegmentSeals({
      forcedAt: 5,
      sink: (_m, seal) => {
        built.push(seal);
        return true;
      },
    });
    const forced: string[] = [];
    seals.onForced = (segmentId) => {
      forced.push(segmentId);
      // The run table's step: move the run to a new segment and seal the old one with the
      // exact count it held when it moved (positions allocated past the bound included).
      const positions = rollSegment(runtime, 3, B.hi, B.lo);
      seals.requestSeal(segmentId, {
        lastSequence: runtime.nextSequence - 1n,
        terminal: false,
        resumable: true,
        runId: RUN,
        sourceId: SOURCE,
        epoch: runtime.epoch,
        positions,
      });
    };
    openSegment(runtime, 3, A.hi, A.lo);
    const inA = Array.from({ length: 7 }, () => runtime.allocate(3).sequence);
    observeRunTable(runtime, seals, 2); // slot 3 is not scanned: nothing yet
    expect(forced).toEqual([]);
    observeRunTable(runtime, seals, MAX_RUNS);
    observeRunTable(runtime, seals, MAX_RUNS);
    expect(forced).toEqual([A.id]);
    const inB = [runtime.allocate(3), runtime.allocate(3)];
    expect(inB.map((a) => [a.segmentHi, a.segmentLo])).toEqual([
      [B.hi, B.lo],
      [B.hi, B.lo],
    ]);
    // Settled out of order; the seal waits for all seven.
    const entries = inA.map((p) => [p, `loss:queue_full`] as [bigint, string]);
    for (const [p, entry] of [...entries].reverse()) {
      expect(built).toHaveLength(0);
      seals.settle(A.id, p, entry);
      seals.drain();
    }
    for (const a of inB) seals.settle(B.id, a.sequence, "loss:shutdown");
    seals.drain();
    expect(built).toHaveLength(1);
    expect(built[0]).toMatchObject({
      segmentId: A.id,
      terminal: false,
      resumable: true,
      runId: RUN,
      sealDigest: sealDigest(entries),
    });
    expect(seals.stats()).toMatchObject({ segment_forced_seal: 1, open_segments: 1 });
    expect(seals.entries(B.id)).toHaveLength(2);
  });

  it("forces a segment counted by noteAllocated, or reached only by settles, once", () => {
    const seals = new SegmentSeals({ forcedAt: 3 });
    const forced: string[] = [];
    seals.onForced = (id) => forced.push(id);
    for (let p = 0n; p < 5n; p++) seals.noteAllocated(A.id);
    for (let p = 10n; p < 14n; p++) seals.settle(B.id, p, "loss:queue_full");
    expect(forced).toEqual([A.id, B.id]);
    expect(seals.outstanding(A.id)).toBe(5);
  });

  it("an onForced that throws is counted and never escapes", () => {
    const seals = new SegmentSeals({ forcedAt: 1 });
    seals.onForced = () => {
      throw new Error("boom");
    };
    expect(() => seals.settle(A.id, 0n, "loss:queue_full")).not.toThrow();
    expect(seals.stats().internal_errors).toBe(1);
  });

  it("the pipeline's tick scans the run table with its configured bound", () => {
    const { runtime, table } = isolate();
    const spool = { writeBatch: () => [] } as never;
    const pipeline = new CapturePipeline(pipelineConfig({ forcedSealPositions: 4 }), spool, {
      lose: () => undefined,
    });
    expect(pipeline.seals.forcedAt).toBe(4);
    const forced: string[] = [];
    pipeline.seals.onForced = (id) => forced.push(id);
    openSegment(runtime, 0, A.hi, A.lo);
    for (let i = 0; i < 3; i++) runtime.allocate(0);
    const handlers = pipelineHandlers(pipeline);
    const context = { runtime, exchanges: table, snapshot: undefined };
    handlers.tick!(context);
    expect(forced).toEqual([]);
    runtime.allocate(0);
    handlers.tick!(context);
    expect(forced).toEqual([A.id]);
  });
});
