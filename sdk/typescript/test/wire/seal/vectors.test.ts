// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §9.5 (unit 055-t10): the shared `seal-digest-v1` and `seal-parity-v1` vectors
 * through the seal accumulator and the loss funnel, not only through the pure functions
 * (`test/wire/codec/p1-vectors.test.ts` covers those).
 */
import { randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import { LossTable, heartbeatSpan, lossAttributes } from "../../../src/wire/loss.js";
import { recordContent, recordDigest, sealDigest } from "../../../src/wire/p1.js";
import {
  FORCED_SEAL_POSITIONS,
  SegmentSeals,
  type SegmentSeal,
  exchangeSealEntry,
  sealFields,
} from "../../../src/wire/seal.js";

import { cases, norm, vector } from "../helpers.js";

const SOURCE = "s-b94f348e8d6890782b2af72c847dc77b";
const EPOCH = 4611686018427387905n;
const RUN = "r-93347307304ecb0a9bb1b51ae90ac326";

/** An accumulator whose built seals are collected, and a loss funnel that settles into it. */
function harness(options: { newId?: () => string } = {}) {
  const built: SegmentSeal[] = [];
  const seals = new SegmentSeals({
    sink: (_marker, seal) => {
      built.push(seal);
      return true;
    },
    newId: options.newId,
  });
  const losses = new LossTable({
    settle: (segmentId, sequence, entry, sourceId, epoch) => {
      if (segmentId === undefined) return;
      seals.noteJob(segmentId, sourceId, epoch);
      seals.settle(segmentId, sequence, entry);
    },
  });
  return { built, seals, losses };
}

describe("seal-digest-v1 through the accumulator", () => {
  const doc = vector("seal-digest-v1");
  const digests = new Map<string, string>(
    doc.records.map((r: any) => [
      r.name,
      recordDigest(
        r.span,
        recordContent(r.kind, r.descriptors, r.span.attributes["fabric.content.object_ids"] ?? []),
      ),
    ]),
  );

  it.each(cases(doc.segments, "name"))("segment: %s", (_name, c: any) => {
    const { built, seals, losses } = harness();
    // Records settle with their digests; every loss of the case goes through the funnel,
    // one position at a time, whatever segment it names (or none).
    for (const [sequence, name] of c.records) {
      seals.noteJob(c.segment_id, SOURCE, EPOCH, RUN);
      seals.settle(c.segment_id, BigInt(sequence), digests.get(name)!);
    }
    for (const loss of c.losses) {
      for (let p = BigInt(loss.first_sequence); p <= BigInt(loss.last_sequence); p++) {
        losses.record(SOURCE, EPOCH, loss.reason, p, loss.segment_id);
      }
    }
    const members = c.entries.length;
    expect(seals.outstanding(c.segment_id)).toBe(0);
    seals.requestSeal(c.segment_id, {
      lastSequence: 41n,
      terminal: true,
      resumable: false,
      runId: RUN,
      sourceId: SOURCE,
      epoch: EPOCH,
      positions: members,
    });
    expect(seals.drain()).toBe(true);
    const own = built.filter((seal) => seal.segmentId === c.segment_id);
    expect(own).toHaveLength(1);
    expect(own[0]!.sealDigest).toBe(c.seal_digest);
    expect([own[0]!.sourceId, own[0]!.epoch]).toEqual([SOURCE, EPOCH]);
  });

  it("waits until the segment holds as many settled positions as the request names", () => {
    const c = doc.segments.find((s: any) => s.records.length === 2 && s.losses.length > 0);
    const { built, seals } = harness();
    seals.requestSeal(c.segment_id, {
      lastSequence: 9n,
      terminal: false,
      runId: RUN,
      sourceId: SOURCE,
      epoch: EPOCH,
      positions: c.entries.length,
    });
    // Settled in an order other than allocation order; a duplicate outcome does not count.
    const entries = [...c.entries].reverse() as [number, string][];
    for (const [index, [sequence, entry]] of entries.entries()) {
      expect(seals.drain()).toBe(true);
      expect(built).toHaveLength(0);
      seals.settle(c.segment_id, BigInt(sequence), entry);
      if (index === 0) seals.settle(c.segment_id, BigInt(sequence), "loss:internal_error");
    }
    seals.drain();
    expect(built.map((s) => s.sealDigest)).toEqual([c.seal_digest]);
  });

  it("hashes a large segment exactly as the pure function does", () => {
    const { built, seals } = harness();
    const segment = "seg-" + "7".repeat(32);
    const expected: [bigint, string][] = [];
    for (let i = 0; i < 20_000; i++) {
      const sequence = BigInt(i * 3 + 1);
      const entry = i % 7 === 0 ? "loss:queue_full" : `sha256:${randomBytes(32).toString("hex")}`;
      expected.push([sequence, entry]);
    }
    // Shuffled: the seal sorts by sequence, never by settle order.
    const shuffled = [...expected].sort(() => Math.random() - 0.5);
    for (const [sequence, entry] of shuffled) seals.settle(segment, sequence, entry);
    seals.requestSeal(segment, {
      lastSequence: 60_000n,
      terminal: true,
      runId: RUN,
      sourceId: SOURCE,
      epoch: EPOCH,
      positions: expected.length,
    });
    seals.drain();
    expect(built[0]!.sealDigest).toBe(sealDigest(expected));
  });

  it("seals a zero-width segment as []", () => {
    const empty = doc.segments.find((s: any) => s.entries.length === 0);
    const { built, seals } = harness();
    seals.requestSeal(empty.segment_id, {
      lastSequence: -1n,
      terminal: true,
      runId: RUN,
      sourceId: SOURCE,
      epoch: EPOCH,
      positions: 0,
    });
    seals.drain();
    expect(built[0]!.sealDigest).toBe(empty.seal_digest);
  });

  it("forces at 1,000,000 positions by default (spec 055 §4.3)", () => {
    expect(FORCED_SEAL_POSITIONS).toBe(1_000_000);
    expect(new SegmentSeals().forcedAt).toBe(1_000_000);
  });
});

describe("seal-parity-v1 through the accumulator", () => {
  const doc = vector("seal-parity-v1");

  it.each(cases(doc.cases, "name"))("%s", (_name, c: any) => {
    const a = c.emitted.attributes;
    const segment = a["fabric.run.segment_id"] as string;
    const sequence = BigInt(a["fabric.source.sequence"] ?? 0);
    if (c.class === "loss") {
      const { built, seals, losses } = harness();
      const first = BigInt(a["fabric.loss.first_sequence"]);
      const last = BigInt(a["fabric.loss.last_sequence"]);
      for (let p = first; p <= last; p++) {
        losses.record(SOURCE, EPOCH, a["fabric.loss.reason"], p, segment);
      }
      const ranges = losses.take();
      expect(ranges).toHaveLength(1);
      const attrs = lossAttributes(ranges[0]!);
      // The emitted span is the spooled range's attributes; its event id is the
      // sender's (Python's loss records carry none either).
      const rest = { ...a };
      delete rest["fabric.event_id"];
      expect(norm(attrs)).toEqual(norm({ ...rest, "fabric.source_id": SOURCE }));
      seals.requestSeal(segment, {
        lastSequence: last,
        terminal: false,
        runId: RUN,
        positions: Number(last - first + 1n),
      });
      seals.drain();
      expect(built[0]!.sealDigest).toBe(sealDigest(c.seal_entries));
      return;
    }
    if (c.class === "segment_seal") {
      // The accumulator's marker carries exactly the emitted attribute set; the digest is
      // the accumulator's own (the vector's is a placeholder).
      const { built, seals } = harness({ newId: () => a["fabric.event_id"] });
      seals.requestSeal(segment, {
        lastSequence: BigInt(a["fabric.segment.last_sequence"]),
        manifestDigest: a["fabric.segment.manifest_digest"],
        terminal: a["fabric.run.terminal"],
        runId: a["fabric.run.id"],
        scopeId: a["fabric.run.scope_id"],
        sourceId: a["fabric.source_id"],
        epoch: BigInt(a["fabric.source.epoch"]),
        positions: 0,
        manifestSeq: a["fabric.capture.manifest_seq"],
      });
      seals.drain();
      const [, attrs] = heartbeatSpan(built[0]!.sourceId, built[0]!.epoch, sealFields(built[0]!));
      expect(attrs["fabric.segment.seal_digest"]).toBe(built[0]!.sealDigest);
      expect(
        norm({ ...attrs, "fabric.segment.seal_digest": a["fabric.segment.seal_digest"] }),
      ).toEqual(norm(a));
      return;
    }
    // A written record or exchange settles its record digest, and the seal over it equals
    // the seal recomputed from the Node's export (receiver-owned keys excluded).
    const entry =
      c.class === "exchange"
        ? exchangeSealEntry(spanOf(c.emitted))
        : recordDigest(c.emitted, c.content);
    expect(entry).toBe(c.digest);
    const exported = recordDigest(
      { ...c.emitted, attributes: c.expected_export.attributes },
      c.content,
    );
    const { built, seals } = harness();
    seals.settle(segment, sequence, entry);
    seals.requestSeal(segment, {
      lastSequence: sequence,
      terminal: true,
      runId: RUN,
      sourceId: SOURCE,
      epoch: EPOCH,
      positions: 1,
    });
    seals.drain();
    expect(built[0]!.sealDigest).toBe(sealDigest([[sequence, exported]]));
  });
});

/** A vector's emitted span in the spool's span form. */
function spanOf(emitted: any) {
  return {
    name: emitted.name,
    start_time_unix_nano: BigInt(emitted.start_ns),
    end_time_unix_nano: BigInt(emitted.end_ns),
    status: emitted.status,
    attributes: emitted.attributes,
  };
}
