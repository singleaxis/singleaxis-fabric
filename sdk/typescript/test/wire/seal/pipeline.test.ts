// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §9.5 (unit 055-t10) through the Fabric worker's capture pipeline: a position
 * settles in its segment's seal only after its record is in the spool (a position the
 * spool refused settles as its loss); at close the `shutdown` losses and the seals are
 * spooled before `final`; persisted uuid4 marker event ids replay unchanged in
 * TypeScript and in Python's drainer.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { heartbeatSpan } from "../../../src/wire/loss.js";
import { recordDigest, sealDigest } from "../../../src/wire/p1.js";
import { STATE_CLOSING, type WireRuntime } from "../../../src/wire/runtime.js";
import { exchangeSealEntry } from "../../../src/wire/seal.js";
import { Spool } from "../../../src/wire/spool.js";
import { CapturePipeline, pipelineHandlers, runtimeSink } from "../../../src/wire/worker.js";
import type { ExchangeTable } from "../../../src/wire/exchange.js";

import { norm } from "../helpers.js";
import { isolate } from "../runtime/helpers.js";
import { KEY, cleanupDirs, native, spoolDir } from "../spool/helpers.js";
import {
  CHAT,
  PUBLISHES_BODIES,
  type Capture,
  type Provider,
  capture,
  provider,
  settle,
} from "../undici/helpers.js";
import {
  RUN,
  SOURCE,
  UUID4_RE,
  openSegment,
  pipelineConfig,
  pythonReads,
  segment,
  spooledDocs,
} from "./helpers.js";

const A = segment(7);

let server: Provider;
let cap: Capture | undefined;
beforeAll(async () => {
  server = await provider();
  server.route(CHAT, (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"choices":[]}');
  });
});
afterAll(async () => {
  await server.close();
  cleanupDirs();
});
afterEach(() => {
  cap?.close();
  cap = undefined;
});

const newSpool = (maxBytes = 1 << 20) => {
  const dir = spoolDir();
  return { dir, spool: new Spool(dir, { maxBytes, addon: native().addon, key: KEY }) };
};

/** One `fetch` in run slot 0 (segment A), and the job the Fabric worker would read. */
async function oneExchange() {
  cap = capture(server.port, { scope: () => ({ runSlot: 0 }) });
  openSegment(cap.runtime, 0, A.hi, A.lo);
  const response = await fetch(`${server.base}${CHAT}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: '{"model":"gpt-4o"}',
  });
  await response.arrayBuffer();
  await settle();
  const { runtime, table } = cap;
  const record = runtime.jobs.peek()!;
  return { runtime, table, job: table.job(record.byteOffset) };
}

/** Hands every loss record of the ring to the pipeline's `loss` handler. */
function handleLosses(
  pipeline: CapturePipeline,
  runtime: WireRuntime,
  table: ExchangeTable,
): number {
  const handlers = pipelineHandlers(pipeline);
  const context = { runtime, exchanges: table, snapshot: undefined };
  let n = 0;
  for (let loss = runtime.peekLoss(); loss !== undefined; loss = runtime.peekLoss()) {
    void handlers.loss!(loss, context);
    runtime.commitLoss();
    n++;
  }
  return n;
}

const sealRequest = (runtime: WireRuntime, positions: bigint | number, terminal = true) => ({
  lastSequence: runtime.nextSequence - 1n,
  manifestDigest: "sha256:" + "ab".repeat(32),
  terminal,
  resumable: false,
  runId: RUN,
  sourceId: SOURCE,
  epoch: runtime.epoch,
  positions,
});

// Python subprocesses: slow on a loaded runner.
describe("settle only after the record is spooled", { timeout: 60_000 }, () => {
  it.skipIf(!PUBLISHES_BODIES)(
    "a written exchange settles its record digest once its record is in the spool",
    async () => {
      const { dir, spool } = newSpool();
      const { runtime, table, job } = await oneExchange();
      const pipeline = new CapturePipeline(pipelineConfig(), spool, runtimeSink(runtime));
      const calls: { entry: string; spooled: string[] }[] = [];
      const real = pipeline.seals.settle.bind(pipeline.seals);
      pipeline.seals.settle = (segmentId, sequence, entry) => {
        calls.push({ entry, spooled: spooledDocs(spool).map((d) => d.record_kind) });
        real(segmentId, sequence, entry);
      };
      expect(await pipeline.handle(job, table.arena, runtime.epoch)).toBe("spooled");
      // The settle came after the exchange record was durable in the spool.
      expect(calls).toHaveLength(1);
      expect(calls[0]!.spooled).toEqual(["marker", "exchange"]);
      // Its entry is the record digest of the span as spooled (and as a drainer reads it).
      const spooled = spooledDocs(spool).find((d) => d.record_kind === "exchange")!.span;
      expect(calls[0]!.entry).toBe(exchangeSealEntry(spooled));
      expect(pipeline.seals.entries(A.id)).toEqual([[job.sequence, calls[0]!.entry]]);
      pipeline.seals.requestSeal(A.id, sealRequest(runtime, runtime.runPositions(0)));
      pipeline.tick(runtime.epoch, runtime.nextSequence - 1n);
      const read = pythonReads(dir);
      expect(read.map((r) => [r.kind, r.marker ?? null, r.ok])).toEqual([
        ["marker", "manifest", true],
        ["exchange", null, true],
        ["marker", "segment_seal", true],
      ]);
      const content = ["fabric.wire.request_sha256", "fabric.wire.response_sha256"]
        .map((k) => spooled.attributes[k])
        .filter((v) => typeof v === "string")
        .map((v) => `sha256:${v}`);
      const recomputed = recordDigest(
        {
          name: spooled.name,
          start_ns: spooled.start_time_unix_nano,
          end_ns: spooled.end_time_unix_nano,
          status: spooled.status,
          attributes: spooled.attributes,
        },
        content,
      );
      expect(read[2].span[1]["fabric.segment.seal_digest"]).toBe(
        sealDigest([[job.sequence, recomputed]]),
      );
      spool.close();
    },
  );

  it.skipIf(!PUBLISHES_BODIES)(
    "a spooled position is never also recorded lost when an observer throws after the write",
    async () => {
      const { spool } = newSpool();
      const { runtime, table, job } = await oneExchange();
      const lost: bigint[] = [];
      const pipeline = new CapturePipeline(pipelineConfig(), spool, {
        lose: (_reason, sequence) => {
          lost.push(sequence);
        },
        written: () => {
          throw new Error("observer failure");
        },
      });
      expect(await pipeline.handle(job, table.arena, runtime.epoch)).toBe("spooled");
      expect(lost).toEqual([]);
      expect(pipeline.seals.entries(A.id).map(([s, e]) => [s, e.slice(0, 7)])).toEqual([
        [job.sequence, "sha256:"],
      ]);
      spool.close();
    },
  );

  it.skipIf(!PUBLISHES_BODIES)(
    "a position the spool refused settles only as its loss, through the loss funnel",
    async () => {
      const { spool } = newSpool(1); // no room for an exchange record
      const { runtime, table, job } = await oneExchange();
      const pipeline = new CapturePipeline(pipelineConfig(), spool, runtimeSink(runtime));
      const entries: string[] = [];
      const real = pipeline.seals.settle.bind(pipeline.seals);
      pipeline.seals.settle = (segmentId, sequence, entry) => {
        entries.push(entry);
        real(segmentId, sequence, entry);
      };
      expect(await pipeline.handle(job, table.arena, runtime.epoch)).toBe("queue_full");
      expect(entries).toEqual([]); // nothing settles before the loss reaches the funnel
      expect(handleLosses(pipeline, runtime, table)).toBe(1);
      expect(entries).toEqual(["loss:queue_full"]);
      expect(pipeline.seals.entries(A.id)).toEqual([[job.sequence, "loss:queue_full"]]);
      expect(pipeline.losses.stats()).toMatchObject({ recorded: 1, byReason: { queue_full: 1 } });
      spool.close();
    },
  );
});

/** A run in slot 0 with `open` exchanges still open, swept by the shutdown. */
function sweptRun(open: number) {
  const { runtime, table } = isolate();
  openSegment(runtime, 0, A.hi, A.lo);
  for (let i = 0; i < open; i++) table.begin({ runSlot: 0 });
  runtime.setState(STATE_CLOSING);
  expect(table.shutdown()).toBe(open);
  return { runtime, table };
}

// Python subprocesses: slow on a loaded runner.
describe("close: shutdown losses and seals precede final", { timeout: 60_000 }, () => {
  it("spools the shutdown losses, then the seal, then final; close is true", async () => {
    const { dir, spool } = newSpool();
    const { runtime, table } = sweptRun(3);
    const pipeline = new CapturePipeline(pipelineConfig(), spool, runtimeSink(runtime));
    pipeline.tick(runtime.epoch, -1n); // manifest 0
    // The run table seals the open segment at final (055-t11); its three positions are
    // still in the loss ring when the request arrives.
    pipeline.seals.requestSeal(A.id, sealRequest(runtime, runtime.runPositions(0)));
    expect(pipeline.seals.waiting()).toEqual([A.id]);
    const handlers = pipelineHandlers(pipeline);
    const context = { runtime, exchanges: table, snapshot: undefined };
    for (let loss = runtime.peekLoss(); loss !== undefined; loss = runtime.peekLoss()) {
      await handlers.loss!(loss, context);
      runtime.commitLoss();
    }
    await handlers.stop!(context);
    expect(pipeline.closed).toBe(true);
    const read = pythonReads(dir);
    expect(read.map((r) => [r.kind, r.marker ?? null, r.ok])).toEqual([
      ["marker", "manifest", true],
      ["loss", null, true],
      ["marker", "segment_seal", true],
      ["marker", "final", true],
    ]);
    expect(read[1].loss).toMatchObject({
      "fabric.loss.reason": "shutdown",
      "fabric.loss.count": 3,
      "fabric.loss.first_sequence": 0,
      "fabric.loss.last_sequence": 2,
      "fabric.run.segment_id": A.id,
    });
    expect(read[2].span[1]).toMatchObject({
      "fabric.run.segment_id": A.id,
      "fabric.run.terminal": true,
      "fabric.capture.manifest_seq": 0,
      "fabric.segment.seal_digest": sealDigest([
        [0n, "loss:shutdown"],
        [1n, "loss:shutdown"],
        [2n, "loss:shutdown"],
      ]),
    });
    expect(read[3].span[1]["fabric.heartbeat.last_sequence"]).toBe(2);
    // The closed epoch settles nothing more.
    pipeline.losses.record(SOURCE, runtime.epoch, "shutdown", 9n, A.id);
    expect(pipeline.seals.stats().open_segments).toBe(0);
    spool.close();
  });

  it("is false, with final still last, while a requested segment has an unsettled position", () => {
    const { dir, spool } = newSpool();
    const { runtime, table } = sweptRun(2);
    const pipeline = new CapturePipeline(pipelineConfig(), spool, runtimeSink(runtime));
    // One position more than ever settles (a loss record that never reached the ring).
    pipeline.seals.requestSeal(A.id, sealRequest(runtime, 3));
    handleLosses(pipeline, runtime, table);
    expect(pipeline.closeEpoch(runtime.epoch, runtime.nextSequence - 1n)).toBe(false);
    expect(pipeline.seals.waiting()).toEqual([A.id]);
    expect(pythonReads(dir).map((r) => [r.kind, r.marker ?? null])).toEqual([
      ["marker", "manifest"],
      ["loss", null],
      ["marker", "final"],
    ]);
    spool.close();
  });

  it("never spools final ahead of a loss the spool refused", () => {
    const { dir, spool } = newSpool();
    const { runtime, table } = sweptRun(1);
    const pipeline = new CapturePipeline(pipelineConfig(), spool, runtimeSink(runtime));
    const write = spool.writeBatch.bind(spool);
    let refuse = true;
    spool.writeBatch = (records, reserve) =>
      refuse && records[0]!.doc.record_kind === "loss"
        ? records.map(() => new Error("refused"))
        : write(records, reserve);
    pipeline.seals.requestSeal(A.id, sealRequest(runtime, 1));
    handleLosses(pipeline, runtime, table);
    expect(pipeline.closeEpoch(runtime.epoch, 0n)).toBe(false);
    // Manifest 0 leads the epoch; the seal and final wait behind the refused loss.
    expect(spooledDocs(spool).map((d) => d.marker?.kind ?? d.record_kind)).toEqual(["manifest"]);
    expect(pipeline.markers.held.map((m) => (m.doc.marker as any).kind)).toEqual([
      "segment_seal",
      "final",
    ]);
    // Room again: the next pump writes the loss first, then the held markers in order.
    refuse = false;
    pipeline.tick(runtime.epoch, 0n);
    expect(pythonReads(dir).map((r) => [r.kind, r.marker ?? null])).toEqual([
      ["marker", "manifest"],
      ["loss", null],
      ["marker", "segment_seal"],
      ["marker", "final"],
    ]);
    spool.close();
  });
});

// Python subprocesses: slow on a loaded runner.
describe("persisted uuid4 marker event ids", { timeout: 60_000 }, () => {
  it("replay unchanged: every read, in TypeScript and in Python, gives the minted id", () => {
    const { dir, spool } = newSpool();
    const { runtime, table } = sweptRun(2);
    const pipeline = new CapturePipeline(pipelineConfig(), spool, runtimeSink(runtime));
    pipeline.seals.requestSeal(A.id, sealRequest(runtime, 2, false));
    handleLosses(pipeline, runtime, table);
    expect(pipeline.closeEpoch(runtime.epoch, 1n)).toBe(true);
    const markers = (docs: Record<string, any>[]) =>
      docs.filter((d) => d.record_kind === "marker" && d.marker.kind !== "manifest");
    const first = markers(spooledDocs(spool));
    const again = markers(spooledDocs(spool));
    expect(first.map((d) => d.marker.kind)).toEqual(["segment_seal", "final"]);
    const ids = first.map((d) => d.marker.event_id as string);
    expect(ids.every((id) => UUID4_RE.test(id))).toBe(true);
    expect(new Set(ids).size).toBe(2);
    expect(again.map((d) => d.marker.event_id)).toEqual(ids);
    // Exported spans carry the persisted id, identical in TypeScript and Python.
    const spans = first.map((d) =>
      heartbeatSpan(d.source.source_id, BigInt(d.source.source_epoch), d.marker),
    );
    expect(spans.map(([, a]) => a["fabric.event_id"])).toEqual(ids);
    const python = pythonReads(dir).filter((r) => r.kind === "marker" && r.marker !== "manifest");
    expect(norm(python.map((r) => r.span))).toEqual(norm(spans));
    const replayed = pythonReads(dir).filter((r) => r.kind === "marker" && r.marker !== "manifest");
    expect(norm(replayed.map((r) => r.span))).toEqual(norm(spans));
    spool.close();
  });
});
