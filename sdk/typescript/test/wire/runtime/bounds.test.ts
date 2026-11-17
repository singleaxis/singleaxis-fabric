// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Every bound of spec 055 §4.5 has a named outcome, and no partially retained body is
 * ever labelled exact: slab, chunk-vector, exchange-slot and ring exhaustion, the side
 * cap, and the byte-ownership rules.
 */
import { describe, expect, it } from "vitest";

import {
  MAX_VECTOR_SLOTS,
  SLAB_BYTES,
  SLABS_PER_VECTOR,
  VECTOR_BYTES,
} from "../../../src/wire/arena.js";
import { META_BYTES, NO_EXCHANGE, REQUEST, RESPONSE } from "../../../src/wire/exchange.js";
import {
  EXCHANGE_SLOT_BYTES,
  JOB_RECORD_BYTES,
  MAX_EXCHANGE_SLOTS,
  createRuntimeShared,
  metadataBytesAtMaximum,
} from "../../../src/wire/runtime.js";
import { KIB, drain, isolate } from "./helpers.js";

const filled = (bytes: number, value: number): Buffer => Buffer.alloc(bytes, value);

describe("payload slab exhaustion", () => {
  it("truncates the side as inflight_budget, keeps the exact prefix and stops retaining", () => {
    const { table } = isolate({
      maxInflightBytes: 4 * SLAB_BYTES,
      initialPayloadBytes: 4 * SLAB_BYTES,
    });
    const handle = table.begin();
    expect(table.admit(handle, REQUEST, filled(200 * KIB, 1))).toBe(true);
    expect(table.arena.chargedBytes).toBe(4 * SLAB_BYTES); // whole slabs are charged
    // A whole chunk or nothing: 100 KiB does not fit, so none of it is kept.
    expect(table.admit(handle, REQUEST, filled(100 * KIB, 2))).toBe(false);
    // Retention stopped at the first rejected chunk, even for one that would fit.
    expect(table.admit(handle, REQUEST, filled(10, 3))).toBe(false);
    expect(table.finish(handle, "complete")).toBe("enqueued");

    const { jobs, losses } = drain(table);
    expect(losses).toEqual([]);
    expect(jobs[0]!.request.state).toBe("truncated");
    expect(jobs[0]!.request.reason).toBe("inflight_budget");
    expect(jobs[0]!.requestBytes.equals(filled(200 * KIB, 1))).toBe(true);
    expect(table.arena.slabs.inUse).toBe(0);
  });

  it("an empty arena refuses the first chunk: truncated with zero bytes, never exact-empty", () => {
    const { table } = isolate({ maxInflightBytes: SLAB_BYTES, initialPayloadBytes: SLAB_BYTES });
    const hog = table.begin();
    table.admit(hog, REQUEST, filled(1, 1));
    const handle = table.begin();
    expect(table.admit(handle, REQUEST, filled(5, 2))).toBe(false);
    table.finish(handle, "complete");
    const job = drain(table).jobs[0]!;
    expect([job.request.state, job.request.reason, job.request.byteLength]).toEqual([
      "truncated",
      "inflight_budget",
      0,
    ]);
  });
});

describe("the per-side cap", () => {
  it("truncates the side as body_cap at the first chunk past max_retain_bytes", () => {
    const { table } = isolate({ maxRetainBytes: 1000 });
    const handle = table.begin();
    table.responseStarted(handle);
    expect(table.admit(handle, RESPONSE, filled(600, 1))).toBe(true);
    expect(table.admit(handle, RESPONSE, filled(400, 2))).toBe(true); // exactly the cap
    expect(table.admit(handle, RESPONSE, filled(1, 3))).toBe(false);
    expect(table.admit(handle, REQUEST, filled(1000, 4))).toBe(true); // sides are independent
    table.finish(handle, "complete");
    const job = drain(table).jobs[0]!;
    expect([job.response.state, job.response.reason, job.response.byteLength]).toEqual([
      "truncated",
      "body_cap",
      1000,
    ]);
    expect([job.request.state, job.request.reason]).toEqual(["exact", undefined]);
  });
});

describe("chunk-vector slot exhaustion", () => {
  it("loses the whole exchange as queue_full and releases every byte it held", () => {
    const { table, runtime } = isolate({ maxVectors: 2 });
    const handle = table.begin();
    const slab = filled(SLAB_BYTES, 7);
    for (let n = 0; n < 2 * SLABS_PER_VECTOR; n++) {
      expect(table.admit(handle, REQUEST, slab)).toBe(true);
    }
    expect(table.arena.vectors.inUse).toBe(2);
    expect(table.admit(handle, REQUEST, slab)).toBe(false); // needs a third vector slot
    expect(table.arena.slabs.inUse).toBe(0);
    expect(table.arena.vectors.inUse).toBe(0);
    expect(table.admit(handle, REQUEST, filled(1, 1))).toBe(false);
    expect(table.finish(handle, "complete")).toBe("lost");

    const { jobs, losses } = drain(table);
    expect(jobs).toEqual([]); // no job: a partial body is never handed on as a record
    expect(losses).toEqual([{ reason: "queue_full", sequence: 0n, segmentHi: 0n, segmentLo: 0n }]);
    expect(runtime.stats().losses.queue_full).toBe(1n);
  });
});

describe("exchange slot exhaustion", () => {
  it("does not capture the call and records its position as queue_full", () => {
    const { table, runtime } = isolate({ maxExchanges: 2 });
    expect(runtime.tryLock()).toBe(true);
    runtime.setRunSegment(0, 5n, 6n);
    runtime.unlock();
    const first = table.begin({ runSlot: 0 });
    const second = table.begin({ runSlot: 0 });
    expect(table.begin({ runSlot: 0 })).toBe(NO_EXCHANGE);
    expect(table.begin({ runSlot: 0, ownership: { ended: false, withheld: false } })).toBe(
      NO_EXCHANGE,
    );
    expect(drain(table).losses).toEqual([
      { reason: "queue_full", sequence: 2n, segmentHi: 5n, segmentLo: 6n },
      { reason: "queue_full", sequence: 3n, segmentHi: 5n, segmentLo: 6n },
    ]);
    // A finished exchange frees its slot for the next call.
    expect(table.finish(first, "complete")).toBe("enqueued");
    expect(table.begin()).not.toBe(NO_EXCHANGE);
    expect(table.finish(second, "complete")).toBe("enqueued");
  });
});

describe("completed-job ring exhaustion", () => {
  it("loses the allocated position as queue_full and releases its bytes", () => {
    const { table } = isolate({ queueMaxItems: 2 });
    const handles = [0, 1, 2].map(() => table.begin());
    for (const handle of handles) table.admit(handle, REQUEST, filled(70 * KIB, 9));
    expect(handles.map((handle) => table.finish(handle, "complete"))).toEqual([
      "enqueued",
      "enqueued",
      "lost",
    ]);
    expect(table.arena.slabs.inUse).toBe(4); // the two queued jobs keep their slabs charged
    const { jobs, losses } = drain(table);
    expect(jobs.map((job) => job.sequence)).toEqual([0n, 1n]);
    expect(losses).toEqual([{ reason: "queue_full", sequence: 2n, segmentHi: 0n, segmentLo: 0n }]);
    // The consumer made room: the ring admits again.
    const next = table.begin();
    expect(table.finish(next, "complete")).toBe("enqueued");
  });

  it("counts a loss that does not fit the loss ring, so its position stays a gap", () => {
    const { runtime } = isolate({ lossRingEntries: 2 });
    for (let n = 0; n < 3; n++) runtime.lose("shutdown", BigInt(n));
    const stats = runtime.stats();
    expect(stats.losses.shutdown).toBe(3n);
    expect(stats.lossesUnattributed).toBe(1n);
  });
});

describe("byte ownership", () => {
  it("copies before returning: later writes to the caller's buffer do not change the record", () => {
    const { table } = isolate();
    const handle = table.begin();
    const pooled = Buffer.from("first chunk|");
    const view = pooled.subarray(0, 5);
    expect(table.admit(handle, REQUEST, pooled)).toBe(true);
    pooled.fill(0x58); // the client reuses its buffer
    expect(table.admit(handle, REQUEST, view)).toBe(true);
    expect(view.byteLength).toBe(5); // nothing was detached or transferred
    expect(pooled.toString()).toBe("XXXXXXXXXXXX"); // and nothing was written to it
    table.finish(handle, "complete");
    expect(drain(table).jobs[0]!.requestBytes.toString()).toBe("first chunk|XXXXX");
  });

  it("encodes a string chunk with the encoding of the original write", () => {
    const { table } = isolate();
    const handle = table.begin();
    table.admit(handle, REQUEST, "é", "utf8");
    table.admit(handle, REQUEST, "é", "latin1");
    table.admit(handle, REQUEST, "6869", "hex");
    table.admit(handle, REQUEST, "");
    table.finish(handle, "complete");
    const job = drain(table).jobs[0]!;
    expect([...job.requestBytes]).toEqual([0xc3, 0xa9, 0xe9, 0x68, 0x69]);
    expect(job.request.state).toBe("exact");
  });

  it("rejects a SharedArrayBuffer-backed body as transport_incomplete", () => {
    const { table } = isolate();
    const handle = table.begin();
    expect(table.admit(handle, REQUEST, new Uint8Array(new SharedArrayBuffer(8)))).toBe(false);
    expect(table.admit(handle, REQUEST, filled(4, 1))).toBe(false);
    table.finish(handle, "complete");
    const job = drain(table).jobs[0]!;
    expect([job.request.state, job.request.reason, job.request.byteLength]).toEqual([
      "truncated",
      "transport_incomplete",
      0,
    ]);
  });

  it("a missing response is absent, not a zero-byte body; an incomplete request is truncated", () => {
    const { table } = isolate();
    const missing = table.begin();
    table.requestIncomplete(missing);
    table.finish(missing, "error");
    const started = table.begin();
    table.responseStarted(started);
    table.finish(started, "complete");
    const [first, second] = drain(table).jobs;
    expect([first!.response.state, first!.responseState]).toEqual(["absent", "error"]);
    expect([first!.request.state, first!.request.reason]).toEqual([
      "truncated",
      "transport_incomplete",
    ]);
    expect([second!.response.state, second!.response.byteLength]).toEqual(["exact", 0]);
  });
});

describe("slot reuse", () => {
  it("a release cut short and run again never frees a slab or vector slot twice", () => {
    const { table } = isolate();
    const { arena } = table;
    const side = { i32: new Int32Array(8), at: 0 };
    expect(arena.append(side, filled(20 * SLAB_BYTES, 5))).toBe(0);
    expect([arena.slabs.inUse, arena.vectors.inUse]).toEqual([20, 2]);
    // The Fabric worker is terminated part-way through releasing a job's bytes ...
    const free = arena.slabs.free.bind(arena.slabs);
    let calls = 0;
    arena.slabs.free = (index: number) => {
      if (++calls === 18) throw new Error("terminated");
      free(index);
    };
    expect(() => arena.release(side)).toThrow("terminated");
    arena.slabs.free = free;
    // ... and its replacement reads the same job and releases it again.
    arena.release(side);
    arena.release(side);
    // At most the one slab in flight leaked; nothing was freed twice.
    expect(arena.slabs.inUse).toBe(1);
    expect(arena.vectors.inUse).toBe(0);
    const taken = new Set<number>();
    for (let index = arena.slabs.take(); index >= 0; index = arena.slabs.take()) {
      expect(taken.has(index)).toBe(false);
      taken.add(index);
    }
    expect(taken.size).toBe(arena.slabs.committed - 1);
  });

  it("a reused exchange slot carries nothing of its previous exchange", () => {
    const { table } = isolate({ maxExchanges: 1 });
    const first = table.begin();
    table.meta(first)!.fill(0xaa);
    table.admit(first, REQUEST, filled(10, 1));
    table.finish(first, "complete");
    const second = table.begin();
    expect(table.meta(second)!.every((byte) => byte === 0)).toBe(true);
    table.finish(second, "complete");
    const jobs = drain(table).jobs;
    expect(jobs[1]!.meta.every((byte) => byte === 0)).toBe(true);
    expect(jobs[1]!.request.byteLength).toBe(0);
  });
});

describe("the configured sizes", () => {
  it("uses 64 KiB slabs, 2 KiB records and 64-byte vector slots, within 260 MiB of metadata", () => {
    expect(SLAB_BYTES).toBe(64 * KIB);
    expect([EXCHANGE_SLOT_BYTES, JOB_RECORD_BYTES, VECTOR_BYTES]).toEqual([2048, 2048, 64]);
    expect([MAX_EXCHANGE_SLOTS, MAX_VECTOR_SLOTS]).toEqual([65536, 65536]);
    expect(metadataBytesAtMaximum()).toBe(260 * KIB * KIB);
    expect(META_BYTES).toBe(1792);
  });

  it("caps the payload arena at the global budget and the ring at the configured entries", () => {
    const shared = createRuntimeShared({ maxInflightBytes: 256 * KIB * KIB, queueMaxItems: 16384 });
    const growable = shared.payload.slabs.data as unknown as { maxByteLength: number };
    expect(growable.maxByteLength).toBe(256 * KIB * KIB);
    expect(shared.payload.slabs.data.byteLength).toBe(4 * KIB * KIB); // grown later, by the worker
    expect(shared.jobs.limit).toBe(16384);
    expect(shared.exchanges.maxSlots).toBe(65536);
  });
});
