// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Finish exactly once (spec 055 §4.6): end of body, early close or abort, transport
 * failure, a garbage-collection notice and recorder shutdown race in every order, in
 * one isolate and across threads, and exactly one of them settles the position.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  ExchangeTable,
  type ExplicitOwnership,
  type FinishOutcome,
  REQUEST,
  RESPONSE,
} from "../../../src/wire/exchange.js";
import {
  STATE_CLOSING,
  STATE_FAILED,
  WireRuntime,
  createRuntimeShared,
} from "../../../src/wire/runtime.js";
import { type Bundles, bundleFixtures, drain, isolate, produce } from "./helpers.js";

type Finisher = (table: ExchangeTable, handle: number) => FinishOutcome | number;
const FINISHERS: Record<string, Finisher> = {
  eof: (table, handle) => table.finish(handle, "complete"),
  "early close": (table, handle) => table.finish(handle, "closed_early"),
  "transport failure": (table, handle) => table.finish(handle, "error"),
  "collection notice": (table, handle) => table.noticeCollected(handle),
  shutdown: (table) => {
    table.runtime.setState(STATE_CLOSING);
    return table.shutdown();
  },
};
const PAIRS = Object.keys(FINISHERS).flatMap((first) =>
  Object.keys(FINISHERS).map((second) => [first, second] as const),
);

describe("finish-once in one isolate", () => {
  it.each(PAIRS)("%s then %s settles the position once", (first, second) => {
    const { table, runtime } = isolate();
    const handle = table.begin();
    table.admit(handle, REQUEST, Buffer.from("request"));
    table.responseStarted(handle);
    table.admit(handle, RESPONSE, Buffer.from("resp"));

    const won = FINISHERS[first]!(table, handle);
    const late = FINISHERS[second]!(table, handle);
    expect(won).toBe(first === "shutdown" ? 1 : "enqueued");
    // After the first finisher: a hook is told it is finished (or, once the recorder
    // is closing, gets nothing more); a second shutdown sweep finds nothing open.
    expect(late).toBe(second === "shutdown" ? 0 : "already_finished");
    expect(table.admit(handle, RESPONSE, Buffer.from("late"))).toBe(false);
    expect(table.meta(handle)).toBeUndefined();

    const { jobs, losses } = drain(table);
    expect(jobs.length + losses.length).toBe(1);
    if (first === "shutdown") {
      // No synthetic response: a shutdown loss, and no record.
      expect(losses).toEqual([{ reason: "shutdown", sequence: 0n, segmentHi: 0n, segmentLo: 0n }]);
    } else {
      const state = {
        eof: "complete",
        "early close": "closed_early",
        "transport failure": "error",
      };
      expect(jobs[0]!.responseState).toBe(state[first as keyof typeof state] ?? "abandoned");
      expect(jobs[0]!.requestBytes.toString()).toBe("request");
      expect(jobs[0]!.responseBytes.toString()).toBe("resp");
    }
    expect([table.active, table.arena.slabs.inUse, table.arena.vectors.inUse]).toEqual([0, 0, 0]);
    expect(runtime.stats().nextSequence).toBe(1n);
  });

  it("a stale handle never touches the slot's next exchange", () => {
    const { table } = isolate({ maxExchanges: 1 });
    const old = table.begin();
    table.finish(old, "complete");
    const current = table.begin(); // the same slot, a new generation
    expect(current).not.toBe(old);
    expect(table.finish(old, "error")).toBe("already_finished");
    expect(table.admit(old, REQUEST, Buffer.from("stale"))).toBe(false);
    table.requestIncomplete(old);
    table.admit(current, REQUEST, Buffer.from("fresh"));
    expect(table.finish(current, "complete")).toBe("enqueued");
    const jobs = drain(table).jobs;
    expect(
      jobs.map((job) => [job.sequence, job.request.state, job.requestBytes.toString()]),
    ).toEqual([
      [0n, "exact", ""],
      [1n, "exact", "fresh"],
    ]);
  });

  it("gives every exchange its own uuid4 exchange id, uuid4 event id and span id, and only the clean parent", () => {
    const { table } = isolate();
    const parent = {
      traceId: Buffer.alloc(16, 0xa1),
      spanId: Buffer.alloc(8, 0xb2),
      flags: 1,
      remote: true,
      baggage: "user=secret",
      tracestate: "vendor=secret",
    };
    for (const options of [{ parent }, {}]) table.finish(table.begin(options), "complete");
    const [first, second] = drain(table).jobs;
    for (const id of [first!.exchangeId, first!.eventId, second!.exchangeId, second!.eventId]) {
      expect(id[6]! >> 4).toBe(4);
      expect(id[8]! >> 6).toBe(2);
    }
    const ids = [first, second].flatMap((job) => [job!.exchangeId, job!.eventId, job!.spanId]);
    expect(new Set(ids.map((id) => Buffer.from(id).toString("hex"))).size).toBe(6);
    expect(first!.parent).toEqual({
      traceId: new Uint8Array(parent.traceId),
      spanId: new Uint8Array(parent.spanId),
      flags: 1,
      remote: true,
    });
    expect(second!.parent).toBeUndefined(); // no parent is invented
    expect(Buffer.from(first!.meta).includes("secret")).toBe(false);
  });

  it("a finish while the recorder is closing or failed is a named loss, never a record", () => {
    for (const [state, reason] of [
      [STATE_CLOSING, "shutdown"],
      [STATE_FAILED, "internal_error"],
    ] as const) {
      const { table, runtime } = isolate();
      const handle = table.begin();
      table.admit(handle, REQUEST, Buffer.from("x"));
      runtime.setState(state);
      expect(table.finish(handle, "complete")).toBe("lost");
      expect(table.begin()).toBe(-1); // nothing new is captured, and no position is spent
      const { jobs, losses } = drain(table);
      expect(jobs).toEqual([]);
      expect(losses.map((loss) => [loss.reason, loss.sequence])).toEqual([[reason, 0n]]);
      expect(runtime.stats().refused).toBe(1n);
      expect(runtime.stats().nextSequence).toBe(1n);
    }
  });
});

describe("mixed capture with an explicit ownership scope", () => {
  const scope = (): ExplicitOwnership => ({ ended: false, withheld: false });

  it("defers to a live explicit scope: no position, no bytes kept", () => {
    const { table, runtime } = isolate();
    const handle = table.begin({ ownership: scope() });
    expect(table.admit(handle, REQUEST, Buffer.alloc(100_000))).toBe(true); // teed provisionally
    expect(runtime.stats().nextSequence).toBe(0n);
    expect(table.finish(handle, "complete")).toBe("deferred_to_explicit");
    expect(table.finish(handle, "complete")).toBe("already_finished");
    expect(drain(table)).toEqual({ jobs: [], losses: [] });
    expect([runtime.stats().nextSequence, table.arena.slabs.inUse, table.active]).toEqual([
      0n,
      0,
      0,
    ]);
  });

  it("adopts the call when the explicit scope ended first, allocating at finish", () => {
    const { table, runtime } = isolate();
    const ownership = scope();
    const handle = table.begin({ ownership });
    table.admit(handle, REQUEST, Buffer.from("kept"));
    const unrelated = table.begin(); // an unrelated call is a new exchange, not suppressed
    ownership.ended = true;
    expect(runtime.stats().nextSequence).toBe(1n);
    expect(table.finish(handle, "complete")).toBe("enqueued");
    table.finish(unrelated, "complete");
    const jobs = drain(table).jobs;
    expect(jobs.map((job) => [job.sequence, job.adopted, job.withheld])).toEqual([
      [1n, true, false],
      [0n, false, false],
    ]);
    expect(jobs[0]!.requestBytes.toString()).toBe("kept");
  });

  it("an adopted call whose scope withheld content stores no bytes; the flag survives scope exit", () => {
    const { table } = isolate();
    const ownership = scope();
    const handle = table.begin({ ownership });
    table.admit(handle, REQUEST, Buffer.from("secret"));
    ownership.withheld = true;
    ownership.ended = true; // the scope exited (or its recorder failed) after withholding
    expect(table.finish(handle, "complete")).toBe("enqueued");
    // A call that starts after the scope ended still sees the withheld flag.
    const later = table.begin({ ownership });
    expect(table.admit(later, REQUEST, Buffer.from("secret"))).toBe(false);
    table.finish(later, "complete");
    for (const job of drain(table).jobs) {
      expect([job.withheld, job.request.byteLength, job.requestBytes.length]).toEqual([true, 0, 0]);
    }
    expect(table.arena.slabs.inUse).toBe(0);
  });

  it("an adoption that fails before a position exists loses no position and leaks nothing", () => {
    const { table, runtime } = isolate();
    const ownership = scope();
    const handle = table.begin({ ownership });
    table.admit(handle, REQUEST, Buffer.from("kept"));
    ownership.ended = true;
    runtime.allocate = () => {
      throw new Error("allocation failed");
    };
    expect(table.finish(handle, "complete")).toBe("lost"); // never an exception
    expect(table.finish(handle, "complete")).toBe("already_finished");
    // No position was allocated, so no loss names one (least of all position 0).
    expect(drain(table)).toEqual({ jobs: [], losses: [] });
    expect([runtime.stats().nextSequence, table.arena.slabs.inUse, table.active]).toEqual([
      0n,
      0,
      0,
    ]);
  });

  it("shutdown drops a provisional exchange without a position and loses an adopted-pending one", () => {
    const { table, runtime } = isolate();
    const provisional = table.begin({ ownership: scope() });
    table.admit(provisional, REQUEST, Buffer.from("x"));
    const open = table.begin();
    runtime.setState(STATE_CLOSING);
    expect(table.shutdown()).toBe(1);
    expect(table.finish(provisional, "complete")).toBe("already_finished");
    expect(drain(table).losses.map((loss) => [loss.reason, loss.sequence])).toEqual([
      ["shutdown", 0n],
    ]);
    expect([table.active, table.arena.slabs.inUse, open >= 0]).toEqual([0, 0, true]);
  });
});

describe("finish-once across threads", () => {
  let bundles: Bundles;
  beforeAll(() => {
    bundles = bundleFixtures();
  });
  afterAll(() => bundles?.cleanup());

  it("8 producers racing recorder shutdown: every position is one record or one loss", async () => {
    // The loss ring holds every position the producers can lose, so each loss keeps its
    // reason however slowly this thread (the consumer) is scheduled.
    const shared = createRuntimeShared({
      maxInflightBytes: 32 * 1024 * 1024,
      queueMaxItems: 256,
      lossRingEntries: 8 * 3000,
    });
    const table = new ExchangeTable(new WireRuntime(shared, "worker"));
    const runtime = table.runtime;
    const settled = new Map<bigint, string>();
    let duplicates = 0;
    const settle = (): void => {
      const { jobs, losses } = drain(table);
      for (const item of [...jobs, ...losses]) {
        if (settled.has(item.sequence)) duplicates++;
        settled.set(item.sequence, "reason" in item ? item.reason : "record");
      }
    };
    let closing = false;
    const results = await produce(
      bundles.file("producer"),
      shared,
      8,
      { mode: "exchange", count: 3000 },
      () => {
        // Shutdown lands while exchanges are open in other threads, then sweeps.
        if (!closing && runtime.stats().nextSequence >= 500n) {
          closing = true;
          runtime.setState(STATE_CLOSING);
        }
        if (closing) table.shutdown();
        settle();
        for (const pool of [table.arena.slabs, table.arena.vectors, table.pool]) pool.growIfLow();
      },
    );
    table.shutdown();
    settle();

    const positions = runtime.stats().nextSequence;
    expect(duplicates).toBe(0);
    expect(runtime.stats().lossesUnattributed).toBe(0n);
    expect(BigInt(settled.size)).toBe(positions);
    for (let sequence = 0n; sequence < positions; sequence++) {
      expect(settled.has(sequence)).toBe(true);
    }
    // The race happened: some exchanges were recorded, some refused after shutdown.
    expect([...settled.values()].includes("record")).toBe(true);
    expect(results.reduce((sum, result) => sum + result.refused, 0)).toBeGreaterThan(0);
    // Nothing leaked and nothing was freed twice.
    expect([table.active, table.arena.slabs.inUse, table.arena.vectors.inUse]).toEqual([0, 0, 0]);
  }, 120_000);
});
