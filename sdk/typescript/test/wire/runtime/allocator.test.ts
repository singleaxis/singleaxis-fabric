// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The position allocator and the bounded try-lock (spec 055 §4.5 "Allocation"), with
 * real worker threads as the simulated application isolates on one control block.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { ExchangeTable, REQUEST, RESPONSE } from "../../../src/wire/exchange.js";
import {
  CONTROL_BYTES,
  LOCK_SPIN_MS,
  STATE_CLOSING,
  WireRuntime,
  createRuntimeShared,
  inheritedRuntime,
  publishRuntime,
} from "../../../src/wire/runtime.js";
import { FabricWorker } from "../../../src/wire/worker.js";
import { REPO } from "../helpers.js";
import { type Bundles, bundleFixtures, drain, isolate, produce, until } from "./helpers.js";

let bundles: Bundles;
beforeAll(() => {
  bundles = bundleFixtures();
});
afterAll(() => bundles?.cleanup());

describe("allocation under 8 concurrent producers", () => {
  it("gives every position to exactly one producer, in increasing order for each", async () => {
    const shared = createRuntimeShared({ firstSequence: 1000n, epoch: 7n });
    const runtime = new WireRuntime(shared, "installer");
    expect(runtime.tryLock()).toBe(true);
    runtime.setRunSegment(0, 11n, 12n);
    runtime.setRunSegment(1, 21n, 22n);
    runtime.unlock();
    // The producers receive the runtime through setEnvironmentData, not workerData.
    publishRuntime(shared);
    expect(inheritedRuntime()).toBe(shared);
    const each = 20_000;
    const results = await produce(bundles.file("producer"), undefined, 8, {
      mode: "allocate",
      count: each,
      runSlot: (id) => id % 2,
    });

    const all = results.flatMap((result) => result.sequences);
    expect(all.length).toBe(8 * each);
    expect(new Set(all).size).toBe(all.length);
    const sorted = [...all].sort((a, b) => (a < b ? -1 : 1));
    expect(sorted[0]).toBe(1000n);
    expect(sorted.at(-1)).toBe(1000n + BigInt(all.length) - 1n);
    for (const result of results) {
      for (let n = 1; n < result.sequences.length; n++) {
        expect(result.sequences[n]! > result.sequences[n - 1]!).toBe(true);
      }
    }
    // Membership is decided with allocation: every position is counted in its run's
    // segment, or is an internal_error loss there (a lock timeout under contention).
    const stats = runtime.stats();
    const lost = results.reduce((sum, result) => sum + result.lost, 0);
    expect(stats.nextSequence).toBe(1000n + BigInt(all.length));
    expect(stats.losses.internal_error).toBe(BigInt(lost));
    expect(stats.lockTimeouts).toBe(BigInt(lost));
    expect(runtime.runPositions(0) + runtime.runPositions(1)).toBe(BigInt(all.length - lost));
    expect(runtime.epoch).toBe(7n);
  }, 120_000);

  it("keeps every body intact while 8 producers share the arenas and the job ring", async () => {
    const shared = createRuntimeShared({
      maxInflightBytes: 48 * 1024 * 1024,
      initialPayloadBytes: 1024 * 1024,
      // Bodies here are under 150 KiB; a 1 MiB side cap keeps the committed headroom
      // small, so the producers run on slabs this thread grows while they run.
      maxRetainBytes: 1024 * 1024,
      queueMaxItems: 64,
    });
    const table = new ExchangeTable(new WireRuntime(shared, "worker"));
    const { patternBody } = await import("./helpers.js");
    const seen = new Set<bigint>();
    let exact = 0;
    let truncated = 0;
    const consume = (): void => {
      // This thread plays the Fabric worker: it reads jobs and grows the arenas.
      for (const job of drain(table).jobs) {
        const expected = patternBody(job.meta[0]!, job.meta[1]! | (job.meta[2]! << 8));
        expect(seen.has(job.sequence)).toBe(false);
        seen.add(job.sequence);
        if (job.request.state === "exact") {
          exact++;
          expect(job.requestBytes.equals(expected)).toBe(true);
        } else {
          // Never a partial body labelled exact: a short body names its reason.
          truncated++;
          expect(job.request.state).toBe("truncated");
          expect(job.request.reason).toBe("inflight_budget");
          expect(job.request.byteLength).toBe(job.requestBytes.length);
          expect(job.requestBytes.length).toBeLessThan(expected.length);
          expect(expected.subarray(0, job.requestBytes.length).equals(job.requestBytes)).toBe(true);
        }
      }
      for (const pool of [table.arena.slabs, table.arena.vectors, table.pool]) pool.growIfLow();
    };
    const results = await produce(
      bundles.file("producer"),
      shared,
      8,
      { mode: "exchange", count: 150 },
      consume,
    );
    consume();

    const enqueued = results.reduce((sum, result) => sum + (result.outcomes.enqueued ?? 0), 0);
    const lost = results.reduce((sum, result) => sum + (result.outcomes.lost ?? 0), 0);
    const stats = table.runtime.stats();
    expect(enqueued + lost).toBe(8 * 150);
    expect(exact + truncated).toBe(enqueued);
    expect(exact).toBeGreaterThan(0);
    // A full ring is the only loss here, and each one is a named queue_full position.
    expect(stats.losses.queue_full).toBe(BigInt(lost));
    expect(stats.nextSequence).toBe(BigInt(8 * 150));
    // The arena grew in this thread and the producers used the new slabs.
    expect(table.arena.slabs.committed).toBeGreaterThan(16);
    expect(table.arena.slabs.inUse).toBe(0);
    expect(table.arena.vectors.inUse).toBe(0);
    expect(table.pool.inUse).toBe(0);
  }, 120_000);
});

describe("the control-block try-lock", () => {
  it("times out without blocking: the position is allocated and lost as internal_error", () => {
    const { runtime } = isolate();
    const other = new WireRuntime(runtime.shared, "worker");
    expect(runtime.tryLock()).toBe(true);
    runtime.setRunSegment(3, 0x51n, 0x52n);
    runtime.unlock();
    const before = runtime.allocate(3);
    expect(before).toEqual({ sequence: 0n, segmentHi: 0x51n, segmentLo: 0x52n, lost: false });

    expect(other.tryLock()).toBe(true); // another isolate holds the lock and stalls
    const started = performance.now();
    const allocation = runtime.allocate(3);
    const elapsed = performance.now() - started;
    expect(allocation).toEqual({ sequence: 1n, segmentHi: 0x51n, segmentLo: 0x52n, lost: true });
    expect(elapsed).toBeGreaterThanOrEqual(LOCK_SPIN_MS);
    expect(elapsed).toBeLessThan(50); // a 20 µs spin, never a wait
    expect(runtime.peekLoss()).toEqual({
      reason: "internal_error",
      sequence: 1n,
      segmentHi: 0x51n,
      segmentLo: 0x52n,
    });
    // The lost position is not counted in the segment, so its seal cannot match.
    expect(runtime.runPositions(3)).toBe(1n);
    expect(runtime.stats().lockTimeouts).toBe(1n);
    // A position outside any run needs no lock.
    expect(runtime.allocate()).toEqual({ sequence: 2n, segmentHi: 0n, segmentLo: 0n, lost: false });
    other.unlock();
    expect(runtime.allocate(3).lost).toBe(false);
  });

  it("an exchange that begins during a lock timeout is not captured and is a named loss", () => {
    const { runtime, table } = isolate();
    const other = new WireRuntime(runtime.shared, "worker");
    other.tryLock();
    expect(table.begin({ runSlot: 0 })).toBe(-1);
    other.unlock();
    expect(drain(table).losses.map((loss) => loss.reason)).toEqual(["internal_error"]);
    expect(table.active).toBe(0);
  });

  it("the Fabric worker waits for the lock with waitAsync, and a dead worker's lock is broken", async () => {
    const { runtime } = isolate();
    const worker = new WireRuntime(runtime.shared, "worker");
    expect(runtime.tryLock()).toBe(true);
    const waiting = worker.lockAsync(5000);
    setTimeout(() => runtime.unlock(), 20);
    expect(await waiting).toBe(true);
    expect(runtime.tryLock()).toBe(false);
    expect(await worker.lockAsync(10)).toBe(false); // not re-entrant: it times out
    runtime.breakWorkerLock();
    expect(runtime.tryLock()).toBe(true);
    runtime.breakWorkerLock(); // never breaks a lock the worker does not hold
    expect(worker.tryLock()).toBe(false);
  });

  it("calls the registration mirror with the next sequence, and survives a mirror that throws", () => {
    const { runtime } = isolate({ firstSequence: 40n });
    const stored: bigint[] = [];
    runtime.mirror = (next) => stored.push(next);
    runtime.allocate();
    runtime.allocate(0);
    expect(stored).toEqual([41n, 42n]);
    runtime.mirror = () => {
      throw new Error("store64 failed");
    };
    expect(runtime.allocate().sequence).toBe(42n);
  });
});

describe("no Atomics.wait on the installing isolate (trip-wire)", () => {
  it("never calls Atomics.wait through allocation, contention, exhaustion, finish, shutdown or the worker", async () => {
    const wait = vi.spyOn(Atomics, "wait").mockImplementation(() => {
      throw new Error("Atomics.wait was called on an application isolate");
    });
    try {
      const { runtime, table } = isolate({ queueMaxItems: 2, maxExchanges: 4, maxVectors: 2 });
      const other = new WireRuntime(runtime.shared, "worker");
      other.tryLock();
      runtime.allocate(0); // lock timeout
      other.unlock();
      runtime.allocate(0);
      const report = new SharedArrayBuffer(64);
      const fabric = new FabricWorker(runtime, {
        entry: bundles.file("fabric-entry"),
        snapshot: { report },
      });
      fabric.start();
      for (let n = 0; n < 12; n++) {
        const handle = table.begin({ runSlot: 0 });
        table.admit(handle, REQUEST, Buffer.alloc(100_000, n));
        table.responseStarted(handle);
        table.admit(handle, RESPONSE, "text", "utf8");
        table.finish(handle, n % 2 === 0 ? "complete" : "error");
      }
      const open = table.begin();
      await until(() => runtime.stats().queuedJobs === 0);
      expect(await fabric.stop(5000)).toBe(true);
      runtime.setState(STATE_CLOSING);
      expect(table.shutdown()).toBe(1);
      expect(table.finish(open, "complete")).toBe("already_finished");
      expect(wait).not.toHaveBeenCalled();
    } finally {
      wait.mockRestore();
    }
  }, 30_000);

  it("has no Atomics.wait call in the shared runtime's sources", () => {
    for (const name of ["runtime", "arena", "queue", "exchange", "worker"]) {
      const source = readFileSync(join(REPO, "sdk/typescript/src/wire", `${name}.ts`), "utf8");
      const code = source.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
      expect(code).not.toMatch(/Atomics\s*\.\s*wait\s*\(/);
      expect(code).not.toMatch(/Atomics\s*\[/);
    }
  });

  it("keeps the control block within 64 KiB", () => {
    expect(CONTROL_BYTES).toBeLessThanOrEqual(64 * 1024);
  });
});
