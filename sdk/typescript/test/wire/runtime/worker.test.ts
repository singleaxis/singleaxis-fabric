// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The Fabric worker (spec 055 §4.5): started with `execArgv: []` and `env: {}`,
 * unref'd, never running a preload even with `NODE_OPTIONS` set, and recreated after a
 * crash on the same shared memory, so the position counter is never reset.
 */
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Worker } from "node:worker_threads";

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { SlotPool, createPool } from "../../../src/wire/arena.js";
import { JOB_EXCHANGE, JOB_RELEASING, REQUEST } from "../../../src/wire/exchange.js";
import { STATE_FAILED, STATE_RUNNING } from "../../../src/wire/runtime.js";
import {
  FABRIC_WORKER_MARKER,
  FabricWorker,
  growPools,
  isFabricWorkerThread,
  runFabricWorker,
} from "../../../src/wire/worker.js";
import { type Bundles, bundleFixtures, drain, isolate, until } from "./helpers.js";

let bundles: Bundles;
const started: FabricWorker[] = [];

beforeAll(() => {
  bundles = bundleFixtures();
});
afterEach(async () => {
  for (const fabric of started.splice(0)) await fabric.stop(2000);
});
afterAll(() => bundles?.cleanup());

function start(options: Partial<ConstructorParameters<typeof FabricWorker>[1]> = {}) {
  const { runtime, table } = isolate();
  const report = new Int32Array(new SharedArrayBuffer(64));
  const fabric = new FabricWorker(runtime, {
    entry: bundles.file("fabric-entry"),
    snapshot: { report: report.buffer },
    ...options,
  });
  started.push(fabric);
  return { runtime, table, report, fabric };
}

/** Sends one exchange whose first metadata byte tells the test entry what to do. */
function send(table: ReturnType<typeof isolate>["table"], tag = 0): bigint {
  const handle = table.begin();
  table.meta(handle)![0] = tag;
  table.admit(handle, REQUEST, Buffer.from([1, 2, 3, 4]));
  const sequence = table.runtime.stats().nextSequence - 1n;
  expect(table.finish(handle, "complete")).toBe("enqueued");
  return sequence;
}

describe("starting the Fabric worker", () => {
  it("unrefs the worker and never reads its stdout or stderr", () => {
    const unref = vi.spyOn(Worker.prototype, "unref");
    const { fabric, runtime } = start();
    try {
      fabric.start();
      expect(unref).toHaveBeenCalledTimes(1);
      expect(unref.mock.instances[0]).toBe(fabric.worker);
      expect(runtime.state).toBe(STATE_RUNNING);
      // Captured (not the agent's streams) and not flowing: a flowing stream would
      // keep the agent's process alive.
      expect(fabric.worker!.stdout).not.toBe(process.stdout);
      expect(fabric.worker!.stdout.readableFlowing).not.toBe(true);
      expect(fabric.worker!.stderr.readableFlowing).not.toBe(true);
    } finally {
      unref.mockRestore();
    }
  });

  it("the worker sees no execArgv, no argv, an empty environment and the marker", async () => {
    const previous = process.env.F055_T4_CANARY;
    process.env.F055_T4_CANARY = "must-not-reach-the-worker";
    try {
      const { fabric, table, report, runtime } = start();
      fabric.start();
      const sequence = send(table);
      await until(() => Atomics.load(report, 0) === 1);
      expect({
        execArgv: report[1],
        envKeys: report[2],
        marked: report[3],
        sequence: BigInt(report[6]!),
        byteSum: report[7],
        generation: report[8],
        argv: report[9],
      }).toEqual({
        execArgv: 0,
        envKeys: 0,
        marked: 1,
        sequence,
        byteSum: 10,
        generation: 1,
        argv: 2,
      });
      expect(report[5]).toBe(fabric.worker!.threadId);
      // The worker released the job's bytes and removed it from the ring.
      await until(() => table.arena.slabs.inUse === 0 && runtime.stats().queuedJobs === 0);
      expect(await fabric.stop(5000)).toBe(true); // it drains and exits by itself
      expect(fabric.worker).toBeUndefined();
    } finally {
      if (previous === undefined) delete process.env.F055_T4_CANARY;
      else process.env.F055_T4_CANARY = previous;
    }
  });

  it("the worker reads each loss record once; a loss it cannot handle stays a gap without a reason", async () => {
    const { fabric, report, runtime } = start();
    fabric.start();
    runtime.lose("shutdown", 666n); // the test handler throws on this one
    runtime.lose("queue_full", 77n, 5n, 6n);
    await until(() => Atomics.load(report, 10) === 1 && runtime.peekLoss() === undefined);
    expect([report[11], report[12], report[13]]).toEqual([77, 6, 1]);
    const stats = runtime.stats();
    expect([stats.losses.queue_full, stats.losses.shutdown, stats.lossesUnattributed]).toEqual([
      1n,
      1n,
      1n,
    ]);
    expect(stats.workerRestarts).toBe(0); // a failing handler does not crash the worker
  });

  it("ticks the manifests' clock when idle and through a sustained job stream", async () => {
    const { fabric, table, report } = start();
    fabric.start();
    await until(() => Atomics.load(report, 14) >= 2); // idle: once per loop pass
    // 20 jobs of 25 ms each keep the queue non-empty for about 500 ms: the loop pass
    // never ends, yet the tick still runs between jobs every WORKER_TICK_MS.
    for (let n = 0; n < 20; n++) send(table, 0xd0);
    await until(() => Atomics.load(report, 0) === 20, 10_000);
    expect(Atomics.load(report, 15)).toBeGreaterThanOrEqual(2);
  });

  it("is not the Fabric worker anywhere else: the loop does not start", () => {
    expect(isFabricWorkerThread()).toBe(false);
    expect(runFabricWorker()).toBeUndefined();
    expect(FABRIC_WORKER_MARKER).toBe("fabric.wire.worker/1");
  });

  it("an entry that cannot start is a failed runtime, never an exception or a crash loop", async () => {
    const { fabric, runtime, table } = start({ entry: join(bundles.dir, "missing.cjs") });
    expect(() => fabric.start()).not.toThrow();
    await until(() => runtime.state === STATE_FAILED);
    expect(runtime.stats().workerRestarts).toBe(5);
    expect(runtime.stats().failureReason).toBe("worker_crash_loop");
    expect(table.begin()).toBe(-1);
  });

  it("a worker that cannot be constructed is a failed runtime with its reason", () => {
    const { fabric, runtime, table } = start({ entry: "not-a-path.cjs" });
    expect(runtime.stats().failureReason).toBeUndefined();
    expect(() => fabric.start()).not.toThrow();
    expect([runtime.state, runtime.stats().failureReason]).toEqual([
      STATE_FAILED,
      "worker_start_failed",
    ]);
    expect(fabric.worker).toBeUndefined();
    expect(table.begin()).toBe(-1);
  });
});

describe("arena growth in the Fabric worker", () => {
  it("a pool that cannot grow does not stop the others from growing", () => {
    const pool = (): SlotPool =>
      new SlotPool(
        createPool({ slotBytes: 64, maxSlots: 64, initialSlots: 2, lowWater: 2, growStep: 4 }),
      );
    const [failing, slabs, vectors] = [pool(), pool(), pool()];
    for (const each of [failing, slabs, vectors]) each.take();
    failing.growIfLow = () => {
      throw new RangeError("Array buffer allocation failed");
    };
    expect(() => growPools([failing, slabs, vectors])).not.toThrow();
    expect([failing.committed, slabs.committed, vectors.committed]).toEqual([2, 6, 6]);
  });
});

describe("with NODE_OPTIONS set to a customer preload", () => {
  // `--import` is the form the wire preload itself uses (§9.4); `--require` is kept for
  // launchers that only pass `-r`.
  it.each(["--require", "--import"])(
    "never runs a %s preload in the Fabric worker, and does not keep the process alive",
    (flag) => {
      const log = join(bundles.dir, `preload${flag}.log`);
      const preload = join(bundles.dir, "preload.cjs");
      writeFileSync(
        preload,
        `globalThis.__f055Preload = 1;\n` +
          `require("node:fs").appendFileSync(${JSON.stringify(log)}, ` +
          `String(require("node:worker_threads").threadId) + "\\n");\n`,
      );
      const control = join(bundles.dir, "control.cjs");
      writeFileSync(control, "process.exit(0);\n");
      const child = spawnSync(
        process.execPath,
        [bundles.file("host"), bundles.file("fabric-entry"), control],
        {
          encoding: "utf8",
          env: { ...process.env, NODE_OPTIONS: `${flag}=${preload}`, FABRIC_WIRE_AUTOLOAD: "1" },
          timeout: 90_000,
        },
      );
      // The host never stops the worker: a clean exit proves the worker is unref'd.
      expect([child.status, child.signal, child.stderr]).toEqual([0, null, ""]);
      const result = JSON.parse(child.stdout) as Record<string, number | boolean>;
      expect(result).toMatchObject({
        preloadedHere: 1,
        processed: 1,
        execArgv: 0,
        envKeys: 0,
        argv: 2,
        marked: 1,
        preloadedInFabricWorker: 0,
        fabricAlive: true,
      });
      const ran = readFileSync(log, "utf8").trim().split("\n").map(Number);
      // The trip-wire works: the preload ran in the main thread and in an ordinary
      // Worker (the control), and in no other thread.
      expect(ran).toEqual([0, result.controlThreadId]);
      expect(ran).not.toContain(result.fabricThreadId);
    },
    120_000,
  );
});

describe("a crashed Fabric worker", () => {
  it("is recreated on the same shared memory without resetting the counter", async () => {
    const { fabric, table, report, runtime } = start();
    fabric.start();
    send(table);
    await until(() => Atomics.load(report, 0) === 1);
    const first = fabric.worker!;
    const before = runtime.stats();
    expect([before.workerGeneration, before.workerRestarts, before.nextSequence]).toEqual([
      1,
      0,
      1n,
    ]);

    const crashing = send(table, 0xee); // the first worker dies handling this job
    await until(() => runtime.stats().workerGeneration === 2);
    // The replacement reads the unfinished job again and handles it.
    await until(() => Atomics.load(report, 0) === 2);
    expect(fabric.worker).not.toBe(first);
    expect([BigInt(report[6]!), report[8]]).toEqual([crashing, 2]);
    const after = runtime.stats();
    expect([after.workerRestarts, after.state]).toEqual([1, STATE_RUNNING]);
    // The counter continued: the next position follows the last, in the same epoch.
    expect(after.nextSequence).toBe(2n);
    expect(send(table)).toBe(2n);
    await until(() => Atomics.load(report, 0) === 3);
    expect(report[8]).toBe(2);
    await until(() => table.arena.slabs.inUse === 0);
    expect(drain(table).losses).toEqual([]);
  }, 30_000);

  it("a job the dead worker had handled and half released is not handled again with missing bytes", async () => {
    const { fabric, table, report, runtime } = start();
    const handled = send(table);
    // What a worker leaves when it dies after the handler returned and the request
    // side was released, but before the record left the ring.
    const record = runtime.jobs.peek()!;
    expect(record.kind).toBe(JOB_EXCHANGE);
    runtime.jobs.retag(JOB_RELEASING);
    table.arena.release(table.job(record.byteOffset).request.words);

    fabric.start();
    const next = send(table);
    await until(() => Atomics.load(report, 0) === 1);
    await until(() => runtime.stats().queuedJobs === 0);
    // Only the second job reached the handler, with all four of its bytes.
    expect([Atomics.load(report, 0), BigInt(report[6]!), report[7]]).toEqual([1, next, 10]);
    expect(next).toBe(handled + 1n);
    await until(() => table.arena.slabs.inUse === 0);
    expect(table.arena.vectors.inUse).toBe(0);
    expect(runtime.stats().jobsUnprocessed).toBe(0n);
    expect(drain(table).losses).toEqual([]);
  }, 30_000);

  it("is recreated after terminate(), and its lock is released", async () => {
    const { fabric, table, report, runtime } = start();
    fabric.start();
    send(table);
    await until(() => Atomics.load(report, 0) === 1);
    Atomics.store(runtime.i32, 65, 2); // the worker died holding the control-block lock
    await fabric.worker!.terminate();
    await until(() => runtime.stats().workerGeneration === 2);
    expect(runtime.tryLock()).toBe(true);
    runtime.unlock();
    send(table);
    await until(() => Atomics.load(report, 0) === 2);
  }, 30_000);

  it("an awaited stop() completes even when nothing else keeps the process alive", () => {
    // The worker is unref'd so it never holds the agent's process open; an explicit
    // stop the agent awaits must still drain and resolve within its deadline.
    const child = spawnSync(
      process.execPath,
      [bundles.file("stopper"), bundles.file("fabric-entry")],
      {
        encoding: "utf8",
        timeout: 60_000,
      },
    );
    expect([child.status, child.signal, child.stderr]).toEqual([0, null, ""]);
    expect(JSON.parse(child.stdout)).toEqual({ stopped: true, clean: true, queued: 0 });
  });

  it("a worker that crashes while it drains for stop() is not reported as a clean stop", async () => {
    const { fabric, table, runtime } = start();
    fabric.start();
    send(table, 0xef); // the worker dies on this job, after stop() asked it to drain
    expect(await fabric.stop(10_000)).toBe(false);
    expect(fabric.worker).toBeUndefined();
    expect(runtime.stats().workerRestarts).toBe(0); // a stopping worker is not replaced
  }, 30_000);

  it("stops capture with a failed state after five quick crashes; the agent's calls go on", async () => {
    const { fabric, table, runtime } = start();
    fabric.start();
    const sequence = send(table, 0xef); // every worker dies on this job
    await until(() => runtime.state === STATE_FAILED);
    expect(runtime.stats().workerRestarts).toBe(5);
    expect(runtime.stats().failureReason).toBe("worker_crash_loop");
    expect(fabric.worker).toBeUndefined();
    // Hooks keep returning at once: nothing is captured, nothing throws.
    expect(table.begin()).toBe(-1);
    expect(runtime.stats().nextSequence).toBe(sequence + 1n);
  }, 30_000);
});
