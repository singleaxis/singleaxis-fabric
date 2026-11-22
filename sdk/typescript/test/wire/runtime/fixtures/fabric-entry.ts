// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * What the wire core does in the Fabric worker: call `runFabricWorker`. The job handler
 * stands in for the pipeline of later units; it reports what the worker saw through a
 * shared buffer, and crashes the worker when a test job asks it to.
 */
import { setImmediate } from "node:timers";
import { threadId } from "node:worker_threads";

import { isFabricWorkerThread, runFabricWorker } from "../../../../src/wire/worker.js";

const CRASH_ONCE = 0xee;
const CRASH_ALWAYS = 0xef;
/** A job the handler takes 25 ms over: a run of them is a sustained job stream. */
const SLOW = 0xd0;

function crash(): Promise<void> {
  setImmediate(() => {
    throw new Error("fabric worker test crash");
  });
  return new Promise(() => undefined);
}

void runFabricWorker({
  async job(job, { runtime, exchanges, snapshot }) {
    const report = new Int32Array((snapshot as { report: SharedArrayBuffer }).report);
    const generation = runtime.workerGeneration;
    if (job.meta[0] === CRASH_ALWAYS) return crash();
    if (job.meta[0] === CRASH_ONCE && generation === 1) return crash();
    if (job.meta[0] === SLOW) await new Promise((resolve) => setTimeout(resolve, 25));
    // A stray line from the worker must never reach the agent's stdout or stderr.
    console.log("f055-t4 stray stdout line");
    console.error("f055-t4 stray stderr line");
    let sum = 0;
    for (const chunk of exchanges.arena.chunks(job.request.words)) {
      for (const byte of chunk) sum = (sum + byte) | 0;
    }
    Atomics.store(report, 1, process.execArgv.length);
    Atomics.store(report, 2, Object.keys(process.env).length);
    Atomics.store(report, 3, isFabricWorkerThread() ? 1 : 0);
    Atomics.store(report, 4, (globalThis as { __f055Preload?: number }).__f055Preload ?? 0);
    Atomics.store(report, 5, threadId);
    Atomics.store(report, 6, Number(job.sequence));
    Atomics.store(report, 7, sum);
    Atomics.store(report, 8, generation);
    Atomics.store(report, 9, process.argv.length);
    Atomics.add(report, 0, 1);
  },
  loss(loss, { snapshot }) {
    const report = new Int32Array((snapshot as { report: SharedArrayBuffer }).report);
    if (loss.sequence === 666n) throw new Error("fabric worker test loss failure");
    Atomics.store(report, 11, Number(loss.sequence));
    Atomics.store(report, 12, Number(loss.segmentLo));
    Atomics.store(report, 13, loss.reason === "queue_full" ? 1 : 0);
    Atomics.add(report, 10, 1);
  },
  async tick({ runtime, snapshot }) {
    const report = new Int32Array((snapshot as { report: SharedArrayBuffer }).report);
    Atomics.add(report, 14, 1);
    // A tick while jobs wait: the job stream did not starve the clock.
    if (runtime.stats().queuedJobs > 0) Atomics.add(report, 15, 1);
    // While a test holds the tick (slot 18), the worker sits between its job drain and its
    // stop check; slot 19 says it got there.
    if (Atomics.load(report, 18) === 1) {
      Atomics.store(report, 19, 1);
      while (Atomics.load(report, 18) === 1) {
        await new Promise((resolve) => setTimeout(resolve, 2));
      }
    }
  },
  stop({ runtime, snapshot }) {
    // 055-t10: the orderly stop, after every loss recorded before the request was handled.
    const report = new Int32Array((snapshot as { report: SharedArrayBuffer }).report);
    Atomics.store(report, 16, Atomics.load(report, 10));
    Atomics.store(report, 17, runtime.peekLoss() === undefined ? 1 : 2);
    // Jobs handled when the stop handler ran, plus one (0: never ran).
    Atomics.store(report, 20, Atomics.load(report, 0) + 1);
  },
});
