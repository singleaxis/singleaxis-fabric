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

function crash(): Promise<void> {
  setImmediate(() => {
    throw new Error("fabric worker test crash");
  });
  return new Promise(() => undefined);
}

void runFabricWorker({
  job(job, { runtime, exchanges, snapshot }) {
    const report = new Int32Array((snapshot as { report: SharedArrayBuffer }).report);
    const generation = runtime.workerGeneration;
    if (job.meta[0] === CRASH_ALWAYS) return crash();
    if (job.meta[0] === CRASH_ONCE && generation === 1) return crash();
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
});
