// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * A Fabric worker whose pipeline is CPU-bound (unit 055-t8, "worker CPU stall does not
 * move the hook medians"): each job spins for `stallMs` on the worker thread, as a slow
 * PROTECT would.
 */
import { workerData } from "node:worker_threads";

import { runFabricWorker } from "../../../../src/wire/worker.js";

const stallMs = (workerData as { snapshot?: { stallMs?: number } } | null)?.snapshot?.stallMs ?? 0;
void runFabricWorker({
  job: () => {
    const until = performance.now() + stallMs;
    while (performance.now() < until) {
      // the worker's CPU, never the application's
    }
  },
});
