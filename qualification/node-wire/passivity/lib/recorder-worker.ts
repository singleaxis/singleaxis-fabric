// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The Fabric worker of the stalled-recorder step (spec 055 §9.2): the arm's test-only
 * faults, then the SDK's own Fabric worker (`runFabricMain`: pipeline and sender). The
 * faults exist only in this harness file; the arm writes them into a one-line entry file
 * that sets `globalThis.__f055t13Faults` before requiring this bundle.
 *
 * - `fsyncMs`: every file fsync of the spool waits this long first (a stalled disk);
 * - `jobMs`: every captured exchange waits this long before the pipeline handles it (a
 *   saturated capture worker).
 */
import fs from "node:fs";

import { runFabricMain } from "../../../../sdk/typescript/src/wire/fabric-main.js";
import { CapturePipeline } from "../../../../sdk/typescript/src/wire/worker.js";

const faults = ((globalThis as { __f055t13Faults?: Record<string, number> }).__f055t13Faults ?? {}) as {
  fsyncMs?: number;
  jobMs?: number;
};
const sleeper = new Int32Array(new SharedArrayBuffer(4));
if (faults.fsyncMs !== undefined) {
  const fsyncSync = fs.fsyncSync;
  (fs as { fsyncSync: typeof fs.fsyncSync }).fsyncSync = (fd) => {
    Atomics.wait(sleeper, 0, 0, faults.fsyncMs);
    fsyncSync(fd);
  };
}
if (faults.jobMs !== undefined) {
  const handle = CapturePipeline.prototype.handle;
  CapturePipeline.prototype.handle = async function stalled(this: CapturePipeline, ...args) {
    await new Promise((resolve) => setTimeout(resolve, faults.jobMs));
    return handle.apply(this, args);
  };
}
void runFabricMain();
