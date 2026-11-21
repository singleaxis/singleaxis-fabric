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
 *   saturated capture worker);
 * - `diskFull` (055-t16): the spool directory; creating a file in it fails with `ENOSPC`
 *   (a full volume), so every record and loss is refused and only the loss ledger,
 *   preallocated when the spool opened, holds the losses.
 */
import fs from "node:fs";

import { runFabricMain } from "../../../../sdk/typescript/src/wire/fabric-main.js";
import { CapturePipeline } from "../../../../sdk/typescript/src/wire/worker.js";

const faults = ((globalThis as { __f055t13Faults?: Record<string, unknown> }).__f055t13Faults ?? {}) as {
  fsyncMs?: number;
  jobMs?: number;
  diskFull?: string;
};
const sleeper = new Int32Array(new SharedArrayBuffer(4));
if (faults.fsyncMs !== undefined) {
  const fsyncSync = fs.fsyncSync;
  (fs as { fsyncSync: typeof fs.fsyncSync }).fsyncSync = (fd) => {
    Atomics.wait(sleeper, 0, 0, faults.fsyncMs);
    fsyncSync(fd);
  };
}
if (faults.diskFull !== undefined) {
  const inSpool = `${faults.diskFull}/`;
  const openSync = fs.openSync;
  (fs as { openSync: typeof fs.openSync }).openSync = ((path, flags, mode) => {
    if (
      typeof path === "string" &&
      path.startsWith(inSpool) &&
      typeof flags === "number" &&
      (flags & fs.constants.O_CREAT) !== 0
    ) {
      throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC", errno: -28 });
    }
    return openSync(path, flags, mode);
  }) as typeof fs.openSync;
}
if (faults.jobMs !== undefined) {
  const handle = CapturePipeline.prototype.handle;
  CapturePipeline.prototype.handle = async function stalled(this: CapturePipeline, ...args) {
    await new Promise((resolve) => setTimeout(resolve, faults.jobMs));
    return handle.apply(this, args);
  };
}
void runFabricMain();
