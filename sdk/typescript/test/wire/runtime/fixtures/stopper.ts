// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * An agent whose last act is an explicit, awaited stop of the Fabric worker: nothing
 * else keeps its event loop alive. The stop must still complete (and print) within its
 * deadline, although the worker itself is unref'd.
 */
import { ExchangeTable, REQUEST } from "../../../../src/wire/exchange.js";
import { WireRuntime, createRuntimeShared } from "../../../../src/wire/runtime.js";
import { FabricWorker } from "../../../../src/wire/worker.js";

async function main(): Promise<void> {
  const runtime = new WireRuntime(createRuntimeShared(), "installer");
  const table = new ExchangeTable(runtime);
  const fabric = new FabricWorker(runtime, {
    entry: process.argv[2]!,
    snapshot: { report: new SharedArrayBuffer(64) },
  });
  fabric.start();
  const handle = table.begin();
  table.admit(handle, REQUEST, Buffer.from([1, 2, 3]));
  table.finish(handle, "complete");
  const clean = await fabric.stop(10_000);
  process.stdout.write(JSON.stringify({ stopped: true, clean, queued: runtime.jobs.count }) + "\n");
}

void main();
