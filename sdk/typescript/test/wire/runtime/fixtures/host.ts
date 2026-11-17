// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * An agent process started with a customer `NODE_OPTIONS=--require` preload. It starts
 * the Fabric worker, sends it one job, starts an ordinary Worker as the control, prints
 * what happened and returns. It does not stop the Fabric worker: the process must end
 * by itself, because the worker is unref'd.
 */
import { Worker } from "node:worker_threads";

import { ExchangeTable, REQUEST } from "../../../../src/wire/exchange.js";
import { WireRuntime, createRuntimeShared } from "../../../../src/wire/runtime.js";
import { FabricWorker } from "../../../../src/wire/worker.js";

async function main(): Promise<void> {
  const entry = process.argv[2]!;
  const runtime = new WireRuntime(createRuntimeShared(), "installer");
  const table = new ExchangeTable(runtime);
  const report = new SharedArrayBuffer(64);
  const words = new Int32Array(report);
  const fabric = new FabricWorker(runtime, { entry, snapshot: { report } });
  fabric.start();
  const handle = table.begin();
  table.admit(handle, REQUEST, Buffer.from([1, 2, 3]));
  table.finish(handle, "complete");
  while (Atomics.load(words, 0) === 0) await new Promise((resolve) => setTimeout(resolve, 5));
  // The control: an ordinary Worker inherits NODE_OPTIONS and runs the preload. It runs
  // a file, because an `--import` preload does not run in an `eval: true` Worker.
  const control = new Worker(process.argv[3]!);
  const controlThreadId = control.threadId;
  await new Promise((resolve) => control.once("exit", resolve));
  const fabricThread = fabric.worker;
  process.stdout.write(
    JSON.stringify({
      preloadedHere: (globalThis as { __f055Preload?: number }).__f055Preload ?? 0,
      processed: Atomics.load(words, 0),
      execArgv: Atomics.load(words, 1),
      envKeys: Atomics.load(words, 2),
      marked: Atomics.load(words, 3),
      preloadedInFabricWorker: Atomics.load(words, 4),
      fabricThreadId: Atomics.load(words, 5),
      argv: Atomics.load(words, 9),
      controlThreadId,
      fabricAlive: fabricThread !== undefined,
    }) + "\n",
  );
}

void main();
