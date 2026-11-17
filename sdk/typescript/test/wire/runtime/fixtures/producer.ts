// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * A simulated application isolate: a real worker thread on the shared control block.
 * It allocates positions, or runs whole exchanges, as fast as it can, and reports what
 * it saw. It never calls `Atomics.wait`.
 */
import { clearInterval, setInterval } from "node:timers";
import { parentPort, workerData } from "node:worker_threads";

import { ExchangeTable, NO_EXCHANGE, REQUEST } from "../../../../src/wire/exchange.js";
import { type RuntimeShared, WireRuntime, inheritedRuntime } from "../../../../src/wire/runtime.js";
import { patternBody } from "./pattern.js";

interface ProducerData {
  readonly shared?: RuntimeShared;
  readonly start: SharedArrayBuffer;
  readonly mode: "allocate" | "exchange";
  readonly id: number;
  readonly count: number;
  readonly runSlot: number;
}

const data = workerData as ProducerData;
// Without `shared`, the runtime must arrive through setEnvironmentData (§4.5).
const shared = data.shared ?? inheritedRuntime();
if (shared === undefined) throw new Error("no runtime was inherited");
const runtime = new WireRuntime(shared, "application");
const table = new ExchangeTable(runtime);
const start = new Int32Array(data.start);

function run(): void {
  const sequences: bigint[] = [];
  let lost = 0;
  let refused = 0;
  const outcomes: Record<string, number> = {};
  for (let n = 0; n < data.count; n++) {
    if (data.mode === "allocate") {
      const allocation = runtime.allocate(data.runSlot);
      sequences.push(allocation.sequence);
      if (allocation.lost) lost++;
      continue;
    }
    const handle = table.begin();
    if (handle === NO_EXCHANGE) {
      refused++;
      continue;
    }
    const body = patternBody(data.id, n);
    const meta = table.meta(handle);
    if (meta !== undefined) {
      meta[0] = data.id;
      meta[1] = n & 0xff;
      meta[2] = n >> 8;
    }
    // Several chunks, so appends cross slab boundaries while other isolates allocate.
    for (let at = 0; at < body.length; at += 50_000) {
      table.admit(handle, REQUEST, body.subarray(at, at + 50_000));
    }
    const outcome = table.finish(handle, "complete");
    outcomes[outcome] = (outcomes[outcome] ?? 0) + 1;
  }
  parentPort?.postMessage({ id: data.id, sequences, lost, refused, outcomes });
}

// Wait for the start signal on a timer: no `Atomics.wait`, as in a hook, and no busy
// loop either, so producers still starting are not starved by the ones already waiting.
Atomics.add(start, 1, 1);
const poll = setInterval(() => {
  if (Atomics.load(start, 0) === 0) return;
  clearInterval(poll);
  run();
}, 1);
