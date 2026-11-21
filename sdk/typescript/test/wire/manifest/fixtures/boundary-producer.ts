// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * A simulated application isolate for the manifest boundary test: it allocates
 * positions on the shared control block as fast as it can and, after each allocation,
 * reads the shared point-state word, as a hook reads its state. It reports every
 * `(sequence, state seen)` pair. It never calls `Atomics.wait`.
 */
import { parentPort, workerData } from "node:worker_threads";

import { type RuntimeShared, WireRuntime } from "../../../../src/wire/runtime.js";

interface Data {
  readonly shared: RuntimeShared;
  readonly start: SharedArrayBuffer;
  readonly state: SharedArrayBuffer;
  readonly count: number;
}

const data = workerData as Data;
const runtime = new WireRuntime(data.shared, "application");
const start = new Int32Array(data.start);
const state = new Int32Array(data.state);

Atomics.add(start, 1, 1);
while (Atomics.load(start, 0) === 0) {
  // spin until every producer is ready
}
const sequences = new BigInt64Array(data.count);
const seen = new Int8Array(data.count);
for (let n = 0; n < data.count; n++) {
  sequences[n] = runtime.allocate().sequence;
  seen[n] = Atomics.load(state, 0);
}
parentPort!.postMessage({ sequences, seen });
