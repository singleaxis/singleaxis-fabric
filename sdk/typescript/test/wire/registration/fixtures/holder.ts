// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * A Node process that installs as the recorder would: loads the native module, creates
 * the shared runtime, registers its epoch on the spool and allocates positions, from the
 * installing thread and from attached application isolates (worker threads that mirror
 * through the published map handle). It prints one JSON line and stays alive until the
 * test kills it.
 *
 *   node holder.cjs <prebuilds> <sha256> <spool> <source> <count> <workers> <per-worker> [epoch]
 */
import { clearInterval, setInterval } from "node:timers";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

import { loadNative, nativeTarget } from "../../../../src/wire/native.js";
import { attachMirror, register } from "../../../../src/wire/registration.js";
import {
  type RuntimeShared,
  WireRuntime,
  createRuntimeShared,
} from "../../../../src/wire/runtime.js";

interface IsolateData {
  readonly shared: RuntimeShared;
  readonly prebuilds: string;
  readonly digest: string;
  readonly count: number;
  readonly start: SharedArrayBuffer;
}

function load(prebuilds: string, digest: string, selfTestDir?: string) {
  const target = nativeTarget();
  if (target === null) throw new Error("no native target for this platform");
  const loaded = loadNative({
    prebuildsDir: prebuilds,
    digests: { [target]: digest },
    ...(selfTestDir === undefined ? {} : { selfTestDir }),
  });
  if (!loaded.ok) throw new Error(`${loaded.reason}: ${loaded.message}`);
  return loaded.addon;
}

if (!isMainThread) {
  // An attached application isolate: its own runtime view, the mirror from the
  // control block, and as many allocations as it can make once all have started.
  const data = workerData as IsolateData;
  const addon = load(data.prebuilds, data.digest);
  const runtime = new WireRuntime(data.shared, "application");
  attachMirror(runtime, addon);
  const start = new Int32Array(data.start);
  Atomics.add(start, 1, 1);
  const poll = setInterval(() => {
    if (Atomics.load(start, 0) === 0) return;
    clearInterval(poll);
    for (let n = 0; n < data.count; n++) runtime.allocate();
    parentPort?.postMessage("done");
  }, 1);
} else {
  const [script, prebuilds, digest, spool, source, count, workers, perWorker, forced] =
    process.argv.slice(1);
  if ([script, prebuilds, digest, spool, source, count, workers, perWorker].includes(undefined)) {
    throw new Error(
      "usage: holder.cjs <prebuilds> <sha256> <spool> <source> <count> <workers> <per-worker> [epoch]",
    );
  }
  const addon = load(prebuilds!, digest!, spool);
  const shared = createRuntimeShared({
    maxInflightBytes: 4 * 1024 * 1024,
    maxRetainBytes: 1024 * 1024,
    initialPayloadBytes: 1024 * 1024,
    queueMaxItems: 16,
    maxExchanges: 16,
    maxVectors: 16,
    ...(forced === undefined ? {} : { epoch: BigInt(forced) }),
  });
  const runtime = new WireRuntime(shared, "installer");
  const drawn = runtime.epoch;
  const registration = register({ addon, spoolDir: spool, sourceId: source!, runtime });
  for (let n = 0; n < Number(count); n++) runtime.allocate();
  const start = new SharedArrayBuffer(8);
  const isolates = Array.from(
    { length: Number(workers) },
    () =>
      new Worker(script!, {
        workerData: {
          shared,
          prebuilds: prebuilds!,
          digest: digest!,
          count: Number(perWorker),
          start,
        } satisfies IsolateData,
      }),
  );
  const finished = isolates.map(
    (worker) => new Promise<void>((resolve) => worker.once("message", () => resolve())),
  );
  const flag = new Int32Array(start);
  const begin = setInterval(() => {
    if (Atomics.load(flag, 1) < isolates.length) return;
    clearInterval(begin);
    Atomics.store(flag, 0, 1);
  }, 1);
  void Promise.all(finished).then(async () => {
    await Promise.all(isolates.map((worker) => worker.terminate()));
    process.stdout.write(
      `${JSON.stringify({
        status: registration.status,
        reason: registration.reason ?? null,
        epoch: String(registration.epoch),
        drawn: String(drawn),
        runtimeEpoch: String(runtime.epoch),
        next: String(runtime.nextSequence),
        pid: process.pid,
      })}\n`,
    );
    setInterval(() => undefined, 1000);
  });
}
