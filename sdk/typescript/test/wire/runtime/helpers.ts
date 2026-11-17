// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the shared-runtime tests (spec 055 §9.5, unit 055-t4).
 *
 * Worker threads need JavaScript files, and the wire core is not packaged until unit
 * 055-t14, so the fixtures are bundled here with esbuild: the exact version the
 * package pins in `overrides` and locks in `package-lock.json` (tsup builds with it).
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";

import { buildSync } from "esbuild";

import { ExchangeTable, type ExchangeJob } from "../../../src/wire/exchange.js";
import {
  type RuntimeLossReason,
  type RuntimeOptions,
  type RuntimeShared,
  WireRuntime,
  createRuntimeShared,
} from "../../../src/wire/runtime.js";

export { patternBody } from "./fixtures/pattern.js";

const HERE = dirname(fileURLToPath(import.meta.url));

export interface Bundles {
  readonly dir: string;
  file(name: "producer" | "fabric-entry" | "host"): string;
  cleanup(): void;
}

/** Bundles the worker fixtures into a temporary directory as CommonJS files. */
export function bundleFixtures(): Bundles {
  const dir = mkdtempSync(join(tmpdir(), "f055-t4-runtime-"));
  const names = ["producer", "fabric-entry", "host"] as const;
  buildSync({
    entryPoints: names.map((name) => join(HERE, "fixtures", `${name}.ts`)),
    outdir: dir,
    outExtension: { ".js": ".cjs" },
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    logLevel: "silent",
  });
  return {
    dir,
    file: (name) => join(dir, `${name}.cjs`),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

export const KIB = 1024;

/** One isolate's view of a new runtime, small enough to exhaust in a test. */
export function isolate(options: RuntimeOptions = {}): {
  runtime: WireRuntime;
  table: ExchangeTable;
} {
  const runtime = new WireRuntime(
    createRuntimeShared({ maxInflightBytes: 64 * 64 * KIB, ...options }),
    "installer",
  );
  return { runtime, table: new ExchangeTable(runtime) };
}

export interface Drained {
  readonly jobs: (ExchangeJob & { requestBytes: Buffer; responseBytes: Buffer })[];
  readonly losses: { reason: RuntimeLossReason; sequence: bigint; segmentHi: bigint }[];
}

/** What the Fabric worker would read: every queued job (with its bytes) and loss. */
export function drain(table: ExchangeTable): Drained {
  const { runtime, arena } = table;
  const out: Drained = { jobs: [], losses: [] };
  for (let record = runtime.jobs.peek(); record !== undefined; record = runtime.jobs.peek()) {
    const job = table.job(record.byteOffset);
    out.jobs.push({
      ...job,
      meta: job.meta.slice(),
      requestBytes: Buffer.concat([...arena.chunks(job.request.words)]),
      responseBytes: Buffer.concat([...arena.chunks(job.response.words)]),
    });
    arena.release(job.request.words);
    arena.release(job.response.words);
    runtime.jobs.commit();
  }
  for (let loss = runtime.peekLoss(); loss !== undefined; loss = runtime.peekLoss()) {
    out.losses.push(loss);
    runtime.commitLoss();
  }
  return out;
}

/** Polls `done` without blocking the thread. */
export async function until(done: () => boolean, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!done()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for the condition");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

export interface ProducerResult {
  id: number;
  sequences: bigint[];
  lost: number;
  refused: number;
  outcomes: Record<string, number>;
}

/** Starts `count` producers together and resolves with their reports. */
export async function produce(
  file: string,
  shared: RuntimeShared | undefined,
  count: number,
  each: { mode: "allocate" | "exchange"; count: number; runSlot?: (id: number) => number },
  whileRunning: () => void = () => undefined,
): Promise<ProducerResult[]> {
  const start = new SharedArrayBuffer(8);
  const results: Promise<ProducerResult>[] = [];
  for (let id = 0; id < count; id++) {
    const worker = new Worker(file, {
      workerData: { shared, start, id, ...each, runSlot: each.runSlot?.(id) ?? -1 },
    });
    results.push(
      new Promise((resolve, reject) => {
        worker.once("message", resolve);
        worker.once("error", reject);
      }),
    );
  }
  const words = new Int32Array(start);
  await until(() => Atomics.load(words, 1) === count);
  Atomics.store(words, 0, 1);
  let running = true;
  const all = Promise.all(results).finally(() => (running = false));
  while (running) {
    whileRunning();
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  return all;
}
