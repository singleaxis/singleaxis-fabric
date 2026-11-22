// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The capture the passivity harness measures (spec 055 §9.2): the shared runtime, a real
 * Fabric worker and the undici hook, built from the SDK source into one CommonJS file by
 * `build.mjs` (the packed package replaces this from unit 055-t14). The Fabric worker
 * has no pipeline yet (units 055-t7, 055-t8): it drains each job and releases its slabs,
 * which is the hook's side of the handoff the gates measure.
 *
 * Modes:
 * - `enabled`: runtime running, worker draining, hook subscribed;
 * - `disabled`: hook subscribed to a runtime that is not running (installed, capturing
 *   nothing);
 * - `saturated`: hook subscribed, no Fabric worker, so the ring and the arena fill and
 *   every later exchange is a named loss (the memory-bound step).
 */
import { endpointMatcher } from "../../../../sdk/typescript/src/wire/match.js";
import { ExchangeTable } from "../../../../sdk/typescript/src/wire/exchange.js";
import {
  STATE_CLOSED,
  WireRuntime,
  createRuntimeShared,
  type RuntimeOptions,
} from "../../../../sdk/typescript/src/wire/runtime.js";
import { installUndiciHook, type UndiciHook } from "../../../../sdk/typescript/src/wire/undici.js";
import { FabricWorker } from "../../../../sdk/typescript/src/wire/worker.js";

export type Mode = "enabled" | "disabled" | "saturated";

export interface Started {
  readonly hook: UndiciHook;
  readonly runtime: WireRuntime;
  readonly table: ExchangeTable;
  /** Memory the runtime reserved (shared buffers at their current length). */
  sharedBytes(): number;
  /** The most the shared buffers can grow to under this configuration. */
  sharedMaxBytes(): number;
  /** High-water marks of the pools (slots). */
  peaks(): { exchanges: number; slabs: number; vectors: number; jobs: number };
  stop(): Promise<void>;
}

/** Starts capture for `http://127.0.0.1:<port>` (openai dialect). */
export function startCapture(options: {
  readonly port: number;
  readonly mode: Mode;
  readonly workerEntry: string;
  readonly runtime?: RuntimeOptions;
  /** Match any port on 127.0.0.1 (a scenario whose server port is not known yet). */
  readonly anyPort?: boolean;
}): Started {
  const shared = createRuntimeShared(options.runtime);
  const runtime = new WireRuntime(shared, "installer");
  const table = new ExchangeTable(runtime);
  let worker: FabricWorker | undefined;
  if (options.mode === "enabled") {
    worker = new FabricWorker(runtime, { entry: options.workerEntry });
    worker.start();
  } else if (options.mode === "disabled") {
    runtime.setState(STATE_CLOSED);
  }
  const hook = installUndiciHook({
    table,
    endpoints: [
      endpointMatcher({
        endpointId: "harness",
        dialect: "openai",
        hosts: ["127.0.0.1"],
        ports: options.anyPort === true ? undefined : [options.port],
        schemes: ["http"],
      }),
    ],
  });
  return {
    hook,
    runtime,
    table,
    sharedBytes: () =>
      shared.control.byteLength +
      shared.payload.slabs.data.byteLength +
      shared.payload.slabs.meta.byteLength +
      shared.payload.vectors.data.byteLength +
      shared.payload.vectors.meta.byteLength +
      shared.exchanges.data.byteLength +
      shared.exchanges.meta.byteLength +
      shared.jobs.buffer.byteLength +
      shared.losses.buffer.byteLength,
    sharedMaxBytes: () =>
      [
        shared.control,
        shared.payload.slabs.data,
        shared.payload.slabs.meta,
        shared.payload.vectors.data,
        shared.payload.vectors.meta,
        shared.exchanges.data,
        shared.exchanges.meta,
        shared.jobs.buffer,
        shared.losses.buffer,
      ].reduce(
        (sum, buffer) =>
          sum + ((buffer as { maxByteLength?: number }).maxByteLength ?? buffer.byteLength),
        0,
      ),
    peaks: () => ({
      exchanges: table.pool.peak,
      slabs: table.arena.slabs.peak,
      vectors: table.arena.vectors.peak,
      jobs: runtime.jobs.peak,
    }),
    async stop() {
      hook.uninstall();
      if (worker !== undefined) await worker.stop(2000);
    },
  };
}

export { STATE_CLOSED };
