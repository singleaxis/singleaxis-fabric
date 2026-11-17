// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The Fabric worker's bootstrap (spec 055 §4.5 "Fabric worker").
 *
 * One internal Worker does everything that is not hook work. The installing thread
 * starts it with `execArgv: []` and `env: {}`: an empty environment is required,
 * because a `NODE_OPTIONS` preload still runs in a Worker created with `execArgv: []`
 * unless the Worker's environment omits `NODE_OPTIONS`. So the worker never autoloads
 * capture and never loads a customer preload. It carries an internal `workerData`
 * marker (the preload stays inert when it sees it), is `unref()`'d so it never keeps
 * the agent's process alive, and writes nothing to the agent's stdout or stderr.
 *
 * If the worker dies, the installing thread starts a replacement on the same shared
 * memory: the position counter, the job ring's read position and every lock are in the
 * control block, so nothing is reset and a job the dead worker had not finished is read
 * again. After five quick crashes in a row the runtime is marked failed and capture
 * stops with a reason; the agent is never affected.
 *
 * This unit builds the bootstrap and the consume loop. Protection, the spool and the
 * sender (units 055-t7, 055-t8, 055-t13) plug in as the `job` handler.
 */
import { Worker, isMainThread, workerData } from "node:worker_threads";

import { SlotPool } from "./arena.js";
import { ExchangeTable, JOB_EXCHANGE, JOB_RELEASING, type ExchangeJob } from "./exchange.js";
import {
  type RuntimeLoss,
  type RuntimeShared,
  STATE_FAILED,
  WireRuntime,
  waitAsync,
} from "./runtime.js";

/** The `workerData` key that marks the Fabric worker. */
export const FABRIC_WORKER_MARKER = "fabric.wire.worker/1";
/** How often the worker wakes without a notification (growth, detached isolates). */
export const WORKER_TICK_MS = 100;

interface FabricWorkerData {
  readonly [FABRIC_WORKER_MARKER]: 1;
  readonly shared: RuntimeShared;
  readonly snapshot: unknown;
}

function markerData(data: unknown): FabricWorkerData | undefined {
  if (data === null || typeof data !== "object") return undefined;
  return (data as Record<string, unknown>)[FABRIC_WORKER_MARKER] === 1
    ? (data as FabricWorkerData)
    : undefined;
}

/** True in the Fabric worker. The preload and `install()` do nothing there. */
export function isFabricWorkerThread(): boolean {
  return !isMainThread && markerData(workerData) !== undefined;
}

export interface FabricWorkerOptions {
  /** The file the worker runs: the wire core, which calls {@link runFabricWorker}. */
  readonly entry: string | URL;
  /** The configuration snapshot (structured-cloneable); the worker reads no environment. */
  readonly snapshot?: unknown;
  /** Crashes in a row, each within `quickCrashMs` of its start, before capture stops. */
  readonly maxQuickCrashes?: number;
  readonly quickCrashMs?: number;
}

/** The installing thread's handle on the Fabric worker. */
export class FabricWorker {
  private thread: Worker | undefined;
  private stopping: (() => void) | undefined;
  private quickCrashes = 0;

  constructor(
    private readonly runtime: WireRuntime,
    private readonly options: FabricWorkerOptions,
  ) {}

  /** The live Worker, for tests and for `close()`. */
  get worker(): Worker | undefined {
    return this.thread;
  }

  /** Starts the worker. Never throws: a worker that cannot start is a failed runtime. */
  start(): void {
    const startedAt = performance.now();
    let worker: Worker;
    try {
      const data: FabricWorkerData = {
        [FABRIC_WORKER_MARKER]: 1,
        shared: this.runtime.shared,
        snapshot: this.options.snapshot,
      };
      worker = new Worker(this.options.entry, {
        execArgv: [],
        argv: [],
        env: {},
        workerData: data,
        // Not forwarded to the agent's stdout/stderr. The two streams are never read
        // here: reading one keeps the process alive, which an unref'd worker must not.
        // The worker discards its own output at the source (see runFabricWorker), so
        // nothing collects in them either.
        stdout: true,
        stderr: true,
      });
    } catch {
      this.runtime.setState(STATE_FAILED);
      return;
    }
    worker.unref();
    // An uncaught error in the worker ends it; it is never rethrown on this thread.
    worker.on("error", () => undefined);
    worker.once("exit", () => this.exited(worker, startedAt));
    this.thread = worker;
  }

  private exited(worker: Worker, startedAt: number): void {
    if (this.thread !== worker) return;
    this.thread = undefined;
    if (this.stopping !== undefined) {
      this.stopping();
      return;
    }
    const runtime = this.runtime;
    if (!runtime.running) return;
    // The dead worker's lock and unfinished job stay in shared memory; so does the
    // position counter. Free the lock, then start a replacement on the same buffers.
    runtime.breakWorkerLock();
    runtime.countWorkerRestart();
    const quick = performance.now() - startedAt < (this.options.quickCrashMs ?? 1000);
    this.quickCrashes = quick ? this.quickCrashes + 1 : 0;
    if (this.quickCrashes >= (this.options.maxQuickCrashes ?? 5)) {
      runtime.setState(STATE_FAILED);
      return;
    }
    this.start();
  }

  /**
   * Asks the worker to drain and exit, and terminates it after `timeoutMs`. Resolves
   * `true` when it exited by itself.
   */
  async stop(timeoutMs: number): Promise<boolean> {
    const worker = this.thread;
    if (worker === undefined) return true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const exited = new Promise<boolean>((resolve) => {
      this.stopping = () => resolve(true);
      timer = setTimeout(() => resolve(false), timeoutMs);
      timer.unref();
    });
    this.runtime.requestStop();
    const clean = await exited;
    clearTimeout(timer);
    if (!clean) {
      this.thread = undefined;
      await worker.terminate().catch(() => undefined);
    }
    return clean;
  }
}

/** What a job handler receives. */
export interface FabricWorkerContext {
  readonly runtime: WireRuntime;
  readonly exchanges: ExchangeTable;
  readonly snapshot: unknown;
}

export interface FabricWorkerHandlers {
  /**
   * Handles one completed exchange. Its bodies are read in place and released when the
   * handler returns; a handler that throws loses the position as `internal_error`.
   */
  job?(job: ExchangeJob, context: FabricWorkerContext): void | Promise<void>;
  /**
   * Handles one lost position (reason, position, segment). Without this handler loss
   * records stay in the loss ring; a handler that throws leaves the position a gap
   * without a reason (`lossesUnattributed`).
   */
  loss?(loss: RuntimeLoss, context: FabricWorkerContext): void | Promise<void>;
}

/**
 * Runs the Fabric worker's loop when called in the Fabric worker, and returns
 * `undefined` anywhere else. The wire core calls it at load.
 */
export function runFabricWorker(handlers: FabricWorkerHandlers = {}): Promise<void> | undefined {
  const data = isMainThread ? undefined : markerData(workerData);
  if (data === undefined) return undefined;
  silence();
  const runtime = new WireRuntime(data.shared, "worker");
  runtime.workerStarted();
  const exchanges = new ExchangeTable(runtime);
  return consume({ runtime, exchanges, snapshot: data.snapshot }, handlers);
}

/**
 * Discards everything the Fabric worker would print. Its stdout and stderr are not
 * the agent's, and the installing thread does not read them, so a stray line from a
 * dependency must go nowhere instead of collecting in memory.
 */
function silence(): void {
  const discard = (...args: unknown[]): boolean => {
    const done = args[args.length - 1];
    if (typeof done === "function") (done as () => void)();
    return true;
  };
  for (const stream of [process.stdout, process.stderr]) {
    try {
      stream.write = discard as typeof stream.write;
    } catch {
      // A stream that cannot be replaced is left alone; the worker prints nothing itself.
    }
  }
}

async function consume(
  context: FabricWorkerContext,
  handlers: FabricWorkerHandlers,
): Promise<void> {
  const { runtime, exchanges } = context;
  const jobs = runtime.jobs;
  const pools = [exchanges.arena.slabs, exchanges.arena.vectors, exchanges.pool];
  for (;;) {
    const seen = Atomics.load(jobs.wakeWords, jobs.wakeIndex);
    for (let record = jobs.peek(); record !== undefined; record = jobs.peek()) {
      if (record.kind === JOB_EXCHANGE || record.kind === JOB_RELEASING) {
        const job = exchanges.job(record.byteOffset);
        if (record.kind === JOB_EXCHANGE) {
          try {
            if (handlers.job === undefined) runtime.countUnprocessed();
            else await handlers.job(job, context);
          } catch {
            runtime.lose("internal_error", job.sequence, job.segmentHi, job.segmentLo);
          }
          // Handled. From here a replacement worker only finishes the release: a side
          // that is already empty must never reach the handler as an exact body.
          jobs.retag(JOB_RELEASING);
        }
        exchanges.arena.release(job.request.words);
        exchanges.arena.release(job.response.words);
      } else {
        runtime.countUnprocessed();
      }
      jobs.commit();
      grow(pools);
    }
    if (handlers.loss !== undefined) {
      for (let loss = runtime.peekLoss(); loss !== undefined; loss = runtime.peekLoss()) {
        try {
          await handlers.loss(loss, context);
        } catch {
          runtime.countUnattributed();
        }
        runtime.commitLoss();
      }
    }
    grow(pools);
    if (runtime.stopRequested) return;
    const waited = waitAsync(jobs.wakeWords, jobs.wakeIndex, seen, WORKER_TICK_MS);
    if (!waited.async) continue;
    // A pending waitAsync does not keep a thread alive; the timer does.
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([
      waited.value,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, WORKER_TICK_MS);
      }),
    ]);
    clearTimeout(timer);
  }
}

/** Only the Fabric worker grows arenas, ahead of each pool's low-water mark. */
function grow(pools: readonly SlotPool[]): void {
  for (const pool of pools) {
    try {
      while (pool.growIfLow() > 0);
    } catch {
      // Out of memory for this step: the pool stays as it is and hooks see it full.
      break;
    }
  }
}
