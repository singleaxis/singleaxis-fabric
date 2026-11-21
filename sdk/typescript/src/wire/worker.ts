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
 * Unit 055-t4 built the bootstrap and the consume loop. Unit 055-t8 adds the capture
 * pipeline ({@link CapturePipeline}), the `job` handler: PROTECT (`protect.ts`), then the
 * span and the spool record (`writer.ts`), then admission to the spool (055-t7). The
 * protector and its redaction service client are built here, in the Fabric worker, from
 * a plain configuration ({@link PipelineConfig}); no object holding a socket crosses an
 * isolate. The sender (055-t13) drains the spool.
 *
 * Unit 055-t10 adds the loss funnel and the seal accumulator: every lost position reaches
 * the worker through the runtime's loss ring and its `loss` handler, then
 * {@link LossTable.record} (`loss.ts`), which settles the position in its segment's seal;
 * a spooled exchange settles its record digest ({@link SegmentSeals}, `seal.ts`). Loss
 * ranges and `segment_seal` markers are spooled on the worker's tick, and at stop the
 * `shutdown` losses and the seals precede the epoch's `final` heartbeat.
 */
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

import { DeploymentPolicy, type DeploymentPolicyData } from "../deployment-policy.js";
import { labelPseudonym, operatorLabel } from "../identity.js";
import type { RedactionServiceOptions, Transformation } from "../redaction.js";
import { SDK_VERSION } from "../version.js";
import { type PayloadArena, SlotPool } from "./arena.js";
import { ExchangeTable, JOB_EXCHANGE, JOB_RELEASING, type ExchangeJob } from "./exchange.js";
import {
  Heartbeats,
  ManifestChain,
  emittedAt,
  type ManifestTemplate,
  MarkerQueue,
  type PointState,
} from "./manifest.js";
import {
  type ContentGate,
  Protector,
  ROLE_REQUEST,
  ROLE_RESPONSE,
  decideGate,
  modeOf,
} from "./protect.js";
import { LossTable } from "./loss.js";
import { compactInt, parseInt64 } from "./codec.js";
import { formatEntry } from "./p1.js";
import {
  NO_MANIFEST_DIGEST,
  RUN_MESSAGE_PART,
  RunMessages,
  SEGMENT_PREFIX,
  type MarkerMessage,
  type SealMessage,
  type SegmentMessage,
} from "./segments.js";
import {
  MAX_RUNS,
  RUN_FLAG_RESUMABLE,
  type RuntimeLoss,
  type RuntimeLossReason,
  type RuntimeShared,
  WireRuntime,
  waitAsync,
} from "./runtime.js";
import {
  type RunTableView,
  SegmentSeals,
  exchangeSealEntry,
  observeRunTable,
  segmentIdOf,
} from "./seal.js";
import type { Spool } from "./spool.js";
import type { WireSettings } from "./types.js";
import { UNDICI_POINT, contentEncodingOf, mediaTypeOf, readUndiciMeta } from "./undici.js";
import {
  type AdmitOutcome,
  type CapturedExchange,
  type CapturedSide,
  type Enrichment,
  type SpanDoc,
  admitEntries,
  exchangeEntry,
  prepareExchange,
} from "./writer.js";

/** The `workerData` key that marks the Fabric worker. */
export const FABRIC_WORKER_MARKER = "fabric.wire.worker/1";
/** How often the worker wakes without a notification (growth, detached isolates). */
export const WORKER_TICK_MS = 100;
/** The `postMessage` key of a request to the Fabric worker (flush, the stop budget). */
export const WORKER_REQUEST = "fabric.wire.request/1";

/** The `postMessage` key of a class-only warning from the worker (fixed text, never a value). */
export const WORKER_WARNING = "fabric.wire.warning/1";

/** The key of the orderly stop's result the worker posts before it exits (`fabric-main.ts`). */
export const STOP_RESULT = "fabric.wire.stop-result/1";

/** A request from the installing thread (`FabricWorker.request`). */
export interface WorkerRequest {
  readonly id: number;
  /** `flush`, or `stop` (the budget of the orderly stop that follows). */
  readonly kind: "flush" | "stop";
  /** The caller's budget in ms; the worker turns it into its own deadline on receipt. */
  readonly budgetMs: number;
  /** `stop` at process exit: a process that does not drain only leaves its records durable. */
  readonly exiting?: boolean;
  /** `stop`: the capture points whose hooks `close()` removed, and the cut it happened at. */
  readonly uninstalled?: Uninstalled;
  /** `stop`: the installing thread's content-free counters, for the exit status document. */
  readonly counters?: Readonly<Record<string, number>>;
}

/**
 * Hooks removed by `close()` (050 §3.8; Python `_p1_uninstalled`): each point that was
 * `active` becomes `disabled(shutdown)` in a chained manifest after `cut`, before `final`.
 */
export interface Uninstalled {
  readonly points: readonly string[];
  readonly cut: bigint;
}

interface FabricWorkerData {
  readonly [FABRIC_WORKER_MARKER]: 1;
  readonly shared: RuntimeShared;
  readonly snapshot: unknown;
  /** This worker replaces one that crashed. */
  readonly restarted?: boolean;
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
  /**
   * Receives the worker's class-only warnings ({@link WORKER_WARNING}): the worker's own
   * stdout and stderr are discarded, so `install()` prints them here, and only with
   * `FABRIC_WIRE_DIAGNOSTICS=stderr`. A callback that throws is ignored.
   */
  readonly warn?: (text: string) => void;
}

/** The installing thread's handle on the Fabric worker. */
export class FabricWorker {
  private thread: Worker | undefined;
  private stopping: ((clean: boolean) => void) | undefined;
  private quickCrashes = 0;
  private requests = 0;
  private started = false;
  /** Requests awaiting a reply: the worker holds the process open while any does. */
  private waiting = 0;
  private readonly replies = new Map<number, (result: unknown) => void>();
  /** What the last orderly stop reported (`STOP_RESULT`), if it reported anything. */
  stopResult: unknown;

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
        // A replacement after a crash: once-per-process work (the install status document)
        // is not repeated.
        restarted: this.started,
      };
      this.started = true;
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
      this.runtime.fail("worker_start_failed");
      return;
    }
    // An uncaught error in the worker ends it; it is never rethrown on this thread.
    worker.on("error", () => undefined);
    worker.on("message", (message: unknown) => {
      const stopped = (message as Record<string, unknown> | null)?.[STOP_RESULT];
      if (stopped !== undefined) this.stopResult = stopped;
      const warning = (message as Record<string, unknown> | null)?.[WORKER_WARNING];
      if (typeof warning === "string" && warning.length <= 1024) {
        try {
          this.options.warn?.(warning);
        } catch {
          // a warning sink's failure is never the agent's
        }
      }
      const reply = (message as Record<string, unknown> | null)?.[WORKER_REQUEST] as
        { id?: unknown; result?: unknown } | undefined;
      if (reply === undefined || typeof reply.id !== "number") return;
      this.replies.get(reply.id)?.(reply.result);
    });
    // After the listeners: a `message` listener refs the worker's port, and an unref'd
    // worker must never keep the agent's process alive.
    worker.unref();
    worker.once("exit", (code) => this.exited(worker, startedAt, code));
    this.thread = worker;
  }

  private exited(worker: Worker, startedAt: number, code: number): void {
    if (this.thread !== worker) return;
    this.thread = undefined;
    if (this.stopping !== undefined) {
      // Only a worker that left its loop exits with 0; a crash while it drained did not
      // finish the jobs it was asked to.
      this.stopping(code === 0);
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
      runtime.fail("worker_crash_loop");
      return;
    }
    this.start();
  }

  /**
   * Sends a request to the worker and resolves with its reply, or `undefined` when none
   * came within `timeoutMs` (no worker, a crash, a stall). While it waits the worker
   * holds the process open: the caller awaits the reply. Never rejects.
   */
  async request(
    kind: WorkerRequest["kind"],
    timeoutMs: number,
    extra: { exiting?: boolean } = {},
  ): Promise<unknown> {
    const worker = this.thread;
    if (worker === undefined) return undefined;
    const id = ++this.requests;
    let timer: ReturnType<typeof setTimeout> | undefined;
    this.waiting += 1;
    worker.ref();
    try {
      return await new Promise<unknown>((resolve) => {
        this.replies.set(id, resolve);
        timer = setTimeout(() => resolve(undefined), Math.max(0, timeoutMs));
        const request: WorkerRequest = { id, kind, budgetMs: Math.max(0, timeoutMs), ...extra };
        try {
          worker.postMessage({ [WORKER_REQUEST]: request });
        } catch {
          resolve(undefined);
        }
      });
    } finally {
      clearTimeout(timer);
      this.replies.delete(id);
      this.waiting -= 1;
      if (this.waiting === 0 && this.thread === worker && this.stopping === undefined) {
        worker.unref();
      }
    }
  }

  /**
   * Asks the worker to drain and exit, and terminates it after `timeoutMs`. Resolves
   * `true` only when it drained and exited by itself; `false` when it crashed while
   * draining or had to be terminated. `exiting`: the process is exiting (the stop
   * handler then only makes records durable unless this process drains the spool).
   */
  async stop(
    timeoutMs: number,
    options: {
      exiting?: boolean;
      uninstalled?: Uninstalled;
      counters?: Readonly<Record<string, number>>;
    } = {},
  ): Promise<boolean> {
    const worker = this.thread;
    if (worker === undefined) return true;
    try {
      // The budget of the orderly stop: the worker delivers within it, then exits.
      const request: WorkerRequest = {
        id: ++this.requests,
        kind: "stop",
        budgetMs: Math.max(0, timeoutMs),
        ...options,
      };
      worker.postMessage({ [WORKER_REQUEST]: request });
    } catch {
      // the worker uses its default budget
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    // The caller awaits this stop with a deadline, so the worker and the deadline timer
    // hold the process open until it ends: unref'd, an agent whose last act is an
    // awaited close would exit before the drain finished. Never longer than the deadline.
    worker.ref();
    const exited = new Promise<boolean>((resolve) => {
      this.stopping = resolve;
      timer = setTimeout(() => resolve(false), timeoutMs);
    });
    this.runtime.requestStop();
    const clean = await exited;
    clearTimeout(timer);
    worker.unref();
    this.stopping = undefined;
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
  /**
   * The orderly stop's deadline (`performance.now()` ms of this worker) and whether the
   * process is exiting, once the installing thread sent them (`FabricWorker.stop`).
   */
  stop?: {
    readonly deadline: number;
    readonly exiting: boolean;
    readonly uninstalled?: Uninstalled | undefined;
    /** The installing thread's counters (the exit status document), when it sent them. */
    readonly counters?: Readonly<Record<string, number>> | undefined;
  };
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
  /**
   * Handles one run-structure record (a part of a run marker or seal request,
   * `segments.ts`). Records are handled before each job, so an exchange's segment is
   * known when its job is. Without this handler the records stay in the run ring.
   */
  run?(body: Uint8Array, context: FabricWorkerContext): void | Promise<void>;
  /**
   * Called once per loop pass, and between jobs whenever {@link WORKER_TICK_MS} passed
   * since the last call, so a sustained job stream cannot starve it: the manifests' and
   * heartbeats' clock. A handler that throws is ignored until the next call.
   */
  tick?(context: FabricWorkerContext): void | Promise<void>;
  /**
   * Called once when the worker stops in order, after every queued job and loss record
   * was handled: the pipeline seals and writes the epoch's `final` here. A handler that
   * throws is ignored.
   */
  stop?(context: FabricWorkerContext): void | Promise<void>;
  /**
   * A `flush` request from the installing thread, with its deadline (`performance.now()`
   * ms of this worker); the reply is its result. Runs beside the loop. A handler that
   * throws replies `false`.
   */
  flush?(deadline: number, context: FabricWorkerContext): boolean | Promise<boolean>;
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
  // A predecessor terminated inside a commit left the read position one record behind.
  runtime.jobs.recover();
  runtime.lossRing.recover();
  runtime.workerStarted();
  const exchanges = new ExchangeTable(runtime);
  const context: FabricWorkerContext = { runtime, exchanges, snapshot: data.snapshot };
  listen(context, handlers);
  return consume(context, handlers);
}

/** Answers the installing thread's requests (flush) and takes the stop budget. */
function listen(context: FabricWorkerContext, handlers: FabricWorkerHandlers): void {
  const port = parentPort;
  if (port === null) return;
  port.on("message", (message: unknown) => {
    const request = (message as Record<string, unknown> | null)?.[WORKER_REQUEST] as
      WorkerRequest | undefined;
    if (request === undefined || typeof request.id !== "number") return;
    const deadline = performance.now() + Math.max(0, Number(request.budgetMs) || 0);
    if (request.kind === "stop") {
      const off = request.uninstalled;
      context.stop = {
        deadline,
        exiting: request.exiting === true,
        uninstalled:
          off !== undefined && Array.isArray(off.points) && typeof off.cut === "bigint"
            ? off
            : undefined,
        counters:
          request.counters !== null && typeof request.counters === "object"
            ? request.counters
            : undefined,
      };
      return;
    }
    if (request.kind !== "flush") return;
    void (async () => {
      let result: boolean;
      try {
        result = handlers.flush === undefined ? false : await handlers.flush(deadline, context);
      } catch {
        result = false;
      }
      try {
        port.postMessage({ [WORKER_REQUEST]: { id: request.id, result } });
      } catch {
        // the installing thread times out
      }
    })();
  });
  // A listening port must not keep the worker (or the process) alive on its own.
  (port as unknown as { unref?: () => void }).unref?.();
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
  let lastTick = performance.now();
  // The manifests' and heartbeats' clock: once per loop pass, and every WORKER_TICK_MS
  // while a sustained job stream keeps the pass from ending, so a busy source still
  // beats and its held markers still reach the spool.
  const tick = async (): Promise<void> => {
    lastTick = performance.now();
    if (handlers.tick === undefined) return;
    try {
      await handlers.tick(context);
    } catch {
      // the next pass tries again
    }
  };
  // Set once the stop request is seen: one more full pass, then the stop handler.
  let stopping = false;
  for (;;) {
    const seen = Atomics.load(jobs.wakeWords, jobs.wakeIndex);
    for (let record = jobs.peek(); record !== undefined; record = jobs.peek()) {
      // Run markers pushed before this job's allocation are visible now: handle them
      // first, so the job's segment names its run.
      await handleRuns(context, handlers);
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
      growPools(pools);
      if (performance.now() - lastTick >= WORKER_TICK_MS) await tick();
    }
    await handleRuns(context, handlers);
    await handleLosses(context, handlers);
    growPools(pools);
    await tick();
    if (runtime.stopRequested) {
      if (!stopping) {
        // A job queued after this pass drained the ring but before the stop request (it
        // was enqueued while the losses or the tick were handled) is handled by one more
        // pass, so the stop handler never writes final over a position still queued.
        stopping = true;
        continue;
      }
      // Losses recorded just before the stop request (the shutdown sweep) and the seals
      // the run table requested at final are handled before the stop handler, so they
      // precede the epoch's final.
      await handleRuns(context, handlers);
      await handleLosses(context, handlers);
      try {
        await handlers.stop?.(context);
      } catch {
        // a final not written leaves the epoch unverified; never the agent's problem
      }
      return;
    }
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

/** Hands every queued run record to the `run` handler (left in the ring without one). */
async function handleRuns(
  context: FabricWorkerContext,
  handlers: FabricWorkerHandlers,
): Promise<void> {
  const ring = context.runtime.runRing;
  if (handlers.run === undefined || ring === undefined) return;
  for (let record = ring.peek(); record !== undefined; record = ring.peek()) {
    if (record.kind === RUN_MESSAGE_PART) {
      try {
        await handlers.run(record.body, context);
      } catch {
        // a run record that cannot be handled leaves its run unverified, never stuck
      }
    }
    ring.commit();
  }
}

/** Hands every queued loss record to the `loss` handler (left in the ring without one). */
async function handleLosses(
  context: FabricWorkerContext,
  handlers: FabricWorkerHandlers,
): Promise<void> {
  if (handlers.loss === undefined) return;
  const { runtime } = context;
  for (let loss = runtime.peekLoss(); loss !== undefined; loss = runtime.peekLoss()) {
    try {
      await handlers.loss(loss, context);
    } catch {
      runtime.countUnattributed();
    }
    runtime.commitLoss();
  }
}

/**
 * Only the Fabric worker grows arenas, ahead of each pool's low-water mark. A pool that
 * cannot grow (out of memory for this step) stays as it is, and hooks see it full; the
 * other pools still grow.
 */
export function growPools(pools: readonly SlotPool[]): void {
  for (const pool of pools) {
    try {
      while (pool.growIfLow() > 0);
    } catch {
      // This pool stays as it is until the next tick; go on to the next pool.
    }
  }
}

// ---------------------------------------------------------------- capture pipeline

/**
 * What the capture pipeline needs, as plain structured-cloneable data: the installing
 * thread builds it ({@link pipelineConfig}) and the Fabric worker, which reads no
 * environment, builds the protector, its redaction client and the gate from it.
 */
export interface PipelineConfig {
  readonly sourceId: string;
  readonly tenantId: string | undefined;
  /** The capture `service.name` as emitted (`svc-` label unless labels are clear). */
  readonly serviceName: string;
  /** Content goes to the Fabric Node (`FABRIC_WIRE_CONTENT_ENDPOINT`). */
  readonly node: boolean;
  /** A direct `file://` store is configured. */
  readonly store: boolean;
  /** A spool is used (`FABRIC_WIRE_SPOOL_DIR`). */
  readonly spool: boolean;
  /** The validated deployment policy document (`FABRIC_CAPTURE_POLICY`), if any. */
  readonly policy: DeploymentPolicyData | undefined;
  readonly transformations: Readonly<Record<string, Transformation>>;
  /** The redaction service (endpoint and token file; the token is read in the worker). */
  readonly redaction: RedactionServiceOptions | undefined;
  readonly maxBodyBytes: number;
  readonly idKey: Uint8Array | undefined;
  readonly spoolKey: Uint8Array | undefined;
  readonly tokenizationKey: Uint8Array | undefined;
  /** The endpoints in the order the hook was given them (its slots store the index). */
  readonly endpoints: readonly { readonly endpointId: string; readonly providerName: string }[];
  readonly enrichment: Enrichment;
  /**
   * The capture manifest of this install (spec 055 §7.2): the template read once at
   * install and the prior unsealed epochs the registration scan declared (manifest 0 of
   * the registered epoch lists them). Absent: this pipeline spools no manifest.
   */
  readonly manifest?: {
    readonly template: ManifestTemplate;
    readonly unsealed: { readonly epochs: readonly bigint[]; readonly count: number };
    /**
     * Manifest 0 as `install()` minted and published it before returning (its manifest
     * and event ids, its `emitted_at`): the chain issues the identical document, so run
     * markers, seals and tokens made before the worker's first tick name it.
     */
    readonly first?: { readonly ids: readonly [string, string]; readonly stamp: string };
  };
  /** The forced-seal bound (default 1,000,000 positions, spec 055 §4.3; tests scale it). */
  readonly forcedSealPositions?: number;
}

const LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const SERVICE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const BUILTIN_NAME_RE = /^[a-z][a-z0-9_]{0,31}\.default$/;
/** X05 (049 §2.9; 050 §3.9): the deployment identity block on capture spans. */
export const IDENTITY_ENV: Readonly<Record<string, string>> = Object.freeze({
  "fabric.agent_id": "FABRIC_AGENT_ID",
  "fabric.system_id": "FABRIC_SYSTEM_ID",
  "fabric.deployment_id": "FABRIC_DEPLOYMENT_ID",
  "fabric.release_id": "FABRIC_RELEASE_ID",
  "fabric.environment": "FABRIC_ENVIRONMENT",
});
const MAX_POLICY_BYTES = 1 << 20;

/**
 * The C35 value of an endpoint (Python `endpoint_label`): a built-in endpoint is
 * `<name>.default`; a configured one `lbl-` + the keyed v1 label of its configured name,
 * also under clear labels (the Node admits no clear name). Never a host.
 */
export function endpointLabel(
  endpointId: string,
  builtin: boolean,
  key: Uint8Array | undefined,
): string {
  if (builtin) {
    const name = endpointId.toLowerCase().replace(/[^a-z0-9_]/g, "_") + ".default";
    if (BUILTIN_NAME_RE.test(name)) return name;
  }
  return labelPseudonym("lbl", endpointId, key);
}

/**
 * The pipeline configuration of an install, on the installing thread: reads the policy
 * file once more (already validated by the configuration) and the X05 and service-name
 * variables. `endpoints` must be the list the hook was given, in its order.
 */
export function pipelineConfig(
  settings: WireSettings,
  options: {
    readonly sourceId: string;
    readonly endpoints?: readonly { readonly endpointId: string; readonly providerName: string }[];
    readonly transformations?: Readonly<Record<string, Transformation>>;
    readonly env?: Readonly<Record<string, string | undefined>>;
  },
): PipelineConfig {
  const env = options.env ?? process.env;
  const key = settings.secrets.idKey;
  const clear = settings.labels === "clear";
  let policy: DeploymentPolicyData | undefined;
  if (settings.capturePolicyPath !== undefined) {
    const raw = readFileSync(settings.capturePolicyPath);
    if (raw.byteLength > MAX_POLICY_BYTES) throw new Error("FABRIC_CAPTURE_POLICY is too large");
    policy = new DeploymentPolicy(JSON.parse(raw.toString("utf8"))).toDict();
  }
  const builtin = new Set(settings.endpoints.map((m) => m.endpointId));
  const endpoints = options.endpoints ?? [...settings.extraEndpoints, ...settings.endpoints];
  const endpointIds: Record<string, string> = {};
  for (const endpoint of endpoints) {
    endpointIds[endpoint.endpointId] = endpointLabel(
      endpoint.endpointId,
      builtin.has(endpoint.endpointId),
      key,
    );
  }
  const identity: Record<string, string> = {};
  for (const [attribute, name] of Object.entries(IDENTITY_ENV)) {
    const raw = (env[name] ?? "").trim();
    if (raw !== "" && LABEL_RE.test(raw)) identity[attribute] = operatorLabel(raw, key, { clear });
  }
  const service = env.OTEL_SERVICE_NAME ?? "";
  const name = SERVICE_NAME_RE.test(service) ? service : "fabric-wire";
  return {
    sourceId: options.sourceId,
    tenantId: settings.tenantId,
    serviceName: clear ? name : labelPseudonym("svc", name, key),
    node: settings.contentEndpoint !== undefined,
    store: settings.store?.kind === "file",
    spool: settings.spoolDir !== undefined,
    policy,
    transformations: { ...(options.transformations ?? {}) },
    redaction:
      settings.redactionEndpoint === undefined
        ? undefined
        : { endpoint: settings.redactionEndpoint, tokenFile: settings.redactionTokenFile },
    maxBodyBytes: settings.maxBodyBytes,
    idKey: key,
    spoolKey: settings.secrets.spoolKey,
    tokenizationKey: settings.secrets.tokenizationKey,
    endpoints: endpoints.map((m) => ({ endpointId: m.endpointId, providerName: m.providerName })),
    enrichment: {
      points: { [UNDICI_POINT]: `${UNDICI_POINT}@${SDK_VERSION}` },
      endpointIds,
      identity,
      requestIdKey: settings.providerRequestId ? key : undefined,
      modelAllowlist: [...settings.modelAllowlist],
    },
  };
}

/**
 * Where the pipeline's own losses go: the runtime's loss ring, from which the worker's
 * `loss` handler takes them to {@link CapturePipeline.lost}, the single loss funnel.
 */
export interface PipelineSink {
  lose(reason: RuntimeLossReason, sequence: bigint, segmentHi: bigint, segmentLo: bigint): void;
  /** A class-only notice (catalogue id and reason), never a value. */
  notice?(id: string, reason: string): void;
  /** A record was written (its segment's seal is already settled). */
  written?(job: CapturedExchange, span: SpanDoc): void;
}

/** Content-free counters of the pipeline. */
export interface PipelineStats {
  readonly outcomes: Readonly<Record<AdmitOutcome, number>>;
  readonly unreadable: number;
  readonly protection: ReturnType<Protector["stats"]> | undefined;
  /** The manifest in force and the marker counters, when the pipeline has manifests. */
  readonly manifests:
    | {
        readonly manifestSeq: number | undefined;
        readonly held: number;
        readonly spooled: number;
        readonly dropped: number;
        readonly beatsPending: number;
        readonly internalErrors: number;
      }
    | undefined;
  readonly losses: ReturnType<LossTable["stats"]>;
  readonly seals: ReturnType<SegmentSeals["stats"]>;
  /** Run markers spooled, seal requests taken, records refused, forced rolls. */
  readonly runs: Readonly<Record<string, number>>;
}

/** What the worker keeps of an open segment's `run_start` (exchanges and forced rolls). */
interface SegmentRun {
  readonly runId: string;
  readonly scopeId: string;
  readonly idBasis: string | undefined;
}

/** Open segments the worker remembers (as many as the seal accumulator keeps open). */
const MAX_SEGMENT_RUNS = 65_536;
/**
 * Held continuation `run_start`s (one per live run at most, `segments.ts`); past this
 * bound the oldest is spooled, never dropped.
 */
const MAX_HELD = 1024;
const RUN_MARKER_KINDS: ReadonlySet<unknown> = new Set(["run_start", "run_end"]);

/** How long one tick may spend building handed-off seals. */
export const SEAL_BUDGET_MS = 20;

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const uuidText = (bytes: Uint8Array): string => {
  const h = hex(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
};

/**
 * The Fabric worker's capture pipeline: one completed exchange in, one protected spool
 * record (or one named loss) out. PROTECT runs before anything is written; a failure
 * anywhere is a loss for that position and never reaches the agent.
 */
export class CapturePipeline {
  readonly gate: ContentGate;
  readonly protector: Protector | undefined;
  readonly #config: PipelineConfig;
  readonly #spool: Spool;
  readonly #sink: PipelineSink;
  readonly #outcomes: Record<AdmitOutcome, number> = {
    spooled: 0,
    queue_full: 0,
    disk_full: 0,
    internal_error: 0,
  };
  readonly #noticed = new Set<bigint>();
  /** A masking role has no service or transformation: its content is withheld (FW-032). */
  readonly #maskedWithheld: boolean = false;
  #unreadable = 0;
  /** The install's manifests (spec 055 §7.2), when configured. */
  readonly manifests: ManifestChain | undefined;
  readonly heartbeats: Heartbeats | undefined;
  /** Manifests and `final` waiting for the spool, written in order ahead of exchanges. */
  readonly markers = new MarkerQueue();
  #unsealed: { readonly epochs: readonly bigint[]; readonly count: number } | undefined;
  /** Segment seals (050 §3.7): settled after the record is spooled, or by the loss funnel. */
  readonly seals: SegmentSeals;
  /** The single loss funnel and its ranges (050 §3.3, R3). */
  readonly losses: LossTable;
  /** The result of the orderly close ({@link closeEpoch}), once it ran. */
  closed: boolean | undefined;
  /** Run markers and seal requests from the run table (`segments.ts`). */
  readonly #runMessages = new RunMessages();
  /** Open segments' runs, learned from their `run_start` markers (bounded, oldest out). */
  readonly #segmentRuns = new Map<string, SegmentRun>();
  /** Segments at the forced bound, to roll on the next tick ({@link rollForced}). */
  readonly #forced: string[] = [];
  /** Held continuation `run_start` markers by segment, with their epoch (insertion order). */
  readonly #held = new Map<string, { readonly doc: Record<string, unknown>; epoch: bigint }>();
  #published: string | undefined;
  readonly #runStats = {
    markers: 0,
    seals: 0,
    rejected: 0,
    forced_rolls: 0,
    forced_missed: 0,
    held_discarded: 0,
  };

  constructor(config: PipelineConfig, spool: Spool, sink: PipelineSink) {
    this.#config = config;
    this.#spool = spool;
    this.#sink = sink;
    this.manifests =
      config.manifest === undefined
        ? undefined
        : new ManifestChain(config.manifest.template, firstManifest(config.manifest.first));
    this.seals = new SegmentSeals({
      // Manifest 0 of the seal's epoch goes ahead of its first seal.
      sink: (marker, seal) => {
        this.#ensureManifest(seal.epoch);
        return this.markers.queue(marker);
      },
      manifestSeq: (epoch) => this.manifests?.latestSeq(epoch),
      forcedAt: config.forcedSealPositions,
    });
    this.seals.onForced = (segmentId) => {
      if (this.#forced.length < MAX_RUNS) this.#forced.push(segmentId);
    };
    this.losses = new LossTable({
      settle: (segmentId, sequence, entry, sourceId, epoch) => {
        if (segmentId === undefined) return;
        this.seals.noteJob(segmentId, sourceId, epoch);
        this.seals.settle(segmentId, sequence, entry);
      },
    });
    this.heartbeats = this.manifests === undefined ? undefined : new Heartbeats(this.manifests);
    this.#unsealed = config.manifest?.unsealed;
    const policy = config.policy === undefined ? undefined : new DeploymentPolicy(config.policy);
    this.gate = decideGate({
      node: config.node,
      store: config.store,
      policy,
      idKey: config.idKey !== undefined,
      spool: config.spool,
      spoolKey: config.spoolKey !== undefined,
    });
    const capture = this.gate.contentCapture === "enabled" ? this.gate.policy : undefined;
    if (capture !== undefined && config.tenantId === undefined) {
      throw new Error("wire content capture needs a tenant id: set FABRIC_TENANT_ID");
    }
    this.protector =
      capture === undefined
        ? undefined
        : new Protector(capture, {
            maxBodyBytes: config.maxBodyBytes,
            transformations: config.transformations,
            redaction: config.redaction,
            tokenizationKey: config.tokenizationKey,
          });
    if (capture !== undefined) {
      const masked = [ROLE_REQUEST, ROLE_RESPONSE].filter((role) => {
        const mode = modeOf(capture, role);
        return (
          (mode === "redact" || mode === "masked_only") &&
          (config.redaction === undefined || !Object.hasOwn(config.transformations, role))
        );
      });
      // A masking role with no service or transformation is withheld: say so at install,
      // and again at the first exchange of each epoch (§5).
      this.#maskedWithheld = masked.length > 0;
      if (this.#maskedWithheld) sink.notice?.("FW-032", "protection_failed");
    }
  }

  stats(): PipelineStats {
    const chain = this.manifests;
    return {
      outcomes: { ...this.#outcomes },
      unreadable: this.#unreadable,
      protection: this.protector?.stats(),
      manifests:
        chain === undefined
          ? undefined
          : {
              manifestSeq: chain.ref?.manifestSeq,
              held: this.markers.held.length,
              spooled: this.markers.spooled,
              dropped: this.markers.dropped,
              beatsPending: this.heartbeats?.pending.length ?? 0,
              internalErrors: chain.internalErrors,
            },
      losses: this.losses.stats(),
      seals: this.seals.stats(),
      runs: { ...this.#runStats, dropped: this.#runMessages.dropped },
    };
  }

  /**
   * The manifests at the head of the queue (an epoch's manifest 0 leads it), then the
   * losses, then the other held markers (Python's sender writes losses ahead of markers
   * and spools a prefix): a seal or `final` never overtakes a loss range that could not
   * be written, so a `final` never precedes a `shutdown` loss.
   */
  #pump(): void {
    const isManifest = (marker: { doc: Record<string, unknown> }): boolean =>
      (marker.doc.marker as { kind?: unknown } | undefined)?.kind === "manifest";
    this.markers.pump(this.#spool, (marker) => !isManifest(marker));
    // A manifest the spool refused still leads: nothing, a loss included, may precede it.
    const head = this.markers.held[0];
    if (head !== undefined && isManifest(head)) return;
    if (this.losses.pump(this.#spool)) this.markers.pump(this.#spool);
  }

  /**
   * The single loss funnel of the Fabric worker (050 §3.3): one lost position from the
   * runtime's loss ring, in the epoch it was allocated in. Never throws.
   */
  lost(loss: RuntimeLoss, epoch: bigint): void {
    try {
      this.#release(segmentIdOf(loss.segmentHi, loss.segmentLo));
      this.#ensureManifest(epoch);
      this.losses.record(
        this.#config.sourceId,
        epoch,
        loss.reason,
        loss.sequence,
        segmentIdOf(loss.segmentHi, loss.segmentLo),
      );
    } catch {
      // the position stays a gap; never the agent's problem
    }
  }

  /** The tick's run-table scan: a segment at the forced bound is sealed non-terminally. */
  observeRuns(runtime: RunTableView, runs = MAX_RUNS): void {
    try {
      observeRunTable(runtime, this.seals, runs);
    } catch {
      // the next tick scans again
    }
  }

  // -------------------------------------------------------------- run structure (§4.3)

  /** One run-ring record (`segments.ts`): a run marker to spool or a seal request. */
  runRecord(body: Uint8Array): void {
    try {
      const message = this.#runMessages.take(body);
      if (message === undefined) return;
      if (message.t === "marker") this.#runMarker(message);
      else if (message.t === "seal") this.#sealRequest(message);
      else this.#segmentOp(message);
    } catch {
      this.#runStats.rejected++;
    }
  }

  #runMarker(message: MarkerMessage): void {
    const fields = { ...message.fields };
    const last =
      typeof fields.last_sequence === "string" ? parseInt64(fields.last_sequence) : undefined;
    const epoch = parseInt64(message.epoch);
    if (
      !RUN_MARKER_KINDS.has(fields.kind) ||
      last === undefined ||
      epoch === undefined ||
      message.source !== this.#config.sourceId
    ) {
      this.#runStats.rejected++;
      return;
    }
    fields.last_sequence = compactInt(last);
    const doc = {
      record_kind: "marker",
      source: { source_id: message.source, source_epoch: compactInt(epoch) },
      marker: fields,
    };
    const segmentId = typeof fields.segment_id === "string" ? fields.segment_id : undefined;
    if (fields.kind === "run_start" && segmentId !== undefined) {
      this.#remember(segmentId, {
        runId: String(fields.run_id),
        scopeId: String(fields.scope_id),
        idBasis: typeof fields.id_basis === "string" ? fields.id_basis : undefined,
      });
      if (message.hold === true) {
        this.#held.set(segmentId, { doc, epoch });
        while (this.#held.size > MAX_HELD) this.#release(this.#held.keys().next().value!);
        return;
      }
    }
    this.#spoolMarker(doc, epoch);
  }

  #spoolMarker(doc: Record<string, unknown>, epoch: bigint): void {
    this.#ensureManifest(epoch);
    if (this.markers.queue({ doc, bodies: [] })) this.#runStats.markers++;
  }

  /** Spools a held continuation `run_start` once its segment is used. Never throws. */
  #release(segmentId: string | undefined): void {
    if (segmentId === undefined || this.#held.size === 0) return;
    const held = this.#held.get(segmentId);
    if (held === undefined) return;
    this.#held.delete(segmentId);
    try {
      this.#spoolMarker(held.doc, held.epoch);
    } catch {
      this.#runStats.rejected++;
    }
  }

  /** `commit` spools a held continuation; `discard` drops one that stayed empty. */
  #segmentOp(message: SegmentMessage): void {
    if (message.op === "commit") {
      this.#release(message.segment);
    } else if (message.op === "discard" && this.#held.delete(message.segment)) {
      this.#segmentRuns.delete(message.segment);
      this.#runStats.held_discarded++;
    }
  }

  #remember(segmentId: string, run: SegmentRun): void {
    const runs = this.#segmentRuns;
    runs.delete(segmentId);
    runs.set(segmentId, run);
    while (runs.size > MAX_SEGMENT_RUNS) runs.delete(runs.keys().next().value as string);
  }

  #sealRequest(message: SealMessage): void {
    const epoch = parseInt64(message.epoch);
    const last = parseInt64(message.lastSequence);
    const positions = parseInt64(message.positions);
    if (epoch === undefined || last === undefined || positions === undefined) {
      this.#runStats.rejected++;
      return;
    }
    this.#release(message.segment);
    this.#ensureManifest(epoch);
    this.seals.requestSeal(message.segment, {
      lastSequence: last,
      manifestDigest: message.manifestDigest,
      terminal: message.terminal,
      resumable: message.resumable,
      branchIds: message.branchIds,
      runId: message.runId,
      sourceId: message.source,
      epoch,
      positions,
    });
    this.#runStats.seals++;
  }

  /** The run of an exchange's segment, from its `run_start` (undefined when unknown). */
  runOf(segmentId: string | undefined): string | undefined {
    return segmentId === undefined ? undefined : this.#segmentRuns.get(segmentId)?.runId;
  }

  /**
   * Publishes the manifest in force to the control block when it changed, so the run
   * table names it in run markers, seals and tokens. Never throws.
   */
  publishManifest(runtime: WireRuntime): void {
    try {
      const ref = this.manifests?.ref;
      if (ref === undefined || ref.manifestId === this.#published) return;
      runtime.publishManifest({
        epoch: ref.epoch,
        manifestSeq: ref.manifestSeq,
        manifestId: ref.manifestId,
        digest: ref.digest,
      });
      this.#published = ref.manifestId;
    } catch {
      // the run table then names no manifest; the verifier reports the epoch
    }
  }

  /**
   * Rolls each segment at the forced bound (spec 055 §4.3, 050 §3.7): under the run-table
   * lock the run's slot moves to a new segment and the old one's exact position count is
   * read; then the old segment's non-terminal seal is requested and the new segment's
   * continuation `run_start` (predecessor: the old segment) is spooled. A segment whose
   * `run_start` the worker never saw is not rolled (counted): it seals when its run does.
   */
  async rollForced(runtime: WireRuntime): Promise<void> {
    while (this.#forced.length > 0) {
      const segmentId = this.#forced.shift()!;
      try {
        await this.#roll(runtime, segmentId);
      } catch {
        this.#runStats.forced_missed++;
      }
    }
  }

  async #roll(runtime: WireRuntime, segmentId: string): Promise<void> {
    this.#release(segmentId);
    const run = this.#segmentRuns.get(segmentId);
    // Find the run's slot before taking the lock: the application isolates spin for it
    // for at most 20 µs, so it is held only to check that slot again and move it.
    let found = -1;
    for (let slot = 0; slot < MAX_RUNS && run !== undefined; slot++) {
      const [hi, lo] = runtime.runSegment(slot);
      if (segmentIdOf(hi, lo) === segmentId) {
        found = slot;
        break;
      }
    }
    if (run === undefined || found < 0 || !(await runtime.lockAsync(1000))) {
      this.#runStats.forced_missed++;
      return;
    }
    const next = SEGMENT_PREFIX + randomBytes(16).toString("hex");
    let positions: bigint | undefined;
    let resumable = false;
    let last = -1n;
    try {
      const [hi, lo] = runtime.runSegment(found);
      if (segmentIdOf(hi, lo) === segmentId) {
        // Still the run's open segment (not sealed or moved meanwhile).
        positions = runtime.runPositions(found);
        resumable = (runtime.runFlags(found) & RUN_FLAG_RESUMABLE) !== 0n;
        const hex = next.slice(SEGMENT_PREFIX.length);
        runtime.setRunSegment(
          found,
          BigInt.asIntN(64, BigInt("0x" + hex.slice(0, 16))),
          BigInt.asIntN(64, BigInt("0x" + hex.slice(16))),
        );
        last = runtime.nextSequence - 1n;
      }
    } finally {
      runtime.unlock();
    }
    if (positions === undefined) {
      this.#runStats.forced_missed++; // the run moved on (sealed or rolled) first
      return;
    }
    const epoch = runtime.epoch;
    const ref = this.manifests?.ref;
    const digest = ref !== undefined && ref.epoch === epoch ? ref.digest : NO_MANIFEST_DIGEST;
    this.seals.requestSeal(segmentId, {
      lastSequence: last,
      manifestDigest: digest,
      terminal: false,
      resumable,
      runId: run.runId,
      sourceId: this.#config.sourceId,
      epoch,
      positions,
    });
    const fields: Record<string, unknown> = {
      kind: "run_start",
      last_sequence: last.toString(),
      ...(run.idBasis === undefined ? {} : { id_basis: run.idBasis }),
      ...(ref !== undefined && ref.epoch === epoch
        ? { manifest_digest: ref.digest, manifest_id: ref.manifestId }
        : {}),
      predecessors: [formatEntry(segmentId, this.#config.sourceId, epoch, last, digest)],
      run_id: run.runId,
      scope_id: run.scopeId,
      segment_id: next,
      event_id: randomUUID(),
    };
    this.#runMarker({
      t: "marker",
      source: this.#config.sourceId,
      epoch: epoch.toString(),
      fields,
    });
    this.#runStats.forced_rolls++;
  }

  // ------------------------------------------------------------------ manifests (§7.2)

  /**
   * Manifest 0 of `epoch`, once, queued ahead of anything else this pipeline spools in
   * that epoch (`after_source_sequence = -1`: it precedes position 0 whatever was
   * allocated meanwhile). Only the registered epoch's manifest 0 declares the prior
   * unsealed epochs.
   */
  #ensureManifest(epoch: bigint): void {
    const chain = this.manifests;
    if (chain === undefined || chain.ref?.epoch === epoch) return;
    const unsealed = this.#unsealed;
    this.#unsealed = undefined;
    this.markers.queue(chain.initial(epoch, unsealed));
  }

  /**
   * The Fabric worker's tick (at most every 100 ms): manifest 0 when the epoch has none,
   * a periodic heartbeat when one is due (`last`: the last allocated position), and any
   * held marker to the spool. Never throws.
   */
  tick(epoch: bigint, last: bigint): void {
    try {
      this.#ensureManifest(epoch);
      this.heartbeats?.tick(epoch, last);
      this.seals.drain(SEAL_BUDGET_MS);
      this.#pump();
    } catch {
      // a manifest not written leaves its epoch unverified; never the agent's problem
    }
  }

  /**
   * A capture point changed state, effective after `cut` (`WireRuntime.cut`): the next
   * chained manifest is spooled. Never throws.
   */
  pointChanged(
    epoch: bigint,
    point: string,
    state: PointState,
    reason: string | undefined,
    cut: bigint,
  ): void {
    try {
      this.#ensureManifest(epoch);
      this.markers.queue(this.manifests?.pointChanged(epoch, point, state, reason, cut));
      this.#pump();
    } catch {
      // as tick
    }
  }

  /** A model-traffic class became uncaptured after `cut` (`node_worker_unattached`). */
  classUncaptured(epoch: bigint, cls: string, cut: bigint): void {
    try {
      this.#ensureManifest(epoch);
      this.markers.queue(this.manifests?.classUncaptured(epoch, cls, cut));
      this.#pump();
    } catch {
      // as tick
    }
  }

  /**
   * The `final` heartbeat of `epoch` at `last`, after every position is settled (orderly
   * close only). `true` when it and every earlier marker are spooled.
   */
  final(epoch: bigint, last: bigint): boolean {
    try {
      this.#ensureManifest(epoch);
      this.markers.queue(this.heartbeats?.final(epoch, last));
      this.#pump();
      return this.markers.held.length === 0 && this.markers.dropped === 0 && !this.losses.pending;
    } catch {
      return false;
    }
  }

  /**
   * The orderly close of `epoch` at `last` (spec 055 §4.3, 050 §3.7), after the shutdown
   * sweep's `shutdown` losses were recorded: build every handed-off seal, spool the loss
   * ranges, the `segment_seal` markers and then `final`. `true` only when every seal
   * requested was built and queued, none was dropped, and every loss and marker,
   * `final` last, is in the spool. Afterwards the closed epoch settles nothing more.
   * Never throws.
   */
  closeEpoch(epoch: bigint, last: bigint): boolean {
    let sealed: boolean;
    try {
      sealed =
        this.seals.drain() && this.seals.dropped() === 0 && this.seals.waiting().length === 0;
    } catch {
      sealed = false;
    }
    const final = this.final(epoch, last);
    this.losses.setSettle(undefined);
    this.closed = sealed && final;
    return this.closed;
  }

  async close(): Promise<void> {
    await this.protector?.close();
  }

  /** The exchange as the writer reads it, or `undefined` when its record is unreadable. */
  captured(job: ExchangeJob, arena: PayloadArena, epoch: bigint): CapturedExchange | undefined {
    const meta = readUndiciMeta(job.meta);
    const endpoint = meta === undefined ? undefined : this.#config.endpoints[meta.endpointIndex];
    if (meta === undefined || meta.api === undefined || endpoint === undefined) return undefined;
    const side = (
      which: ExchangeJob["request"],
      media: string,
      encoding: string,
    ): CapturedSide => ({
      pieces: [...arena.chunks(which.words)],
      observed: which.state === "exact" ? which.byteLength : undefined,
      truncated: which.state === "truncated",
      cutReason: which.state === "truncated" ? (which.reason ?? "transport_incomplete") : undefined,
      mediaType: mediaTypeOf(media),
      contentEncoding: contentEncodingOf(encoding),
    });
    return {
      exchangeId: uuidText(job.exchangeId),
      eventId: uuidText(job.eventId),
      spanId: hex(job.spanId),
      parent:
        job.parent === undefined
          ? undefined
          : {
              traceId: hex(job.parent.traceId),
              spanId: hex(job.parent.spanId),
              remote: job.parent.remote,
            },
      api: meta.api,
      providerName: endpoint.providerName,
      endpointId: endpoint.endpointId,
      point: UNDICI_POINT,
      sourceId: this.#config.sourceId,
      sourceEpoch: epoch,
      sequence: job.sequence,
      segmentId: segmentIdOf(job.segmentHi, job.segmentLo),
      runId: this.runOf(segmentIdOf(job.segmentHi, job.segmentLo)),
      scopeId: job.scopeId === undefined ? undefined : uuidText(job.scopeId),
      startNs: job.startNs,
      endNs: job.endNs,
      request: side(job.request, meta.requestMediaType, meta.requestContentEncoding),
      response:
        job.response.state === "absent"
          ? undefined
          : side(job.response, meta.responseMediaType, meta.responseContentEncoding),
      responseState: job.responseState,
      statusCode: meta.statusCode,
      errorType: meta.errorType,
      firstChunkOffsetNs: meta.firstChunkOffsetNs,
      providerRequestId:
        this.#config.enrichment.requestIdKey === undefined ? undefined : meta.providerRequestId,
      withheld: job.withheld,
    };
  }

  /**
   * Handles one completed exchange: PROTECT, the span, then spool admission. A position
   * that is not spooled is lost with its reason (`queue_full`, `disk_full`,
   * `internal_error`). Never throws.
   */
  async handle(job: ExchangeJob, arena: PayloadArena, epoch: bigint): Promise<AdmitOutcome> {
    let outcome: AdmitOutcome = "internal_error";
    try {
      const captured = this.captured(job, arena, epoch);
      if (captured === undefined) {
        this.#unreadable += 1;
      } else {
        this.#noticeDisabled(epoch);
        // A held continuation run_start is spooled with its segment's first record.
        this.#release(captured.segmentId);
        // The epoch's manifests go to the spool ahead of its exchanges.
        this.#ensureManifest(epoch);
        this.#pump();
        const prepared = await prepareExchange(
          captured,
          {
            gate: this.gate,
            protector: this.protector,
            tenantId: this.#config.tenantId,
            enrichment: this.#config.enrichment,
          },
          rootTraceId(),
        );
        const entry = exchangeEntry(captured.sourceId, epoch, this.#config.serviceName, prepared);
        outcome = admitEntries(this.#spool, [entry])[0]!;
        if (outcome === "spooled") {
          // The record is in the spool: from here nothing may turn the position into a
          // loss (a spooled position recorded lost would carry two outcomes).
          try {
            this.heartbeats?.noteActivity();
          } catch {
            // the heartbeat's activity flag only; the record stands
          }
          this.#settleWritten(captured, prepared.span);
          try {
            this.#sink.written?.(captured, prepared.span);
          } catch {
            // an observer's failure never changes the outcome
          }
        }
      }
    } catch {
      outcome = "internal_error";
    }
    this.#outcomes[outcome] += 1;
    if (outcome !== "spooled") {
      try {
        this.#sink.lose(outcome, job.sequence, job.segmentHi, job.segmentLo);
      } catch {
        // the position stays a gap; never the agent's problem
      }
    }
    return outcome;
  }

  /**
   * 050 §3.7: a spooled position settles its segment with its record digest, only now
   * that the record is in the spool. A digest that cannot be built leaves the position
   * unsettled, so its segment never seals complete.
   */
  #settleWritten(captured: CapturedExchange, span: SpanDoc): void {
    const segmentId = captured.segmentId;
    if (segmentId === undefined) return;
    try {
      this.seals.noteJob(
        segmentId,
        captured.sourceId,
        captured.sourceEpoch,
        captured.runId,
        captured.scopeId,
      );
      this.seals.settle(segmentId, captured.sequence, exchangeSealEntry(span));
    } catch {
      // unsettled: the verifier reports the segment unsealed
    }
  }

  /**
   * 049 §7.3, spec 055 §5: missing protection is noted, by class only, at the first
   * exchange of each epoch: content disabled (FW-008), or a masking role whose content
   * is withheld for want of a redaction service or transformation (FW-032).
   */
  #noticeDisabled(epoch: bigint): void {
    const disabled = this.gate.contentCapture === "disabled";
    if ((!disabled && !this.#maskedWithheld) || this.#noticed.has(epoch)) return;
    this.#noticed.add(epoch);
    if (disabled) this.#sink.notice?.("FW-008", this.gate.reason ?? "content_capture_disabled");
    else this.#sink.notice?.("FW-032", "protection_failed");
  }
}

/**
 * Chain options that issue manifest 0 with the ids and time `install()` minted (then
 * fresh ones), so the worker's manifest 0 is the document already published.
 */
export function firstManifest(
  first: { readonly ids: readonly [string, string]; readonly stamp: string } | undefined,
): { newId?: () => string; stamp?: () => string } {
  if (first === undefined) return {};
  const ids = [...first.ids];
  let stamp: string | undefined = first.stamp;
  return {
    newId: () => ids.shift() ?? randomUUID(),
    stamp: () => {
      const value = stamp ?? emittedAt(BigInt(Date.now()) * 1_000_000n);
      stamp = undefined;
      return value;
    },
  };
}

/** A random, non-zero trace id for an exchange with no host parent (a root span). */
function rootTraceId(): string {
  for (;;) {
    const id = randomBytes(16).toString("hex");
    if (/[1-9a-f]/.test(id)) return id;
  }
}

/**
 * The Fabric worker's handlers for a pipeline: each completed exchange goes through
 * {@link CapturePipeline.handle} under the runtime's current epoch; every loss record of
 * the runtime's loss ring goes through the loss funnel ({@link CapturePipeline.lost});
 * each loop pass scans the run table for forced seals and ticks the seals, manifests and
 * heartbeats at the last allocated position; an orderly stop closes the epoch.
 */
export function pipelineHandlers(pipeline: CapturePipeline): FabricWorkerHandlers {
  return {
    job: async (job, context) => {
      await pipeline.handle(job, context.exchanges.arena, context.runtime.epoch);
      pipeline.publishManifest(context.runtime);
    },
    loss: (loss, { runtime }) => pipeline.lost(loss, runtime.epoch),
    run: (body) => pipeline.runRecord(body),
    tick: async ({ runtime }) => {
      pipeline.observeRuns(runtime);
      await pipeline.rollForced(runtime);
      pipeline.tick(runtime.epoch, runtime.nextSequence - 1n);
      pipeline.publishManifest(runtime);
    },
    stop: ({ runtime }) => {
      pipeline.closeEpoch(runtime.epoch, runtime.nextSequence - 1n);
    },
  };
}

/** A sink that hands the pipeline's losses to the runtime's loss ring. */
export function runtimeSink(
  runtime: WireRuntime,
  extra: Omit<PipelineSink, "lose"> = {},
): PipelineSink {
  return {
    ...extra,
    lose: (reason, sequence, segmentHi, segmentLo) =>
      runtime.lose(reason, sequence, segmentHi, segmentLo),
  };
}
