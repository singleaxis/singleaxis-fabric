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
 */
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { Worker, isMainThread, workerData } from "node:worker_threads";

import { DeploymentPolicy, type DeploymentPolicyData } from "../deployment-policy.js";
import { labelPseudonym, operatorLabel } from "../identity.js";
import type { RedactionServiceOptions, Transformation } from "../redaction.js";
import { SDK_VERSION } from "../version.js";
import { type PayloadArena, SlotPool } from "./arena.js";
import { ExchangeTable, JOB_EXCHANGE, JOB_RELEASING, type ExchangeJob } from "./exchange.js";
import {
  Heartbeats,
  ManifestChain,
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
import {
  type RuntimeLoss,
  type RuntimeLossReason,
  type RuntimeShared,
  WireRuntime,
  waitAsync,
} from "./runtime.js";
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
  private stopping: ((clean: boolean) => void) | undefined;
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
      this.runtime.fail("worker_start_failed");
      return;
    }
    worker.unref();
    // An uncaught error in the worker ends it; it is never rethrown on this thread.
    worker.on("error", () => undefined);
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
   * Asks the worker to drain and exit, and terminates it after `timeoutMs`. Resolves
   * `true` only when it drained and exited by itself; `false` when it crashed while
   * draining or had to be terminated.
   */
  async stop(timeoutMs: number): Promise<boolean> {
    const worker = this.thread;
    if (worker === undefined) return true;
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
   * Called once per loop pass (at least every {@link WORKER_TICK_MS}): the manifests'
   * and heartbeats' clock. A handler that throws is ignored until the next pass.
   */
  tick?(context: FabricWorkerContext): void | Promise<void>;
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
      growPools(pools);
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
    growPools(pools);
    if (handlers.tick !== undefined) {
      try {
        await handlers.tick(context);
      } catch {
        // the next pass tries again
      }
    }
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
  };
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

/** Where the pipeline's own losses go (the runtime's loss ring; 055-t10 seals them). */
export interface PipelineSink {
  lose(reason: RuntimeLossReason, sequence: bigint, segmentHi: bigint, segmentLo: bigint): void;
  /** A class-only notice (catalogue id and reason), never a value. */
  notice?(id: string, reason: string): void;
  /** A record was written: 055-t10 settles its segment's seal here. */
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
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const uuidText = (bytes: Uint8Array): string => {
  const h = hex(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
};
const u64hex = (value: bigint): string => BigInt.asUintN(64, value).toString(16).padStart(16, "0");

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

  constructor(config: PipelineConfig, spool: Spool, sink: PipelineSink) {
    this.#config = config;
    this.#spool = spool;
    this.#sink = sink;
    this.manifests =
      config.manifest === undefined ? undefined : new ManifestChain(config.manifest.template);
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
    };
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
      this.markers.pump(this.#spool);
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
      this.markers.pump(this.#spool);
    } catch {
      // as tick
    }
  }

  /** A model-traffic class became uncaptured after `cut` (`node_worker_unattached`). */
  classUncaptured(epoch: bigint, cls: string, cut: bigint): void {
    try {
      this.#ensureManifest(epoch);
      this.markers.queue(this.manifests?.classUncaptured(epoch, cls, cut));
      this.markers.pump(this.#spool);
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
      this.markers.pump(this.#spool);
      return this.markers.held.length === 0 && this.markers.dropped === 0;
    } catch {
      return false;
    }
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
    const segmented = job.segmentHi !== 0n || job.segmentLo !== 0n;
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
      segmentId: segmented ? `seg-${u64hex(job.segmentHi)}${u64hex(job.segmentLo)}` : undefined,
      runId: undefined,
      scopeId: undefined,
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
        // The epoch's manifests go to the spool ahead of its exchanges.
        this.#ensureManifest(epoch);
        this.markers.pump(this.#spool);
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
          this.heartbeats?.noteActivity();
          this.#sink.written?.(captured, prepared.span);
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

/** A random, non-zero trace id for an exchange with no host parent (a root span). */
function rootTraceId(): string {
  for (;;) {
    const id = randomBytes(16).toString("hex");
    if (/[1-9a-f]/.test(id)) return id;
  }
}

/**
 * The Fabric worker's handlers for a pipeline: each completed exchange goes through
 * {@link CapturePipeline.handle} under the runtime's current epoch; its losses go to the
 * runtime's loss ring; each loop pass ticks the manifests and heartbeats at the last
 * allocated position.
 */
export function pipelineHandlers(pipeline: CapturePipeline): FabricWorkerHandlers {
  return {
    job: async (job, context) => {
      await pipeline.handle(job, context.exchanges.arena, context.runtime.epoch);
    },
    tick: ({ runtime }) => pipeline.tick(runtime.epoch, runtime.nextSequence - 1n),
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
