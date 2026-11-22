// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The Fabric worker's composition (spec 055 §4.5, §7.1): the capture pipeline
 * (`worker.ts` `CapturePipeline`) writes protected records to the spool and the sender
 * (`sender.ts`) delivers them, both on the one Fabric worker, from the plain snapshot the
 * installing thread built (`install.ts`). The worker reads no environment.
 *
 * - every spooled record wakes the sender;
 * - `flush` waits for the jobs queued before it, spools the markers, queues a heartbeat
 *   and settles this process's records;
 * - the orderly stop closes the epoch (seals, then `final`), then delivers within the
 *   stop budget; an exiting process that does not drain the spool only leaves its records
 *   durable. Records left with no live drainer are counted in the spool's exit note
 *   (`.exit-backlog`, content-free) and reported back to the installing thread.
 */
import { isMainThread, parentPort, workerData } from "node:worker_threads";

import { FileContentClient } from "./file-content.js";
import { NodeContentClient } from "./node-content.js";
import { type DeliveryTarget, TraceClient } from "./delivery.js";
import { loadNative } from "./native.js";
import { type Orphan, scanOrphans } from "./registration.js";
import type { WireRuntime } from "./runtime.js";
import { Sender } from "./sender.js";
import { Spool } from "./spool.js";
import type { SpoolDoc } from "./spool-codec.js";
import { type StatusDocument, exitDocument, writeStatusFile } from "./status.js";
import {
  CapturePipeline,
  STOP_RESULT,
  WORKER_WARNING,
  type FabricWorkerContext,
  type FabricWorkerHandlers,
  type PipelineConfig,
  isFabricWorkerThread,
  pipelineHandlers,
  runFabricWorker,
} from "./worker.js";

/** The structured-cloneable snapshot the installing thread hands the Fabric worker. */
export interface FabricMainSnapshot {
  readonly pipeline: PipelineConfig;
  readonly spoolDir: string;
  readonly spoolMaxBytes: number;
  /** `FABRIC_WIRE_SPOOL_MAX_RECEIPTS` (default 4,096). */
  readonly spoolMaxReceipts?: number;
  /** `FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY`: where the barrier walk stops. */
  readonly spoolDurableBoundary?: string;
  /** The explicit plaintext migration (already refused under the production profile). */
  readonly spoolMigratePlaintext?: boolean;
  /** Where the native module is (default: the package's prebuilds and digest table). */
  readonly native: {
    readonly prebuildsDir?: string;
    readonly digests?: Readonly<Record<string, string>>;
  };
  /** `/v1/traces`; the headers travel explicitly (a target's own are non-enumerable). */
  readonly traces: { readonly target: DeliveryTarget; readonly headers: Record<string, string> };
  /** The Node's content endpoint, when one is configured. */
  readonly content:
    { readonly target: DeliveryTarget; readonly headers: Record<string, string> } | undefined;
  /**
   * The local profile's direct store (`FABRIC_WIRE_STORE=file:///dir`, no Node): the
   * sender writes the bodies there itself (`file-content.ts`).
   */
  readonly fileStore?: { readonly root: string; readonly tenant: string };
  readonly proxy: string | undefined;
  readonly batchBodies: number;
  readonly concurrency: number;
  /** The default stop budget when no `stop` request arrived (`shutdown_timeout`). */
  readonly shutdownTimeoutMs: number;
  /** `FABRIC_WIRE_DRAIN_ON_EXIT_S` in ms (written into the exit note). */
  readonly drainOnExitMs: number;
  /** `FABRIC_WIRE_DIAGNOSTICS`: the sender's class-only warnings reach stderr only on `stderr`. */
  readonly diagnostics?: "silent" | "stderr";
  /**
   * `FABRIC_WIRE_STATUS_FILE` and the install document the installing thread decided:
   * this worker writes it when it starts and the exit document at the orderly stop.
   */
  readonly status?: { readonly path: string; readonly install: StatusDocument };
}

/** Distinct warnings one worker prints at most (each once). */
const MAX_WARNINGS = 64;

/**
 * Fabric's diagnostics channel on the worker (spec 055 §4.7): silent by default; with
 * `FABRIC_WIRE_DIAGNOSTICS=stderr` each distinct class-only warning goes once to the
 * installing thread, which prints it (this worker's own stderr is discarded).
 */
function warnings(
  mode: FabricMainSnapshot["diagnostics"],
  post: (message: unknown) => void,
): ((text: string) => void) | undefined {
  if (mode !== "stderr") return undefined;
  const printed = new Set<string>();
  return (text) => {
    if (printed.has(text) || printed.size >= MAX_WARNINGS) return;
    printed.add(text);
    post({ [WORKER_WARNING]: text });
  };
}

/** What the orderly stop reports back to the installing thread. */
export interface StopResult {
  /** Every seal and `final` is in the spool (050 §3.2 rule 3: the registration's final). */
  readonly closed: boolean;
  /** Every record pending at the stop was delivered and nothing was lost. */
  readonly delivered: boolean;
  /** Records left in the spool with no live drainer (written into the exit note). */
  readonly backlog: number;
}

/** Of the stop budget, kept back so the worker exits on its own before it is terminated. */
const STOP_MARGIN = 0.1;
/** How long the stop waits for a pass its closed clients cut short to end. */
const LATE_PASS_MS = 50;

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Waits until the jobs queued now were handled, or the deadline. */
async function jobsHandled(runtime: WireRuntime, deadline: number): Promise<boolean> {
  while (runtime.jobs.count > 0) {
    if (performance.now() >= deadline) return false;
    await delay(5);
  }
  return true;
}

/**
 * Runs the Fabric worker with the pipeline and the sender when called in a Fabric worker
 * started by `install()`; `undefined` anywhere else (the wire core calls it at load).
 * Throws (the worker then counts as crashed) when the native module or the spool cannot
 * be used there.
 */
export function runFabricMain(): Promise<void> | undefined {
  if (isMainThread || !isFabricWorkerThread()) return undefined;
  const snapshot = (workerData as { snapshot?: unknown }).snapshot as
    FabricMainSnapshot | undefined;
  if (snapshot === undefined || typeof snapshot !== "object" || !("pipeline" in snapshot)) {
    return undefined;
  }
  const post = (message: unknown): void => parentPort?.postMessage(message);
  const warn = warnings(snapshot.diagnostics, post);
  const native = loadNative(snapshot.native as Parameters<typeof loadNative>[0]);
  if (!native.ok) throw new Error(`the native lock module is unusable (${native.reason})`);
  const config = snapshot.pipeline;
  const spool = new Spool(snapshot.spoolDir, {
    maxBytes: snapshot.spoolMaxBytes,
    addon: native.addon,
    ...(config.spoolKey === undefined ? {} : { key: config.spoolKey }),
    ...(snapshot.spoolMaxReceipts === undefined ? {} : { maxReceipts: snapshot.spoolMaxReceipts }),
    ...(snapshot.spoolDurableBoundary === undefined
      ? {}
      : { durableBoundary: snapshot.spoolDurableBoundary }),
    migratePlaintext: snapshot.spoolMigratePlaintext === true,
  });
  let runtime: WireRuntime | undefined;
  const pipeline = new CapturePipeline(config, spool, {
    lose: (reason, sequence, hi, lo) => runtime?.lose(reason, sequence, hi, lo),
  });
  const target = (side: { target: DeliveryTarget; headers: Record<string, string> }) => ({
    ...side.target,
    headers: side.headers,
  });
  const traces = new TraceClient(target(snapshot.traces), { proxy: snapshot.proxy });
  const content =
    snapshot.content !== undefined
      ? new NodeContentClient(target(snapshot.content), {
          serviceName: config.serviceName,
          proxy: snapshot.proxy,
        })
      : snapshot.fileStore !== undefined
        ? new FileContentClient(snapshot.fileStore.root, snapshot.fileStore.tenant)
        : undefined;
  const sender = new Sender({
    spool,
    traces,
    content,
    serviceName: config.serviceName,
    batchBodies: snapshot.batchBodies,
    concurrency: snapshot.concurrency,
    beats: pipeline.heartbeats,
    orphans: (): readonly Orphan[] =>
      scanOrphans({ addon: native.addon, spoolDir: spool.dir, runtime }),
    quarantined: (docs) => quarantinedLosses(pipeline, docs),
    warn,
    failures: () => {
      const stats = pipeline.stats();
      return stats.losses.recorded + (stats.manifests?.dropped ?? 0) + spool.failed;
    },
  });
  const status = snapshot.status;
  // The install document, once per process: a replacement worker after a crash does not
  // write it again over a newer one.
  if (status !== undefined && (workerData as { restarted?: unknown }).restarted !== true) {
    writeStatusFile(status.path, { ...status.install, written_at: new Date().toISOString() }, warn);
  }
  const base = pipelineHandlers(pipeline);
  const handlers: FabricWorkerHandlers = {
    ...base,
    job: async (job, context) => {
      runtime = context.runtime;
      await base.job!(job, context);
      sender.wake();
    },
    loss: (loss, context) => {
      runtime = context.runtime;
      return base.loss!(loss, context);
    },
    tick: async (context) => {
      runtime = context.runtime;
      sender.start();
      await base.tick!(context);
    },
    flush: async (deadline, context) => {
      runtime = context.runtime;
      const handled = await jobsHandled(context.runtime, deadline);
      await base.tick!(context);
      pipeline.heartbeats?.tick(context.runtime.epoch, context.runtime.nextSequence - 1n, true);
      const delivered = await sender.flush(deadline);
      // A loss or marker still in memory (perhaps mirrored to the ledger) is not durable
      // spool evidence yet: the flush does not succeed.
      return handled && delivered && !pipeline.losses.pending && pipeline.markers.held.length === 0;
    },
    stop: async (context) => {
      runtime = context.runtime;
      uninstalled(pipeline, context);
      await base.stop!(context);
      const result = await stopDelivery(sender, spool, snapshot, context, pipeline.closed === true);
      const stats = exitStats(pipeline, sender, result, context.stop?.counters);
      if (status !== undefined) {
        writeStatusFile(
          status.path,
          exitDocument(status.install, result.delivered, stats, context.stop?.unmatched),
          warn,
        );
      }
      try {
        post({ [STOP_RESULT]: { ...result, stats } });
      } catch {
        // the installing thread reads no result: the registration stays unfinalized
      }
      try {
        // Closing the clients ends a delivery pass still exporting past the stop budget
        // (its requests resolve `retry`); that pass keeps the drain lock and the spool
        // until it ends, or until the worker is terminated, which releases both.
        traces.close();
        content?.close();
        await pipeline.close();
        if (await sender.stopped(LATE_PASS_MS)) spool.close();
      } catch {
        // the process is ending this worker either way
      }
    },
  };
  return runFabricWorker(handlers);
}

/**
 * The exit document's counters (content-free integers): the installing thread's (matched,
 * not captured, unmatched model-shaped requests), the pipeline's admissions and losses by
 * reason, and the sender's deliveries and rejections.
 */
function exitStats(
  pipeline: CapturePipeline,
  sender: Sender,
  result: StopResult,
  counters: Readonly<Record<string, number>> | undefined,
): Record<string, number> {
  const out: Record<string, number> = {};
  const put = (name: string, value: unknown): void => {
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) out[name] = value;
  };
  try {
    for (const [name, value] of Object.entries(counters ?? {})) put(name, value);
    if (out.matched !== undefined) put("captured", out.matched - (out.not_captured ?? 0));
    const stats = pipeline.stats();
    for (const [name, value] of Object.entries(stats.outcomes)) put(name, value);
    put("lost", stats.losses.recorded);
    for (const [reason, value] of Object.entries(stats.losses.byReason))
      put(`lost.${reason}`, value);
    const sent = sender.stats();
    put("delivered", sent.delivered);
    put("content_rejected", sent.content_rejected);
    put("traces_rejected", sent.traces_rejected);
    put("quarantined", sent.quarantined);
    put("backlog", result.backlog);
    put("spool_migrated", sent.spool_migrated);
    put("ledger_recovered", sent.ledger_recovered);
    for (const [name, value] of Object.entries(sender.health())) put(name, value);
  } catch {
    // the counters gathered so far
  }
  return out;
}

async function stopDelivery(
  sender: Sender,
  spool: Spool,
  snapshot: FabricMainSnapshot,
  context: FabricWorkerContext,
  closed: boolean,
): Promise<StopResult> {
  const start = performance.now();
  const deadline = context.stop?.deadline ?? start + snapshot.shutdownTimeoutMs;
  const exiting = context.stop?.exiting === true;
  const budget = Math.max(0, deadline - start);
  sender.start();
  const delivered = await sender.close(start + budget * (1 - STOP_MARGIN), { exiting });
  let backlog = 0;
  try {
    backlog = sender.exitBacklog();
    if (backlog > 0) spool.writeExitNote(backlog, snapshot.drainOnExitMs / 1000);
  } catch {
    // the note is best effort; the count still reaches the installing thread
  }
  // 050 §3.2 rule 3: `final` counts only once the spool's directory barrier holds.
  return { closed: closed && spool.durable, delivered: delivered && backlog === 0, backlog };
}

/**
 * The hooks `close()` removed (050 §3.8; Python `_p1_uninstalled`): every point that was
 * `active` becomes `disabled(shutdown)` in a chained manifest at the cut where its hook
 * went, before the stop handler seals the segments and spools `final`.
 */
function uninstalled(pipeline: CapturePipeline, context: FabricWorkerContext): void {
  const off = context.stop?.uninstalled;
  if (off === undefined) return;
  for (const point of off.points) {
    try {
      if (pipeline.manifests?.states[point]?.[0] !== "active") continue;
      pipeline.pointChanged(context.runtime.epoch, point, "disabled", "shutdown", off.cut);
    } catch {
      // the manifest keeps the point active; the stop goes on
    }
  }
}

/** A quarantined file's parsed headers: each position is an `internal_error` loss. */
function quarantinedLosses(pipeline: CapturePipeline, docs: readonly SpoolDoc[]): void {
  for (const doc of docs) {
    try {
      const attrs = (doc.span as Record<string, unknown> | undefined)?.attributes as
        Record<string, unknown> | undefined;
      const source = attrs?.["fabric.source_id"];
      const epoch = attrs?.["fabric.source.epoch"];
      const sequence = attrs?.["fabric.source.sequence"];
      const segment = attrs?.["fabric.run.segment_id"];
      const exact = (v: unknown): bigint | undefined =>
        typeof v === "bigint" ? v : Number.isSafeInteger(v) ? BigInt(v as number) : undefined;
      const e = exact(epoch);
      const s = exact(sequence);
      if (typeof source !== "string" || e === undefined || s === undefined) continue;
      // retain, not record: the record existed and its digest is already in its seal
      pipeline.losses.retain({
        sourceId: source,
        epoch: e,
        reason: "internal_error",
        segmentId: typeof segment === "string" ? segment : undefined,
        first: s,
        last: s,
        count: 1n,
      });
    } catch {
      // that position stays an unexplained gap
    }
  }
}
