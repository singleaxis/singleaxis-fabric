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

import { NodeContentClient } from "./node-content.js";
import { type DeliveryTarget, TraceClient } from "./delivery.js";
import { loadNative } from "./native.js";
import { type Orphan, scanOrphans } from "./registration.js";
import type { WireRuntime } from "./runtime.js";
import { Sender } from "./sender.js";
import { Spool } from "./spool.js";
import type { SpoolDoc } from "./spool-codec.js";
import {
  CapturePipeline,
  STOP_RESULT,
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
  readonly proxy: string | undefined;
  readonly batchBodies: number;
  readonly concurrency: number;
  /** The default stop budget when no `stop` request arrived (`shutdown_timeout`). */
  readonly shutdownTimeoutMs: number;
  /** `FABRIC_WIRE_DRAIN_ON_EXIT_S` in ms (written into the exit note). */
  readonly drainOnExitMs: number;
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
  const native = loadNative(snapshot.native as Parameters<typeof loadNative>[0]);
  if (!native.ok) throw new Error(`the native lock module is unusable (${native.reason})`);
  const config = snapshot.pipeline;
  const spool = new Spool(snapshot.spoolDir, {
    maxBytes: snapshot.spoolMaxBytes,
    addon: native.addon,
    ...(config.spoolKey === undefined ? {} : { key: config.spoolKey }),
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
    snapshot.content === undefined
      ? undefined
      : new NodeContentClient(target(snapshot.content), {
          serviceName: config.serviceName,
          proxy: snapshot.proxy,
        });
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
    failures: () => {
      const stats = pipeline.stats();
      return stats.losses.recorded + (stats.manifests?.dropped ?? 0) + spool.failed;
    },
  });
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
      return handled && delivered && !pipeline.losses.pending && pipeline.markers.held.length === 0;
    },
    stop: async (context) => {
      runtime = context.runtime;
      await base.stop!(context);
      const result = await stopDelivery(sender, spool, snapshot, context, pipeline.closed === true);
      try {
        post({ [STOP_RESULT]: result });
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
  return { closed, delivered: delivered && backlog === 0, backlog };
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
