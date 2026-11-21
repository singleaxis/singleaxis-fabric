// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The Fabric worker of the privacy harness: loads the native lock module, opens the
 * spool and runs the SDK's capture pipeline (`CapturePipeline`) as the job handler.
 *
 * The scanner self-test (`fault: "leak"`) wraps the spool's write so that each record's
 * span gets an attribute holding one canary and its header an extra field holding
 * another. That fault exists only in this harness file; the scanner must report both.
 * `leak_span` (055-t13) leaks the span attribute only: the record stays valid, the
 * sender delivers it, and the scan of the sink must report the canary.
 *
 * `disk_full` (055-t16) is a full volume: every spool record write fails with `ENOSPC`,
 * so each exchange is a `disk_full` loss that the spool cannot take either, and the
 * pipeline (with its loss and tick handlers) mirrors it to the preallocated loss ledger.
 * The scan then reads the ledger's slots, and the delivery step exports them.
 */
import { workerData } from "node:worker_threads";

import { loadNative, nativeTarget } from "../../../../sdk/typescript/src/wire/native.js";
import type { WireRuntime } from "../../../../sdk/typescript/src/wire/runtime.js";
import { Spool, type SpoolEntry, nodeSpoolIo } from "../../../../sdk/typescript/src/wire/spool.js";
import {
  CapturePipeline,
  FABRIC_WORKER_MARKER,
  pipelineHandlers,
  runFabricWorker,
} from "../../../../sdk/typescript/src/wire/worker.js";
import type { WorkerSnapshot } from "./agent.js";

const data = (workerData as Record<string, { snapshot?: WorkerSnapshot }> | null) ?? {};
const snapshot = (data as unknown as { snapshot: WorkerSnapshot }).snapshot;
if ((data as Record<string, unknown>)[FABRIC_WORKER_MARKER] === 1 && snapshot !== undefined) {
  const target = nativeTarget();
  const loaded = loadNative({ prebuildsDir: snapshot.prebuilds, digests: { [target!]: snapshot.digest } });
  if (!loaded.ok) throw new Error(`native: ${loaded.reason}`);
  const full = (): never => {
    throw Object.assign(new Error("no space left on device"), { code: "ENOSPC" });
  };
  const diskFull = snapshot.fault === "disk_full";
  const spool = new Spool(snapshot.spoolDir, {
    maxBytes: snapshot.spoolMaxBytes,
    addon: loaded.addon,
    ...(diskFull ? { io: { ...nodeSpoolIo(loaded.addon), write: full, writev: full } } : {}),
    ...(snapshot.config.spoolKey === undefined ? {} : { key: snapshot.config.spoolKey }),
  });
  if (snapshot.fault === "leak" || snapshot.fault === "leak_span") {
    const write = spool.writeBatch.bind(spool);
    const [attribute, header] = snapshot.leaks;
    spool.writeBatch = (records: readonly SpoolEntry[], reserve?: boolean) =>
      write(
        records.map((record) => {
          const doc = record.doc as Record<string, any>;
          const span = { ...doc.span, attributes: { ...doc.span.attributes, "fabric.test.leak": attribute } };
          // leak_span (055-t13): the span attribute only, so the record stays valid and
          // the sender delivers it: the sink scan must report the canary.
          return { ...record, doc: snapshot.fault === "leak_span" ? { ...doc, span } : { ...doc, span, leak: header } };
        }),
        reserve,
      );
  }
  let runtime: WireRuntime | undefined;
  const pipeline = new CapturePipeline(snapshot.config, spool, {
    lose: (reason, sequence, hi, lo) => runtime?.lose(reason, sequence, hi, lo),
  });
  const handlers = pipelineHandlers(pipeline);
  void runFabricWorker({
    // on a full disk the losses must reach the pipeline, which mirrors them to the ledger
    ...(diskFull ? { loss: handlers.loss, tick: handlers.tick } : {}),
    job: (job, context) => {
      runtime = context.runtime;
      return handlers.job!(job, context);
    },
  });
}
