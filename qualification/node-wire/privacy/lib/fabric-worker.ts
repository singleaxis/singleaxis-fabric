// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The Fabric worker of the privacy harness: loads the native lock module, opens the
 * spool and runs the SDK's capture pipeline (`CapturePipeline`) as the job handler.
 *
 * The scanner self-test (`fault: "leak"`) wraps the spool's write so that each record's
 * span gets an attribute holding one canary and its header an extra field holding
 * another. That fault exists only in this harness file; the scanner must report both.
 */
import { workerData } from "node:worker_threads";

import { loadNative, nativeTarget } from "../../../../sdk/typescript/src/wire/native.js";
import type { WireRuntime } from "../../../../sdk/typescript/src/wire/runtime.js";
import { Spool, type SpoolEntry } from "../../../../sdk/typescript/src/wire/spool.js";
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
  const spool = new Spool(snapshot.spoolDir, {
    maxBytes: snapshot.spoolMaxBytes,
    addon: loaded.addon,
    ...(snapshot.config.spoolKey === undefined ? {} : { key: snapshot.config.spoolKey }),
  });
  if (snapshot.fault === "leak") {
    const write = spool.writeBatch.bind(spool);
    const [attribute, header] = snapshot.leaks;
    spool.writeBatch = (records: readonly SpoolEntry[], reserve?: boolean) =>
      write(
        records.map((record) => {
          const doc = record.doc as Record<string, any>;
          const span = { ...doc.span, attributes: { ...doc.span.attributes, "fabric.test.leak": attribute } };
          return { ...record, doc: { ...doc, span, leak: header } };
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
    job: (job, context) => {
      runtime = context.runtime;
      return handlers.job!(job, context);
    },
  });
}
