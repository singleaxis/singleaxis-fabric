// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §9.5, unit 055-t19: model calls made inside application worker threads are
 * recorded, and threads that record nothing are declared. Real processes, real Workers, the
 * source wire core bundled as the package lays it out (`helpers.ts`):
 *
 * - 8 attached Workers share the process allocator: one epoch, one source, no position
 *   twice, no gap;
 * - a Worker terminated mid-exchange: its open position settles as a `shutdown` loss in the
 *   segment it was allocated in within 200 ms of `terminate()`, and the installing thread's
 *   run is untouched;
 * - a Worker that ran `install()` before the process installed is counted when the Fabric
 *   worker's roll call reaches it, and the manifest declares `node_worker_unattached`;
 * - `takeDetachedEnvs` returning OVERFLOW (the fault build) is counted, and close() still
 *   settles every position;
 * - `cluster.fork()` children register their own epochs.
 *
 * The preload-reach cases are in `reach.test.ts`.
 */
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  type Package,
  buildPackage,
  captureEnv,
  cleanup,
  exchanges,
  losses,
  manifests,
  runHost,
  scratch,
  spoolDocs,
} from "./helpers.js";

const NODE_24 = Number(process.versions.node.split(".")[0]) >= 24;

let pkg: Package;
beforeAll(async () => {
  pkg = await buildPackage();
});
afterAll(() => cleanup());

const declares = (docs: readonly any[]): boolean =>
  manifests(docs).some((m) =>
    (m["fabric.manifest.uncaptured_classes"] ?? []).includes("node_worker_unattached"),
  );

describe.runIf(NODE_24)("application worker threads", { timeout: 120_000 }, () => {
  it("8 attached Workers share one allocator: one epoch, no duplicate position, no gap", async () => {
    const root = scratch("pool");
    const done = await runHost("host.cjs", captureEnv(root, pkg), ["pool"]);
    expect(done.code, done.stderr).toBe(0);
    const { main, workers, status } = done.report;
    expect(workers).toHaveLength(8);
    for (const w of workers) {
      expect(w).toMatchObject({
        capturing: true,
        reason: null,
        epoch: main.epoch,
        source: main.source,
      });
      // Each attached thread names itself in its own status: installed, its own counters.
      expect(w.status.capture).toBe("installed");
      expect(w.status.status.matched).toBe(4);
    }
    expect(status.status.workers_attached).toBe(8);
    expect(status.status.workers_unattached).toBeUndefined();
    expect(status.warning_ids).not.toContain("FW-030");

    const docs = spoolDocs(join(root, "spool"));
    const seen = exchanges(docs);
    // 8 x 4 from the workers, 2 from the installing thread.
    expect(seen).toHaveLength(34);
    expect(new Set(seen.map((e) => e.epoch))).toEqual(new Set([BigInt(main.epoch)]));
    expect(new Set(seen.map((e) => e.source)).size).toBe(1);
    const sequences = seen.map((e) => e.sequence).sort((a, b) => (a < b ? -1 : 1));
    expect(sequences).toEqual(Array.from({ length: 34 }, (_, n) => BigInt(n)));
    expect(losses(docs)).toEqual([]);
    expect(declares(docs)).toBe(false);
    // Every worker exited on its own: settled, nothing lost.
    expect(done.report.exit.stats).toMatchObject({
      workers_attached: 8,
      workers_detached: 8,
      worker_positions_shutdown: 0,
    });
  });

  it("a Worker terminated mid-exchange: its position is a shutdown loss in its own segment within 200 ms", async () => {
    const root = scratch("terminate");
    const done = await runHost("host.cjs", captureEnv(root, pkg), ["terminate"]);
    expect(done.code, done.stderr).toBe(0);
    const { open, settled, elapsedMs, status } = done.report;
    expect(open).toMatchObject({ open: true, capturing: true });
    expect(settled).toBe(true);
    expect(elapsedMs).toBeLessThan(200);
    expect(status.status.worker_positions_shutdown).toBe(1);

    const docs = spoolDocs(join(root, "spool"));
    const seen = exchanges(docs);
    // The worker's first call and the installing thread's call completed.
    expect(seen).toHaveLength(2);
    const ranges = losses(docs);
    expect(ranges).toHaveLength(1);
    const [lost] = ranges;
    expect(lost!.reason).toBe("shutdown");
    expect(lost!.first).toBe(lost!.last);
    // The held call was the worker's second position, in the worker's run segment: the
    // segment of its first (completed) call, not the installing thread's run.
    const segments = new Set(seen.map((e) => e.segment));
    expect(segments.size).toBe(2);
    const workerSegment = seen.find((e) => e.sequence === lost!.first - 1n)?.segment;
    expect(workerSegment).toBeDefined();
    expect(lost!.segment).toBe(workerSegment);
    // Every position is an exchange or a named loss.
    const named = [...seen.map((e) => e.sequence), lost!.first].sort((a, b) => (a < b ? -1 : 1));
    expect(named).toEqual([0n, 1n, 2n]);
    expect(done.report.exit.stats).toMatchObject({
      workers_detached: 1,
      worker_positions_shutdown: 1,
    });
  });

  it("a Worker that closed its handle and installed again keeps one row, and still settles", async () => {
    const root = scratch("reinstall");
    const done = await runHost("host.cjs", captureEnv(root, pkg), ["reinstall"]);
    expect(done.code, done.stderr).toBe(0);
    const { open, settled, elapsedMs, status } = done.report;
    expect(open).toMatchObject({ open: true, capturing: true });
    // A second row under the same environment id was never settled before this fix.
    expect(settled).toBe(true);
    expect(elapsedMs).toBeLessThan(200);
    expect(status.status.workers_attached).toBe(1);
    expect(status.status.worker_positions_shutdown).toBe(1);
    const ranges = losses(spoolDocs(join(root, "spool")));
    expect(ranges.map((r) => r.reason)).toEqual(["shutdown"]);
    expect(done.report.exit.stats).toMatchObject({
      workers_attached: 1,
      workers_detached: 1,
      worker_positions_shutdown: 1,
    });
  });

  it("a Worker that ran install() before the process installed is counted and declared", async () => {
    const root = scratch("preinstall");
    const done = await runHost("host.cjs", captureEnv(root, pkg), ["preinstall"]);
    expect(done.code, done.stderr).toBe(0);
    const { before, counted, status } = done.report;
    expect(before).toMatchObject({ capturing: false, reason: "worker_without_process_runtime" });
    expect(counted).toBe(true);
    expect(status.status.workers_unattached).toBe(1);
    expect(status.warning_ids).toContain("FW-030");
    expect(done.report.exit.warning_ids).toContain("FW-030");
    const docs = spoolDocs(join(root, "spool"));
    const chain = manifests(docs);
    // Manifest 0 did not know; a chained manifest declares the class from its cut on.
    expect(chain[0]!["fabric.manifest.uncaptured_classes"]).not.toContain("node_worker_unattached");
    expect(declares(docs)).toBe(true);
  });

  it("OVERFLOW from takeDetachedEnvs is counted, and close() still settles every position", async () => {
    const faults = await buildPackage("faults");
    const root = scratch("overflow");
    const env = captureEnv(root, faults, { FABRIC_WIRE_TEST_FAULT: "ring=overflow" });
    const done = await runHost("host.cjs", env, ["overflow"]);
    expect(done.code, done.stderr).toBe(0);
    expect(done.report.worker.capturing).toBe(true);
    expect(done.report.exit.stats.worker_detach_overflows).toBeGreaterThanOrEqual(1);
    const docs = spoolDocs(join(root, "spool"));
    expect(exchanges(docs)).toHaveLength(1);
    expect(losses(docs)).toEqual([]);
  });

  it("cluster.fork() children register their own epochs; each process counts from 0", async () => {
    const root = scratch("cluster");
    const env = captureEnv(root, pkg, {
      FABRIC_WIRE_AUTOLOAD: "1",
      NODE_OPTIONS: `--require=${pkg.register}`,
    });
    const done = await runHost("host.cjs", env, ["cluster"]);
    expect(done.code, done.stderr).toBe(0);
    const { primary, children } = done.report;
    expect(children.map((c: any) => c.capturing)).toEqual([true, true]);
    const epochs = new Set([primary.epoch, ...children.map((c: any) => c.epoch)]);
    expect(epochs.size).toBe(3);
    const seen = exchanges(spoolDocs(join(root, "spool")));
    expect(seen).toHaveLength(3);
    expect(new Set(seen.map((e) => String(e.epoch)))).toEqual(epochs);
    expect(seen.map((e) => e.sequence)).toEqual([0n, 0n, 0n]);
  });
});
