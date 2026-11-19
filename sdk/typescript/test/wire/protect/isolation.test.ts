// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * PROTECT is isolated from the agent and from the disk (spec 055 §5, §6.3; unit 055-t8):
 * a process killed while protection runs leaves no unprotected byte on disk, and a
 * CPU-bound Fabric worker does not move the hook's medians on the application thread.
 */
import { spawn } from "node:child_process";
import { existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildSync } from "esbuild";
import { afterAll, describe, expect, it } from "vitest";

import { ExchangeTable, REQUEST, RESPONSE } from "../../../src/wire/exchange.js";
import { WireRuntime, createRuntimeShared } from "../../../src/wire/runtime.js";
import { FabricWorker } from "../../../src/wire/worker.js";
import { native, spoolDir, cleanupDirs } from "../spool/helpers.js";
import { PUBLISHES_BODIES } from "../undici/helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const built = mkdtempSync(join(tmpdir(), "f055-t8-protect-"));
buildSync({
  entryPoints: [join(HERE, "fixtures", "crash.ts"), join(HERE, "fixtures", "stall-worker.ts")],
  outdir: built,
  outExtension: { ".js": ".cjs" },
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node22",
  logLevel: "silent",
});
afterAll(() => {
  rmSync(built, { recursive: true, force: true });
  cleanupDirs();
});

function everyFile(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return lstatSync(path).isDirectory() ? everyFile(path) : [path];
  });
}

describe("isolation of PROTECT", () => {
  // The child captures a real `fetch`, which needs a build that publishes body chunks.
  it.skipIf(!PUBLISHES_BODIES)(
    "a process killed while protecting leaves no unprotected byte on disk",
    async () => {
      const { build, digest } = native();
      const dir = spoolDir();
      const socketDir = mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "f055-t8-"));
      const canary = "UNPROTECTED-CANARY-" + process.pid;
      const child = spawn(
        process.execPath,
        [
          join(built, "crash.cjs"),
          JSON.stringify({
            prebuilds: build.dir,
            digest,
            spool: dir,
            socket: join(socketDir, "r.sock"),
            canary,
          }),
        ],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      let err = "";
      child.stderr.on("data", (part: Buffer) => (err += part.toString()));
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error(`the child never reached PROTECT: ${err}`)),
          30_000,
        );
        child.stdout.on("data", (part: Buffer) => {
          if (part.toString().includes('"protecting":true')) {
            clearTimeout(timer);
            resolve();
          }
        });
        child.once("exit", (code) => reject(new Error(`the child exited ${code}: ${err}`)));
      });
      const exited = new Promise((resolve) => child.once("exit", resolve));
      child.kill("SIGKILL");
      await exited;
      rmSync(socketDir, { recursive: true, force: true });
      const files = everyFile(dir);
      // The spool exists (its lock files), and nothing in it holds the body.
      expect(files.length).toBeGreaterThan(0);
      expect(files.filter((path) => path.endsWith(".rec"))).toEqual([]);
      for (const path of files) {
        const bytes = readFileSync(path).toString("latin1");
        expect(bytes, path).not.toContain(canary);
      }
    },
  );

  it("a CPU-bound Fabric worker does not move the hook medians", async () => {
    const chunk = Buffer.alloc(1024, 0x61);
    const measure = async (stallMs: number): Promise<number> => {
      const runtime = new WireRuntime(createRuntimeShared(), "installer");
      const table = new ExchangeTable(runtime);
      const worker = new FabricWorker(runtime, {
        entry: join(built, "stall-worker.cjs"),
        snapshot: { stallMs },
      });
      worker.start();
      const samples: number[] = [];
      for (let i = 0; i < 600; i++) {
        // The hook's runtime work for one matched non-streaming exchange.
        const start = process.hrtime.bigint();
        const handle = table.begin();
        table.admit(handle, REQUEST, chunk);
        table.responseStarted(handle);
        table.admit(handle, RESPONSE, chunk);
        table.finish(handle, "complete");
        if (i >= 100) samples.push(Number(process.hrtime.bigint() - start));
        if (i % 50 === 49) await new Promise((resolve) => setTimeout(resolve, 1));
      }
      const stats = runtime.stats();
      await worker.stop(2000);
      expect(stats.losses.queue_full).toBe(0n); // the stalled worker never filled the ring
      samples.sort((a, b) => a - b);
      return samples[samples.length >> 1]!;
    };
    await measure(0); // warm the JIT on a throwaway runtime
    const idle = await measure(0);
    const stalled = await measure(20);
    // The stalled worker runs on its own thread: the application's median stays within
    // the per-exchange budget (50 µs) and near the idle median.
    expect(stalled).toBeLessThan(50_000);
    expect(stalled).toBeLessThan(Math.max(2 * idle, idle + 20_000));
  }, 60_000);
});
