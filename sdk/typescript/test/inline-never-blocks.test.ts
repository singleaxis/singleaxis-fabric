// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * v0.8.1 (spec 049 §7.1 rule 1, Sol review item 5): an `inline` durability
 * write never runs on the caller's stack. The record call queues it and
 * returns at once (the item is `pending`); the write runs on the next
 * event-loop turn, and `flush()` waits for it. A synchronous store still
 * occupies the event loop while its write runs, as `process` durability does.
 *
 * Round-2 review F2: the queued write keeps the process alive until it has run,
 * so a process that records and then exits naturally (no `flush()`) still
 * delivers the object and the manifest its span already references.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildSync } from "esbuild";

import { afterEach, describe, expect, it } from "vitest";

import { Fabric, LocalFilesystemContentStore, MemoryKind } from "../src/index.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

class SlowStore extends LocalFilesystemContentStore {
  override putObject(descriptor: Record<string, unknown>, content: string) {
    const until = Date.now() + 80;
    while (Date.now() < until) {
      // a synchronous 80 ms write
    }
    return super.putObject(descriptor, content);
  }
}

describe("inline durability", () => {
  it("never makes the caller wait on a slow synchronous store", async () => {
    const root = mkdtempSync(join(tmpdir(), "fabric-inline-"));
    roots.push(root);
    const fabric = new Fabric({
      tenantId: "acme",
      agentId: "bot",
      identityMode: "clear",
      contentCapture: {
        store: new SlowStore(root, "acme"),
        roles: "all",
        durability: "inline",
      },
    });
    let elapsed = Number.POSITIVE_INFINITY;
    let statuses: string[] = [];
    fabric.decision({ sessionId: "s", requestId: "r" }, (d) => {
      const start = performance.now();
      d.remember({ kind: MemoryKind.SEMANTIC, content: "governed body" });
      elapsed = performance.now() - start;
      statuses = (d.contentManifest?.items ?? []).map((item) => item.status);
    });
    expect(elapsed).toBeLessThan(5);
    expect(statuses).toEqual(["pending"]);
    const result = await fabric.flushContent();
    expect(result?.pending).toBe(0);
    expect(result?.stored).toBeGreaterThanOrEqual(1);
    expect(result?.failed).toBe(0);
  });
});

function filesUnder(root: string): string[] {
  const out: string[] = [];
  if (!existsSync(root)) return out;
  for (const name of readdirSync(root)) {
    const full = join(root, name);
    if (statSync(full).isDirectory()) out.push(...filesUnder(full));
    else out.push(full);
  }
  return out;
}

describe("inline durability on natural exit", () => {
  it("delivers the queued object and manifest when the process exits without flush()", () => {
    const work = mkdtempSync(join(tmpdir(), "fabric-inline-exit-"));
    roots.push(work);
    const here = dirname(fileURLToPath(import.meta.url));
    const entry = join(work, "child.ts");
    const bundle = join(work, "child.mjs");
    const store = join(work, "store");
    const src = join(here, "..", "src", "index.ts").replaceAll("\\", "/");
    // The child records one inline write and falls off the end of the script.
    const script = [
      `import { Fabric, LocalFilesystemContentStore, MemoryKind } from ${JSON.stringify(src)};`,
      `const fabric = new Fabric({ tenantId: "acme", agentId: "bot", identityMode: "clear",`,
      `  contentCapture: { store: new LocalFilesystemContentStore(process.argv[2], "acme"),`,
      `    roles: "all", durability: "inline" } });`,
      `fabric.decision({ sessionId: "s", requestId: "r" }, (d) => {`,
      `  d.remember({ kind: MemoryKind.SEMANTIC, content: "exit body" });`,
      `});`,
    ].join("\n");
    writeFileSync(entry, script);
    buildSync({
      entryPoints: [entry],
      bundle: true,
      platform: "node",
      format: "esm",
      outfile: bundle,
      external: ["@aws-sdk/*"],
      logLevel: "silent",
      banner: {
        js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
      },
    });
    execFileSync(process.execPath, [bundle, store], { stdio: "pipe", timeout: 20_000 });
    const files = filesUnder(store).map((f) => f.slice(store.length));
    expect(files.some((f) => f.includes("/manifests/") && !f.includes("by-decision"))).toBe(true);
    expect(files.some((f) => !f.includes("/manifests/"))).toBe(true);
  });
});
