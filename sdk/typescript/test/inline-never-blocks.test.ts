// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * v0.8.1 (spec 049 §7.1 rule 1, Sol review item 5): an `inline` durability
 * write never runs on the caller's stack. The record call queues it and
 * returns at once (the item is `pending`); the write runs on the next
 * event-loop turn, and `flush()` waits for it. A synchronous store still
 * occupies the event loop while its write runs, as `process` durability does.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
