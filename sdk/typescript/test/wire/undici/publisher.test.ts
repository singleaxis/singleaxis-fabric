// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §3.1, TS-OD-6 (unit 055-t17): only the undici bundled with this Node.js build
 * is qualified. With `publishers: "bundled"` (what `install()` passes), a matched call
 * that another undici copy publishes is never captured: its position is an
 * `uninstrumented_client` loss, so the reader names the gap and the run cannot verify
 * complete, and the status reports FW-035. Calls through global `fetch` in the same
 * process are still captured.
 */
import { createRequire } from "node:module";

import { afterEach, describe, expect, it } from "vitest";

import { exitDocument } from "../../../src/wire/status.js";
import { bundledPublisher } from "../../../src/wire/undici.js";
import {
  CHAT,
  type Capture,
  PUBLISHES_BODIES,
  type Provider,
  capture,
  provider,
  settle,
} from "./helpers.js";

const external = createRequire(import.meta.url)("./fixtures/external-publisher.cjs") as {
  publishCreate(origin: string, path: string): object;
};

let server: Provider | undefined;
let cap: Capture | undefined;
afterEach(async () => {
  cap?.close();
  cap = undefined;
  await server?.close();
  server = undefined;
});

describe("publisher qualification", () => {
  // The hook subscribes only where undici publishes body chunks (Node 24.4+, spec 055 §3.1).
  it.runIf(PUBLISHES_BODIES)(
    "a matched call another undici copy publishes is an uninstrumented_client loss",
    async () => {
      server = await provider();
      cap = capture(server.port, { publishers: "bundled" });
      external.publishCreate(server.base, CHAT);
      external.publishCreate(server.base, CHAT);
      const out = cap.drained();
      expect(out.jobs).toEqual([]);
      expect(out.losses.map((l) => [l.reason, l.sequence])).toEqual([
        ["uninstrumented_client", 0n],
        ["uninstrumented_client", 1n],
      ]);
      expect(cap.hook.stats.unqualifiedPublisher).toBe(2);
      expect(cap.hook.stats.notCaptured).toBe(2);
      expect(cap.runtime.stats().losses.uninstrumented_client).toBe(2n);
    },
  );

  it.runIf(PUBLISHES_BODIES)(
    "inside a live explicit model call the explicit record owns the call: no loss (049 §5 rule 13)",
    async () => {
      server = await provider();
      const ownership = { ended: false, withheld: false };
      cap = capture(server.port, { publishers: "bundled", scope: () => ({ ownership }) });
      external.publishCreate(server.base, CHAT);
      expect(cap.drained().losses).toEqual([]);
      expect(cap.hook.stats.unqualifiedPublisher).toBe(1);
      // Once the explicit scope has ended, the next such call is a named loss again.
      ownership.ended = true;
      external.publishCreate(server.base, CHAT);
      expect(cap.drained().losses.map((l) => l.reason)).toEqual(["uninstrumented_client"]);
    },
  );

  it("an unmatched call from another copy allocates nothing", async () => {
    server = await provider();
    cap = capture(server.port, { publishers: "bundled" });
    external.publishCreate(server.base, "/v1/files");
    expect(cap.drained().losses).toEqual([]);
    expect(cap.hook.stats.unqualifiedPublisher).toBe(0);
  });

  it("publishers: any (the hook's default) captures every copy, as before", async () => {
    server = await provider();
    cap = capture(server.port);
    external.publishCreate(server.base, CHAT);
    expect(cap.hook.stats.unqualifiedPublisher).toBe(0);
    expect(cap.drained().losses).toEqual([]);
  });

  it.runIf(PUBLISHES_BODIES)(
    "global fetch in the same process is still captured, byte for byte",
    async () => {
      server = await provider();
      server.route(CHAT, (_req, res) => res.end('{"ok":true}'));
      cap = capture(server.port, { publishers: "bundled" });
      external.publishCreate(server.base, CHAT);
      const response = await fetch(server.base + CHAT, { method: "POST", body: '{"q":1}' });
      expect(await response.text()).toBe('{"ok":true}');
      await settle();
      const out = cap.drained();
      expect(out.losses.map((l) => l.reason)).toEqual(["uninstrumented_client"]);
      expect(out.jobs.map((j) => j.requestBytes.toString())).toEqual(['{"q":1}']);
      expect(out.jobs.map((j) => j.responseBytes.toString())).toEqual(['{"ok":true}']);
    },
  );

  it("a class is decided once; a prototype-less request is never the bundled one", () => {
    const a = external.publishCreate("http://127.0.0.1:1", "/x");
    expect(bundledPublisher(a)).toBe(false); // decided outside a publish: not bundled
    expect(bundledPublisher(Object.create(null) as object)).toBe(false);
  });

  it.runIf(PUBLISHES_BODIES)(
    "an application's Error.prepareStackTrace is never called and is put back",
    async () => {
      const local = await provider();
      server = local;
      cap = capture(local.port, { publishers: "bundled" });
      const calls: unknown[] = [];
      const mine = (_e: unknown, sites: unknown): unknown => {
        calls.push(sites);
        return "mine";
      };
      const E = Error as unknown as { prepareStackTrace?: unknown; stackTraceLimit: number };
      const before = E.prepareStackTrace;
      E.prepareStackTrace = mine;
      E.stackTraceLimit = 3;
      try {
        class Other {
          method = "POST";
          origin = local.base;
          path = CHAT;
        }
        const { channel } = await import("node:diagnostics_channel");
        channel("undici:request:create").publish({ request: new Other() });
        expect(calls).toEqual([]);
        expect(E.prepareStackTrace).toBe(mine);
        expect(E.stackTraceLimit).toBe(3);
      } finally {
        E.prepareStackTrace = before;
        E.stackTraceLimit = 10;
      }
      expect(cap.drained().losses.map((l) => l.reason)).toEqual(["uninstrumented_client"]);
    },
  );

  it("an application's prepareStackTrace accessor is never run; the class is not captured", () => {
    class Undecided {}
    const own = Object.getOwnPropertyDescriptor(Error, "prepareStackTrace");
    let ran = 0;
    Object.defineProperty(Error, "prepareStackTrace", {
      configurable: true,
      get: () => {
        ran++;
        return undefined;
      },
      set: () => {
        ran++;
      },
    });
    try {
      expect(bundledPublisher(new Undecided())).toBe(false);
    } finally {
      if (own === undefined) delete (Error as { prepareStackTrace?: unknown }).prepareStackTrace;
      else Object.defineProperty(Error, "prepareStackTrace", own);
    }
    expect(ran).toBe(0);
  });

  it("the status documents name FW-035 with its fix", () => {
    const exit = exitDocument({ warning_ids: [], notice_ids: [] }, true, {
      unqualified_publisher: 2,
    });
    expect([...exit.warning_ids, ...exit.notice_ids]).toContain("FW-035");
  });
});
