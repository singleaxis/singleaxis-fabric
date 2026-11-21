// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §9.5 (unit 055-t11), §4.3 "Intentional language differences", R9: run scopes
 * follow promises, timers and `queueMicrotask`; `run()` returns the callback's value and
 * keeps thrown and rejected objects as they are; strict mode throws, the default fails
 * open; caller ids and the environment never leak (canaries), and Fabric adds no baggage.
 */
import { spawnSync } from "node:child_process";
import { createServer, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";

import { afterEach, describe, expect, it } from "vitest";

import { RUN_COUNTERS, RunApiMisuse, setStrictModeForTesting } from "../../../src/wire/segments.js";
import {
  captureScope,
  endRun,
  resumeToken,
  resumeTokens,
  run,
  setRunOutcome,
} from "../../../src/wire/run-api.js";
import { currentRunScope } from "../../../src/wire/scope.js";

import { harness, unbind } from "./helpers.js";

afterEach(() => {
  unbind();
  setStrictModeForTesting(undefined);
});

describe("AsyncLocalStorage propagation", () => {
  it("promises, timers, setImmediate and queueMicrotask keep the run's segment", async () => {
    const h = harness();
    const seen = await run({ runId: "async" }, async () => {
      const out: (string | undefined)[] = [h.alloc().segment];
      await Promise.resolve();
      out.push(h.alloc().segment);
      await sleep(1);
      out.push(h.alloc().segment);
      await new Promise<void>((resolve) =>
        setTimeout(() => {
          out.push(h.alloc().segment);
          resolve();
        }, 1),
      );
      await new Promise<void>((resolve) =>
        globalThis.queueMicrotask(() => {
          out.push(h.alloc().segment);
          resolve();
        }),
      );
      await new Promise<void>((resolve) =>
        setImmediate(() => {
          out.push(h.alloc().segment);
          resolve();
        }),
      );
      // Promise fan-out inside the block shares its segment.
      out.push(...(await Promise.all([1, 2, 3].map(async () => h.alloc().segment))));
      return out;
    });
    const [start] = h.markers("run_start");
    expect(seen).toHaveLength(9);
    expect(new Set(seen)).toEqual(new Set([start!.segment_id]));
    expect(h.seals()[0]).toMatchObject({ segment: start!.segment_id, positions: "9" });
  });

  it("the scope ends when the returned promise settles; a continuation after it is outside the run", async () => {
    const h = harness();
    let later: Promise<string | undefined> | undefined;
    await run({ runId: "short" }, async () => {
      later = sleep(5).then(() => h.alloc().segment);
    });
    expect(h.markers("run_end")).toHaveLength(1);
    expect(await later).toBeUndefined();
    expect(currentRunScope()).toBeUndefined();
  });

  it("callbacks bound to another context run outside the run", async () => {
    const h = harness();
    const outside = h.table; // keep a reference only
    void outside;
    const { AsyncResource } = await import("node:async_hooks");
    const bound = AsyncResource.bind(() => captureScope());
    const inside = run({ runId: "ctx" }, () => [captureScope(), bound()]);
    expect(inside[0]?.runSlot).toBeGreaterThanOrEqual(0);
    expect(inside[1]).toBeUndefined();
  });

  it("nested blocks of other runs: the innermost open scope names the call", () => {
    const h = harness();
    run({ runId: "outer" }, () => {
      const outerSeg = h.alloc().segment;
      run({ runId: "inner" }, () => expect(h.alloc().segment).not.toBe(outerSeg));
      expect(h.alloc().segment).toBe(outerSeg);
    });
  });
});

describe("run() returns what the callback returns, as it is", () => {
  it("a synchronous value, and a thrown object as the same object", () => {
    harness();
    const value = { v: 1 };
    expect(run({}, () => value)).toBe(value);
    const thrown = new TypeError("app");
    let caught: unknown;
    try {
      run({}, () => {
        throw thrown;
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBe(thrown);
    const odd = { notAnError: true };
    expect(() =>
      run({}, () => {
        throw odd;
      }),
    ).toThrow(expect.objectContaining({ notAnError: true }));
  });

  it("a rejected promise rejects with the same object; a resolved one with the same value", async () => {
    const h = harness();
    const reason = new RangeError("app");
    await expect(run({}, () => Promise.reject(reason))).rejects.toBe(reason);
    const value = { v: 2 };
    await expect(run({}, async () => value)).resolves.toBe(value);
    expect(h.markers("run_end").map((m) => m.scope_status)).toEqual(["error", "ok"]);
  });

  it("an abort is a cancelled scope; the app's own error class is never read through a getter", async () => {
    const h = harness();
    const controller = new AbortController();
    controller.abort();
    await expect(run({}, () => Promise.reject(controller.signal.reason))).rejects.toBe(
      controller.signal.reason,
    );
    let touched = false;
    const sneaky = Object.create(Error.prototype, {
      name: {
        get() {
          touched = true;
          return "AbortError";
        },
      },
    });
    let caught: unknown;
    try {
      run({}, () => {
        throw sneaky;
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBe(sneaky);
    expect(touched).toBe(false);
    expect(h.markers("run_end").map((m) => m.scope_status)).toEqual(["cancelled", "error"]);
  });

  it("a rejection the application never handles stays unhandled", async () => {
    harness();
    const reason = new Error("unhandled by the app");
    const seen: unknown[] = [];
    const listener = (error: unknown): void => {
      seen.push(error);
    };
    const others = process.listeners("unhandledRejection");
    process.removeAllListeners("unhandledRejection");
    process.on("unhandledRejection", listener);
    try {
      void run({}, () => Promise.reject(reason));
      await sleep(20);
    } finally {
      process.off("unhandledRejection", listener);
      for (const other of others) process.on("unhandledRejection", other);
    }
    expect(seen).toEqual([reason]);
  });

  it("without capture the callback runs exactly once, untouched", async () => {
    const promise = Promise.resolve(3);
    let calls = 0;
    expect(
      run({}, () => {
        calls++;
        return promise;
      }),
    ).toBe(promise);
    expect(calls).toBe(1);
    expect(resumeToken()).toBeUndefined();
    expect(resumeTokens(2)).toEqual([]);
  });
});

describe("fail open by default, throw in strict mode (FABRIC_RECORDS_STRICT=1)", () => {
  it("default: misuse is counted and dropped; a non-string runId runs the callback uncaptured", () => {
    const h = harness();
    const before = RUN_COUNTERS.apiMisuse;
    expect(run({ runId: 42 as never }, () => "ran")).toBe("ran");
    expect(run({ runId: "x", openDeadlineS: 5, links: "nope" as never }, () => "ran")).toBe("ran");
    expect(resumeTokens(0)).toEqual([]);
    expect(setRunOutcome("bogus" as never)).toBe(false);
    // runId, openDeadlineS, links, branches and the outcome: five misused arguments.
    expect(RUN_COUNTERS.apiMisuse - before).toBe(5);
    expect(h.markers("run_start")).toHaveLength(1); // only the second block
    expect(h.markers("run_start")[0]!.open_deadline_s).toBeUndefined();
  });

  it("default: an internal failure never reaches the application", () => {
    const h = harness();
    h.table.enter = () => {
      throw new Error("fabric bug");
    };
    expect(run({ runId: "x" }, () => "ran")).toBe("ran");
  });

  it("strict: misuse throws a fixed-text Error before the callback runs", () => {
    harness();
    setStrictModeForTesting(true);
    let calls = 0;
    expect(() => run({ runId: 42 as never }, () => calls++)).toThrow(RunApiMisuse);
    expect(() => run({ runId: "orders/42" }, () => calls++)).toThrow(/runId must match/);
    expect(() => run({ openDeadlineS: 1 }, () => calls++)).toThrow(/openDeadlineS/);
    expect(() => resumeTokens(65)).toThrow(/branches/);
    expect(() => endRun({ outcome: "nope" as never, resume: [] })).toThrow(/outcome/);
    expect(calls).toBe(0);
  });

  it("strict: an internal failure throws fixed text, never the original object", () => {
    const h = harness();
    setStrictModeForTesting(true);
    const secret = new Error("canary-internal-detail");
    h.table.enter = () => {
      throw secret;
    };
    expect(() => run({}, () => 1)).toThrow(
      "fabric run API internal error (FABRIC_RECORDS_STRICT=1)",
    );
  });

  it("the default and strict modes are read from FABRIC_RECORDS_STRICT", () => {
    harness();
    const saved = process.env.FABRIC_RECORDS_STRICT;
    try {
      process.env.FABRIC_RECORDS_STRICT = "1";
      expect(() => resumeTokens(0)).toThrow(RunApiMisuse);
      process.env.FABRIC_RECORDS_STRICT = "0";
      expect(resumeTokens(0)).toEqual([]);
    } finally {
      if (saved === undefined) delete process.env.FABRIC_RECORDS_STRICT;
      else process.env.FABRIC_RECORDS_STRICT = saved;
    }
  });
});

describe("canaries: caller ids, the environment and propagation", () => {
  const CANARY = "canary-7f3e-clear-caller-id";

  it("no clear caller id reaches any marker, seal or token in the pseudonymous mode", () => {
    const h = harness();
    const token = run(
      {
        runId: CANARY,
        sessionId: CANARY + "-session",
        userId: CANARY + "-user",
        parentRunId: CANARY + "-parent",
        resumedFrom: CANARY + "-from",
        links: [CANARY + "-link"],
      },
      () => resumeToken()!,
    );
    endRun({ runId: CANARY, outcome: "completed", resume: token });
    const text = JSON.stringify(h.messages) + token;
    expect(text).not.toContain("canary-7f3e");
    const [root] = h.markers("run_start");
    expect(root).toMatchObject({
      session_id: expect.stringMatching(/^sess-[0-9a-f]{32}$/),
      user_id: expect.stringMatching(/^usr-[0-9a-f]{32}$/),
      parent_run_id: expect.stringMatching(/^r-[0-9a-f]{32}$/),
      resumed_from: expect.stringMatching(/^r-[0-9a-f]{32}$/),
      links: [expect.stringMatching(/^r-[0-9a-f]{32}$/)],
    });
  });

  it("the production profile without a key derives nothing from caller ids", () => {
    const h = harness({ key: undefined, production: true });
    run({ runId: CANARY, sessionId: CANARY, links: [CANARY] }, () => undefined);
    const [root] = h.markers("run_start");
    expect(JSON.stringify(h.messages)).not.toContain("canary-7f3e");
    expect(root!.run_id).toMatch(/^source:s-[0-9a-f]{32}:[0-9]+$/);
    expect(root!.session_id).toBeUndefined();
    expect(root!.links).toBeUndefined();
  });

  it("run() changes no child argv or environment and injects no baggage or header", async () => {
    harness();
    const received: IncomingHttpHeaders[] = [];
    const server = createServer((req, res) => {
      received.push(req.headers);
      res.end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/chat/completions`;
    const call = () => fetch(url, { method: "POST", body: "{}" }).then((r) => r.text());
    const envBefore = { ...process.env };
    const child = () =>
      spawnSync(process.execPath, ["-e", "process.stdout.write(JSON.stringify(process.env))"], {
        encoding: "utf8",
      }).stdout;
    const plain = { headers: (await call(), received.pop()!), env: child() };
    const inside = await run({ runId: CANARY, resumable: true }, async () => {
      resumeToken();
      return { headers: (await call(), received.pop()!), env: child() };
    });
    await new Promise<void>((resolve) => server.close(() => resolve()));
    expect(inside.headers.baggage).toBeUndefined();
    expect(inside.headers).toEqual(plain.headers);
    expect(inside.env).toBe(plain.env);
    expect(inside.env).not.toContain("canary-7f3e");
    expect(inside.env).not.toContain("fr3/");
    expect(process.env).toEqual(envBefore);
  });
});
