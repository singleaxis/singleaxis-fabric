// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The undici hook's correctness rules (spec 055 §3.2, §4.5, §9.5 unit 055-t6): matched-only
 * capture, request identity never retained or leaked, subscriber faults never reaching the
 * application, one owned snapshot per admitted chunk (pooled and subarray buffers reused
 * after the callback), finish-once, and captured bytes equal to the bytes the server
 * received and the application read.
 */
import { channel } from "node:diagnostics_channel";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import type { ExchangeTable } from "../../../src/wire/exchange.js";
import { endpointMatcher } from "../../../src/wire/match.js";
import {
  ERROR_TYPES,
  UNDICI_CHANNELS,
  bundledUndiciPublishesBodies,
  contentEncodingOf,
  errorType,
  installUndiciHook,
  mediaTypeOf,
} from "../../../src/wire/undici.js";
import { drain, isolate } from "../runtime/helpers.js";
import {
  CHAT,
  type Capture,
  PUBLISHES_BODIES,
  type Provider,
  capture,
  prng,
  provider,
  readAll,
  settle,
} from "./helpers.js";

let server: Provider;
const open: Capture[] = [];
beforeAll(async () => {
  server = await provider();
  server.route(CHAT, (_req, res) => res.writeHead(200).end('{"ok":true}'));
});
afterAll(async () => {
  await server.close();
});
afterEach(() => {
  for (const cap of open.splice(0)) cap.close();
});
const track = (cap: Capture): Capture => (open.push(cap), cap);

/** Publishes one undici lifecycle for a request object built by the test. */
const publish = {
  create: (request: object) => channel("undici:request:create").publish({ request }),
  sent: (request: object, chunk: unknown) =>
    channel("undici:request:bodyChunkSent").publish({ request, chunk }),
  bodySent: (request: object) => channel("undici:request:bodySent").publish({ request }),
  headers: (request: object, statusCode = 200, headers: unknown[] = []) =>
    channel("undici:request:headers").publish({ request, response: { statusCode, headers } }),
  received: (request: object, chunk: unknown) =>
    channel("undici:request:bodyChunkReceived").publish({ request, chunk }),
  trailers: (request: object) =>
    channel("undici:request:trailers").publish({ request, trailers: [] }),
  error: (request: object, error: unknown) =>
    channel("undici:request:error").publish({ request, error }),
};

const fakeRequest = (port: number, path = CHAT): object => ({
  method: "POST",
  origin: `http://127.0.0.1:${port}`,
  path,
  headers: ["authorization", "Bearer canary-secret-token", "content-type", "application/json"],
  contentType: "application/json",
});

describe("subscriptions", () => {
  it("are the seven request channels and nothing else; uninstall removes them", () => {
    const before = UNDICI_CHANNELS.map((name) => channel(name).hasSubscribers);
    const cap = capture(1, { publishesBodies: true });
    expect(cap.hook.installed).toBe(true);
    expect(UNDICI_CHANNELS.map((name) => channel(name).hasSubscribers)).toEqual(
      UNDICI_CHANNELS.map(() => true),
    );
    for (const name of ["undici:client:sendHeaders", "undici:client:connected"]) {
      expect(channel(name).hasSubscribers).toBe(false);
    }
    cap.close();
    expect(UNDICI_CHANNELS.map((name) => channel(name).hasSubscribers)).toEqual(before);
  });

  it("the body-publication floor follows the audit (undici 7.11.0)", () => {
    expect(bundledUndiciPublishesBodies("6.29.1")).toBe(false);
    expect(bundledUndiciPublishesBodies("7.10.0")).toBe(false);
    expect(bundledUndiciPublishesBodies("7.11.0")).toBe(true);
    expect(bundledUndiciPublishesBodies("7.30.2")).toBe(true);
    expect(bundledUndiciPublishesBodies("8.0.0")).toBe(true);
    expect(bundledUndiciPublishesBodies("")).toBe(false);
  });
});

describe("matched-only capture", () => {
  it("allocates nothing for a GET, another path, port, host or scheme", () => {
    const cap = track(capture(server.port, { publishesBodies: true }));
    const unmatched = [
      { ...fakeRequest(server.port), method: "GET" },
      fakeRequest(server.port, "/v1/models"),
      fakeRequest(server.port + 1),
      { ...fakeRequest(server.port), origin: `http://localhost:${server.port}` },
      { ...fakeRequest(server.port), origin: `https://127.0.0.1:${server.port}` },
      // The anthropic endpoint has a path prefix; the openai one has no /messages suffix.
      fakeRequest(server.port, "/v1/messages"),
    ];
    for (const request of unmatched) {
      publish.create(request);
      publish.sent(request, Buffer.from("x"));
      publish.headers(request);
      publish.received(request, Buffer.from("y"));
      publish.trailers(request);
    }
    expect(cap.runtime.nextSequence).toBe(0n);
    expect(cap.jobs()).toEqual([]);
    expect(cap.hook.stats.matched).toBe(0);
    // POSTs to a model API path on no configured endpoint are counted (FW-006).
    expect(cap.hook.stats.unmatchedModelShaped).toBe(4);
  });

  it("matches a target named in the path, as sent through an HTTP proxy", () => {
    const cap = track(capture(server.port, { publishesBodies: true }));
    const request = {
      ...fakeRequest(9),
      origin: "http://proxy.internal:3128",
      path: `http://127.0.0.1:${server.port}${CHAT}?q=1`,
    };
    publish.create(request);
    publish.bodySent(request);
    publish.headers(request);
    publish.trailers(request);
    expect(cap.jobs().length).toBe(1);
  });

  it.skipIf(!PUBLISHES_BODIES)("captures a matched fetch and leaves the others alone", async () => {
    const cap = track(capture(server.port));
    server.route("/other", (_req, res) => res.writeHead(200).end("other"));
    expect(await (await fetch(`${server.base}/other`, { method: "POST", body: "a" })).text()).toBe(
      "other",
    );
    expect(await (await fetch(server.base + CHAT)).status).toBe(200); // GET
    expect(await (await fetch(server.base + CHAT, { method: "POST", body: "b" })).text()).toBe(
      '{"ok":true}',
    );
    await settle();
    const jobs = cap.jobs();
    expect(jobs.map((job) => job.requestBytes.toString())).toEqual(["b"]);
    expect(cap.runtime.nextSequence).toBe(1n);
  });
});

describe("request identity", () => {
  it("is never retained: the request object is collected and nothing stays open", async () => {
    setFlagsFromString("--expose-gc");
    const gc = runInNewContext("gc") as () => void;
    const cap = track(capture(server.port, { publishesBodies: true }));
    // A FinalizationRegistry callback, not a WeakRef: V8 keeps a WeakRef's target alive
    // for the rest of the job that created it.
    let collected = false;
    const watch = new FinalizationRegistry<number>(() => (collected = true));
    (() => {
      const request = fakeRequest(server.port);
      watch.register(request, 1);
      publish.create(request);
      publish.bodySent(request);
      publish.headers(request);
      publish.received(request, Buffer.from("done"));
      publish.trailers(request);
    })();
    expect(cap.hook.open).toBe(0);
    for (let i = 0; i < 20 && !collected; i++) {
      await settle(5);
      gc();
    }
    expect(collected).toBe(true);
  });

  it("a request collected unfinished is finished once as abandoned (a notice, not a read)", async () => {
    setFlagsFromString("--expose-gc");
    const gc = runInNewContext("gc") as () => void;
    const cap = track(capture(server.port, { publishesBodies: true }));
    (() => {
      const request = fakeRequest(server.port);
      publish.create(request);
      publish.sent(request, Buffer.from("half"));
    })();
    expect(cap.hook.open).toBe(1);
    for (let i = 0; i < 20 && cap.hook.open > 0; i++) {
      await settle(5);
      gc();
    }
    expect(cap.hook.open).toBe(0);
    expect(cap.hook.stats.collected).toBe(1);
    const [job] = cap.jobs();
    expect(job!.responseState).toBe("abandoned");
    expect(job!.requestBytes.toString()).toBe("half");
  });

  it("never leaks: no URL, host, path, query or header value reaches the job record", () => {
    const cap = track(capture(server.port, { publishesBodies: true }));
    const request = {
      ...fakeRequest(server.port),
      path: `${CHAT}?key=canary-query-value`,
    };
    publish.create(request);
    publish.bodySent(request);
    publish.headers(request, 200, [
      Buffer.from("set-cookie"),
      Buffer.from("canary-cookie"),
      Buffer.from("x-request-id"),
      Buffer.from("canary-request-id"),
    ]);
    publish.trailers(request);
    const raw = drain(cap.table);
    const record = Buffer.from(raw.jobs[0]!.meta).toString("latin1");
    for (const canary of [
      "canary",
      "127.0.0.1",
      String(server.port),
      "chat/completions",
      "authorization",
    ]) {
      expect(record).not.toContain(canary);
    }
  });
});

describe("subscriber faults never reach the application", () => {
  const hostile = (port: number): object[] => {
    const throwing = new Proxy(
      {},
      {
        get: () => {
          throw new Error("canary proxy get");
        },
      },
    );
    const getter = Object.defineProperty({ ...fakeRequest(port) }, "path", {
      get: () => {
        throw new Error("canary getter");
      },
    });
    return [throwing, getter];
  };

  it("malformed and hostile messages are contained and counted", () => {
    const cap = track(capture(server.port, { publishesBodies: true }));
    const uncaught: unknown[] = [];
    const onUncaught = (error: unknown) => uncaught.push(error);
    process.on("uncaughtException", onUncaught);
    try {
      for (const name of UNDICI_CHANNELS) {
        for (const message of [undefined, null, 1, "x", {}, { request: 1 }]) {
          expect(() => channel(name).publish(message)).not.toThrow();
        }
      }
      for (const request of hostile(server.port)) {
        expect(() => publish.create(request)).not.toThrow();
      }
      const request = fakeRequest(server.port);
      publish.create(request);
      publish.headers(request, Number.NaN, [Symbol("x")]);
      publish.received(request, { not: "bytes" });
      publish.error(request, hostile(server.port)[0]);
    } finally {
      process.off("uncaughtException", onUncaught);
    }
    expect(uncaught).toEqual([]);
    expect(cap.hook.stats.faults).toBeGreaterThanOrEqual(1);
    const [job] = cap.jobs();
    // The unreadable chunk makes the response incomplete, never exact.
    expect([job!.response.state, job!.response.reason]).toEqual([
      "truncated",
      "transport_incomplete",
    ]);
  });

  it("unreadable header metadata never leaks a slot: the exchange is still kept and finished", () => {
    const cap = track(capture(server.port, { publishesBodies: true }));
    const throwingArray = (): unknown[] =>
      new Proxy(["content-encoding", "gzip"], {
        get: (target, key) => {
          if (key === "length") return 2;
          if (key === "0" || key === "1") throw new Error("canary header get");
          return Reflect.get(target, key) as unknown;
        },
      });
    const request = { ...fakeRequest(server.port), headers: throwingArray() };
    publish.create(request);
    publish.sent(request, Buffer.from("q"));
    publish.bodySent(request);
    publish.headers(request, 200, throwingArray());
    publish.received(request, Buffer.from("a"));
    publish.trailers(request);
    expect(cap.hook.open).toBe(0);
    expect(cap.hook.stats.faults).toBe(2);
    const [job, ...rest] = cap.jobs();
    expect(rest).toEqual([]);
    expect(job!.requestBytes.toString()).toBe("q");
    expect([job!.response.state, job!.responseBytes.toString()]).toEqual(["exact", "a"]);
    expect(job!.responseState).toBe("complete");
    expect(job!.undici).toMatchObject({
      statusCode: 200,
      requestContentEncoding: "identity",
      responseMediaType: "application/octet-stream",
    });
  });

  it("a scope that throws is counted as not captured, and nothing is allocated", () => {
    const cap = track(
      capture(server.port, {
        publishesBodies: true,
        scope: () => {
          throw new Error("injected scope failure");
        },
      }),
    );
    const request = fakeRequest(server.port);
    publish.create(request);
    publish.trailers(request);
    expect(cap.hook.stats).toMatchObject({ matched: 1, notCaptured: 1, faults: 1 });
    expect(cap.runtime.nextSequence).toBe(0n);
    expect(cap.jobs()).toEqual([]);
  });

  it.skipIf(!PUBLISHES_BODIES)(
    "a runtime that throws everywhere leaves every fetch result unchanged",
    async () => {
      const broken = new Proxy({} as ExchangeTable, {
        get: () => () => {
          throw new Error("injected table failure");
        },
      });
      const hook = installUndiciHook({
        table: broken,
        endpoints: [
          endpointMatcher({
            endpointId: "local",
            dialect: "openai",
            hosts: ["127.0.0.1"],
            schemes: ["http"],
          }),
        ],
        scope: () => {
          throw new Error("injected scope failure");
        },
        parent: () => {
          throw new Error("injected parent failure");
        },
      });
      try {
        for (let i = 0; i < 5; i++) {
          const response = await fetch(server.base + CHAT, { method: "POST", body: `q${i}` });
          expect(await response.text()).toBe('{"ok":true}');
        }
        expect(hook.stats.faults).toBeGreaterThanOrEqual(5);
      } finally {
        hook.uninstall();
      }
    },
  );
});

describe("one owned snapshot per admitted chunk", () => {
  it("pooled and subarray buffers reused after the callback never change the capture", () => {
    const random = prng(0x055_7006);
    const cap = track(capture(server.port, { publishesBodies: true }));
    for (let round = 0; round < 50; round++) {
      // One pooled buffer, reused for every chunk of both sides, as undici's socket
      // buffer and an application's pool are.
      const pool = Buffer.alloc(4096);
      const expected = { request: [] as Buffer[], response: [] as Buffer[] };
      const request = fakeRequest(server.port);
      publish.create(request);
      const chunks = 1 + Math.floor(random() * 12);
      for (const side of ["request", "response"] as const) {
        if (side === "response") {
          publish.bodySent(request);
          publish.headers(request);
        }
        for (let n = 0; n < chunks; n++) {
          const offset = Math.floor(random() * 2048);
          const length = Math.floor(random() * 2048);
          for (let i = 0; i < length; i++) pool[offset + i] = Math.floor(random() * 256);
          const view =
            random() < 0.5
              ? pool.subarray(offset, offset + length)
              : new Uint8Array(pool.buffer, pool.byteOffset + offset, length);
          expected[side].push(Buffer.from(view));
          if (side === "request") publish.sent(request, view);
          else publish.received(request, view);
          pool.fill(round & 0xff); // the caller reuses its buffer at once
        }
      }
      publish.trailers(request);
      const [job] = cap.jobs();
      expect(job!.requestBytes).toEqual(Buffer.concat(expected.request));
      expect(job!.responseBytes).toEqual(Buffer.concat(expected.response));
    }
  });

  it("a SharedArrayBuffer-backed chunk is never claimed exact", () => {
    const cap = track(capture(server.port, { publishesBodies: true }));
    const request = fakeRequest(server.port);
    publish.create(request);
    publish.sent(request, new Uint8Array(new SharedArrayBuffer(8)));
    publish.bodySent(request);
    publish.headers(request);
    publish.trailers(request);
    const [job] = cap.jobs();
    expect([job!.request.state, job!.request.reason]).toEqual([
      "truncated",
      "transport_incomplete",
    ]);
  });

  it("retention stops at the side cap and later chunks are forwarded uncaptured", () => {
    const cap = track(
      capture(server.port, { publishesBodies: true, runtime: { maxRetainBytes: 100 } }),
    );
    const request = fakeRequest(server.port);
    publish.create(request);
    publish.sent(request, Buffer.alloc(60, 1));
    publish.sent(request, Buffer.alloc(60, 2)); // over the cap: retention stops here
    publish.sent(request, Buffer.alloc(10, 3)); // would fit, but never resumes
    publish.bodySent(request);
    publish.headers(request);
    publish.trailers(request);
    const [job] = cap.jobs();
    expect(job!.requestBytes).toEqual(Buffer.alloc(60, 1));
    expect([job!.request.state, job!.request.reason]).toEqual(["truncated", "body_cap"]);
    expect(cap.hook.stats.chunksNotRetained).toBe(2);
  });
});

describe("finish once", () => {
  it("a late error, trailers or uninstall after finish changes nothing", () => {
    const cap = track(capture(server.port, { publishesBodies: true }));
    const request = fakeRequest(server.port);
    publish.create(request);
    publish.bodySent(request);
    publish.headers(request);
    publish.trailers(request);
    publish.error(request, new Error("late"));
    publish.trailers(request);
    cap.close();
    const jobs = cap.jobs();
    expect(jobs.length).toBe(1);
    expect(jobs[0]!.responseState).toBe("complete");
  });

  it("uninstall finishes what is still open as abandoned", () => {
    const cap = capture(server.port, { publishesBodies: true });
    const request = fakeRequest(server.port);
    publish.create(request);
    publish.sent(request, Buffer.from("partial"));
    cap.close();
    const [job] = cap.jobs();
    expect(job!.responseState).toBe("abandoned");
    expect(job!.request.state).toBe("truncated");
  });
});

describe.skipIf(!PUBLISHES_BODIES)(
  "captured bytes equal server-received and application-received",
  () => {
    it("for random bodies, chunkings and response shapes", async () => {
      const random = prng(7);
      const cap = track(capture(server.port));
      const sent: Buffer[] = [];
      let response = Buffer.alloc(0);
      let cuts: number[] = [];
      server.route("/v1/random/chat/completions", (_req, res) => {
        res.writeHead(200, { "content-type": "text/event-stream" });
        let at = 0;
        const next = () => {
          if (cuts.length === 0) return void res.end(response.subarray(at));
          const cut = cuts.shift()!;
          res.write(response.subarray(at, cut));
          at = cut;
          setImmediate(next);
        };
        next();
      });
      const app: Buffer[] = [];
      server.received.length = 0;
      for (let n = 0; n < 25; n++) {
        const body = Buffer.from(
          Array.from({ length: Math.floor(random() * 5000) }, () => random() * 256),
        );
        response = Buffer.from(
          Array.from({ length: 1 + Math.floor(random() * 9000) }, () => random() * 256),
        );
        cuts = [...new Set(Array.from({ length: 4 }, () => Math.floor(random() * response.length)))]
          .filter((c) => c > 0)
          .sort((a, b) => a - b);
        sent.push(body);
        const streamed = random() < 0.5;
        const init: RequestInit & { duplex?: string } = streamed
          ? {
              method: "POST",
              duplex: "half",
              body: new ReadableStream({
                start(controller) {
                  for (let at = 0; at < body.length; at += 777) {
                    controller.enqueue(new Uint8Array(body.subarray(at, at + 777)));
                  }
                  controller.close();
                },
              }),
            }
          : { method: "POST", body };
        app.push(
          Buffer.concat(
            await readAll(await fetch(`${server.base}/v1/random/chat/completions`, init)),
          ),
        );
      }
      await settle();
      const jobs = cap.jobs();
      expect(jobs.length).toBe(25);
      jobs.forEach((job, n) => {
        expect(job.requestBytes).toEqual(server.received[n]);
        expect(job.requestBytes).toEqual(sent[n]);
        expect(job.responseBytes).toEqual(app[n]);
      });
    });
  },
);

describe("metadata rules (Python parity)", () => {
  it.each([
    ["application/json; charset=utf-8", "application/json"],
    ["  Text/Event-Stream ", "text/event-stream"],
    ["application/json, text/plain", "application/octet-stream"],
    ["", "application/octet-stream"],
    ["x".repeat(200) + "/json", "application/octet-stream"],
  ])("media type %j -> %j", (value, expected) => expect(mediaTypeOf(value)).toBe(expected));

  it.each([
    ["GZIP", "gzip"],
    ["gzip, br", "gzip,br"],
    ["", "identity"],
    ["a,b,c,d,e", "unknown"],
    ["gzip;q=1", "unknown"],
  ])("content encoding %j -> %j", (value, expected) =>
    expect(contentEncodingOf(value)).toBe(expected),
  );

  it("error types come from the allowlist, read without running application code", () => {
    let touched = false;
    const sneaky = Object.defineProperty(new Error("m"), "name", {
      get: () => ((touched = true), "AbortError"),
    });
    class CanaryNamedError extends Error {
      override name = "CanaryNamedError";
    }
    const name = (error: unknown) => ERROR_TYPES[errorType(error)];
    expect(name(new DOMException("x", "AbortError"))).toBe("AbortError");
    expect(name(new DOMException("x", "TimeoutError"))).toBe("TimeoutError");
    expect(name(new TypeError("x"))).toBe("TypeError");
    expect(name(Object.assign(new Error("x"), { name: "SocketError" }))).toBe("SocketError");
    expect(name(new CanaryNamedError("x"))).toBe("Error");
    expect(name(sneaky)).toBe("Error");
    // An application abort reason can be a DOMException with its own `name` accessor.
    const sneakyDom = Object.defineProperty(new DOMException("x", "AbortError"), "name", {
      get: () => ((touched = true), "AbortError"),
    });
    expect(name(sneakyDom)).toBe("Error");
    const ownData = Object.defineProperty(new DOMException("x"), "name", {
      value: "canary-name",
    });
    expect(name(ownData)).toBe("Error");
    expect(name(new Proxy(new Error("x"), {}))).toBe("Error");
    expect(name("string reason")).toBe("Error");
    expect(touched).toBe(false);
  });
});

describe("an isolate whose runtime is not running", () => {
  it("refuses capture without touching the request", () => {
    const { runtime, table } = isolate();
    runtime.setState(2);
    const hook = installUndiciHook({
      table,
      publishesBodies: true,
      endpoints: [
        endpointMatcher({
          endpointId: "local",
          dialect: "openai",
          hosts: ["127.0.0.1"],
          schemes: ["http"],
        }),
      ],
    });
    try {
      const request = fakeRequest(server.port);
      publish.create(request);
      publish.trailers(request);
      expect(hook.stats.notCaptured).toBe(1);
      expect(drain(table).jobs).toEqual([]);
    } finally {
      hook.uninstall();
    }
  });
});
