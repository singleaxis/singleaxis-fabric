// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Byte fixtures of the undici hook (spec 055 §9.5, unit 055-t6): real global `fetch`
 * calls to a scripted loopback provider. For each shape the captured request bytes equal
 * what the server received, the captured response bytes equal what was on the wire (the
 * publication sits before decompression on every audited build), and the application
 * reads exactly what it would read with no hook.
 */
import { brotliCompressSync, deflateSync, gzipSync } from "node:zlib";

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  CHAT,
  type Capture,
  MESSAGES,
  PUBLISHES_BODIES,
  type Provider,
  capture,
  provider,
  readAll,
  settle,
} from "./helpers.js";

const REQUEST = JSON.stringify({
  model: "m",
  messages: [{ role: "user", content: "héllo ✓ \r\n tool" }],
});
const RESPONSE = JSON.stringify({ id: "r", choices: [{ message: { content: "wörld ✓" } }] });
// SSE with a multi-byte character, CRLF and LF line ends, a comment and multiline data.
const SSE = Buffer.from(
  ': keep-alive\r\n\r\ndata: {"delta":"é✓"}\r\n\r\nevent: x\ndata: a\ndata: b\n\ndata: [DONE]\n\n',
  "utf8",
);

let server: Provider;
let cap: Capture;
beforeAll(async () => {
  server = await provider();
});
afterAll(async () => {
  await server.close();
});
beforeEach(() => {
  cap?.close();
  cap = capture(server.port);
  server.received.length = 0;
});

const post = (path: string, init: RequestInit = {}): Promise<Response> =>
  fetch(server.base + path, { method: "POST", body: REQUEST, ...init });

describe.skipIf(!PUBLISHES_BODIES)("byte fixtures", () => {
  it("JSON: request, response and metadata are exact; the app reads the same bytes", async () => {
    server.route(CHAT, (_req, res) => {
      res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
      res.end(RESPONSE);
    });
    const response = await post(`${CHAT}?api-version=1`, {
      headers: { "content-type": "application/json" },
    });
    const app = Buffer.concat(await readAll(response));
    await settle();
    const [job, ...rest] = cap.jobs();
    expect(rest).toEqual([]);
    expect(job!.request.state).toBe("exact");
    expect(job!.requestBytes).toEqual(server.received[0]);
    expect(job!.requestBytes.toString("utf8")).toBe(REQUEST);
    expect(job!.response.state).toBe("exact");
    expect(job!.responseBytes).toEqual(app);
    expect(app.toString("utf8")).toBe(RESPONSE);
    expect(job!.responseState).toBe("complete");
    const meta = job!.undici;
    expect(meta).toMatchObject({
      endpointIndex: 0,
      api: "openai.chat_completions",
      statusCode: 200,
      errorType: undefined,
      requestSent: true,
      requestMediaType: "application/json",
      requestContentEncoding: "identity",
      responseMediaType: "application/json",
      responseContentEncoding: "identity",
      providerRequestId: undefined,
    });
    expect(meta.firstChunkOffsetNs! >= meta.headersOffsetNs!).toBe(true);
    expect(meta.endOffsetNs >= meta.firstChunkOffsetNs!).toBe(true);
    expect(job!.sequence).toBe(0n);
  });

  it("anthropic Messages on its own endpoint, with the C40 request id only when enabled", async () => {
    server.route(`/anthropic${MESSAGES}`, (_req, res) => {
      res.writeHead(200, { "content-type": "application/json", "request-id": "req_01abc" });
      res.end(RESPONSE);
    });
    await (await post(`/anthropic${MESSAGES}`)).text();
    cap.close();
    cap = capture(server.port, { providerRequestId: true });
    await (await post(`/anthropic${MESSAGES}`)).text();
    await settle();
    const [job] = cap.jobs();
    expect(job!.undici).toMatchObject({
      endpointIndex: 1,
      api: "anthropic.messages",
      providerRequestId: "req_01abc",
    });
  });

  it("SSE split at every byte boundary is captured whole and read unchanged", async () => {
    let split = 0;
    server.route(CHAT, (_req, res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write(SSE.subarray(0, split));
      setImmediate(() => res.end(SSE.subarray(split)));
    });
    for (split = 1; split < SSE.length; split++) {
      const app = Buffer.concat(await readAll(await post(CHAT)));
      expect(app).toEqual(SSE);
    }
    await settle();
    const jobs = cap.jobs();
    expect(jobs.length).toBe(SSE.length - 1);
    for (const job of jobs) {
      expect(job.responseBytes).toEqual(SSE);
      expect(job.response.state).toBe("exact");
      expect(job.undici.responseMediaType).toBe("text/event-stream");
      expect(job.responseState).toBe("complete");
    }
    expect(new Set(jobs.map((job) => job.sequence)).size).toBe(jobs.length);
  });

  it.each([
    ["gzip", gzipSync],
    ["deflate", deflateSync],
    ["br", brotliCompressSync],
  ])("%s: the compressed wire bytes are kept with their encoding", async (encoding, compress) => {
    const wire = compress(Buffer.from(RESPONSE));
    server.route(CHAT, (_req, res) => {
      res.writeHead(200, { "content-type": "application/json", "content-encoding": encoding });
      res.write(wire.subarray(0, 7));
      res.end(wire.subarray(7));
    });
    const app = await (await post(CHAT)).text();
    await settle();
    const [job] = cap.jobs();
    expect(app).toBe(RESPONSE);
    // boundary pre_decompression (wire-qualification.json): never a fabricated digest.
    expect(job!.responseBytes).toEqual(wire);
    expect(job!.undici.responseContentEncoding).toBe(encoding);
  });

  it("zero-byte request and response bodies are exact and empty, not absent", async () => {
    server.route(CHAT, (_req, res) => res.writeHead(200, { "content-length": "0" }).end());
    const empty = await fetch(server.base + CHAT, { method: "POST" });
    expect(await empty.arrayBuffer()).toEqual(new ArrayBuffer(0));
    await (await post(CHAT, { body: "" })).arrayBuffer();
    await settle();
    const jobs = cap.jobs();
    expect(jobs.length).toBe(2);
    for (const job of jobs) {
      expect([job.request.state, job.request.byteLength]).toEqual(["exact", 0]);
      expect([job.response.state, job.response.byteLength]).toEqual(["exact", 0]);
      expect(job.responseState).toBe("complete");
    }
  });

  it("early close by the server keeps the received prefix and finishes as error", async () => {
    server.route(CHAT, (req, res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write(SSE.subarray(0, 10));
      setTimeout(() => req.socket.destroy(), 10);
    });
    const response = await post(CHAT);
    const read: Buffer[] = [];
    await expect(
      (async () => {
        for await (const chunk of response.body!) read.push(Buffer.from(chunk));
      })(),
    ).rejects.toBeInstanceOf(TypeError);
    await settle();
    const [job] = cap.jobs();
    expect(job!.responseBytes).toEqual(Buffer.concat(read));
    expect(job!.responseState).toBe("error");
    expect(job!.undici.errorType).toBe("SocketError");
  });

  it("early close by the application (reader cancel) finishes as closed_early", async () => {
    server.route(CHAT, (_req, res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write(SSE.subarray(0, 12));
    });
    const reader = (await post(CHAT)).body!.getReader();
    const first = Buffer.from((await reader.read()).value!);
    await reader.cancel();
    await settle();
    const [job] = cap.jobs();
    expect(job!.responseBytes).toEqual(first);
    expect(job!.responseState).toBe("closed_early");
    expect(job!.undici.errorType).toBe("AbortError");
  });

  describe("abort at three points", () => {
    it("before headers: no response side, closed_early, the app's reason rejects as itself", async () => {
      server.route(CHAT, () => undefined); // never answers
      const controller = new AbortController();
      const reason = { why: "user" };
      const pending = post(CHAT, { signal: controller.signal });
      await settle(30);
      controller.abort(reason);
      await expect(pending).rejects.toBe(reason);
      await settle();
      const [job] = cap.jobs();
      expect(job!.response.state).toBe("absent");
      expect(job!.request.state).toBe("exact");
      expect(job!.responseState).toBe("error");
      // A non-error abort reason is never named: `Error`, not its class or content.
      expect(job!.undici.errorType).toBe("Error");
      expect(job!.undici.statusCode).toBeUndefined();
    });

    it("mid-body: the received prefix, closed_early", async () => {
      server.route(CHAT, (_req, res) => {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write(SSE.subarray(0, 20));
      });
      const controller = new AbortController();
      const reader = (await post(CHAT, { signal: controller.signal })).body!.getReader();
      const first = Buffer.from((await reader.read()).value!);
      controller.abort();
      await expect(reader.read()).rejects.toMatchObject({ name: "AbortError" });
      await settle();
      const [job] = cap.jobs();
      expect(job!.responseBytes).toEqual(first);
      expect([job!.responseState, job!.undici.errorType]).toEqual(["closed_early", "AbortError"]);
    });

    it("after completion: nothing changes", async () => {
      server.route(CHAT, (_req, res) => res.writeHead(200).end(RESPONSE));
      const controller = new AbortController();
      const text = await (await post(CHAT, { signal: controller.signal })).text();
      controller.abort();
      await settle();
      const [job, ...rest] = cap.jobs();
      expect(rest).toEqual([]);
      expect(job!.responseBytes.toString()).toBe(text);
      expect([job!.responseState, job!.undici.errorType]).toEqual(["complete", undefined]);
    });
  });

  it("a transport error before headers: no response, error, the request is kept", async () => {
    server.route(CHAT, (req) => req.socket.destroy());
    await expect(post(CHAT)).rejects.toBeInstanceOf(TypeError);
    await settle();
    const [job] = cap.jobs();
    expect(job!.response.state).toBe("absent");
    expect(job!.responseState).toBe("error");
    expect(job!.requestBytes.toString()).toBe(REQUEST);
    expect(job!.undici.errorType).toBe("SocketError");
  });

  it("a request body that was not sent whole is truncated(transport_incomplete)", async () => {
    server.early("/v1/cut/chat/completions", (req) => setTimeout(() => req.socket.destroy(), 5));
    let pull = 0;
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (pull++ < 50) {
          controller.enqueue(new TextEncoder().encode("part,"));
          await settle(2);
        } else controller.close();
      },
    });
    await expect(
      post("/v1/cut/chat/completions", { body, duplex: "half" } as RequestInit),
    ).rejects.toThrow();
    await settle();
    const [job] = cap.jobs();
    expect(job!.undici.requestSent).toBe(false);
    expect([job!.request.state, job!.request.reason]).toEqual([
      "truncated",
      "transport_incomplete",
    ]);
  });

  it("a redirect: each hop is its own exchange; an unmatched hop is not captured", async () => {
    const other = await provider();
    try {
      other.route(CHAT, (_req, res) => res.writeHead(200).end("other"));
      server.route("/hop", (_req, res) => res.writeHead(307, { location: CHAT }).end("moved"));
      server.route(CHAT, (_req, res) => res.writeHead(200).end(RESPONSE));
      server.route("/v1/away/chat/completions", (_req, res) =>
        res.writeHead(307, { location: other.base + CHAT }).end(),
      );
      // /hop is not a model path: only the second hop matches.
      expect(await (await post("/hop")).text()).toBe(RESPONSE);
      expect(await (await post("/v1/away/chat/completions")).text()).toBe("other");
      server.route("/v1/first/chat/completions", (_req, res) =>
        res.writeHead(307, { location: CHAT }).end("moved"),
      );
      expect(await (await post("/v1/first/chat/completions")).text()).toBe(RESPONSE);
      await settle();
      const jobs = cap.jobs();
      expect(jobs.map((job) => job.undici.statusCode)).toEqual([200, 307, 307, 200]);
      // A 307 resends the body: each hop's request equals what that hop received.
      expect(jobs.every((job) => job.requestBytes.toString() === REQUEST)).toBe(true);
      expect(jobs[2]!.responseBytes.toString()).toBe("moved");
      expect(other.received.length).toBe(1); // reached, but never captured
    } finally {
      await other.close();
    }
  });

  it("an informational response does not finish the exchange", async () => {
    server.route(CHAT, (_req, res) => {
      res.writeEarlyHints({ link: "</a>; rel=preload" });
      setTimeout(() => res.writeHead(200, { "content-type": "application/json" }).end(RESPONSE), 5);
    });
    expect(await (await post(CHAT)).text()).toBe(RESPONSE);
    await settle();
    const [job, ...rest] = cap.jobs();
    expect(rest).toEqual([]);
    expect(job!.undici).toMatchObject({ statusCode: 200, informational: 1 });
    expect(job!.responseBytes.toString()).toBe(RESPONSE);
    expect(cap.hook.stats.informational).toBe(1);
  });
});

describe.skipIf(PUBLISHES_BODIES)("a Node build without body publications", () => {
  it("subscribes nothing, so no empty body can be recorded as exact", async () => {
    server.route(CHAT, (_req, res) => res.writeHead(200).end(RESPONSE));
    expect(cap.hook.installed).toBe(false);
    expect(await (await post(CHAT)).text()).toBe(RESPONSE);
    await settle();
    expect(cap.jobs()).toEqual([]);
    expect(cap.runtime.nextSequence).toBe(0n);
  });
});
