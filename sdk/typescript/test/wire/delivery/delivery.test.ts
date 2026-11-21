// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §3.4 / §7.1 / §9.5 (unit 055-t12): the private delivery clients. The status
 * matrix of every code of §7.1; a batch refused as a whole is resent one record per
 * request; `Retry-After` bounded; no redirect followed; loopback always direct;
 * `FABRIC_WIRE_PROXY` as a CONNECT tunnel with end-to-end certificate verification.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  Backoff,
  BACKOFF_CAP_MS,
  classify,
  DeliveryClient,
  type DeliveryTarget,
  retryAfterMs,
  TraceClient,
} from "../../../src/wire/delivery.js";
import { NodeContentClient } from "../../../src/wire/node-content.js";
import { encodeLogRecord, encodeLogsRequest, type OtlpSpan } from "../../../src/wire/otlp.js";
import {
  recordingSocket,
  type Recorder,
  type Reply,
  scriptedServer,
  testPki,
  type TestPki,
  tunnelProxy,
} from "./helpers.js";

const SERVICE = "svc-test";
const CREDENTIAL = "FWCANARY-ingress-credential-7f3a";
const BODY_CANARY = "FWCANARY-body-91c2";
const AT = "2026-10-07T00:00:01.120000+00:00";

const item = (n: number, text = `${BODY_CANARY}-${n}`) => ({
  descriptor: {
    role: "model.exchange.request",
    object_id: `obj-${n}`,
    captured_at: AT,
    stored_byte_length: text.length,
  },
  body: Buffer.from(text),
});
const target = (url: string, extra: Partial<DeliveryTarget> = {}): DeliveryTarget => ({
  url,
  headers: { authorization: `Bearer ${CREDENTIAL}` },
  timeoutMs: 5000,
  ...extra,
});
const span: OtlpSpan = {
  name: "fabric.model_call",
  traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
  spanId: "a3ce929d0e0e4736",
  kind: "client",
  startNs: 1n,
  endNs: 2n,
  attributes: { "fabric.source.sequence": 1 },
  status: "unset",
  serviceName: SERVICE,
  scope: { name: "fabric.wire", version: "0" },
};

let redirectTarget: Recorder;
beforeAll(async () => {
  redirectTarget = await recordingSocket();
});
afterAll(async () => {
  await redirectTarget.close();
});

/** A server that answers every request with `reply`, and its URL for `signal`. */
async function serving(reply: Reply | ((index: number) => Reply)) {
  const server = await scriptedServer((_r, i) => (typeof reply === "function" ? reply(i) : reply));
  return server;
}

describe("§7.1 outcome classes: the status matrix", () => {
  const MATRIX: [number, "ok" | "retry" | "rejected"][] = [
    [200, "ok"], [201, "ok"], [202, "ok"], [204, "ok"],
    [301, "retry"], [302, "retry"], [303, "retry"], [307, "retry"], [308, "retry"],
    [400, "rejected"], [413, "rejected"], [415, "rejected"], [422, "rejected"],
    [401, "retry"], [403, "retry"], [404, "retry"], [408, "retry"], [429, "retry"],
    [500, "retry"], [502, "retry"], [503, "retry"], [504, "retry"],
  ]; // prettier-ignore

  it.each(MATRIX)("HTTP %i is %s, for content and for traces", async (status, expected) => {
    const location = `${redirectTarget.url}/v1/logs`;
    const server = await serving({
      status,
      headers: status >= 300 && status < 400 ? { location } : {},
    });
    const content = new NodeContentClient(target(`${server.url}/v1/logs`), {
      serviceName: SERVICE,
    });
    const traces = new TraceClient(target(`${server.url}/v1/traces`));
    try {
      expect(await content.send(item(1))).toBe(expected);
      const exported = await traces.export([span]);
      expect(exported.outcome).toBe(expected);
      expect(exported.status).toBe(status);
      // Each request reached the configured Node exactly once; a Location was never followed.
      expect(server.received.map((r) => r.url)).toEqual(["/v1/logs", "/v1/traces"]);
      expect(redirectTarget.connections).toBe(0);
    } finally {
      content.close();
      traces.close();
      await server.close();
    }
  });

  it("a 2xx whose partial_success rejects records is a rejection for content only", async () => {
    const server = await serving({ status: 200, body: Buffer.from("0a020802", "hex") });
    const content = new DeliveryClient(target(`${server.url}/v1/logs`), { signal: "logs" });
    const traces = new DeliveryClient(target(`${server.url}/v1/traces`), { signal: "traces" });
    try {
      expect(await content.post(Buffer.from("x"))).toEqual({
        outcome: "rejected",
        status: 200,
        rejectedRecords: 2n,
      });
      expect(await traces.post(Buffer.from("x"))).toEqual({ outcome: "ok", status: 200 });
    } finally {
      content.close();
      traces.close();
      await server.close();
    }
  });

  it("an unparsable or oversized 2xx body still means accepted", async () => {
    const server = await serving((i) => ({
      status: 200,
      body: i === 0 ? Buffer.from("0aff", "hex") : Buffer.alloc(2 * 1024 * 1024, 0x0a),
    }));
    const client = new DeliveryClient(target(`${server.url}/v1/logs`), { signal: "logs" });
    try {
      expect((await client.post(Buffer.from("x"))).outcome).toBe("ok");
      expect((await client.post(Buffer.from("x"))).outcome).toBe("ok");
    } finally {
      client.close();
      await server.close();
    }
  });

  it("connection refused, reset and timeout are retries, with a fixed code and no message", async () => {
    const closed = await recordingSocket();
    const port = closed.port;
    await closed.close();
    const refused = new DeliveryClient(target(`http://127.0.0.1:${port}/v1/logs`), {
      signal: "logs",
    });
    const reset = await scriptedServer(() => "reset");
    const hang = await scriptedServer(() => "hang");
    const resetClient = new DeliveryClient(target(`${reset.url}/v1/logs`), { signal: "logs" });
    const hangClient = new DeliveryClient(target(`${hang.url}/v1/logs`, { timeoutMs: 200 }), {
      signal: "logs",
    });
    try {
      expect(await refused.post(Buffer.from("x"))).toEqual({
        outcome: "retry",
        status: 0,
        errorCode: "ECONNREFUSED",
      });
      expect(await resetClient.post(Buffer.from("x"))).toMatchObject({
        outcome: "retry",
        status: 0,
      });
      const started = Date.now();
      expect(await hangClient.post(Buffer.from("x"))).toEqual({
        outcome: "retry",
        status: 0,
        errorCode: "timeout",
      });
      expect(Date.now() - started).toBeLessThan(2000);
    } finally {
      refused.close();
      resetClient.close();
      hangClient.close();
      await reset.close();
      await hang.close();
    }
  });

  it("sends the protobuf media type and the ingress headers, and never a proxy header", async () => {
    const server = await serving({ status: 200 });
    const client = new NodeContentClient(
      target(`${server.url}/v1/logs`, {
        headers: { authorization: `Bearer ${CREDENTIAL}`, "content-type": "text/plain" },
      }),
      { serviceName: SERVICE },
    );
    try {
      expect(await client.send(item(1))).toBe("ok");
      const [request] = server.received;
      expect(request!.headers["content-type"]).toBe("application/x-protobuf");
      expect(request!.headers.authorization).toBe(`Bearer ${CREDENTIAL}`);
      expect(request!.headers["proxy-authorization"]).toBeUndefined();
      expect(request!.headers["user-agent"]).toMatch(/^singleaxis-fabric-node\//);
      expect(request!.body.equals(encodeLogsRequest([encodeLogRecord(item(1))], SERVICE))).toBe(
        true,
      );
    } finally {
      client.close();
      await server.close();
    }
  });

  it("compresses trace exports only when the route asks (gzip, deflate)", async () => {
    const { gunzipSync, inflateSync } = await import("node:zlib");
    const server = await serving({ status: 200 });
    const gz = new TraceClient(target(`${server.url}/v1/traces`, { compression: "gzip" }));
    const df = new TraceClient(target(`${server.url}/v1/traces`, { compression: "deflate" }));
    const logs = new DeliveryClient(target(`${server.url}/v1/logs`, { compression: "gzip" }), {
      signal: "logs",
    });
    try {
      await gz.export([span]);
      await df.export([span]);
      await logs.post(Buffer.from("plain"));
      const [a, b, c] = server.received;
      expect(a!.headers["content-encoding"]).toBe("gzip");
      expect(b!.headers["content-encoding"]).toBe("deflate");
      expect(gunzipSync(a!.body).equals(inflateSync(b!.body))).toBe(true);
      expect(c!.headers["content-encoding"]).toBeUndefined();
      expect(c!.body.toString()).toBe("plain");
    } finally {
      gz.close();
      df.close();
      logs.close();
      await server.close();
    }
  });

  it("refuses plaintext to a remote host and a URL carrying credentials, naming the variable", () => {
    expect(
      () =>
        new NodeContentClient(target("http://node.example:4318/v1/logs"), { serviceName: SERVICE }),
    ).toThrow(/FABRIC_WIRE_CONTENT_ENDPOINT requires verified HTTPS or loopback HTTP/);
    expect(() => new TraceClient(target("https://u:p@node.example/v1/traces"))).toThrow(
      /FABRIC_OTLP_ENDPOINT must not carry credentials/,
    );
    expect(classify(299)).toBe("ok");
    expect(classify(200, 1n)).toBe("rejected");
  });
});

describe("§7.1 a batch refused as a whole is resent one record per request", () => {
  it("only the refused record counts as rejected; the others are accepted alone", async () => {
    const server = await scriptedServer((request) => {
      const one = [1, 2, 3].map((n) => encodeLogsRequest([encodeLogRecord(item(n))], SERVICE));
      if (!one.some((b) => b.equals(request.body))) return { status: 413 }; // the batch
      return { status: request.body.equals(one[1]!) ? 400 : 200 };
    });
    const warnings: string[] = [];
    const client = new NodeContentClient(target(`${server.url}/v1/logs`), {
      serviceName: SERVICE,
      warn: (t) => warnings.push(t),
    });
    try {
      expect(await client.sendMany([item(1), item(2), item(3)])).toEqual(["ok", "rejected", "ok"]);
      const bodies = server.received.map((r) => r.body);
      expect(bodies).toHaveLength(4);
      expect(
        bodies[0]!.equals(
          encodeLogsRequest(
            [1, 2, 3].map((n) => encodeLogRecord(item(n))),
            SERVICE,
          ),
        ),
      ).toBe(true);
      expect(bodies.slice(1).map((b) => b.toString("hex"))).toEqual(
        [1, 2, 3].map((n) =>
          encodeLogsRequest([encodeLogRecord(item(n))], SERVICE).toString("hex"),
        ),
      );
      // Class-only warning: the status, never a URL, header or body.
      expect(warnings).toEqual(["fabric.wire: content record rejected by the Node (HTTP 400)"]);
    } finally {
      client.close();
      await server.close();
    }
  });

  it("a 2xx with rejected records also triggers the one-by-one resend", async () => {
    const server = await scriptedServer((_r, i) =>
      i === 0 ? { status: 200, body: Buffer.from("0a020801", "hex") } : { status: 200 },
    );
    const client = new NodeContentClient(target(`${server.url}/v1/logs`), { serviceName: SERVICE });
    try {
      expect(await client.sendMany([item(1), item(2)])).toEqual(["ok", "ok"]);
      expect(server.received).toHaveLength(3);
    } finally {
      client.close();
      await server.close();
    }
  });

  it("a retried batch is never split: every record stays pending", async () => {
    const server = await serving({ status: 503, headers: { "retry-after": "7" } });
    const client = new NodeContentClient(target(`${server.url}/v1/logs`), { serviceName: SERVICE });
    try {
      expect(await client.sendMany([item(1), item(2), item(3)])).toEqual([
        "retry",
        "retry",
        "retry",
      ]);
      expect(server.received).toHaveLength(1);
      expect(client.lastResult?.retryAfterMs).toBe(7000);
    } finally {
      client.close();
      await server.close();
    }
  });

  it("an unencodable record is rejected alone, without a round trip", async () => {
    const server = await serving({ status: 200 });
    const warnings: string[] = [];
    const client = new NodeContentClient(target(`${server.url}/v1/logs`), {
      serviceName: SERVICE,
      warn: (t) => warnings.push(t),
    });
    const bad = { descriptor: { captured_at: "not a time" }, body: Buffer.from(BODY_CANARY) };
    try {
      expect(await client.sendMany([item(1), bad, item(3)])).toEqual(["ok", "rejected", "ok"]);
      expect(server.received).toHaveLength(1);
      expect(
        server.received[0]!.body.equals(
          encodeLogsRequest([encodeLogRecord(item(1)), encodeLogRecord(item(3))], SERVICE),
        ),
      ).toBe(true);
      expect(await client.send(bad)).toBe("rejected");
      expect(warnings).toEqual(
        Array(2).fill("fabric.wire: content record not encodable (OtlpEncodeError)"),
      );
    } finally {
      client.close();
      await server.close();
    }
  });

  it("setting the batch to one record sends one record per request", async () => {
    const server = await serving({ status: 200 });
    const client = new NodeContentClient(target(`${server.url}/v1/logs`), { serviceName: SERVICE });
    try {
      expect(await client.sendMany([item(1)])).toEqual(["ok"]);
      expect(await client.sendMany([])).toEqual([]);
      expect(server.received).toHaveLength(1);
    } finally {
      client.close();
      await server.close();
    }
  });
});

describe("§7.1 Retry-After is bounded", () => {
  it("parses only the delay-seconds form and caps it at 30 s", () => {
    expect(retryAfterMs("5")).toBe(5000);
    expect(retryAfterMs(" 12 ")).toBe(12000);
    expect(retryAfterMs("0")).toBe(0);
    expect(retryAfterMs("9999999")).toBe(BACKOFF_CAP_MS);
    for (const bad of [
      "-1",
      "1.5",
      "Wed, 21 Oct 2026 07:28:00 GMT",
      "",
      "5s",
      undefined,
      ["5", "6"],
    ])
      expect(retryAfterMs(bad as never)).toBeUndefined();
  });

  it("is read from 429 and 5xx answers, never from a redirect", async () => {
    const server = await scriptedServer(
      (_r, i) =>
        (
          [
            { status: 429, headers: { "retry-after": "86400" } },
            { status: 503, headers: { "retry-after": "3" } },
            { status: 301, headers: { "retry-after": "3", location: redirectTarget.url } },
            { status: 500, headers: { "retry-after": "soon" } },
          ] as Reply[]
        )[i]!,
    );
    const client = new DeliveryClient(target(`${server.url}/v1/logs`), { signal: "logs" });
    try {
      expect(await client.post(Buffer.from("x"))).toEqual({
        outcome: "retry",
        status: 429,
        retryAfterMs: BACKOFF_CAP_MS,
      });
      expect(await client.post(Buffer.from("x"))).toEqual({
        outcome: "retry",
        status: 503,
        retryAfterMs: 3000,
      });
      expect(await client.post(Buffer.from("x"))).toEqual({ outcome: "retry", status: 301 });
      expect(await client.post(Buffer.from("x"))).toEqual({ outcome: "retry", status: 500 });
      expect(redirectTarget.connections).toBe(0);
    } finally {
      client.close();
      await server.close();
    }
  });

  it("backoff doubles from 0.5 s to 30 s and honours a bounded hint", () => {
    const backoff = new Backoff();
    expect([1, 2, 3, 4, 5, 6, 7, 8].map(() => backoff.next())).toEqual([
      500, 1000, 2000, 4000, 8000, 16000, 30000, 30000,
    ]);
    backoff.reset();
    expect(backoff.next(5000)).toBe(5000);
    expect(backoff.next(10 ** 9)).toBe(BACKOFF_CAP_MS);
    expect(backoff.next(-5)).toBe(2000);
  });
});

describe("§3.4 proxies: loopback always direct; FABRIC_WIRE_PROXY is a verified CONNECT tunnel", () => {
  let pki: TestPki;
  beforeAll(() => {
    pki = testPki(["fabric-node.test", "localhost"]);
  });
  afterAll(() => pki.cleanup());

  it("ignores HTTP_PROXY, HTTPS_PROXY, ALL_PROXY and NO_PROXY", async () => {
    const hostile = await recordingSocket();
    const server = await serving({ status: 200 });
    const saved = { ...process.env };
    Object.assign(process.env, {
      HTTP_PROXY: hostile.url,
      HTTPS_PROXY: hostile.url,
      ALL_PROXY: hostile.url,
      http_proxy: hostile.url,
      https_proxy: hostile.url,
      NO_PROXY: "",
    });
    const client = new NodeContentClient(target(`${server.url}/v1/logs`), { serviceName: SERVICE });
    try {
      expect(await client.send(item(1))).toBe("ok");
      expect(hostile.connections).toBe(0);
    } finally {
      process.env = saved;
      client.close();
      await server.close();
      await hostile.close();
    }
  });

  it.each(["http", "https"])(
    "a loopback %s endpoint is reached directly even with FABRIC_WIRE_PROXY",
    async (scheme) => {
      const proxy = await tunnelProxy(1);
      const server = await scriptedServer(
        () => ({ status: 200 }),
        scheme === "https" ? { cert: pki.cert, key: pki.key } : undefined,
      );
      const url =
        scheme === "https" ? `https://localhost:${server.port}/v1/logs` : `${server.url}/v1/logs`;
      const client = new NodeContentClient(target(url, { certificate: pki.caFile }), {
        serviceName: SERVICE,
        proxy: proxy.url,
      });
      try {
        expect(client.proxied).toBe(false);
        expect(await client.send(item(1))).toBe("ok");
        expect(server.received).toHaveLength(1);
        expect(proxy.connects).toHaveLength(0);
        expect(proxy.plain).toHaveLength(0);
      } finally {
        client.close();
        await server.close();
        await proxy.close();
      }
    },
  );

  it.each(["http", "https"])(
    "tunnels a remote endpoint through an %s proxy, verifying the Node end to end",
    async (proxyScheme) => {
      const server = await scriptedServer(() => ({ status: 200 }), {
        cert: pki.cert,
        key: pki.key,
      });
      const proxy = await tunnelProxy(
        server.port,
        proxyScheme === "https" ? { tls: { cert: pki.cert, key: pki.key } } : {},
      );
      const proxyUrl = proxy.url.replace("://", "://fab%40user:s3cr%3At@");
      const content = new NodeContentClient(
        target(`https://fabric-node.test:${server.port}/v1/logs`, { certificate: pki.caFile }),
        {
          serviceName: SERVICE,
          proxy: proxyUrl,
        },
      );
      const traces = new TraceClient(
        target(`https://fabric-node.test:${server.port}/v1/traces`, { certificate: pki.caFile }),
        { proxy: proxyUrl },
      );
      try {
        expect(content.proxied).toBe(true);
        expect(await content.send(item(1))).toBe("ok");
        expect(await content.send(item(2))).toBe("ok");
        expect((await traces.export([span])).outcome).toBe("ok");
        // Keep-alive: the content client reused its tunnel; the trace client opened its own.
        expect(proxy.connects.map((c) => c.target)).toEqual([
          `fabric-node.test:${server.port}`,
          `fabric-node.test:${server.port}`,
        ]);
        // Proxy credentials go only to the proxy, on the CONNECT.
        const basic = `Basic ${Buffer.from("fab@user:s3cr:t").toString("base64")}`;
        expect(proxy.connects.every((c) => c.headers["proxy-authorization"] === basic)).toBe(true);
        expect(proxy.plain).toHaveLength(0);
        // The Node got the ingress credential and the body, and no proxy credential.
        expect(server.received).toHaveLength(3);
        for (const request of server.received) {
          expect(request.headers.authorization).toBe(`Bearer ${CREDENTIAL}`);
          expect(request.headers["proxy-authorization"]).toBeUndefined();
        }
        // The proxy saw only TLS records: no credential, no body byte in the clear.
        const seen = proxy.tunnelled().toString("latin1");
        expect(seen.length).toBeGreaterThan(0);
        expect(seen).not.toContain(CREDENTIAL);
        expect(seen).not.toContain(BODY_CANARY);
        expect(seen).not.toContain("/v1/logs");
      } finally {
        content.close();
        traces.close();
        await server.close();
        await proxy.close();
      }
    },
  );

  it("the Node's client certificate goes only to the Node, never to an https proxy", async () => {
    const certFile = `${pki.dir}/server.pem`;
    const keyFile = `${pki.dir}/server.key`;
    const server = await scriptedServer(() => ({ status: 200 }), { cert: pki.cert, key: pki.key });
    const proxy = await tunnelProxy(server.port, { tls: { cert: pki.cert, key: pki.key } });
    // a malformed escape in the proxy's user info is sent as written, never a throw
    const proxyUrl = proxy.url.replace("://", "://user%zz:pw@");
    const client = new DeliveryClient(
      target(`https://fabric-node.test:${server.port}/v1/logs`, {
        certificate: pki.caFile,
        clientCertificate: certFile,
        clientKey: keyFile,
      }),
      { signal: "logs", proxy: proxyUrl },
    );
    try {
      expect(await client.post(Buffer.from("x"))).toEqual({ outcome: "ok", status: 200 });
      expect(server.clientCertificates).toEqual([true]);
      expect(proxy.clientCertificates).toEqual([false]);
      expect(proxy.connects[0]!.headers["proxy-authorization"]).toBe(
        `Basic ${Buffer.from("user%zz:pw").toString("base64")}`,
      );
    } finally {
      client.close();
      await server.close();
      await proxy.close();
    }
  });

  it("an untrusted or misnamed Node certificate behind the tunnel is a retry; nothing is sent", async () => {
    const rogue = await scriptedServer(() => ({ status: 200 }), {
      cert: pki.rogueCert,
      key: pki.rogueKey,
    });
    const genuine = await scriptedServer(() => ({ status: 200 }), { cert: pki.cert, key: pki.key });
    const viaRogue = await tunnelProxy(rogue.port);
    const viaGenuine = await tunnelProxy(genuine.port);
    // trusted CA, but the name is not on the certificate
    const misnamed = new DeliveryClient(
      target(`https://other-node.test:${genuine.port}/v1/logs`, { certificate: pki.caFile }),
      { signal: "logs", proxy: viaGenuine.url },
    );
    const untrusted = new DeliveryClient(
      target(`https://fabric-node.test:${rogue.port}/v1/logs`, { certificate: pki.caFile }),
      { signal: "logs", proxy: viaRogue.url },
    );
    // no CA configured: the default trust store does not know the test CA
    const defaultTrust = new DeliveryClient(
      target(`https://fabric-node.test:${genuine.port}/v1/logs`),
      { signal: "logs", proxy: viaGenuine.url },
    );
    try {
      for (const client of [misnamed, untrusted, defaultTrust]) {
        const result = await client.post(Buffer.from(BODY_CANARY));
        expect(result.outcome).toBe("retry");
        expect(result.status).toBe(0);
        expect(result.errorCode).toMatch(/^[A-Z_]+$/);
      }
      expect(rogue.received).toHaveLength(0);
      expect(genuine.received).toHaveLength(0);
      for (const proxy of [viaRogue, viaGenuine])
        expect(proxy.tunnelled().toString("latin1")).not.toContain(BODY_CANARY);
    } finally {
      for (const c of [misnamed, untrusted, defaultTrust]) c.close();
      for (const s of [rogue, genuine, viaRogue, viaGenuine]) await s.close();
    }
  });

  it("a proxy that refuses the tunnel is a retry; the Node credential never reaches it", async () => {
    const proxy = await tunnelProxy(1, { refuse: true });
    const client = new DeliveryClient(
      target("https://fabric-node.test:4318/v1/logs", { certificate: pki.caFile }),
      { signal: "logs", proxy: proxy.url },
    );
    try {
      expect(await client.post(Buffer.from(BODY_CANARY))).toEqual({
        outcome: "retry",
        status: 0,
        errorCode: "proxy_refused",
      });
      expect(proxy.connects).toHaveLength(1);
      expect(JSON.stringify(proxy.connects)).not.toContain(CREDENTIAL);
    } finally {
      client.close();
      await proxy.close();
    }
  });
});
