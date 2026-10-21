// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The redaction service client (spec 049 §7.7, contracts/redaction/v1): protocol,
 * failure semantics, bounds, privacy canaries and passivity.
 */
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ByteEvidenceRecorder,
  ContentProtector,
  DeploymentPolicy,
  LocalFilesystemContentStore,
  RedactionClient,
  parseRedactionEndpoint,
  redactionServiceFromEnv,
  type DeploymentPolicyData,
  type PrivacyMode,
} from "../src/index.js";
import { hang, mask, startService, status, type Handler } from "./redaction-service.js";

const ROOT = path.resolve(import.meta.dirname, "../../..");
const CANARY = Buffer.from("canary-4c1d-patient-jane-doe");
const CANARY_SHA = createHash("sha256").update(CANARY).digest("hex");
const T = { id: "mask-email", version: "3" };
const REQUEST = { transformation: T, role: "terminal.stdout", mode: "redact" as const };
const cleanup: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  for (const step of cleanup.splice(0).reverse()) await step();
});

async function service(handler: Handler, kind: "unix" | "http" = "unix") {
  const started = await startService(handler, kind);
  cleanup.push(() => started.close());
  return started;
}
function client(endpoint: string, options: Record<string, unknown> = {}, maxOutputBytes = 1024) {
  const created = new RedactionClient({ endpoint, ...options }, { maxOutputBytes });
  cleanup.push(() => created.close());
  return created;
}
function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "frt-"));
  cleanup.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

describe("endpoint configuration", () => {
  it.each([
    "unix:///run/fabric/redaction.sock",
    "http://127.0.0.1:8181",
    "http://127.0.0.1:8181/",
    "http://[::1]:1",
    "http://127.0.0.1:65535",
  ])("accepts %s", (endpoint) => {
    expect(() => parseRedactionEndpoint(endpoint)).not.toThrow();
  });
  it.each([
    "https://127.0.0.1:8181",
    "http://localhost:8181",
    "http://10.0.0.5:8181",
    "http://127.0.0.2:8181",
    "http://127.0.0.1",
    "http://127.0.0.1:0",
    "http://127.0.0.1:65536",
    "http://127.0.0.1:8181/v1/transform",
    "http://127.0.0.1:8181?x=1",
    "http://127.0.0.1:8181#x",
    "http://user:pw@127.0.0.1:8181",
    "unix://relative/path.sock",
    "unix://",
    "unix:///",
    "/run/fabric/redaction.sock",
    "",
  ])("rejects %s with fixed text", (endpoint) => {
    let message = "";
    try {
      parseRedactionEndpoint(endpoint);
    } catch (error) {
      message = (error as Error).message;
    }
    // one fixed text, whatever the value: it is never echoed
    expect(message).toBe(
      "FABRIC_REDACTION_ENDPOINT must be unix:///absolute/path or http://127.0.0.1:<port> " +
        "or http://[::1]:<port>",
    );
  });
  it("reads FABRIC_REDACTION_ENDPOINT and fails construction on a malformed one", () => {
    expect(redactionServiceFromEnv({})).toBeUndefined();
    expect(redactionServiceFromEnv({ FABRIC_REDACTION_ENDPOINT: "http://[::1]:9" })).toEqual({
      endpoint: "http://[::1]:9",
    });
    expect(() => redactionServiceFromEnv({ FABRIC_REDACTION_TOKEN_FILE: "/x" })).toThrow(
      "needs FABRIC_REDACTION_ENDPOINT",
    );
    vi.stubEnv("FABRIC_REDACTION_ENDPOINT", "http://203.0.113.9:80");
    const data = JSON.parse(
      fs.readFileSync(path.join(ROOT, "examples/enterprise/policy.local.json"), "utf8"),
    ) as DeploymentPolicyData;
    expect(() => new ContentProtector(DeploymentPolicy.fromDict(data))).toThrow(
      "FABRIC_REDACTION_ENDPOINT must be",
    );
  });
  it("bounds the timeout and in-flight settings", () => {
    for (const bad of [{ timeoutMs: 0 }, { timeoutMs: 300_001 }, { maxInFlight: 0 }])
      expect(() => client("http://127.0.0.1:9", bad)).toThrow();
    expect(client("http://127.0.0.1:9", { timeoutMs: 300_000 }).timeoutMs).toBe(300_000);
  });
});

describe("the protocol", () => {
  it.each(["unix", "http"] as const)(
    "posts the raw bytes and returns the body (%s)",
    async (kind) => {
      const svc = await service(mask, kind);
      const out = await client(svc.endpoint).transform(CANARY, REQUEST);
      expect(Buffer.from(out!).toString()).toBe("[redacted]");
      const [request] = svc.requests;
      expect(request!.method).toBe("POST");
      expect(request!.url).toBe("/v1/transform");
      expect(request!.body.equals(CANARY)).toBe(true);
      expect(request!.headers).toMatchObject({
        "content-type": "application/octet-stream",
        "content-length": String(CANARY.length),
        "x-fabric-transformation": "mask-email",
        "x-fabric-transformation-version": "3",
        "x-fabric-role": "terminal.stdout",
        "x-fabric-mode": "redact",
      });
      expect(request!.headers.authorization).toBeUndefined();
      if (kind === "unix") expect(request!.headers.host).toBe("localhost");
    },
  );
  it("reuses one connection across calls", async () => {
    const ports = new Set<number | undefined>();
    const svc = await service((req, body, res) => {
      ports.add(req.socket.remotePort);
      mask(req, body, res);
    }, "http");
    const used = client(svc.endpoint);
    for (let i = 0; i < 3; i += 1) expect(await used.transform(CANARY, REQUEST)).not.toBeNull();
    expect(ports.size).toBe(1);
  });
  it("retries once when a pooled connection closes before any answer", async () => {
    let calls = 0;
    const svc = await service((req, body, res) => {
      calls += 1;
      if (calls === 2)
        req.socket.destroy(); // the reused connection dies unanswered
      else mask(req, body, res);
    }, "http");
    const used = client(svc.endpoint);
    expect(await used.transform(CANARY, REQUEST)).not.toBeNull();
    expect(Buffer.from((await used.transform(CANARY, REQUEST))!).toString()).toBe("[redacted]");
    expect(calls).toBe(3);
    expect(used.stats().redaction_failures).toBe(0);
  });
  it("accepts an empty transformed body and chunked framing", async () => {
    const svc = await service((_req, _body, res) => {
      res.writeHead(200, { "Content-Type": "application/octet-stream" });
      res.write("[mas");
      res.end("ked]");
    });
    expect(Buffer.from((await client(svc.endpoint).transform(CANARY, REQUEST))!).toString()).toBe(
      "[masked]",
    );
    const empty = await service((_req, _body, res) => {
      res.writeHead(200);
      res.end();
    });
    expect((await client(empty.endpoint).transform(CANARY, REQUEST))!.byteLength).toBe(0);
  });
  it("sends the bearer token from an owner-only file and refuses a readable one", async () => {
    const svc = await service(mask);
    const dir = tempDir();
    const file = path.join(dir, "token");
    fs.writeFileSync(file, "s3cr3t-token\n", { mode: 0o644 });
    fs.chmodSync(file, 0o644);
    let message = "";
    try {
      client(svc.endpoint, { tokenFile: file });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("mode 0600");
    expect(message).not.toContain("s3cr3t");
    expect(message).not.toContain(file);
    fs.chmodSync(file, 0o600);
    expect(
      await client(svc.endpoint, { tokenFile: file }).transform(CANARY, REQUEST),
    ).not.toBeNull();
    expect(svc.requests[0]!.headers.authorization).toBe("Bearer s3cr3t-token");
    const link = path.join(dir, "link");
    fs.symlinkSync(file, link);
    expect(() => client(svc.endpoint, { tokenFile: link })).toThrow("not readable");
    expect(() => client(svc.endpoint, { tokenFile: dir })).toThrow();
    const empty = path.join(dir, "empty");
    fs.writeFileSync(empty, "\n", { mode: 0o600 });
    expect(() => client(svc.endpoint, { tokenFile: empty })).toThrow("printable ASCII");
  });
});

describe("failures resolve to null and are counted", () => {
  it.each([
    ["an error status", status(500)],
    ["a redirect", status(307, { Location: "http://127.0.0.1:1/v1/transform" })],
    ["a 204", status(204)],
  ] as const)("%s", async (_name, handler) => {
    const svc = await service(handler);
    const used = client(svc.endpoint);
    expect(await used.transform(CANARY, REQUEST)).toBeNull();
    expect(used.stats()).toEqual({
      redaction_timeouts: 0,
      redaction_saturated: 0,
      redaction_failures: 1,
    });
    expect(svc.requests).toHaveLength(1); // a redirect is never followed
  });
  it("an oversized response", async () => {
    const svc = await service((_req, _body, res) => {
      res.writeHead(200);
      res.write(Buffer.alloc(600, 1));
      res.end(Buffer.alloc(600, 1));
    });
    const used = client(svc.endpoint, {}, 1024);
    expect(await used.transform(CANARY, REQUEST)).toBeNull();
    expect(used.stats().redaction_failures).toBe(1);
  });
  it("a service that never answers: the hard timeout", async () => {
    const svc = await service(hang);
    const used = client(svc.endpoint, { timeoutMs: 100 });
    const start = Date.now();
    expect(await used.transform(CANARY, REQUEST)).toBeNull();
    expect(Date.now() - start).toBeLessThan(2_000);
    expect(used.stats()).toMatchObject({ redaction_timeouts: 1, redaction_failures: 0 });
  });
  it("a body that trickles past the timeout", async () => {
    const svc = await service((_req, _body, res) => {
      res.writeHead(200);
      let open = true;
      res.on("close", () => (open = false));
      const trickle = () => {
        if (!open) return;
        res.write("x");
        setTimeout(trickle, 20);
      };
      trickle();
    });
    const used = client(svc.endpoint, { timeoutMs: 150 });
    expect(await used.transform(CANARY, REQUEST)).toBeNull();
    expect(used.stats().redaction_timeouts).toBe(1);
  });
  it("connection refused and a missing socket", async () => {
    const probe = net.createServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
    const port = (probe.address() as net.AddressInfo).port;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const refused = client(`http://127.0.0.1:${port}`);
    expect(await refused.transform(CANARY, REQUEST)).toBeNull();
    const missing = client("unix://" + path.join(tempDir(), "absent.sock"));
    expect(await missing.transform(CANARY, REQUEST)).toBeNull();
    expect(refused.stats().redaction_failures + missing.stats().redaction_failures).toBe(2);
  });
  it("saturation: a call above the in-flight bound fails at once", async () => {
    const svc = await service(hang);
    const used = client(svc.endpoint, { timeoutMs: 300, maxInFlight: 1 });
    const first = used.transform(CANARY, REQUEST);
    const start = Date.now();
    expect(await used.transform(CANARY, REQUEST)).toBeNull();
    expect(Date.now() - start).toBeLessThan(50);
    expect(await first).toBeNull();
    expect(used.stats()).toEqual({
      redaction_timeouts: 1,
      redaction_saturated: 1,
      redaction_failures: 0,
    });
    // the bound is released: a later call is attempted again
    expect(await used.transform(CANARY, REQUEST)).toBeNull();
    expect(used.stats().redaction_timeouts).toBe(2);
  });
  it("close: an in-flight call fails and later calls fail at once", async () => {
    const svc = await service(hang);
    const used = client(svc.endpoint, { timeoutMs: 5_000 });
    const pending = used.transform(CANARY, REQUEST);
    await new Promise((resolve) => setTimeout(resolve, 50));
    await used.close();
    expect(await pending).toBeNull();
    expect(await used.transform(CANARY, REQUEST)).toBeNull();
    expect(svc.requests.length).toBeLessThanOrEqual(1);
  });
});

function policyFor(mode: PrivacyMode): DeploymentPolicy {
  const data = JSON.parse(
    fs.readFileSync(path.join(ROOT, "examples/enterprise/policy.local.json"), "utf8"),
  ) as DeploymentPolicyData;
  data.privacy = { "terminal.stdout": mode };
  return DeploymentPolicy.fromDict(data);
}
function stores(tenant: string) {
  const dirs = [tempDir(), tempDir()];
  return {
    dirs,
    original: new LocalFilesystemContentStore(dirs[0]!, tenant),
    review: new LocalFilesystemContentStore(dirs[1]!, tenant),
  };
}
const CAPTURE = {
  role: "terminal.stdout",
  boundary: "terminal",
  sourceId: "sdk",
  sourceEpoch: 0,
  sourceSequence: 1,
};

describe("the byte recorder", () => {
  it.each(["redact", "masked_only"] as const)(
    "stores the service's bytes and the transformation identity (%s)",
    async (mode) => {
      const svc = await service(mask);
      const policy = policyFor(mode);
      const { original, review } = stores(policy.tenant_id);
      const recorder = new ByteEvidenceRecorder({
        store: original,
        reviewStore: review,
        roles: new Set(["terminal.stdout"]),
        contentProtector: new ContentProtector(policy, {
          transformations: { "terminal.stdout": T },
          redaction: { endpoint: svc.endpoint },
        }),
      });
      const initial = recorder.capture(CANARY, CAPTURE);
      await recorder.flush();
      const settled = recorder.get(initial.object_id)!;
      expect(settled).toMatchObject({
        status: "redacted",
        privacy_mode: mode,
        transformation_id: "mask-email",
        transformation_version: "3",
      });
      expect(Buffer.from(review.read(settled.ref!)).toString()).toBe("[redacted]");
      expect(svc.requests[0]!.headers["x-fabric-mode"]).toBe(mode);
      await recorder.close();
      // close() closed the recorder's connection pool
      expect(svc.requests).toHaveLength(1);
    },
  );

  it.each([
    ["an error status", status(500), {}],
    ["a redirect", status(302, { Location: "http://127.0.0.1:1/" }), {}],
    ["a timeout", hang, { timeoutMs: 100 }],
    [
      "an oversized response",
      ((_req, body, res) => {
        res.writeHead(200);
        res.end(Buffer.concat([body, body, body]));
      }) as Handler,
      {},
    ],
    ["connection refused", undefined, {}],
  ] as const)(
    "withholds on %s: no original bytes or digest persisted",
    async (_name, handler, extra) => {
      const policy = policyFor("masked_only");
      const { dirs, original, review } = stores(policy.tenant_id);
      const endpoint =
        handler === undefined
          ? "unix://" + path.join(tempDir(), "absent.sock")
          : (await service(handler)).endpoint;
      const recorder = new ByteEvidenceRecorder({
        store: original,
        reviewStore: review,
        roles: new Set(["terminal.stdout"]),
        contentProtector: new ContentProtector(policy, {
          transformations: { "terminal.stdout": T },
          redaction: { endpoint, ...extra },
          payloadMaxBytes: 2 * CANARY.length,
        }),
      });
      const initial = recorder.capture(CANARY, CAPTURE);
      expect(initial.status).toBe("pending");
      await recorder.flush();
      const settled = recorder.get(initial.object_id)!;
      expect(settled).toMatchObject({
        status: "not_captured",
        status_reason: "protection_failed",
        protection_status: "withheld",
        representation: "unavailable",
      });
      expect(original.listObjectUris()).toEqual([]);
      expect(review.listObjectUris()).toEqual([]);
      const text = JSON.stringify([initial, settled, recorder.drainSettled()]);
      expect(text).not.toContain(CANARY.toString());
      expect(text).not.toContain(CANARY_SHA);
      expect(settled.source_byte_length).toBeUndefined();
      for (const dir of dirs)
        for (const name of fs.readdirSync(dir, { recursive: true })) {
          const file = path.join(dir, String(name));
          if (fs.lstatSync(file).isFile()) {
            const bytes = fs.readFileSync(file);
            expect(bytes.includes(CANARY)).toBe(false);
            expect(bytes.includes(Buffer.from(CANARY_SHA))).toBe(false);
          }
        }
      await recorder.close();
    },
  );

  it("never delays capture(): a hung service only loses content", async () => {
    const svc = await service(hang);
    const policy = policyFor("redact");
    const { original, review } = stores(policy.tenant_id);
    const recorder = new ByteEvidenceRecorder({
      store: original,
      reviewStore: review,
      roles: new Set(["terminal.stdout"]),
      contentProtector: new ContentProtector(policy, {
        transformations: { "terminal.stdout": T },
        redaction: { endpoint: svc.endpoint, timeoutMs: 300, maxInFlight: 1 },
      }),
    });
    const timings: number[] = [];
    const ids: string[] = [];
    for (let sequence = 1; sequence <= 20; sequence += 1) {
      const start = performance.now();
      ids.push(recorder.capture(CANARY, { ...CAPTURE, sourceSequence: sequence }).object_id);
      timings.push(performance.now() - start);
    }
    timings.sort((a, b) => a - b);
    expect(timings[Math.floor(timings.length / 2)]!).toBeLessThan(5);
    expect(Math.max(...timings)).toBeLessThan(50);
    await recorder.flush(20_000);
    for (const id of ids) expect(recorder.get(id)!.status).toBe("not_captured");
    expect(original.listObjectUris()).toEqual([]);
    expect(review.listObjectUris()).toEqual([]);
    await recorder.close();
  }, 30_000);
});
