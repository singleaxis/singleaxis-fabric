// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * PROTECT before persistence (spec 055 §5, unit 055-t8): one golden per whole-object
 * mode and per redaction service failure, the production gate's precedence, bounded
 * decoding, the role table and the 050 object bounds.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync, deflateRawSync, brotliCompressSync } from "node:zlib";

import { afterEach, describe, expect, it } from "vitest";

import { DeploymentPolicy } from "../../../src/deployment-policy.js";
import { encodeJson, parseJson } from "../../../src/wire/codec.js";
import {
  LOCAL_DEFAULT,
  ROLES,
  TooLargeError,
  UndecodableError,
  admits,
  decideGate,
  decodeContent,
  modeOf,
} from "../../../src/wire/protect.js";
import { ROLE_ROWS } from "../../../src/wire/roles.generated.js";
import {
  ObjectBoundError,
  exchangeEntry,
  overObjectBound,
  prepareExchange,
  pyIsoformat,
} from "../../../src/wire/writer.js";
import {
  mask,
  startService,
  status,
  hang,
  type Handler,
  type TestService,
} from "../../redaction-service.js";
import {
  CHAT_REQUEST,
  CHAT_RESPONSE,
  ENRICHMENT,
  TENANT,
  enabledGate,
  exchange,
  normalized,
  policyDoc,
  policyFor,
  protector,
} from "./helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDENS = join(HERE, "goldens.json");
const UPDATE = process.env.FABRIC_UPDATE_GOLDENS === "1";
const canon = (value: unknown): unknown => parseJson(encodeJson(value));
const written: Record<string, unknown> = {};
const goldens: Record<string, unknown> =
  existsSync(GOLDENS) && !UPDATE
    ? (parseJson(readFileSync(GOLDENS, "utf8")) as Record<string, unknown>)
    : {};

function golden(name: string, value: unknown): void {
  const actual = canon(value);
  if (UPDATE) {
    written[name] = actual;
    writeFileSync(GOLDENS, pretty(written) + "\n");
    return;
  }
  expect(
    actual,
    `golden ${name} (FABRIC_UPDATE_GOLDENS=1 rewrites test/wire/protect/goldens.json)`,
  ).toEqual(goldens[name]);
}

/** JSON with exact integers, indented, keys sorted. */
function pretty(value: unknown): string {
  const marks: bigint[] = [];
  const text = JSON.stringify(
    value,
    (_key, item: unknown) => {
      if (typeof item === "bigint") {
        marks.push(item);
        return `__BIGINT_${marks.length - 1}__`;
      }
      if (item !== null && typeof item === "object" && !Array.isArray(item)) {
        return Object.fromEntries(Object.entries(item).sort(([a], [b]) => (a < b ? -1 : 1)));
      }
      return item;
    },
    2,
  );
  return text.replace(/"__BIGINT_(\d+)__"/g, (_m, i: string) => String(marks[Number(i)]));
}

const services: TestService[] = [];
afterEach(async () => {
  for (const service of services.splice(0)) await service.close();
});

async function service(handler: Handler): Promise<TestService> {
  const started = await startService(handler);
  services.push(started);
  return started;
}

const TRANSFORM = { id: "acme-pii", version: "2" };
const transforms = {
  "model.exchange.request": TRANSFORM,
  "model.exchange.response": TRANSFORM,
};
const originalDigests = [CHAT_REQUEST, CHAT_RESPONSE].map((b) =>
  createHash("sha256").update(b).digest("hex"),
);

async function run(
  mode: string | undefined,
  options: Parameters<typeof protector>[1] = {},
  job = exchange(),
) {
  const policy = policyFor(mode);
  const prepared = await prepareExchange(
    job,
    {
      gate: enabledGate(policy),
      protector: protector(policy, options),
      tenantId: TENANT,
      enrichment: ENRICHMENT,
    },
    "0".repeat(31) + "1",
  );
  return prepared;
}

/** No digest, range or length of an original survives a withheld or transformed object. */
function expectNoOriginal(prepared: Awaited<ReturnType<typeof run>>): void {
  const text = encodeJson({ span: prepared.span, d: prepared.objects.map((o) => o.descriptor) });
  for (const digest of originalDigests) expect(text).not.toContain(digest);
  for (const object of prepared.objects) {
    expect(object.descriptor).not.toHaveProperty("source_sha256");
    expect(object.descriptor).not.toHaveProperty("byte_range");
  }
  const bytes = Buffer.concat(prepared.objects.map((o) => o.data)).toString("latin1");
  expect(bytes).not.toContain("PROMPT-CANARY-1");
  expect(bytes).not.toContain("RESPONSE-CANARY-1");
}

describe("whole-object modes (one golden each)", () => {
  it("retain_original keeps the exact bytes with source and stored digests", async () => {
    const prepared = await run("retain_original");
    expect(Buffer.concat(prepared.objects.map((o) => o.data))).toEqual(
      Buffer.concat([CHAT_REQUEST, CHAT_RESPONSE]),
    );
    expect(prepared.span.attributes["fabric.wire.request_sha256"]).toBe(originalDigests[0]);
    expect(prepared.span.attributes["gen_ai.response.model"]).toBe("gpt-4o-2024-08-06");
    golden("retain_original", normalized(prepared));
  });

  it("the implicit local default retains both exchange roles", async () => {
    const prepared = await run(undefined);
    expect(prepared.objects.map((o) => o.descriptor.policy_id)).toEqual([
      "fabric.local-default",
      "fabric.local-default",
    ]);
    golden("local_default", normalized(prepared));
  });

  it("metadata_only stores a descriptor with the byte count and no digest", async () => {
    const prepared = await run("metadata_only");
    expect(prepared.objects.map((o) => o.descriptor.source_byte_length)).toEqual([
      CHAT_REQUEST.length,
      CHAT_RESPONSE.length,
    ]);
    expect(prepared.span.attributes["fabric.wire.store_reason"]).toBe("privacy_policy");
    expect(prepared.span.attributes).not.toHaveProperty("gen_ai.response.model");
    expectNoOriginal(prepared);
    golden("metadata_only", normalized(prepared));
  });

  it("omit stores nothing and extracts nothing", async () => {
    const prepared = await run("omit");
    expect(prepared.objects).toEqual([]);
    expect(prepared.span.attributes["fabric.wire.store_status"]).toBe("disabled");
    expectNoOriginal(prepared);
    golden("omit", normalized(prepared));
  });

  for (const mode of ["redact", "masked_only"]) {
    it(`${mode} stores only the service's bytes, with no original digest or length`, async () => {
      const masker = await service(mask);
      const prepared = await run(mode, {
        transformations: transforms,
        redaction: { endpoint: masker.endpoint },
      });
      expect(prepared.objects.map((o) => Buffer.from(o.data).toString())).toEqual([
        "[redacted]",
        "[redacted]",
      ]);
      expect(masker.requests.map((r) => r.headers["x-fabric-mode"])).toEqual([mode, mode]);
      expectNoOriginal(prepared);
      golden(mode, normalized(prepared));
    });
  }

  it("tokenize stores the scoped whole-object HMAC token", async () => {
    const prepared = await run("tokenize");
    expect(Buffer.from(prepared.objects[0]!.data).toString()).toMatch(
      /^fabric\.token\.v1:[0-9a-f]{64}$/,
    );
    expectNoOriginal(prepared);
    golden("tokenize", normalized(prepared));
  });

  it("tokenize without a key is withheld (protection_failed)", async () => {
    const prepared = await run("tokenize", { tokenizationKey: undefined });
    expect(prepared.objects.map((o) => o.descriptor.status_reason)).toEqual([
      "protection_failed",
      "protection_failed",
    ]);
    expectNoOriginal(prepared);
  });

  it("original_plus_masked is withheld as a pair until unit 055-t15 builds the review copy", async () => {
    const prepared = await run("original_plus_masked");
    expect(prepared.objects.map((o) => o.descriptor.status)).toEqual(Array(4).fill("not_captured"));
    expectNoOriginal(prepared);
    golden("original_plus_masked", normalized(prepared));
  });

  it("a side over max_body_bytes is cut whole-piece (body_cap) and never transformed", async () => {
    const big = exchange({
      request: {
        ...exchange().request,
        pieces: [CHAT_REQUEST, CHAT_REQUEST],
        observed: 2 * CHAT_REQUEST.length,
      },
    });
    const kept = await run("retain_original", { maxBodyBytes: CHAT_REQUEST.length + 10 }, big);
    expect(kept.objects[0]!.data).toEqual(CHAT_REQUEST);
    expect(kept.objects[0]!.descriptor).toMatchObject({
      representation: "truncated",
      status: "truncated",
    });
    expect(kept.span.attributes["fabric.wire.truncated"]).toBe(true);
    const masker = await service(mask);
    const masked = await run(
      "redact",
      {
        maxBodyBytes: CHAT_REQUEST.length + 10,
        transformations: transforms,
        redaction: { endpoint: masker.endpoint },
      },
      big,
    );
    expect(masked.objects[0]!.descriptor).toMatchObject({
      status: "not_captured",
      status_reason: "body_cap",
    });
    golden("body_cap", { retained: normalized(kept), redacted: normalized(masked) });
  });

  it("an adopted call whose explicit scope withheld stores nothing (explicit_withheld)", async () => {
    const prepared = await run("retain_original", {}, exchange({ withheld: true }));
    expect(prepared.objects).toEqual([]);
    expect(prepared.span.attributes).toMatchObject({
      "fabric.wire.store_status": "disabled",
      "fabric.wire.store_reason": "explicit_withheld",
    });
    expectNoOriginal(prepared);
  });

  it("a compressed side is decoded before a transformation, and withheld when it cannot be", async () => {
    const masker = await service((_req, body, res) => {
      res.writeHead(200).end(body.toString().replace(/CANARY-\d/g, "[x]"));
    });
    const gz = exchange({
      response: {
        ...exchange().response!,
        pieces: [gzipSync(CHAT_RESPONSE)],
        contentEncoding: "gzip",
      },
    });
    const prepared = await run(
      "redact",
      { transformations: transforms, redaction: { endpoint: masker.endpoint } },
      gz,
    );
    expect(prepared.objects[1]!.descriptor.content_encoding).toBe("identity");
    expect(Buffer.from(prepared.objects[1]!.data).toString()).toContain("RESPONSE-[x]");
    const corrupt = exchange({
      response: {
        ...exchange().response!,
        pieces: [Buffer.from("not gzip")],
        contentEncoding: "gzip",
      },
    });
    const withheld = await run(
      "redact",
      { transformations: transforms, redaction: { endpoint: masker.endpoint } },
      corrupt,
    );
    expect(withheld.objects[1]!.descriptor).toMatchObject({
      status: "not_captured",
      status_reason: "protection_failed",
    });
    golden("decoded", { decoded: normalized(prepared), undecodable: normalized(withheld) });
  });
});

describe("redaction service failures withhold (protection_failed)", () => {
  const redirect: Handler = (_req, _body, res) => {
    res.writeHead(302, { Location: "http://127.0.0.1:9/elsewhere" }).end();
  };
  const oversized: Handler = (_req, _body, res) => {
    res.writeHead(200).end(Buffer.alloc(64 * 1024, 0x61));
  };
  const malformed: Handler = (_req, _body, res) => {
    res.writeHead(200, { "Content-Length": "100" });
    res.write("[red");
    res.socket?.destroy();
  };
  const cases: [string, Handler, Record<string, unknown>][] = [
    ["timeout", hang, { timeoutMs: 50 }],
    ["redirect", redirect, {}],
    ["non-200", status(500), {}],
    ["oversized", oversized, {}],
    ["malformed", malformed, {}],
  ];
  for (const [name, handler, extra] of cases) {
    it(name, async () => {
      const failing = await service(handler);
      const prepared = await run("redact", {
        maxBodyBytes: 4096,
        transformations: transforms,
        redaction: { endpoint: failing.endpoint, ...extra },
      });
      expect(prepared.objects.map((o) => o.descriptor.status_reason)).toEqual([
        "protection_failed",
        "protection_failed",
      ]);
      expect(prepared.span.attributes).toMatchObject({
        "fabric.wire.store_status": "disabled",
        "fabric.wire.store_reason": "protection_failed",
      });
      expectNoOriginal(prepared);
      golden(`failure_${name}`, normalized(prepared));
    });
  }

  it("connection error", async () => {
    const prepared = await run("redact", {
      transformations: transforms,
      redaction: { endpoint: "unix:///nonexistent/f055-t8/redaction.sock" },
    });
    expect(prepared.objects.map((o) => o.descriptor.status_reason)).toEqual([
      "protection_failed",
      "protection_failed",
    ]);
    expectNoOriginal(prepared);
  });

  it("saturated: a call over the in-flight bound is withheld at once", async () => {
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => (release = resolve));
    const slow = await service((_req, _body, res) => {
      void held.then(() => res.writeHead(200).end("[redacted]"));
    });
    const policy = policyFor("redact");
    const shared = protector(policy, {
      transformations: transforms,
      redaction: { endpoint: slow.endpoint, maxInFlight: 1 },
    });
    const context = {
      gate: enabledGate(policy),
      protector: shared,
      tenantId: TENANT,
      enrichment: ENRICHMENT,
    };
    const first = prepareExchange(exchange(), context, "1".repeat(32));
    await new Promise((resolve) => setTimeout(resolve, 20));
    const second = await prepareExchange(
      exchange({ request: { ...exchange().request, pieces: [Buffer.from("{}")] } }),
      context,
      "1".repeat(32),
    );
    release();
    await first;
    expect(second.objects[0]!.descriptor.status_reason).toBe("protection_failed");
    expect(shared.stats().redaction_saturated).toBeGreaterThan(0);
    expectNoOriginal(second);
    golden("failure_saturated", normalized(second));
  });

  it("a masking role with no transformation or no service is withheld, never raw", async () => {
    const masker = await service(mask);
    const noTransform = await run("redact", { redaction: { endpoint: masker.endpoint } });
    const noService = await run("masked_only", {});
    for (const prepared of [noTransform, noService]) {
      expect(prepared.objects.map((o) => o.descriptor.status_reason)).toEqual([
        "protection_failed",
        "protection_failed",
      ]);
      expectNoOriginal(prepared);
    }
    expect(masker.requests).toEqual([]);
  });

  it("transformations without a redaction service are a fixed-text configuration error", () => {
    expect(() => protector(policyFor("redact"), { transformations: transforms })).toThrow(
      "transformations require a redaction service endpoint: set FABRIC_REDACTION_ENDPOINT",
    );
  });
});

describe("the production gate (049 §7.3, §7.8)", () => {
  const production = new DeploymentPolicy(
    policyDoc({ "model.exchange.request": "retain_original" }, "production"),
  );
  const local = new DeploymentPolicy(policyDoc({ "model.exchange.request": "retain_original" }));
  const base = {
    node: true,
    store: false,
    policy: production,
    idKey: true,
    spool: true,
    spoolKey: true,
  };

  it("reports the reasons with Python's precedence", () => {
    const reason = (inputs: Partial<typeof base>) => decideGate({ ...base, ...inputs }).reason;
    expect(reason({ policy: undefined, idKey: false, spoolKey: false })).toBe(
      "missing_capture_policy",
    );
    expect(reason({ idKey: false, spoolKey: false })).toBe("missing_id_key");
    expect(reason({ spoolKey: false })).toBe("missing_spool_key");
    expect(reason({})).toBeUndefined();
    expect(decideGate({ ...base, node: false, store: false }).contentCapture).toBe("metadata_only");
    expect(decideGate({ ...base, node: false, store: false }).reason).toBe("no_store");
  });

  it("a production policy makes a local store production; a local one needs no keys", () => {
    expect(decideGate({ ...base, node: false, store: true, idKey: false }).reason).toBe(
      "missing_id_key",
    );
    const gate = decideGate({
      ...base,
      node: false,
      store: true,
      policy: local,
      idKey: false,
      spoolKey: false,
    });
    expect([gate.profile, gate.contentCapture]).toEqual(["local", "enabled"]);
    expect(
      decideGate({ ...base, node: false, store: true, policy: undefined, idKey: false }).policy,
    ).toBe(LOCAL_DEFAULT);
  });

  it("disabled content keeps safe metadata and names its reason on the span", async () => {
    const gate = decideGate({ ...base, idKey: false });
    const prepared = await prepareExchange(
      exchange(),
      { gate, protector: undefined, tenantId: TENANT, enrichment: ENRICHMENT },
      "2".repeat(32),
    );
    expect(prepared.objects).toEqual([]);
    expect(prepared.span.attributes).toMatchObject({
      "fabric.wire.store_status": "disabled",
      "fabric.wire.store_reason": "missing_id_key",
      "http.response.status_code": 200,
    });
    expect(prepared.span.attributes).not.toHaveProperty("gen_ai.response.model");
    expectNoOriginal(prepared);
    golden("content_disabled", normalized(prepared));
  });
});

describe("support", () => {
  it("decodes gzip, deflate (zlib and raw) and br, bounded, and refuses anything else", () => {
    const text = Buffer.from("x".repeat(1000));
    expect(decodeContent(gzipSync(text), "gzip", 2000)).toEqual(text);
    expect(decodeContent(deflateRawSync(text), "deflate", 2000)).toEqual(text);
    expect(decodeContent(brotliCompressSync(text), "br", 2000)).toEqual(text);
    expect(decodeContent(gzipSync(gzipSync(text)), "gzip, gzip", 2000)).toEqual(text);
    expect(() => decodeContent(gzipSync(text), "gzip", 999)).toThrow(TooLargeError);
    expect(() => decodeContent(gzipSync(text).subarray(0, 20), "gzip", 2000)).toThrow(
      UndecodableError,
    );
    expect(() => decodeContent(text, "compress", 2000)).toThrow(UndecodableError);
  });

  it("the role table is the registry's, and admits only what the Node would", () => {
    expect(ROLES.size).toBe(ROLE_ROWS.length);
    const ok = {
      boundary: "provider_bound",
      provenance: "protocol",
      mediaType: "application/json",
      storedByteLength: 10,
      maxBodyBytes: 100,
    };
    expect(admits("model.exchange.request", ok)).toBe(true);
    expect(admits("model.exchange.request", { ...ok, boundary: "caller" })).toBe(false);
    expect(admits("model.exchange.request", { ...ok, storedByteLength: 101 })).toBe(false);
    expect(admits("model.exchange.part", ok)).toBe(false);
    expect(admits("no.such.role", ok)).toBe(false);
    expect(modeOf(LOCAL_DEFAULT, "model.exchange.request")).toBe("retain_original");
    expect(modeOf(policyFor("redact"), "tool.definition")).toBe("omit");
  });

  it("captured_at is Python's isoformat of ns / 1e9", () => {
    expect(pyIsoformat(1791331201120000000n)).toBe("2026-10-07T00:00:01.120000+00:00");
    expect(pyIsoformat(1791331200000000000n)).toBe("2026-10-07T00:00:00+00:00");
    expect(pyIsoformat(1791331200999999999n)).toBe("2026-10-07T00:00:01+00:00");
  });

  it("an exchange over 260 objects or a record over 8 is refused before admission", async () => {
    expect(overObjectBound("exchange", 260)).toBe(false);
    expect(overObjectBound("exchange", 261)).toBe(true);
    expect(overObjectBound("record", 9)).toBe(true);
    const prepared = await run("retain_original");
    const many = { ...prepared, objects: Array(261).fill(prepared.objects[0]) };
    expect(() => exchangeEntry("s-x", 1n, "svc", many)).toThrow(ObjectBoundError);
    expect(exchangeEntry("s-x", 1n, "svc", prepared).bodies).toHaveLength(2);
  });
});

if (!UPDATE) {
  it("every golden in goldens.json is checked", () => {
    expect(Object.keys(goldens).sort()).toEqual(
      [
        "body_cap",
        "content_disabled",
        "decoded",
        "failure_malformed",
        "failure_non-200",
        "failure_oversized",
        "failure_redirect",
        "failure_saturated",
        "failure_timeout",
        "local_default",
        "masked_only",
        "metadata_only",
        "omit",
        "original_plus_masked",
        "redact",
        "retain_original",
        "tokenize",
      ].sort(),
    );
  });
}
