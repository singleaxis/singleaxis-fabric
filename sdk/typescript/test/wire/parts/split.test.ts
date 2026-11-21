// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * PROTECT II (spec 055 §5, unit 055-t15): split sides, the part role's own policy,
 * `part_cap`, `body_cap`, `original_plus_masked` review copies linked by `derived_from`
 * (a failed review withholds both objects) and the 260-object bound at its exact shape.
 */
import { afterEach, describe, expect, it } from "vitest";

import type { RedactionServiceOptions } from "../../../src/redaction.js";
import { encodeJson } from "../../../src/wire/codec.js";
import {
  LOCAL_DEFAULT,
  type ContentObject,
  isStored,
  wholePiecePrefix,
} from "../../../src/wire/protect.js";
import { MAX_EXCHANGE_BODIES } from "../../../src/wire/p1-types.js";
import { partObjectId } from "../../../src/wire/parts.js";
import { ObjectBoundError, exchangeEntry, prepareExchange } from "../../../src/wire/writer.js";
import {
  mask,
  startService,
  status,
  hang,
  type Handler,
  type TestService,
} from "../../redaction-service.js";
import { ENRICHMENT, TENANT, enabledGate, exchange } from "../protect/helpers.js";
import {
  MASK,
  PART,
  PNG,
  REQUEST,
  RESPONSE,
  CANARY,
  WAV,
  bigRequest,
  expectNothingOriginal,
  policy,
  protectorOf,
  rangeOf,
  reassemble,
  sha,
  side,
} from "./helpers.js";

const services: TestService[] = [];
afterEach(async () => {
  for (const service of services.splice(0)) await service.close();
});
async function service(handler: Handler = mask): Promise<TestService> {
  const started = await startService(handler);
  services.push(started);
  return started;
}

const descriptors = (objects: readonly ContentObject[]) => objects.map((o) => o.descriptor);

describe("split sides (retain_original)", () => {
  it("retains the parts with half-open ranges and reassembles to source_sha256", async () => {
    const data = bigRequest([PNG, WAV]);
    const result = await side(protectorOf(LOCAL_DEFAULT, { maxBodyBytes: 1500 }), data);
    const [skeleton, ...parts] = result.objects;
    expect(result.primary).toBe(skeleton);
    expect(result.reason).toBeUndefined();
    expect(parts).toHaveLength(2);
    expect(skeleton!.descriptor).toMatchObject({
      representation: "split",
      transformations: ["extract_parts"],
      status: "stored",
      source_sha256: sha(data),
      source_byte_length: data.byteLength,
      stored_sha256: sha(skeleton!.data),
    });
    expect(parts.map((p) => p.descriptor.media_type)).toEqual(["image/png", "audio/wav"]);
    parts.forEach((part, index) => {
      const [start, end] = rangeOf(part);
      expect(part.descriptor.links).toEqual([
        {
          relation: "part_of",
          object_id: skeleton!.descriptor.object_id,
          byte_range: [start, end],
        },
      ]);
      expect(Buffer.from(part.data)).toEqual(data.subarray(start, end));
      expect(part.descriptor).toMatchObject({
        role: PART,
        content_encoding: "base64",
        representation: "exact",
        source_sha256: sha(part.data),
        object_id: partObjectId(String(skeleton!.descriptor.object_id), index),
      });
    });
    expect(sha(reassemble(skeleton!.data, parts))).toBe(sha(data));
    expect(Buffer.from(skeleton!.data).toString()).toContain(CANARY); // the text survives
  });

  it("a part beyond the object cap is descriptor-only part_cap, keeping its retained digest", async () => {
    const huge = Buffer.concat([
      Buffer.from("\x89PNG\r\n\x1a\n", "latin1"),
      Buffer.alloc(4096),
    ]).toString("base64");
    const data = bigRequest([huge]);
    const result = await side(protectorOf(LOCAL_DEFAULT, { maxBodyBytes: 2048 }), data);
    const [skeleton, part] = result.objects;
    expect(result.primary).toBe(skeleton);
    expect(result.reason).toBe("part_cap");
    expect(part!.data.byteLength).toBe(0);
    expect(part!.descriptor).toMatchObject({
      status: "not_captured",
      status_reason: "part_cap",
      protection_status: "withheld",
      representation: "unavailable",
      source_byte_length: huge.length,
      source_sha256: sha(Buffer.from(huge)),
    });
    expect(part!.descriptor).not.toHaveProperty("stored_sha256");
    const [start, end] = rangeOf(part!);
    expect(end - start).toBe(huge.length);

    // The span names it body_cap (X40's vocabulary) and stays stored: the skeleton is.
    const job = exchange();
    const prepared = await prepareExchange(
      exchange({ request: { ...job.request, pieces: [data], observed: data.byteLength } }),
      {
        gate: enabledGate(LOCAL_DEFAULT),
        protector: protectorOf(LOCAL_DEFAULT, { maxBodyBytes: 2048 }),
        tenantId: TENANT,
        enrichment: ENRICHMENT,
      },
      "0".repeat(31) + "1",
    );
    expect(prepared.span.attributes).toMatchObject({
      "fabric.wire.store_status": "stored",
      "fabric.wire.store_reason": "body_cap",
      "fabric.wire.truncated": false,
    });
  });

  it("an unnamed part role is omitted while the skeleton follows its role", async () => {
    const result = await side(
      protectorOf(policy({ request: "retain_original" }), { maxBodyBytes: 1100 }),
      bigRequest([PNG]),
    );
    expect(result.objects).toHaveLength(1);
    expect(result.objects[0]!.descriptor.representation).toBe("split");
    expect(result.reason).toBeUndefined();
  });

  it("a part under metadata_only keeps its length and nothing else", async () => {
    const data = bigRequest([PNG]);
    const result = await side(
      protectorOf(policy({ request: "retain_original", part: "metadata_only" }), {
        maxBodyBytes: 1100,
      }),
      data,
    );
    const part = result.objects[1]!;
    expect(part.descriptor).toMatchObject({
      status_reason: "privacy_policy",
      source_byte_length: PNG.length,
    });
    expect(part.descriptor).not.toHaveProperty("source_sha256");
    expect(part.descriptor.links).toEqual([
      { relation: "part_of", object_id: result.objects[0]!.descriptor.object_id },
    ]);
  });

  it("does not split a non-JSON, encoded, partial or over-max_retain side: it is cut (body_cap)", async () => {
    const data = bigRequest([PNG]);
    const protector = protectorOf(LOCAL_DEFAULT, { maxBodyBytes: 1100, maxRetainBytes: 1 << 20 });
    const pieces = [data.subarray(0, 1000), data.subarray(1000)];
    for (const options of [
      { base: { media_type: "text/event-stream" } },
      { base: { content_encoding: "gzip" } },
      { base: { content_encoding: "identity, identity" } }, // Python compares the literal
      { role: RESPONSE, partial: true },
    ]) {
      const result = await side(protector, data, { pieces, ...options });
      expect(result.objects[0]!.descriptor.representation).toBe("truncated");
      expect(result.reason).toBe("body_cap");
    }
    const small = protectorOf(LOCAL_DEFAULT, {
      maxBodyBytes: 1100,
      maxRetainBytes: data.byteLength - 1,
    });
    const cut = await side(small, data, { pieces });
    expect(cut.objects[0]!.descriptor.representation).toBe("truncated");
  });

  it("a side whose skeleton would still exceed max_body_bytes is not split", async () => {
    const data = bigRequest([PNG], "x".repeat(2000));
    const result = await side(protectorOf(LOCAL_DEFAULT, { maxBodyBytes: 1500 }), data, {
      pieces: [data.subarray(0, 1400), data.subarray(1400)],
    });
    expect(result.objects).toHaveLength(1);
    expect(result.objects[0]!.descriptor.representation).toBe("truncated");
    expect(Buffer.from(result.objects[0]!.data)).toEqual(data.subarray(0, 1400));
  });

  it("a side already cut by the hook is never split", async () => {
    const data = bigRequest([PNG]);
    const result = await side(protectorOf(LOCAL_DEFAULT, { maxBodyBytes: 1100 }), data, {
      cut: "body_cap",
      pieces: [data.subarray(0, 600), data.subarray(600)],
    });
    expect(result.objects.map((o) => o.descriptor.representation)).toEqual(["truncated"]);
  });
});

describe("split sides under protecting modes", () => {
  it("redact: the skeleton is masked, a binary part with no transformation is withheld, no ranges", async () => {
    const masker = await service();
    const data = bigRequest([PNG]);
    const result = await side(
      protectorOf(policy({ request: "redact", part: "redact" }), {
        maxBodyBytes: 1100,
        transformations: { [REQUEST]: { id: "acme-redactor", version: "3" } },
        redaction: { endpoint: masker.endpoint },
      }),
      data,
    );
    const [skeleton, part] = result.objects;
    expect(skeleton!.descriptor.transformations).toEqual(["extract_parts", "redact"]);
    expect(skeleton!.descriptor).not.toHaveProperty("source_sha256");
    expect(part!.descriptor.status_reason).toBe("privacy_policy");
    expect(part!.descriptor.links).toEqual([
      { relation: "part_of", object_id: skeleton!.descriptor.object_id },
    ]);
    // The service saw the skeleton only, never the part.
    expect(masker.requests.some((r) => r.body.includes(PNG))).toBe(false);
    expectNothingOriginal(result, data, [PNG], expect);
  });

  it("tokenize: each object is tokenized; no range, no original digest", async () => {
    const data = bigRequest([PNG]);
    const result = await side(
      protectorOf(policy({ request: "tokenize", part: "tokenize" }), { maxBodyBytes: 1100 }),
      data,
    );
    const [skeleton, part] = result.objects;
    expect(skeleton!.descriptor.transformations).toEqual(["extract_parts", "tokenize"]);
    expect(part!.descriptor.transformations).toEqual(["tokenize"]);
    expect(part!.descriptor.representation).toBe("tokenized");
    expectNothingOriginal(result, data, [PNG], expect);
  });

  it("property: retained splits reassemble; protecting modes never leak", async () => {
    const masker = await service();
    let seed = 55015;
    const random = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
    const between = (lo: number, hi: number) => lo + Math.floor(random() * (hi - lo + 1));
    for (let round = 0; round < 30; round++) {
      const parts = Array.from({ length: between(1, 5) }, () =>
        Buffer.from(Array.from({ length: between(48, 900) }, () => between(0, 255))).toString(
          "base64",
        ),
      );
      const data = bigRequest(parts);
      const skeletonLength = data.byteLength - parts.reduce((n, p) => n + p.length, 0);
      const maxBodyBytes = between(skeletonLength + 8, data.byteLength - 1);
      const kept = await side(protectorOf(LOCAL_DEFAULT, { maxBodyBytes }), data);
      const stored = kept.objects.slice(1).filter(isStored);
      if (stored.length === kept.objects.length - 1) {
        expect(sha(reassemble(kept.objects[0]!.data, stored))).toBe(sha(data));
      }
      const mode = ["redact", "masked_only", "tokenize", "metadata_only"][between(0, 3)]!;
      const protectedSide = await side(
        protectorOf(policy({ request: mode, part: mode }), {
          maxBodyBytes,
          transformations: { [REQUEST]: { id: "acme-redactor", version: "3" } },
          redaction: { endpoint: masker.endpoint },
        }),
        data,
      );
      expectNothingOriginal(protectedSide, data, parts, expect);
    }
  });
});

describe("original_plus_masked: review copies linked by derived_from", () => {
  it("a whole side keeps the original and a masked review copy derived from it", async () => {
    const masker = await service();
    const data = Buffer.from('{"messages":[{"content":"' + CANARY + '"}]}');
    const result = await side(
      protectorOf(policy({ request: "original_plus_masked" }), {
        transformations: { [REQUEST]: MASK },
        redaction: { endpoint: masker.endpoint },
      }),
      data,
    );
    const [original, review] = result.objects;
    expect(result.primary).toBe(original);
    expect(result.reason).toBeUndefined();
    expect(original!.descriptor).toMatchObject({
      representation: "exact",
      status: "stored",
      protection_status: "retained",
      privacy_mode: "original_plus_masked",
      source_sha256: sha(data),
    });
    expect(Buffer.from(review!.data).toString()).toBe("[redacted]");
    expect(review!.descriptor).toMatchObject({
      status: "redacted",
      protection_status: "redacted",
      transformation_id: MASK.id,
      transformation_version: MASK.version,
      links: [{ relation: "derived_from", object_id: original!.descriptor.object_id }],
    });
    expect(review!.descriptor).not.toHaveProperty("source_sha256");
    expect(review!.descriptor).not.toHaveProperty("source_byte_length");
  });

  it("a split side: skeleton and parts, plus one review copy of the whole side", async () => {
    const masker = await service();
    const data = bigRequest([PNG]);
    const result = await side(
      protectorOf(policy({ request: "original_plus_masked", part: "retain_original" }), {
        maxBodyBytes: 1100,
        transformations: { [REQUEST]: MASK },
        redaction: { endpoint: masker.endpoint },
      }),
      data,
    );
    const [skeleton, part, review] = result.objects;
    expect(skeleton!.descriptor.representation).toBe("split");
    expect(sha(reassemble(skeleton!.data, [part!]))).toBe(sha(data));
    expect(review!.descriptor.links).toEqual([
      { relation: "derived_from", object_id: skeleton!.descriptor.object_id },
    ]);
    // The review copy masks the whole plaintext, parts included.
    expect(masker.requests.map((r) => sha(r.body))).toEqual([sha(data)]);
  });

  it("parts get their own review copy, part_of the skeleton and derived_from the part", async () => {
    const masker = await service();
    const data = bigRequest([PNG]);
    const result = await side(
      protectorOf(policy({ request: "retain_original", part: "original_plus_masked" }), {
        maxBodyBytes: 1100,
        transformations: { [PART]: MASK },
        redaction: { endpoint: masker.endpoint },
      }),
      data,
    );
    const [skeleton, part, review] = result.objects;
    expect(result.primary).toBe(skeleton);
    expect(result.reason).toBeUndefined();
    const [start, end] = rangeOf(part!);
    expect(Buffer.from(part!.data).toString()).toBe(PNG);
    expect(data.subarray(start, end).toString()).toBe(PNG);
    expect(part!.descriptor).toMatchObject({
      status: "stored",
      protection_status: "retained",
      object_id: partObjectId(String(skeleton!.descriptor.object_id), 0),
    });
    expect(review!.descriptor).toMatchObject({
      status: "redacted",
      privacy_mode: "original_plus_masked",
      transformation_id: MASK.id,
      links: [
        { relation: "part_of", object_id: skeleton!.descriptor.object_id },
        { relation: "derived_from", object_id: part!.descriptor.object_id },
      ],
    });
    expect(review!.descriptor).not.toHaveProperty("source_sha256");
  });
});

describe("a failed review withholds both objects", () => {
  const oversized: Handler = (_req, _body, res) => {
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end("x".repeat(4096)); // over max_body_bytes (1100 here)
  };
  const failures: [string, () => Promise<RedactionServiceOptions | undefined>][] = [
    ["no transformation or service", async () => undefined],
    ["non-200", async () => ({ endpoint: (await service(status(500))).endpoint })],
    ["timeout", async () => ({ endpoint: (await service(hang)).endpoint, timeoutMs: 100 })],
    ["connection error", async () => ({ endpoint: "unix:///nonexistent/f055-t15/redaction.sock" })],
    ["oversized review", async () => ({ endpoint: (await service(oversized)).endpoint })],
  ];
  const withheld = (object: ContentObject | undefined) => {
    expect(object!.data.byteLength).toBe(0);
    expect(object!.descriptor).toMatchObject({
      status: "not_captured",
      status_reason: "protection_failed",
      protection_status: "withheld",
    });
    expect(object!.descriptor).not.toHaveProperty("source_sha256");
    expect(object!.descriptor).not.toHaveProperty("source_byte_length");
  };

  for (const [name, setup] of failures) {
    it(`whole side: ${name}`, async () => {
      const redaction = await setup();
      const data = Buffer.from('{"messages":[{"content":"' + CANARY + '"}]}');
      const result = await side(
        protectorOf(policy({ request: "original_plus_masked" }), {
          maxBodyBytes: 1100,
          ...(redaction === undefined ? {} : { redaction, transformations: { [REQUEST]: MASK } }),
        }),
        data,
      );
      const [original, review] = result.objects;
      expect(result.objects).toHaveLength(2);
      expect(result.primary).toBeUndefined();
      expect(result.reason).toBe("protection_failed");
      withheld(original);
      withheld(review);
      expect(review!.descriptor.links).toEqual([
        { relation: "derived_from", object_id: original!.descriptor.object_id },
      ]);
      expectNothingOriginal(result, data, [], expect);
    });

    it(`part: ${name}`, async () => {
      const redaction = await setup();
      const data = bigRequest([PNG]);
      const result = await side(
        protectorOf(policy({ request: "retain_original", part: "original_plus_masked" }), {
          maxBodyBytes: 1100,
          ...(redaction === undefined ? {} : { redaction, transformations: { [PART]: MASK } }),
        }),
        data,
      );
      const [skeleton, part, review] = result.objects;
      expect(result.objects).toHaveLength(3);
      expect(result.primary).toBe(skeleton);
      expect(result.reason).toBe("protection_failed");
      withheld(part);
      withheld(review);
      expect(part!.descriptor.links).toEqual([
        { relation: "part_of", object_id: skeleton!.descriptor.object_id },
      ]);
      expect(review!.descriptor.links).toEqual([
        { relation: "part_of", object_id: skeleton!.descriptor.object_id },
        { relation: "derived_from", object_id: part!.descriptor.object_id },
      ]);
      expect(Buffer.from(skeleton!.data).toString()).not.toContain(PNG);
      expect(encodeJson(descriptors(result.objects))).not.toContain(sha(Buffer.from(PNG)).slice(7));
    });
  }
});

describe("the 260-object bound (050 R6)", () => {
  /** A JSON side over `maxBody` with exactly 64 inline parts, and one more past the scan. */
  const sixtyFive = (): Buffer =>
    Buffer.from(
      JSON.stringify({
        items: Array.from({ length: 65 }, (_, i) => ({
          data: Buffer.alloc(60, i).toString("base64"),
        })),
      }),
    );

  it("the largest shape is exactly 260 objects (both sides: skeleton, 64 parts, 64 part reviews, side review) and is admitted", async () => {
    const masker = await service();
    const body = sixtyFive();
    const capture = policy({
      request: "original_plus_masked",
      response: "original_plus_masked",
      part: "original_plus_masked",
    });
    const protector = protectorOf(capture, {
      maxBodyBytes: 2048,
      transformations: { [REQUEST]: MASK, [RESPONSE]: MASK, [PART]: MASK },
      redaction: { endpoint: masker.endpoint, maxInFlight: 4 },
    });
    const job = exchange();
    const prepared = await prepareExchange(
      exchange({
        request: { ...job.request, pieces: [body], observed: body.byteLength },
        response: { ...job.response!, pieces: [body], observed: body.byteLength },
      }),
      { gate: enabledGate(capture), protector, tenantId: TENANT, enrichment: ENRICHMENT },
      "0".repeat(31) + "1",
    );
    expect(prepared.objects).toHaveLength(MAX_EXCHANGE_BODIES);
    expect(MAX_EXCHANGE_BODIES).toBe(260);
    // The 65th part stays in the skeleton: at most 64 parts per side.
    expect(prepared.objects.filter((o) => o.descriptor.role === PART)).toHaveLength(4 * 64);
    expect(prepared.span.attributes["fabric.wire.store_status"]).toBe("stored");
    expect(exchangeEntry("s-x", 1n, "svc", prepared).bodies).toHaveLength(260);
    // One object more is refused before anything is written (the pipeline loses it as
    // internal_error: test/wire/parts/large.test.ts).
    const over = { ...prepared, objects: [...prepared.objects, prepared.objects[0]!] };
    expect(() => exchangeEntry("s-x", 1n, "svc", over)).toThrow(ObjectBoundError);
  });
});

describe("support", () => {
  it("wholePiecePrefix keeps whole pieces only", () => {
    const pieces = [Buffer.alloc(40, 0x61), Buffer.alloc(40, 0x62), Buffer.alloc(40, 0x63)];
    expect(wholePiecePrefix(pieces, 100)).toEqual(Buffer.concat(pieces.slice(0, 2)));
    expect(wholePiecePrefix(pieces, 39).byteLength).toBe(0);
  });
});
