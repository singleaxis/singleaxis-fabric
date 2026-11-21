// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Large request shapes end to end (spec 055 §5, §9.2; unit 055-t15): real `fetch` calls
 * through the undici hook and `CapturePipeline` into a real encrypted spool, read back by
 * TypeScript and by Python.
 *
 * - A 40 MiB request with one inline image keeps its text (the skeleton) and its image
 *   (a `model.exchange.part`), and the two reassemble to the request's `source_sha256`.
 * - A 70 MiB request is `truncated(body_cap)`: the hook retains at most
 *   `max_retain_bytes`, and the stored object is the longest whole-piece prefix within
 *   `max_body_bytes`.
 * - An exchange whose PROTECT result would exceed 260 objects is an `internal_error`
 *   loss, never a shortened object list. The 260 shape is the largest PROTECT can make
 *   (split.test.ts), so the 261st object is injected here.
 */
import { createHash } from "node:crypto";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import type { ContentObject, SideResult } from "../../../src/wire/protect.js";
import { Spool } from "../../../src/wire/spool.js";
import { CapturePipeline } from "../../../src/wire/worker.js";
import { runPython } from "../registration/helpers.js";
import { KEY, cleanupDirs, native, spoolDir } from "../spool/helpers.js";
import {
  CHAT,
  PUBLISHES_BODIES,
  type Capture,
  type Provider,
  capture,
  provider,
  settle,
} from "../undici/helpers.js";
import { policyDoc } from "../protect/helpers.js";
import { pipelineConfig, processJobs, recorder } from "../protect/pipeline-helpers.js";
import { PART, REQUEST, RESPONSE, CANARY } from "./helpers.js";

const MIB = 1024 * 1024;
const ANSWER = Buffer.from('{"model":"gpt-4o-2024-08-06","choices":[{"finish_reason":"stop"}]}');
const RETAIN_ALL = policyDoc(
  { [REQUEST]: "retain_original", [RESPONSE]: "retain_original", [PART]: "retain_original" },
  "production",
);
const sha = (data: Uint8Array): string =>
  "sha256:" + createHash("sha256").update(data).digest("hex");

let server: Provider;
let cap: Capture | undefined;
beforeAll(async () => {
  server = await provider();
  server.route(CHAT, (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(ANSWER);
  });
});
afterAll(async () => {
  await server.close();
  cleanupDirs();
});
afterEach(() => {
  cap?.close();
  cap = undefined;
  server.received.length = 0;
});

function bigCapture(): Capture {
  return capture(server.port, {
    // No Fabric worker grows the arena in these tests: commit room for a 64 MiB side
    // and the response up front.
    runtime: {
      maxInflightBytes: 160 * MIB,
      maxRetainBytes: 64 * MIB,
      initialPayloadBytes: 80 * MIB,
    },
  });
}

async function post(body: Buffer | ReadableStream<Uint8Array>): Promise<void> {
  const response = await fetch(`${server.base}${CHAT}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
    ...(body instanceof ReadableStream ? { duplex: "half" } : {}),
  } as RequestInit);
  await response.arrayBuffer();
  await settle();
}

/** A request stream of `size` bytes in 1 MiB chunks. */
function streamed(size: number): ReadableStream<Uint8Array> {
  let sent = 0;
  return new ReadableStream({
    pull(controller) {
      if (sent >= size) return controller.close();
      const part = Math.min(MIB, size - sent);
      controller.enqueue(new Uint8Array(part).fill(0x61));
      sent += part;
    },
  });
}

/** The one spooled record: its span attributes and its objects (descriptor, bytes). */
function readRecord(spool: Spool): { attributes: any; objects: ContentObject[] } {
  expect(spool.tryLock()).toBe(true);
  const records = spool.recover().files.flatMap((f) => f.records);
  spool.release();
  expect(records).toHaveLength(1);
  const { doc, blob } = records[0]!;
  const bodies = doc.bodies as {
    descriptor: Record<string, unknown>;
    offset: number;
    length: number;
  }[];
  return {
    attributes: (doc.span as any).attributes,
    objects: bodies.map((b) => ({
      descriptor: b.descriptor,
      data: blob.subarray(Number(b.offset), Number(b.offset) + Number(b.length)),
    })),
  };
}

describe("large request shapes", () => {
  it.skipIf(!PUBLISHES_BODIES)(
    "a 40 MiB request with one inline image keeps its text and reassembles to source_sha256",
    async () => {
      const image = Buffer.concat([
        Buffer.from("\x89PNG\r\n\x1a\n", "latin1"),
        Buffer.alloc(22.5 * MIB, 7),
      ]).toString("base64"); // 30 MiB of base64
      const text = `describe ${CANARY} ` + "lorem ipsum ".repeat(Math.ceil((10.5 * MIB) / 12));
      const body = Buffer.from(
        JSON.stringify({
          model: "gpt-4o",
          messages: [
            {
              role: "user",
              content: [
                { type: "text", text },
                { type: "image_url", image_url: { url: "data:image/png;base64," + image } },
                { type: "text", text: "END-" + CANARY },
              ],
            },
          ],
        }),
      );
      expect(body.byteLength).toBeGreaterThan(40 * MIB);
      expect(body.byteLength).toBeLessThan(41 * MIB);

      const dir = spoolDir();
      const spool = new Spool(dir, { maxBytes: 256 * MIB, addon: native().addon, key: KEY });
      const seen = recorder();
      const pipeline = new CapturePipeline(
        pipelineConfig({
          policy: RETAIN_ALL as never,
          maxRetainBytes: 64 * MIB,
          partMinBytes: 64 * 1024,
        }),
        spool,
        seen.sink,
      );
      cap = bigCapture();
      await post(body);
      expect(server.received[0]!.equals(body)).toBe(true); // the server saw the request unchanged
      expect(await processJobs(cap, pipeline)).toEqual(["spooled"]);
      expect(seen.losses).toEqual([]);

      const { attributes, objects } = readRecord(spool);
      expect(attributes).toMatchObject({
        "fabric.wire.store_status": "stored",
        "fabric.wire.truncated": false,
      });
      expect(attributes).not.toHaveProperty("fabric.wire.store_reason");
      const [skeleton, part, response] = objects;
      expect(objects.map((o) => o.descriptor.role)).toEqual([REQUEST, PART, RESPONSE]);
      expect(skeleton!.descriptor).toMatchObject({
        representation: "split",
        transformations: ["extract_parts"],
        source_sha256: sha(body),
        source_byte_length: body.byteLength,
      });
      expect(attributes["fabric.wire.request_sha256"]).toBe(
        String(skeleton!.descriptor.stored_sha256).slice(7),
      );
      const skeletonText = Buffer.from(skeleton!.data).toString();
      expect(skeletonText).toContain(`describe ${CANARY}`);
      expect(skeletonText).toContain("END-" + CANARY);
      expect(part!.descriptor).toMatchObject({
        media_type: "image/png",
        content_encoding: "base64",
      });
      expect(part!.data.byteLength).toBe(image.length);
      const [start, end] = (part!.descriptor.links as { byte_range: [number, number] }[])[0]!
        .byte_range;
      const reassembled = Buffer.concat([
        skeleton!.data.subarray(0, start!),
        part!.data,
        skeleton!.data.subarray(start!),
      ]);
      expect(end! - start!).toBe(image.length);
      expect(sha(reassembled)).toBe(skeleton!.descriptor.source_sha256);
      expect(Buffer.from(response!.data)).toEqual(ANSWER);

      // Python's spool reader takes the same record and reassembles it the same way.
      const python = runPython(
        String.raw`
import hashlib, json, sys
from fabric.wire._spool import Spool, unframe_all, valid_header
spool = Spool(sys.argv[1], 1 << 30, key=bytes.fromhex(sys.argv[2]))
try:
    out = []
    for name in spool.names():
        for doc, blob in unframe_all(spool.read(name)):
            blob = bytes(blob)
            objs = [(b["descriptor"], blob[b["offset"]:b["offset"] + b["length"]]) for b in doc["bodies"]]
            skeleton = objs[0][1]
            parts = sorted((d["links"][0]["byte_range"], data) for d, data in objs if d["role"] == "model.exchange.part")
            whole, pos, consumed = b"", 0, 0
            for (start, end), data in parts:
                take = start - consumed
                whole += skeleton[pos:pos + take] + data
                pos, consumed = pos + take, end
            whole += skeleton[pos:]
            out.append({"valid": valid_header(doc, len(blob)),
                        "reassembled": "sha256:" + hashlib.sha256(whole).hexdigest(),
                        "source": objs[0][0]["source_sha256"]})
    print(json.dumps(out))
finally:
    spool.release()
`,
        [dir, KEY.toString("hex")],
      );
      expect(python).toEqual([{ valid: true, reassembled: sha(body), source: sha(body) }]);
    },
    180_000,
  );

  it.skipIf(!PUBLISHES_BODIES)(
    "a 70 MiB side is truncated(body_cap), streamed (a whole-piece prefix) or in one chunk (nothing)",
    async () => {
      const dir = spoolDir();
      const spool = new Spool(dir, { maxBytes: 256 * MIB, addon: native().addon, key: KEY });
      const seen = recorder();
      const pipeline = new CapturePipeline(
        pipelineConfig({ policy: RETAIN_ALL as never, maxRetainBytes: 64 * MIB }),
        spool,
        seen.sink,
      );
      cap = bigCapture();
      await post(streamed(70 * MIB));
      expect(server.received[0]!.byteLength).toBe(70 * MIB); // forwarded whole
      expect(await processJobs(cap, pipeline)).toEqual(["spooled"]);
      const { attributes, objects } = readRecord(spool);
      expect(attributes).toMatchObject({
        "fabric.wire.store_status": "stored",
        "fabric.wire.store_reason": "body_cap",
        "fabric.wire.truncated": true,
      });
      const request = objects[0]!;
      expect(request.descriptor).toMatchObject({
        role: REQUEST,
        status: "truncated",
        representation: "truncated",
        transformations: ["truncate"],
      });
      expect(request.descriptor).not.toHaveProperty("source_sha256");
      expect(request.data.byteLength).toBeGreaterThan(0);
      expect(request.data.byteLength).toBeLessThanOrEqual(32 * MIB);
      expect(request.data.every((byte) => byte === 0x61)).toBe(true);

      // One 70 MiB chunk is over max_retain_bytes: refused whole, so no request bytes.
      const dir2 = spoolDir();
      const spool2 = new Spool(dir2, { maxBytes: 256 * MIB, addon: native().addon, key: KEY });
      const pipeline2 = new CapturePipeline(
        pipelineConfig({ policy: RETAIN_ALL as never, maxRetainBytes: 64 * MIB }),
        spool2,
        seen.sink,
      );
      await post(Buffer.alloc(70 * MIB, 0x62));
      expect(await processJobs(cap, pipeline2)).toEqual(["spooled"]);
      const whole = readRecord(spool2);
      expect(whole.attributes).toMatchObject({
        "fabric.wire.store_status": "partial",
        "fabric.wire.store_reason": "body_cap",
        "fabric.wire.truncated": true,
      });
      expect(whole.objects.map((o) => o.descriptor.role)).toEqual([RESPONSE]);
      expect(seen.losses).toEqual([]);
    },
    180_000,
  );

  it.skipIf(!PUBLISHES_BODIES)(
    "an exchange above 260 objects is an internal_error loss, never a shortened record",
    async () => {
      const dir = spoolDir();
      const spool = new Spool(dir, { maxBytes: 16 * MIB, addon: native().addon, key: KEY });
      const seen = recorder();
      const pipeline = new CapturePipeline(pipelineConfig(), spool, seen.sink);
      const protector = pipeline.protector!;
      const original = protector.side.bind(protector);
      // Test-only fault: the request side comes back with 261 objects.
      protector.side = async (...args: Parameters<typeof original>): Promise<SideResult> => {
        const result = await original(...args);
        if (args[1] === REQUEST) {
          const first = result.objects[0]!;
          while (result.objects.length < 261) result.objects.push(first);
        }
        return result;
      };
      cap = capture(server.port);
      await post(Buffer.from('{"model":"gpt-4o","messages":[]}'));
      expect(await processJobs(cap, pipeline)).toEqual(["internal_error"]);
      expect(seen.losses).toEqual([["internal_error", 0n]]);
      expect(pipeline.stats().outcomes.internal_error).toBe(1);
      expect(spool.tryLock()).toBe(true);
      expect(spool.recover().files).toHaveLength(0);
      spool.release();
    },
  );
});
