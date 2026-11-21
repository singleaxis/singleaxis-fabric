// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The capture pipeline end to end (spec 055 §5, unit 055-t8): real `fetch` calls through
 * the undici hook, the completed jobs through `CapturePipeline` into a real encrypted
 * spool, read back by TypeScript and by Python's reader; every outcome that is not a
 * spooled record is a named loss; the install notices.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { encodeJson } from "../../../src/wire/codec.js";
import { validHeader } from "../../../src/wire/spool-codec.js";
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
import { policyDoc } from "./helpers.js";
import { pipelineConfig, processJobs, recorder } from "./pipeline-helpers.js";

const PROMPT = Buffer.from(
  '{"model":"gpt-4o","messages":[{"role":"user","content":"PIPELINE-CANARY"}]}',
);
const ANSWER = Buffer.from('{"model":"gpt-4o-2024-08-06","choices":[{"finish_reason":"stop"}]}');

let server: Provider;
let cap: Capture | undefined;
beforeAll(async () => {
  server = await provider();
  server.route(CHAT, (_req, res) => {
    res.writeHead(200, { "content-type": "application/json", "x-request-id": "HEADER-CANARY" });
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
});

async function call(): Promise<void> {
  const response = await fetch(`${server.base}${CHAT}?q=QUERY-CANARY`, {
    method: "POST",
    headers: { authorization: "Bearer AUTH-CANARY", "content-type": "application/json" },
    body: PROMPT,
  });
  await response.arrayBuffer();
  await settle();
}

describe("capture pipeline into the spool", () => {
  it.skipIf(!PUBLISHES_BODIES)(
    "writes a protected record that TypeScript and Python both read",
    async () => {
      const dir = spoolDir();
      const spool = new Spool(dir, { maxBytes: 1 << 20, addon: native().addon, key: KEY });
      const seen = recorder();
      const pipeline = new CapturePipeline(pipelineConfig(), spool, seen.sink);
      cap = capture(server.port);
      await call();
      expect(await processJobs(cap, pipeline)).toEqual(["spooled"]);
      expect(seen.losses).toEqual([]);

      expect(spool.tryLock()).toBe(true);
      const scan = spool.recover();
      spool.release();
      expect(scan.files).toHaveLength(1);
      const { doc, blob } = scan.files[0]!.records[0]!;
      expect(validHeader(doc, blob.length)).toBe(true);
      expect(blob).toEqual(Buffer.concat([PROMPT, ANSWER]));
      const attributes = (doc.span as any).attributes;
      expect(attributes).toMatchObject({
        "fabric.wire.store_status": "stored",
        "fabric.capture.point": "wire.ts.undici@1.0.0",
        "fabric.wire.endpoint_id": "lbl-" + "1".repeat(32),
        "gen_ai.response.model": "gpt-4o-2024-08-06",
        "http.response.status_code": 200,
      });
      const header = encodeJson(doc);
      for (const canary of [
        "QUERY-CANARY",
        "AUTH-CANARY",
        "HEADER-CANARY",
        "127.0.0.1",
        "/v1/chat",
      ]) {
        expect(header).not.toContain(canary);
      }

      const python = runPython(
        String.raw`
import json, sys
from fabric.wire._spool import Spool, unframe_all, valid_header
spool = Spool(sys.argv[1], 1 << 20, key=bytes.fromhex(sys.argv[2]))
try:
    out = []
    for name in spool.names():
        for doc, blob in unframe_all(spool.read(name)):
            out.append({"valid": valid_header(doc, len(blob)), "blob": bytes(blob).hex(),
                        "status": doc["span"]["attributes"]["fabric.wire.store_status"]})
    print(json.dumps(out))
finally:
    spool.release()
`,
        [dir, KEY.toString("hex")],
      );
      expect(python).toEqual([
        { valid: true, blob: Buffer.concat([PROMPT, ANSWER]).toString("hex"), status: "stored" },
      ]);
    },
    60_000, // a Python subprocess: the 5 s default flakes under a loaded full-suite run
  );

  it.skipIf(!PUBLISHES_BODIES)(
    "a record the spool refuses is a named loss: queue_full, disk_full, internal_error",
    async () => {
      cap = capture(server.port);
      for (let i = 0; i < 4; i++) await call();
      const outcomes: unknown[] = [
        null,
        Object.assign(new Error("no space"), { code: "ENOSPC" }),
        new Error("EIO"),
      ];
      const fake = {
        writeBatch: () => {
          const next = outcomes.shift();
          if (next === undefined) throw new Error("spool gone");
          return [next];
        },
      } as unknown as Spool;
      const seen = recorder();
      const pipeline = new CapturePipeline(pipelineConfig(), fake, seen.sink);
      const result = await processJobs(cap, pipeline);
      expect(result).toEqual(["queue_full", "disk_full", "internal_error", "internal_error"]);
      expect(seen.losses.map(([reason]) => reason)).toEqual(result);
      expect(seen.losses.map(([, sequence]) => sequence)).toEqual([0n, 1n, 2n, 3n]);
      expect(pipeline.stats().outcomes).toEqual({
        spooled: 0,
        queue_full: 1,
        disk_full: 1,
        internal_error: 2,
      });
    },
  );

  it.skipIf(!PUBLISHES_BODIES)(
    "an unreadable job record is an internal_error loss, never a guessed record",
    async () => {
      cap = capture(server.port);
      await call();
      const seen = recorder();
      const config = pipelineConfig({ endpoints: [] }); // the slot's endpoint index resolves to nothing
      const pipeline = new CapturePipeline(config, {} as Spool, seen.sink);
      expect(await processJobs(cap, pipeline)).toEqual(["internal_error"]);
      expect(pipeline.stats().unreadable).toBe(1);
    },
  );

  it.skipIf(!PUBLISHES_BODIES)(
    "disabled content is noted once per epoch (FW-008) and still writes safe metadata",
    async () => {
      const dir = spoolDir();
      const spool = new Spool(dir, { maxBytes: 1 << 20, addon: native().addon, key: KEY });
      const seen = recorder();
      const pipeline = new CapturePipeline(pipelineConfig({ idKey: undefined }), spool, seen.sink);
      expect(pipeline.gate.reason).toBe("missing_id_key");
      cap = capture(server.port);
      await call();
      await call();
      expect(await processJobs(cap, pipeline)).toEqual(["spooled", "spooled"]);
      expect(seen.notices).toEqual([["FW-008", "missing_id_key"]]);
      expect(spool.tryLock()).toBe(true);
      const docs = spool.recover().files.flatMap((f) => f.records);
      spool.release();
      expect(docs.map(({ blob }) => blob.length)).toEqual([0, 0]);
      expect(
        docs.map(({ doc }) => (doc.span as any).attributes["fabric.wire.store_reason"]),
      ).toEqual(["missing_id_key", "missing_id_key"]);
    },
  );

  it("a masking role with no redaction service is noted at install (FW-032)", () => {
    const seen = recorder();
    const masked = policyDoc({ "model.exchange.request": "redact" }, "production");
    new CapturePipeline(pipelineConfig({ policy: masked as never }), {} as Spool, seen.sink);
    expect(seen.notices).toEqual([["FW-032", "protection_failed"]]);
  });

  it("original_plus_masked with nothing to make the review copy is noted at install too (FW-032)", () => {
    for (const privacy of [
      { "model.exchange.response": "original_plus_masked" },
      {
        "model.exchange.request": "retain_original",
        "model.exchange.part": "original_plus_masked",
      },
    ]) {
      const seen = recorder();
      const masked = policyDoc(privacy, "production");
      new CapturePipeline(pipelineConfig({ policy: masked as never }), {} as Spool, seen.sink);
      expect(seen.notices).toEqual([["FW-032", "protection_failed"]]);
    }
    // A redacted part with no transformation is withheld by policy, not a missing service.
    const seen = recorder();
    const policy = policyDoc(
      { "model.exchange.request": "retain_original", "model.exchange.part": "redact" },
      "production",
    );
    new CapturePipeline(pipelineConfig({ policy: policy as never }), {} as Spool, seen.sink);
    expect(seen.notices).toEqual([]);
  });

  it.skipIf(!PUBLISHES_BODIES)(
    "a masking role with no redaction service is noted again at the first exchange of each epoch (FW-032)",
    async () => {
      const seen = recorder();
      const masked = policyDoc({ "model.exchange.request": "redact" }, "production");
      const written: unknown[] = [];
      const fake = {
        writeBatch: (entries: readonly unknown[]) => {
          written.push(...entries);
          return entries.map(() => "rec");
        },
      } as unknown as Spool;
      const pipeline = new CapturePipeline(
        pipelineConfig({ policy: masked as never }),
        fake,
        seen.sink,
      );
      cap = capture(server.port);
      await call();
      await call();
      expect(await processJobs(cap, pipeline)).toEqual(["spooled", "spooled"]);
      // install, then once for the epoch: never per exchange
      expect(seen.notices).toEqual([
        ["FW-032", "protection_failed"],
        ["FW-032", "protection_failed"],
      ]);
      const reasons = written.map(
        (entry) =>
          ((entry as any).doc.bodies[0].descriptor as Record<string, unknown>).status_reason,
      );
      expect(reasons).toEqual(["protection_failed", "protection_failed"]);
    },
  );

  it.skipIf(!PUBLISHES_BODIES)(
    "an exchange over 260 objects is an accounted internal_error loss and writes nothing (R6)",
    async () => {
      const seen = recorder();
      let writes = 0;
      const fake = {
        writeBatch: (entries: readonly unknown[]) => {
          writes += 1;
          return entries.map(() => "rec");
        },
      } as unknown as Spool;
      const pipeline = new CapturePipeline(pipelineConfig(), fake, seen.sink);
      // Whole-object modes make at most two objects per side; a side that made 131 (as
      // split parts and review copies can, 055-t15) puts the exchange at 262.
      const protector = pipeline.protector!;
      const side = protector.side.bind(protector);
      protector.side = async (...args: Parameters<typeof side>) => {
        const result = await side(...args);
        return {
          ...result,
          objects: Array<(typeof result.objects)[number]>(131).fill(result.objects[0]!),
        };
      };
      cap = capture(server.port);
      await call();
      expect(await processJobs(cap, pipeline)).toEqual(["internal_error"]);
      expect(writes).toBe(0);
      expect(seen.losses.map(([reason]) => reason)).toEqual(["internal_error"]);
      expect(pipeline.stats().outcomes.internal_error).toBe(1);
    },
  );

  it("content capture without a tenant id is a fixed-text configuration error that names the fix", () => {
    expect(
      () =>
        new CapturePipeline(pipelineConfig({ tenantId: undefined }), {} as Spool, recorder().sink),
    ).toThrow("wire content capture needs a tenant id: set FABRIC_TENANT_ID");
  });

  // §3.1: Node 22 and Node 24.0–24.3 publish no body chunks, so the hook installs nothing
  // and the pipeline is handed nothing to protect or write; the call itself is unchanged.
  it.skipIf(PUBLISHES_BODIES)(
    "a Node build without body publications gives it nothing to write",
    async () => {
      const dir = spoolDir();
      const spool = new Spool(dir, { maxBytes: 1 << 20, addon: native().addon, key: KEY });
      const pipeline = new CapturePipeline(pipelineConfig(), spool, recorder().sink);
      cap = capture(server.port);
      const response = await fetch(`${server.base}${CHAT}`, { method: "POST", body: PROMPT });
      expect(Buffer.from(await response.arrayBuffer())).toEqual(ANSWER);
      await settle();
      expect(await processJobs(cap, pipeline)).toEqual([]);
      expect(spool.tryLock()).toBe(true);
      expect(spool.recover().files).toEqual([]);
      spool.release();
    },
  );
});
