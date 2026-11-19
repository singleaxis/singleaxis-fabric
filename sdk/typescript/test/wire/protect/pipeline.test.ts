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
import {
  CapturePipeline,
  type PipelineConfig,
  type PipelineSink,
} from "../../../src/wire/worker.js";
import { runPython } from "../registration/helpers.js";
import { KEY, cleanupDirs, native, spoolDir } from "../spool/helpers.js";
import { CHAT, type Capture, type Provider, capture, provider, settle } from "../undici/helpers.js";
import { ID_KEY, TENANT, policyDoc } from "./helpers.js";

const MODES = {
  "model.exchange.request": "retain_original",
  "model.exchange.response": "retain_original",
};

function pipelineConfig(overrides: Partial<PipelineConfig> = {}): PipelineConfig {
  return {
    sourceId: "s-" + "cd".repeat(16),
    tenantId: TENANT,
    serviceName: "svc-test",
    node: true,
    store: false,
    spool: true,
    policy: policyDoc(MODES, "production") as never,
    transformations: {},
    redaction: undefined,
    maxBodyBytes: 32 * 1024 * 1024,
    idKey: ID_KEY,
    spoolKey: KEY,
    tokenizationKey: undefined,
    endpoints: [
      { endpointId: "local-openai", providerName: "openai" },
      { endpointId: "local-anthropic", providerName: "anthropic" },
    ],
    enrichment: {
      points: { "wire.ts.undici": "wire.ts.undici@1.0.0" },
      endpointIds: {
        "local-openai": "lbl-" + "1".repeat(32),
        "local-anthropic": "lbl-" + "2".repeat(32),
      },
      identity: {},
      requestIdKey: undefined,
      modelAllowlist: [],
    },
    ...overrides,
  };
}

interface Recorded {
  losses: [string, bigint][];
  notices: [string, string][];
  sink: PipelineSink;
}

function recorder(): Recorded {
  const out: Recorded = { losses: [], notices: [], sink: undefined as never };
  out.sink = {
    lose: (reason, sequence) => out.losses.push([reason, sequence]),
    notice: (id, reason) => out.notices.push([id, reason]),
  };
  return out;
}

/** What the Fabric worker does with each ring record: the pipeline, then the release. */
async function processJobs(cap: Capture, pipeline: CapturePipeline): Promise<string[]> {
  const { runtime, table } = cap;
  const outcomes: string[] = [];
  for (let record = runtime.jobs.peek(); record !== undefined; record = runtime.jobs.peek()) {
    const job = table.job(record.byteOffset);
    outcomes.push(await pipeline.handle(job, table.arena, runtime.epoch));
    table.arena.release(job.request.words);
    table.arena.release(job.response.words);
    runtime.jobs.commit();
  }
  return outcomes;
}

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
  it("writes a protected record that TypeScript and Python both read", async () => {
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
  });

  it("a record the spool refuses is a named loss: queue_full, disk_full, internal_error", async () => {
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
  });

  it("an unreadable job record is an internal_error loss, never a guessed record", async () => {
    cap = capture(server.port);
    await call();
    const seen = recorder();
    const config = pipelineConfig({ endpoints: [] }); // the slot's endpoint index resolves to nothing
    const pipeline = new CapturePipeline(config, {} as Spool, seen.sink);
    expect(await processJobs(cap, pipeline)).toEqual(["internal_error"]);
    expect(pipeline.stats().unreadable).toBe(1);
  });

  it("disabled content is noted once per epoch (FW-008) and still writes safe metadata", async () => {
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
    expect(docs.map(({ doc }) => (doc.span as any).attributes["fabric.wire.store_reason"])).toEqual(
      ["missing_id_key", "missing_id_key"],
    );
  });

  it("a masking role with no redaction service is noted at install (FW-032)", () => {
    const seen = recorder();
    const masked = policyDoc({ "model.exchange.request": "redact" }, "production");
    new CapturePipeline(pipelineConfig({ policy: masked as never }), {} as Spool, seen.sink);
    expect(seen.notices).toEqual([["FW-032", "protection_failed"]]);
  });

  it("content capture without a tenant id is a fixed-text configuration error that names the fix", () => {
    expect(
      () =>
        new CapturePipeline(pipelineConfig({ tenantId: undefined }), {} as Spool, recorder().sink),
    ).toThrow("wire content capture needs a tenant id: set FABRIC_TENANT_ID");
  });
});
