// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Manifests and heartbeats through the Fabric worker's capture pipeline (spec 055 §7.2,
 * 055-t9): manifest 0 is spooled ahead of the epoch's first exchange record, a state
 * change is the next chained manifest, the tick queues periodic heartbeats for the
 * sender, and `final` is spooled last. Python's drainer reads every marker.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { NODE_HTTP_POINT, UNDICI_POINT, manifestTemplate } from "../../../src/wire/manifest.js";
import { decideGate } from "../../../src/wire/protect.js";
import { Spool } from "../../../src/wire/spool.js";
import { CapturePipeline, type PipelineConfig } from "../../../src/wire/worker.js";

import { ID_KEY, TENANT, policyDoc } from "../protect/helpers.js";
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
import { settingsFor } from "./helpers.js";

const SOURCE = "s-" + "cd".repeat(16);
const MODES = {
  "model.exchange.request": "retain_original",
  "model.exchange.response": "retain_original",
};
const RUNTIME = { node: "24.4.0", undici: "7.11.0", platform: "linux-x64-glibc" };

function config(): PipelineConfig {
  const policy = policyDoc(MODES, "production");
  const gate = decideGate({
    node: true,
    store: false,
    policy: undefined,
    idKey: true,
    spool: true,
    spoolKey: true,
  });
  const template = manifestTemplate(settingsFor(undefined), {
    sourceId: SOURCE,
    gate,
    states: {
      [UNDICI_POINT]: ["active", undefined],
      [NODE_HTTP_POINT]: ["disabled", "hook_disabled"],
    },
    runtime: RUNTIME,
  });
  return {
    sourceId: SOURCE,
    tenantId: TENANT,
    serviceName: "svc-test",
    node: true,
    store: false,
    spool: true,
    policy: policy as never,
    transformations: {},
    redaction: undefined,
    maxBodyBytes: 32 * 1024 * 1024,
    idKey: ID_KEY,
    spoolKey: KEY,
    tokenizationKey: undefined,
    endpoints: [{ endpointId: "local-openai", providerName: "openai" }],
    enrichment: {
      points: { [UNDICI_POINT]: `${UNDICI_POINT}@1.0.0` },
      endpointIds: { "local-openai": "lbl-" + "1".repeat(32) },
      identity: {},
      requestIdKey: undefined,
      modelAllowlist: [],
    },
    manifest: { template, unsealed: { epochs: [3n, 4n], count: 2 } },
  };
}

const sink = { lose: () => undefined };

/** Python's drainer over the spool: each record's kind, marker kind and header check. */
const PY_KINDS = `
import json, sys
from fabric.wire._spool import Spool, unframe_all, valid_header
spool = Spool(sys.argv[1], 1 << 20, key=bytes.fromhex(sys.argv[2]))
out = []
try:
    for name in spool.names():
        for doc, blob in unframe_all(spool.read(name)):
            marker = doc.get("marker") or {}
            out.append([doc["record_kind"], marker.get("kind"), valid_header(doc, len(blob))])
finally:
    spool.release()
print(json.dumps(out))
`;

const pyKinds = (dir: string) => runPython(PY_KINDS, [dir, KEY.toString("hex")]);

let server: Provider;
let cap: Capture | undefined;
beforeAll(async () => {
  server = await provider();
  server.route(CHAT, (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"choices":[]}');
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

describe("manifests through the capture pipeline", () => {
  it("spools manifest 0 on the first tick, then changes and final in order", () => {
    const dir = spoolDir();
    const spool = new Spool(dir, { maxBytes: 1 << 20, addon: native().addon, key: KEY });
    const pipeline = new CapturePipeline(config(), spool, sink);
    pipeline.tick(9n, -1n);
    pipeline.tick(9n, -1n); // nothing new: manifest 0 once, no heartbeat due yet
    expect(spool.mine.size).toBe(1);
    const zero = pipeline.manifests!.document!;
    expect([zero.manifest_seq, zero.after_source_sequence]).toEqual([0, -1]);
    expect([zero.unsealed_prior_epochs, zero.unsealed_prior_epoch_count]).toEqual([[3, 4], 2]);
    pipeline.pointChanged(9n, UNDICI_POINT, "failed", "internal_error", 6n);
    pipeline.classUncaptured(9n, "node_worker_unattached", 6n);
    expect(pipeline.final(9n, 6n)).toBe(true);
    expect(pipeline.stats().manifests).toMatchObject({
      manifestSeq: 2,
      held: 0,
      spooled: 4,
      dropped: 0,
    });
    expect(pyKinds(dir)).toEqual([
      ["marker", "manifest", true],
      ["marker", "manifest", true],
      ["marker", "manifest", true],
      ["marker", "final", true],
    ]);
    // A later epoch (after final) starts with its own manifest 0, without the scan's list.
    pipeline.tick(10n, -1n);
    const next = pipeline.manifests!.document!;
    expect([next.source_epoch, next.manifest_seq, next.unsealed_prior_epoch_count]).toEqual([
      10, 0, 0,
    ]);
    spool.close();
  });

  it.skipIf(!PUBLISHES_BODIES)(
    "spools manifest 0 ahead of the epoch's first exchange record",
    async () => {
      const dir = spoolDir();
      const spool = new Spool(dir, { maxBytes: 1 << 20, addon: native().addon, key: KEY });
      const pipeline = new CapturePipeline(config(), spool, sink);
      cap = capture(server.port);
      const response = await fetch(`${server.base}${CHAT}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: '{"model":"gpt-4o"}',
      });
      await response.arrayBuffer();
      await settle();
      const { runtime, table } = cap;
      for (let record = runtime.jobs.peek(); record !== undefined; record = runtime.jobs.peek()) {
        const job = table.job(record.byteOffset);
        expect(job.sequence).toBe(0n);
        expect(await pipeline.handle(job, table.arena, runtime.epoch)).toBe("spooled");
        table.arena.release(job.request.words);
        table.arena.release(job.response.words);
        runtime.jobs.commit();
      }
      expect(pyKinds(dir)).toEqual([
        ["marker", "manifest", true],
        ["exchange", null, true],
      ]);
      // The source allocated: the next due tick queues a periodic heartbeat for the sender.
      pipeline.tick(runtime.epoch, runtime.nextSequence - 1n);
      expect(pipeline.heartbeats!.pending).toEqual([]);
      expect(pipeline.heartbeats!.tick(runtime.epoch, 0n, true)).toMatchObject({
        kind: "periodic",
        lastSequence: 0n,
        manifestSeq: 0,
      });
      spool.close();
    },
  );
});
