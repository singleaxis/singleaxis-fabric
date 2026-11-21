// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The fixture replayer (spec 055 §13.2, unit 055-t13): `replayExchange(fixture)` sends a
 * recorded request/response fixture through the real undici hook and the real capture
 * pipeline (PROTECT, the `fabric.model_call` span, spool admission, manifests, seals and
 * `final`) and returns the spool directory it wrote, sealed under {@link KEY}. Spec 057
 * WP7-16 replays its dialect fixtures through it and reads the result with
 * `python -m fabric.reconstruct`; nothing here knows a dialect beyond the endpoint path.
 *
 * A scripted loopback provider answers the fixture's response (its chunks written in
 * order); the global `fetch` of this process sends the fixture's request bytes. The
 * Fabric worker's loop is run in this isolate, one pass, as `consume` runs it. Needs a
 * Node build that publishes the body channels (24.4 or newer).
 */
import { randomBytes } from "node:crypto";

import { NODE_HTTP_POINT, UNDICI_POINT, manifestTemplate } from "../../../src/wire/manifest.js";
import { nativeTarget } from "../../../src/wire/native.js";
import { decideGate } from "../../../src/wire/protect.js";
import type { ExchangeTable } from "../../../src/wire/exchange.js";
import type { WireRuntime } from "../../../src/wire/runtime.js";
import { Spool } from "../../../src/wire/spool.js";
import {
  CapturePipeline,
  type PipelineConfig,
  pipelineHandlers,
  runtimeSink,
} from "../../../src/wire/worker.js";

import { settingsFor } from "../manifest/helpers.js";
import { ID_KEY, TENANT, policyDoc } from "../protect/helpers.js";
import { KEY, native, spoolDir } from "../spool/helpers.js";
import { capture, provider, settle } from "../undici/helpers.js";

export { KEY };

/** One recorded exchange. Bytes are given as text (UTF-8) or as bytes. */
export interface ExchangeFixture {
  /** `openai` (default, `/v1/chat/completions`) or `anthropic` (`/anthropic/v1/messages`). */
  readonly dialect?: "openai" | "anthropic";
  /** The request path (default by dialect). */
  readonly path?: string;
  readonly request: string | Uint8Array;
  readonly requestHeaders?: Readonly<Record<string, string>>;
  readonly status?: number;
  readonly responseHeaders?: Readonly<Record<string, string>>;
  /** The response body, or its chunks (written in order, as a stream). */
  readonly response: string | Uint8Array | readonly (string | Uint8Array)[];
}

export interface ReplayOptions {
  /** The privacy mode of both exchange roles (default `retain_original`). */
  readonly mode?: string;
  /** The source id of the capture (default: a random `s-` id). */
  readonly sourceId?: string;
}

export interface Replayed {
  /** The spool directory (sealed under {@link KEY}). */
  readonly dir: string;
  readonly sourceId: string;
  readonly epoch: bigint;
  /** What the provider received and what the application read. */
  readonly received: Buffer;
  readonly read: Buffer;
  readonly status: number;
  /** `true` when the epoch closed in order (seals and `final` in the spool). */
  readonly closed: boolean;
}

const bytes = (value: string | Uint8Array): Buffer =>
  typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);

function config(sourceId: string, mode: string): PipelineConfig {
  const gate = decideGate({
    node: true,
    store: false,
    policy: undefined,
    idKey: true,
    spool: true,
    spoolKey: true,
  });
  const template = manifestTemplate(settingsFor(undefined), {
    sourceId,
    gate,
    states: {
      [UNDICI_POINT]: ["active", undefined],
      [NODE_HTTP_POINT]: ["disabled", "hook_disabled"],
    },
    runtime: {
      node: process.versions.node,
      undici: process.versions.undici,
      // The manifest states the platform this replay ran on.
      platform: nativeTarget() ?? "linux-x64-glibc",
    },
  });
  const roles = { "model.exchange.request": mode, "model.exchange.response": mode };
  return {
    sourceId,
    tenantId: TENANT,
    serviceName: "svc-replay",
    node: true,
    store: false,
    spool: true,
    policy: policyDoc(roles, "production") as never,
    transformations: {},
    redaction: undefined,
    maxBodyBytes: 32 * 1024 * 1024,
    idKey: ID_KEY,
    spoolKey: KEY,
    tokenizationKey: undefined,
    // The order of the hook's endpoints (`undici/helpers.ts` `capture`).
    endpoints: [
      { endpointId: "local-openai", providerName: "openai" },
      { endpointId: "local-anthropic", providerName: "anthropic" },
    ],
    enrichment: {
      points: { [UNDICI_POINT]: `${UNDICI_POINT}@1.0.0` },
      endpointIds: { "local-openai": "openai.default", "local-anthropic": "anthropic.default" },
      identity: {},
      requestIdKey: undefined,
      modelAllowlist: [],
    },
    manifest: { template, unsealed: { epochs: [], count: 0 } },
  };
}

/** One pass of the Fabric worker's loop over what is queued (runs, jobs, losses, tick). */
async function workerPass(
  pipeline: CapturePipeline,
  runtime: WireRuntime,
  table: ExchangeTable,
): Promise<void> {
  const handlers = pipelineHandlers(pipeline);
  const context = { runtime, exchanges: table, snapshot: undefined };
  const runs = async (): Promise<void> => {
    const ring = runtime.runRing;
    for (let r = ring?.peek(); r !== undefined; r = ring!.peek()) {
      await handlers.run!(r.body, context);
      ring!.commit();
    }
  };
  await runs();
  for (let record = runtime.jobs.peek(); record !== undefined; record = runtime.jobs.peek()) {
    await runs();
    const job = table.job(record.byteOffset);
    await handlers.job!(job, context);
    table.arena.release(job.request.words);
    table.arena.release(job.response.words);
    runtime.jobs.commit();
  }
  for (let loss = runtime.peekLoss(); loss !== undefined; loss = runtime.peekLoss()) {
    await handlers.loss!(loss, context);
    runtime.commitLoss();
  }
  await handlers.tick!(context);
}

/**
 * Sends `fixture` through the real hook and pipeline; returns the spool directory with
 * manifest 0, the exchange record, the seals and `final`.
 */
export async function replayExchange(
  fixture: ExchangeFixture,
  options: ReplayOptions = {},
): Promise<Replayed> {
  const anthropic = fixture.dialect === "anthropic";
  const path = fixture.path ?? (anthropic ? "/anthropic/v1/messages" : "/v1/chat/completions");
  const server = await provider();
  const chunks = (Array.isArray(fixture.response) ? fixture.response : [fixture.response]) as (
    string | Uint8Array
  )[];
  server.route(path.split("?")[0]!, (_req, res) => {
    res.writeHead(fixture.status ?? 200, {
      "content-type": "application/json",
      ...fixture.responseHeaders,
    });
    void (async () => {
      for (const chunk of chunks) {
        res.write(bytes(chunk));
        await new Promise((resolve) => setImmediate(resolve));
      }
      res.end();
    })();
  });
  const cap = capture(server.port);
  const sourceId = options.sourceId ?? "s-" + randomBytes(16).toString("hex");
  const dir = spoolDir();
  const spool = new Spool(dir, { maxBytes: 1 << 26, addon: native().addon, key: KEY });
  try {
    const pipeline = new CapturePipeline(
      config(sourceId, options.mode ?? "retain_original"),
      spool,
      runtimeSink(cap.runtime),
    );
    await workerPass(pipeline, cap.runtime, cap.table); // manifest 0 first
    const response = await fetch(server.base + path, {
      method: "POST",
      headers: { "content-type": "application/json", ...fixture.requestHeaders },
      body: bytes(fixture.request),
    });
    const read = Buffer.from(await response.arrayBuffer());
    await settle();
    cap.close();
    await workerPass(pipeline, cap.runtime, cap.table);
    const closed = pipeline.closeEpoch(cap.runtime.epoch, cap.runtime.nextSequence - 1n);
    await pipeline.close();
    return {
      dir,
      sourceId,
      epoch: cap.runtime.epoch,
      received: server.received.at(-1) ?? Buffer.alloc(0),
      read,
      status: response.status,
      closed,
    };
  } finally {
    cap.close();
    spool.close();
    await server.close();
  }
}
