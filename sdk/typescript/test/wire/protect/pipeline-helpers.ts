// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the capture-pipeline tests (spec 055 §5; units 055-t8, 055-t15): the
 * pipeline configuration, a sink that records losses and notices, and the Fabric
 * worker's job loop (the pipeline, then the release of the job's slabs).
 */
import {
  type CapturePipeline,
  type PipelineConfig,
  type PipelineSink,
} from "../../../src/wire/worker.js";
import type { Capture } from "../undici/helpers.js";
import { ID_KEY, TENANT, policyDoc } from "./helpers.js";
import { KEY } from "../spool/helpers.js";

const MODES = {
  "model.exchange.request": "retain_original",
  "model.exchange.response": "retain_original",
};

export function pipelineConfig(overrides: Partial<PipelineConfig> = {}): PipelineConfig {
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

export interface Recorded {
  losses: [string, bigint][];
  notices: [string, string][];
  sink: PipelineSink;
}

export function recorder(): Recorded {
  const out: Recorded = { losses: [], notices: [], sink: undefined as never };
  out.sink = {
    lose: (reason, sequence) => out.losses.push([reason, sequence]),
    notice: (id, reason) => out.notices.push([id, reason]),
  };
  return out;
}

/** What the Fabric worker does with each ring record: the pipeline, then the release. */
export async function processJobs(cap: Capture, pipeline: CapturePipeline): Promise<string[]> {
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
