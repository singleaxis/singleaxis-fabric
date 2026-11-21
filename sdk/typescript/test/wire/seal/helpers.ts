// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the seal and loss tests (spec 055 §9.5, unit 055-t10): a capture pipeline
 * configuration with manifests, the spool's records as TypeScript and Python read them,
 * and a run slot holding a segment.
 */
import { NODE_HTTP_POINT, UNDICI_POINT, manifestTemplate } from "../../../src/wire/manifest.js";
import { decideGate } from "../../../src/wire/protect.js";
import type { WireRuntime } from "../../../src/wire/runtime.js";
import { unframeAll } from "../../../src/wire/spool-codec.js";
import type { Spool } from "../../../src/wire/spool.js";
import type { PipelineConfig } from "../../../src/wire/worker.js";

import { settingsFor } from "../manifest/helpers.js";
import { ID_KEY, TENANT, policyDoc } from "../protect/helpers.js";
import { runPython } from "../registration/helpers.js";
import { KEY } from "../spool/helpers.js";

export const SOURCE = "s-" + "cd".repeat(16);
export const RUN = "r-" + "ab".repeat(16);
export const UUID4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const MODES = {
  "model.exchange.request": "retain_original",
  "model.exchange.response": "retain_original",
};
const RUNTIME = { node: "24.4.0", undici: "7.11.0", platform: "linux-x64-glibc" };

/** A production pipeline configuration with manifests (as `test/wire/manifest`'s). */
export function pipelineConfig(overrides: Partial<PipelineConfig> = {}): PipelineConfig {
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
    policy: policyDoc(MODES, "production") as never,
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
    manifest: { template, unsealed: { epochs: [], count: 0 } },
    ...overrides,
  };
}

/** The headers of every record in the spool, in drain order, as TypeScript reads them. */
export function spooledDocs(spool: Spool): Record<string, any>[] {
  return spool.names().flatMap((name) => unframeAll(spool.read(name)).map(({ doc }) => doc as any));
}

const PY_READ = `
import json, sys
from fabric.wire._spool import Spool, unframe_all, valid_header, loss_range
from fabric._loss import marker_span, loss_attributes
spool = Spool(sys.argv[1], 1 << 20, key=bytes.fromhex(sys.argv[2]))
out = []
try:
    for name in spool.names():
        for doc, blob in unframe_all(spool.read(name)):
            item = {"kind": doc["record_kind"], "ok": valid_header(doc, len(blob))}
            src = doc["source"]
            if doc["record_kind"] == "marker":
                item["marker"] = doc["marker"]["kind"]
                item["span"] = marker_span(src["source_id"], src["source_epoch"], doc["marker"])
            if doc["record_kind"] == "loss":
                item["loss"] = loss_attributes(loss_range(doc))
            out.append(item)
finally:
    spool.release()
print(json.dumps(out))
`;

/** What Python's drainer reads from the spool: kind, header check, marker spans, losses. */
export function pythonReads(dir: string): any[] {
  return runPython(PY_READ, [dir, KEY.toString("hex")]) as any[];
}

/** A fresh segment id (its two 64-bit halves and its text). */
export function segment(n: number): { hi: bigint; lo: bigint; id: string } {
  const hi = BigInt(n) << 32n;
  const lo = BigInt(n) + 1n;
  return {
    hi,
    lo,
    id: `seg-${hi.toString(16).padStart(16, "0")}${lo.toString(16).padStart(16, "0")}`,
  };
}

/** Opens (or moves) `slot`'s segment under the run-table lock, as the run table does. */
export function openSegment(runtime: WireRuntime, slot: number, hi: bigint, lo: bigint): void {
  if (!runtime.tryLock(1000)) throw new Error("run-table lock not taken");
  try {
    runtime.setRunSegment(slot, hi, lo);
  } finally {
    runtime.unlock();
  }
}

/** Moves `slot` to a new segment and returns the count the old one held (one lock). */
export function rollSegment(runtime: WireRuntime, slot: number, hi: bigint, lo: bigint): bigint {
  if (!runtime.tryLock(1000)) throw new Error("run-table lock not taken");
  try {
    const positions = runtime.runPositions(slot);
    runtime.setRunSegment(slot, hi, lo);
    return positions;
  } finally {
    runtime.unlock();
  }
}
