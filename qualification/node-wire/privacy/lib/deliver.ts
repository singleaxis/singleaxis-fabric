// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Delivers a scenario's spool with the SDK's own sender (spec 055 §7.1, unit 055-t13) to
 * a recording sink, so the privacy scan also reads every OTLP byte Fabric sends: the
 * content logs (`/v1/logs`) and the spans (`/v1/traces`). Built from the SDK source by
 * `build.mjs`.
 */
import { TraceClient } from "../../../../sdk/typescript/src/wire/delivery.js";
import { loadNative, nativeTarget } from "../../../../sdk/typescript/src/wire/native.js";
import { NodeContentClient } from "../../../../sdk/typescript/src/wire/node-content.js";
import { Sender } from "../../../../sdk/typescript/src/wire/sender.js";
import { Spool } from "../../../../sdk/typescript/src/wire/spool.js";

export async function deliverSpool(options: {
  readonly spoolDir: string;
  readonly key: Uint8Array;
  readonly prebuilds: string;
  readonly digest: string;
  readonly url: string;
}): Promise<{ readonly left: number; readonly stats: Record<string, number> }> {
  const target = nativeTarget();
  const loaded = loadNative({ prebuildsDir: options.prebuilds, digests: { [target!]: options.digest } });
  if (!loaded.ok) throw new Error(`native: ${loaded.reason}`);
  const spool = new Spool(options.spoolDir, { maxBytes: 1 << 30, addon: loaded.addon, key: options.key });
  const at = (path: string) => ({ url: `${options.url}${path}`, headers: {}, timeoutMs: 10_000 });
  const traces = new TraceClient(at("/v1/traces"));
  const content = new NodeContentClient(at("/v1/logs"), { serviceName: "svc-privacy" });
  const sender = new Sender({ spool, traces, content, serviceName: "svc-privacy" });
  try {
    if (!spool.tryLock()) throw new Error("the spool's drain lock is held");
    for (let pass = 0; pass < 50 && spool.names().length > 0; pass++) {
      if ((await sender.drain()) === "retry") break;
    }
    return { left: spool.names().length, stats: { ...sender.stats() } };
  } finally {
    traces.close();
    content.close();
    spool.close();
  }
}
