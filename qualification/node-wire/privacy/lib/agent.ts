// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The capture the privacy harness drives (spec 055 §9.2 `ts-wire-privacy`): the real
 * configuration (`resolveConfig` over the scenario's environment), the shared runtime,
 * the undici hook and a real Fabric worker running the capture pipeline into the spool.
 * Built from the SDK source by `build.mjs` (the packed package replaces it from unit
 * 055-t14).
 */
import { randomBytes } from "node:crypto";

import { ExchangeTable } from "../../../../sdk/typescript/src/wire/exchange.js";
import { resolveConfig } from "../../../../sdk/typescript/src/wire/config.js";
import { WireRuntime, createRuntimeShared } from "../../../../sdk/typescript/src/wire/runtime.js";
import { installUndiciHook, type UndiciHook } from "../../../../sdk/typescript/src/wire/undici.js";
import type { Transformation } from "../../../../sdk/typescript/src/redaction.js";
import { FabricWorker, pipelineConfig } from "../../../../sdk/typescript/src/wire/worker.js";

export interface Agent {
  readonly hook: UndiciHook;
  readonly runtime: WireRuntime;
  /** Waits until every completed exchange was handled, then stops the Fabric worker. */
  stop(): Promise<boolean>;
}

export interface WorkerSnapshot {
  readonly config: ReturnType<typeof pipelineConfig>;
  readonly spoolDir: string;
  readonly spoolMaxBytes: number;
  readonly prebuilds: string;
  readonly digest: string;
  /** Test-only fault of the scanner self-test (`leak`); never in the SDK. */
  readonly fault: string | undefined;
  readonly leaks: readonly string[];
}

export function startAgent(options: {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly workerEntry: string;
  readonly prebuilds: string;
  readonly digest: string;
  readonly transformations?: Readonly<Record<string, Transformation>>;
  readonly fault?: string;
  readonly leaks?: readonly string[];
}): Agent {
  const settings = resolveConfig({}, options.env);
  const endpoints = [...settings.extraEndpoints, ...settings.endpoints];
  const config = pipelineConfig(settings, {
    sourceId: "s-" + randomBytes(16).toString("hex"),
    endpoints,
    transformations: options.transformations,
    env: options.env,
  });
  const runtime = new WireRuntime(createRuntimeShared({ maxInflightBytes: 64 * 1024 * 1024 }), "installer");
  const table = new ExchangeTable(runtime);
  const snapshot: WorkerSnapshot = {
    config,
    spoolDir: settings.spoolDir!,
    spoolMaxBytes: Number(settings.spoolMaxBytes),
    prebuilds: options.prebuilds,
    digest: options.digest,
    fault: options.fault,
    leaks: options.leaks ?? [],
  };
  const worker = new FabricWorker(runtime, { entry: options.workerEntry, snapshot });
  worker.start();
  const hook = installUndiciHook({ table, endpoints });
  return {
    hook,
    runtime,
    async stop() {
      hook.uninstall();
      const deadline = Date.now() + 30_000;
      while (runtime.jobs.count > 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      return worker.stop(10_000);
    },
  };
}
