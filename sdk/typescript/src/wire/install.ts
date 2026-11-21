// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Explicit `install()` (spec 055 §4.2, §7.1, §9.4), on the installing thread: validate
 * the configuration, load the native module (with its self-test in the spool directory),
 * create the shared runtime, register the epoch, start the Fabric worker (pipeline and
 * sender, `fabric-main.ts`), bind the run table and subscribe the undici hook. Every
 * step that is not a hook runs here or in the Fabric worker, never in a hook.
 *
 * Malformed configuration throws fixed text (`WireConfigError`); a missing prerequisite
 * (no spool directory, no usable native module) returns a handle that captures nothing
 * and names the reason. Nothing here sends a provider probe.
 *
 * `flush()` and `close()` are bounded; `close()` stops new capture first (the hook is
 * removed, open exchanges become `shutdown` losses, open segments are sealed), then the
 * worker closes the epoch and delivers within the budget. A bounded `beforeExit` drain
 * runs once if the application did not close: `shutdown_timeout`, plus
 * `FABRIC_WIRE_DRAIN_ON_EXIT_S` when the customer opts in. No signal handler is
 * installed; `process.exit()` and SIGKILL cannot promise a flush.
 *
 * Unit 055-t13 builds this for the source build (the first verified Node record); unit
 * 055-t14 packages it as `@singleaxis/fabric/wire`, adds the preload, the status
 * document and the qualification-table gate of the packaged build.
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { hostname } from "node:os";
import { fileURLToPath } from "node:url";

import { DeploymentPolicy } from "../deployment-policy.js";
import { labelPseudonym } from "../identity.js";
import type { Transformation } from "../redaction.js";
import { resolveConfig, type WireOptions } from "./config.js";
import { targetOf } from "./delivery.js";
import { ExchangeTable } from "./exchange.js";
import type { FabricMainSnapshot, StopResult } from "./fabric-main.js";
import {
  ManifestChain,
  NODE_HTTP_POINT,
  type QualificationTable,
  emittedAt,
  UNDICI_POINT,
  currentRuntime,
  initialStates,
  manifestTemplate,
} from "./manifest.js";
import { loadNative, type NativeLoadOptions } from "./native.js";
import { encodeOpaqueId } from "./p1.js";
import { decideGate } from "./protect.js";
import { register, unsealedPriorEpochs, type Registration } from "./registration.js";
import { bindRunTable, captureScope, createRunTable } from "./run-api.js";
import { STATE_CLOSING, WireRuntime, createRuntimeShared } from "./runtime.js";
import { spoolKeyId } from "./spool-codec.js";
import { secureDir } from "./spool.js";
import type { WireSettings } from "./types.js";
import { type UndiciHook, installUndiciHook } from "./undici.js";
import { FabricWorker, firstManifest, isFabricWorkerThread, pipelineConfig } from "./worker.js";

/** `install()` options: the configuration options, plus what a source build must name. */
export interface InstallOptions extends WireOptions {
  /** The Fabric worker's entry: the wire core file (default: this module's file). */
  readonly workerEntry?: string | URL;
  /** Where the native module is (default: the package's prebuilds and digest table). */
  readonly native?: Pick<NativeLoadOptions, "prebuildsDir" | "digests">;
  /** The qualification table (default: the package's `wire-qualification.json`). */
  readonly qualification?: QualificationTable;
  /** The environment to read (default `process.env`). */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Install the bounded `beforeExit` drain (default true). */
  readonly drainOnExit?: boolean;
  /**
   * The customer transformation of each `redact` or `masked_only` role (049 §7.7),
   * performed by the redaction service `FABRIC_REDACTION_ENDPOINT` names.
   */
  readonly transformations?: Readonly<Record<string, Transformation>>;
}

export interface WireHandle {
  /** Whether capture is running in this process. */
  readonly capturing: boolean;
  /** Why capture is not running (a fixed reason), when it is not. */
  readonly reason: string | undefined;
  /** The emitted (pseudonymous) source id and the registered epoch. */
  readonly sourceId: string | undefined;
  readonly epoch: bigint | undefined;
  /**
   * Waits until every exchange completed so far is spooled and this process's records
   * are delivered, within `timeoutMs` (default 2000). Never rejects.
   */
  flush(options?: { timeoutMs?: number }): Promise<boolean>;
  /**
   * Stops capture, closes the epoch and delivers within `timeoutMs` (default
   * `FABRIC_WIRE_SHUTDOWN_TIMEOUT`). `false` on loss, unresolved durability or
   * undelivered evidence. Idempotent; never rejects.
   */
  close(options?: { timeoutMs?: number }): Promise<boolean>;
  /** The orderly stop's report, once `close()` ran. */
  readonly stopResult: StopResult | undefined;
}

let installed: WireHandle | undefined;

function moduleFile(): string | undefined {
  // The wire core is one CommonJS file in the package (and in the source-build bundles):
  // that file is the Fabric worker's entry. Under ESM tests a worker entry is passed.
  // eslint-disable-next-line no-undef -- CommonJS only; `typeof` never throws in ESM
  if (typeof __filename === "string") return __filename;
  try {
    return fileURLToPath(import.meta.url);
  } catch {
    return undefined;
  }
}

function inert(reason: string): WireHandle {
  return {
    capturing: false,
    reason,
    sourceId: undefined,
    epoch: undefined,
    flush: () => Promise.resolve(false),
    close: () => Promise.resolve(false),
    stopResult: undefined,
  };
}

/** The emitted source id (Python `_source_id`, J1). */
function emittedSourceId(
  settings: WireSettings,
  production: boolean,
  env: Readonly<Record<string, string | undefined>>,
): string {
  const key = settings.secrets.idKey;
  if (production && key === undefined) return "s-" + randomBytes(16).toString("hex");
  const service = env.OTEL_SERVICE_NAME || "unknown";
  const chosen =
    settings.sourceId ??
    "wire-" +
      createHash("sha256").update(`${hostname()}\0${service}`, "utf8").digest("hex").slice(0, 16);
  const opaque = encodeOpaqueId(chosen);
  return settings.labels === "clear" ? opaque : labelPseudonym("s", opaque, key);
}

function packagedTable(): QualificationTable {
  for (const candidate of ["../wire-qualification.json", "../../wire-qualification.json"]) {
    try {
      const base = moduleFile();
      if (base === undefined) break;
      const url = new URL(candidate, `file://${base}`);
      return JSON.parse(readFileSync(url, "utf8")) as QualificationTable;
    } catch {
      // try the next location
    }
  }
  return { tuples: [] };
}

/**
 * Installs wire capture in this process (one runtime per process: a second call returns
 * the first handle). Throws only for malformed configuration.
 */
export function install(options: InstallOptions = {}): WireHandle {
  if (isFabricWorkerThread()) return inert("fabric_worker");
  if (installed !== undefined) return installed;
  const env = options.env ?? process.env;
  const settings = resolveConfig(options, env);
  if (settings.spoolDir === undefined) return inert("no_spool");
  const entry = options.workerEntry ?? moduleFile();
  if (entry === undefined) return inert("no_worker_entry");
  try {
    secureDir(settings.spoolDir);
  } catch {
    return inert("spool_unusable");
  }
  const native = loadNative({ ...options.native, selfTestDir: settings.spoolDir });
  if (!native.ok) return inert(native.reason);

  const endpoints = [...settings.extraEndpoints, ...settings.endpoints];
  const provisional = pipelineConfig(settings, { sourceId: "s-0", endpoints, env });
  const policy =
    provisional.policy === undefined ? undefined : new DeploymentPolicy(provisional.policy);
  const gate = decideGate({
    node: provisional.node,
    store: provisional.store,
    policy,
    idKey: settings.secrets.idKey !== undefined,
    spool: true,
    spoolKey: settings.secrets.spoolKey !== undefined,
  });
  const sourceId = emittedSourceId(settings, gate.profile === "production", env);
  const config = pipelineConfig(settings, {
    sourceId,
    endpoints,
    env,
    transformations: options.transformations,
  });

  const runtime = new WireRuntime(
    createRuntimeShared({
      maxInflightBytes: settings.maxInflightBytes,
      maxRetainBytes: settings.maxRetainBytes,
      queueMaxItems: settings.queueMaxItems,
    }),
    "installer",
  );
  const registration: Registration = register({
    addon: native.addon,
    spoolDir: settings.spoolDir,
    sourceId,
    runtime,
    warn: () => undefined,
  });
  const build = currentRuntime(native.target);
  const states = initialStates({
    runtime: build,
    table: options.qualification ?? packagedTable(),
    nativeOk: true,
    enabled: { [UNDICI_POINT]: settings.undici, [NODE_HTTP_POINT]: settings.nodeHttp },
    installed: { [UNDICI_POINT]: settings.undici },
    endpoints: endpoints.length,
  });
  const template = manifestTemplate(settings, {
    sourceId,
    gate,
    spoolKeyId:
      settings.secrets.spoolKey === undefined ? undefined : spoolKeyId(settings.secrets.spoolKey),
    states,
    runtime: build,
  });
  // Manifest 0, minted and published here, before any hook exists: run markers, seals and
  // tokens made before the worker's first tick name it (rev 3.11 deviation 5). The worker
  // issues the identical document from the same ids and time (`firstManifest`).
  const unsealed = unsealedPriorEpochs(native.addon, settings.spoolDir);
  const first = {
    ids: [randomUUID(), randomUUID()] as [string, string],
    stamp: emittedAt(BigInt(Date.now()) * 1_000_000n),
  };
  try {
    const chain = new ManifestChain(template, firstManifest(first));
    chain.initial(runtime.epoch, unsealed);
    const ref = chain.ref;
    if (ref !== undefined) {
      runtime.publishManifest({
        epoch: ref.epoch,
        manifestSeq: ref.manifestSeq,
        manifestId: ref.manifestId,
        digest: ref.digest,
      });
    }
  } catch {
    // the worker publishes it at its first tick instead
  }
  const contentRoute = settings.otlpLogs ?? settings.otlp;
  const snapshot: FabricMainSnapshot = {
    pipeline: {
      ...config,
      manifest: { template, unsealed, first },
    },
    spoolDir: settings.spoolDir,
    spoolMaxBytes: Number(settings.spoolMaxBytes),
    native: { ...options.native },
    traces: { target: { ...targetOf(settings.otlp) }, headers: { ...settings.otlp.headers } },
    content:
      settings.contentEndpoint === undefined
        ? undefined
        : {
            target: { ...targetOf(contentRoute, settings.contentEndpoint) },
            headers: { ...contentRoute.headers },
          },
    proxy: settings.proxy,
    batchBodies: settings.contentBatchBodies,
    concurrency: settings.contentConcurrency,
    shutdownTimeoutMs: settings.shutdownTimeoutMs,
    drainOnExitMs: settings.drainOnExitMs,
  };
  const worker = new FabricWorker(runtime, { entry, snapshot });
  worker.start();
  const table = new ExchangeTable(runtime);
  const runs = createRunTable(runtime, settings, {
    sourceId,
    production: gate.profile === "production",
  });
  bindRunTable(runs);
  let hook: UndiciHook | undefined;
  if (settings.undici) {
    hook = installUndiciHook({
      table,
      endpoints,
      scope: captureScope,
      providerRequestId: settings.providerRequestId,
    });
  }

  let closing: Promise<boolean> | undefined;
  let stopResult: StopResult | undefined;
  const close = (timeoutMs: number, exiting: boolean): Promise<boolean> => {
    closing ??= (async () => {
      process.off("beforeExit", onExit);
      try {
        hook?.uninstall();
        runtime.setState(STATE_CLOSING);
        table.shutdown();
        runs.onFinal();
      } catch {
        // capture is stopping either way; the record says what was lost
      }
      const clean = await worker.stop(timeoutMs, { exiting });
      stopResult = worker.stopResult as StopResult | undefined;
      const closed = clean && stopResult?.closed === true;
      try {
        if (closed) registration.final();
        registration.close();
      } catch {
        // an unfinalized registration is declared an orphan by the next drainer
      }
      bindRunTable(undefined);
      if (stopResult !== undefined && stopResult.backlog > 0 && settings.diagnostics === "stderr") {
        process.stderr.write(
          `fabric.wire: ${stopResult.backlog} records left in the spool at exit and no process ` +
            "is draining it; start the agent again, or set FABRIC_WIRE_DRAIN_ON_EXIT_S for batch " +
            "or serverless workers [FW-033]\n",
        );
      }
      return closed && stopResult?.delivered === true;
    })();
    return closing;
  };
  // The bounded exit drain: once, only if the application did not close (§9.4).
  const onExit = (): void => {
    const exiting = settings.drainOnExitMs <= 0;
    void close(settings.shutdownTimeoutMs + settings.drainOnExitMs, exiting);
  };
  if (options.drainOnExit !== false) process.once("beforeExit", onExit);

  const handle: WireHandle = {
    capturing: true,
    reason: undefined,
    sourceId,
    epoch: runtime.epoch,
    async flush(flushOptions = {}) {
      if (closing !== undefined) return false;
      const result = await worker.request("flush", flushOptions.timeoutMs ?? 2000);
      return result === true;
    },
    close: (closeOptions = {}) =>
      close(closeOptions.timeoutMs ?? settings.shutdownTimeoutMs, false),
    get stopResult() {
      return stopResult;
    },
  };
  installed = handle;
  return handle;
}

/** Tests only: forget the installed handle after it was closed. */
export function resetInstalledForTests(): void {
  installed = undefined;
}
