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
import { hostname } from "node:os";
import { fileURLToPath } from "node:url";
import { isMainThread } from "node:worker_threads";

import { DeploymentPolicy } from "../deployment-policy.js";
import { labelPseudonym } from "../identity.js";
import type { Transformation } from "../redaction.js";
import { WireConfigError, resolveConfig, type WireOptions } from "./config.js";
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
import { loadNative, nativeTarget, type NativeLoadOptions } from "./native.js";
import { encodeOpaqueId } from "./p1.js";
import { decideGate } from "./protect.js";
import { register, unsealedPriorEpochs, type Registration } from "./registration.js";
import { bindRunTable, captureScope, createRunTable } from "./run-api.js";
import { STATE_CLOSING, WireRuntime, createRuntimeShared } from "./runtime.js";
import { spoolKeyId } from "./spool-codec.js";
import { secureDir } from "./spool.js";
import {
  type HookCounters,
  type StatusDocument,
  type StatusFacts,
  Reason,
  exitDocument,
  installDocument,
  maskedWithheld,
  packagedQualification,
  printable,
  runtimeListed,
  writeStatusFile,
} from "./status.js";
import type { WireSettings } from "./types.js";
import { type UndiciHook, installUndiciHook } from "./undici.js";
import {
  FabricWorker,
  type Uninstalled,
  firstManifest,
  isFabricWorkerThread,
  pipelineConfig,
} from "./worker.js";

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
  /**
   * The content-free status document (`fabric.wire-status/v1`, spec 055 §4.7): the
   * capture state, each capture point's state and reason, the runtime qualification, the
   * catalogue ids of every warning and notice, and this thread's counters; after
   * `close()`, the exit document. `node -p` prints each id's text and fix beside it.
   */
  status(): StatusDocument;
}

let installed: { handle: WireHandle; fingerprint: string; objects: readonly unknown[] } | undefined;

/** Forgets `handle` as the process's installed one once it is closed. */
function release(handle: WireHandle): void {
  if (installed?.handle === handle) installed = undefined;
}

/**
 * The caller-supplied objects that change what is captured or how, compared by identity:
 * a transformation, a qualification table, a native location or a worker entry given to a
 * second install() must be the very ones the first install used.
 */
function objectsOf(options: InstallOptions): readonly unknown[] {
  return [options.transformations, options.qualification, options.native, options.workerEntry];
}

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

/** The diagnostics channel: fixed text naming the fix, only with `FABRIC_WIRE_DIAGNOSTICS=stderr`. */
function stderrWarn(
  settings: Pick<WireSettings, "diagnostics"> | undefined,
): (text: string) => void {
  return (text) => {
    if (settings?.diagnostics !== "stderr") return;
    try {
      process.stderr.write(`${text}\n`);
    } catch {
      // diagnostics never reach the agent as an error
    }
  };
}

/**
 * A handle that captures nothing and says why. Its install document is written to the
 * status file here (no Fabric worker runs), once per process.
 */
function inert(
  reason: string,
  facts: Omit<StatusFacts, "capture" | "reason">,
  statusFile?: string,
): WireHandle {
  const document = installDocument({ ...facts, capture: "disabled", reason });
  if (statusFile !== undefined) writeStatusFile(statusFile, document, stderrWarn(facts.settings));
  const handle: WireHandle = {
    capturing: false,
    reason,
    sourceId: undefined,
    epoch: undefined,
    flush: () => Promise.resolve(false),
    close: () => {
      release(handle);
      return Promise.resolve(false);
    },
    stopResult: undefined,
    status: () => printable({ ...document }),
  };
  return handle;
}

/** Whether this is Bun or Deno running Node.js code, not Node.js itself. */
export function nonNodeRuntime(): boolean {
  const versions = process.versions as Record<string, string | undefined>;
  return versions.bun !== undefined || versions.deno !== undefined || "Deno" in globalThis;
}

/** The runtime facts every document carries, before anything is loaded. */
function runtimeFacts(table: QualificationTable, platform: string | null = nativeTarget()) {
  const runtime = currentRuntime(platform);
  return { runtime, listed: runtimeListed(table, runtime) };
}

/**
 * What makes two installs compatible: the settings that decide what is captured and
 * where it goes (never a secret's value, only whether one is set).
 */
function fingerprint(settings: WireSettings): string {
  return JSON.stringify([
    settings.spoolDir,
    settings.undici,
    settings.nodeHttp,
    [...settings.extraEndpoints, ...settings.endpoints].map((m) => m.endpointId),
    settings.store?.kind,
    settings.contentEndpoint,
    settings.otlp.endpoint,
    settings.otlpLogs?.endpoint,
    settings.store?.kind === "file" ? settings.store.root : undefined,
    settings.redactionEndpoint,
    settings.redactionTokenFile,
    settings.modelAllowlist,
    settings.providerRequestId,
    settings.builtinEndpoints,
    settings.capturePolicyPath,
    settings.labels,
    settings.identityMode,
    settings.tenantId,
    settings.sourceId,
    settings.secrets.idKey !== undefined,
    settings.secrets.spoolKey !== undefined,
  ]);
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
  const base = moduleFile();
  return base === undefined
    ? { tuples: [] }
    : packagedQualification(fileURLToPath(new URL(".", `file://${base}`)));
}

/** Whether `options` asks for anything beyond the defaults the environment decides. */
function onlyDefaults(options: InstallOptions): boolean {
  return Object.keys(options).every((key) => key === "drainOnExit");
}

/**
 * Installs wire capture in this process: one runtime per process. A second call with no
 * options, or with options that resolve to the same capture, returns the first handle (the
 * preload and an explicit `install()` share it); options that would capture differently
 * throw fixed text (close the installed handle first), never a second capture.
 * Throws only for malformed or conflicting configuration.
 */
export function install(options: InstallOptions = {}): WireHandle {
  const table = options.qualification ?? packagedTable();
  if (isFabricWorkerThread()) return inert(Reason.fabricWorker, runtimeFacts(table));
  if (!isMainThread) {
    // An application worker thread: attaching to the process runtime is spec 055 §4.5's
    // isolate attach (unit 055-t19). Until then it records nothing and says so (FW-030).
    return inert(Reason.workerThread, runtimeFacts(table));
  }
  const env = options.env ?? process.env;
  if (installed !== undefined && onlyDefaults(options)) return installed.handle;
  const settings = resolveConfig(options, env);
  const print = fingerprint(settings);
  if (installed !== undefined) {
    const first = installed.objects;
    const same =
      print === installed.fingerprint && objectsOf(options).every((o, i) => o === first[i]);
    if (same) return installed.handle;
    // A first install that captures nothing set nothing up: this one replaces it.
    if (installed.handle.capturing) {
      throw new WireConfigError(
        "wire capture is already installed in this process with a different configuration: " +
          "await close() on the installed handle before installing again",
      );
    }
  }
  const handle = installChecked(options, env, settings, table);
  installed = { handle, fingerprint: print, objects: objectsOf(options) };
  return handle;
}

function installChecked(
  options: InstallOptions,
  env: Readonly<Record<string, string | undefined>>,
  settings: WireSettings,
  table: QualificationTable,
): WireHandle {
  const file = settings.statusFile;
  const base = { settings, ...runtimeFacts(table) };
  // Bun and Deno report a Node.js version for compatibility, but they are not a Node.js
  // build in the qualification table: capture never starts there (spec 055 §9.3).
  if (nonNodeRuntime()) return inert(Reason.unsupportedRuntime, base, file);
  if (settings.otelSdkDisabled) return inert(Reason.otelSdkDisabled, base, file);
  if (settings.spoolDir === undefined) return inert(Reason.noSpool, base, file);
  const entry = options.workerEntry ?? moduleFile();
  if (entry === undefined) return inert(Reason.internalError, base, file);
  try {
    secureDir(settings.spoolDir);
  } catch {
    return inert(Reason.spoolUnusable, base, file);
  }
  // Spec 055 §4.2 (R9): only malformed configuration throws. Any other failure past this
  // point undoes what was set up (hook, run table, worker, registration) and returns a
  // handle that captures nothing and names the reason; it never reaches the application.
  const undo: (() => void)[] = [];
  try {
    return installWith(options, env, settings, settings.spoolDir, entry, table, undo);
  } catch (error) {
    for (const step of undo.reverse()) {
      try {
        step();
      } catch {
        // best effort: the next drainer declares an unfinalized epoch an orphan
      }
    }
    if (error instanceof WireConfigError) throw error;
    return inert(Reason.internalError, base, file);
  }
}

function installWith(
  options: InstallOptions,
  env: Readonly<Record<string, string | undefined>>,
  settings: WireSettings,
  spoolDir: string,
  entry: string | URL,
  table: QualificationTable,
  undo: (() => void)[],
): WireHandle {
  const file = settings.statusFile;
  const native = loadNative({ ...options.native, selfTestDir: spoolDir });
  if (!native.ok) {
    return inert(
      native.reason,
      { settings, ...runtimeFacts(table), nativeReasonId: native.reasonId },
      file,
    );
  }
  const build = currentRuntime(native.target);
  const facts = { settings, runtime: build, listed: runtimeListed(table, build) };
  const enabled = { [UNDICI_POINT]: settings.undici, [NODE_HTTP_POINT]: settings.nodeHttp };
  const planned = initialStates({
    runtime: build,
    table,
    nativeOk: true,
    enabled,
    installed: { [UNDICI_POINT]: settings.undici },
    endpoints: settings.extraEndpoints.length + settings.endpoints.length,
  });
  const wireStates = {
    [UNDICI_POINT]: planned[UNDICI_POINT]!,
    [NODE_HTTP_POINT]: planned[NODE_HTTP_POINT]!,
  };
  // Spec 055 §9.4: a capture point is active only for a tuple of the qualification table.
  // With no point that can be active, nothing is installed: no hook, no worker, no epoch.
  if (wireStates[UNDICI_POINT][0] !== "active") {
    return inert(
      wireStates[UNDICI_POINT][1] ?? Reason.noActivePoint,
      { ...facts, states: wireStates },
      file,
    );
  }

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
    spoolDir,
    sourceId,
    runtime,
    // Fixed text naming the fix (never a path); only where diagnostics go to stderr.
    warn: (message) => {
      if (settings.diagnostics === "stderr") process.stderr.write(`${message}\n`);
    },
  });
  // Nothing was captured under this epoch: finalized, its registration file goes.
  undo.push(() => {
    registration.final();
    registration.close();
  });
  const states = planned;
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
  const unsealed = unsealedPriorEpochs(native.addon, spoolDir);
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
  // The install document: the Fabric worker writes it to the status file when it starts.
  const statusFacts: StatusFacts = {
    ...facts,
    capture: "installed",
    gate,
    states: wireStates,
    maskedWithheld: maskedWithheld(gate, settings, options.transformations),
  };
  const installed_ = installDocument(statusFacts);
  const contentRoute = settings.otlpLogs ?? settings.otlp;
  const snapshot: FabricMainSnapshot = {
    pipeline: {
      ...config,
      manifest: { template, unsealed, first },
    },
    spoolDir,
    spoolMaxBytes: Number(settings.spoolMaxBytes),
    spoolMaxReceipts: settings.spoolMaxReceipts,
    ...(settings.spoolDurableBoundary === undefined
      ? {}
      : { spoolDurableBoundary: settings.spoolDurableBoundary }),
    // 049 §7.8: the plaintext migration is the local profile's explicit opt-in only; under
    // production it is refused (FW-022 in the status document) and never run.
    spoolMigratePlaintext: settings.spoolMigratePlaintext && gate.profile !== "production",
    native: { ...options.native },
    traces: { target: { ...targetOf(settings.otlp) }, headers: { ...settings.otlp.headers } },
    content:
      settings.contentEndpoint === undefined
        ? undefined
        : {
            target: { ...targetOf(contentRoute, settings.contentEndpoint) },
            headers: { ...contentRoute.headers },
          },
    // The local profile's direct store: the sender writes the bodies there itself.
    ...(settings.contentEndpoint === undefined &&
    settings.store?.kind === "file" &&
    settings.tenantId !== undefined
      ? { fileStore: { root: settings.store.root, tenant: settings.tenantId } }
      : {}),
    proxy: settings.proxy,
    batchBodies: settings.contentBatchBodies,
    concurrency: settings.contentConcurrency,
    shutdownTimeoutMs: settings.shutdownTimeoutMs,
    drainOnExitMs: settings.drainOnExitMs,
    diagnostics: settings.diagnostics,
    ...(file === undefined ? {} : { status: { path: file, install: installed_ } }),
  };
  const worker = new FabricWorker(runtime, {
    entry,
    snapshot,
    // The worker's class-only warnings (fixed text naming the fix), only where
    // diagnostics go to stderr (spec 055 §4.7).
    ...(settings.diagnostics === "stderr"
      ? { warn: (text: string) => void process.stderr.write(`${text}\n`) }
      : {}),
  });
  worker.start();
  undo.push(() => void worker.stop(0));
  const exchanges = new ExchangeTable(runtime);
  const runs = createRunTable(runtime, settings, {
    sourceId,
    production: gate.profile === "production",
  });
  bindRunTable(runs);
  undo.push(() => bindRunTable(undefined));
  // The undici point is active (checked above): its hook is subscribed. A hook that
  // subscribes nothing is a failed install, undone like any other failure.
  const hook: UndiciHook = installUndiciHook({
    table: exchanges,
    endpoints,
    scope: captureScope,
    providerRequestId: settings.providerRequestId,
    // Only Node's own undici is in the table; another copy's calls are named losses.
    publishers: "bundled",
  });
  undo.push(() => hook.uninstall());
  if (!hook.installed) throw new Error("the undici hook subscribed nothing");
  const counters = (): HookCounters => ({
    matched: hook.stats.matched,
    not_captured: hook.stats.notCaptured,
    unmatched_model_shaped: hook.stats.unmatchedModelShaped,
    unqualified_publisher: hook.stats.unqualifiedPublisher,
  });
  let exitStatus: StatusDocument | undefined;

  let closing: Promise<boolean> | undefined;
  let stopResult: StopResult | undefined;
  const close = (timeoutMs: number, exiting: boolean): Promise<boolean> => {
    closing ??= (async () => {
      process.off("beforeExit", onExit);
      let off: Uninstalled | undefined;
      try {
        // The hook goes first; the cut is the position after which nothing it captured
        // can be allocated (050 §3.8: a chained `disabled(shutdown)` manifest).
        const cut = runtime.cut(() => hook.uninstall());
        if (cut !== undefined) off = { points: [UNDICI_POINT], cut };
        runtime.setState(STATE_CLOSING);
        exchanges.shutdown();
        runs.onFinal();
      } catch {
        // capture is stopping either way; the record says what was lost
      }
      const final = counters();
      const unmatched = hook.unmatchedHosts();
      const clean = await worker.stop(timeoutMs, {
        exiting,
        counters: { ...final },
        unmatched,
        ...(off === undefined ? {} : { uninstalled: off }),
      });
      const reported = worker.stopResult as (StopResult & { stats?: unknown }) | undefined;
      if (reported !== undefined) {
        const { stats, ...result } = reported;
        stopResult = result;
        const known = stats !== null && typeof stats === "object" ? stats : {};
        exitStatus = exitDocument(
          installed_,
          result.delivered,
          { ...final, ...(known as Record<string, number>) },
          unmatched,
        );
      } else {
        exitStatus = exitDocument(installed_, false, { ...final }, unmatched);
      }
      const closed = clean && stopResult?.closed === true;
      try {
        if (closed) registration.final();
        registration.close();
      } catch {
        // an unfinalized registration is declared an orphan by the next drainer
      }
      bindRunTable(undefined);
      if (stopResult !== undefined && stopResult.backlog > 0 && settings.diagnostics === "stderr") {
        try {
          process.stderr.write(
            `fabric.wire: ${stopResult.backlog} records left in the spool at exit and no process ` +
              "is draining it; start the agent again, or set FABRIC_WIRE_DRAIN_ON_EXIT_S for " +
              "batch or serverless workers [FW-033]\n",
          );
        } catch {
          // diagnostics never reach the agent as an error
        }
      }
      // Everything this runtime set up is torn down: a later install() starts afresh.
      release(handle);
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
  undo.push(() => process.off("beforeExit", onExit));

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
    status() {
      if (exitStatus !== undefined) return printable({ ...exitStatus });
      return printable(
        installDocument({
          ...statusFacts,
          counters: counters(),
          unmatched: hook.unmatchedHosts(),
        }),
      );
    },
  };
  return handle;
}

/** Tests only: forget the installed handle after it was closed. */
export function resetInstalledForTests(): void {
  installed = undefined;
}
