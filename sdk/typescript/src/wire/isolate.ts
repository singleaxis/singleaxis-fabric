// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Application worker threads (spec 055 §4.4 lifecycle, §4.5 isolate attach, §6.4).
 *
 * **Attach.** `install()` (or the preload) in a worker thread that inherited the process
 * runtime (`setEnvironmentData`, {@link RUNTIME_KEY} and {@link ATTACH_KEY}) loads the
 * native module, calls `envAttach`, claims its own row of the isolate table and installs
 * its own hook subscriptions on the shared allocator. It never creates a second
 * allocator, epoch, Fabric worker or registration, and reads no configuration: what it
 * needs (the native module's location, the endpoints, the run-table identity settings)
 * is what the installing thread published.
 *
 * **Unattached threads are declared, never guessed.** A worker thread records nothing
 * when it did not run Fabric (created before installation, without the preload: an
 * `eval: true` Worker, `execArgv: []`), or ran it without the process runtime
 * (`worker_without_process_runtime`). Each is counted in the control block, reported in
 * the status (`workers_unattached`, FW-030) and declared in a chained manifest as the
 * uncaptured class `node_worker_unattached`. Three ways in:
 * - an attached isolate sees every thread it creates on the `worker_threads`
 *   diagnostics channel; one not attached after {@link UNATTACHED_GRACE_MS} is counted;
 * - a thread that ran Fabric without the runtime says so on a `BroadcastChannel`, and
 *   answers the Fabric worker's roll call (so a thread started before installation is
 *   counted once the Fabric worker exists);
 * - an attach that fails (native module, `envAttach`, a full isolate table) counts itself.
 *
 * **Teardown.** The native environment cleanup hook only appends the isolate's
 * environment id to the detached ring. The Fabric worker polls `takeDetachedEnvs` on
 * every tick (at most 100 ms apart) and settles the dead isolate's open exchanges as
 * `shutdown` losses in the segments they were allocated in (R3), frees a lock it died
 * holding and its run slots, and skips a ring cell it claimed and never filled. On
 * `OVERFLOW` the dropped isolates cannot be named: their positions settle as `shutdown`
 * at `close()` (the shutdown sweep), and their seals wait until then. No JavaScript ever
 * runs in a dead isolate.
 *
 * Passivity: attach runs at preload or `install()` time, never in a hook; the channel
 * subscriber is one compare-exchange; nothing here throws into the application.
 */
import { subscribe, unsubscribe } from "node:diagnostics_channel";
import {
  BroadcastChannel,
  getEnvironmentData,
  setEnvironmentData,
  threadId,
} from "node:worker_threads";

import { ExchangeTable } from "./exchange.js";
import { NativeCode, type NativeAddon, type NativeLoadOptions, loadNative } from "./native.js";
import { attachMirror } from "./registration.js";
import { bindRunTable, captureScope } from "./run-api.js";
import {
  MAX_PENDING_THREADS,
  RUNTIME_KEY,
  type RuntimeShared,
  WireRuntime,
  inheritedRuntime,
} from "./runtime.js";
import { SegmentTable } from "./segments.js";
import type { EndpointMatcher } from "./types.js";
import { type UndiciHook, installUndiciHook } from "./undici.js";
import { creatingFabricWorker } from "./worker.js";

/** The `setEnvironmentData` key of what an attaching isolate needs beside the buffers. */
export const ATTACH_KEY = "fabric.wire.attach/1";
/** The `BroadcastChannel` of threads that ran Fabric without the process runtime. */
export const ISOLATE_CHANNEL = "fabric.wire.isolate/1";
/** The `worker_threads` diagnostics channel: published when a thread creates a Worker. */
export const WORKER_CHANNEL = "worker_threads";
/** How long a created thread has to attach before it is counted unattached. */
export const UNATTACHED_GRACE_MS = 2000;
/** A ring head left claimed and unpublished this long is skipped (its producer is gone). */
export const STUCK_MS = 1000;
/** A lock held this long by one application isolate: its holder is gone. */
export const STALE_LOCK_MS = 1000;

/** What the installing thread publishes for attaching isolates (structured-cloneable). */
export interface AttachData {
  readonly native: Pick<NativeLoadOptions, "prebuildsDir" | "digests">;
  readonly endpoints: readonly EndpointMatcher[];
  readonly providerRequestId: boolean;
  readonly sourceId: string;
  /** The run table's identity settings (the id key stays in this process's memory). */
  readonly run: {
    readonly idKey: Uint8Array | undefined;
    readonly identityMode: "pseudonymous" | "clear";
    readonly labels: "pseudonymous" | "clear";
    readonly production: boolean;
  };
}

/** Publishes the runtime's attach data for every Worker created from now on. */
export function publishAttach(data: AttachData): void {
  setEnvironmentData(ATTACH_KEY, data as unknown as Parameters<typeof setEnvironmentData>[1]);
}

/** Stops publishing the runtime (orderly close): a Worker created later does not attach. */
export function unpublishRuntime(): void {
  try {
    setEnvironmentData(RUNTIME_KEY, undefined);
    setEnvironmentData(ATTACH_KEY, undefined);
  } catch {
    // a later Worker attaches to a closed runtime, which refuses every exchange
  }
}

function attachData(): AttachData | undefined {
  try {
    const value = getEnvironmentData(ATTACH_KEY) as unknown;
    if (value === null || typeof value !== "object") return undefined;
    const data = value as AttachData;
    return typeof data.sourceId === "string" && Array.isArray(data.endpoints) ? data : undefined;
  } catch {
    return undefined;
  }
}

// ------------------------------------------------------------------ the creating side

let watched: WireRuntime | undefined;

/**
 * Counts each worker thread this isolate creates (the `worker_threads` diagnostics
 * channel, published synchronously inside `new Worker`) as pending in the control block;
 * the Fabric worker decides whether it attached. Not the Fabric worker itself. One
 * subscriber per isolate; never throws.
 */
function onWorker(message: unknown): void {
  const runtime = watched;
  if (runtime === undefined || creatingFabricWorker()) return;
  try {
    const id = (message as { worker?: { threadId?: unknown } } | null)?.worker?.threadId;
    if (typeof id !== "number" || !runtime.notePendingThread(id)) runtime.countUnattached();
  } catch {
    // a thread that cannot be followed is never the agent's problem
  }
}

/** Starts following the worker threads this isolate creates, for `runtime`. */
export function watchWorkerThreads(runtime: WireRuntime): void {
  try {
    if (watched === undefined) subscribe(WORKER_CHANNEL, onWorker);
    watched = runtime;
  } catch {
    watched = undefined;
  }
}

/** Stops following (orderly close). */
export function unwatchWorkerThreads(): void {
  try {
    if (watched !== undefined) unsubscribe(WORKER_CHANNEL, onWorker);
  } catch {
    // nothing to undo
  }
  watched = undefined;
}

// ------------------------------------------------------------------- the attaching side

let reporter: BroadcastChannel | undefined;

/**
 * This thread ran Fabric without the process runtime: it says so now, and answers each
 * roll call of a Fabric worker started later. The channel never keeps the thread alive.
 */
function reportUnattached(): void {
  if (reporter !== undefined) return;
  try {
    const channel = new BroadcastChannel(ISOLATE_CHANNEL);
    const say = (): void => {
      try {
        channel.postMessage({ unattached: threadId });
      } catch {
        // the count is best effort; the status of this thread still names the reason
      }
    };
    channel.onmessage = (event: unknown) => {
      if ((event as { data?: { roll?: unknown } } | null)?.data?.roll === 1) say();
    };
    (channel as unknown as { unref?: () => void }).unref?.();
    reporter = channel;
    say();
  } catch {
    // as above
  }
}

/** An attached isolate's hook, run table and runtime view. */
export interface Attached {
  readonly runtime: WireRuntime;
  readonly hook: UndiciHook;
  readonly runs: SegmentTable;
  readonly data: AttachData;
  /** Removes this isolate's hook and seals its open run segments. Never throws. */
  detach(): void;
}

/** Why an application thread is not attached (a status reason). */
export type UnattachedReason =
  | "worker_without_process_runtime"
  | "runtime_closed"
  | "native_load_failed"
  | "isolate_limit"
  | "internal_error";

export type AttachOutcome =
  | { readonly ok: true; readonly attached: Attached }
  | { readonly ok: false; readonly reason: UnattachedReason };

let current: Attached | undefined;

/**
 * Attaches this application thread to the process runtime it inherited (spec 055 §4.5).
 * Idempotent per thread. Never throws.
 */
export function attachIsolate(): AttachOutcome {
  if (current !== undefined) return { ok: true, attached: current };
  let shared: RuntimeShared | undefined;
  let data: AttachData | undefined;
  try {
    shared = inheritedRuntime();
    data = attachData();
  } catch {
    shared = undefined;
  }
  if (shared === undefined || data === undefined) {
    reportUnattached();
    return { ok: false, reason: "worker_without_process_runtime" };
  }
  // Counted on the shared runtime from here: the Fabric worker declares the class.
  const probe = new WireRuntime(shared, "application", -1);
  if (!probe.running) return { ok: false, reason: "runtime_closed" };
  try {
    const native = loadNative(data.native);
    if (!native.ok) {
      probe.countUnattached();
      return { ok: false, reason: "native_load_failed" };
    }
    const envId = native.addon.envAttach();
    const row = envId > 0 ? probe.claimIsolateRow(envId, threadId) : -1;
    if (row < 0) {
      probe.countUnattached();
      const full = envId === NativeCode.LIMIT || envId > 0;
      return { ok: false, reason: full ? "isolate_limit" : "internal_error" };
    }
    current = bind(shared, data, native.addon, row);
    return { ok: true, attached: current };
  } catch {
    probe.countUnattached();
    return { ok: false, reason: "internal_error" };
  }
}

function bind(shared: RuntimeShared, data: AttachData, addon: NativeAddon, row: number): Attached {
  const runtime = new WireRuntime(shared, "application", row);
  attachMirror(runtime, addon);
  const exchanges = new ExchangeTable(runtime);
  // A worker thread's own run table: ALS does not cross threads, and FABRIC_RUN_ID and
  // FABRIC_RUN_RESUME_TOKEN belong to the installing thread (a second consumer of one
  // token would fork the run). A run continues here from a token the application passes.
  const runs = new SegmentTable({
    runtime,
    sourceId: data.sourceId,
    key: data.run.idKey,
    identityMode: data.run.identityMode,
    labels: data.run.labels,
    production: data.run.production,
  });
  bindRunTable(runs);
  const hook = installUndiciHook({
    table: exchanges,
    endpoints: data.endpoints,
    scope: captureScope,
    providerRequestId: data.providerRequestId,
    publishers: "bundled",
  });
  if (!hook.installed) {
    hook.uninstall();
    bindRunTable(undefined);
    runtime.countUnattached();
    throw new Error("the undici hook subscribed nothing");
  }
  watchWorkerThreads(runtime);
  let detached = false;
  return {
    runtime,
    hook,
    runs,
    data,
    detach() {
      if (detached) return;
      detached = true;
      try {
        hook.uninstall();
        runs.onFinal();
      } catch {
        // the record names what was lost
      }
      bindRunTable(undefined);
      unwatchWorkerThreads();
      if (current?.runtime === runtime) current = undefined;
    },
  };
}

// --------------------------------------------------------------- the Fabric worker side

export interface IsolateWatchOptions {
  /** How long a created thread has to attach (default {@link UNATTACHED_GRACE_MS}). */
  readonly graceMs?: number;
  /** Called once, when the first unattached thread is counted, with the cut. */
  readonly onUnattached?: (cut: bigint) => void;
  /** The monotonic clock in ms (tests). */
  readonly now?: () => number;
}

/** What one poll did. */
export interface IsolatePoll {
  /** Isolates torn down and settled by this poll. */
  readonly detached: number;
  /** Their positions settled as `shutdown` losses. */
  readonly shutdown: number;
  /** `takeDetachedEnvs` reported OVERFLOW. */
  readonly overflow: boolean;
}

/**
 * The Fabric worker's view of application isolates: polls the detached ring, settles
 * torn-down isolates, counts unattached threads and declares the class once.
 */
export class IsolateWatch {
  readonly #runtime: WireRuntime;
  readonly #exchanges: ExchangeTable;
  readonly #addon: NativeAddon;
  readonly #grace: number;
  readonly #now: () => number;
  readonly #onUnattached: ((cut: bigint) => void) | undefined;
  readonly #ids = new Uint32Array(64);
  /** Pending entries first seen, by entry: thread id and time. */
  readonly #pending = new Map<number, { threadId: number; since: number }>();
  /** Threads that reported themselves unattached (deduplicated, bounded). */
  readonly #reported = new Set<number>();
  readonly #stuck = new Map<string, { head: number; since: number }>();
  #lock: { tag: number; since: number } | undefined;
  #declared = false;
  #channel: BroadcastChannel | undefined;

  constructor(
    runtime: WireRuntime,
    exchanges: ExchangeTable,
    addon: NativeAddon,
    options: IsolateWatchOptions = {},
  ) {
    this.#runtime = runtime;
    this.#exchanges = exchanges;
    this.#addon = addon;
    this.#grace = options.graceMs ?? UNATTACHED_GRACE_MS;
    this.#now = options.now ?? (() => performance.now());
    this.#onUnattached = options.onUnattached;
    try {
      const channel = new BroadcastChannel(ISOLATE_CHANNEL);
      channel.onmessage = (event: unknown) => this.#heard(event);
      (channel as unknown as { unref?: () => void }).unref?.();
      this.#channel = channel;
      // A thread that ran Fabric before this worker existed answers the roll call.
      channel.postMessage({ roll: 1 });
    } catch {
      this.#channel = undefined;
    }
  }

  #heard(event: unknown): void {
    const id = (event as { data?: { unattached?: unknown } } | null)?.data?.unattached;
    if (typeof id !== "number" || this.#reported.has(id) || this.#reported.size >= 4096) return;
    this.#reported.add(id);
    this.#runtime.countUnattached();
  }

  /** One poll: at most every tick. Never throws. */
  poll(): IsolatePoll {
    let detached = 0;
    let shutdown = 0;
    let overflow = false;
    try {
      for (let round = 0; round < 32; round++) {
        const count = this.#addon.takeDetachedEnvs(this.#ids);
        if (count === NativeCode.OVERFLOW) {
          overflow = true;
          this.#runtime.countDetachOverflow();
          continue;
        }
        if (count <= 0) break;
        for (const envId of this.#ids.subarray(0, count)) {
          const settled = this.settle(envId);
          if (settled < 0) continue;
          detached++;
          shutdown += settled;
        }
      }
      this.#pendingScan();
      this.#staleLock();
      this.#stuckRings();
      if (!this.#declared && this.#runtime.stats().isolates.unattached > 0n) {
        this.#declared = true;
        const cut = this.#runtime.cut();
        if (cut !== undefined) this.#onUnattached?.(cut);
      }
    } catch {
      // the next tick polls again
    }
    // Losses were queued: the loop handles them on its next pass, not after a wait.
    if (shutdown > 0) this.#runtime.jobs.wake();
    return { detached, shutdown, overflow };
  }

  /**
   * Settles the isolate of `envId`: its open exchanges become `shutdown` losses, then
   * its lock and run slots are released. Returns the positions lost, or -1 when no
   * attached isolate has that environment (the installing thread, or a module load
   * that never attached).
   */
  settle(envId: number): number {
    const runtime = this.#runtime;
    const row = runtime.rowOfEnv(envId);
    if (row < 0) return -1;
    const settled = this.#exchanges.settleDetached(row + 1);
    runtime.countDetached(settled.shutdown, settled.abandoned);
    runtime.detachIsolate(row);
    return settled.shutdown;
  }

  /** Created threads that did not attach within the grace period are counted. */
  #pendingScan(): void {
    const runtime = this.#runtime;
    const now = this.#now();
    for (let entry = 0; entry < MAX_PENDING_THREADS; entry++) {
      const id = runtime.pendingThread(entry);
      if (id === 0) {
        this.#pending.delete(entry);
        continue;
      }
      let seen = this.#pending.get(entry);
      if (seen === undefined || seen.threadId !== id) {
        seen = { threadId: id, since: now };
        this.#pending.set(entry, seen);
      }
      if (runtime.threadAttached(id)) {
        runtime.clearPendingThread(entry, id);
        this.#pending.delete(entry);
      } else if (now - seen.since >= this.#grace) {
        runtime.clearPendingThread(entry, id);
        this.#pending.delete(entry);
        // A thread that ran Fabric without the runtime may have said so already.
        if (!this.#reported.has(id)) runtime.countUnattached();
      }
    }
  }

  /** A lock one application isolate keeps for a second is freed: its holder is gone. */
  #staleLock(): void {
    const runtime = this.#runtime;
    const tag = runtime.lockHolder;
    // Rows 0 and 1 (tags 1 and 2) are the installing thread and the Fabric worker.
    if (tag <= 2) {
      this.#lock = undefined;
      return;
    }
    const now = this.#now();
    if (this.#lock?.tag !== tag) {
      this.#lock = { tag, since: now };
      return;
    }
    if (now - this.#lock.since >= STALE_LOCK_MS) {
      runtime.breakLock(tag);
      this.#lock = undefined;
    }
  }

  /** A ring head claimed and never published for a second is skipped (§4.4). */
  #stuckRings(): void {
    const runtime = this.#runtime;
    const rings = { jobs: runtime.jobs, losses: runtime.lossRing, runs: runtime.runRing };
    const now = this.#now();
    for (const [name, ring] of Object.entries(rings)) {
      if (ring === undefined) continue;
      const head = ring.stuckHead();
      const seen = this.#stuck.get(name);
      if (head === undefined) {
        this.#stuck.delete(name);
      } else if (seen === undefined || seen.head !== head) {
        this.#stuck.set(name, { head, since: now });
      } else if (now - seen.since >= STUCK_MS && ring.voidStuck(head)) {
        this.#stuck.delete(name);
        runtime.countRingVoided();
        runtime.jobs.wake();
      }
    }
  }

  /** Stops listening for unattached threads. */
  close(): void {
    try {
      this.#channel?.close();
    } catch {
      // nothing to undo
    }
    this.#channel = undefined;
  }
}
