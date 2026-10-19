// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Bounded execution of customer redaction code (spec 049 §7.1, §7.7 rule 4).
 *
 * A customer redactor is code Fabric does not control: it may throw, run long or never
 * return. In Node.js anything run on the application's thread blocks its event loop, so
 * a redactor is a customer *module* loaded in a `worker_threads` Worker (a function
 * cannot cross threads). Each call waits at most its timeout; on timeout the Worker is
 * terminated (`worker.terminate()` preempts even a synchronous infinite loop) and the
 * caller withholds the content (`protection_failed`). At most `maxConcurrent` calls run
 * at once and at most `maxAbandoned` timed-out Workers may still be terminating; beyond
 * either bound a call is refused at once (`saturated`), never queued, so a slow or hung
 * redactor never stalls capture. Nothing here logs a value or keeps error text.
 */

import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";

/**
 * A customer redactor: an ES or CommonJS module, by absolute path or `file:` URL, whose
 * export `exportName` (default `redact`; `default` for a default export) maps the bytes
 * of one object (`Uint8Array`) to their masked replacement (`Uint8Array`, or a promise of
 * one). It runs in a worker thread, so it shares no state with the application.
 */
export interface RedactorModule {
  module: string | URL;
  exportName?: string;
}

export type TransformOutcome =
  | { outcome: "ok"; data: Uint8Array }
  | { outcome: "error" | "invalid_output" | "timeout" | "saturated" };

export const DEFAULT_MAX_CONCURRENT = 2;
export const DEFAULT_MAX_ABANDONED = 2;
const EXPORT_NAME = /^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/;

/**
 * Run by `new Worker(..., { eval: true })` (no separate file to package). Written to be
 * valid as a CommonJS script and as an ES module (a Worker inherits `--input-type`), so
 * it uses only dynamic `import()`.
 */
export const WORKER_SOURCE = `"use strict";
(async () => {
  const { parentPort, workerData } = await import("node:worker_threads");
  const loaded = import(workerData.href).then((module) => {
    const fn = module[workerData.exportName];
    if (typeof fn !== "function") throw new TypeError("redactor export is not a function");
    return fn;
  });
  loaded.catch(() => undefined);
  parentPort.on("message", async ({ id, data }) => {
    let reply;
    try {
      const fn = await loaded;
      const out = await fn(new Uint8Array(data));
      if (out instanceof Uint8Array) {
        const copy = new Uint8Array(out);
        reply = [{ id, kind: "ok", data: copy }, [copy.buffer]];
      } else {
        reply = [{ id, kind: "invalid_output" }, []];
      }
    } catch {
      reply = [{ id, kind: "error" }, []];
    }
    parentPort.postMessage(reply[0], reply[1]);
  });
})();
`;

/** The module's `file:` URL; throws (fixed text) for anything else. */
export function redactorHref(spec: RedactorModule): string {
  if (typeof spec === "function")
    throw new Error(
      "in-process redactor functions are not supported for redact and masked_only: pass " +
        "{ module } naming a customer module, which runs in a worker thread",
    );
  if (spec === null || typeof spec !== "object")
    throw new Error("a redactor is { module, exportName? }");
  const { module, exportName = "redact" } = spec;
  if (typeof exportName !== "string" || !EXPORT_NAME.test(exportName))
    throw new Error("redactor exportName must be a JavaScript identifier");
  if (module instanceof URL) {
    if (module.protocol !== "file:")
      throw new Error("a redactor module must be an absolute path or file: URL");
    return module.href;
  }
  if (typeof module === "string" && module.startsWith("file:")) return new URL(module).href;
  if (typeof module === "string" && isAbsolute(module)) return pathToFileURL(module).href;
  throw new Error("a redactor module must be an absolute path or file: URL");
}

interface Reply {
  id: number;
  kind: "ok" | "invalid_output" | "error";
  data?: Uint8Array;
}

/** Runs one redactor module's calls in Worker threads, each bounded by a timeout. */
export class WorkerTransformRunner {
  readonly #href: string;
  readonly #exportName: string;
  readonly #maxConcurrent: number;
  readonly #maxAbandoned: number;
  readonly #idle: Worker[] = [];
  #active = 0;
  #terminating = 0;
  #nextId = 0;
  #closed = false;
  timeouts = 0;
  saturated = 0;

  constructor(
    spec: RedactorModule,
    options: { maxConcurrent?: number; maxAbandoned?: number } = {},
  ) {
    this.#href = redactorHref(spec);
    this.#exportName = spec.exportName ?? "redact";
    this.#maxConcurrent = options.maxConcurrent ?? DEFAULT_MAX_CONCURRENT;
    this.#maxAbandoned = options.maxAbandoned ?? DEFAULT_MAX_ABANDONED;
    for (const bound of [this.#maxConcurrent, this.#maxAbandoned])
      if (!Number.isInteger(bound) || bound < 1)
        throw new Error("redactor concurrency bounds must be positive integers");
  }

  /** Counters only, never a value. */
  stats(): {
    transform_timeouts: number;
    transform_saturated: number;
    transform_abandoned: number;
  } {
    return {
      transform_timeouts: this.timeouts,
      transform_saturated: this.saturated,
      transform_abandoned: this.#terminating,
    };
  }

  /** One call: never rejects, never waits longer than `timeoutMs` (plus Worker start). */
  async run(data: Uint8Array, timeoutMs: number): Promise<TransformOutcome> {
    if (
      this.#closed ||
      this.#active >= this.#maxConcurrent ||
      this.#terminating >= this.#maxAbandoned
    ) {
      this.saturated += 1;
      return { outcome: "saturated" };
    }
    this.#active += 1;
    let worker: Worker;
    try {
      worker = this.#idle.pop() ?? this.#spawn();
    } catch {
      this.#active -= 1;
      return { outcome: "error" };
    }
    try {
      const result = await this.#call(worker, data, timeoutMs);
      if (result.outcome === "timeout") {
        this.timeouts += 1;
        this.#abandon(worker);
      } else if (result.alive && !this.#closed) {
        this.#idle.push(worker);
      } else if (result.alive) {
        void worker.terminate().catch(() => undefined);
      }
      return result.outcome === "ok" ? { outcome: "ok", data: result.data! } : result;
    } finally {
      this.#active -= 1;
    }
  }

  /** Terminate idle Workers; later calls are refused (`saturated`). */
  async close(): Promise<void> {
    this.#closed = true;
    await Promise.all(this.#idle.splice(0).map((w) => w.terminate().catch(() => undefined)));
  }

  #spawn(): Worker {
    const worker = new Worker(WORKER_SOURCE, {
      eval: true,
      workerData: { href: this.#href, exportName: this.#exportName },
    });
    worker.unref(); // never keeps the application alive
    worker.on("error", () => undefined); // an uncaught worker error is an "error" outcome
    return worker;
  }

  #abandon(worker: Worker): void {
    this.#terminating += 1;
    void worker
      .terminate()
      .catch(() => undefined)
      .finally(() => {
        this.#terminating -= 1;
      });
  }

  #call(
    worker: Worker,
    data: Uint8Array,
    timeoutMs: number,
  ): Promise<
    | { outcome: "ok"; data: Uint8Array; alive: true }
    | { outcome: "error" | "invalid_output"; alive: boolean }
    | { outcome: "timeout" }
  > {
    const id = (this.#nextId += 1);
    return new Promise((resolve) => {
      const cleanup = () => {
        clearTimeout(timer);
        worker.off("message", onMessage);
        worker.off("exit", onExit);
        worker.off("error", onError);
      };
      const onMessage = (reply: Reply) => {
        if (reply?.id !== id) return;
        cleanup();
        if (reply.kind === "ok" && reply.data instanceof Uint8Array)
          resolve({ outcome: "ok", data: reply.data, alive: true });
        else resolve({ outcome: reply.kind === "ok" ? "error" : reply.kind, alive: true });
      };
      const onExit = () => {
        cleanup();
        resolve({ outcome: "error", alive: false });
      };
      const onError = () => {
        cleanup();
        resolve({ outcome: "error", alive: false });
      };
      const timer = setTimeout(() => {
        cleanup();
        resolve({ outcome: "timeout" });
      }, timeoutMs); // kept referenced: bounded by the timeout
      worker.on("message", onMessage);
      worker.once("exit", onExit);
      worker.once("error", onError);
      try {
        const copy = new Uint8Array(data); // the caller's buffer is never transferred
        worker.postMessage({ id, data: copy }, [copy.buffer]);
      } catch {
        cleanup();
        resolve({ outcome: "error", alive: true });
      }
    });
  }
}
