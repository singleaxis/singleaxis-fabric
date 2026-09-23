// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Bounded, passive delivery of content objects to a GovernedStore
 * (spec 032) — mirrors Python `fabric._content_writer`.
 *
 * `submit` returns the object status: `pending` when accepted for later
 * delivery, `stored` (inline), `dropped` at a resource bound, or
 * `failed` when the store itself rejected the item. It never throws into
 * the agent path. Delivery runs on the event loop via a scheduled drain
 * — Node's cooperative concurrency replaces Python's worker thread.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";

import { ContentStatus, type ContentDescriptor } from "./content.js";
import type { GovernedStore } from "./content-store.js";

const DURABILITY_MODES = new Set(["inline", "process", "spooled"]);

const QUEUE_MAX_CAP = 1 << 20;
const PAYLOAD_MAX_CAP = 64 * 1024 * 1024;

/** Explicit governed-capture configuration (spec 028). */
export interface ContentCaptureConfig {
  /** Customer-controlled governed store — required. */
  store: GovernedStore;
  /** Role filter: `"all"` or an explicit subset of CONTENT_ROLES. */
  roles: "all" | ReadonlySet<string>;
  /** `inline` (sync store write on the caller path), `process`
   * (in-memory queue + event-loop drain), or `spooled` (fsync'd local
   * handoff first). `inline` requires a synchronous store. */
  durability?: "inline" | "process" | "spooled";
  /** Bounded queue capacity; overflow marks the item `dropped`. */
  queueMaxItems?: number;
  /** Per-object byte bound; oversized content is truncated + marked. */
  payloadMaxBytes?: number;
  /** Directory for the durable spool; required for `spooled`. */
  spoolDir?: string;
  /** Spool byte bound. */
  spoolMaxBytes?: number;
  /** Delivery attempt bound per object. */
  retryMaxAttempts?: number;
  /** Delivery retry wall-clock bound (seconds). */
  retryMaxElapsedS?: number;
  /** Drain-loop interval between passes (ms). */
  workerFlushIntervalMs?: number;
  /** `close()`/auto-flush deadline (seconds). */
  shutdownFlushTimeoutS?: number;
}

/** Outcome of {@link ContentWriter.flush} — exact accounting. */
export interface FlushResult {
  stored: number;
  pending: number;
  dropped: number;
  failed: number;
}

interface Task {
  descriptor: ContentDescriptor;
  content: string;
  attempts: number;
  firstEnqueued: number;
}

function isGovernedStoreShape(store: unknown): store is GovernedStore {
  const s = store as GovernedStore;
  return (
    s !== null &&
    typeof s === "object" &&
    typeof s.tenantId === "string" &&
    s.tenantId.length > 0 &&
    typeof s.refFor === "function" &&
    typeof s.putObject === "function" &&
    typeof s.writeManifest === "function" &&
    typeof s.ownsUri === "function" &&
    typeof s.read === "function"
  );
}

/** Validate a config once; throws on any missing piece (fail closed). */
export function validateContentCaptureConfig(
  config: ContentCaptureConfig,
  allRoles: ReadonlySet<string>,
): ReadonlySet<string> {
  if (!isGovernedStoreShape(config.store)) {
    throw new Error(
      "contentCapture.store must implement the governed store contract " +
        "with a tenant namespace (LocalFilesystemContentStore/S3ContentStore " +
        "with tenantId, or an equivalent GovernedStore)",
    );
  }
  const durability = config.durability ?? "process";
  if (!DURABILITY_MODES.has(durability)) {
    throw new Error(`contentCapture.durability must be one of ${[...DURABILITY_MODES].join(", ")}`);
  }
  if (durability === "inline" && !config.store.synchronous) {
    throw new Error(
      "contentCapture.durability 'inline' requires a synchronous store " +
        "(LocalFilesystemContentStore); S3 is async — use 'process' or 'spooled'",
    );
  }
  if (durability === "spooled" && !config.spoolDir) {
    throw new Error("contentCapture: spooled durability requires spoolDir");
  }
  if (config.roles !== "all") {
    const unknown = [...config.roles].filter((r) => !allRoles.has(r));
    if (unknown.length > 0) {
      throw new Error(
        `contentCapture: unknown roles ${unknown.sort().join(", ")}; ` +
          `supported: ${[...allRoles].sort().join(", ")}`,
      );
    }
  }
  for (const [name, value, cap] of [
    ["queueMaxItems", config.queueMaxItems ?? 1024, QUEUE_MAX_CAP],
    ["payloadMaxBytes", config.payloadMaxBytes ?? 1024 * 1024, PAYLOAD_MAX_CAP],
  ] as const) {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`contentCapture.${name} must be a non-negative int`);
    }
    if (value > cap) {
      throw new Error(`contentCapture.${name} exceeds hard cap ${cap}`);
    }
  }
  return config.roles === "all" ? allRoles : config.roles;
}

export class ContentWriter {
  private readonly config: Required<
    Pick<
      ContentCaptureConfig,
      | "durability"
      | "queueMaxItems"
      | "payloadMaxBytes"
      | "spoolMaxBytes"
      | "retryMaxAttempts"
      | "retryMaxElapsedS"
      | "workerFlushIntervalMs"
      | "shutdownFlushTimeoutS"
    >
  > &
    ContentCaptureConfig;
  private readonly queue: Task[] = [];
  private readonly pending = new Map<string, Task>();
  private readonly settledCallbacks: ((d: ContentDescriptor, s: string) => void)[] = [];
  private readonly stats = {
    enqueued: 0,
    stored: 0,
    dropped: 0,
    failed: 0,
    spooled: 0,
    recovered: 0,
  };
  private closed = false;
  private draining = false;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private readonly spoolDirPath: string | undefined;
  private retryBacklog: Task[] = [];

  constructor(config: ContentCaptureConfig) {
    this.config = {
      durability: config.durability ?? "process",
      queueMaxItems: config.queueMaxItems ?? 1024,
      payloadMaxBytes: config.payloadMaxBytes ?? 1024 * 1024,
      spoolMaxBytes: config.spoolMaxBytes ?? 1024 * 1024 * 1024,
      retryMaxAttempts: config.retryMaxAttempts ?? 5,
      retryMaxElapsedS: config.retryMaxElapsedS ?? 300.0,
      workerFlushIntervalMs: config.workerFlushIntervalMs ?? 250,
      shutdownFlushTimeoutS: config.shutdownFlushTimeoutS ?? 10.0,
      ...config,
    };
    if (this.config.durability === "spooled") {
      this.spoolDirPath = this.config.spoolDir;
      fs.mkdirSync(this.spoolDirPath as string, { recursive: true, mode: 0o700 });
      this.recoverSpool();
    }
    if (this.config.durability !== "inline") {
      this.scheduleDrain();
    }
  }

  /** Register a hook fired when a pending item reaches stored/failed. */
  onSettled(callback: (descriptor: ContentDescriptor, status: string) => void): void {
    this.settledCallbacks.push(callback);
  }

  /**
   * Enqueue a content object for delivery; returns its item status.
   * Never throws — failures map to `dropped`/`failed` statuses.
   */
  submit(descriptor: ContentDescriptor, content: string): string {
    if (this.closed) {
      return ContentStatus.FAILED;
    }
    const task: Task = {
      descriptor,
      content,
      attempts: 0,
      firstEnqueued: Date.now() / 1000,
    };
    if (this.config.durability === "inline") {
      return this.deliverInline(task);
    }
    if (this.config.durability === "spooled") {
      // Durable handoff first: a queue-full or spool-full drop never
      // leaves a durable-but-unreported entry behind.
      if (this.queue.length >= this.config.queueMaxItems || !this.spool(task)) {
        this.stats.dropped += 1;
        return ContentStatus.DROPPED;
      }
    }
    if (this.queue.length >= this.config.queueMaxItems) {
      this.stats.dropped += 1;
      return ContentStatus.DROPPED;
    }
    this.queue.push(task);
    this.pending.set(descriptor.object_id, task);
    this.stats.enqueued += 1;
    this.scheduleDrain();
    return ContentStatus.PENDING;
  }

  private deliverInline(task: Task): string {
    task.attempts += 1;
    try {
      // A synchronous store resolves immediately.
      const result = this.config.store.putObject(
        task.descriptor as unknown as Record<string, unknown>,
        task.content,
      );
      if (result instanceof Promise) {
        throw new Error("async store cannot satisfy inline durability");
      }
      this.stats.stored += 1;
      this.settle(task, ContentStatus.STORED);
      return ContentStatus.STORED;
    } catch {
      this.stats.failed += 1;
      this.settle(task, ContentStatus.FAILED);
      return ContentStatus.FAILED;
    }
  }

  // -- spool --------------------------------------------------------------

  private spoolRoot(): string {
    if (this.spoolDirPath === undefined) {
      throw new Error("spool requested without a spoolDir");
    }
    return this.spoolDirPath;
  }

  private spoolPath(objectId: string): string {
    return path.join(this.spoolRoot(), `${objectId}.json`);
  }

  private spool(task: Task): boolean {
    const dir = this.spoolRoot();
    const entry = new TextEncoder().encode(
      JSON.stringify({
        descriptor: task.descriptor,
        content_b64: Buffer.from(task.content, "utf-8").toString("base64"),
      }),
    );
    if (this.spoolUsage() + entry.length > this.config.spoolMaxBytes) {
      return false;
    }
    const target = this.spoolPath(task.descriptor.object_id);
    const tmp = path.join(dir, `.spool-${randomUUID()}.tmp`);
    try {
      const fd = fs.openSync(tmp, "w", 0o600);
      try {
        fs.writeSync(fd, entry);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(tmp, target);
      const dirFd = fs.openSync(dir, "r");
      try {
        fs.fsyncSync(dirFd);
      } finally {
        fs.closeSync(dirFd);
      }
      this.stats.spooled += 1;
      return true;
    } catch {
      try {
        fs.unlinkSync(tmp);
      } catch {
        // best-effort
      }
      return false;
    }
  }

  private spoolUsage(): number {
    let total = 0;
    for (const name of fs.readdirSync(this.spoolRoot())) {
      if (!name.endsWith(".json")) continue;
      try {
        total += fs.statSync(path.join(this.spoolRoot(), name)).size;
      } catch {
        // entry vanished — ignore
      }
    }
    return total;
  }

  private recoverSpool(): void {
    for (const name of fs.readdirSync(this.spoolRoot()).sort()) {
      if (!name.endsWith(".json")) continue;
      const file = path.join(this.spoolRoot(), name);
      let task: Task;
      try {
        const entry = JSON.parse(fs.readFileSync(file, "utf-8")) as {
          descriptor: ContentDescriptor;
          content_b64: string;
        };
        task = {
          descriptor: entry.descriptor,
          content: Buffer.from(entry.content_b64, "base64").toString("utf-8"),
          attempts: 0,
          firstEnqueued: Date.now() / 1000,
        };
      } catch {
        continue;
      }
      if (this.queue.length >= this.config.queueMaxItems) {
        this.stats.dropped += 1;
        continue;
      }
      this.queue.push(task);
      this.pending.set(task.descriptor.object_id, task);
      this.stats.recovered += 1;
    }
  }

  // -- delivery -------------------------------------------------------------

  private async deliver(task: Task): Promise<void> {
    task.attempts += 1;
    try {
      await this.config.store.putObject(
        task.descriptor as unknown as Record<string, unknown>,
        task.content,
      );
      this.stats.stored += 1;
      this.settle(task, ContentStatus.STORED);
    } catch {
      const elapsed = Date.now() / 1000 - task.firstEnqueued;
      if (task.attempts < this.config.retryMaxAttempts && elapsed < this.config.retryMaxElapsedS) {
        this.retryBacklog.push(task);
        return;
      }
      this.stats.failed += 1;
      this.settle(task, ContentStatus.FAILED);
    }
    if (this.config.durability === "spooled") {
      try {
        fs.unlinkSync(this.spoolPath(task.descriptor.object_id));
      } catch {
        // best-effort spool cleanup
      }
    }
  }

  private settle(task: Task, status: string): void {
    this.pending.delete(task.descriptor.object_id);
    for (const cb of this.settledCallbacks) {
      try {
        cb(task.descriptor, status);
      } catch {
        // a sink hook must never break delivery
      }
    }
  }

  private scheduleDrain(): void {
    if (this.timer !== undefined || this.config.durability === "inline") {
      return;
    }
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.drain();
    }, this.config.workerFlushIntervalMs);
    this.timer.unref();
  }

  private async drain(): Promise<void> {
    if (this.draining) {
      return;
    }
    this.draining = true;
    try {
      const backlog = this.retryBacklog;
      this.retryBacklog = [];
      for (const task of backlog) {
        await this.deliver(task);
      }
      for (;;) {
        const task = this.queue.shift();
        if (task === undefined) {
          break;
        }
        await this.deliver(task);
      }
    } finally {
      this.draining = false;
    }
    if (!this.closed && (this.queue.length > 0 || this.retryBacklog.length > 0)) {
      this.scheduleDrain();
    }
  }

  // -- lifecycle --------------------------------------------------------------

  /**
   * Block until the queue + retry backlog drain or `timeoutS` expires.
   * Opt-in awaitable for tests and graceful shutdown — a `pending`
   * remainder is an honest gap, not a silent loss.
   */
  async flush(timeoutS?: number): Promise<FlushResult> {
    const deadline = timeoutS === undefined ? undefined : Date.now() + timeoutS * 1000;
    for (;;) {
      // Give the drain loop a chance to make progress — bounded by the
      // deadline so a hung store cannot pin close() forever (a pending
      // remainder is the honest gap).
      const draining = this.drain();
      if (deadline !== undefined) {
        await Promise.race([
          draining,
          new Promise((resolve) => setTimeout(resolve, Math.max(1, deadline - Date.now()))),
        ]);
      } else {
        await draining;
      }
      if (this.pending.size === 0 && this.queue.length === 0 && this.retryBacklog.length === 0) {
        break;
      }
      if (deadline !== undefined && Date.now() >= deadline) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    return {
      stored: this.stats.stored,
      pending: this.pending.size,
      dropped: this.stats.dropped,
      failed: this.stats.failed,
    };
  }

  async close(): Promise<FlushResult> {
    this.closed = true;
    const result = await this.flush(this.config.shutdownFlushTimeoutS);
    if (this.timer !== undefined) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
    return result;
  }
}
