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
import { createHash, randomUUID } from "node:crypto";

import {
  ContentStatus,
  DESCRIPTOR_STATUSES,
  canonicalJson,
  type ContentDescriptor,
} from "./content.js";
import type { GovernedStore } from "./content-store.js";

const DURABILITY_MODES = new Set(["inline", "process", "spooled"]);

const QUEUE_MAX_CAP = 1 << 20;
const PAYLOAD_MAX_CAP = 64 * 1024 * 1024;
const SPOOL_VERSION = "fabric.content-spool/v2";
const LEGACY_SPOOL_VERSION = 1;
const CORRUPT_SUFFIX = ".corrupt";

/** Canonical-JSON bytes for the spool checksum (sorted keys, compact).
 * Spool records are per-language — recovery only verifies records this
 * SDK wrote — so cross-language byte equality is not required here. */
function canonicalJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}

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

/**
 * One unit of store work: an object PUT or a manifest write. `key` is
 * the pending-map and spool-file identity (`object_id` for objects,
 * `manifest:<manifest_id>` for manifests). Manifest tasks carry the full
 * document plus the identity needed to reconcile after a restart
 * (spec 032 §4).
 */
interface Task {
  kind: "object" | "manifest";
  key: string;
  descriptor?: ContentDescriptor;
  content?: string;
  manifest?: Record<string, unknown>;
  manifestId?: string;
  manifestItemSequence?: number;
  manifestRevision?: number;
  decisionId?: string;
  tenantId?: string;
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
    typeof s.manifestUriFor === "function" &&
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
  // Zero is rejected outright: an unbounded queue defeats the documented
  // loss bound and a zero-capacity queue drops everything — neither is a
  // usable "bounded" mode (spec 032 §3).
  if ((config.queueMaxItems ?? 1024) === 0) {
    throw new Error("contentCapture.queueMaxItems must be positive");
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
  /** Keyed settlement subscribers: delivery id -> callback. Removed on
   * terminal settlement so a shared writer never accumulates
   * per-decision callbacks (spec 032 §3). */
  private readonly subscribers = new Map<string, (d: ContentDescriptor, s: string) => void>();
  /** Latest submitted generation for each stable manifest identity. */
  private readonly manifestRevisions = new Map<string, number>();
  private readonly counters = {
    enqueued: 0,
    stored: 0,
    dropped: 0,
    failed: 0,
    spooled: 0,
    recovered: 0,
    corrupt: 0,
  };
  private closed = false;
  private draining = false;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private readonly spoolDirPath: string | undefined;
  private retryBacklog: Task[] = [];
  /** Recovered-but-not-yet-delivered spool tasks. Kept separate from the
   * bounded queue so a restart never discards durable records for
   * capacity reasons (spec 032 §4). */
  private readonly recoveryBacklog: Task[] = [];

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
      try {
        fs.chmodSync(this.spoolDirPath as string, 0o700);
      } catch {
        // best-effort tightening of a pre-existing directory
      }
      this.recoverSpool();
    }
    if (this.config.durability !== "inline") {
      this.scheduleDrain();
    }
  }

  /**
   * Route `objectId`'s terminal settlement to `callback`. Keyed,
   * one-shot: the entry is removed when the delivery settles. Must be
   * registered *before* `submit` so an inline store cannot settle ahead
   * of registration.
   */
  subscribe(
    objectId: string,
    callback: (descriptor: ContentDescriptor, status: string) => void,
  ): void {
    this.subscribers.set(objectId, callback);
  }

  /** Remove a subscriber (e.g. a dropped delivery that never settles). */
  unsubscribe(objectId: string): void {
    this.subscribers.delete(objectId);
  }

  /** Exposed for tests: live keyed subscribers. */
  get subscriberCount(): number {
    return this.subscribers.size;
  }

  /** Exact accounting snapshot — mirrors Python `ContentWriter.stats()`. */
  stats(): Record<string, number> {
    return {
      ...this.counters,
      pending: this.pending.size,
      queue_depth: this.queue.length,
    };
  }

  /**
   * Enqueue a content object for delivery; returns its item status.
   * Never throws — failures map to `dropped`/`failed` statuses.
   */
  submit(
    descriptor: ContentDescriptor,
    content: string,
    decisionId?: string,
    manifestId?: string,
    manifestItemSequence?: number,
  ): string {
    if (this.closed) {
      return ContentStatus.FAILED;
    }
    const task: Task = {
      kind: "object",
      key: descriptor.object_id,
      descriptor,
      content,
      decisionId,
      manifestId,
      manifestItemSequence,
      tenantId: descriptor.tenant_id,
      attempts: 0,
      firstEnqueued: Date.now() / 1000,
    };
    return this.submitTask(task);
  }

  /**
   * Enqueue a manifest write for bounded async/durable delivery. The
   * manifest URI is deterministic and already stamped on the decision
   * span — this only delivers the bytes. Rewrites are idempotent: same
   * `manifestId`, same destination, last complete document wins
   * (spec 032 §5).
   */
  submitManifest(
    manifest: Record<string, unknown>,
    decisionId: string,
    manifestId: string,
    tenantId: string,
  ): string {
    if (this.closed) {
      console.warn("fabric.contentWriter: manifest submit after close");
      return ContentStatus.FAILED;
    }
    const previousRevision = this.manifestRevisions.get(manifestId) ?? 0;
    const revision = previousRevision + 1;
    const task: Task = {
      kind: "manifest",
      key: `manifest:${manifestId}`,
      manifest: { ...manifest },
      manifestId,
      manifestRevision: revision,
      decisionId,
      tenantId,
      attempts: 0,
      firstEnqueued: Date.now() / 1000,
    };
    const status = this.submitTask(task);
    if (status === ContentStatus.PENDING || status === ContentStatus.STORED) {
      this.manifestRevisions.set(
        manifestId,
        Math.max(this.manifestRevisions.get(manifestId) ?? 0, revision),
      );
    }
    return status;
  }

  private submitTask(task: Task): string {
    if (this.config.durability === "inline") {
      return this.deliverInline(task);
    }
    if (this.config.durability === "spooled") {
      // Durable handoff first: a queue-full or spool-full drop never
      // leaves a durable-but-unreported entry behind.
      if (this.queue.length >= this.config.queueMaxItems || !this.spool(task)) {
        this.counters.dropped += 1;
        return ContentStatus.DROPPED;
      }
    }
    if (this.queue.length >= this.config.queueMaxItems) {
      this.counters.dropped += 1;
      return ContentStatus.DROPPED;
    }
    this.pending.set(task.key, task);
    this.queue.push(task);
    this.counters.enqueued += 1;
    this.scheduleDrain();
    return ContentStatus.PENDING;
  }

  private deliverInline(task: Task): string {
    task.attempts += 1;
    try {
      const result =
        task.kind === "manifest"
          ? this.config.store.writeManifest(
              task.manifest as Record<string, unknown>,
              task.decisionId ?? "",
              task.manifestId ?? "",
            )
          : this.config.store.putObject(
              task.descriptor as unknown as Record<string, unknown>,
              task.content as string,
            );
      if (result instanceof Promise) {
        throw new Error("async store cannot satisfy inline durability");
      }
      this.counters.stored += 1;
      this.settle(task, ContentStatus.STORED);
      return ContentStatus.STORED;
    } catch {
      this.counters.failed += 1;
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

  private spoolPath(task: Task): string {
    const safe = task.key.replace(/[^A-Za-z0-9._-]/g, "_");
    return path.join(this.spoolRoot(), `${safe}.json`);
  }

  /** A self-describing durable record (spec 032 §4): enough identity to
   * reconcile the owning manifest after a restart, plus a checksum so
   * torn/corrupted entries quarantine instead of delivering garbage. */
  private spoolRecord(task: Task): Record<string, unknown> {
    const record: Record<string, unknown> = {
      schema_version: SPOOL_VERSION,
      kind: task.kind,
      key: task.key,
      tenant_id: task.tenantId,
      decision_id: task.decisionId,
      attempts: task.attempts,
      first_enqueued: task.firstEnqueued,
      manifest_id: task.manifestId,
      manifest_item_sequence: task.manifestItemSequence,
      manifest_revision: task.manifestRevision,
    };
    if (task.kind === "manifest" && task.manifestId !== undefined) {
      record["ref"] = this.config.store.manifestUriFor(task.manifestId);
    }
    if (task.kind === "manifest") {
      record["manifest"] = task.manifest;
    } else {
      record["descriptor"] = task.descriptor;
      record["ref"] = this.config.store.refFor(
        (task.descriptor as ContentDescriptor).digest.split(":", 2)[1] ?? "",
      );
      record["content_b64"] = Buffer.from(task.content as string, "utf-8").toString("base64");
    }
    record["checksum"] = createHash("sha256").update(canonicalJsonBytes(record)).digest("hex");
    return record;
  }

  private spool(task: Task, count = true): boolean {
    const dir = this.spoolRoot();
    const entry = new TextEncoder().encode(JSON.stringify(this.spoolRecord(task)));
    const target = this.spoolPath(task);
    let previousSize = 0;
    try {
      previousSize = fs.statSync(target).size;
    } catch {
      // no previous revision at this stable path
    }
    if (this.spoolUsage() - previousSize + entry.length > this.config.spoolMaxBytes) {
      return false;
    }
    const tmp = path.join(dir, `.spool-${randomUUID()}.tmp`);
    try {
      const fd = fs.openSync(tmp, "w", 0o600);
      try {
        let offset = 0;
        while (offset < entry.length) {
          const written = fs.writeSync(fd, entry, offset, entry.length - offset);
          if (!Number.isInteger(written) || written <= 0 || written > entry.length - offset) {
            throw new Error("spool write made no valid progress");
          }
          offset += written;
        }
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(tmp, target);
      fs.chmodSync(target, 0o600);
      const dirFd = fs.openSync(dir, "r");
      try {
        fs.fsyncSync(dirFd);
      } finally {
        fs.closeSync(dirFd);
      }
      if (count) this.counters.spooled += 1;
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

  /**
   * Recover spool entries surviving a previous process. Every valid
   * record goes to the recovery backlog — never bounded by the
   * in-memory queue size, so restart never discards durable work.
   * Unreadable or checksum-failed entries quarantine to `*.corrupt`
   * with an explicit stat, never silently ignored.
   */
  private recoverSpool(): void {
    const recovered: Task[] = [];
    for (const name of fs.readdirSync(this.spoolRoot()).sort()) {
      if (!name.endsWith(".json")) continue;
      const file = path.join(this.spoolRoot(), name);
      let task: Task;
      try {
        const record = JSON.parse(fs.readFileSync(file, "utf-8")) as Record<string, unknown>;
        task = this.taskFromRecord(record);
      } catch {
        this.quarantine(file);
        continue;
      }
      recovered.push(task);
      this.pending.set(task.key, task);
      if (task.manifestId !== undefined && task.manifestRevision !== undefined) {
        this.manifestRevisions.set(
          task.manifestId,
          Math.max(this.manifestRevisions.get(task.manifestId) ?? 0, task.manifestRevision),
        );
      }
      this.counters.recovered += 1;
    }
    // Recreate each pending manifest before its recovered objects attempt
    // to fold terminal delivery results into it.
    recovered.sort((a, b) => Number(b.kind === "manifest") - Number(a.kind === "manifest"));
    this.recoveryBacklog.push(...recovered);
  }

  private taskFromRecord(record: Record<string, unknown>): Task {
    const { checksum, ...body } = record;
    const expected = createHash("sha256").update(canonicalJsonBytes(body)).digest("hex");
    if (checksum !== expected) {
      throw new Error("spool record checksum mismatch");
    }
    if (
      record["schema_version"] !== SPOOL_VERSION &&
      record["schema_version"] !== LEGACY_SPOOL_VERSION
    ) {
      throw new Error(`unsupported spool schema_version ${String(record["schema_version"])}`);
    }
    const kind = record["kind"];
    let task: Task;
    if (kind === "manifest") {
      task = {
        kind: "manifest",
        key: String(record["key"]),
        manifest: record["manifest"] as Record<string, unknown>,
        manifestId: String(record["manifest_id"]),
        manifestRevision: Number(record["manifest_revision"] ?? 1),
        decisionId: String(record["decision_id"] ?? ""),
        tenantId: String(record["tenant_id"] ?? ""),
        attempts: 0,
        firstEnqueued: Date.now() / 1000,
      };
    } else if (kind === "object") {
      task = {
        kind: "object",
        key: String(record["key"]),
        descriptor: record["descriptor"] as ContentDescriptor,
        content: Buffer.from(String(record["content_b64"]), "base64").toString("utf-8"),
        decisionId: String(record["decision_id"] ?? ""),
        manifestId: record["manifest_id"] === undefined ? undefined : String(record["manifest_id"]),
        manifestItemSequence:
          record["manifest_item_sequence"] === undefined
            ? undefined
            : Number(record["manifest_item_sequence"]),
        tenantId: String(record["tenant_id"] ?? ""),
        attempts: 0,
        firstEnqueued: Date.now() / 1000,
      };
    } else {
      throw new Error(`unknown spool kind ${String(kind)}`);
    }
    task.attempts = Number(record["attempts"] ?? 0) || 0;
    task.firstEnqueued = Number(record["first_enqueued"] ?? Date.now() / 1000);
    return task;
  }

  /** Move an unreadable record aside; the explicit outcome is a
   * `corrupt` stat + `.corrupt` marker, never silent loss. */
  private quarantine(file: string): void {
    this.counters.corrupt += 1;
    console.warn(`fabric.contentWriter: quarantining corrupt spool entry ${file}`);
    try {
      fs.renameSync(file, file + CORRUPT_SUFFIX);
    } catch {
      // could not move — still reported via the stat
    }
  }

  // -- delivery -------------------------------------------------------------

  private async deliver(task: Task): Promise<void> {
    if (task.kind === "manifest" && this.isStaleManifest(task)) {
      this.settle(task, ContentStatus.STORED);
      return;
    }
    task.attempts += 1;
    let preserveSpool = false;
    try {
      if (task.kind === "manifest") {
        await this.config.store.writeManifest(
          task.manifest as Record<string, unknown>,
          task.decisionId ?? "",
          task.manifestId ?? "",
        );
      } else {
        await this.config.store.putObject(
          task.descriptor as unknown as Record<string, unknown>,
          task.content as string,
        );
        if (!this.subscribers.has(task.key) && task.manifestId !== undefined) {
          await this.reconcileRecoveredObject(task, ContentStatus.STORED);
        }
      }
      this.counters.stored += 1;
      this.settle(task, ContentStatus.STORED);
    } catch {
      const elapsed = Date.now() / 1000 - task.firstEnqueued;
      if (task.attempts < this.config.retryMaxAttempts && elapsed < this.config.retryMaxElapsedS) {
        if (this.config.durability === "spooled") {
          this.spool(task, false);
        }
        this.retryBacklog.push(task);
        return;
      }
      this.counters.failed += 1;
      if (
        task.kind === "object" &&
        task.manifestId !== undefined &&
        !this.subscribers.has(task.key)
      ) {
        try {
          await this.reconcileRecoveredObject(task, ContentStatus.FAILED);
        } catch {
          // Failed reconciliation must leave the original bytes available to a later restart.
          preserveSpool = true;
        }
      }
      this.settle(task, ContentStatus.FAILED);
    }
    if (this.config.durability === "spooled" && !preserveSpool) {
      this.removeSpool(task);
    }
  }

  private removeSpool(task: Task): void {
    try {
      fs.rmSync(this.spoolPath(task), { force: true });
      const dirFd = fs.openSync(this.spoolRoot(), "r");
      try {
        fs.fsyncSync(dirFd);
      } finally {
        fs.closeSync(dirFd);
      }
    } catch {
      // Best-effort cleanup. A surviving record is safe to redeliver.
    }
  }

  private settle(task: Task, status: string): void {
    if (this.pending.get(task.key) === task) {
      this.pending.delete(task.key);
    }
    const callback = this.subscribers.get(task.key);
    this.subscribers.delete(task.key);
    // Manifest tasks carry no subscriber — settlement is bookkeeping
    // only; object tasks route to their manifest item.
    if (callback !== undefined && task.descriptor !== undefined) {
      try {
        callback(task.descriptor, status);
      } catch {
        // a sink hook must never break delivery
      }
    }
  }

  private isStaleManifest(task: Task): boolean {
    if (task.manifestId === undefined || task.manifestRevision === undefined) {
      return false;
    }
    return task.manifestRevision < (this.manifestRevisions.get(task.manifestId) ?? 0);
  }

  private async reconcileRecoveredObject(task: Task, status: string): Promise<void> {
    if (task.descriptor === undefined || task.manifestId === undefined) {
      throw new Error("recovered object lacks descriptor/manifest identity");
    }
    const manifest = await this.config.store.readManifest(
      this.config.store.manifestUriFor(task.manifestId),
    );
    const items = manifest["items"];
    if (!Array.isArray(items)) {
      throw new Error("recovered manifest has no items array");
    }
    const item = this.findManifestItem(items, task);
    if (item === undefined) {
      throw new Error(`manifest ${task.manifestId} has no item for ${task.descriptor.object_id}`);
    }
    if (item["status"] !== ContentStatus.PENDING) {
      return;
    }
    const statusValue =
      status === ContentStatus.STORED && task.descriptor.representation === "truncated"
        ? ContentStatus.TRUNCATED
        : status;
    item["status"] = statusValue;
    if (DESCRIPTOR_STATUSES.has(statusValue)) {
      item["descriptor"] = { ...task.descriptor, status: statusValue };
    } else {
      delete item["descriptor"];
      delete item["ref"];
      item["status_reason"] = "delivery_failed_after_restart";
    }
    const completeness: Record<string, number> = {};
    const rolesObserved = new Set<string>();
    for (const candidate of items) {
      if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) continue;
      const record = candidate as Record<string, unknown>;
      const candidateStatus = String(record["status"] ?? "");
      completeness[candidateStatus] = (completeness[candidateStatus] ?? 0) + 1;
      if (DESCRIPTOR_STATUSES.has(candidateStatus)) {
        rolesObserved.add(String(record["role"]));
      }
    }
    manifest["completeness"] = completeness;
    const coverage =
      typeof manifest["coverage"] === "object" &&
      manifest["coverage"] !== null &&
      !Array.isArray(manifest["coverage"])
        ? (manifest["coverage"] as Record<string, unknown>)
        : {};
    coverage["roles_observed"] = [...rolesObserved].sort();
    manifest["coverage"] = coverage;
    await this.config.store.writeManifest(
      manifest,
      task.decisionId ?? String(manifest["decision_id"] ?? ""),
      task.manifestId,
    );
  }

  private findManifestItem(items: unknown[], task: Task): Record<string, unknown> | undefined {
    const candidates = items.filter(
      (item): item is Record<string, unknown> =>
        typeof item === "object" && item !== null && !Array.isArray(item),
    );
    if (task.manifestItemSequence !== undefined) {
      const bySequence = candidates.find(
        (candidate) => candidate["sequence"] === task.manifestItemSequence,
      );
      if (bySequence !== undefined) return bySequence;
    }
    return candidates.find((candidate) => {
      const descriptor = candidate["descriptor"];
      return (
        typeof descriptor === "object" &&
        descriptor !== null &&
        !Array.isArray(descriptor) &&
        (descriptor as Record<string, unknown>)["object_id"] === task.descriptor?.object_id
      );
    });
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
      // Recovered durable work drains after live submissions — never
      // dropped for queue-capacity reasons (spec 032 §4).
      for (;;) {
        const task = this.recoveryBacklog.shift();
        if (task === undefined) {
          break;
        }
        await this.deliver(task);
      }
    } finally {
      this.draining = false;
    }
    if (
      !this.closed &&
      (this.queue.length > 0 || this.retryBacklog.length > 0 || this.recoveryBacklog.length > 0)
    ) {
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
      if (
        this.pending.size === 0 &&
        this.queue.length === 0 &&
        this.retryBacklog.length === 0 &&
        this.recoveryBacklog.length === 0
      ) {
        break;
      }
      if (deadline !== undefined && Date.now() >= deadline) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    return {
      stored: this.counters.stored,
      pending: this.pending.size,
      dropped: this.counters.dropped,
      failed: this.counters.failed,
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
