// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Opt-in, caller-reported content-v2 exact-byte capture. This is a bounded
 * process-memory handoff, not an automatic tool interceptor, durable spool,
 * OTLP delivery receipt, or run-completeness verdict.
 */

import { createHash, randomUUID } from "node:crypto";

import type { GovernedStore } from "./content-store.js";

export const BYTE_EVIDENCE_ROLES = new Set([
  "model.request.instructions",
  "model.request.messages",
  "model.request.tool_definitions",
  "model.request.parameters",
  "model.output.messages",
  "tool.definition",
  "tool.call.arguments",
  "tool.call.result",
  "retrieval.query",
  "retrieval.results",
  "memory.write.content",
  "memory.read.content",
  "side_effect.request",
  "side_effect.result",
  "context.file",
  "interaction.payload",
  "terminal.argv",
  "terminal.stdin",
  "terminal.stdout",
  "terminal.stderr",
  "remote.request",
  "remote.result",
  "remote.stream",
  "database.query",
  "database.parameters",
  "database.rows",
  "database.mutation",
  "network.request",
  "network.response",
  "network.stream",
  "sandbox.config",
  "sandbox.output",
  "artifact.before",
  "artifact.after",
  "service.receipt",
]);

export const BYTE_EVIDENCE_BOUNDARIES = new Set([
  "caller",
  "provider_bound",
  "tool",
  "terminal",
  "sandbox",
  "remote",
  "host",
  "service",
]);

const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MEDIA_TYPE = /^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/;
const HARD_MAX_BYTES = 64 * 1024 * 1024;
const HARD_MAX_ITEMS = 1 << 20;

export interface ByteEvidenceDescriptor {
  schema_version: "fabric.content-object/v2";
  object_id: string;
  tenant_id: string;
  run_id?: string;
  operation_id?: string;
  attempt_id?: string;
  stream_id?: string;
  chunk_index?: number;
  role: string;
  media_type: string;
  encoding: "binary";
  representation: "exact" | "unavailable";
  source_byte_length?: number;
  source_sha256?: string;
  stored_byte_length?: number;
  stored_sha256?: string;
  ref?: string;
  provenance: "caller_reported";
  boundary: string;
  source_id: string;
  source_epoch: number;
  source_sequence: number;
  captured_at: string;
  status: "pending" | "stored" | "not_captured" | "dropped" | "failed";
  status_reason?: string;
}

export interface ByteEvidenceCapture {
  role: string;
  boundary: string;
  sourceId: string;
  sourceEpoch: number;
  sourceSequence: number;
  mediaType?: string;
  runId?: string;
  operationId?: string;
  attemptId?: string;
  streamId?: string;
  chunkIndex?: number;
}

export interface ByteEvidenceConfig {
  /** Store must support the v2 byte methods, bound to exactly this tenant. */
  store: GovernedStore;
  /** Closed, explicitly enabled role set. `all` is intentionally absent. */
  roles: ReadonlySet<string>;
  /** In-memory queue length; overflow becomes a visible dropped descriptor. */
  queueMaxItems?: number;
  /** Bounded descriptor index, including terminal outcomes until drained. */
  maxRecords?: number;
  /** Maximum distinct source epochs tracked for monotonicity. */
  maxSources?: number;
  /** Larger inputs are not truncated or mislabeled exact. */
  payloadMaxBytes?: number;
  /** Best-effort delivery attempts; no source spool or durable receipt. */
  retryMaxAttempts?: number;
}

interface WorkItem {
  descriptor: ByteEvidenceDescriptor;
  bytes: Uint8Array;
}

export class ByteEvidenceRecorder {
  private readonly store: GovernedStore;
  private readonly roles: ReadonlySet<string>;
  private readonly queueMaxItems: number;
  private readonly maxRecords: number;
  private readonly maxSources: number;
  private readonly payloadMaxBytes: number;
  private readonly retryMaxAttempts: number;
  private readonly highWater = new Map<string, number>();
  private readonly records = new Map<string, ByteEvidenceDescriptor>();
  private readonly queue: WorkItem[] = [];
  private running = false;
  private closed = false;
  private lostRecordCount = 0;
  private readonly counts = { stored: 0, pending: 0, dropped: 0, failed: 0, not_captured: 0 };

  constructor(config: ByteEvidenceConfig) {
    if (
      !config.store ||
      typeof config.store.tenantId !== "string" ||
      typeof config.store.evidenceRefFor !== "function" ||
      typeof config.store.putBytesObject !== "function"
    ) {
      throw new Error("ByteEvidenceRecorder requires a tenant-bound content-v2 byte store");
    }
    if (!OPAQUE_ID.test(config.store.tenantId)) throw new Error("invalid store tenantId");
    if (
      !(config.roles instanceof Set) ||
      config.roles.size === 0 ||
      [...config.roles].some((role) => !BYTE_EVIDENCE_ROLES.has(role))
    ) {
      throw new Error("byte evidence requires a non-empty, closed role set");
    }
    this.queueMaxItems = config.queueMaxItems ?? 64;
    this.maxRecords = config.maxRecords ?? 4096;
    this.maxSources = config.maxSources ?? 4096;
    this.payloadMaxBytes = config.payloadMaxBytes ?? 1024 * 1024;
    this.retryMaxAttempts = config.retryMaxAttempts ?? 3;
    if (
      !Number.isInteger(this.queueMaxItems) ||
      this.queueMaxItems < 1 ||
      this.queueMaxItems > HARD_MAX_ITEMS ||
      !Number.isInteger(this.maxRecords) ||
      this.maxRecords < 1 ||
      this.maxRecords > HARD_MAX_ITEMS ||
      !Number.isInteger(this.maxSources) ||
      this.maxSources < 1 ||
      this.maxSources > HARD_MAX_ITEMS ||
      !Number.isInteger(this.payloadMaxBytes) ||
      this.payloadMaxBytes < 1 ||
      this.payloadMaxBytes > HARD_MAX_BYTES ||
      !Number.isInteger(this.retryMaxAttempts) ||
      this.retryMaxAttempts < 1 ||
      this.retryMaxAttempts > 20
    ) {
      throw new Error("invalid bounded byte-evidence queue, payload, or retry limit");
    }
    this.store = config.store;
    this.roles = new Set(config.roles);
  }

  /** Snapshot of terminal and pending counts. A pending remainder is a gap. */
  stats(): Record<string, number> {
    return {
      ...this.counts,
      queue_depth: this.queue.length,
      indexed_records: this.records.size,
      unretained_drops: this.lostRecordCount,
    };
  }

  /** Process-local status lookup. `undefined` after a terminal record is drained. */
  get(objectId: string): ByteEvidenceDescriptor | undefined {
    const record = this.records.get(objectId);
    return record === undefined ? undefined : { ...record };
  }

  /** Remove and return all terminal records; pending records stay indexed. */
  drainSettled(): ByteEvidenceDescriptor[] {
    const settled: ByteEvidenceDescriptor[] = [];
    for (const [id, record] of this.records) {
      if (record.status !== "pending") {
        settled.push({ ...record });
        this.records.delete(id);
      }
    }
    return settled;
  }

  /**
   * Capture exactly the caller-supplied bytes. `provenance` is always
   * caller_reported; SDK entry cannot attest a native/protocol boundary.
   * No content bytes are put on OTLP. Caller must retain the returned
   * descriptor (or persist it separately); this slice has no run manifest.
   */
  capture(data: Uint8Array, options: ByteEvidenceCapture): ByteEvidenceDescriptor {
    if (!(data instanceof Uint8Array)) throw new TypeError("byte evidence requires Uint8Array");
    this.validateOptions(options);
    const key = JSON.stringify([options.sourceId, options.sourceEpoch]);
    const previous = this.highWater.get(key);
    if (previous !== undefined && options.sourceSequence <= previous) {
      throw new Error("sourceSequence must increase within sourceId/sourceEpoch");
    }
    const sourceRegistryFull = previous === undefined && this.highWater.size >= this.maxSources;
    if (!sourceRegistryFull) this.highWater.set(key, options.sourceSequence);
    const descriptor: ByteEvidenceDescriptor = {
      schema_version: "fabric.content-object/v2",
      object_id: randomUUID(),
      tenant_id: this.store.tenantId,
      role: options.role,
      media_type: options.mediaType ?? "application/octet-stream",
      encoding: "binary",
      representation: "unavailable",
      provenance: "caller_reported",
      boundary: options.boundary,
      source_id: options.sourceId,
      source_epoch: options.sourceEpoch,
      source_sequence: options.sourceSequence,
      captured_at: new Date().toISOString(),
      status: "not_captured",
    };
    for (const [keyName, value] of [
      ["run_id", options.runId],
      ["operation_id", options.operationId],
      ["attempt_id", options.attemptId],
      ["stream_id", options.streamId],
    ] as const) {
      if (value !== undefined) descriptor[keyName] = value;
    }
    if (options.chunkIndex !== undefined) descriptor.chunk_index = options.chunkIndex;
    if (sourceRegistryFull) {
      descriptor.status = "dropped";
      descriptor.status_reason = "source_registry_full";
      this.counts.dropped += 1;
      this.lostRecordCount += 1;
      return descriptor;
    }
    if (this.records.size >= this.maxRecords) {
      descriptor.status = "dropped";
      descriptor.status_reason = "record_index_full";
      this.counts.dropped += 1;
      this.lostRecordCount += 1;
      return descriptor;
    }
    this.records.set(descriptor.object_id, descriptor);
    if (!this.roles.has(options.role)) {
      descriptor.status_reason = "outside_capture_policy";
      this.counts.not_captured += 1;
      return descriptor;
    }
    if (
      this.closed ||
      data.byteLength > this.payloadMaxBytes ||
      this.queue.length + Number(this.running) >= this.queueMaxItems
    ) {
      descriptor.status = "dropped";
      descriptor.status_reason = this.closed
        ? "recorder_closed"
        : data.byteLength > this.payloadMaxBytes
          ? "payload_too_large"
          : "queue_full";
      this.counts.dropped += 1;
      return descriptor;
    }
    const bytes = new Uint8Array(data); // immutable capture snapshot
    descriptor.representation = "exact";
    descriptor.source_byte_length = bytes.byteLength;
    descriptor.source_sha256 = digest(bytes);
    descriptor.status = "pending";
    this.queue.push({ descriptor, bytes });
    this.counts.pending += 1;
    this.schedule();
    return descriptor;
  }

  private validateOptions(options: ByteEvidenceCapture): void {
    if (typeof options.sourceId !== "string" || !OPAQUE_ID.test(options.sourceId)) {
      throw new Error("sourceId must be an opaque identifier");
    }
    for (const [name, value] of [
      ["role", options.role],
      ["boundary", options.boundary],
      ["sourceId", options.sourceId],
      ["runId", options.runId],
      ["operationId", options.operationId],
      ["attemptId", options.attemptId],
      ["streamId", options.streamId],
    ] as const) {
      if (value !== undefined && (typeof value !== "string" || !OPAQUE_ID.test(value))) {
        throw new Error(`${name} must be an opaque identifier`);
      }
    }
    if (!BYTE_EVIDENCE_ROLES.has(options.role) || !BYTE_EVIDENCE_BOUNDARIES.has(options.boundary)) {
      throw new Error("unknown byte evidence role or boundary");
    }
    if (
      !Number.isSafeInteger(options.sourceEpoch) ||
      options.sourceEpoch < 0 ||
      !Number.isSafeInteger(options.sourceSequence) ||
      options.sourceSequence < 0
    ) {
      throw new Error("source epoch and sequence must be non-negative safe integers");
    }
    if (
      options.chunkIndex !== undefined &&
      (!Number.isSafeInteger(options.chunkIndex) ||
        options.chunkIndex < 0 ||
        options.streamId === undefined)
    ) {
      throw new Error("chunkIndex requires streamId and must be non-negative");
    }
    const media = options.mediaType ?? "application/octet-stream";
    if (media.length > 128 || !MEDIA_TYPE.test(media)) throw new Error("invalid media type");
  }

  private schedule(): void {
    if (this.running) return;
    this.running = true;
    setTimeout(() => {
      void this.drain();
    }, 0);
  }

  private async drain(): Promise<void> {
    try {
      while (this.queue.length > 0) {
        const item = this.queue.shift() as WorkItem;
        const d = item.descriptor;
        let succeeded = false;
        let stored: ByteEvidenceDescriptor | undefined;
        for (let attempt = 0; attempt < this.retryMaxAttempts; attempt += 1) {
          try {
            stored = {
              ...d,
              status: "stored",
              stored_byte_length: item.bytes.byteLength,
              stored_sha256: digest(item.bytes),
              ref: this.store.evidenceRefFor!(d.object_id),
            };
            const result = await this.store.putBytesObject!(
              stored as unknown as Record<string, unknown>,
              item.bytes,
            );
            if (
              result.uri !== stored.ref ||
              result.contentHash !== stored.stored_sha256?.slice(7)
            ) {
              throw new Error("store returned mismatched evidence reference or digest");
            }
            succeeded = true;
            break;
          } catch {
            // Retry is bounded and entirely off the monitored caller path.
          }
        }
        this.counts.pending -= 1;
        if (succeeded && stored !== undefined) {
          Object.assign(d, stored);
          this.counts.stored += 1;
        } else {
          d.status = "failed";
          d.status_reason = "store_delivery_failed";
          d.representation = "unavailable";
          this.counts.failed += 1;
        }
      }
    } finally {
      this.running = false;
      if (this.queue.length > 0) this.schedule();
    }
  }

  /** Wait for process-memory delivery; return honest per-status counts. */
  async flush(timeoutMs = 10_000): Promise<Record<string, number>> {
    if (!Number.isFinite(timeoutMs) || timeoutMs < 0) throw new Error("invalid flush timeout");
    const end = Date.now() + timeoutMs;
    while (this.running || this.queue.length > 0) {
      if (Date.now() >= end) break;
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
    return this.stats();
  }

  async close(timeoutMs = 10_000): Promise<Record<string, number>> {
    this.closed = true;
    return this.flush(timeoutMs);
  }
}

function digest(bytes: Uint8Array): string {
  return "sha256:" + createHash("sha256").update(bytes).digest("hex");
}
