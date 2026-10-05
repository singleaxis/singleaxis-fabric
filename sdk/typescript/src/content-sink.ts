// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Per-decision governed-content sink — mirrors Python `fabric._content_sink`.
 *
 * Bridges the async {@link ContentWriter} and the per-decision
 * {@link TranscriptManifest}: every capture serializes to exact bytes,
 * enqueues through the writer, lands an ordered manifest item, and
 * returns the deterministic ref URI for stamping on the emitting span.
 */

import { randomUUID } from "node:crypto";
import type { Span } from "@opentelemetry/api";

import { ATTR_CONTENT_MANIFEST_REF } from "./attributes.js";
import {
  ContentStatus,
  DESCRIPTOR_STATUSES,
  Representation,
  TranscriptManifest,
  buildContentDescriptor,
  type ContentDescriptor,
  type ManifestItem,
} from "./content.js";
import type { ContentCaptureConfig, ContentWriter } from "./content-writer.js";
import type { GovernedStore } from "./content-store.js";
import { SDK_VERSION } from "./version.js";

/** One governed-content accumulator per decision. */
export class ContentSink {
  private readonly manifest: TranscriptManifest;
  /** Deterministic manifest URI — computable immediately with no store
   * I/O, so `manifest_ref` can be stamped before the span ends even
   * though the bytes arrive asynchronously (spec 032 §5). */
  private readonly manifestUri: string;
  private manifestSubmitted = false;

  constructor(
    private readonly config: ContentCaptureConfig,
    private readonly writer: ContentWriter,
    tenantId: string,
    agentId: string,
    decisionId: string,
    private readonly rolesEnabled: ReadonlySet<string>,
  ) {
    this.manifest = new TranscriptManifest({
      manifestId: randomUUID(),
      tenantId,
      agentId,
      decisionId,
      producer: {
        name: "fabric-typescript",
        version: SDK_VERSION,
        language: "typescript",
      },
      rolesEnabled,
    });
    this.manifestUri = this.store.manifestUriFor(this.manifest.manifest_id);
  }

  get transcript(): TranscriptManifest {
    return this.manifest;
  }

  /** No transcript exists until at least one capture outcome is observed. */
  get uri(): string | undefined {
    return this.manifest.items.length === 0 ? undefined : this.manifestUri;
  }

  private get store(): GovernedStore {
    return this.config.store;
  }

  bind(options: {
    traceId?: string;
    spanId?: string;
    executionId?: string;
    sessionId?: string;
    requestId?: string;
    workflowId?: string;
    startedAt?: string;
  }): void {
    const m = this.manifest;
    m.trace_id = options.traceId ?? m.trace_id;
    m.span_id = options.spanId ?? m.span_id;
    m.execution_id = options.executionId ?? m.execution_id;
    m.session_id = options.sessionId ?? m.session_id;
    m.request_id = options.requestId ?? m.request_id;
    m.workflow_id = options.workflowId ?? m.workflow_id;
    m.started_at = options.startedAt ?? m.started_at;
  }

  enabled(role: string): boolean {
    return this.rolesEnabled.has(role);
  }

  /**
   * Capture one content object; return its resolution ref.
   * `undefined` when the role is outside the capture policy — the caller
   * then emits no ref attribute. Every other outcome lands an explicit
   * manifest item, never a silent omission.
   */
  capture(
    role: string,
    content: unknown,
    options: {
      mediaType?: string;
      bindings?: Record<string, unknown>;
      links?: Record<string, unknown>;
      statusReason?: string;
      representation?: string;
    } = {},
  ): string | undefined {
    if (content === undefined || content === null) {
      return undefined;
    }
    if (!this.enabled(role)) {
      this.manifest.add(
        newItem(role, ContentStatus.NOT_CAPTURED, {
          statusReason: "outside_capture_policy",
          links: options.links,
        }),
      );
      return undefined;
    }
    const mediaType =
      options.mediaType ?? (typeof content === "string" ? "text/plain" : "application/json");
    let descriptor: ContentDescriptor;
    let data: Uint8Array;
    try {
      ({ descriptor, data } = buildContentDescriptor({
        tenantId: this.manifest.tenant_id,
        role,
        content,
        mediaType,
        source: "caller",
        status: ContentStatus.PENDING,
        bindings: options.bindings ?? {},
        payloadMaxBytes: this.config.payloadMaxBytes ?? 1024 * 1024,
        statusReason: options.statusReason,
      }));
    } catch (err) {
      this.manifest.add(
        newItem(role, ContentStatus.UNSUPPORTED, {
          statusReason: err instanceof Error ? err.message : String(err),
          links: options.links,
        }),
      );
      return undefined;
    }
    if (options.representation !== undefined) {
      descriptor = { ...descriptor, representation: options.representation };
    }
    const contentText = new TextDecoder("utf-8", { fatal: false }).decode(data);
    const ref = this.store.refFor(descriptor.digest.split(":", 2)[1] ?? "");
    // Register the manifest item BEFORE the writer can settle it — an
    // inline store fires its settlement inside submit() (spec 029 §4:
    // pending slot first, then delivery).
    const item = this.manifest.add(
      newItem(role, ContentStatus.PENDING, {
        descriptor: { ...descriptor, status: ContentStatus.PENDING },
        ref,
        statusReason: options.statusReason,
        links: options.links,
      }),
    );
    this.writer.subscribe(descriptor.object_id, (d, s) => this.onItemSettled(d, s));
    const status = this.writer.submit(
      descriptor,
      contentText,
      this.manifest.decision_id,
      this.manifest.manifest_id,
      item.sequence,
    );
    // An inline store has already settled inside submit(); only items
    // still pending can be dropped (queue full) or failed (closed
    // writer) by the return value itself.
    if (
      item.status === ContentStatus.PENDING &&
      (status === ContentStatus.DROPPED || status === ContentStatus.FAILED)
    ) {
      this.writer.unsubscribe(descriptor.object_id);
      this.transition(item, status, status === ContentStatus.DROPPED ? "queue_full" : undefined);
    }
    // Failed/dropped items expose no ref; pending and stored do.
    return DESCRIPTOR_STATUSES.has(item.status) ? ref : undefined;
  }

  /**
   * Record an explicit non-stored item (`not_captured`/`unsupported`/
   * `redacted`) so the transcript is complete.
   */
  mark(
    role: string,
    status: string,
    options: { reason?: string; links?: Record<string, unknown> } = {},
  ): void {
    if (!this.enabled(role)) {
      return;
    }
    this.manifest.add(
      newItem(role, status, { statusReason: options.reason, links: options.links }),
    );
  }

  private onItemSettled(descriptor: ContentDescriptor, status: string): void {
    const item = this.manifest.itemFor(descriptor.object_id);
    if (item === undefined) {
      // A settlement for an unregistered item is an SDK defect — surface
      // it, never silently absorb.
      console.warn(`fabric.content: settlement for unregistered object ${descriptor.object_id}`);
      return;
    }
    this.transition(item, status, undefined, descriptor);
  }

  /**
   * Apply the spec-029 state machine to `item`: only `pending` may
   * transition (to `stored`/`truncated`/`failed`); terminal statuses are
   * final. Non-descriptor statuses strip `descriptor`/`ref` so the
   * manifest stays contract-valid.
   */
  private transition(
    item: ManifestItem,
    status: string,
    reason?: string,
    descriptor?: ContentDescriptor,
  ): void {
    if (item.status !== ContentStatus.PENDING) {
      console.warn(`fabric.content: late settlement ${status} for terminal item ${item.role}`);
      return;
    }
    let statusValue = status;
    if (
      statusValue === ContentStatus.STORED &&
      item.descriptor !== undefined &&
      item.descriptor.representation === Representation.TRUNCATED
    ) {
      statusValue = ContentStatus.TRUNCATED;
    }
    item.status = statusValue;
    if (reason !== undefined) {
      item.status_reason = reason;
    }
    if (DESCRIPTOR_STATUSES.has(statusValue)) {
      if (descriptor !== undefined) {
        item.descriptor = { ...descriptor, status: statusValue };
      }
    } else {
      delete item.descriptor;
      delete item.ref;
    }
    if (this.manifestSubmitted) {
      // Idempotent rewrite through the writer: same manifest_id, same
      // destination, last complete document wins.
      this.submitManifest();
    }
  }

  /**
   * Hand the current manifest bytes to the writer's bounded path. Never
   * does store I/O inline except in `inline` durability — the caller
   * path only ever sees a queue/spool handoff.
   */
  private submitManifest(): void {
    const status = this.writer.submitManifest(
      this.manifest.toJSON() as Record<string, unknown>,
      this.manifest.decision_id,
      this.manifest.manifest_id,
      this.manifest.tenant_id,
    );
    if (status === ContentStatus.DROPPED) {
      console.warn(
        `fabric.content: manifest ${this.manifest.manifest_id} handoff dropped (queue full)`,
      );
    }
  }

  /**
   * Submit the manifest and stamp `fabric.content.manifest_ref`. The
   * stamped URI is deterministic — known before the bytes are
   * delivered. Called at decision close, before the span ends, so the
   * attribute lands for observed outcomes; an empty observation window returns
   * undefined without writing or stamping a manifest. A resolver reading early sees `missing`
   * and a later settlement rewrites the document idempotently
   * (spec 032 §5).
   */
  close(options: { decisionSpan?: Span; closedAt?: string } = {}): string | undefined {
    this.manifest.closed_at = options.closedAt ?? this.manifest.closed_at;
    // No calls were observed: do not manufacture an action, stored count or
    // schema-invalid empty manifest that could look like complete capture.
    if (this.manifest.items.length === 0) {
      return undefined;
    }
    this.manifestSubmitted = true;
    this.submitManifest();
    const span = options.decisionSpan;
    if (span !== undefined) {
      try {
        span.setAttribute(ATTR_CONTENT_MANIFEST_REF, this.manifestUri);
      } catch {
        // stamping must never break the decision path
      }
    }
    return this.manifestUri;
  }
}

function newItem(
  role: string,
  status: string,
  options: {
    descriptor?: ContentDescriptor;
    ref?: string;
    statusReason?: string;
    links?: Record<string, unknown>;
  } = {},
): ManifestItem {
  const item: ManifestItem = { sequence: -1, role, status };
  if (options.descriptor !== undefined) item.descriptor = options.descriptor;
  if (options.ref !== undefined) item.ref = options.ref;
  if (options.statusReason !== undefined) item.status_reason = options.statusReason;
  if (options.links !== undefined) item.links = options.links;
  return item;
}
