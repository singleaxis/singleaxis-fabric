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
  private manifestUri: string | undefined;

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
    writer.onSettled((d, s) => this.onSettled(d, s));
  }

  get transcript(): TranscriptManifest {
    return this.manifest;
  }

  get uri(): string | undefined {
    return this.manifestUri;
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
    const status = this.writer.submit(descriptor, contentText);
    if (status === ContentStatus.DROPPED) {
      this.manifest.add(
        newItem(role, ContentStatus.DROPPED, {
          statusReason: "queue_full",
          links: options.links,
        }),
      );
      return undefined;
    }
    const itemStatus =
      descriptor.representation === Representation.TRUNCATED &&
      (status === ContentStatus.STORED || status === ContentStatus.PENDING)
        ? ContentStatus.TRUNCATED
        : status;
    descriptor = { ...descriptor, status: itemStatus };
    this.manifest.add(
      newItem(role, itemStatus, {
        descriptor,
        ref,
        links: options.links,
      }),
    );
    return ref;
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

  private onSettled(descriptor: ContentDescriptor, status: string): void {
    const item = this.manifest.itemFor(descriptor.object_id);
    if (item === undefined) {
      return;
    }
    item.status = status;
    item.descriptor = { ...descriptor, status };
    if (this.manifestUri !== undefined) {
      void this.writeManifest();
    }
  }

  private async writeManifest(): Promise<string | undefined> {
    try {
      this.manifestUri = await this.store.writeManifest(
        this.manifest.toJSON() as Record<string, unknown>,
        this.manifest.decision_id,
        this.manifest.manifest_id,
      );
      return this.manifestUri;
    } catch {
      return undefined;
    }
  }

  /**
   * Write the manifest and stamp `fabric.content.manifest_ref`. Called
   * at decision close — before the span ends, so the attribute lands.
   * Pending items stay pending in the manifest; a later settle rewrites
   * it idempotently (spec 032 §5).
   */
  close(options: { decisionSpan?: Span; closedAt?: string } = {}): string | undefined {
    this.manifest.closed_at = options.closedAt ?? this.manifest.closed_at;
    const span = options.decisionSpan;
    if (this.store.synchronous) {
      // Write + stamp inline so the attribute lands before the span ends.
      try {
        const uri = this.store.writeManifest(
          this.manifest.toJSON() as Record<string, unknown>,
          this.manifest.decision_id,
          this.manifest.manifest_id,
        ) as string;
        this.manifestUri = uri;
        if (uri !== undefined && span !== undefined) {
          try {
            span.setAttribute(ATTR_CONTENT_MANIFEST_REF, uri);
          } catch {
            // stamping must never break the decision path
          }
        }
      } catch {
        // a failed manifest write lands as an absent ref, not a raised error
      }
      return this.manifestUri;
    }
    void this.writeManifest().then((uri) => {
      if (uri !== undefined && span !== undefined) {
        try {
          span.setAttribute(ATTR_CONTENT_MANIFEST_REF, uri);
        } catch {
          // stamping must never break the decision path
        }
      }
    });
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
