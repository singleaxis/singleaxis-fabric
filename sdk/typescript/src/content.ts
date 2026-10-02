// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Governed-content primitives: roles, canonical bytes, descriptors, manifests.
 *
 * Internal module backing spec 028/029 — mirrors Python `fabric._content`.
 * The public surface is {@link ContentCaptureConfig} (content-writer.ts),
 * `ContentResolver` (resolver.ts), and the `ContentRole` vocabulary.
 */

import { createHash, randomUUID } from "node:crypto";

export const SCHEMA_CONTENT_OBJECT = "fabric.content-object/v1";
export const SCHEMA_TRANSCRIPT_MANIFEST = "fabric.transcript-manifest/v1";
export const SCHEMA_TRANSCRIPT_EXPORT = "fabric.transcript-export/v1";

/** Closed set of governed content roles (spec 028). */
export const ContentRole = {
  MODEL_REQUEST_INSTRUCTIONS: "model.request.instructions",
  MODEL_REQUEST_MESSAGES: "model.request.messages",
  MODEL_REQUEST_TOOL_DEFINITIONS: "model.request.tool_definitions",
  MODEL_REQUEST_PARAMETERS: "model.request.parameters",
  MODEL_OUTPUT_MESSAGES: "model.output.messages",
  TOOL_CALL_ARGUMENTS: "tool.call.arguments",
  TOOL_CALL_RESULT: "tool.call.result",
  RETRIEVAL_QUERY: "retrieval.query",
  RETRIEVAL_RESULTS: "retrieval.results",
  MEMORY_WRITE_CONTENT: "memory.write.content",
  MEMORY_READ_CONTENT: "memory.read.content",
  SIDE_EFFECT_REQUEST: "side_effect.request",
  SIDE_EFFECT_RESULT: "side_effect.result",
  CONTEXT_FILE: "context.file",
  INTERACTION_PAYLOAD: "interaction.payload",
} as const;
export type ContentRole = (typeof ContentRole)[keyof typeof ContentRole];

export const CONTENT_ROLES: ReadonlySet<string> = new Set(Object.values(ContentRole));

/** Lifecycle states for a manifest item (spec 029 §3). */
export const ContentStatus = {
  PENDING: "pending",
  STORED: "stored",
  NOT_CAPTURED: "not_captured",
  REDACTED: "redacted",
  TRUNCATED: "truncated",
  DROPPED: "dropped",
  FAILED: "failed",
  UNSUPPORTED: "unsupported",
} as const;
export type ContentStatus = (typeof ContentStatus)[keyof typeof ContentStatus];

/** Item statuses whose manifest entry may carry `descriptor`/`ref`
 * (spec 029 §4). All other statuses must not. */
export const DESCRIPTOR_STATUSES: ReadonlySet<string> = new Set([
  ContentStatus.PENDING,
  ContentStatus.STORED,
  ContentStatus.TRUNCATED,
]);

/** How the stored bytes relate to what the caller supplied. */
export const Representation = {
  CAPTURED: "captured",
  CANONICALIZED: "canonicalized",
  ASSEMBLED: "assembled",
  TRUNCATED: "truncated",
} as const;
export type Representation = (typeof Representation)[keyof typeof Representation];

/** Spec-029 canonical JSON: UTF-8, sorted keys, no insignificant whitespace. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortForJson(value));
}

/** Recursively sort object keys so the serialized form is deterministic. */
export function sortForJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortForJson);
  }
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortForJson((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

export function sha256Prefixed(data: Uint8Array): string {
  return "sha256:" + createHash("sha256").update(data).digest("hex");
}

/**
 * Serialize `content` to the exact bytes that will be stored.
 *
 * - `application/json`: canonical JSON (sorted keys, compact, literal
 *   UTF-8). A `string` input is parsed and re-serialized; a string that
 *   does not parse is a caller error.
 * - `text/plain`: the caller-supplied string encoded UTF-8 verbatim.
 * - `Uint8Array` input is rejected: v1 stores text/JSON only — callers
 *   mark binary content `unsupported` instead of storing it.
 *
 * Mirrors Python `canonical_bytes` byte-for-byte.
 */
export function canonicalBytes(
  content: unknown,
  mediaType: string,
): { data: Uint8Array; representation: Representation } {
  if (content instanceof Uint8Array) {
    throw new TypeError("governed content v1 stores text/JSON only; mark bytes unsupported");
  }
  if (mediaType === "application/json") {
    let value = content;
    if (typeof content === "string") {
      value = JSON.parse(content);
    }
    return {
      data: new TextEncoder().encode(canonicalJson(value)),
      representation: Representation.CANONICALIZED,
    };
  }
  if (typeof content === "string") {
    return { data: new TextEncoder().encode(content), representation: Representation.CAPTURED };
  }
  throw new TypeError(`media_type ${mediaType} requires str content; got ${typeof content}`);
}

const UTF8_CONTINUATION = 0x80;
const UTF8_LEAD_OR_ASCII_MASK = 0xc0;

/** Truncate to `maxBytes` without splitting a UTF-8 sequence. */
export function truncateBytes(data: Uint8Array, maxBytes: number): Uint8Array {
  if (data.length <= maxBytes) {
    return data;
  }
  let end = maxBytes;
  // Only back up when the first excluded byte continues a character.
  // Looking at the last retained byte would discard a complete final rune.
  while (end > 0 && ((data[end] ?? 0) & UTF8_LEAD_OR_ASCII_MASK) === UTF8_CONTINUATION) {
    end -= 1;
  }
  return data.subarray(0, end);
}

export function rfc3339Now(): string {
  return new Date().toISOString();
}

/** `fabric.content-object/v1` descriptor (spec 029 §1). */
export interface ContentDescriptor {
  schema_version: string;
  object_id: string;
  tenant_id: string;
  role: string;
  media_type: string;
  encoding: string;
  byte_length: number;
  digest: string;
  captured_at: string;
  representation: string;
  source: string;
  status: string;
  bindings: Record<string, unknown>;
  original_byte_length?: number;
  status_reason?: string;
}

export interface BuildDescriptorOptions {
  tenantId: string;
  role: string;
  content: unknown;
  mediaType: string;
  source: string;
  status: string;
  bindings: Record<string, unknown>;
  payloadMaxBytes: number;
  statusReason?: string;
}

/**
 * Serialize + digest `content` and build its descriptor. Oversized
 * content is truncated at a UTF-8 boundary and marked `truncated` with
 * the original length. Returns the descriptor and the stored bytes.
 */
export function buildContentDescriptor(options: BuildDescriptorOptions): {
  descriptor: ContentDescriptor;
  data: Uint8Array;
} {
  const { data: serialized, representation: initial } = canonicalBytes(
    options.content,
    options.mediaType,
  );
  const originalLength = serialized.length;
  let data = serialized;
  let representation: string = initial;
  if (data.length > options.payloadMaxBytes) {
    data = truncateBytes(data, options.payloadMaxBytes);
    representation = Representation.TRUNCATED;
  }
  const descriptor: ContentDescriptor = {
    schema_version: SCHEMA_CONTENT_OBJECT,
    object_id: randomUUID(),
    tenant_id: options.tenantId,
    role: options.role,
    media_type: options.mediaType,
    encoding: "utf-8",
    byte_length: data.length,
    digest: sha256Prefixed(data),
    captured_at: rfc3339Now(),
    representation,
    source: options.source,
    status: options.status,
    bindings: { ...options.bindings },
  };
  if (representation === Representation.TRUNCATED) {
    descriptor.original_byte_length = originalLength;
  }
  if (options.statusReason !== undefined) {
    descriptor.status_reason = options.statusReason;
  }
  return { descriptor, data };
}

/** One ordered entry in a transcript manifest. */
export interface ManifestItem {
  sequence: number;
  role: string;
  status: string;
  descriptor?: ContentDescriptor;
  ref?: string;
  status_reason?: string;
  links?: Record<string, unknown>;
}

/** `fabric.transcript-manifest/v1` accumulator for one decision. */
export class TranscriptManifest {
  manifest_id: string;
  tenant_id: string;
  agent_id: string;
  decision_id: string;
  producer: Record<string, unknown>;
  roles_enabled: ReadonlySet<string>;
  trace_id?: string;
  span_id?: string;
  execution_id?: string;
  session_id?: string;
  request_id?: string;
  workflow_id?: string;
  started_at?: string;
  closed_at?: string;
  items: ManifestItem[] = [];

  constructor(options: {
    manifestId: string;
    tenantId: string;
    agentId: string;
    decisionId: string;
    producer: Record<string, unknown>;
    rolesEnabled: ReadonlySet<string>;
  }) {
    this.manifest_id = options.manifestId;
    this.tenant_id = options.tenantId;
    this.agent_id = options.agentId;
    this.decision_id = options.decisionId;
    this.producer = options.producer;
    this.roles_enabled = options.rolesEnabled;
  }

  add(item: ManifestItem): ManifestItem {
    item.sequence = this.items.length;
    this.items.push(item);
    return item;
  }

  itemFor(objectId: string): ManifestItem | undefined {
    return this.items.find((i) => i.descriptor?.object_id === objectId);
  }

  completeness(): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const item of this.items) {
      counts[item.status] = (counts[item.status] ?? 0) + 1;
    }
    return counts;
  }

  rolesObserved(): string[] {
    return [...new Set(this.items.map((i) => i.role))].sort();
  }

  toJSON(): Record<string, unknown> {
    const doc: Record<string, unknown> = {
      schema_version: SCHEMA_TRANSCRIPT_MANIFEST,
      manifest_id: this.manifest_id,
      tenant_id: this.tenant_id,
      agent_id: this.agent_id,
      decision_id: this.decision_id,
      producer: this.producer,
      roles_enabled: [...this.roles_enabled].sort(),
      roles_observed: this.rolesObserved(),
      items: this.items,
      completeness: this.completeness(),
    };
    for (const key of [
      "trace_id",
      "span_id",
      "execution_id",
      "session_id",
      "request_id",
      "workflow_id",
      "started_at",
      "closed_at",
    ] as const) {
      const value = this[key];
      if (value !== undefined) {
        doc[key] = value;
      }
    }
    return doc;
  }
}
