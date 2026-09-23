// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Authorized resolution of governed content (spec 033/034) — mirrors
 * Python `fabric.resolver`.
 *
 * {@link ContentResolver} reads objects and manifests from the stores the
 * operator explicitly configures — never from arbitrary URIs. Every read
 * is verified against the descriptor's byte length and SHA-256 digest
 * before content is returned. Digests are integrity checks, not
 * authorization: access is scoped by the configured store namespaces.
 */

import { createHash } from "node:crypto";

import { SCHEMA_TRANSCRIPT_EXPORT } from "./content.js";
import type { GovernedStore } from "./content-store.js";

const DESCRIPTOR_STATUSES = new Set(["stored", "pending", "truncated"]);

export const ResolveStatus = {
  AVAILABLE: "available",
  PENDING: "pending",
  MISSING: "missing",
  DENIED: "denied",
  CORRUPTED: "corrupted",
} as const;
export type ResolveStatus = (typeof ResolveStatus)[keyof typeof ResolveStatus];

export interface ResolveResult {
  status: ResolveStatus;
  content?: Uint8Array;
  descriptor?: Record<string, unknown>;
  reason?: string;
}

export interface ExportTranscriptOptions {
  materialize?: boolean;
  exportMaxBytes?: number;
}

/** Verified read path over explicitly configured governed stores. */
export class ContentResolver {
  private readonly stores: GovernedStore[];

  constructor(stores: GovernedStore[]) {
    if (stores.length === 0) {
      throw new Error("ContentResolver: at least one store is required");
    }
    this.stores = [...stores];
  }

  private storeFor(uri: string): GovernedStore | undefined {
    return this.stores.find((s) => s.ownsUri(uri));
  }

  /**
   * Resolve one object URI to verified bytes. `descriptor` (from a
   * manifest item) supplies expected `byte_length`/`digest`; when
   * omitted the store's sidecar is used. A URI outside every configured
   * store is `denied`; absent bytes `missing`; a digest/size mismatch
   * `corrupted` — the bytes are never returned then.
   */
  async resolve(uri: string, descriptor?: Record<string, unknown>): Promise<ResolveResult> {
    const store = this.storeFor(uri);
    if (store === undefined) {
      return { status: ResolveStatus.DENIED, reason: "outside_configured_store" };
    }
    let data: Uint8Array;
    try {
      data = await store.read(uri);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (/escapes|outside|scheme/i.test(message)) {
        return { status: ResolveStatus.DENIED, reason: message };
      }
      return { status: ResolveStatus.MISSING };
    }
    let effectiveDescriptor = descriptor;
    if (effectiveDescriptor === undefined) {
      try {
        effectiveDescriptor = await store.readDescriptor(uri);
      } catch {
        effectiveDescriptor = undefined;
      }
    }
    if (effectiveDescriptor !== undefined) {
      const expectedLen = effectiveDescriptor["byte_length"];
      const expectedDigest = String(effectiveDescriptor["digest"] ?? "");
      if (typeof expectedLen === "number" && data.length !== expectedLen) {
        return {
          status: ResolveStatus.CORRUPTED,
          descriptor: effectiveDescriptor,
          reason: "byte_length_mismatch",
        };
      }
      if (
        expectedDigest.startsWith("sha256:") &&
        createHash("sha256").update(data).digest("hex") !== expectedDigest.slice(7)
      ) {
        return {
          status: ResolveStatus.CORRUPTED,
          descriptor: effectiveDescriptor,
          reason: "digest_mismatch",
        };
      }
    }
    return {
      status: ResolveStatus.AVAILABLE,
      content: data,
      descriptor: effectiveDescriptor,
    };
  }

  /** Read a manifest document through a configured store. */
  async resolveManifest(uri: string): Promise<Record<string, unknown> | undefined> {
    const store = this.storeFor(uri);
    if (store === undefined) {
      return undefined;
    }
    try {
      return await store.readManifest(uri);
    } catch {
      return undefined;
    }
  }

  /** Resolve the manifest for one decision via the by-decision alias. */
  async manifestForDecision(decisionId: string): Promise<Record<string, unknown> | undefined> {
    for (const store of this.stores) {
      try {
        const alias = await store.readManifest(store.manifestUriForDecision(decisionId));
        const ref = alias["manifest_uri"];
        if (typeof ref === "string") {
          const manifest = await this.resolveManifest(ref);
          if (manifest !== undefined) {
            return manifest;
          }
        }
      } catch {
        // try the next configured store
      }
    }
    return undefined;
  }

  /**
   * Produce a `fabric.transcript-export/v1` document. Groups manifest
   * items into ordered steps (by child span when bound, else by emission
   * order), resolves each item through the configured stores, and
   * reports per-object integrity. Unresolvable items keep their explicit
   * status — never silently dropped, never replaced by empty text.
   */
  async exportTranscript(
    manifestUri: string,
    options: ExportTranscriptOptions = {},
  ): Promise<Record<string, unknown>> {
    const materialize = options.materialize ?? true;
    const exportMaxBytes = options.exportMaxBytes ?? 64 * 1024 * 1024;
    const manifest = await this.resolveManifest(manifestUri);
    if (manifest === undefined) {
      throw new Error(`cannot resolve manifest: ${manifestUri}`);
    }
    const failures: { ref: string; reason: string }[] = [];
    let checked = 0;
    let materialized = 0;
    const steps = new Map<string, Record<string, unknown>>();
    const stepOrder: string[] = [];
    for (const item of manifest["items"] as Record<string, unknown>[]) {
      const links = (item["links"] ?? {}) as Record<string, unknown>;
      const bindings = ((item["descriptor"] ?? {}) as Record<string, unknown>)["bindings"] as
        | Record<string, unknown>
        | undefined;
      const span =
        (links["span_id"] as string | undefined) ?? (bindings?.["span_id"] as string | undefined);
      const groupKey = span ?? `__item_${item["sequence"]}`;
      let step = steps.get(groupKey);
      if (step === undefined) {
        const kind =
          (bindings?.["step_type"] as string | undefined) ?? kindForRole(String(item["role"]));
        step = { sequence: stepOrder.length, kind, content: {} };
        if (span !== undefined) {
          step["span_id"] = span;
        }
        const toolCall =
          (links["tool_call_id"] as string | undefined) ??
          (bindings?.["tool_call_id"] as string | undefined);
        if (toolCall !== undefined) {
          step["tool_call_id"] = toolCall;
        }
        steps.set(groupKey, step);
        stepOrder.push(groupKey);
      }
      const entry = await this.exportEntry(item, materialize);
      if (entry["status"] === "available") {
        checked += 1;
        materialized += (entry["byte_length"] as number | undefined) ?? 0;
        if (materialized > exportMaxBytes) {
          throw new Error(`export exceeds exportMaxBytes (${exportMaxBytes})`);
        }
      } else if (item["ref"] !== undefined && DESCRIPTOR_STATUSES.has(String(item["status"]))) {
        failures.push({ ref: String(item["ref"]), reason: String(entry["status"]) });
      }
      (step["content"] as Record<string, unknown>)[String(item["role"])] = entry;
    }
    const manifestHeader: Record<string, unknown> = {
      manifest_id: manifest["manifest_id"],
      decision_id: manifest["decision_id"],
      tenant_id: manifest["tenant_id"],
    };
    for (const key of ["agent_id", "trace_id", "span_id", "started_at", "closed_at", "producer"]) {
      if (key in manifest) {
        manifestHeader[key] = manifest[key];
      }
    }
    return {
      schema_version: SCHEMA_TRANSCRIPT_EXPORT,
      manifest: manifestHeader,
      steps: stepOrder.map((k) => steps.get(k)),
      completeness: manifest["completeness"],
      integrity: {
        verified: failures.length === 0,
        objects_checked: checked,
        failures,
      },
    };
  }

  private async exportEntry(
    item: Record<string, unknown>,
    materialize: boolean,
  ): Promise<Record<string, unknown>> {
    const descriptor = (item["descriptor"] ?? {}) as Record<string, unknown>;
    const entry: Record<string, unknown> = {
      status: item["status"],
      role: item["role"],
    };
    if (item["status_reason"] !== undefined) {
      entry["status_reason"] = item["status_reason"];
    }
    if (!DESCRIPTOR_STATUSES.has(String(item["status"]))) {
      return entry;
    }
    const ref = item["ref"] as string | undefined;
    if (ref !== undefined) {
      entry["ref"] = ref;
    }
    for (const key of ["digest", "byte_length", "media_type", "object_id"]) {
      if (key in descriptor) {
        entry[key] = descriptor[key];
      }
    }
    if (ref === undefined) {
      return entry;
    }
    const result = await this.resolve(
      ref,
      Object.keys(descriptor).length > 0 ? descriptor : undefined,
    );
    if (result.status !== ResolveStatus.AVAILABLE) {
      entry["status"] = result.status;
      if (result.reason !== undefined) {
        entry["status_reason"] = result.reason;
      }
      return entry;
    }
    entry["status"] = "available";
    if (materialize && result.content !== undefined) {
      const media = (descriptor["media_type"] as string | undefined) ?? "text/plain";
      entry["text"] = materializeText(media, result.content);
    }
    return entry;
  }
}

function materializeText(mediaType: string, content: Uint8Array): unknown {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(content);
  if (mediaType === "application/json") {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      // fall through to raw text
    }
  }
  return text;
}

function kindForRole(role: string): string {
  if (role.startsWith("model.")) return "llm_call";
  if (role.startsWith("tool.")) return "tool_call";
  if (role.startsWith("retrieval.")) return "retrieval";
  if (role.startsWith("memory.")) return "memory";
  if (role.startsWith("side_effect.")) return "side_effect";
  return "context";
}
