// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared resolver for the generic cross-cutting kwargs (spec 023).
 *
 * `tags` / `baseline` / `signature` are surface-agnostic: the exact same
 * three capabilities attach to `recordInteraction`, every spec-022
 * surface method (`recordSkill` / `delegate` / `recordHook` /
 * `recordFileAccess` / `recordMcpInventory`) and `toolCall`. This leaf
 * module owns the one place that turns those kwargs into span-event
 * attributes, mirroring Python's `fabric._crosscut`.
 *
 * Unlike Python, the TS SDK does not ship `Baseline` / `SignatureCheck`
 * verification helpers — the caller supplies the *result* of their own
 * check and the SDK stamps it verbatim (the raw inputs — keys, secrets,
 * artifact bytes — never reach the SDK).
 *
 * This is a leaf: it imports only attribute constants and validator
 * helpers, so `decision.ts` and `calls.ts` can use it without an import
 * cycle.
 */

import {
  ATTR_BASELINE_NAME,
  ATTR_BASELINE_STATUS,
  ATTR_SIGNATURE_KEY_ID,
  ATTR_SIGNATURE_SCHEME,
  ATTR_SIGNATURE_VERIFIED,
  ATTR_TAGS,
} from "./attributes.js";
import { assertNonEmpty, assertOneOf, describe } from "./validators.js";

/** The three possible outcomes of a baseline comparison. A closed set. */
export type BaselineStatus = "match" | "deviation" | "unknown";

/** Closed set mirroring Python's baseline statuses. */
export const BASELINE_STATUSES: readonly BaselineStatus[] = ["match", "deviation", "unknown"];

/**
 * A bound baseline comparison result, passed as `baseline` to a record_*
 * call. The host ran the comparison (approved hash vs observed hash);
 * the SDK stamps only the outcome.
 */
export interface BaselineResult {
  /** Name of the baselined artifact (a skill manifest, MCP tool set, …). */
  name: string;
  /** Comparison outcome: `match` / `deviation` / `unknown`. */
  status: BaselineStatus;
}

/**
 * The result of a host-side signature verification over an artifact
 * hash. No key material or signed artifact ever reaches the SDK.
 */
export interface SignatureResult {
  /** Whether the signature verified. */
  verified: boolean;
  /** Signature scheme label (e.g. `"ed25519"`, `"hmac-sha256"`). */
  scheme: string;
  /** Optional opaque key identifier echoed onto the event. */
  keyId?: string;
}

/** The generic cross-cutting options accepted by the record_* surfaces. */
export interface CrossCuttingOptions {
  /** Open-vocabulary `namespace:code` taxonomy tags. */
  tags?: string[];
  /** Result of a host-side baseline comparison. */
  baseline?: BaselineResult;
  /** Result of a host-side signature verification. */
  signature?: SignatureResult;
}

/** The attribute-value union OTel span events accept. */
export type AttrValue = string | number | boolean | string[];

/**
 * Normalize a `tags` option into a list of non-empty strings.
 *
 * Open vocabulary: tags are NOT validated against any taxonomy —
 * arbitrary `namespace:code` strings are always allowed. Only empties
 * are dropped. A non-string element throws (mirrors Python
 * `normalize_tags`'s TypeError).
 */
export function normalizeTags(tags: readonly string[] | undefined): string[] {
  if (tags === undefined) {
    return [];
  }
  const out: string[] = [];
  for (const tag of tags) {
    if (typeof tag !== "string") {
      throw new TypeError(`tags must be strings, got ${describe(tag)}`);
    }
    if (tag !== "") {
      out.push(tag);
    }
  }
  return out;
}

/** The resolved results of the generic cross-cutting kwargs. */
export interface CrossCuttingResolution {
  /** The baseline status that was stamped, if a baseline was supplied. */
  baselineStatus?: BaselineStatus;
  /** Whether any (post-normalization) tags were attached. */
  hasTags: boolean;
}

/**
 * Stamp tags / baseline / signature results onto `attrs` in place.
 *
 * Each capability is stamped only when its option is supplied, so a call
 * that passes none leaves `attrs` byte-identical (additive). The raw
 * inputs are never placed on the span — only the *results* (a status, a
 * verified bool, a scheme/key id) and the open-vocabulary tag strings.
 *
 * Returns the baseline status + whether any tags were attached, which
 * the caller feeds to the coverage loop (an unclassified deviation is a
 * deviation with no tags).
 */
export function applyCrossCutting(
  attrs: Record<string, AttrValue>,
  options: CrossCuttingOptions,
): CrossCuttingResolution {
  const tags = normalizeTags(options.tags);
  if (tags.length > 0) {
    attrs[ATTR_TAGS] = tags;
  }

  let baselineStatus: BaselineStatus | undefined;
  if (options.baseline !== undefined) {
    const baseline = options.baseline;
    assertNonEmpty("baseline name", baseline.name);
    assertOneOf("baseline status", baseline.status, BASELINE_STATUSES);
    baselineStatus = baseline.status;
    attrs[ATTR_BASELINE_NAME] = baseline.name;
    attrs[ATTR_BASELINE_STATUS] = baseline.status;
  }

  if (options.signature !== undefined) {
    const signature = options.signature;
    if (typeof signature.verified !== "boolean") {
      throw new TypeError(
        `signature.verified must be boolean, got ${describe(signature.verified)}`,
      );
    }
    assertNonEmpty("signature.scheme", signature.scheme);
    attrs[ATTR_SIGNATURE_VERIFIED] = signature.verified;
    attrs[ATTR_SIGNATURE_SCHEME] = signature.scheme;
    if (signature.keyId !== undefined) {
      attrs[ATTR_SIGNATURE_KEY_ID] = signature.keyId;
    }
  }

  return { baselineStatus, hasTags: tags.length > 0 };
}
