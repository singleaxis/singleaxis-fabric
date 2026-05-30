// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * TypeScript port of `sdk/python/tests/conformance/normalize.py`.
 *
 * Produces the same stable, comparable shape from a captured span so the
 * TS-emitted telemetry can be deep-equal-asserted against the SAME golden
 * JSON files the Python conformance suite uses. Matches the Python logic:
 *
 * - drops trace/span/parent ids, timestamps, duration
 * - drops the OTel `exception` event
 * - sorts attribute keys
 * - normalizes UUID-/latency-bearing attribute values to a placeholder
 * - KEEPS sha-256 hashes (part of the contract)
 * - orders spans by name
 */

import type { ReadableSpan } from "@opentelemetry/sdk-trace-node";
import { SpanKind, SpanStatusCode } from "@opentelemetry/api";

const PLACEHOLDER = "<normalized>";

const UUID_ATTR_KEYS = new Set<string>([
  "fabric.checkpoint.checkpoint_id",
  "fabric.eval.eval_id",
  "fabric.policy.evaluation_id",
  "fabric.judge.request_id",
]);

const LATENCY_ATTR_KEYS = new Set<string>([
  "fabric.guardrail.latency_ms",
  "fabric.policy.latency_ms",
  "fabric.retrieval.latency_ms",
]);

type Json = unknown;

function normalizeAttrValue(value: unknown): Json {
  if (Array.isArray(value)) {
    return value.map((v) => normalizeAttrValue(v));
  }
  return value as Json;
}

export function normalizeAttributes(
  attributes: Record<string, unknown> | undefined,
): Record<string, Json> {
  const out: Record<string, Json> = {};
  if (!attributes) {
    return out;
  }
  for (const key of Object.keys(attributes).sort()) {
    if (UUID_ATTR_KEYS.has(key) || LATENCY_ATTR_KEYS.has(key)) {
      out[key] = PLACEHOLDER;
    } else {
      out[key] = normalizeAttrValue(attributes[key]);
    }
  }
  return out;
}

// OTel JS exposes SpanKind as a numeric enum; the goldens use the Python
// SpanKind *names* (INTERNAL/CLIENT/...). Map to the same strings.
const SPAN_KIND_NAME: Record<number, string> = {
  [SpanKind.INTERNAL]: "INTERNAL",
  [SpanKind.SERVER]: "SERVER",
  [SpanKind.CLIENT]: "CLIENT",
  [SpanKind.PRODUCER]: "PRODUCER",
  [SpanKind.CONSUMER]: "CONSUMER",
};

// Likewise StatusCode: OTel JS uses UNSET/OK/ERROR numeric enum; Python
// goldens carry the names. Map to UNSET/OK/ERROR strings.
const STATUS_CODE_NAME: Record<number, string> = {
  [SpanStatusCode.UNSET]: "UNSET",
  [SpanStatusCode.OK]: "OK",
  [SpanStatusCode.ERROR]: "ERROR",
};

interface NormalizedEvent {
  name: string;
  attributes: Record<string, Json>;
}

interface NormalizedSpan {
  name: string;
  kind: string;
  status: { code: string; description: string | null };
  attributes: Record<string, Json>;
  events: NormalizedEvent[];
}

function normalizeEvent(event: {
  name: string;
  attributes?: Record<string, unknown>;
}): NormalizedEvent {
  return {
    name: event.name,
    attributes: normalizeAttributes(event.attributes),
  };
}

export function normalizeSpan(span: ReadableSpan): NormalizedSpan {
  // OTel JS carries the status description on `message` and leaves it
  // undefined when unset; Python emits the status description as null.
  // Normalize undefined/"" -> null.
  const description = span.status.message ? span.status.message : null;
  const events = span.events
    .filter((e) => e.name !== "exception")
    .map((e) => normalizeEvent({ name: e.name, attributes: e.attributes }));
  return {
    name: span.name,
    kind: SPAN_KIND_NAME[span.kind] ?? String(span.kind),
    status: {
      code: STATUS_CODE_NAME[span.status.code] ?? String(span.status.code),
      description,
    },
    attributes: normalizeAttributes(span.attributes),
    events,
  };
}

export function normalizeSpans(spans: ReadableSpan[]): NormalizedSpan[] {
  const normalized = spans.map((s) => normalizeSpan(s));
  normalized.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return normalized;
}
