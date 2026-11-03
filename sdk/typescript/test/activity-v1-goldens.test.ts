// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Reproduce the activity v1 goldens whose example values were neutralized in
 * v0.9. The full conformance suite that ran every activity v1 scenario was
 * retired with the passive-capture release qualification; the `hook` and
 * `interaction_tagged` goldens were re-valued (neutral hook name and tags),
 * so this proves the current SDK still emits them after the same
 * normalization the retired suite used. Python twin:
 * `sdk/python/tests/test_activity_v1_goldens.py`.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { trace, type Attributes } from "@opentelemetry/api";
import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { Fabric, testing, type Decision } from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONTRACT_DIR = resolve(HERE, "..", "..", "..", "contracts", "activity", "v1");
const PLACEHOLDER = "<normalized>";
// Minted per run: the retired normalizer kept the key and replaced the value.
const VOLATILE_KEYS = new Set(["fabric.decision_id"]);
// Standard gen_ai.* keys follow the separately versioned OpenTelemetry
// schema; activity v1 pins only these (the retired normalizer's allowlist).
const V1_GEN_AI_KEYS = new Set([
  "gen_ai.system",
  "gen_ai.request.model",
  "gen_ai.request.temperature",
  "gen_ai.request.top_p",
  "gen_ai.request.max_tokens",
  "gen_ai.response.model",
  "gen_ai.response.finish_reasons",
  "gen_ai.usage.input_tokens",
  "gen_ai.usage.output_tokens",
  "gen_ai.usage.cache_creation_input_tokens",
  "gen_ai.usage.cache_read_input_tokens",
  "gen_ai.tool.name",
  "gen_ai.tool.call.id",
]);
// OTel SpanKind / SpanStatusCode numeric values -> the Python enum names the goldens use.
const KIND_NAMES = ["INTERNAL", "SERVER", "CLIENT", "PRODUCER", "CONSUMER"];
const STATUS_NAMES = ["UNSET", "OK", "ERROR"];

type ScenarioManifest = { name: string; fixture: string; sha256: string; support: string[] };

function normalizeAttributes(attributes: Attributes | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(attributes ?? {}).sort()) {
    if (key.startsWith("gen_ai.") && !V1_GEN_AI_KEYS.has(key)) continue;
    const value = (attributes ?? {})[key];
    out[key] = VOLATILE_KEYS.has(key) ? PLACEHOLDER : Array.isArray(value) ? [...value] : value;
  }
  return out;
}

function normalize(spans: readonly ReadableSpan[]): unknown[] {
  return spans
    .map((span) => ({
      name: span.name,
      kind: KIND_NAMES[span.kind],
      status: {
        code: STATUS_NAMES[span.status.code],
        description: span.status.message ?? null,
      },
      attributes: normalizeAttributes(span.attributes),
      events: span.events
        .filter((event) => event.name !== "exception" && !event.name.startsWith("gen_ai."))
        .map((event) => ({ name: event.name, attributes: normalizeAttributes(event.attributes) })),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function loadGolden(name: string): unknown {
  const manifest = JSON.parse(readFileSync(resolve(CONTRACT_DIR, "manifest.json"), "utf-8")) as {
    scenarios: ScenarioManifest[];
  };
  const entries = manifest.scenarios.filter((entry) => entry.name === name);
  expect(entries).toHaveLength(1);
  const entry = entries[0]!;
  expect(entry.support).toContain("typescript");
  const bytes = readFileSync(resolve(CONTRACT_DIR, entry.fixture));
  expect(createHash("sha256").update(bytes).digest("hex")).toBe(entry.sha256);
  return JSON.parse(bytes.toString("utf-8"));
}

const exporter = new InMemorySpanExporter();
let provider: BasicTracerProvider;

beforeAll(() => {
  provider = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  trace.setGlobalTracerProvider(provider);
});

afterAll(async () => {
  await provider.shutdown();
  trace.disable();
});

beforeEach(() => {
  exporter.reset();
  // The goldens pin the pre-049 identity output, which clear mode reproduces.
  vi.stubEnv("FABRIC_IDENTITY_MODE", "clear");
});
afterEach(() => vi.unstubAllEnvs());

function decision(fn: (d: Decision) => void): void {
  const f = new Fabric({
    tenantId: "tenant-conformance",
    agentId: "agent-conformance",
    profile: "permissive-dev",
  });
  f.decision({ sessionId: "session-0001", requestId: "request-0001", userId: "user-0001" }, fn);
}

describe("activity v1 neutralized goldens", () => {
  it("hook", () => {
    decision((d) => {
      d.recordHook("example-redactor", "pre_model", {
        modified: true,
        inputHash: "a".repeat(64),
        outputHash: "b".repeat(64),
      });
    });
    expect(normalize(exporter.getFinishedSpans())).toEqual(loadGolden("hook"));
  });

  it("interaction_tagged", () => {
    testing.resetCoverageRegistry();
    decision((d) => {
      d.recordInteraction("db.query", "orders", {
        direction: "internal",
        payloadHash: "b".repeat(64),
        // The golden predates hashed-by-default targets.
        redactTarget: false,
        tags: ["example:category", "example:label", "myco:risk-high"],
        baseline: { name: "db.query", status: "match" },
        signature: { verified: true, scheme: "hmac-sha256", keyId: "conformance-key-1" },
      });
    });
    expect(normalize(exporter.getFinishedSpans())).toEqual(loadGolden("interaction_tagged"));
  });
});
