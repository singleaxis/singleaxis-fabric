// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * v0.8.1 (Sol review item 2): an exported `ToolCall` / `LlmCall` built
 * outside a decision resolves the identity mode from the environment, as
 * Python's standalone helpers do, and keeps a payload digest only when the
 * policy keeps the original (the clear mode).
 */

import { AlwaysOnSampler, BasicTracerProvider } from "@opentelemetry/sdk-trace-node";
import type { ReadableSpan } from "@opentelemetry/sdk-trace-node";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LlmCall, ToolCall, sha256Hex } from "../src/index.js";
import { labelPseudonym, pseudonymV2 } from "../src/identity.js";

const KEY = "fabric-test-id-key-not-a-secret";
const providers: BasicTracerProvider[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(providers.splice(0).map((p) => p.shutdown()));
});

function span() {
  const provider = new BasicTracerProvider({ sampler: new AlwaysOnSampler() });
  providers.push(provider);
  return provider.getTracer("t").startSpan("standalone");
}

function exercise(): Record<string, unknown> {
  const s = span();
  const tool = new ToolCall(s);
  tool.setIdempotency({ idempotent: true, key: "CANARY-idem" });
  tool.setArguments("yes");
  tool.setResult("yes");
  new LlmCall(s).setResponse({ responseId: "CANARY-response" });
  s.end();
  return { ...(s as unknown as ReadableSpan).attributes };
}

describe("standalone ToolCall and LlmCall", () => {
  it("map ids and drop digests in the pseudonymous mode", () => {
    vi.stubEnv("FABRIC_IDENTITY_MODE", "pseudonymous");
    vi.stubEnv("FABRIC_WIRE_ID_KEY", KEY);
    const attrs = exercise();
    expect(attrs["fabric.tool.idempotency_key"]).toBe(labelPseudonym("lbl", "CANARY-idem", KEY));
    expect(attrs["gen_ai.response.id"]).toBe(pseudonymV2("p", "CANARY-response", KEY));
    expect(attrs).not.toHaveProperty("fabric.tool.arguments_hash");
    expect(attrs).not.toHaveProperty("fabric.tool.result_hash");
    expect(JSON.stringify(attrs)).not.toContain("CANARY");
  });

  it("omit ids without a key", () => {
    vi.stubEnv("FABRIC_IDENTITY_MODE", "pseudonymous");
    vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const attrs = exercise();
    expect(attrs).not.toHaveProperty("fabric.tool.idempotency_key");
    expect(attrs).not.toHaveProperty("gen_ai.response.id");
  });

  it("keep the v0.8.0 output in the clear mode", () => {
    vi.stubEnv("FABRIC_IDENTITY_MODE", "clear");
    const attrs = exercise();
    expect(attrs["fabric.tool.idempotency_key"]).toBe("CANARY-idem");
    expect(attrs["gen_ai.response.id"]).toBe("CANARY-response");
    expect(attrs["fabric.tool.arguments_hash"]).toBe(sha256Hex("yes"));
  });
});
