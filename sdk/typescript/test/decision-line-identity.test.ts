// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * v0.8.1: caller data on decision-line telemetry keys is mapped in
 * pseudonymous mode (spec 049 §2.9, §4.2; spec 051 §4.9), in parity with
 * Python `tests/test_decision_line_identity.py`. `identityMode: "clear"`
 * reproduces the v0.8 output.
 */

import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-node";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Fabric, MemoryKind, sha256Hex, type Decision } from "../src/index.js";
import { labelPseudonym } from "../src/identity.js";

const KEY = "fabric-test-id-key-not-a-secret";
const VALUES = {
  idempotency: "idem-canary-7c1",
  toolIdempotency: "tool-idem-canary-2b9",
  docA: "doc-canary-patient-file-1",
  docB: "doc-canary-patient-file-2",
  step: "after-canary-step",
  tag: "canary:tag-secret",
  memoryTag: "canary-memory-tag",
  tool: "canary_lookup_customer",
};
const TOOL = { name: VALUES.tool, description: "d", inputSchema: {} };
const providers: BasicTracerProvider[] = [];

afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(providers.splice(0).map((p) => p.shutdown()));
});

function run(config: { identityMode: "pseudonymous" | "clear"; idKey?: string }) {
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  providers.push(provider);
  const fabric = new Fabric({
    tenantId: "acme",
    agentId: "bot",
    tracerProvider: provider,
    ...config,
  });
  fabric.decision({ sessionId: "s", requestId: "r" }, (d: Decision) => {
    d.recordSideEffect({
      type: "other",
      targetSystem: "crm",
      operation: "update",
      idempotencyKey: VALUES.idempotency,
    });
    d.toolCall("lookup", {}, (tool) => {
      tool.setIdempotency({ idempotent: true, key: VALUES.toolIdempotency });
    });
    d.recordRetrieval({
      source: "rag",
      query: "q",
      resultCount: 2,
      sourceDocumentIds: [VALUES.docA, VALUES.docB],
    });
    d.remember({ kind: MemoryKind.SEMANTIC, content: "c", tags: [VALUES.memoryTag] });
    d.checkpoint(VALUES.step);
    d.recordInteraction("message.send", "t", { tags: [VALUES.tag] });
    d.recordMcpInventory({ server: "srv", transport: "stdio", tools: [TOOL] });
  });
  const attrs: Record<string, unknown>[] = [];
  for (const span of exporter.getFinishedSpans()) {
    attrs.push({ ...span.attributes });
    for (const event of span.events) attrs.push({ ...event.attributes });
  }
  return attrs;
}

function values(attrs: Record<string, unknown>[], key: string): unknown[] {
  return attrs.filter((a) => key in a).map((a) => a[key]);
}

const lbl = (value: string) => labelPseudonym("lbl", value, KEY);
const defHash = sha256Hex(
  JSON.stringify({ description: "d", inputSchema: {}, name: VALUES.tool })
    .replace(/,"/g, ', "')
    .replace(/":/g, '": '),
).slice(0, 12);

describe("decision-line keys in pseudonymous mode", () => {
  it("maps every key with the id key", () => {
    const attrs = run({ identityMode: "pseudonymous", idKey: KEY });
    expect(values(attrs, "fabric.side_effect.idempotency_key")).toEqual([lbl(VALUES.idempotency)]);
    expect(values(attrs, "fabric.tool.idempotency_key")).toEqual([lbl(VALUES.toolIdempotency)]);
    expect(values(attrs, "fabric.retrieval.source_document_ids")).toEqual([
      [lbl(VALUES.docA), lbl(VALUES.docB)],
    ]);
    expect(values(attrs, "fabric.checkpoint.step_name")).toEqual([lbl(VALUES.step)]);
    expect(values(attrs, "fabric.tags")).toEqual([[lbl(VALUES.tag)]]);
    expect(values(attrs, "fabric.memory.tags")).toEqual([[lbl(VALUES.memoryTag)]]);
    expect(values(attrs, "fabric.mcp.tools")).toEqual([[`${lbl(VALUES.tool)}:${defHash}`]]);
    const text = JSON.stringify(attrs);
    for (const value of Object.values(VALUES)) expect(text).not.toContain(value);
  });

  it("omits them without a key", () => {
    vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
    const attrs = run({ identityMode: "pseudonymous" });
    for (const key of [
      "fabric.side_effect.idempotency_key",
      "fabric.tool.idempotency_key",
      "fabric.retrieval.source_document_ids",
      "fabric.checkpoint.step_name",
      "fabric.tags",
      "fabric.memory.tags",
      "fabric.mcp.tools",
    ]) {
      expect(values(attrs, key), key).toEqual([]);
    }
    expect(values(attrs, "fabric.mcp.tool_count")).toEqual([1]);
    const text = JSON.stringify(attrs);
    for (const value of Object.values(VALUES)) expect(text).not.toContain(value);
  });

  it("keeps operator labels clear with FABRIC_WIRE_LABELS=clear, never ids", () => {
    vi.stubEnv("FABRIC_WIRE_LABELS", "clear");
    const attrs = run({ identityMode: "pseudonymous", idKey: KEY });
    expect(values(attrs, "fabric.checkpoint.step_name")).toEqual([VALUES.step]);
    expect(values(attrs, "fabric.tags")).toEqual([[VALUES.tag]]);
    expect(values(attrs, "fabric.mcp.tools")).toEqual([[`${VALUES.tool}:${defHash}`]]);
    expect(values(attrs, "fabric.side_effect.idempotency_key")).toEqual([lbl(VALUES.idempotency)]);
  });

  it("reproduces the v0.8 output in clear mode", () => {
    const attrs = run({ identityMode: "clear", idKey: KEY });
    expect(values(attrs, "fabric.side_effect.idempotency_key")).toEqual([VALUES.idempotency]);
    expect(values(attrs, "fabric.tool.idempotency_key")).toEqual([VALUES.toolIdempotency]);
    expect(values(attrs, "fabric.retrieval.source_document_ids")).toEqual([
      [VALUES.docA, VALUES.docB],
    ]);
    expect(values(attrs, "fabric.checkpoint.step_name")).toEqual([VALUES.step]);
    expect(values(attrs, "fabric.tags")).toEqual([[VALUES.tag]]);
    expect(values(attrs, "fabric.memory.tags")).toEqual([[VALUES.memoryTag]]);
    expect(values(attrs, "fabric.mcp.tools")).toEqual([[`${VALUES.tool}:${defHash}`]]);
  });
});
