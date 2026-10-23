// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * v0.8.1 (spec 049 §7.5, spec 051 D-14): a `*_hash` digest of an original
 * payload is emitted only when the payload's content role retains the
 * original, in parity with Python `tests/test_digest_gating.py`. The clear
 * identity mode reproduces the v0.8.0 output.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-node";
import { afterEach, describe, expect, it } from "vitest";

import {
  Fabric,
  LocalFilesystemContentStore,
  MemoryKind,
  sha256Hex,
  type Decision,
} from "../src/index.js";

const KEY = "fabric-test-id-key-not-a-secret";
const PAYLOAD = "yes"; // low entropy: its sha256 is a dictionary lookup away
const DIGEST = sha256Hex(PAYLOAD);
const ROLE_KEYS: Record<string, string[]> = {
  "retrieval.query": ["fabric.retrieval.query_hash"],
  "retrieval.results": ["fabric.retrieval.result_hashes"],
  "memory.write.content": ["fabric.memory.content_hash"],
  "memory.read.content": ["fabric.memory.content_hash"],
  "side_effect.request": ["fabric.side_effect.request_hash"],
  "side_effect.result": ["fabric.side_effect.result_hash"],
  "interaction.payload": ["fabric.interaction.payload_hash"],
  "tool.call.arguments": ["fabric.tool.arguments_hash"],
  "tool.call.result": ["fabric.tool.result_hash"],
};
const HASH_KEYS = [...new Set(Object.values(ROLE_KEYS).flat())].sort();
const providers: BasicTracerProvider[] = [];
const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(providers.splice(0).map((p) => p.shutdown()));
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function run(mode: "pseudonymous" | "clear", roles?: "all" | string[]): Record<string, unknown[]> {
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  providers.push(provider);
  let contentCapture;
  if (roles !== undefined) {
    const root = mkdtempSync(join(tmpdir(), "fabric-digest-"));
    dirs.push(root);
    contentCapture = {
      store: new LocalFilesystemContentStore(root, "acme"),
      roles: roles === "all" ? ("all" as const) : new Set(roles),
      durability: "inline" as const,
    };
  }
  const fabric = new Fabric({
    tenantId: "acme",
    agentId: "bot",
    tracerProvider: provider,
    identityMode: mode,
    idKey: KEY,
    ...(contentCapture !== undefined ? { contentCapture } : {}),
  });
  fabric.decision({ sessionId: "s", requestId: "r" }, (d: Decision) => {
    d.recordRetrieval({ source: "rag", query: PAYLOAD, resultCount: 1, resultHashes: [DIGEST] });
    d.remember({ kind: MemoryKind.SEMANTIC, content: PAYLOAD });
    d.recall({ kind: MemoryKind.SEMANTIC, key: "k", content: PAYLOAD });
    d.recordSideEffect({
      type: "other",
      targetSystem: "crm",
      operation: "u",
      requestPayload: PAYLOAD,
      resultPayload: PAYLOAD,
    });
    d.recordSideEffect({
      type: "other",
      targetSystem: "crm",
      operation: "u",
      requestHash: DIGEST,
      resultHash: DIGEST,
    });
    d.recordInteraction("message.send", "t", { payload: PAYLOAD });
    d.recordInteraction("message.send", "t", { payloadHash: DIGEST });
    d.toolCall("lookup", {}, (tool) => {
      tool.setArguments(PAYLOAD);
      tool.setResult(PAYLOAD);
    });
  });
  const found: Record<string, unknown[]> = {};
  for (const span of exporter.getFinishedSpans()) {
    for (const attrs of [span.attributes, ...span.events.map((e) => e.attributes ?? {})]) {
      for (const key of HASH_KEYS) {
        if (key in attrs) (found[key] ??= []).push(attrs[key]);
      }
    }
  }
  return found;
}

describe("payload digests follow the role's privacy mode", () => {
  it("emits no payload digest when nothing retains the original", () => {
    expect(run("pseudonymous")).toEqual({});
  });

  it("keeps the digests of retained roles", () => {
    const found = run("pseudonymous", "all");
    expect(Object.keys(found).sort()).toEqual(HASH_KEYS);
    expect(found["fabric.memory.content_hash"]).toEqual([DIGEST, DIGEST]);
  });

  it.each(Object.keys(ROLE_KEYS).sort())("gates %s on its own role", (role) => {
    const found = run("pseudonymous", [role]);
    expect(Object.keys(found).sort()).toEqual([...ROLE_KEYS[role]!].sort());
  });

  it("reproduces the v0.8.0 digests in clear mode", () => {
    const found = run("clear");
    expect(Object.keys(found).sort()).toEqual(HASH_KEYS);
    expect(found["fabric.interaction.payload_hash"]).toEqual([DIGEST, DIGEST]);
  });
});
