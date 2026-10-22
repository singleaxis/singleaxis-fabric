// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * v0.8.1 privacy canaries for the decision line (spec 049 §7.6, spec 051
 * §8.3), in parity with Python `tests/test_decision_line_canaries.py`. A
 * canary is planted in every field the v0.8.1 fixes cover: idempotency keys,
 * document ids, MCP tool names, the checkpoint step name, tags, exception text
 * and low-entropy payloads (whose digests would reveal them). In the
 * pseudonymous identity mode, with and without `FABRIC_WIRE_ID_KEY`, no
 * canary and no digest of a canary payload may appear in telemetry, in the
 * SDK's console output or in the governed content spool and store.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  Fabric,
  LocalFilesystemContentStore,
  MemoryKind,
  sha256Hex,
  type Decision,
} from "../src/index.js";

const KEY = "fabric-test-id-key-not-a-secret";
const CANARIES = {
  idempotency: "CANARY-idem-q8z",
  toolIdempotency: "CANARY-tool-idem-q8z",
  document: "CANARY-doc-q8z",
  toolName: "CANARY_tool_q8z",
  step: "CANARY-step-q8z",
  tag: "canary:CANARY-tag-q8z",
  memoryTag: "CANARY-memory-tag-q8z",
  exception: "CANARY-exception-text-q8z",
  previousResponse: "CANARY-prev-q8z",
  response: "CANARY-response-q8z",
  toolCall: "CANARY-call-q8z",
  request: "CANARY-request-q8z",
  sideEffectId: "CANARY-effect-q8z",
  targetSystem: "CANARY-patient-crm-q8z",
  operation: "CANARY-update-jane-q8z",
  metadata: "CANARY-metadata-q8z",
};
/** Governed content keeps its bindings (request, tool call) as given: the
 * content store is the customer's destination for content (spec 049 §2.9). */
const CONTENT_BINDINGS = new Set(["request", "toolCall"]);
const PAYLOADS = ["yes", "no", "CANARY-payload-q8z"]; // low entropy: digests are lookups
const DIGESTS = PAYLOADS.map((p) => sha256Hex(p));
const providers: BasicTracerProvider[] = [];
const roots: string[] = [];

afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  await Promise.all(providers.splice(0).map((p) => p.shutdown()));
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

class CanaryError extends Error {}

function exercise(fabric: Fabric): void {
  const raise = () => {
    throw new CanaryError(CANARIES.exception);
  };
  expect(() =>
    fabric.execution({}, () =>
      fabric.decision({ sessionId: "s", requestId: CANARIES.request }, (d: Decision) => {
        d.recordSideEffect({
          type: "other",
          targetSystem: CANARIES.targetSystem,
          operation: CANARIES.operation,
          idempotencyKey: CANARIES.idempotency,
          sideEffectId: CANARIES.sideEffectId,
          parentToolCallId: CANARIES.toolCall,
          requestPayload: PAYLOADS[0],
          resultPayload: PAYLOADS[1],
        });
        d.recordReplayMetadata();
        expect(() =>
          d.toolCall(CANARIES.toolName, { callId: CANARIES.toolCall }, (tool) => {
            tool.setIdempotency({ idempotent: true, key: CANARIES.toolIdempotency });
            tool.setArguments(PAYLOADS[0]!);
            tool.setResult(PAYLOADS[1]!);
            raise();
          }),
        ).toThrow(CanaryError);
        expect(() =>
          d.llmCall(
            { provider: "openai", model: "m", previousResponseId: CANARIES.previousResponse },
            (llm) => {
              llm.setResponse({ responseId: CANARIES.response });
              raise();
            },
          ),
        ).toThrow(CanaryError);
        d.recordRetrieval({
          source: "rag",
          query: PAYLOADS[2]!,
          resultCount: 1,
          resultHashes: [DIGESTS[2]!],
          sourceDocumentIds: [CANARIES.document],
        });
        d.remember({
          kind: MemoryKind.SEMANTIC,
          content: PAYLOADS[0]!,
          tags: [CANARIES.memoryTag],
        });
        d.recall({ kind: MemoryKind.SEMANTIC, key: "k", content: PAYLOADS[1]! });
        d.checkpoint(CANARIES.step);
        d.recordInteraction("message.send", "t", {
          payload: PAYLOADS[2],
          tags: [CANARIES.tag],
          metadata: { note: CANARIES.metadata },
        });
        d.recordMcpInventory({
          server: "srv",
          transport: "stdio",
          tools: [{ name: CANARIES.toolName, description: "d", inputSchema: {} }],
        });
        raise();
      }),
    ),
  ).toThrow(CanaryError);
}

function telemetry(exporter: InMemorySpanExporter): string {
  return JSON.stringify(
    (exporter.getFinishedSpans() as ReadableSpan[]).map((s) => ({
      name: s.name,
      attributes: s.attributes,
      status: s.status,
      events: s.events.map((e) => ({ name: e.name, attributes: e.attributes })),
    })),
  );
}

function files(root: string): string {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else out.push(readFileSync(path, "utf8"));
    }
  };
  walk(root);
  return out.join("\n");
}

function assertClean(haystack: string, where: string, skip = new Set<string>()): void {
  for (const [name, canary] of Object.entries(CANARIES)) {
    if (skip.has(name)) continue;
    expect(haystack, `${name} canary in ${where}`).not.toContain(canary);
  }
  for (const digest of DIGESTS) {
    expect(haystack, `payload digest in ${where}`).not.toContain(digest);
  }
}

function harness(config: { identityMode: "pseudonymous" | "clear"; idKey?: string }) {
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  providers.push(provider);
  const root = mkdtempSync(join(tmpdir(), "fabric-decision-canary-"));
  roots.push(root);
  const fabric = new Fabric({
    tenantId: "acme",
    agentId: "bot",
    tracerProvider: provider,
    contentCapture: {
      store: new LocalFilesystemContentStore(join(root, "store"), "acme"),
      roles: new Set(["model.output.messages"]),
      durability: "spooled",
      spoolDir: join(root, "spool"),
    },
    ...config,
  });
  return { fabric, exporter, root };
}

describe("decision-line privacy canaries", () => {
  for (const keyed of [true, false]) {
    it(`no canary leaves the process in pseudonymous mode (${keyed ? "keyed" : "no key"})`, async () => {
      vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
      vi.stubEnv("FABRIC_WIRE_LABELS", "");
      const lines: string[] = [];
      const capture = (...args: unknown[]) => {
        lines.push(args.map(String).join(" "));
      };
      for (const method of ["warn", "error", "log", "info", "debug"] as const) {
        vi.spyOn(console, method).mockImplementation(capture);
      }
      const h = harness({ identityMode: "pseudonymous", ...(keyed ? { idKey: KEY } : {}) });
      exercise(h.fabric);
      await h.fabric.close();
      assertClean(telemetry(h.exporter), "telemetry");
      assertClean(lines.join("\n"), "console output");
      const written = files(h.root);
      expect(written.length).toBeGreaterThan(0);
      assertClean(written, "spool and store", CONTENT_BINDINGS);
    });
  }

  it("shows the canaries in clear mode (the control)", async () => {
    const h = harness({ identityMode: "clear", idKey: KEY });
    exercise(h.fabric);
    await h.fabric.close();
    const blob = telemetry(h.exporter);
    for (const [name, canary] of Object.entries(CANARIES)) {
      // TS never exports exception text, and metadata is only ever hashed.
      if (name === "exception" || name === "metadata") continue;
      expect(blob, name).toContain(canary);
    }
    expect(blob).toContain(DIGESTS[2]);
  });
});
