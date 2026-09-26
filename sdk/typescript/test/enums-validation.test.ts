// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Closed-vocabulary acceptance/rejection coverage plus the input
 * validation parity ported from Python's model-level guards
 * (retrieval/side-effect/checkpoint/memory/tool-call contracts).
 */

import { trace, type Attributes } from "@opentelemetry/api";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  Fabric,
  FILE_OPERATIONS,
  HOOK_PHASES,
  MEMORY_KINDS,
  RETRIEVAL_SOURCES,
  REPLAY_BEHAVIORS,
  SIDE_EFFECT_TYPES,
  type Decision,
} from "../src/index.js";

const exporter = new InMemorySpanExporter();
let provider: BasicTracerProvider;

beforeAll(() => {
  provider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] });
  trace.setGlobalTracerProvider(provider);
});

afterAll(async () => {
  await provider.shutdown();
  trace.disable();
});

beforeEach(() => exporter.reset());

function fabric(): Fabric {
  return new Fabric({ tenantId: "t", agentId: "a", profile: "p" });
}

function inDecision(fn: (decision: Decision) => void): () => void {
  return () => fabric().decision({ sessionId: "s", requestId: "r" }, fn);
}

function decisionSpan(): ReadableSpan {
  return exporter.getFinishedSpans().find((s) => s.name === "fabric.decision")!;
}

describe("closed vocabularies accept their members", () => {
  it.each(RETRIEVAL_SOURCES)("accepts retrieval source %s", (source) => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordRetrieval({ source, query: "q", resultCount: 0 });
    });
    expect(decisionSpan().events[0]!.attributes!["fabric.retrieval.source"]).toBe(source);
  });

  it.each(MEMORY_KINDS)("accepts memory kind %s", (kind) => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.remember({ kind, content: "c" });
    });
    expect(decisionSpan().events[0]!.attributes!["fabric.memory.kind"]).toBe(kind);
  });

  it.each(SIDE_EFFECT_TYPES)("accepts side-effect type %s", (type) => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordSideEffect({ type, targetSystem: "sys", operation: "op" });
    });
    expect(decisionSpan().events[0]!.attributes!["fabric.side_effect.type"]).toBe(type);
  });

  it.each(HOOK_PHASES)("accepts hook phase %s", (phase) => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordHook("h", phase, { modified: false });
    });
    expect(decisionSpan().events[0]!.attributes!["fabric.hook.phase"]).toBe(phase);
  });

  it.each(FILE_OPERATIONS)("accepts file operation %s", (operation) => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordFileAccess("/tmp/x", operation);
    });
    expect(decisionSpan().events[0]!.attributes!["fabric.file.operation"]).toBe(operation);
  });

  it.each(REPLAY_BEHAVIORS)("accepts side-effect replayBehavior %s", (replayBehavior) => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordSideEffect({
        type: "external_write",
        targetSystem: "crm",
        operation: "create",
        replayBehavior,
      });
    });
    expect(decisionSpan().events[0]!.attributes!["fabric.side_effect.replay_behavior"]).toBe(
      replayBehavior,
    );
  });
});

describe("closed vocabularies reject non-members", () => {
  it("rejects an unknown retrieval source", () => {
    expect(
      inDecision((d) =>
        d.recordRetrieval({ source: "vectordb" as never, query: "q", resultCount: 0 }),
      ),
    ).toThrow(/source must be one of/);
  });

  it("rejects an unknown memory kind", () => {
    expect(inDecision((d) => d.remember({ kind: "longterm" as never, content: "c" }))).toThrow(
      /kind must be one of/,
    );
    expect(inDecision((d) => d.forget("longterm" as never, "k"))).toThrow(/kind must be one of/);
    expect(
      inDecision((d) => d.recall({ kind: "longterm" as never, key: "k", content: "c" })),
    ).toThrow(/kind must be one of/);
  });

  it("rejects an unknown side-effect type", () => {
    expect(
      inDecision((d) =>
        d.recordSideEffect({ type: "rm_rf" as never, targetSystem: "sys", operation: "o" }),
      ),
    ).toThrow(/type must be one of/);
  });

  it("rejects an unknown hook phase", () => {
    expect(inDecision((d) => d.recordHook("h", "mid_model" as never, { modified: false }))).toThrow(
      /phase must be one of/,
    );
  });

  it("rejects an unknown file operation", () => {
    expect(inDecision((d) => d.recordFileAccess("/x", "execute" as never))).toThrow(
      /operation must be one of/,
    );
  });
});

describe("input validation parity", () => {
  it("rejects an empty retrieval query", () => {
    expect(
      inDecision((d) => d.recordRetrieval({ source: "rag", query: "", resultCount: 0 })),
    ).toThrow(/query/);
  });

  it("rejects a negative resultCount and a hash/count mismatch", () => {
    expect(
      inDecision((d) => d.recordRetrieval({ source: "rag", query: "q", resultCount: -1 })),
    ).toThrow(/resultCount/);
    const hash = "a".repeat(64);
    expect(
      inDecision((d) =>
        d.recordRetrieval({ source: "rag", query: "q", resultCount: 2, resultHashes: [hash] }),
      ),
    ).toThrow(/must equal resultCount/);
    // An empty hashes list does not trigger the parity check (mirrors Python).
    expect(
      inDecision((d) =>
        d.recordRetrieval({ source: "rag", query: "q", resultCount: 2, resultHashes: [] }),
      ),
    ).not.toThrow();
    // Negative latency rejected.
    expect(
      inDecision((d) =>
        d.recordRetrieval({ source: "rag", query: "q", resultCount: 0, latencyMs: -1 }),
      ),
    ).toThrow(/latencyMs/);
  });

  it("rejects empty / oversized side-effect fields", () => {
    expect(
      inDecision((d) => d.recordSideEffect({ type: "other", targetSystem: "", operation: "o" })),
    ).toThrow(/targetSystem/);
    expect(
      inDecision((d) => d.recordSideEffect({ type: "other", targetSystem: "sys", operation: "" })),
    ).toThrow(/operation/);
    expect(
      inDecision((d) =>
        d.recordSideEffect({
          type: "other",
          targetSystem: "x".repeat(129),
          operation: "o",
        }),
      ),
    ).toThrow(/targetSystem/);
    expect(
      inDecision((d) =>
        d.recordSideEffect({
          type: "other",
          targetSystem: "sys",
          operation: "x".repeat(257),
        }),
      ),
    ).toThrow(/operation/);
    expect(
      inDecision((d) =>
        d.recordSideEffect({
          type: "other",
          targetSystem: "sys",
          operation: "o",
          idempotencyKey: "k".repeat(257),
        }),
      ),
    ).toThrow(/idempotencyKey/);
  });

  it("rejects an empty checkpoint stepName and emits the stripped name", () => {
    expect(inDecision((d) => d.checkpoint("  "))).toThrow(/stepName/);
    let event!: { checkpointId: string; stepName: string };
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      event = d.checkpoint("  after-retrieval  ");
    });
    expect(event.stepName).toBe("after-retrieval");
    // The failed decision above also finished a span; find the one
    // carrying the checkpoint event.
    const span = exporter
      .getFinishedSpans()
      .find((s) => s.events.some((e) => e.name === "fabric.checkpoint"))!;
    const attrs: Attributes = span.events.find((e) => e.name === "fabric.checkpoint")!.attributes!;
    expect(attrs["fabric.checkpoint.step_name"]).toBe("after-retrieval");
  });

  it("rejects a negative memory ttlSeconds", () => {
    expect(
      inDecision((d) => d.remember({ kind: "semantic", content: "c", ttlSeconds: -1 })),
    ).toThrow(/ttlSeconds/);
  });

  it("drops empty tags and rejects non-string tags", () => {
    const hash = "a".repeat(64);
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordInteraction("http.request", "t", {
        tags: ["a:b", "", "c:d"],
        baseline: { name: "b", status: "match" },
      });
      void hash;
    });
    const event = decisionSpan().events.find((e) => e.name === "fabric.interaction")!;
    expect(event.attributes!["fabric.tags"]).toEqual(["a:b", "c:d"]);
    expect(
      inDecision((d) => d.recordInteraction("k", "t", { tags: ["ok", 5 as unknown as string] })),
    ).toThrow(/tags must be strings/);
  });

  it("rejects empty retry reasons / idempotency keys / response ids", () => {
    expect(
      inDecision((d) =>
        d.llmCall({ provider: "p", model: "m" }, (c) => c.setRetry({ count: 1, reason: "" })),
      ),
    ).toThrow(/retry reason/);
    expect(
      inDecision((d) => d.toolCall("t", {}, (c) => c.setRetry({ count: 1, reason: " " }))),
    ).toThrow(/retry reason/);
    expect(
      inDecision((d) =>
        d.toolCall("t", {}, (c) => c.setIdempotency({ idempotent: true, key: "" })),
      ),
    ).toThrow(/idempotency key/);
    expect(
      inDecision((d) =>
        d.llmCall({ provider: "p", model: "m" }, (c) => c.setResponse({ responseId: "" })),
      ),
    ).toThrow(/responseId/);
  });

  it("rejects promptVersion without promptName and provider/system disagreement", () => {
    expect(
      inDecision((d) => d.llmCall({ provider: "p", model: "m", promptVersion: "3" }, () => {})),
    ).toThrow(/promptVersion requires promptName/);
    expect(
      inDecision((d) =>
        d.llmCall({ provider: "anthropic", system: "openai", model: "m" }, () => {}),
      ),
    ).toThrow(/disagree/);
    expect(
      inDecision((d) => d.llmCall({ provider: "p", model: "m", operationName: "" }, () => {})),
    ).toThrow(/operationName/);
  });

  it("rejects non-scalar attributes on llm/tool setAttribute", () => {
    expect(
      inDecision((d) =>
        d.llmCall({ provider: "p", model: "m" }, (c) =>
          (c.setAttribute as (k: string, v: unknown) => void)("k", { nope: 1 }),
        ),
      ),
    ).toThrow(/must be a string, number, or boolean/);
    expect(
      inDecision((d) => d.llmCall({ provider: "p", model: "m" }, (c) => c.setAttribute("k", NaN))),
    ).toThrow(/finite/);
    expect(
      inDecision((d) =>
        d.toolCall("t", {}, (c) => (c.setAttribute as (k: string, v: unknown) => void)("k", [1])),
      ),
    ).toThrow(/must be a string, number, or boolean/);
    expect(inDecision((d) => d.toolCall("t", {}, (c) => c.setAttribute("k", Infinity)))).toThrow(
      /finite/,
    );
  });
});
