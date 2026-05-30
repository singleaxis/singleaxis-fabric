// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Regression suite for async callback forms. Before the fix, the callback
 * forms (`decision`, `llmCall`, `toolCall`) ended their span synchronously
 * after invoking `fn`, so an ASYNC callback's `setUsage`/`setResult` landed
 * AFTER the span had closed and were silently dropped. These tests prove
 * that an awaited async body's setters now land on the emitted span, that
 * child spans opened after an `await` still parent under the decision span,
 * and that an async throw records the exception + ERROR status.
 */

import { context, SpanStatusCode, trace } from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { Fabric } from "../src/index.js";
import {
  FABRIC_LLM_USAGE_INPUT_TOKENS,
  FABRIC_LLM_USAGE_OUTPUT_TOKENS,
  FABRIC_TOOL_ARGS_HASH,
  FABRIC_TOOL_RESULT_HASH,
  GEN_AI_USAGE_INPUT_TOKENS,
  GEN_AI_USAGE_OUTPUT_TOKENS,
  SPAN_NAME_DECISION,
  SPAN_NAME_LLM_CALL,
} from "../src/attributes.js";
import { sha256Hex } from "../src/index.js";

const exporter = new InMemorySpanExporter();
let provider: BasicTracerProvider;
const contextManager = new AsyncLocalStorageContextManager();

beforeAll(() => {
  // Register an async context manager (what NodeTracerProvider.register()
  // installs in real apps) so the decision span's active context survives
  // an `await`, letting child spans opened after one parent correctly.
  contextManager.enable();
  context.setGlobalContextManager(contextManager);
  provider = new BasicTracerProvider({
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  trace.setGlobalTracerProvider(provider);
});

afterAll(async () => {
  await provider.shutdown();
  trace.disable();
  context.disable();
});

beforeEach(() => {
  exporter.reset();
});

function fabric(): Fabric {
  return new Fabric({ tenantId: "t", agentId: "a", profile: "permissive-dev" });
}

function ids(): { sessionId: string; requestId: string } {
  return { sessionId: "session-async", requestId: "request-async" };
}

function spanByName(name: string): ReadableSpan {
  const span = exporter.getFinishedSpans().find((s) => s.name === name);
  if (!span) {
    throw new Error(`no finished span named ${name}`);
  }
  return span;
}

describe("async callback forms record after an await", () => {
  it("async llmCall: setUsage after an awaited microtask lands on the span", async () => {
    const f = fabric();
    await f.decision(ids(), async (d) => {
      await d.llmCall({ system: "anthropic", model: "claude-opus-4-8" }, async (call) => {
        await Promise.resolve(); // simulate awaiting the real LLM response
        call.setUsage({ inputTokens: 120, outputTokens: 64, finishReason: "end_turn" });
      });
    });

    const llm = spanByName(SPAN_NAME_LLM_CALL);
    expect(llm.attributes[GEN_AI_USAGE_INPUT_TOKENS]).toBe(120);
    expect(llm.attributes[GEN_AI_USAGE_OUTPUT_TOKENS]).toBe(64);
    expect(llm.attributes[FABRIC_LLM_USAGE_INPUT_TOKENS]).toBe(120);
    expect(llm.attributes[FABRIC_LLM_USAGE_OUTPUT_TOKENS]).toBe(64);
  });

  it("async toolCall: setArguments/setResult after an await land on the span", async () => {
    const f = fabric();
    await f.decision(ids(), async (d) => {
      await d.toolCall("vector_search", { callId: "call-1" }, async (tool) => {
        await Promise.resolve();
        tool.setArguments('{"query":"refunds"}');
        tool.setResult('{"hits":3}');
      });
    });

    const tool = spanByName("fabric.tool_call");
    expect(tool.attributes[FABRIC_TOOL_ARGS_HASH]).toBe(sha256Hex('{"query":"refunds"}'));
    expect(tool.attributes[FABRIC_TOOL_RESULT_HASH]).toBe(sha256Hex('{"hits":3}'));
  });

  it("async decision: a child llmCall opened after an await parents under the decision", async () => {
    const f = fabric();
    await f.decision(ids(), async (d) => {
      await Promise.resolve();
      d.llmCall({ system: "anthropic", model: "claude-opus-4-8" }, (call) => {
        call.setResponseModel("claude-opus-4-8");
      });
    });

    const decision = spanByName(SPAN_NAME_DECISION);
    const llm = spanByName(SPAN_NAME_LLM_CALL);
    expect(llm.parentSpanId).toBe(decision.spanContext().spanId);
    expect(llm.spanContext().traceId).toBe(decision.spanContext().traceId);
  });

  it("async callback that throws records the exception + ERROR status and propagates", async () => {
    const f = fabric();
    const boom = new Error("kaboom");
    await expect(
      f.decision(ids(), async (d) => {
        await d.llmCall({ system: "anthropic", model: "claude-opus-4-8" }, async () => {
          await Promise.resolve();
          throw boom;
        });
      }),
    ).rejects.toBe(boom);

    const llm = spanByName(SPAN_NAME_LLM_CALL);
    expect(llm.status.code).toBe(SpanStatusCode.ERROR);
    expect(llm.status.message).toBe("Error");
    expect(llm.events.some((e) => e.name === "exception")).toBe(true);
  });

  it("sync llmCall still ends synchronously (no regression)", () => {
    const f = fabric();
    let endedInsideCallback = false;
    f.decision(ids(), (d) => {
      d.llmCall({ system: "anthropic", model: "claude-opus-4-8" }, (call) => {
        call.setUsage({ inputTokens: 10 });
        // The span must NOT be finished yet inside a sync body.
        endedInsideCallback = exporter.getFinishedSpans().some((s) => s.name === SPAN_NAME_LLM_CALL);
      });
    });
    expect(endedInsideCallback).toBe(false);
    const llm = spanByName(SPAN_NAME_LLM_CALL);
    expect(llm.attributes[GEN_AI_USAGE_INPUT_TOKENS]).toBe(10);
  });
});
