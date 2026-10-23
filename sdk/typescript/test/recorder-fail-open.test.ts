// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * v0.8.1 (spec 049 §7.1): a failing recorder never escapes a reporting API,
 * and the application's own error object always propagates unchanged from a
 * decision, delegate, LLM, tool or execution callback. Parity with Python
 * `tests/test_recorder_fail_open.py`.
 */

import type { Span, Tracer, TracerProvider } from "@opentelemetry/api";
import { AlwaysOnSampler, BasicTracerProvider } from "@opentelemetry/sdk-trace-node";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Fabric, MemoryKind } from "../src/index.js";

const providers: BasicTracerProvider[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(providers.splice(0).map((p) => p.shutdown()));
});

class AppError extends Error {}

function down(): never {
  throw new Error("recorder-down");
}

/** A provider whose spans throw on every recording call (or whose tracer throws). */
function hostileProvider(mode: "span" | "tracer"): TracerProvider {
  const provider = new BasicTracerProvider({ sampler: new AlwaysOnSampler() });
  providers.push(provider);
  const real = provider.getTracer("hostile");
  const tracer = {
    startSpan(...args: Parameters<Tracer["startSpan"]>): Span {
      if (mode === "tracer") down();
      const span = real.startSpan(...args);
      for (const name of [
        "setAttribute",
        "setAttributes",
        "addEvent",
        "setStatus",
        "recordException",
        "updateName",
        "end",
      ] as const) {
        (span as unknown as Record<string, unknown>)[name] = down;
      }
      return span;
    },
    startActiveSpan: real.startActiveSpan.bind(real),
  } as unknown as Tracer;
  return { getTracer: () => tracer };
}

function fabric(mode: "span" | "tracer"): Fabric {
  return new Fabric({ tenantId: "acme", agentId: "bot", tracerProvider: hostileProvider(mode) });
}

for (const mode of ["span", "tracer"] as const) {
  describe(`a failing ${mode} never reaches the application`, () => {
    it("keeps every reporting API fail-open", () => {
      vi.spyOn(console, "warn").mockImplementation(() => undefined);
      const result = fabric(mode).decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordInteraction("message.send", "t");
        d.remember({ kind: MemoryKind.SEMANTIC, content: "c" });
        d.recall({ kind: MemoryKind.SEMANTIC, key: "k", content: "c" });
        d.forget(MemoryKind.SEMANTIC, "k");
        d.recordRetrieval({ source: "rag", query: "q", resultCount: 0 });
        d.recordSideEffect({ type: "other", targetSystem: "crm", operation: "u" });
        d.checkpoint("step");
        d.recordSkill("skill", "1");
        d.setAttribute("k", "v");
        d.toolCall("lookup", {}, (tool) => tool.setResult("r"));
        d.llmCall({ provider: "openai", model: "m" }, (llm) =>
          llm.setUsage({ inputTokens: 1, outputTokens: 1 }),
        );
        d.delegate("helper", {}, () => undefined);
        return "done";
      });
      expect(result).toBe("done");
    });

    it("propagates the application's own error object", async () => {
      const f = fabric(mode);
      const boom = new AppError("app");
      const ids = { sessionId: "s", requestId: "r" };
      const raise = () => {
        throw boom;
      };
      for (const run of [
        () => f.decision(ids, raise),
        () => f.decision(ids, (d) => d.toolCall("t", {}, raise)),
        () => f.decision(ids, (d) => d.llmCall({ provider: "openai", model: "m" }, raise)),
        () => f.decision(ids, (d) => d.delegate("helper", {}, raise)),
        () => f.execution({}, raise),
      ]) {
        let caught: unknown;
        try {
          run();
        } catch (err) {
          caught = err;
        }
        expect(caught).toBe(boom);
      }
      await expect(
        f.decision(ids, async () => {
          await Promise.resolve();
          throw boom;
        }),
      ).rejects.toBe(boom);
    });
  });
}
