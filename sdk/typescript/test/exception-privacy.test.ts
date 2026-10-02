// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import { SpanStatusCode } from "@opentelemetry/api";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-node";
import { afterAll, beforeEach, expect, it } from "vitest";
import { Fabric } from "../src/index.js";
const exporter = new InMemorySpanExporter();
const provider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] });
const fabric = new Fabric({ tenantId: "t", agentId: "a", tracerProvider: provider });
const ids = { sessionId: "session", requestId: "request" };
beforeEach(() => exporter.reset());
afterAll(() => provider.shutdown());
const operations = {
  execution: (fn: () => unknown) => fabric.execution({}, fn),
  decision: (fn: () => unknown) => fabric.decision(ids, fn),
  llm: (fn: () => unknown) =>
    fabric.decision(ids, (d) => d.llmCall({ system: "test", model: "test" }, fn)),
  tool: (fn: () => unknown) => fabric.decision(ids, (d) => d.toolCall("test", {}, fn)),
};
for (const [operation, run] of Object.entries(operations)) {
  for (const asynchronous of [false, true]) {
    it(`${operation} preserves ${asynchronous ? "async" : "sync"} failures without exporting private error data`, async () => {
      const error = new Error("PRIVATE_MESSAGE_CANARY");
      error.name = "PRIVATE_NAME_CANARY";
      error.stack = "PRIVATE_STACK_CANARY";
      let caught: unknown;
      try {
        await run(() =>
          asynchronous
            ? Promise.reject(error)
            : (() => {
                throw error;
              })(),
        );
      } catch (err) {
        caught = err;
      }
      expect(caught).toBe(error);
      const spans = exporter.getFinishedSpans();
      expect(spans.length).toBe(operation === "llm" || operation === "tool" ? 2 : 1);
      for (const span of spans) {
        expect(span.status.code).toBe(SpanStatusCode.ERROR);
        expect(span.events).toEqual(
          expect.arrayContaining([expect.objectContaining({ name: "exception" })]),
        );
        expect(
          JSON.stringify({ attributes: span.attributes, events: span.events, status: span.status }),
        ).not.toContain("PRIVATE_");
        expect(
          span.events.find((event) => event.name === "exception")?.attributes,
        ).not.toHaveProperty("exception.stacktrace");
      }
    });
  }
}

for (const [operation, run] of Object.entries(operations)) {
  for (const name of [
    "Error",
    "TypeError",
    "RangeError",
    "ReferenceError",
    "SyntaxError",
    "URIError",
    "EvalError",
    "AggregateError",
    "AbortError",
    "TimeoutError",
  ]) {
    it(`${operation} retains bounded ${name} classification and caller cancellation/failure`, async () => {
      const error = new Error("PRIVATE_CANCELLATION_CANARY");
      error.name = name;
      await expect(run(() => Promise.reject(error))).rejects.toBe(error);
      for (const span of exporter.getFinishedSpans()) {
        expect(span.status).toEqual({ code: SpanStatusCode.ERROR, message: name });
        expect(span.events.find((event) => event.name === "exception")?.attributes).toEqual({
          "exception.type": name,
          "exception.message": "Operation failed",
        });
      }
      expect(exporter.getFinishedSpans().length).toBeGreaterThan(0);
    });
  }
  it(`${operation} handles hostile and non-Error thrown values without masking them`, async () => {
    const hostile = new Error("PRIVATE_CANARY");
    Object.defineProperty(hostile, "name", {
      get() {
        throw new Error("PRIVATE_GETTER_CANARY");
      },
    });
    const changing = new Error("PRIVATE_CANARY");
    let reads = 0;
    Object.defineProperty(changing, "name", {
      get() {
        return reads++ === 0 ? "TypeError" : "PRIVATE_CHANGED_CANARY";
      },
    });
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    for (const value of [
      "PRIVATE_STRING_CANARY",
      null,
      { message: "PRIVATE_OBJECT_CANARY" },
      hostile,
      changing,
      proxy,
    ]) {
      let caught: unknown = "not caught";
      try {
        await run(() => Promise.reject(value));
      } catch (err) {
        caught = err;
      }
      expect(caught).toBe(value);
    }
    const spans = exporter.getFinishedSpans();
    expect(spans.length).toBe(operation === "llm" || operation === "tool" ? 12 : 6);
    for (const span of spans) {
      expect(span.status.code).toBe(SpanStatusCode.ERROR);
      expect(
        JSON.stringify({ attributes: span.attributes, events: span.events, status: span.status }),
      ).not.toContain("PRIVATE_");
    }
  });
}

it("rejects generated arbitrary classifications and never reads private diagnostic getters", () => {
  for (let index = 0; index < 128; index++) {
    const error = new Error();
    error.name = `PRIVATE_${index}_${String.fromCharCode(index)}_${"x".repeat(index)}`;
    for (const key of ["message", "stack"]) {
      Object.defineProperty(error, key, {
        get() {
          throw new Error("diagnostic getter accessed");
        },
      });
    }
    let caught: unknown;
    try {
      fabric.execution({}, () => {
        throw error;
      });
    } catch (value) {
      caught = value;
    }
    expect(caught).toBe(error);
  }
  const spans = exporter.getFinishedSpans();
  expect(spans).toHaveLength(128);
  for (const span of spans) {
    expect(span.status).toEqual({ code: SpanStatusCode.ERROR, message: "Error" });
    expect(span.events.find((event) => event.name === "exception")?.attributes).toEqual({
      "exception.type": "Error",
      "exception.message": "Operation failed",
    });
  }
});
