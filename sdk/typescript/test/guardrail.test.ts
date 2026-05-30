// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Unit coverage for the first-class guardrail API on {@link Decision}
 * (`recordGuardrail` / `recordBlock`). The shared-wire shape is covered by
 * the conformance suite against the Python goldens; this file pins the
 * behaviours that are not visible there: entity formatting, first-wins
 * blocking, the non-blocking guard, and the `blocked` accessor.
 */

import { trace, SpanStatusCode, type Attributes } from "@opentelemetry/api";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { Fabric } from "../src/index.js";

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

beforeEach(() => {
  exporter.reset();
});

function fabric(): Fabric {
  return new Fabric({ tenantId: "t", agentId: "a", profile: "p" });
}

function only(): ReadableSpan {
  const spans = exporter.getFinishedSpans();
  expect(spans).toHaveLength(1);
  return spans[0]!;
}

function guardrailEvent(span: ReadableSpan): Attributes {
  const ev = span.events.find((e) => e.name === "fabric.guardrail");
  expect(ev).toBeDefined();
  return ev!.attributes ?? {};
}

describe("Decision guardrail API", () => {
  it("formats detected entities as CATEGORY:count strings", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordGuardrail({
        phase: "input",
        blocked: false,
        latencyMs: 5,
        policies: ["presidio:EMAIL_ADDRESS"],
        entities: [
          { category: "EMAIL_ADDRESS", count: 1 },
          { category: "PERSON", count: 2 },
        ],
      });
    });
    const attrs = guardrailEvent(only());
    expect(attrs["fabric.guardrail.entities"]).toEqual(["EMAIL_ADDRESS:1", "PERSON:2"]);
    expect(attrs["fabric.guardrail.policies"]).toEqual(["presidio:EMAIL_ADDRESS"]);
    expect(attrs["fabric.guardrail.blocked"]).toBe(false);
    expect(attrs["fabric.guardrail.phase"]).toBe("input");
    expect(attrs["fabric.schema_version"]).toBe("1.0");
  });

  it("omits entities/policies attributes when none fired", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordGuardrail({ phase: "output_final", blocked: false, latencyMs: 1 });
    });
    const attrs = guardrailEvent(only());
    expect("fabric.guardrail.entities" in attrs).toBe(false);
    expect("fabric.guardrail.policies" in attrs).toBe(false);
  });

  it("recordBlock stamps fabric.blocked + ERROR status and exposes the result", () => {
    let captured: unknown;
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordBlock({
        phase: "input",
        blocked: true,
        latencyMs: 3,
        policies: ["nemo:jailbreak_defence"],
      });
      captured = d.blocked;
    });
    expect(captured).not.toBeNull();
    const span = only();
    expect(span.attributes["fabric.blocked"]).toBe(true);
    expect(span.attributes["fabric.blocked.policies"]).toEqual(["nemo:jailbreak_defence"]);
    expect(span.status.code).toBe(SpanStatusCode.ERROR);
    expect(span.status.message).toBe("guardrail_blocked");
  });

  it("recordBlock is first-wins — a second call throws", () => {
    expect(() =>
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        const r = { phase: "input" as const, blocked: true, latencyMs: 1, policies: ["x:y"] };
        d.recordBlock(r);
        d.recordBlock(r);
      }),
    ).toThrow(/already blocked/);
  });

  it("recordBlock rejects a non-blocking result", () => {
    expect(() =>
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordBlock({ phase: "input", blocked: false, latencyMs: 1 });
      }),
    ).toThrow(/non-blocking/);
  });

  it("blocked is null when no block recorded", () => {
    let captured: unknown = "sentinel";
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      captured = d.blocked;
    });
    expect(captured).toBeNull();
  });
});
