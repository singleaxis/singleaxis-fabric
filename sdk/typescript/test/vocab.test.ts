// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/** Recorder activity vocabulary and fail-loud validation coverage. */

import { trace, type Attributes } from "@opentelemetry/api";
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

beforeEach(() => exporter.reset());

function fabric(): Fabric {
  return new Fabric({ tenantId: "t", agentId: "a", profile: "p" });
}

function only(): ReadableSpan {
  const spans = exporter.getFinishedSpans();
  expect(spans).toHaveLength(1);
  return spans[0]!;
}

function eventAttrs(span: ReadableSpan, name: string): Attributes {
  const event = span.events.find((candidate) => candidate.name === name);
  expect(event).toBeDefined();
  return event!.attributes ?? {};
}

describe("recorder activity vocabularies", () => {
  for (const behavior of ["replay", "suppress", "mock", "manual"] as const) {
    it(`accepts side-effect replayBehavior ${behavior}`, () => {
      fabric().decision({ sessionId: "s", requestId: "r" }, (decision) => {
        decision.recordSideEffect({
          type: "external_write",
          targetSystem: "crm",
          operation: "create",
          replayBehavior: behavior,
        });
      });
      expect(eventAttrs(only(), "fabric.side_effect")["fabric.side_effect.replay_behavior"]).toBe(
        behavior,
      );
    });
  }
});

describe("malformed recorder telemetry fails loudly", () => {
  function inDecision(fn: (decision: import("../src/index.js").Decision) => void): () => void {
    return () => fabric().decision({ sessionId: "s", requestId: "r" }, fn);
  }

  it("rejects a non-scalar custom attribute", () => {
    expect(
      inDecision((decision) => {
        (decision.setAttribute as (key: string, value: unknown) => void)("k", { nope: true });
      }),
    ).toThrow(/must be a string, number, or boolean/);
  });

  it("rejects an unknown side-effect replay behavior", () => {
    expect(
      inDecision((decision) => {
        decision.recordSideEffect({
          type: "external_write",
          targetSystem: "crm",
          operation: "create",
          replayBehavior: "compensate" as unknown as "replay",
        });
      }),
    ).toThrow(/replayBehavior must be one of/);
  });
});
