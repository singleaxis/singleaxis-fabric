// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Vocabulary-parity + fail-loud coverage for {@link Decision}. Confirms the
 * widened policy/escalation/replay/guardrail vocabularies (matched to the
 * Python reference and the conformance schema) emit the right `fabric.*`
 * attributes, and that malformed telemetry THROWS rather than being emitted
 * as an out-of-contract span. The byte-identical shared-wire shape for valid
 * inputs stays covered by the conformance goldens.
 */

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

function eventAttrs(span: ReadableSpan, name: string): Attributes {
  const ev = span.events.find((e) => e.name === name);
  expect(ev).toBeDefined();
  return ev!.attributes ?? {};
}

describe("widened vocabularies emit the right fabric.* attributes", () => {
  for (const decision of ["warn", "escalate", "redact"] as const) {
    it(`recordPolicyEvaluation accepts policy decision "${decision}"`, () => {
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordPolicyEvaluation({
          engine: "opa",
          policyId: "p1",
          decision,
          reason: "because",
        });
      });
      const attrs = eventAttrs(only(), "fabric.policy.evaluation");
      expect(attrs["fabric.policy.decision"]).toBe(decision);
    });
  }

  it('requestEscalation accepts mode "deferred"', () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.requestEscalation({ reason: "needs review", mode: "deferred" });
    });
    const span = only();
    expect(span.attributes["fabric.escalation.mode"]).toBe("deferred");
    expect(eventAttrs(span, "fabric.escalation")["fabric.escalation.mode"]).toBe("deferred");
  });

  for (const behavior of ["replay", "suppress", "mock", "manual"] as const) {
    it(`recordSideEffect accepts replayBehavior "${behavior}"`, () => {
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordSideEffect({
          type: "external_write",
          targetSystem: "crm",
          operation: "create",
          replayBehavior: behavior,
        });
      });
      const attrs = eventAttrs(only(), "fabric.side_effect");
      expect(attrs["fabric.side_effect.replay_behavior"]).toBe(behavior);
    });
  }
});

describe("malformed telemetry throws instead of emitting junk", () => {
  function inDecision(fn: (d: import("../src/index.js").Decision) => void): () => void {
    return () => fabric().decision({ sessionId: "s", requestId: "r" }, fn);
  }

  it("setAttribute rejects a non-scalar value", () => {
    expect(
      inDecision((d) => {
        (d.setAttribute as (k: string, v: unknown) => void)("k", { nope: true });
      }),
    ).toThrow(/must be a string, number, or boolean/);
  });

  it("recordPolicyEvaluation rejects an out-of-set decision", () => {
    expect(
      inDecision((d) => {
        d.recordPolicyEvaluation({
          engine: "opa",
          policyId: "p1",
          decision: "maybe" as unknown as "allow",
        });
      }),
    ).toThrow(/decision must be one of/);
  });

  it("recordToolAuthorization rejects a decision outside {allow, deny}", () => {
    expect(
      inDecision((d) => {
        d.recordToolAuthorization({
          toolName: "send_email",
          decision: "warn" as unknown as "allow",
        });
      }),
    ).toThrow(/decision must be one of \{allow, deny\}/);
  });

  it("recordSideEffect rejects an out-of-set replayBehavior", () => {
    expect(
      inDecision((d) => {
        d.recordSideEffect({
          type: "external_write",
          targetSystem: "crm",
          operation: "create",
          replayBehavior: "compensate" as unknown as "replay",
        });
      }),
    ).toThrow(/replayBehavior must be one of/);
  });

  it("requestEscalation rejects a mode outside {sync, async, deferred}", () => {
    expect(
      inDecision((d) => {
        d.requestEscalation({ reason: "x", mode: "later" as unknown as "sync" });
      }),
    ).toThrow(/mode must be one of/);
  });

  it("recordGuardrail rejects an out-of-set phase", () => {
    expect(
      inDecision((d) => {
        d.recordGuardrail({
          phase: "middle" as unknown as "input",
          blocked: false,
          latencyMs: 1,
        });
      }),
    ).toThrow(/phase must be one of/);
  });

  it("rejects a NaN numeric field", () => {
    expect(
      inDecision((d) => {
        d.recordPolicyEvaluation({
          engine: "opa",
          policyId: "p1",
          decision: "allow",
          latencyMs: NaN,
        });
      }),
    ).toThrow(/latencyMs must be a finite number/);
  });

  it("rejects an Infinity numeric field on recordGuardrail", () => {
    expect(
      inDecision((d) => {
        d.recordGuardrail({ phase: "input", blocked: false, latencyMs: Infinity });
      }),
    ).toThrow(/latencyMs must be a finite number/);
  });
});
