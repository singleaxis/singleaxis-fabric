// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Coverage for W3C `traceparent` + `tracestate` Fabric context
 * propagation — a port of the Python `test_propagation.py` suite plus the
 * TS-specific composition of the OTel propagator (the carrier must carry
 * both `traceparent` and the `singleaxis` tracestate member).
 */

import { context, trace } from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  Fabric,
  FABRIC_KEY,
  MAX_MEMBERS,
  TRACESTATE_HEADER,
  TRACEPARENT_HEADER,
  extract,
  inject,
  injectDecision,
  type FabricContext,
} from "../src/index.js";

const exporter = new InMemorySpanExporter();
let provider: BasicTracerProvider;
const contextManager = new AsyncLocalStorageContextManager();

beforeAll(() => {
  // A real context manager so `otelContext.active()` inside a decision
  // callback resolves the ambient span — required for `inject` to source
  // `traceparent` from the surrounding context.
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

function fabricValue(carrier: Record<string, string>): string {
  const tracestate = carrier[TRACESTATE_HEADER]!;
  for (const entry of tracestate.split(",")) {
    const eq = entry.trim().indexOf("=");
    if (eq >= 0 && entry.trim().slice(0, eq).trim() === FABRIC_KEY) {
      return entry
        .trim()
        .slice(eq + 1)
        .trim();
    }
  }
  throw new Error(`no ${FABRIC_KEY} member in ${JSON.stringify(tracestate)}`);
}

function memberKeys(carrier: Record<string, string>): string[] {
  return carrier[TRACESTATE_HEADER]!.split(",").map((entry) => entry.trim().split("=")[0]!.trim());
}

function base64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf-8").toString("base64url");
}

describe("FabricContext tracestate member", () => {
  it("round-trips all fields", () => {
    const carrier: Record<string, string> = {};
    const ctx: FabricContext = {
      tenantId: "tenant-1",
      agentId: "agent-1",
      sessionId: "sess-1",
      requestId: "req-1",
    };
    inject(carrier, ctx);
    expect(extract(carrier)).toEqual(ctx);
  });

  it("round-trips with optional fields unset", () => {
    const carrier: Record<string, string> = {};
    const ctx: FabricContext = { tenantId: "tenant-1", agentId: "agent-1" };
    inject(carrier, ctx);
    const recovered = extract(carrier)!;
    expect(recovered.tenantId).toBe("tenant-1");
    expect(recovered.agentId).toBe("agent-1");
    expect(recovered.sessionId).toBeUndefined();
    expect(recovered.requestId).toBeUndefined();
    expect(recovered.workflowId).toBeUndefined();
    expect(recovered.executionId).toBeUndefined();
  });

  it("round-trips workflow + execution retry metadata + parent agent", () => {
    const carrier: Record<string, string> = {};
    const ctx: FabricContext = {
      tenantId: "t",
      agentId: "a",
      sessionId: "sess-1",
      requestId: "req-1",
      decisionId: "dec-1",
      workflowId: "refunds",
      executionId: "refund-task-123",
      executionAttemptId: "attempt-002",
      executionAttempt: 2,
      executionRetryReason: "tool_timeout",
      executionRetryPreviousAttemptId: "attempt-001",
      parentAgentId: "support-bot",
    };
    inject(carrier, ctx);
    expect(extract(carrier)).toEqual(ctx);
  });

  it("decodes an old-format member (only t/a/s/r)", () => {
    const legacy = base64urlJson({ t: "t", a: "a", s: "s", r: "r" });
    const recovered = extract({ [TRACESTATE_HEADER]: `${FABRIC_KEY}=${legacy}` })!;
    expect(recovered).toEqual({
      tenantId: "t",
      agentId: "a",
      sessionId: "s",
      requestId: "r",
      decisionId: undefined,
      workflowId: undefined,
      executionId: undefined,
      executionAttemptId: undefined,
      executionAttempt: undefined,
      executionRetryReason: undefined,
      executionRetryPreviousAttemptId: undefined,
      parentAgentId: undefined,
    });
  });

  it("special characters survive the round trip and stay charset-safe", () => {
    const ctx: FabricContext = {
      tenantId: "tenant with spaces, and = signs",
      agentId: "agent/é☃🚀",
      sessionId: "s,e=s s i,o=n",
      requestId: "r=q,r",
      workflowId: "wf with spaces, = and é☃🚀",
      executionId: "ex,=/x",
    };
    const carrier: Record<string, string> = {};
    inject(carrier, ctx);
    expect(extract(carrier)).toEqual(ctx);
    const value = fabricValue(carrier);
    expect(value).not.toContain(",");
    expect(value).not.toContain("=");
    for (const c of value) {
      const code = c.charCodeAt(0);
      expect(code).toBeGreaterThanOrEqual(0x20);
      expect(code).toBeLessThanOrEqual(0x7e);
    }
  });

  it("preserves an existing tracestate and puts the Fabric member first", () => {
    const carrier = { [TRACESTATE_HEADER]: "othervendor=abc" };
    inject(carrier, { tenantId: "t", agentId: "a" });
    const members = carrier[TRACESTATE_HEADER]!.split(",").map((m) => m.trim());
    expect(memberKeys(carrier)[0]).toBe(FABRIC_KEY);
    expect(members).toContain("othervendor=abc");
    expect(extract(carrier)).toEqual({ tenantId: "t", agentId: "a" });
  });

  it("re-inject replaces the member rather than duplicating it", () => {
    const carrier: Record<string, string> = {};
    inject(carrier, { tenantId: "t1", agentId: "a1" });
    inject(carrier, { tenantId: "t2", agentId: "a2" });
    expect(memberKeys(carrier).filter((k) => k === FABRIC_KEY)).toHaveLength(1);
    expect(extract(carrier)).toEqual({ tenantId: "t2", agentId: "a2" });
  });

  it("tolerates whitespace, empty entries and malformed members", () => {
    const carrier = { [TRACESTATE_HEADER]: " othervendor = abc , , malformed , " };
    inject(carrier, { tenantId: "t", agentId: "a" });
    expect(extract(carrier)).toEqual({ tenantId: "t", agentId: "a" });
    const members = carrier[TRACESTATE_HEADER]!.split(",").map((m) => m.trim());
    expect(members).toContain("othervendor=abc");
    expect(members.every((m) => m !== "malformed")).toBe(true);
  });

  it("caps the member list at MAX_MEMBERS with Fabric first", () => {
    const others = Array.from({ length: MAX_MEMBERS }, (_, i) => `v${i}=val${i}`).join(",");
    const carrier = { [TRACESTATE_HEADER]: others };
    inject(carrier, { tenantId: "t", agentId: "a" });
    const members = carrier[TRACESTATE_HEADER]!.split(",").filter((m) => m.trim() !== "");
    expect(members.length).toBeLessThanOrEqual(MAX_MEMBERS);
    expect(memberKeys(carrier)[0]).toBe(FABRIC_KEY);
    expect(extract(carrier)).toEqual({ tenantId: "t", agentId: "a" });
  });

  it("throws when the encoded value exceeds the W3C per-value limit", () => {
    const huge = "x".repeat(1024);
    expect(() => inject({}, { tenantId: huge, agentId: "a" })).toThrow(/per-value limit/);
  });
});

describe("extract failure tolerance", () => {
  it("returns undefined without a tracestate or a Fabric member", () => {
    expect(extract({})).toBeUndefined();
    expect(extract({ [TRACESTATE_HEADER]: "othervendor=abc,foo=bar" })).toBeUndefined();
  });

  it("returns undefined on a garbage member", () => {
    expect(extract({ [TRACESTATE_HEADER]: `${FABRIC_KEY}=!!!not-base64!!!` })).toBeUndefined();
    // Valid base64 of a non-dict JSON value.
    expect(extract({ [TRACESTATE_HEADER]: `${FABRIC_KEY}=WzEsMiwzXQ` })).toBeUndefined();
    // Empty value.
    expect(extract({ [TRACESTATE_HEADER]: `${FABRIC_KEY}=` })).toBeUndefined();
  });

  it.each([
    "eyJhIjogImFnZW50In0", // {"a": "agent"} — missing required "t"
    "eyJ0IjogInQiLCAiYSI6ICJhIiwgInMiOiA1fQ", // session is an int
    "eyJ0IjogInQiLCAiYSI6ICJhIiwgInIiOiA1fQ", // request is an int
    "eyJ0IjogInQiLCAiYSI6ICJhIiwgInciOiA1fQ", // workflow is an int
    "eyJ0IjogInQiLCAiYSI6ICJhIiwgImUiOiA1fQ", // execution is an int
  ])("returns undefined on a wrong-shaped payload %s", (encoded) => {
    expect(extract({ [TRACESTATE_HEADER]: `${FABRIC_KEY}=${encoded}` })).toBeUndefined();
  });

  it.each([0, "2", true])("returns undefined on a wrong attempt shape %s", (attempt) => {
    const encoded = base64urlJson({ t: "t", a: "a", e: "ex-1", en: attempt });
    expect(extract({ [TRACESTATE_HEADER]: `${FABRIC_KEY}=${encoded}` })).toBeUndefined();
  });
});

describe("traceparent composition", () => {
  const TRACEPARENT_RE = /^00-[0-9a-f]{32}-[0-9a-f]{16}-0[0-9a-f]$/;

  it("injectDecision writes both traceparent and the Fabric member", () => {
    const f = new Fabric({ tenantId: "acme", agentId: "bot" });
    const carrier: Record<string, string> = {};
    f.decision({ sessionId: "s1", requestId: "r1", decisionId: "d1" }, (decision) => {
      injectDecision(carrier, decision);
      expect(carrier[TRACEPARENT_HEADER]).toMatch(TRACEPARENT_RE);
      // The traceparent points at THIS decision's span so downstream
      // spans parent under it.
      const sc = decision.getSpan().spanContext();
      expect(carrier[TRACEPARENT_HEADER]).toContain(sc.traceId);
      expect(carrier[TRACEPARENT_HEADER]).toContain(sc.spanId);
    });
    const recovered = extract(carrier)!;
    expect(recovered).toMatchObject({
      tenantId: "acme",
      agentId: "bot",
      sessionId: "s1",
      requestId: "r1",
      decisionId: "d1",
    });
  });

  it("a bare inject inside a decision also emits traceparent", () => {
    const f = new Fabric({ tenantId: "acme", agentId: "bot" });
    const carrier: Record<string, string> = {};
    f.decision({ sessionId: "s1", requestId: "r1" }, () => {
      inject(carrier, { tenantId: "acme", agentId: "bot" });
    });
    expect(carrier[TRACEPARENT_HEADER]).toMatch(TRACEPARENT_RE);
    expect(extract(carrier)).toEqual({ tenantId: "acme", agentId: "bot" });
  });
});

describe("delegation carrier", () => {
  function decisionSpan(): ReadableSpan {
    const span = exporter.getFinishedSpans().find((s) => s.name === "fabric.decision");
    expect(span).toBeDefined();
    return span!;
  }

  it("the carrier links back to the parent via parentAgentId + traceparent", () => {
    exporter.reset();
    const f = new Fabric({ tenantId: "acme", agentId: "support-bot" });
    let carrier: Record<string, string> = {};
    let parentDecisionId = "";
    f.decision({ sessionId: "s", requestId: "r" }, (d) => {
      parentDecisionId = d.decisionId;
      d.delegate("child-agent", (sub) => {
        carrier = sub.carrier;
      });
    });
    expect(carrier[TRACEPARENT_HEADER]).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-0[0-9a-f]$/);
    const recovered = extract(carrier)!;
    expect(recovered.parentAgentId).toBe("support-bot");
    expect(recovered.agentId).toBe("support-bot");
    expect(recovered.decisionId).toBe(parentDecisionId);
    expect(recovered.tenantId).toBe("acme");
    // The traceparent's span id is the parent's decision span id.
    expect(carrier[TRACEPARENT_HEADER]).toContain(decisionSpan().spanContext().spanId);
  });
});
