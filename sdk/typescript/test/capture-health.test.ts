// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

import { trace, type Span, type TracerProvider } from "@opentelemetry/api";
import {
  AlwaysOffSampler,
  AlwaysOnSampler,
  BasicTracerProvider,
} from "@opentelemetry/sdk-trace-node";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Fabric, testing, type Decision } from "../src/index.js";

const ids = { sessionId: "private-session", requestId: "private-request" };
const providers: BasicTracerProvider[] = [];
function client(options: ConstructorParameters<typeof BasicTracerProvider>[0] = {}) {
  const provider = new BasicTracerProvider({ sampler: new AlwaysOnSampler(), ...options });
  providers.push(provider);
  return new Fabric({
    tenantId: "private-tenant",
    agentId: "private-agent",
    tracerProvider: provider,
  });
}
beforeEach(() => testing.resetCaptureHealthWarnings());
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(providers.splice(0).map((provider) => provider.shutdown()));
});

describe("decision-local capture health", () => {
  it("reports sampled-out capture without claiming the ended span changed state", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const f = client({ sampler: new AlwaysOffSampler() });
    const d = f.startDecision(ids);
    expect(d.captureHealth).toEqual({
      status: "disabled",
      scope: "decision_span_only",
      recordingAtStart: false,
      droppedEvents: null,
      droppedAttributes: null,
    });
    d.end();
    f.startDecision(ids).end();
    expect(d.captureHealth.status).toBe("disabled");
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls.flat().join(" ")).not.toContain("private-");
  });

  it("keeps zero-drop recording unverified and snapshots independent", () => {
    const d = client().startDecision(ids);
    const snapshot = d.captureHealth;
    expect(snapshot).toEqual({
      status: "unverified",
      scope: "decision_span_only",
      recordingAtStart: true,
      droppedEvents: 0,
      droppedAttributes: 0,
    });
    d.end();
    expect(d.getSpan().isRecording()).toBe(false);
    expect(d.captureHealth).toEqual(snapshot);
    expect(d.captureHealth).not.toBe(snapshot);
  });

  it.each([2, 128])("reports overflow at event capacity %i", (eventCountLimit) => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const f = client(eventCountLimit === 128 ? {} : { spanLimits: { eventCountLimit } });
    let decision!: Decision;
    const value = f.decision(ids, (d) => {
      decision = d;
      for (let i = 0; i < eventCountLimit + 1; i++) d.getSpan().addEvent("private-content");
      return 42;
    });
    expect(value).toBe(42);
    expect(decision.captureHealth).toMatchObject({ status: "partial", droppedEvents: 1 });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls.flat().join(" ")).not.toContain("private-");
  });

  it("observes attribute drops including constructor metadata", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const d = client({ spanLimits: { attributeCountLimit: 1 } }).startDecision(ids);
    d.end();
    expect(d.captureHealth.status).toBe("partial");
    expect(d.captureHealth.droppedAttributes).toBeGreaterThan(0);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("contains throwing logger errors and preserves sync/async outcomes", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {
      throw new Error("logger unavailable");
    });
    const f = client({ spanLimits: { eventCountLimit: 0 } });
    const failure = new Error("private-failure");
    let d!: Decision;
    expect(() =>
      f.decision(ids, (decision) => {
        d = decision;
        throw failure;
      }),
    ).toThrow(failure);
    expect(d.captureHealth).toMatchObject({ status: "partial", droppedEvents: 1 });
    testing.resetCaptureHealthWarnings();
    await expect(
      f.decision(ids, async (decision) => {
        d = decision;
        await Promise.resolve();
        throw failure;
      }),
    ).rejects.toBe(failure);
    expect(d.captureHealth).toMatchObject({ status: "partial", droppedEvents: 1 });
    await expect(
      f.decision(ids, async (decision) => {
        d = decision;
        decision.getSpan().addEvent("event");
        return 7;
      }),
    ).resolves.toBe(7);
    expect(d.captureHealth.status).toBe("partial");
  });

  it("checks final public counters after end without requiring a health read", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    let ended = false;
    const base = trace.wrapSpanContext({
      traceId: "1".repeat(32),
      spanId: "2".repeat(16),
      traceFlags: 1,
    });
    const span = new Proxy(base, {
      get(target, key) {
        if (key === "isRecording") return () => !ended;
        if (key === "end")
          return () => {
            ended = true;
          };
        if (key === "droppedEventsCount") return ended ? 1 : 0;
        if (key === "droppedAttributesCount") return 0;
        const value = Reflect.get(target, key);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const provider = { getTracer: () => ({ startSpan: () => span }) } as unknown as TracerProvider;
    const f = new Fabric({ tenantId: "t", agentId: "a", tracerProvider: provider });
    f.decision(ids, () => 1);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("handles providers without counters or with throwing diagnostic getters", () => {
    const base = trace.wrapSpanContext({
      traceId: "1".repeat(32),
      spanId: "2".repeat(16),
      traceFlags: 1,
    });
    const span = new Proxy(base, {
      get(target, key) {
        if (key === "isRecording") return () => true;
        if (key === "droppedAttributesCount") throw new Error("unavailable");
        const value = Reflect.get(target, key);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as Span;
    const provider = { getTracer: () => ({ startSpan: () => span }) } as unknown as TracerProvider;
    const f = new Fabric({ tenantId: "t", agentId: "a", tracerProvider: provider });
    const d = f.startDecision(ids);
    d.end();
    expect(d.captureHealth).toMatchObject({
      status: "unverified",
      recordingAtStart: true,
      droppedEvents: null,
      droppedAttributes: null,
    });
  });
});
