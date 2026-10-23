// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * v0.8.1 (Sol review, deferred P1 items), in parity with Python
 * `tests/test_side_effect_and_tool_identity.py`: side-effect identifiers and
 * labels, tool names on spans and the interaction metadata digest are
 * pseudonymised or omitted in the pseudonymous mode; clear reproduces v0.8.0.
 */

import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-node";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Fabric } from "../src/index.js";
import { labelPseudonym, pseudonymV2 } from "../src/identity.js";

const KEY = "fabric-test-id-key-not-a-secret";
const V = {
  effect: "CANARY-effect-q8z",
  system: "CANARY-patient-crm-q8z",
  operation: "CANARY-update-jane-q8z",
  parent: "CANARY-call-q8z",
  tool: "CANARY_lookup_patient_q8z",
};
const METADATA = { patient: "jane" };
const providers: BasicTracerProvider[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(providers.splice(0).map((p) => p.shutdown()));
});
const lbl = (value: string) => labelPseudonym("lbl", value, KEY);

function run(identityMode: "pseudonymous" | "clear", idKey?: string) {
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  providers.push(provider);
  const fabric = new Fabric({
    tenantId: "acme",
    agentId: "bot",
    tracerProvider: provider,
    identityMode,
    ...(idKey !== undefined ? { idKey } : {}),
  });
  fabric.decision({ sessionId: "s", requestId: "r" }, (d) => {
    d.recordSideEffect({
      type: "other",
      targetSystem: V.system,
      operation: V.operation,
      sideEffectId: V.effect,
      parentToolCallId: V.parent,
    });
    d.recordSideEffect({ type: "other", targetSystem: V.system, operation: V.operation });
    d.recordReplayMetadata();
    d.toolCall(V.tool, {}, () => undefined);
    d.recordInteraction("message.send", "t", { metadata: METADATA });
  });
  const spans = exporter.getFinishedSpans();
  const values = (key: string) =>
    spans
      .flatMap((s) => [s.attributes, ...s.events.map((e) => e.attributes ?? {})])
      .filter((a) => key in a)
      .map((a) => a[key]);
  return {
    values,
    names: spans.map((s) => s.name),
    blob: JSON.stringify(spans.map((s) => [s.name, s.attributes, s.events])),
  };
}

describe("side-effect identifiers, labels and tool names", () => {
  it("are pseudonymised with the key", () => {
    vi.stubEnv("FABRIC_WIRE_LABELS", "");
    const { values, names, blob } = run("pseudonymous", KEY);
    const ids = values("fabric.side_effect.side_effect_id") as string[];
    expect(ids[0]).toBe(lbl(V.effect));
    expect(ids[1]).toMatch(/^[0-9a-f-]{36}$/);
    expect(values("fabric.replay.suppressed_side_effect_ids")).toEqual([ids]);
    expect(values("fabric.side_effect.target_system")).toEqual([lbl(V.system), lbl(V.system)]);
    expect(values("fabric.side_effect.operation")).toEqual([lbl(V.operation), lbl(V.operation)]);
    expect(values("fabric.side_effect.parent_tool_call_id")).toEqual([
      pseudonymV2("p", V.parent, KEY),
    ]);
    expect(values("gen_ai.tool.name")).toEqual([lbl(V.tool)]);
    expect(names).toContain(lbl(V.tool));
    expect(values("fabric.interaction.metadata_hash")).toEqual([]);
    for (const value of Object.values(V)) expect(blob).not.toContain(value);
  });

  it("are omitted without the key", () => {
    vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
    vi.stubEnv("FABRIC_WIRE_LABELS", "");
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const { values, names, blob } = run("pseudonymous");
    expect(values("fabric.side_effect.side_effect_id")).toHaveLength(1);
    for (const key of [
      "fabric.side_effect.target_system",
      "fabric.side_effect.operation",
      "fabric.side_effect.parent_tool_call_id",
      "gen_ai.tool.name",
      "fabric.tool.name",
    ]) {
      expect(values(key), key).toEqual([]);
    }
    expect(names).toContain("execute_tool");
    for (const value of Object.values(V)) expect(blob).not.toContain(value);
  });

  it("reproduce v0.8.0 in clear mode", () => {
    const { values, names } = run("clear", KEY);
    expect((values("fabric.side_effect.side_effect_id") as string[])[0]).toBe(V.effect);
    expect(values("fabric.side_effect.target_system")).toEqual([V.system, V.system]);
    expect(values("fabric.side_effect.parent_tool_call_id")).toEqual([V.parent]);
    expect(values("gen_ai.tool.name")).toEqual([V.tool]);
    expect(names).toContain(V.tool);
    expect(values("fabric.interaction.metadata_hash")).toHaveLength(1);
    expect(values("fabric.interaction.metadata_hash")[0]).toMatch(/^[0-9a-f]{64}$/);
  });
});
