// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * v0.8.1 (spec 049 §2.9 rules 1 and 4, N12/C39/C40), in parity with Python
 * `tests/test_correlation_ids.py`: provider ids (response, previous response,
 * tool call) are the keyed v2 `p-` form in pseudonymous mode; the caller's
 * request id is the keyed `lbl-` form; without the key they are omitted;
 * clear mode reproduces v0.8.0.
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
const IDS = {
  previous: "CANARY-prev-q8z",
  response: "CANARY-response-q8z",
  call: "CANARY-call-q8z",
  request: "CANARY-request-q8z",
};
const providers: BasicTracerProvider[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(providers.splice(0).map((p) => p.shutdown()));
});

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
  fabric.decision({ sessionId: "s", requestId: IDS.request }, (d) => {
    d.llmCall({ provider: "openai", model: "m", previousResponseId: IDS.previous }, (llm) =>
      llm.setResponse({ responseId: IDS.response }),
    );
    d.toolCall("lookup", { callId: IDS.call }, () => undefined);
  });
  const spans = exporter.getFinishedSpans();
  return (key: string) =>
    spans
      .flatMap((s) => [s.attributes, ...s.events.map((e) => e.attributes ?? {})])
      .filter((a) => key in a)
      .map((a) => a[key]);
}

describe("correlation ids", () => {
  it("are p- (provider) and lbl- (caller) pseudonyms with the key", () => {
    const values = run("pseudonymous", KEY);
    expect(values("gen_ai.request.previous_response.id")).toEqual([
      pseudonymV2("p", IDS.previous, KEY),
    ]);
    expect(values("gen_ai.response.id")).toEqual([pseudonymV2("p", IDS.response, KEY)]);
    expect(values("gen_ai.tool.call.id")).toEqual([pseudonymV2("p", IDS.call, KEY)]);
    expect(values("fabric.tool.call.id")).toEqual([pseudonymV2("p", IDS.call, KEY)]);
    expect(values("fabric.request_id")).toEqual([labelPseudonym("lbl", IDS.request, KEY)]);
  });

  it("are omitted without the key", () => {
    vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
    const values = run("pseudonymous");
    for (const key of [
      "gen_ai.request.previous_response.id",
      "gen_ai.response.id",
      "gen_ai.tool.call.id",
      "fabric.tool.call.id",
      "fabric.request_id",
    ]) {
      expect(values(key), key).toEqual([]);
    }
  });

  it("stay as given in clear mode", () => {
    const values = run("clear", KEY);
    expect(values("gen_ai.request.previous_response.id")).toEqual([IDS.previous]);
    expect(values("gen_ai.response.id")).toEqual([IDS.response]);
    expect(values("gen_ai.tool.call.id")).toEqual([IDS.call]);
    expect(values("fabric.request_id")).toEqual([IDS.request]);
  });
});
