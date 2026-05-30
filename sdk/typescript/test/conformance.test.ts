// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Conformance test — proves the TS SDK emits the SAME wire contract as the
 * Python SDK by deep-equal-asserting normalized TS spans against the SAME
 * shared golden JSON files the Python conformance suite uses
 * (`../../python/tests/conformance/goldens/<name>.json`). The goldens are
 * READ from that shared location, never copied.
 *
 * Covered (core capture) scenarios: `bare_decision`, `llm_call`,
 * `tool_call`. The fixed conformance identifiers mirror Python's
 * `scenarios.py` so the emitted spans land verbatim against the goldens.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { trace } from "@opentelemetry/api";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { Fabric } from "../src/index.js";
import { normalizeSpans } from "./normalize.js";

// Fixed per-turn identifiers — mirror sdk/python/tests/conformance/scenarios.py.
const TENANT_ID = "tenant-conformance";
const AGENT_ID = "agent-conformance";
const PROFILE = "permissive-dev";
const SESSION_ID = "session-0001";
const REQUEST_ID = "request-0001";
const USER_ID = "user-0001";

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDENS_DIR = resolve(HERE, "..", "..", "python", "tests", "conformance", "goldens");

function loadGolden(name: string): unknown {
  return JSON.parse(readFileSync(resolve(GOLDENS_DIR, `${name}.json`), "utf-8"));
}

const exporter = new InMemorySpanExporter();
let provider: BasicTracerProvider;

beforeAll(() => {
  provider = new BasicTracerProvider({
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
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
  return new Fabric({ tenantId: TENANT_ID, agentId: AGENT_ID, profile: PROFILE });
}

function decision<T>(f: Fabric, fn: (d: import("../src/index.js").Decision) => T): T {
  return f.decision({ sessionId: SESSION_ID, requestId: REQUEST_ID, userId: USER_ID }, fn);
}

function captured(): ReadableSpan[] {
  return [...exporter.getFinishedSpans()];
}

describe("conformance against shared Python goldens", () => {
  it("bare_decision", () => {
    const f = fabric();
    decision(f, () => {
      // empty body — the bare decision span
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("bare_decision"));
  });

  it("llm_call", () => {
    const f = fabric();
    decision(f, (d) => {
      d.llmCall(
        {
          system: "anthropic",
          model: "claude-opus-4-8",
          temperature: 0.2,
          topP: 0.9,
          maxTokens: 512,
        },
        (call) => {
          call.setResponseModel("claude-opus-4-8");
          call.setUsage({ inputTokens: 120, outputTokens: 64, finishReason: "end_turn" });
        },
      );
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("llm_call"));
  });

  it("tool_call", () => {
    const f = fabric();
    decision(f, (d) => {
      d.toolCall("vector_search", { callId: "call-1" }, (tool) => {
        tool.setKind("retrieval");
        tool.setArguments('{"query":"refunds"}');
        tool.setResult('{"hits":3}');
        tool.setResultCount(3);
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("tool_call"));
  });

  it("guardrail_redaction", () => {
    const f = fabric();
    decision(f, (d) => {
      d.recordGuardrail({
        phase: "input",
        blocked: false,
        latencyMs: 4,
        policies: ["stub-redactor:pii"],
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("guardrail_redaction"));
  });

  it("guardrail_block", () => {
    const f = fabric();
    const result = {
      phase: "input" as const,
      blocked: true,
      latencyMs: 2,
      policies: ["stub-blocker:jailbreak"],
    };
    decision(f, (d) => {
      d.recordGuardrail(result);
      d.recordBlock(result);
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("guardrail_block"));
  });
});
