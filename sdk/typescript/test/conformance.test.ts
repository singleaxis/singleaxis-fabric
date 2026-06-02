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

import { readFileSync, readdirSync } from "node:fs";
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

import { Fabric, sha256Hex } from "../src/index.js";
import { normalizeSpans } from "./normalize.js";

// Fixed per-turn identifiers — mirror sdk/python/tests/conformance/scenarios.py.
const TENANT_ID = "tenant-conformance";
const AGENT_ID = "agent-conformance";
const PROFILE = "permissive-dev";
const SESSION_ID = "session-0001";
const REQUEST_ID = "request-0001";
const USER_ID = "user-0001";

// Fixed execution-correlation ids + attempt metadata — mirror scenarios.py.
// Supplied verbatim and NOT normalized away, so the golden asserts the literal
// value stamped on the execution span and inherited by the inner decision.
const EXECUTION_ID = "execution-0001";
const WORKFLOW_ID = "workflow-0001";
const EXECUTION_ATTEMPT_ID = "attempt-0001";
const EXECUTION_ATTEMPT = 1;

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDENS_DIR = resolve(HERE, "..", "..", "python", "tests", "conformance", "goldens");

function loadGolden(name: string): unknown {
  return JSON.parse(readFileSync(resolve(GOLDENS_DIR, `${name}.json`), "utf-8"));
}

// Every shared golden the TS SDK is expected to reproduce. The
// "covers every shared golden" test below asserts this set equals the
// goldens directory exactly, so a new Python golden can't silently land
// without matching TS coverage.
const COVERED_GOLDENS = [
  "bare_decision",
  "execution",
  "llm_call",
  "tool_call",
  "guardrail_redaction",
  "guardrail_block",
  "content_ref_stamped",
  "escalation",
  "retrieval",
  "memory_read_write",
  "side_effect",
  "checkpoint",
  "eval_record",
  "queue_judge",
  "policy_allow",
  "policy_deny",
  "policy_fail_closed",
  "tool_authorization_allow",
  "tool_authorization_deny",
];

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
  it("covers every shared golden (no Python golden left unreproduced)", () => {
    const onDisk = readdirSync(GOLDENS_DIR)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.replace(/\.json$/, ""))
      .sort();
    expect(onDisk).toEqual([...COVERED_GOLDENS].sort());
  });

  it("bare_decision", () => {
    const f = fabric();
    decision(f, () => {
      // empty body — the bare decision span
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("bare_decision"));
  });

  it("execution", () => {
    const f = fabric();
    f.execution(
      {
        executionId: EXECUTION_ID,
        workflowId: WORKFLOW_ID,
        executionAttemptId: EXECUTION_ATTEMPT_ID,
        executionAttempt: EXECUTION_ATTEMPT,
      },
      () => {
        // A bare decision inside the execution: it inherits execution_id +
        // workflow_id + attempt metadata from the active execution (ALS).
        decision(f, () => {
          // empty body — the inherited decision span
        });
      },
    );
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("execution"));
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

  it("content_ref_stamped", () => {
    const f = fabric();
    decision(f, (d) => {
      // Mirrors the Python DeterministicContentStore: mem://<sha256(content)>.
      d.recordGuardrail({
        phase: "input",
        blocked: false,
        latencyMs: 4,
        policies: ["stub-redactor:pii"],
        contentRef: `mem://${sha256Hex("my email is alice@example.com")}`,
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("content_ref_stamped"));
  });

  it("escalation", () => {
    const f = fabric();
    decision(f, (d) => {
      d.requestEscalation({
        reason: "low confidence on refund eligibility",
        rubricId: "refund-eligibility-v1",
        triggeringScore: 0.42,
        mode: "async",
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("escalation"));
  });

  it("retrieval", () => {
    const f = fabric();
    decision(f, (d) => {
      d.recordRetrieval({
        source: "rag",
        query: "refund policy for late deliveries",
        resultCount: 2,
        resultHashes: ["a".repeat(64), "b".repeat(64)],
        sourceDocumentIds: ["doc-1", "doc-2"],
        latencyMs: 12,
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("retrieval"));
  });

  it("memory_read_write", () => {
    const f = fabric();
    decision(f, (d) => {
      d.remember({
        kind: "semantic",
        content: "customer prefers email contact",
        key: "pref:contact",
        tags: ["preference", "contact"],
        ttlSeconds: 86400,
      });
      d.recall({
        kind: "semantic",
        key: "pref:contact",
        content: "customer prefers email contact",
        source: "vector-store",
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("memory_read_write"));
  });

  it("side_effect", () => {
    const f = fabric();
    decision(f, (d) => {
      d.recordSideEffect({
        type: "ticket_create",
        targetSystem: "zendesk",
        operation: "create_ticket",
        requestPayload: '{"subject":"refund"}',
        resultPayload: '{"id":"T-100"}',
        idempotencyKey: "idem-100",
        approvalRequired: true,
        committed: true,
        rollbackSupported: false,
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("side_effect"));
  });

  it("checkpoint", () => {
    const f = fabric();
    decision(f, (d) => {
      d.checkpoint("after-retrieval", {
        stateHash: "c".repeat(64),
        checkpointId: "11111111-1111-1111-1111-111111111111",
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("checkpoint"));
  });

  it("eval_record", () => {
    const f = fabric();
    decision(f, (d) => {
      d.recordEval({
        rubricId: "faithfulness-v1",
        score: 0.91,
        dimension: "faithfulness",
        evaluatorName: "StubJudge:Faithfulness",
        evaluatorVersion: "1.2.0",
        confidence: 0.8,
        payloadRef: "tenant://payloads/req-0001",
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("eval_record"));
  });

  it("queue_judge", () => {
    const f = fabric();
    decision(f, (d) => {
      d.queueJudge({
        rubricId: "helpfulness-v1",
        dimensions: ["helpfulness", "tone"],
        payloadRef: "tenant://payloads/judge-0001",
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("queue_judge"));
  });

  it("policy_allow", () => {
    const f = fabric();
    decision(f, (d) => {
      d.recordPolicyEvaluation({
        engine: "stub-policy",
        policyId: "finance.refund.cap",
        decision: "allow",
        input: { amount: 50 },
        policyVersion: "v3",
        latencyMs: 1,
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("policy_allow"));
  });

  it("policy_deny", () => {
    const f = fabric();
    decision(f, (d) => {
      d.recordPolicyEvaluation({
        engine: "stub-policy",
        policyId: "finance.refund.cap",
        decision: "deny",
        input: { amount: 5000 },
        policyVersion: "v3",
        reason: "amount exceeds cap",
        evidenceRef: "tenant://evidence/deny-1",
        latencyMs: 1,
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("policy_deny"));
  });

  it("policy_fail_closed", () => {
    const f = fabric();
    decision(f, (d) => {
      // Mirrors the SDK fail-closed path: a raising engine becomes a deny
      // with a synthetic reason. No policy_version (the engine never returned).
      d.recordPolicyEvaluation({
        engine: "stub-policy-raising",
        policyId: "finance.refund.cap",
        decision: "deny",
        input: { amount: 50 },
        reason: "adapter raised: RuntimeError: engine unreachable",
        latencyMs: 1,
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("policy_fail_closed"));
  });

  it("tool_authorization_allow", () => {
    const f = fabric();
    decision(f, (d) => {
      d.recordToolAuthorization({
        toolName: "search_orders",
        decision: "allow",
        arguments: '{"order_id":"O-1"}',
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("tool_authorization_allow"));
  });

  it("tool_authorization_deny", () => {
    const f = fabric();
    decision(f, (d) => {
      d.recordToolAuthorization({
        toolName: "wire_transfer",
        decision: "deny",
        arguments: '{"amount":9999}',
        reason: "tool not on allow-list",
      });
    });
    const got = normalizeSpans(captured());
    expect(got).toEqual(loadGolden("tool_authorization_deny"));
  });
});
