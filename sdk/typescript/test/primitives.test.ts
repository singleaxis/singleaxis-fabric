// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Behavioural unit coverage for the recording primitives ported to the TS
 * Decision (retrieval, memory, side-effect, checkpoint, eval, judge, policy,
 * tool-authorization, escalation). The byte-exact wire shape is covered by
 * the conformance suite against the shared Python goldens; this file pins the
 * behaviours not visible there: rolling counters, distinct-value sets,
 * first-wins escalation + block/escalation status precedence, hash helpers,
 * and the mutually-exclusive payload/hash guards.
 */

import { trace, SpanStatusCode, type Attributes } from "@opentelemetry/api";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { Fabric, sha256Hex } from "../src/index.js";
import { pythonJsonStringify, policyInputHash } from "../src/hash.js";

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

function decisionSpan(): ReadableSpan {
  const spans = exporter.getFinishedSpans();
  return spans.find((s) => s.name === "fabric.decision")!;
}

function eventsNamed(span: ReadableSpan, name: string): Attributes[] {
  return span.events.filter((e) => e.name === name).map((e) => e.attributes ?? {});
}

describe("rolling counters + distinct-value sets", () => {
  it("retrieval folds count + sorted distinct sources", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordRetrieval({ source: "rag", query: "q1", resultCount: 1 });
      d.recordRetrieval({ source: "kg", query: "q2", resultCount: 1 });
      d.recordRetrieval({ source: "rag", query: "q3", resultCount: 1 });
    });
    const span = decisionSpan();
    expect(span.attributes["fabric.retrieval_count"]).toBe(3);
    expect(span.attributes["fabric.retrieval_sources"]).toEqual(["kg", "rag"]);
    expect(eventsNamed(span, "fabric.retrieval")).toHaveLength(3);
  });

  it("memory tracks write/read/erase counts independently + sorted kinds", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.remember({ kind: "semantic", content: "x", key: "k1" });
      d.recall({ kind: "episodic", key: "k1", content: "x" });
      d.forget("semantic", "k1");
    });
    const span = decisionSpan();
    expect(span.attributes["fabric.memory_write_count"]).toBe(1);
    expect(span.attributes["fabric.memory_read_count"]).toBe(1);
    expect(span.attributes["fabric.memory_erase_count"]).toBe(1);
    expect(span.attributes["fabric.memory_kinds"]).toEqual(["episodic", "semantic"]);
  });

  it("side effects fold count + sorted distinct types/systems", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordSideEffect({ type: "ticket_create", targetSystem: "zendesk", operation: "o" });
      d.recordSideEffect({ type: "email_send", targetSystem: "ses", operation: "o" });
    });
    const span = decisionSpan();
    expect(span.attributes["fabric.side_effect_count"]).toBe(2);
    expect(span.attributes["fabric.side_effect_types"]).toEqual(["email_send", "ticket_create"]);
    expect(span.attributes["fabric.side_effect_systems"]).toEqual(["ses", "zendesk"]);
  });
});

describe("escalation + status precedence", () => {
  it("escalation alone sets escalation_requested ERROR status", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.requestEscalation({ reason: "low conf", mode: "async" });
      expect(d.escalation).not.toBeNull();
    });
    const span = decisionSpan();
    expect(span.attributes["fabric.escalated"]).toBe(true);
    expect(span.status.code).toBe(SpanStatusCode.ERROR);
    expect(span.status.message).toBe("escalation_requested");
  });

  it("block + escalation → blocked_and_escalated precedence", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordBlock({ phase: "input", blocked: true, latencyMs: 1, policies: ["x:y"] });
      d.requestEscalation({ reason: "also escalate", mode: "sync" });
    });
    expect(decisionSpan().status.message).toBe("blocked_and_escalated");
  });

  it("requestEscalation is first-wins — second call throws", () => {
    expect(() =>
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.requestEscalation({ reason: "a", mode: "async" });
        d.requestEscalation({ reason: "b", mode: "async" });
      }),
    ).toThrow(/first-wins/);
  });
});

describe("local hashing (raw content never emitted)", () => {
  it("retrieval hashes the query, never emits it", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordRetrieval({ source: "rag", query: "secret query", resultCount: 0 });
    });
    const ev = eventsNamed(decisionSpan(), "fabric.retrieval")[0]!;
    expect(ev["fabric.retrieval.query_hash"]).toBe(sha256Hex("secret query"));
    expect(JSON.stringify(ev)).not.toContain("secret query");
  });

  it("side effect rejects both payload and precomputed hash for one field", () => {
    expect(() =>
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordSideEffect({
          type: "t",
          targetSystem: "sys",
          operation: "o",
          requestPayload: "{}",
          requestHash: "deadbeef",
        });
      }),
    ).toThrow(/not both/);
  });

  it("policy input hashing matches Python json.dumps(sort_keys=True)", () => {
    // The space-after-colon + sorted keys is what makes this equal Python's.
    expect(pythonJsonStringify({ amount: 50 })).toBe('{"amount": 50}');
    expect(pythonJsonStringify({ b: 1, a: 2 })).toBe('{"a": 2, "b": 1}');
    expect(policyInputHash({ amount: 50 })).toBe(
      "76486eecb93e90859a9039a37489b959954ee722a13497353787f5d7f50309d6",
    );
  });

  it("policy rejects both input and inputHash", () => {
    expect(() =>
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordPolicyEvaluation({
          engine: "e",
          policyId: "p",
          decision: "allow",
          input: { a: 1 },
          inputHash: "abc",
        });
      }),
    ).toThrow(/not both/);
  });
});

describe("validation guards", () => {
  it("queueJudge requires a non-empty rubric and at least one dimension", () => {
    expect(() =>
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.queueJudge({ rubricId: "  ", dimensions: ["x"] });
      }),
    ).toThrow(/rubricId/);
    expect(() =>
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.queueJudge({ rubricId: "r1", dimensions: [] });
      }),
    ).toThrow(/dimension/);
  });

  it("checkpoint mints a UUID when none supplied + increments count", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.checkpoint("step-a");
      d.checkpoint("step-b");
    });
    const span = decisionSpan();
    expect(span.attributes["fabric.checkpoint_count"]).toBe(2);
    const ev = eventsNamed(span, "fabric.checkpoint")[0]!;
    expect(String(ev["fabric.checkpoint.checkpoint_id"])).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });
});

describe("fabric.decision_id", () => {
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  it("mints a uuid-shaped decision_id distinct from request_id when none is supplied", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, () => {});
    const span = decisionSpan();
    const decisionId = String(span.attributes["fabric.decision_id"]);
    expect(decisionId).toMatch(UUID_RE);
    expect(span.attributes["fabric.request_id"]).toBe("r");
    expect(decisionId).not.toBe("r");
  });

  it("emits a host-supplied decision_id verbatim, leaving request_id untouched", () => {
    fabric().decision(
      { sessionId: "s", requestId: "r", decisionId: "decision-supplied-0001" },
      () => {},
    );
    const span = decisionSpan();
    expect(span.attributes["fabric.decision_id"]).toBe("decision-supplied-0001");
    expect(span.attributes["fabric.request_id"]).toBe("r");
  });
});
