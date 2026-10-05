// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Behavioural unit coverage for the recording primitives ported to the TS
 * Decision: retrieval, memory, side effects, checkpoints, correlations and
 * content-safe activity hashing.
 */

import { trace, SpanStatusCode, type Attributes } from "@opentelemetry/api";
import {
  AlwaysOnSampler,
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-node";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { Fabric, sha256Hex } from "../src/index.js";

const exporter = new InMemorySpanExporter();
let provider: BasicTracerProvider;

beforeAll(() => {
  provider = new BasicTracerProvider({
    sampler: new AlwaysOnSampler(),
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
  return new Fabric({ tenantId: "t", agentId: "a", profile: "p" });
}

function decisionSpan(): ReadableSpan {
  const spans = exporter.getFinishedSpans();
  return spans.find((s) => s.name === "fabric.decision")!;
}

function executionSpan(): ReadableSpan {
  const spans = exporter.getFinishedSpans();
  return spans.find((s) => s.name === "fabric.execution")!;
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
          type: "other",
          targetSystem: "sys",
          operation: "o",
          requestPayload: "{}",
          requestHash: "deadbeef",
        });
      }),
    ).toThrow(/not both/);
  });

  it("rejects raw content masquerading as precomputed hash metadata", () => {
    expect(() =>
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.recordInteraction("http.request", "target", {
          payloadHash: "raw patient content",
        });
      }),
    ).toThrow(/64 lowercase SHA-256/);
  });

  it("redacts file paths and generic interaction targets by default", () => {
    const path = "/patients/jane/record.pdf";
    const target = "https://internal.example/patient/jane";
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordFileAccess(path, "read");
      d.recordInteraction("http.request", target);
    });
    const span = decisionSpan();
    const file = eventsNamed(span, "fabric.file")[0]!;
    const interaction = eventsNamed(span, "fabric.interaction")[0]!;
    expect(file["fabric.file.path_hash"]).toBe(sha256Hex(path));
    expect(file["fabric.file.path"]).toBeUndefined();
    expect(interaction["fabric.interaction.target_hash"]).toBe(sha256Hex(target));
    expect(interaction["fabric.interaction.target"]).toBeUndefined();
  });

  it("rejects LLM output messages unless content capture is explicitly enabled", () => {
    const outputMessages = [{ role: "assistant", content: "patient diagnosis" }];
    // Without captureContent the messages cannot be safely emitted —
    // the SDK throws rather than silently dropping them (mirrors Python).
    expect(() =>
      fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
        d.llmCall({ system: "test", model: "model" }, (call) => {
          call.setResponse({ outputMessages });
        });
      }),
    ).toThrow(/requires captureContent/);

    exporter.reset();
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.llmCall({ system: "test", model: "model", captureContent: true }, (call) => {
        call.setResponse({ outputMessages });
      });
    });
    const optedIn = exporter.getFinishedSpans().find((span) => span.name === "chat model")!;
    // Emitted as sorted-key compact JSON, mirroring Python's json.dumps
    // with sort_keys — parse before comparing so key order does not leak
    // into the assertion.
    expect(JSON.parse(String(optedIn.attributes["gen_ai.output.messages"]))).toEqual(
      outputMessages,
    );
  });
});

describe("validation guards", () => {
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

describe("execution retry metadata", () => {
  it("emits execution attempt metadata on the decision span", () => {
    const client = new Fabric({
      tenantId: "t",
      agentId: "a",
      profile: "p",
      workflowId: "refunds",
      executionId: "refund-task-123",
      executionAttemptId: "attempt-002",
      executionAttempt: 2,
      executionRetryReason: "tool_timeout",
      executionRetryPreviousAttemptId: "attempt-001",
    });
    client.decision({ sessionId: "s", requestId: "r" }, () => {});
    const span = decisionSpan();
    expect(span.attributes["fabric.workflow_id"]).toBe("refunds");
    expect(span.attributes["fabric.execution_id"]).toBe("refund-task-123");
    expect(span.attributes["fabric.execution.attempt_id"]).toBe("attempt-002");
    expect(span.attributes["fabric.execution.attempt"]).toBe(2);
    expect(span.attributes["fabric.execution.retry.reason"]).toBe("tool_timeout");
    expect(span.attributes["fabric.execution.retry.previous_attempt_id"]).toBe("attempt-001");
  });

  it("rejects invalid execution attempt metadata", () => {
    expect(() => new Fabric({ tenantId: "t", agentId: "a", executionAttempt: 0 })).toThrow(
      /executionAttempt/,
    );
    expect(() => new Fabric({ tenantId: "t", agentId: "a", executionAttemptId: " " })).toThrow(
      /executionAttemptId/,
    );
  });
});

describe("execution span + inheritance (ALS)", () => {
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  it("a decision inside an execution inherits execution_id + attempt metadata", () => {
    const f = fabric();
    f.execution(
      {
        executionId: "exec-1",
        workflowId: "wf-1",
        executionAttemptId: "attempt-7",
        executionAttempt: 7,
        executionRetryReason: "tool_timeout",
        executionRetryPreviousAttemptId: "attempt-6",
      },
      () => {
        f.decision({ sessionId: "s", requestId: "r" }, () => {});
      },
    );
    const d = decisionSpan();
    expect(d.attributes["fabric.execution_id"]).toBe("exec-1");
    expect(d.attributes["fabric.workflow_id"]).toBe("wf-1");
    expect(d.attributes["fabric.execution.attempt_id"]).toBe("attempt-7");
    expect(d.attributes["fabric.execution.attempt"]).toBe(7);
    expect(d.attributes["fabric.execution.retry.reason"]).toBe("tool_timeout");
    expect(d.attributes["fabric.execution.retry.previous_attempt_id"]).toBe("attempt-6");

    const e = executionSpan();
    expect(e.attributes["fabric.execution_id"]).toBe("exec-1");
    expect(e.attributes["fabric.execution.status"]).toBe("completed");
  });

  it("mints a uuid execution_id when none is supplied", () => {
    const f = fabric();
    f.execution({}, () => {});
    expect(String(executionSpan().attributes["fabric.execution_id"])).toMatch(UUID_RE);
  });

  it("explicit DecisionIds value wins over the active execution", () => {
    const f = fabric();
    f.execution({ executionId: "exec-1", workflowId: "wf-1" }, () => {
      f.decision(
        { sessionId: "s", requestId: "r", executionId: "exec-explicit", workflowId: "wf-explicit" },
        () => {},
      );
    });
    const d = decisionSpan();
    expect(d.attributes["fabric.execution_id"]).toBe("exec-explicit");
    expect(d.attributes["fabric.workflow_id"]).toBe("wf-explicit");
  });

  it("a decision OUTSIDE any execution falls back to FabricConfig", () => {
    const client = new Fabric({
      tenantId: "t",
      agentId: "a",
      profile: "p",
      executionId: "cfg-exec",
      workflowId: "cfg-wf",
      executionAttempt: 3,
    });
    client.decision({ sessionId: "s", requestId: "r" }, () => {});
    const d = decisionSpan();
    expect(d.attributes["fabric.execution_id"]).toBe("cfg-exec");
    expect(d.attributes["fabric.workflow_id"]).toBe("cfg-wf");
    expect(d.attributes["fabric.execution.attempt"]).toBe(3);
  });

  it("active execution inheritance overrides FabricConfig for an inner decision", () => {
    const client = new Fabric({
      tenantId: "t",
      agentId: "a",
      profile: "p",
      executionId: "cfg-exec",
    });
    client.execution({ executionId: "active-exec" }, () => {
      client.decision({ sessionId: "s", requestId: "r" }, () => {});
    });
    expect(decisionSpan().attributes["fabric.execution_id"]).toBe("active-exec");
  });

  it("stamps failed status + rethrows when fn throws", () => {
    const f = fabric();
    expect(() =>
      f.execution({ executionId: "exec-fail" }, () => {
        throw new Error("boom");
      }),
    ).toThrow(/boom/);
    const e = executionSpan();
    expect(e.attributes["fabric.execution.status"]).toBe("failed");
    expect(e.status.code).toBe(SpanStatusCode.ERROR);
  });

  it("async fn stamps completed status after the promise settles", async () => {
    const f = fabric();
    await f.execution({ executionId: "exec-async" }, async () => {
      await Promise.resolve();
    });
    expect(executionSpan().attributes["fabric.execution.status"]).toBe("completed");
  });
});

describe("fabric.side_effect.side_effect_id", () => {
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  it("mints a uuid-shaped side_effect_id when none is supplied", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordSideEffect({ type: "ticket_create", targetSystem: "zendesk", operation: "o" });
    });
    const ev = eventsNamed(decisionSpan(), "fabric.side_effect")[0]!;
    expect(String(ev["fabric.side_effect.side_effect_id"])).toMatch(UUID_RE);
  });

  it("mints a distinct side_effect_id per side effect", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordSideEffect({ type: "ticket_create", targetSystem: "zendesk", operation: "o" });
      d.recordSideEffect({ type: "email_send", targetSystem: "ses", operation: "o" });
    });
    const events = eventsNamed(decisionSpan(), "fabric.side_effect");
    const first = String(events[0]!["fabric.side_effect.side_effect_id"]);
    const second = String(events[1]!["fabric.side_effect.side_effect_id"]);
    expect(first).not.toBe(second);
  });

  it("emits a host-supplied side_effect_id verbatim", () => {
    fabric().decision({ sessionId: "s", requestId: "r" }, (d) => {
      d.recordSideEffect({
        sideEffectId: "se-supplied-0001",
        type: "ticket_create",
        targetSystem: "zendesk",
        operation: "o",
      });
    });
    const ev = eventsNamed(decisionSpan(), "fabric.side_effect")[0]!;
    expect(ev["fabric.side_effect.side_effect_id"]).toBe("se-supplied-0001");
  });
});
